// ============================================================================
// C++ Native Security Detection Layer (device_trust.cpp)
//
// WHAT THIS FILE DOES:
// This file performs low-level security checks directly with the Android Linux
// kernel. It checks if the device is rooted, running inside an emulator, being
// tampered with / hooked (e.g. by Frida), or using a compromised ROM.
//
// WHY C++ IS USED INSTEAD OF KOTLIN/JAVA:
// 1. Direct Linux System Calls (Syscalls): High-level Java/Kotlin APIs can be easily
//    faked or intercepted by root hiding tools (e.g. Magisk, Frida). By issuing direct
//    kernel syscalls in C++, we bypass standard Android framework hooks.
// 2. Performance & Security: Native C++ code runs directly on hardware and is harder
//    to decompile or tamper with than Java bytecode.
// ============================================================================

// Header files: Includes built-in C++ libraries and system interfaces.
#include <jni.h>                   // Java Native Interface (JNI) to communicate between C++ and Kotlin/Java
#include <sys/syscall.h>            // Direct Linux system call numbers (__NR_openat, __NR_read, etc.)
#include <sys/system_properties.h>  // Access to Android system properties (e.g., ro.boot.flash.locked)
#include <unistd.h>                 // Standard Linux system call wrappers (close, read)
#include <fcntl.h>                  // File control options (e.g., O_RDONLY open mode)
#include <cerrno>                   // Error number support
#include <string>                  // Standard C++ text string type (std::string)
#include <vector>                  // Resizable dynamic list/array container (std::vector)
#include <array>                   // Fixed-size array container (std::array)
#include <algorithm>               // Utility algorithms (transform, any_of, min)
#include <cctype>                  // Character manipulation functions (tolower)

// Anonymous namespace: Restricts visibility of these helper functions and structs
// strictly to this file so they don't conflict with other native libraries.
namespace {

// Represents a single security threat or indicator found on the device.
struct Signal {
    std::string id;        // Unique identifier for the signal (e.g., "root_artifact")
    std::string category;  // High-level category: "ROOT", "HOOKING", "EMULATOR", or "ROM"
    std::string weight;    // Risk severity score as a string (e.g., "40")
    std::string title;     // Human-readable summary title (e.g., "Privileged artifact")
    std::string detail;    // Extra context about where or how the threat was detected
};

// ----------------------------------------------------------------------------
// Low-Level Helper Functions (Direct Linux Kernel Syscalls)
// ----------------------------------------------------------------------------

// Opens a file using a direct Linux Kernel system call ('openat').
// Normal C libraries use open(), which can be hooked by security bypass tools.
// Calling syscall(__NR_openat, ...) speaks directly to the Linux kernel.
int rawOpen(const char* path) {
    // AT_FDCWD: look up path relative to current working directory
    // O_RDONLY: open for reading only
    // O_CLOEXEC: close file automatically if a new process is executed
    return static_cast<int>(syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0));
}

// Reads up to 'limit' bytes from a file path directly via Linux kernel syscalls.
// Returns the file contents as a std::string.
std::string rawRead(const char* path, size_t limit = 1024 * 1024) {
    int fd = rawOpen(path);
    if (fd < 0) return {}; // Failed to open file (e.g., file doesn't exist or permission denied)

    std::string out;
    std::array<char, 4096> buffer{}; // Temporary 4 KB buffer for reading chunks

    while (out.size() < limit) {
        // Read directly from the kernel using __NR_read syscall
        auto count = static_cast<ssize_t>(syscall(__NR_read, fd, buffer.data(), buffer.size()));
        if (count <= 0) break; // 0 = End of File (EOF), <0 = error
        out.append(buffer.data(), static_cast<size_t>(count));
    }

    // Close the file descriptor using __NR_close syscall
    syscall(__NR_close, fd);
    return out;
}

// Checks whether a file exists by attempting to open it directly via kernel syscall.
bool rawExists(const char* path) {
    int fd = rawOpen(path);
    if (fd < 0) return false;
    syscall(__NR_close, fd);
    return true; // File exists and was successfully opened
}

// Retrieves an Android system property value (like "ro.hardware" or "ro.boot.flash.locked").
std::string property(const char* key) {
    std::array<char, PROP_VALUE_MAX> value{};
    int length = __system_property_get(key, value.data());
    return length > 0 ? std::string(value.data(), static_cast<size_t>(length)) : std::string{};
}

// Helper function: converts 'value' to lowercase and checks if it contains
// any of the target search strings ('needles').
bool containsAny(const std::string& value, const std::vector<std::string>& needles) {
    std::string lower = value;
    // Convert text to lowercase for case-insensitive searching
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });

    // Check if any keyword in 'needles' appears inside 'lower'
    return std::any_of(needles.begin(), needles.end(), [&](const auto& needle) {
        return lower.find(needle) != std::string::npos;
    });
}

// Helper function: creates a new Signal struct and appends it to the output vector.
void add(std::vector<Signal>& out, const char* id, const char* category, int weight,
         const char* title, const std::string& detail) {
    out.push_back({id, category, std::to_string(weight), title, detail});
}

// ----------------------------------------------------------------------------
// Main Signal Collection Function
// ----------------------------------------------------------------------------

// Collects all security indicators across the system.
std::vector<Signal> collect() {
    std::vector<Signal> out;

    // ------------------------------------------------------------------------
    // CHECK 1: Root Detection - Check for known Root Binaries and Artifacts
    // ------------------------------------------------------------------------
    // List of common file paths created when a device is rooted (Magisk, KernelSU, SuperSU, etc.)
    const std::array<const char*, 10> rootPaths = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
        "/data/adb/magisk", "/data/adb/ksu", "/debug_ramdisk/.magisk",
        "/system/app/Superuser.apk", "/system/bin/.ext/.su", "/cache/su"
    };
    for (const char* path : rootPaths) {
        if (rawExists(path)) {
            add(out, "root_artifact", "ROOT", 40, "Privileged artifact", path);
            break; // Found at least one root file, stop checking further root paths
        }
    }

    // ------------------------------------------------------------------------
    // CHECK 2: Root / Hide Detection - Inspecting File System Mounts
    // ------------------------------------------------------------------------
    // /proc/self/mountinfo reveals all active filesystem mounts in the app's process space.
    // Root hiding tools (Magisk, KernelSU, APatch) inject virtual mount overlays to hide root binaries.
    const std::string mounts = rawRead("/proc/self/mountinfo");
    if (containsAny(mounts, {"magisk", "kernelsu", "apatch", "overlay"}))
        add(out, "suspicious_mount", "ROOT", 35, "Suspicious mount namespace", "Magisk, KernelSU, APatch, or overlay marker exposed");

    // ------------------------------------------------------------------------
    // CHECK 3: Hooking & Memory Injection - Inspecting Process Memory Maps
    // ------------------------------------------------------------------------
    // /proc/self/maps lists all dynamic libraries (.so files) loaded into this app's memory space.
    const std::string maps = rawRead("/proc/self/maps");

    // Check if dynamic analysis / hooking tools (Frida, Xposed, LSPosed, Zygisk) are mapped in memory
    if (containsAny(maps, {"frida", "xposed", "lsposed", "zygisk", "substrate"}))
        add(out, "injected_library", "HOOKING", 50, "Injected framework", "A known instrumentation or hooking marker is mapped");

    // Check for "RWX" (Read, Write, Execute) anonymous memory regions.
    // Normal apps store code in read-only/execute regions. Hooking frameworks often allocate
    // writable+executable memory to dynamically rewrite function code (trampolines).
    bool anonymousExecutable = false;
    size_t start = 0;
    while (start < maps.size()) {
        size_t end = maps.find('\n', start);
        std::string line = maps.substr(start, end - start);
        // Look for permission "rwxp" (read-write-execute-private) without an associated file path
        if (line.find("rwxp") != std::string::npos && line.find('/') == std::string::npos) {
            anonymousExecutable = true;
            break;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    if (anonymousExecutable)
        add(out, "anonymous_rwx", "HOOKING", 25, "Writable executable memory", "An anonymous RWX mapping is present");

    // ------------------------------------------------------------------------
    // CHECK 4: Debugger / Tracer Detection - Reading Process Status
    // ------------------------------------------------------------------------
    // /proc/self/status shows metadata about the current process.
    // TracerPid is non-zero if another process (like ptrace, gdb, or lldb) is actively debugging this app.
    const std::string status = rawRead("/proc/self/status");
    auto tracer = status.find("TracerPid:");
    if (tracer != std::string::npos) {
        auto value = status.find_first_of("123456789", tracer + 10);
        if (value != std::string::npos && value < status.find('\n', tracer))
            add(out, "tracer", "HOOKING", 30, "Process is traced", "TracerPid is non-zero");
    }

    // ------------------------------------------------------------------------
    // CHECK 5: Emulator Detection - Hardware Device Nodes
    // ------------------------------------------------------------------------
    // Emulators (Android Studio Emulator, Genymotion, Nox, BlueStacks) create virtual hardware devices.
    const std::array<const char*, 7> emulatorPaths = {
        "/dev/qemu_pipe", "/dev/socket/qemud", "/dev/goldfish_pipe",
        "/sys/qemu_trace", "/system/lib/libc_malloc_debug_qemu.so", "/dev/ttyS0", "/dev/ttyS1"
    };
    int virtualArtifacts = 0;
    for (const char* path : emulatorPaths) if (rawExists(path)) ++virtualArtifacts;
    if (virtualArtifacts > 0)
        add(out, "virtual_device", "EMULATOR", std::min(45, 20 + virtualArtifacts * 5), "Virtual hardware artifacts", std::to_string(virtualArtifacts) + " emulator device nodes found");

    // ------------------------------------------------------------------------
    // CHECK 6: Emulator Detection - Kernel Command Line Arguments
    // ------------------------------------------------------------------------
    // /proc/cmdline contains options passed to the Linux kernel when the device booted up.
    const std::string cmdline = rawRead("/proc/cmdline");
    if (containsAny(cmdline, {"qemu=1", "goldfish", "ranchu", "androidboot.hardware=virtual"}))
        add(out, "virtual_kernel", "EMULATOR", 40, "Virtual kernel parameters", "Kernel command line exposes emulator markers");

    // ------------------------------------------------------------------------
    // CHECK 7: Emulator Detection - System Properties
    // ------------------------------------------------------------------------
    // Check board and hardware properties for virtual machine identifiers.
    const std::string hardware = property("ro.hardware") + " " + property("ro.boot.hardware") + " " + property("ro.product.board");
    if (containsAny(hardware, {"goldfish", "ranchu", "vbox", "nox", "ttvm", "qemu"}))
        add(out, "virtual_properties", "EMULATOR", 35, "Virtual hardware properties", hardware);

    // ------------------------------------------------------------------------
    // CHECK 8: Custom ROM & Bootloader Tampering Checks
    // ------------------------------------------------------------------------
    // Check if the bootloader has been unlocked (0 = unlocked)
    const std::string flashLocked = property("ro.boot.flash.locked");
    if (flashLocked == "0") add(out, "bootloader_unlocked", "ROM", 35, "Bootloader unlocked", "ro.boot.flash.locked=0");

    // Check Android Verified Boot (AVB) state. "green" = verified lock, "orange"/"yellow"/"red" = warning/corrupted
    const std::string verified = property("ro.boot.verifiedbootstate");
    if (verified == "orange" || verified == "red" || verified == "yellow")
        add(out, "verified_boot", "ROM", verified == "red" ? 50 : 35, "Verified Boot degraded", "verified boot state=" + verified);

    // Check if the system build was signed with public Android test keys instead of official release keys
    const std::string tags = property("ro.build.tags");
    if (tags.find("test-keys") != std::string::npos)
        add(out, "test_keys", "ROM", 25, "Build uses test keys", tags);

    // Check if system build is engineering/debug build ("eng" or "userdebug") instead of user production build
    const std::string buildType = property("ro.build.type");
    if (buildType == "eng" || buildType == "userdebug")
        add(out, "debug_build", "ROM", 20, "Non-production system build", "ro.build.type=" + buildType);

    // Check if SELinux security policy is set to Permissive (0) instead of Enforcing (1)
    const std::string selinux = rawRead("/sys/fs/selinux/enforce", 8);
    if (!selinux.empty() && selinux[0] == '0')
        add(out, "selinux_permissive", "ROM", 45, "SELinux is permissive", "Kernel is not enforcing mandatory access control");

    return out;
}

} // end anonymous namespace

// ============================================================================
// JNI Bridge Function (Callable from Kotlin / Java)
// ============================================================================
// Function Name Convention:
// Java_<PackageName>_<ClassName>_<MethodName>
//
// JNIEnv* env: Pointer to the JNI environment, used to create Java objects/strings.
// jobject: Reference to the calling Kotlin object (NativeSignalSource).
//
// Returns: A Java String array (String[]) where each element is tab-delimited
//          containing: "id \t category \t weight \t title \t detail"
// ============================================================================
extern "C" JNIEXPORT jobjectArray JNICALL
Java_io_github_devicetrust_internal_NativeSignalSource_collectEncoded(JNIEnv* env, jobject) {
    // 1. Collect all detected signals using C++ detection logic above
    auto signals = collect();

    // 2. Find the Java String class reflection handle
    jclass stringClass = env->FindClass("java/lang/String");

    // 3. Allocate a new Java String array (String[]) of size = signals.size()
    jobjectArray result = env->NewObjectArray(static_cast<jsize>(signals.size()), stringClass, nullptr);

    // 4. Convert each C++ Signal struct into a tab-delimited Java String and put it into the array
    for (size_t i = 0; i < signals.size(); ++i) {
        const auto& s = signals[i];

        // Format as tab-separated values (TSV)
        std::string encoded = s.id + "\t" + s.category + "\t" + s.weight + "\t" + s.title + "\t" + s.detail;

        // Convert C++ std::string to Java jstring
        jstring value = env->NewStringUTF(encoded.c_str());

        // Place the Java string into the result array at index i
        env->SetObjectArrayElement(result, static_cast<jsize>(i), value);

        // Clean up local reference to avoid memory leaks in the JNI frame
        env->DeleteLocalRef(value);
    }

    // 5. Return the Java String[] array back to Kotlin
    return result;
}
