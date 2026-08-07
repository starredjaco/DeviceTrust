#include <jni.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <cctype>

namespace {

struct Signal {
    std::string id;
    std::string category;
    std::string weight;
    std::string title;
    std::string detail;
};

int rawOpen(const char* path) {
    return static_cast<int>(syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0));
}

std::string rawRead(const char* path, size_t limit = 1024 * 1024) {
    int fd = rawOpen(path);
    if (fd < 0) return {};

    std::string out;
    std::array<char, 4096> buffer{};

    while (out.size() < limit) {
        auto count = static_cast<ssize_t>(syscall(__NR_read, fd, buffer.data(), buffer.size()));
        if (count <= 0) break;
        out.append(buffer.data(), static_cast<size_t>(count));
    }

    syscall(__NR_close, fd);
    return out;
}

bool rawExists(const char* path) {
    int fd = rawOpen(path);
    if (fd < 0) return false;
    syscall(__NR_close, fd);
    return true;
}

std::string property(const char* key) {
    std::array<char, PROP_VALUE_MAX> value{};
    int length = __system_property_get(key, value.data());
    return length > 0 ? std::string(value.data(), static_cast<size_t>(length)) : std::string{};
}

bool containsAny(const std::string& value, const std::vector<std::string>& needles) {
    std::string lower = value;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });

    return std::any_of(needles.begin(), needles.end(), [&](const auto& needle) {
        return lower.find(needle) != std::string::npos;
    });
}

void add(std::vector<Signal>& out, const char* id, const char* category, int weight,
         const char* title, const std::string& detail) {
    out.push_back({id, category, std::to_string(weight), title, detail});
}

std::vector<Signal> collect() {
    std::vector<Signal> out;

    // Root Detection
    const std::array<const char*, 10> rootPaths = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
        "/data/adb/magisk", "/data/adb/ksu", "/debug_ramdisk/.magisk",
        "/system/app/Superuser.apk", "/system/bin/.ext/.su", "/cache/su"
    };
    for (const char* path : rootPaths) {
        if (rawExists(path)) {
            add(out, "root_artifact", "ROOT", 40, "Privileged artifact", path);
            break;
        }
    }

    // Mount Checks
    const std::string mounts = rawRead("/proc/self/mountinfo");
    if (containsAny(mounts, {"magisk", "kernelsu", "apatch", "overlay"}))
        add(out, "suspicious_mount", "ROOT", 35, "Suspicious mount namespace", "Magisk, KernelSU, APatch, or overlay marker exposed");

    // Memory Maps Checks
    const std::string maps = rawRead("/proc/self/maps");

    if (containsAny(maps, {"frida", "xposed", "lsposed", "zygisk", "substrate"}))
        add(out, "injected_library", "HOOKING", 50, "Injected framework", "A known instrumentation or hooking marker is mapped");

    bool anonymousExecutable = false;
    size_t start = 0;
    while (start < maps.size()) {
        size_t end = maps.find('\n', start);
        std::string line = maps.substr(start, end - start);
        if (line.find("rwxp") != std::string::npos && line.find('/') == std::string::npos) {
            anonymousExecutable = true;
            break;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    if (anonymousExecutable)
        add(out, "anonymous_rwx", "HOOKING", 25, "Writable executable memory", "An anonymous RWX mapping is present");

    // Tracer Detection
    const std::string status = rawRead("/proc/self/status");
    auto tracer = status.find("TracerPid:");
    if (tracer != std::string::npos) {
        auto value = status.find_first_of("123456789", tracer + 10);
        if (value != std::string::npos && value < status.find('\n', tracer))
            add(out, "tracer", "HOOKING", 30, "Process is traced", "TracerPid is non-zero");
    }

    // Emulator Detection
    const std::array<const char*, 7> emulatorPaths = {
        "/dev/qemu_pipe", "/dev/socket/qemud", "/dev/goldfish_pipe",
        "/sys/qemu_trace", "/system/lib/libc_malloc_debug_qemu.so", "/dev/ttyS0", "/dev/ttyS1"
    };
    int virtualArtifacts = 0;
    for (const char* path : emulatorPaths) if (rawExists(path)) ++virtualArtifacts;
    if (virtualArtifacts > 0)
        add(out, "virtual_device", "EMULATOR", std::min(45, 20 + virtualArtifacts * 5), "Virtual hardware artifacts", std::to_string(virtualArtifacts) + " emulator device nodes found");

    const std::string cmdline = rawRead("/proc/cmdline");
    if (containsAny(cmdline, {"qemu=1", "goldfish", "ranchu", "androidboot.hardware=virtual"}))
        add(out, "virtual_kernel", "EMULATOR", 40, "Virtual kernel parameters", "Kernel command line exposes emulator markers");

    const std::string hardware = property("ro.hardware") + " " + property("ro.boot.hardware") + " " + property("ro.product.board");
    if (containsAny(hardware, {"goldfish", "ranchu", "vbox", "nox", "ttvm", "qemu"}))
        add(out, "virtual_properties", "EMULATOR", 35, "Virtual hardware properties", hardware);

    // ROM & Bootloader Checks
    const std::string flashLocked = property("ro.boot.flash.locked");
    if (flashLocked == "0") add(out, "bootloader_unlocked", "ROM", 35, "Bootloader unlocked", "ro.boot.flash.locked=0");

    const std::string verified = property("ro.boot.verifiedbootstate");
    if (verified == "orange" || verified == "red" || verified == "yellow")
        add(out, "verified_boot", "ROM", verified == "red" ? 50 : 35, "Verified Boot degraded", "verified boot state=" + verified);

    const std::string tags = property("ro.build.tags");
    if (tags.find("test-keys") != std::string::npos)
        add(out, "test_keys", "ROM", 25, "Build uses test keys", tags);

    const std::string buildType = property("ro.build.type");
    if (buildType == "eng" || buildType == "userdebug")
        add(out, "debug_build", "ROM", 20, "Non-production system build", "ro.build.type=" + buildType);

    const std::string selinux = rawRead("/sys/fs/selinux/enforce", 8);
    if (!selinux.empty() && selinux[0] == '0')
        add(out, "selinux_permissive", "ROM", 45, "SELinux is permissive", "Kernel is not enforcing mandatory access control");

    return out;
}

} // namespace

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_xheghun_devicetrust_internal_NativeSignalSource_collectEncoded(JNIEnv* env, jobject) {
    auto signals = collect();
    jclass stringClass = env->FindClass("java/lang/String");
    jobjectArray result = env->NewObjectArray(static_cast<jsize>(signals.size()), stringClass, nullptr);

    for (size_t i = 0; i < signals.size(); ++i) {
        const auto& s = signals[i];
        std::string encoded = s.id + "\t" + s.category + "\t" + s.weight + "\t" + s.title + "\t" + s.detail;
        jstring value = env->NewStringUTF(encoded.c_str());
        env->SetObjectArrayElement(result, static_cast<jsize>(i), value);
        env->DeleteLocalRef(value);
    }

    return result;
}
