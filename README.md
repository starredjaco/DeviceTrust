# DeviceTrust

DeviceTrust is a compact Android/NDK demonstration of layered device-risk detection. It collects independent local signals for root tooling, runtime hooks, emulators, unlocked or degraded Verified Boot, non-production builds, and permissive SELinux, then produces a risk assessment rather than a misleading boolean verdict.

## Detection layers

- Native raw `openat`/`read` syscalls inspect procfs and device artifacts without relying on Java file APIs.
- `/proc/self/mountinfo` is inspected for Magisk, KernelSU, APatch, and overlay markers.
- `/proc/self/maps` is inspected for known instrumentation frameworks and anonymous RWX mappings.
- `TracerPid` reports attached tracing without calling `PTRACE_TRACEME`, which would interfere with legitimate debuggers and crash tooling.
- Emulator evidence includes QEMU/goldfish device nodes, kernel parameters, Android hardware properties, and correlated `Build` identity markers.
- ROM/boot evidence includes bootloader lock, Verified Boot state, test keys, engineering builds, and SELinux enforcement.

## Security model

Local detection is attacker-controlled evidence. A modified OS can spoof properties, filter procfs, patch the native library, or hook JNI. Therefore:

1. Never authorize payments, account recovery, or valuable operations from this local score alone.
2. Request a Play Integrity standard token close to the protected action.
3. Bind the request with `requestHash` to a server-issued challenge and canonical action payload.
4. Send the encrypted token to your backend and decode it using Google Play's server API.
5. Make a server-side policy decision using app integrity, device integrity, account licensing, recent device activity, app-access risk, local signals, account history, and transaction risk.
6. Return a short-lived, single-use authorization—not a reusable client-side secret.

The project deliberately does not derive cryptographic keys from detection results. Predictable device signals do not provide key entropy, and a patched client can reproduce or bypass that derivation.

## Deliberate exclusions

- A strict SoC whitelist would reject new or uncommon genuine devices and requires a continuously maintained, signed backend dataset.
- CPU timing and translation heuristics are unstable under thermal throttling, power management, and modern ARM-hosted emulators.
- `PTRACE_TRACEME` is not used because it mutates process state and conflicts with legitimate diagnostics. `TracerPid` is an advisory alternative.
- In-memory `.text` comparison needs robust ELF relocation/load-bias handling per ABI and should live in a separately audited hardening component. Incorrect implementations create crashes and false positives.
- Obfuscator-LLVM is not bundled. Use a maintained, reproducible toolchain only after legal/licensing review; obfuscation delays analysis but is not a trust boundary.

## Build

Requirements: Android SDK 36, NDK 27.0.12077973 or compatible, CMake 3.22.1, and JDK 17 or 21.

```bash
./gradlew test assembleDebug
```

For production, replace `com.example.devicetrust`, configure Play App Signing and Play Integrity in Play Console, add the server integration, tune thresholds using labeled telemetry, and test on a diverse physical-device fleet. Do not log raw device evidence without a defined retention and privacy policy.
