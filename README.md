# DeviceTrust Android

DeviceTrust is an Android library that collects layered, local risk evidence for root tooling, runtime hooks, emulators, unlocked or degraded Verified Boot, non-production builds, and permissive SELinux. It returns versioned evidence and a policy result rather than a misleading `isRooted` boolean.

## Modules

- `:device-trust` — publishable Android library containing the public Kotlin API and NDK detector.
- `:sample` — Compose application that consumes only the library API.

## Install from JitPack

Add JitPack to dependency resolution:

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven(url = "https://jitpack.io")
    }
}
```

Then add the published library:

```kotlin
dependencies {
    implementation("com.github.Xheghun:DeviceTrust:0.1.0")
}
```

For a source checkout, use `implementation(project(":device-trust"))` as the sample does. A future Maven Central release will use `io.github.xheghun:device-trust:<version>` after that namespace is verified.

## Use

Create one client and call it from a coroutine:

```kotlin
val client = DeviceTrust.create()
val assessment = client.assess()

when (assessment.level) {
    TrustLevel.LOW_RISK -> Unit
    TrustLevel.REVIEW -> requestAdditionalVerification()
    TrustLevel.HIGH_RISK -> deferDecisionToBackend()
}
```

To apply product-specific policy without changing evidence collection:

```kotlin
val client = DeviceTrust.create(
    DefaultTrustPolicy(reviewThreshold = 30, highRiskThreshold = 70)
)
```

Consumers can also call `collectEvidence()` and evaluate the returned `DeviceEvidence` on their backend. Persist `schemaVersion` with serialized evidence; signal IDs and schemas must be treated as versioned contracts.

## Detection layers

- Native raw `openat`/`read` syscalls inspect procfs and device artifacts without Java file APIs.
- Mount information is inspected for Magisk, KernelSU, APatch, and overlay markers.
- Process maps are inspected for known instrumentation frameworks and anonymous RWX mappings.
- `TracerPid` reports attached tracing without mutating process state through `PTRACE_TRACEME`.
- Emulator evidence includes QEMU/goldfish device nodes, kernel parameters, hardware properties, and correlated Android `Build` markers.
- System-integrity evidence includes bootloader lock state, Verified Boot state, test keys, engineering builds, and SELinux enforcement.

## Security model

Local detection is attacker-controlled evidence. A modified OS can spoof properties, filter procfs, patch the native library, or hook JNI. Never authorize payments, account recovery, or other valuable operations using the local score alone.

For production, request a Play Integrity standard token close to the protected action, bind its `requestHash` to a server challenge and canonical payload, and decode the token on your backend. Combine its verdict with this library's evidence, account history, recent activity, and transaction risk. Return only short-lived, single-use authorization.

The library deliberately does not derive cryptographic keys from detection results. Device signals are predictable and do not provide secret entropy.

## Build and publish locally

Requirements: Android SDK 36, NDK 27.0.12077973 or compatible, CMake 3.22.1, and JDK 17 or 21.

```bash
./gradlew :device-trust:test :sample:assembleDebug
./gradlew :device-trust:publishReleasePublicationToLocalBuildRepository
```

The second command creates a Maven repository under `device-trust/build/repo`. The release AAR contains native libraries for ARM64, ARMv7, x86, and x86_64, source JAR, POM metadata, and consumer R8 rules.

Before Maven Central release, verify the `io.github.xheghun` namespace, add a Javadoc artifact, configure artifact signing and Central Portal credentials, and establish API compatibility checks in CI.

## Deliberate exclusions

- Strict SoC whitelists reject new or uncommon genuine devices and require a continuously maintained signed backend dataset.
- CPU timing heuristics vary with thermal throttling, power management, and ARM-hosted emulators.
- `PTRACE_TRACEME` conflicts with legitimate diagnostics; `TracerPid` is advisory instead.
- In-memory `.text` comparison requires audited ELF relocation/load-bias handling per ABI.
- Obfuscation slows analysis but is not a trust boundary and is not bundled into the reproducible build.

Licensed under Apache-2.0. See [LICENSE](LICENSE).
