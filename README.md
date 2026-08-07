# DeviceTrust

DeviceTrust is an Android library for collecting device integrity signals. It detects indicators associated with rooted devices, runtime instrumentation, emulators, unlocked bootloaders, custom system images, and weakened platform security settings.

The library includes:

- A Kotlin API based on coroutines
- Native Android NDK checks
- Configurable risk thresholds
- Versioned evidence models
- Consumer R8 rules
- Native binaries for ARM64, ARMv7, x86, and x86_64

## Requirements

- Android API 26 or later
- Kotlin coroutines
- JitPack repository access

## Installation

Add JitPack to `settings.gradle.kts`:

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven(url = "https://jitpack.io")
    }
}
```

Add DeviceTrust to the application or library module:

```kotlin
dependencies {
    implementation("com.github.Xheghun:DeviceTrust:0.1.2")
}
```

## Basic usage

Create a client and run an assessment from a coroutine:

```kotlin
import com.xheghun.devicetrust.DeviceTrust
import com.xheghun.devicetrust.TrustLevel

val deviceTrust = DeviceTrust.create()
val assessment = deviceTrust.assess()

when (assessment.level) {
    TrustLevel.LOW_RISK -> allowNormalFlow()
    TrustLevel.REVIEW -> requireAdditionalVerification()
    TrustLevel.HIGH_RISK -> sendForServerReview()
}
```

`assess()` performs file and system inspection and runs on an I/O dispatcher. Call it from a lifecycle-aware coroutine, such as `viewModelScope`.

```kotlin
viewModelScope.launch {
    val assessment = deviceTrust.assess()
    _state.update { it.copy(assessment = assessment) }
}
```

## Assessment results

`TrustAssessment` contains:

| Property | Description |
|---|---|
| `score` | Risk score from `0` to `100` |
| `level` | `LOW_RISK`, `REVIEW`, or `HIGH_RISK` |
| `signals` | Detected integrity signals ordered by weight |
| `evidence` | Versioned evidence used to produce the assessment |
| `isRootOrHookingSuspected` | Whether root or runtime-hooking signals were found |
| `isEmulatorSuspected` | Whether emulator signals were found |
| `isSystemIntegritySuspected` | Whether boot or system-integrity signals were found |

Each `TrustSignal` provides an identifier, category, weight, title, and detail value.

```kotlin
assessment.signals.forEach { signal ->
    Log.d(
        "DeviceTrust",
        "${signal.category}: ${signal.id} (${signal.weight})"
    )
}
```

Available signal categories are:

- `ROOT`
- `HOOKING`
- `EMULATOR`
- `SYSTEM_INTEGRITY`

## Custom risk policy

The default policy uses review and high-risk thresholds of `25` and `60`. Supply different thresholds when creating the client:

```kotlin
import com.xheghun.devicetrust.DefaultTrustPolicy
import com.xheghun.devicetrust.DeviceTrust

val deviceTrust = DeviceTrust.create(
    policy = DefaultTrustPolicy(
        reviewThreshold = 30,
        highRiskThreshold = 70,
    )
)
```

Applications that require a different scoring model can implement `TrustPolicy`:

```kotlin
val policy = TrustPolicy { evidence ->
    evaluateWithApplicationPolicy(evidence)
}

val deviceTrust = DeviceTrust.create(policy)
```

## Collecting evidence without local scoring

Use `collectEvidence()` to obtain the signals without applying a policy:

```kotlin
val evidence = deviceTrust.collectEvidence()
```

`DeviceEvidence` includes a `schemaVersion`, collection timestamp, and list of signals. Store or transmit the schema version together with the evidence so that server implementations can handle future schema changes.

## Checks

DeviceTrust currently checks for:

- Common `su`, Magisk, KernelSU, APatch, and root-related files
- Suspicious mount and overlay entries
- Frida, Xposed, LSPosed, Zygisk, and Substrate mappings
- Anonymous writable and executable memory mappings
- An attached process tracer
- QEMU, goldfish, ranchu, and other emulator artifacts
- Emulator-related kernel parameters and Android build properties
- Bootloader lock state
- Android Verified Boot state
- Test-key and engineering builds
- SELinux enforcement state

## Security considerations

DeviceTrust provides local risk signals, not proof that a device is trustworthy. An attacker with control of the operating system can modify system properties, filter procfs, hook JNI calls, or patch application code.

Do not use the local result as the only authorization control for payments, account recovery, authentication, or other sensitive operations. Production fraud controls should combine these signals with server-verified Play Integrity results, account history, request context, and transaction risk.

Avoid logging or retaining detailed device evidence unless the application has an appropriate privacy and data-retention policy.

## Project structure

```text
device-trust/   Android library and native detector
sample/         Compose sample application
```

## Building from source

The project requires Android SDK 36, NDK 27.0.12077973 or compatible, CMake 3.22.1, and JDK 17 or 21.

Run the unit tests and build the sample application:

```bash
./gradlew :device-trust:test :sample:assembleDebug
```

## License

DeviceTrust is available under the Apache License 2.0. See [LICENSE](LICENSE).
