package io.github.devicetrust.internal

import android.os.Build
import io.github.devicetrust.SignalCategory
import io.github.devicetrust.TrustSignal

internal object BuildSignalSource {
    fun collect(): List<TrustSignal> = buildList {
        val values = listOf(Build.FINGERPRINT, Build.MODEL, Build.PRODUCT, Build.BRAND).map(String::lowercase)
        val markers = listOf("generic", "unknown", "emulator", "sdk_gphone", "google_sdk", "genymotion")
        val matches = values.count { value -> markers.any(value::contains) }
        if (matches >= 2) add(
            TrustSignal("build_emulator", SignalCategory.EMULATOR, 25, "Emulator-like build identity", "$matches independent Build fields contain virtual-device markers")
        )
        if (Build.TAGS?.contains("test-keys") == true) add(
            TrustSignal("java_test_keys", SignalCategory.SYSTEM_INTEGRITY, 20, "Android build uses test keys", Build.TAGS.orEmpty())
        )
    }
}
