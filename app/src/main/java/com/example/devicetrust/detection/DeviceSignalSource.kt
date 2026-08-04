package com.example.devicetrust.detection

import android.os.Build

object DeviceSignalSource {
    fun collect(): List<TrustSignal> = buildList {
        val fingerprint = Build.FINGERPRINT.lowercase()
        val model = Build.MODEL.lowercase()
        val product = Build.PRODUCT.lowercase()
        val brand = Build.BRAND.lowercase()
        val emulatorMarkers = listOf("generic", "unknown", "emulator", "sdk_gphone", "google_sdk", "genymotion")
        val matches = listOf(fingerprint, model, product, brand).count { value -> emulatorMarkers.any(value::contains) }
        if (matches >= 2) add(
            TrustSignal("build_emulator", SignalCategory.EMULATOR, 25, "Emulator-like build identity", "$matches independent Build fields contain virtual-device markers")
        )
        if (Build.TAGS?.contains("test-keys") == true) add(
            TrustSignal("java_test_keys", SignalCategory.ROM, 20, "Android build uses test keys", Build.TAGS.orEmpty())
        )
    }
}
