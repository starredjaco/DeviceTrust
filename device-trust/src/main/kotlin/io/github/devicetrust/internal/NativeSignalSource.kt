package io.github.devicetrust.internal

import io.github.devicetrust.SignalCategory
import io.github.devicetrust.TrustSignal

internal object NativeSignalSource {
    init { System.loadLibrary("devicetrust") }

    private external fun collectEncoded(): Array<String>

    fun collect(): List<TrustSignal> = collectEncoded().mapNotNull { encoded ->
        val parts = encoded.split('\t', limit = 5)
        if (parts.size != 5) return@mapNotNull null
        val category = when (parts[1]) {
            "ROM" -> SignalCategory.SYSTEM_INTEGRITY
            else -> runCatching { SignalCategory.valueOf(parts[1]) }.getOrNull()
        } ?: return@mapNotNull null
        TrustSignal(parts[0], category, parts[2].toIntOrNull() ?: 0, parts[3], parts[4])
    }
}
