package com.example.devicetrust.detection

enum class SignalCategory { ROOT, HOOKING, EMULATOR, ROM }
enum class TrustLevel { TRUSTED, REVIEW, HIGH_RISK }

data class TrustSignal(
    val id: String,
    val category: SignalCategory,
    val weight: Int,
    val title: String,
    val detail: String,
)

data class TrustAssessment(
    val score: Int,
    val level: TrustLevel,
    val signals: List<TrustSignal>,
) {
    val isRootSuspected: Boolean get() = signals.any { it.category == SignalCategory.ROOT || it.category == SignalCategory.HOOKING }
    val isEmulatorSuspected: Boolean get() = signals.any { it.category == SignalCategory.EMULATOR }
    val isCustomRomSuspected: Boolean get() = signals.any { it.category == SignalCategory.ROM }
}
