package com.example.devicetrust.detection

object RiskEngine {
    fun assess(signals: List<TrustSignal>): TrustAssessment {
        val deduplicated = signals.distinctBy { it.id }
        // Correlated indicators have diminishing returns. This avoids one noisy family
        // overwhelming the assessment while still rewarding independent evidence.
        val score = deduplicated
            .groupBy { it.category }
            .values
            .sumOf { categorySignals ->
                categorySignals.sortedByDescending { it.weight }
                    .mapIndexed { index, signal -> signal.weight / (index + 1) }
                    .sum()
            }.coerceIn(0, 100)
        val level = when {
            score >= 60 -> TrustLevel.HIGH_RISK
            score >= 25 -> TrustLevel.REVIEW
            else -> TrustLevel.TRUSTED
        }
        return TrustAssessment(score, level, deduplicated.sortedByDescending { it.weight })
    }
}
