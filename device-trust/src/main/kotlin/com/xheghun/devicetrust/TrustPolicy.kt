package com.xheghun.devicetrust

public fun interface TrustPolicy {
    public fun evaluate(evidence: DeviceEvidence): TrustAssessment
}

/**
 * Default advisory policy. Correlated signals in one category receive diminishing
 * weight so a noisy signal family cannot dominate independent evidence.
 */
public class DefaultTrustPolicy(
    private val reviewThreshold: Int = 25,
    private val highRiskThreshold: Int = 60,
) : TrustPolicy {
    init {
        require(reviewThreshold in 1..100) { "reviewThreshold must be in 1..100" }
        require(highRiskThreshold in reviewThreshold..100) { "highRiskThreshold must be >= reviewThreshold and <= 100" }
    }

    override fun evaluate(evidence: DeviceEvidence): TrustAssessment {
        val deduplicated = evidence.signals.distinctBy { it.id }
        val score = deduplicated
            .groupBy { it.category }
            .values
            .sumOf { categorySignals ->
                categorySignals.sortedByDescending { it.weight }
                    .mapIndexed { index, signal -> signal.weight / (index + 1) }
                    .sum()
            }
            .coerceIn(0, 100)
        val level = when {
            score >= highRiskThreshold -> TrustLevel.HIGH_RISK
            score >= reviewThreshold -> TrustLevel.REVIEW
            else -> TrustLevel.LOW_RISK
        }
        val normalizedEvidence = evidence.copy(signals = deduplicated.sortedByDescending { it.weight })
        return TrustAssessment(score, level, normalizedEvidence)
    }
}
