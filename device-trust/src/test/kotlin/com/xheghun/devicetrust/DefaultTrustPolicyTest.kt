package com.xheghun.devicetrust

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DefaultTrustPolicyTest {
    private val policy = DefaultTrustPolicy()

    @Test fun `no signals is low risk`() {
        val result = policy.evaluate(evidence())
        assertEquals(0, result.score)
        assertEquals(TrustLevel.LOW_RISK, result.level)
    }

    @Test fun `independent high confidence signals produce high risk`() {
        val result = policy.evaluate(evidence(
            signal("root", SignalCategory.ROOT, 40),
            signal("hook", SignalCategory.HOOKING, 30),
        ))
        assertEquals(70, result.score)
        assertEquals(TrustLevel.HIGH_RISK, result.level)
        assertTrue(result.isRootOrHookingSuspected)
    }

    @Test fun `correlated signals have diminishing weight`() {
        val result = policy.evaluate(evidence(
            signal("a", SignalCategory.EMULATOR, 40),
            signal("b", SignalCategory.EMULATOR, 30),
            signal("c", SignalCategory.EMULATOR, 20),
        ))
        assertEquals(61, result.score)
    }

    @Test fun `duplicate ids cannot inflate score`() {
        val duplicate = signal("same", SignalCategory.ROOT, 40)
        assertEquals(40, policy.evaluate(evidence(duplicate, duplicate)).score)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `invalid thresholds are rejected`() {
        DefaultTrustPolicy(reviewThreshold = 60, highRiskThreshold = 50)
    }

    private fun evidence(vararg signals: TrustSignal) = DeviceEvidence(1, 123L, signals.toList())
    private fun signal(id: String, category: SignalCategory, weight: Int) =
        TrustSignal(id, category, weight, id, "test")
}
