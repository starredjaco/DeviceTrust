package com.example.devicetrust.detection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RiskEngineTest {
    @Test fun `no signals is trusted`() {
        val result = RiskEngine.assess(emptyList())
        assertEquals(0, result.score)
        assertEquals(TrustLevel.TRUSTED, result.level)
    }

    @Test fun `independent high confidence signals produce high risk`() {
        val result = RiskEngine.assess(listOf(
            signal("root", SignalCategory.ROOT, 40),
            signal("hook", SignalCategory.HOOKING, 30),
        ))
        assertEquals(70, result.score)
        assertEquals(TrustLevel.HIGH_RISK, result.level)
        assertTrue(result.isRootSuspected)
    }

    @Test fun `correlated signals have diminishing weight`() {
        val result = RiskEngine.assess(listOf(
            signal("a", SignalCategory.EMULATOR, 40),
            signal("b", SignalCategory.EMULATOR, 30),
            signal("c", SignalCategory.EMULATOR, 20),
        ))
        assertEquals(61, result.score)
    }

    @Test fun `duplicate ids cannot inflate score`() {
        val duplicate = signal("same", SignalCategory.ROOT, 40)
        assertEquals(40, RiskEngine.assess(listOf(duplicate, duplicate)).score)
    }

    private fun signal(id: String, category: SignalCategory, weight: Int) =
        TrustSignal(id, category, weight, id, "test")
}
