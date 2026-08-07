package com.xheghun.devicetrust

import com.xheghun.devicetrust.internal.BuildSignalSource
import com.xheghun.devicetrust.internal.NativeSignalSource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal class DefaultDeviceTrustClient(private val policy: TrustPolicy) : DeviceTrustClient {
    override suspend fun collectEvidence(): DeviceEvidence = withContext(Dispatchers.IO) {
        DeviceEvidence(
            schemaVersion = DeviceTrust.SIGNAL_SCHEMA_VERSION,
            collectedAtEpochMillis = System.currentTimeMillis(),
            signals = NativeSignalSource.collect() + BuildSignalSource.collect(),
        )
    }

    override suspend fun assess(): TrustAssessment = policy.evaluate(collectEvidence())
}
