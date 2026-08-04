package com.example.devicetrust.detection

class DeviceTrustRepository {
    fun assess(): TrustAssessment = RiskEngine.assess(NativeSignalSource.collect() + DeviceSignalSource.collect())
}
