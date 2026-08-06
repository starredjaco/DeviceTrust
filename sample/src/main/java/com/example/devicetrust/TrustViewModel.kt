package com.example.devicetrust

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.github.devicetrust.DeviceTrust
import io.github.devicetrust.DeviceTrustClient
import io.github.devicetrust.TrustAssessment
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class TrustUiState(val scanning: Boolean = true, val assessment: TrustAssessment? = null, val error: String? = null)

class TrustViewModel(private val client: DeviceTrustClient = DeviceTrust.create()) : ViewModel() {
    private val _state = MutableStateFlow(TrustUiState())
    val state = _state.asStateFlow()

    init { scan() }

    fun scan() {
        _state.value = TrustUiState(scanning = true)
        viewModelScope.launch {
            _state.value = runCatching { withContext(Dispatchers.IO) { client.assess() } }
                .fold(
                    onSuccess = { TrustUiState(scanning = false, assessment = it) },
                    onFailure = { TrustUiState(scanning = false, error = it.message ?: "Scan failed") },
                )
        }
    }
}
