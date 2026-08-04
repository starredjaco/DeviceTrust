package com.example.devicetrust

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.devicetrust.detection.DeviceTrustRepository
import com.example.devicetrust.detection.TrustAssessment
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class TrustUiState(val scanning: Boolean = true, val assessment: TrustAssessment? = null, val error: String? = null)

class TrustViewModel(private val repository: DeviceTrustRepository = DeviceTrustRepository()) : ViewModel() {
    private val _state = MutableStateFlow(TrustUiState())
    val state = _state.asStateFlow()

    init { scan() }

    fun scan() {
        _state.value = TrustUiState(scanning = true)
        viewModelScope.launch {
            _state.value = runCatching { withContext(Dispatchers.IO) { repository.assess() } }
                .fold(
                    onSuccess = { TrustUiState(scanning = false, assessment = it) },
                    onFailure = { TrustUiState(scanning = false, error = it.message ?: "Scan failed") },
                )
        }
    }
}
