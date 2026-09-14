package com.example.tfgvpp.presentation.screens.pairing

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.tfgvpp.data.remote.VppEndpoints
import com.example.tfgvpp.domain.model.EnrollmentProgress
import com.example.tfgvpp.domain.model.PairingInfo
import com.example.tfgvpp.domain.usecase.EnrollApplianceUseCase
import com.example.tfgvpp.domain.usecase.FactoryResetApplianceUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class PairingViewModel @Inject constructor(
    private val enrollAppliance: EnrollApplianceUseCase,
    private val factoryResetAppliance: FactoryResetApplianceUseCase,
    private val endpoints: VppEndpoints,
) : ViewModel() {

    private val _uiState = MutableStateFlow(PairingUiState())
    val uiState: StateFlow<PairingUiState> = _uiState.asStateFlow()

    private var lastPairing: PairingInfo? = null

    /** Result of the QR scan; ignores cancellations, flags non-URLs. */
    fun onQrScanned(contents: String?) {
        if (contents == null) return // scan cancelled
        val info = PairingInfo.fromQr(contents)
        if (info == null) {
            _uiState.update {
                it.copy(phase = PairingUiState.Phase.ERROR,
                    error = contents, alreadyPaired = false)
            }
            return
        }
        enroll(info)
    }

    /** Enrolls against the appliance emulated on the PC (no QR needed). */
    fun useDevelopmentAppliance() = enroll(PairingInfo(endpoints.defaultApplianceUrl))

    fun retry() {
        lastPairing?.let(::enroll)
    }

    /** Returns the appliance to state 0 (it answered 409: already paired). */
    fun factoryReset() {
        val pairing = lastPairing ?: return
        viewModelScope.launch {
            factoryResetAppliance(pairing)
                .onSuccess {
                    _uiState.update {
                        it.copy(phase = PairingUiState.Phase.IDLE,
                            alreadyPaired = false, error = null, resetDone = true)
                    }
                }
                .onFailure { e ->
                    _uiState.update { it.copy(error = e.message ?: e.javaClass.simpleName) }
                }
        }
    }

    fun consumeResetDone() {
        _uiState.update { it.copy(resetDone = false) }
    }

    private fun enroll(pairing: PairingInfo) {
        if (_uiState.value.phase == PairingUiState.Phase.RUNNING) return
        lastPairing = pairing
        _uiState.value = PairingUiState(phase = PairingUiState.Phase.RUNNING)
        viewModelScope.launch {
            enrollAppliance(pairing).collect { progress ->
                when (progress) {
                    is EnrollmentProgress.Step -> _uiState.update {
                        it.copy(
                            completedSteps = it.completedSteps + listOfNotNull(it.currentStep),
                            currentStep = progress.step,
                        )
                    }
                    is EnrollmentProgress.Success -> _uiState.update {
                        it.copy(
                            phase = PairingUiState.Phase.SUCCESS,
                            completedSteps = it.completedSteps + listOfNotNull(it.currentStep),
                            currentStep = null,
                            enrolled = progress.appliance,
                            checks = progress.checks,
                        )
                    }
                    is EnrollmentProgress.Failure -> _uiState.update {
                        it.copy(
                            phase = PairingUiState.Phase.ERROR,
                            currentStep = null,
                            error = progress.message,
                            alreadyPaired = progress.alreadyPaired,
                        )
                    }
                }
            }
        }
    }
}
