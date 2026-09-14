package com.example.tfgvpp.presentation.screens.pairing

import com.example.tfgvpp.domain.model.Appliance
import com.example.tfgvpp.domain.model.EnrollmentStep
import com.example.tfgvpp.domain.model.OwnerProofChecks

data class PairingUiState(
    val phase: Phase = Phase.IDLE,
    val completedSteps: List<EnrollmentStep> = emptyList(),
    val currentStep: EnrollmentStep? = null, // spinner; null outside RUNNING
    val enrolled: Appliance? = null,
    val checks: OwnerProofChecks? = null,
    val error: String? = null,
    val alreadyPaired: Boolean = false, // the appliance answered 409: offer a reset
    val resetDone: Boolean = false,
) {
    /** Screen states: waiting for a QR, enrolling, done, or stopped. */
    enum class Phase { IDLE, RUNNING, SUCCESS, ERROR }
}
