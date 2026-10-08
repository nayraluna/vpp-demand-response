package com.example.tfgvpp.domain.model

enum class EnrollmentStep {
    CONNECTING,
    DELIVERING_CONFIGURATION,
    VERIFYING_OWNER_PROOF,
    REGISTERING_AT_VPP,
    REFRESHING,
}

/** Local verification of the owner proof, the same checks the VPP repeats. */
data class OwnerProofChecks(
    val signatureValid: Boolean,
    val certChainsToRa: Boolean,
    val ownerMatches: Boolean,
    val powerMatchesCertified: Boolean,
) {
    val allPassed: Boolean
        get() = signatureValid && certChainsToRa && ownerMatches && powerMatchesCertified
}

data class PairedAppliance(
    val venSubject: String,
    val nominalPowerW: Long,
    val maxCurtailmentMin: Long,
    val recoveryPeriodMin: Long,
    val ownerProofJws: String,
    val checks: OwnerProofChecks,
)

sealed interface EnrollmentProgress {
    data class Step(val step: EnrollmentStep) : EnrollmentProgress

    data class Success(val appliance: Appliance, val checks: OwnerProofChecks) : EnrollmentProgress

    data class Failure(val message: String, val alreadyPaired: Boolean) : EnrollmentProgress
}

/** The appliance is already configured (HTTP 409). */
class AlreadyPairedException(message: String) : Exception(message)
