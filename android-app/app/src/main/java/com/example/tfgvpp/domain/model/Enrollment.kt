package com.example.tfgvpp.domain.model

enum class EnrollmentStep {
    CONNECTING,
    DELIVERING_CONFIGURATION, // the user-signed bundle, as a JWS
    VERIFYING_OWNER_PROOF,    // the HSM-signed proof, checked on the phone
    REGISTERING_AT_VPP,       // forwarded over mutual TLS
    REFRESHING,
}

/**
 * Local verification of the owner proof: the same checks the VPP repeats when
 * the proof is forwarded. All four must pass for the enrollment to continue.
 */
data class OwnerProofChecks(
    /** The JWS signature verifies with the VEN certificate's public key. */
    val signatureValid: Boolean,
    /** The VEN certificate chains to the platform RA. */
    val certChainsToRa: Boolean,
    /** The proof names the active user as owner. */
    val ownerMatches: Boolean,
    /** The declared P equals the power certified inside the VEN certificate. */
    val powerMatchesCertified: Boolean,
) {
    val allPassed: Boolean
        get() = signatureValid && certChainsToRa && ownerMatches && powerMatchesCertified
}

/**
 * What the appliance answers to a successful pairing: its identity, its
 * certified operational parameters and the owner proof, already verified
 * locally ([checks]).
 */
data class PairedAppliance(
    val venSubject: String,
    val nominalPowerW: Long,
    val maxCurtailmentMin: Long,
    val recoveryPeriodMin: Long,
    /** Compact JWS signed inside the appliance's HSM; opaque to the app. */
    val ownerProofJws: String,
    val checks: OwnerProofChecks,
)

/** Progress of [com.example.tfgvpp.domain.usecase.EnrollApplianceUseCase]. */
sealed interface EnrollmentProgress {
    data class Step(val step: EnrollmentStep) : EnrollmentProgress

    /** The appliance is enrolled and bound to the user at the VPP. */
    data class Success(val appliance: Appliance, val checks: OwnerProofChecks) : EnrollmentProgress

    /** [alreadyPaired] hints that a factory reset would unblock the retry. */
    data class Failure(val message: String, val alreadyPaired: Boolean) : EnrollmentProgress
}

/** The appliance refused to pair because it is already configured (HTTP 409). */
class AlreadyPairedException(message: String) : Exception(message)
