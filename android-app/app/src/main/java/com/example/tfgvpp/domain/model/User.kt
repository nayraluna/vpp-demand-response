package com.example.tfgvpp.domain.model

enum class CertificateStatus {
    /** The certificate chains to the platform RA/CA. */
    VALID,

    /** The certificate does not chain to the RA (e.g. the CA was regenerated). */
    INVALID,
}

/**
 * The registered user as the rest of the app sees them: only displayable
 * facts. The cryptographic material behind this (private key in the Android
 * Keystore, certificates) never leaves the data layer.
 */
data class User(
    val subject: String,     // RFC 2253, "CN=..."
    val commonName: String,  // the CN alone; the real DNI when the DNIe was used (U1)
    val holderName: String?, // from the DNIe; null for test identities
    val dni: String?,        // idem
    val raSerial: String,
    val enrollStatus: String, // "enrolled" | "already-enrolled" | "restored"
    val certificateStatus: CertificateStatus,
)

/**
 * Identity proven with the electronic ID document (DNIe over NFC). Produced by
 * the DNIe login and consumed by user registration: the CSR's CN becomes [dni].
 */
data class EidIdentity(
    val holderName: String,
    val dni: String,
)
