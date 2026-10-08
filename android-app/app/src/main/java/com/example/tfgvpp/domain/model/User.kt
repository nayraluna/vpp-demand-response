package com.example.tfgvpp.domain.model

enum class CertificateStatus {
    VALID,

    INVALID,
}

/** Displayable facts only; the key material never leaves the data layer. */
data class User(
    val subject: String,     // RFC 2253, "CN=..."
    val commonName: String,  // the real DNI when the DNIe was used
    val holderName: String?,
    val dni: String?,
    val raSerial: String,
    val enrollStatus: String, // "enrolled" | "already-enrolled" | "restored"
    val certificateStatus: CertificateStatus,
)

/** Identity proven with the DNIe; the CSR's CN becomes [dni]. */
data class EidIdentity(
    val holderName: String,
    val dni: String,
)
