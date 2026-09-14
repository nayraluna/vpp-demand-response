package com.example.tfgvpp.domain.model

data class PairingInfo(
    val applianceUrl: String,
) {
    companion object {
        /** Parses a scanned QR, or null if it does not encode a pairing URL. */
        fun fromQr(text: String?): PairingInfo? {
            val trimmed = text?.trim() ?: return null
            return if (trimmed.startsWith("http")) PairingInfo(trimmed) else null
        }
    }
}
