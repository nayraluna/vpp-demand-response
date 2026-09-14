package com.example.tfgvpp.domain.model

data class Appliance(
    val ven: String,
    val name: String,
    val nominalPowerW: Long,
    val maxCurtailmentMin: Long,
    val recoveryPeriodMin: Long,
    val availabilityDeclared: Boolean,
    val availabilityUpdatedAt: String?,
) {
    companion object {
        /** "CN=appliance-0001,OU=..." -> "appliance-0001". */
        fun nameFromVen(ven: String): String =
            Regex("(?:^|,)\\s*CN=([^,]+)").find(ven)?.groupValues?.get(1) ?: ven
    }
}
