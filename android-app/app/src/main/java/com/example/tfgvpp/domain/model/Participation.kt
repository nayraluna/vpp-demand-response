package com.example.tfgvpp.domain.model

data class ParticipationRecord(
    val activationId: String,
    val applianceVen: String,
    val day: String,          // "mon".."sun"
    val interval: String,     // e.g. "15:00-17:00"
    val action: String,       // "reduce" | "shutdown"
    val reductionPct: Long,   // achieved reduction over the nominal power
    val energyKwh: Double,    // energy NOT consumed
    val rewardEur: Double,    // energy x reference price
    val executedAt: String,   // ISO-8601 UTC, as the VPP recorded it
)

/** The user's participation history plus the accumulated totals. */
data class ParticipationSummary(
    val records: List<ParticipationRecord>,
    val totalEnergyKwh: Double,
    val totalRewardEur: Double,
    val priceEurPerKwh: Double,
)
