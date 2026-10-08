package com.example.tfgvpp.domain.model

data class ParticipationRecord(
    val activationId: String,
    val applianceVen: String,
    val day: String,          // "mon".."sun"
    val interval: String,
    val action: String,       // "reduce" | "shutdown"
    val reductionPct: Long,
    val energyKwh: Double,
    val rewardEur: Double,
    val executedAt: String,   // ISO-8601 UTC
)

data class ParticipationSummary(
    val records: List<ParticipationRecord>,
    val totalEnergyKwh: Double,
    val totalRewardEur: Double,
    val priceEurPerKwh: Double,
)
