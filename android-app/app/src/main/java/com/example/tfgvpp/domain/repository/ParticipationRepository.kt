package com.example.tfgvpp.domain.repository

import com.example.tfgvpp.domain.model.ParticipationSummary

interface ParticipationRepository {

    /** History plus accumulated totals, over mutual TLS. */
    suspend fun getSummary(): Result<ParticipationSummary>
}
