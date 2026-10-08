package com.example.tfgvpp.domain.repository

import com.example.tfgvpp.domain.model.ParticipationSummary

interface ParticipationRepository {

    suspend fun getSummary(): Result<ParticipationSummary>
}
