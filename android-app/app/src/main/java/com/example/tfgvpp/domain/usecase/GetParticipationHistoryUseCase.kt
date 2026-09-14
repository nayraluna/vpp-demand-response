package com.example.tfgvpp.domain.usecase

import com.example.tfgvpp.domain.model.ParticipationSummary
import com.example.tfgvpp.domain.repository.ParticipationRepository
import javax.inject.Inject

class GetParticipationHistoryUseCase @Inject constructor(
    private val participation: ParticipationRepository,
) {
    suspend operator fun invoke(): Result<ParticipationSummary> =
        participation.getSummary()
}
