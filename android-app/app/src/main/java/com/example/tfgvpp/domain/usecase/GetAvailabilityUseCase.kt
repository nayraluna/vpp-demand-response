package com.example.tfgvpp.domain.usecase

import com.example.tfgvpp.domain.model.AvailabilitySchedule
import com.example.tfgvpp.domain.repository.AvailabilityRepository
import javax.inject.Inject

class GetAvailabilityUseCase @Inject constructor(
    private val availability: AvailabilityRepository,
) {
    suspend operator fun invoke(ven: String): Result<AvailabilitySchedule> =
        availability.getSchedule(ven)
}
