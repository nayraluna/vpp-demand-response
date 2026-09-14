package com.example.tfgvpp.domain.usecase

import com.example.tfgvpp.domain.model.AvailabilitySchedule
import com.example.tfgvpp.domain.repository.AvailabilityRepository
import javax.inject.Inject

class UpdateAvailabilityUseCase @Inject constructor(
    private val availability: AvailabilityRepository,
) {
    suspend operator fun invoke(schedule: AvailabilitySchedule): Result<Unit> =
        availability.updateSchedule(schedule)
}
