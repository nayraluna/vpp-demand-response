package com.example.tfgvpp.domain.repository

import com.example.tfgvpp.domain.model.AvailabilitySchedule

interface AvailabilityRepository {

    /** Empty if none declared yet. */
    suspend fun getSchedule(ven: String): Result<AvailabilitySchedule>

    suspend fun updateSchedule(schedule: AvailabilitySchedule): Result<Unit>
}
