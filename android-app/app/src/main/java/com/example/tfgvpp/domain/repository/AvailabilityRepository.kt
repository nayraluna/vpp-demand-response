package com.example.tfgvpp.domain.repository

import com.example.tfgvpp.domain.model.AvailabilitySchedule

interface AvailabilityRepository {

    /** The calendar currently declared for [ven], empty if none yet. */
    suspend fun getSchedule(ven: String): Result<AvailabilitySchedule>

    suspend fun updateSchedule(schedule: AvailabilitySchedule): Result<Unit>
}
