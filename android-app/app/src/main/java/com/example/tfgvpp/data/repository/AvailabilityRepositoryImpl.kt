package com.example.tfgvpp.data.repository

import com.example.tfgvpp.data.remote.VppEndpoints
import com.example.tfgvpp.data.remote.vpp.OperationalClient
import com.example.tfgvpp.data.security.CaProvider
import com.example.tfgvpp.di.IoDispatcher
import com.example.tfgvpp.domain.model.AvailabilitySchedule
import com.example.tfgvpp.domain.repository.AvailabilityRepository
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AvailabilityRepositoryImpl @Inject constructor(
    private val sessionManager: SessionManager,
    private val ca: CaProvider,
    private val endpoints: VppEndpoints,
    @IoDispatcher private val io: CoroutineDispatcher,
) : AvailabilityRepository {

    override suspend fun getSchedule(ven: String): Result<AvailabilitySchedule> =
        withContext(io) {
            runCatching {
                val client = OperationalClient(ca.newInputStream(), sessionManager.require())
                val mine = client.myAppliances(endpoints.mtlsUrl).find { it.ven == ven }
                    ?: error("Appliance not enrolled: $ven")
                AvailabilitySchedule(
                    applianceVen = ven,
                    hours = bitmapsToHours(mine.availability),
                )
            }
        }

    override suspend fun updateSchedule(schedule: AvailabilitySchedule): Result<Unit> =
        withContext(io) {
            runCatching {
                // The owner-signed, versioned calendar goes to the VPP only;
                // the appliance retrieves it through its own outbound polling.
                val client = OperationalClient(ca.newInputStream(), sessionManager.require())
                client.declareAvailability(
                    endpoints.mtlsUrl, schedule.applianceVen, schedule.toBitmaps(),
                )
                Unit
            }
        }

    /** 1-hour grid -> 48-slot bitmaps ('1' on both halves of each hour). */
    private fun AvailabilitySchedule.toBitmaps(): Map<String, String> =
        AvailabilitySchedule.DAYS.associateWith { day ->
            val authorised = hours[day].orEmpty()
            buildString(OperationalClient.SLOTS_PER_DAY) {
                for (slot in 0 until OperationalClient.SLOTS_PER_DAY)
                    append(if (slot / 2 in authorised) '1' else '0')
            }
        }

    /** 48-slot bitmaps -> 1-hour grid (an hour is set if either half is). */
    private fun bitmapsToHours(bitmaps: Map<String, String>?): Map<String, Set<Int>> =
        AvailabilitySchedule.DAYS.associateWith { day ->
            val bitmap = bitmaps?.get(day) ?: return@associateWith emptySet()
            (0..23).filter { h ->
                bitmap.getOrNull(2 * h) == '1' || bitmap.getOrNull(2 * h + 1) == '1'
            }.toSet()
        }
}
