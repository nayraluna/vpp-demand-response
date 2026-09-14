package com.example.tfgvpp.data.repository

import com.example.tfgvpp.data.remote.VppEndpoints
import com.example.tfgvpp.data.remote.vpp.OperationalClient
import com.example.tfgvpp.data.security.CaProvider
import com.example.tfgvpp.di.IoDispatcher
import com.example.tfgvpp.domain.model.ParticipationRecord
import com.example.tfgvpp.domain.model.ParticipationSummary
import com.example.tfgvpp.domain.repository.ParticipationRepository
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ParticipationRepositoryImpl @Inject constructor(
    private val sessionManager: SessionManager,
    private val ca: CaProvider,
    private val endpoints: VppEndpoints,
    @IoDispatcher private val io: CoroutineDispatcher,
) : ParticipationRepository {

    override suspend fun getSummary(): Result<ParticipationSummary> = withContext(io) {
        runCatching {
            val client = OperationalClient(ca.newInputStream(), sessionManager.require())
            val summary = client.participation(endpoints.mtlsUrl)
            ParticipationSummary(
                records = summary.participations.map {
                    ParticipationRecord(
                        activationId = it.activationId,
                        applianceVen = it.ven,
                        day = it.day,
                        interval = it.interval,
                        action = it.action,
                        reductionPct = it.reductionPct,
                        energyKwh = it.energyKwh,
                        rewardEur = it.rewardEur,
                        executedAt = it.executedAt,
                    )
                },
                totalEnergyKwh = summary.totalEnergyKwh,
                totalRewardEur = summary.totalRewardEur,
                priceEurPerKwh = summary.priceEurPerKwh,
            )
        }
    }
}
