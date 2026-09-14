package com.example.tfgvpp.data.repository

import com.example.tfgvpp.data.local.SessionStore
import com.example.tfgvpp.data.remote.VppEndpoints
import com.example.tfgvpp.data.remote.appliance.PairingClient
import com.example.tfgvpp.data.remote.vpp.OperationalClient
import com.example.tfgvpp.data.security.CaProvider
import com.example.tfgvpp.di.IoDispatcher
import com.example.tfgvpp.domain.model.AlreadyPairedException
import com.example.tfgvpp.domain.model.Appliance
import com.example.tfgvpp.domain.model.OwnerProofChecks
import com.example.tfgvpp.domain.model.PairedAppliance
import com.example.tfgvpp.domain.model.PairingInfo
import com.example.tfgvpp.domain.repository.ApplianceRepository
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ApplianceRepositoryImpl @Inject constructor(
    private val sessionManager: SessionManager,
    private val store: SessionStore,
    private val ca: CaProvider,
    private val endpoints: VppEndpoints,
    @IoDispatcher private val io: CoroutineDispatcher,
) : ApplianceRepository {

    private val cache = MutableStateFlow<List<Appliance>>(emptyList())

    override val appliances: Flow<List<Appliance>> = cache.asStateFlow()

    override suspend fun refresh(): Result<List<Appliance>> = withContext(io) {
        runCatching {
            val client = OperationalClient(ca.newInputStream(), sessionManager.require())
            client.myAppliances(endpoints.mtlsUrl)
                .map { it.toAppliance() }
                .also { cache.value = it }
        }
    }

    override suspend fun getAppliance(ven: String): Appliance? {
        if (cache.value.isEmpty()) refresh()
        return cache.value.find { it.ven == ven }
    }

    override suspend fun pairWithAppliance(pairing: PairingInfo): Result<PairedAppliance> =
        withContext(io) {
            runCatching {
                // Availability declarations later reuse the appliance's URL.
                store.saveApplianceUrl(pairing.applianceUrl)
                val client = PairingClient(ca.newInputStream(), sessionManager.require())
                val p = try {
                    client.pair(
                        pairing.applianceUrl,
                        endpoints.vppUrlForAppliance,
                        endpoints.vppMtlsUrlForAppliance,
                    )
                } catch (e: IllegalStateException) {
                    if (e.message?.contains("409") == true)
                        throw AlreadyPairedException(
                            "Appliance already paired (do a factory reset)")
                    throw e
                }
                PairedAppliance(
                    venSubject = p.venSubject,
                    nominalPowerW = p.parameters["P"] ?: 0,
                    maxCurtailmentMin = p.parameters["max"] ?: 0,
                    recoveryPeriodMin = p.parameters["rec"] ?: 0,
                    ownerProofJws = p.ownerProof,
                    checks = OwnerProofChecks(
                        signatureValid = p.proofSignatureValid,
                        certChainsToRa = p.proofCertChainsToRa,
                        ownerMatches = p.proofOwnerMatches,
                        powerMatchesCertified = p.powerMatchesCertified,
                    ),
                )
            }
        }

    override suspend fun bindOwnerProof(ownerProofJws: String): Result<String> =
        withContext(io) {
            runCatching {
                val client = PairingClient(ca.newInputStream(), sessionManager.require())
                client.forwardOwnerProof(endpoints.mtlsUrl, ownerProofJws).ven
            }
        }

    override suspend fun factoryReset(pairing: PairingInfo): Result<String> =
        withContext(io) {
            runCatching { PairingClient.factoryReset(pairing.applianceUrl) }
        }
}

/** Wire appliance -> domain model. */
internal fun OperationalClient.ApplianceInfo.toAppliance() = Appliance(
    ven = ven,
    name = Appliance.nameFromVen(ven),
    nominalPowerW = nominalPower,
    maxCurtailmentMin = maxCurtail,
    recoveryPeriodMin = recovery,
    availabilityDeclared = availability != null,
    availabilityUpdatedAt = updatedAt,
)
