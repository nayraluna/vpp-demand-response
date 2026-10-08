package com.example.tfgvpp.domain.repository

import com.example.tfgvpp.domain.model.Appliance
import com.example.tfgvpp.domain.model.PairedAppliance
import com.example.tfgvpp.domain.model.PairingInfo
import kotlinx.coroutines.flow.Flow

interface ApplianceRepository {

    val appliances: Flow<List<Appliance>>

    suspend fun refresh(): Result<List<Appliance>>

    /** From the cache, refreshing first if it is empty. */
    suspend fun getAppliance(ven: String): Appliance?

    /** Signs the bundle, delivers it to the appliance and verifies the owner proof; [AlreadyPairedException] on 409. */
    suspend fun pairWithAppliance(pairing: PairingInfo): Result<PairedAppliance>

    /** Forwards the owner proof over mutual TLS; the VPP binds the appliance to the channel identity. Returns the VEN subject. */
    suspend fun bindOwnerProof(ownerProofJws: String): Result<String>

    suspend fun factoryReset(pairing: PairingInfo): Result<String>
}
