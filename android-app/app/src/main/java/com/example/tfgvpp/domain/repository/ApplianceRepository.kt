package com.example.tfgvpp.domain.repository

import com.example.tfgvpp.domain.model.Appliance
import com.example.tfgvpp.domain.model.PairedAppliance
import com.example.tfgvpp.domain.model.PairingInfo
import kotlinx.coroutines.flow.Flow

interface ApplianceRepository {

    /** Cached list of enrolled appliances; refreshed by [refresh]. */
    val appliances: Flow<List<Appliance>>

    /** Re-reads the appliance list from the VPP over mutual TLS. */
    suspend fun refresh(): Result<List<Appliance>>

    /** One appliance from the cache (refreshing first if it is empty). */
    suspend fun getAppliance(ven: String): Appliance?

    /**
     * Registration step 8b: signs the configuration bundle with the user's
     * credential, delivers it to the appliance's local pairing service and
     * verifies the owner proof it answers with. Fails with
     * [com.example.tfgvpp.domain.model.AlreadyPairedException] if the
     * appliance is already configured.
     */
    suspend fun pairWithAppliance(pairing: PairingInfo): Result<PairedAppliance>

    /**
     * Registration step 8c: forwards the owner proof to the VPP over mutual
     * TLS; the VPP checks proof.owner == channel identity and binds the
     * appliance to the user. Returns the bound VEN identity.
     */
    suspend fun bindOwnerProof(ownerProofJws: String): Result<String>

    /** Dev/demo helper: returns the appliance to its unconfigured state. */
    suspend fun factoryReset(pairing: PairingInfo): Result<String>
}
