package com.example.tfgvpp.domain.usecase

import com.example.tfgvpp.domain.model.PairingInfo
import com.example.tfgvpp.domain.repository.ApplianceRepository
import javax.inject.Inject

class FactoryResetApplianceUseCase @Inject constructor(
    private val appliances: ApplianceRepository,
) {
    suspend operator fun invoke(pairing: PairingInfo): Result<String> =
        appliances.factoryReset(pairing)
}
