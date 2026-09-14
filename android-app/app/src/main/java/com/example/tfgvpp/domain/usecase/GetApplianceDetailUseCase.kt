package com.example.tfgvpp.domain.usecase

import com.example.tfgvpp.domain.model.Appliance
import com.example.tfgvpp.domain.repository.ApplianceRepository
import javax.inject.Inject

class GetApplianceDetailUseCase @Inject constructor(
    private val appliances: ApplianceRepository,
) {
    suspend operator fun invoke(ven: String): Appliance? = appliances.getAppliance(ven)
}
