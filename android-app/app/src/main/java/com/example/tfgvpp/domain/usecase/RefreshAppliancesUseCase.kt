package com.example.tfgvpp.domain.usecase

import com.example.tfgvpp.domain.model.Appliance
import com.example.tfgvpp.domain.repository.ApplianceRepository
import javax.inject.Inject

class RefreshAppliancesUseCase @Inject constructor(
    private val appliances: ApplianceRepository,
) {
    suspend operator fun invoke(): Result<List<Appliance>> = appliances.refresh()
}
