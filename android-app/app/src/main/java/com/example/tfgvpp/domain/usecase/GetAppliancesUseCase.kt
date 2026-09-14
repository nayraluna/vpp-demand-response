package com.example.tfgvpp.domain.usecase

import com.example.tfgvpp.domain.model.Appliance
import com.example.tfgvpp.domain.repository.ApplianceRepository
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class GetAppliancesUseCase @Inject constructor(
    private val appliances: ApplianceRepository,
) {
    operator fun invoke(): Flow<List<Appliance>> = appliances.appliances
}
