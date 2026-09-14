package com.example.tfgvpp.domain.usecase

import com.example.tfgvpp.domain.model.AlreadyPairedException
import com.example.tfgvpp.domain.model.Appliance
import com.example.tfgvpp.domain.model.EnrollmentProgress
import com.example.tfgvpp.domain.model.EnrollmentStep
import com.example.tfgvpp.domain.model.PairingInfo
import com.example.tfgvpp.domain.repository.ApplianceRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import javax.inject.Inject

class EnrollApplianceUseCase @Inject constructor(
    private val appliances: ApplianceRepository,
) {
    operator fun invoke(pairing: PairingInfo): Flow<EnrollmentProgress> = flow {
        emit(EnrollmentProgress.Step(EnrollmentStep.CONNECTING))
        emit(EnrollmentProgress.Step(EnrollmentStep.DELIVERING_CONFIGURATION))
        val paired = appliances.pairWithAppliance(pairing).getOrElse { e ->
            emit(failure(e, alreadyPaired = e is AlreadyPairedException))
            return@flow
        }

        emit(EnrollmentProgress.Step(EnrollmentStep.VERIFYING_OWNER_PROOF))
        if (!paired.checks.allPassed) {
            emit(EnrollmentProgress.Failure(
                "Owner proof verification failed: $paired", alreadyPaired = false))
            return@flow
        }

        emit(EnrollmentProgress.Step(EnrollmentStep.REGISTERING_AT_VPP))
        appliances.bindOwnerProof(paired.ownerProofJws).getOrElse { e ->
            emit(failure(e, alreadyPaired = false))
            return@flow
        }

        emit(EnrollmentProgress.Step(EnrollmentStep.REFRESHING))
        val list = appliances.refresh().getOrDefault(emptyList())

        // Java's RFC 2253 rendering escapes the '=' inside OU=P=<W>; the VPP's
        // RFC 4514 rendering does not. Strip escapes to match the two forms.
        val enrolled = list.find { it.ven == paired.venSubject.replace("\\", "") }
            ?: Appliance(
                ven = paired.venSubject,
                name = Appliance.nameFromVen(paired.venSubject),
                nominalPowerW = paired.nominalPowerW,
                maxCurtailmentMin = paired.maxCurtailmentMin,
                recoveryPeriodMin = paired.recoveryPeriodMin,
                availabilityDeclared = false,
                availabilityUpdatedAt = null,
            )
        emit(EnrollmentProgress.Success(enrolled, paired.checks))
    }

    private fun failure(e: Throwable, alreadyPaired: Boolean) =
        EnrollmentProgress.Failure(e.message ?: e.javaClass.simpleName, alreadyPaired)
}
