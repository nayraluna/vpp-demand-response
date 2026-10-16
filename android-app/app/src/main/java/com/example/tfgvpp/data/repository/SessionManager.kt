package com.example.tfgvpp.data.repository

import com.example.tfgvpp.data.local.SessionStore
import com.example.tfgvpp.data.remote.vpp.RegistrationClient
import com.example.tfgvpp.data.security.CaProvider
import com.example.tfgvpp.data.security.KeystoreCredentials
import com.example.tfgvpp.domain.model.CertificateStatus
import com.example.tfgvpp.domain.model.EidIdentity
import com.example.tfgvpp.domain.model.User
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class SessionManager @Inject constructor(
    private val store: SessionStore,
    private val keystore: KeystoreCredentials,
    private val ca: CaProvider,
) {
    data class ActiveSession(
        val registration: RegistrationClient.Registration,
        val holderName: String?,
        val dni: String?,
    )

    private val _session = MutableStateFlow<ActiveSession?>(null)
    val session: StateFlow<ActiveSession?> = _session.asStateFlow()

    fun current(): ActiveSession? = _session.value

    /** The current registration; fails with a readable message without one. */
    fun require(): RegistrationClient.Registration =
        current()?.registration ?: error("No session: register first")

    suspend fun restore(): ActiveSession? {
        _session.value?.let { return it }
        val persisted = store.load() ?: return null
        val privateKey = keystore.loadPrivateKey() ?: return null

        val userChain = RegistrationClient.parseChain(persisted.userCertPem)
        val vppChain = RegistrationClient.parseChain(persisted.vppCertPem)

        val credential = RegistrationClient.UserCredential(
            privateKey, userChain.first(), persisted.userCertPem)
        val registration = RegistrationClient.Registration(
            credential = credential,
            subject = credential.subject,
            raSerial = persisted.raSerial,
            userCertChainsToRa = RegistrationClient.validatesToRoot(userChain, ca.certificate),
            enrollStatus = persisted.enrollStatus,
            vppCertificatePem = persisted.vppCertPem,
            vppCertChainsToRa = RegistrationClient.validatesToRoot(vppChain, ca.certificate),
        )
        return ActiveSession(registration, persisted.holderName, persisted.dni)
            .also { _session.value = it }
    }

    suspend fun activate(
        registration: RegistrationClient.Registration, identity: EidIdentity?,
    ): ActiveSession {
        store.save(SessionStore.PersistedSession(
            userCertPem = registration.credential.certificatePem,
            vppCertPem = registration.vppCertificatePem,
            raSerial = registration.raSerial,
            enrollStatus = registration.enrollStatus,
            holderName = identity?.holderName,
            dni = identity?.dni,
        ))
        return ActiveSession(registration, identity?.holderName, identity?.dni)
            .also { _session.value = it }
    }

    suspend fun clear() {
        store.clear()
        keystore.clear()
        _session.value = null
    }
}

fun SessionManager.ActiveSession.toUser(): User = User(
    subject = registration.subject,
    commonName = registration.subject.removePrefix("CN="),
    holderName = holderName,
    dni = dni,
    raSerial = registration.raSerial,
    enrollStatus = registration.enrollStatus,
    certificateStatus =
        if (registration.userCertChainsToRa && registration.vppCertChainsToRa)
            CertificateStatus.VALID
        else CertificateStatus.INVALID,
)
