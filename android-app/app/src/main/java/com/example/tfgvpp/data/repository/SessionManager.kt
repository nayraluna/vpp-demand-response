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
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class SessionManager @Inject constructor(
    private val store: SessionStore,
    private val keystore: KeystoreCredentials,
    private val ca: CaProvider,
) {
    /** The live session: real credential plus the DNIe attributes, if any. */
    data class ActiveSession(
        val registration: RegistrationClient.Registration,
        val holderName: String?,
        val dni: String?,
    )

    private val _session = MutableStateFlow<ActiveSession?>(null)
    val session: StateFlow<ActiveSession?> = _session.asStateFlow()

    /** The current session, or null; repositories that REQUIRE one use [require]. */
    fun current(): ActiveSession? = _session.value

    /** The current registration, failing with a readable message without one. */
    fun require(): RegistrationClient.Registration =
        current()?.registration ?: error("No session: register first")

    /** Rebuilds the persisted session, or null if nothing (usable) was stored. */
    suspend fun restore(): ActiveSession? {
        _session.value?.let { return it }
        val persisted = store.load() ?: return null
        val privateKey = keystore.loadPrivateKey() ?: return null

        val cf = CertificateFactory.getInstance("X.509")
        val userCert = cf.generateCertificate(
            persisted.userCertPem.byteInputStream()) as X509Certificate
        val vppCert = cf.generateCertificate(
            persisted.vppCertPem.byteInputStream()) as X509Certificate

        val credential = RegistrationClient.UserCredential(
            privateKey, userCert, persisted.userCertPem)
        val registration = RegistrationClient.Registration(
            credential = credential,
            subject = credential.subject,
            raSerial = persisted.raSerial,
            userCertChainsToRa = chainsToRa(userCert),
            enrollStatus = persisted.enrollStatus,
            vppCertificatePem = persisted.vppCertPem,
            vppCertChainsToRa = chainsToRa(vppCert),
        )
        return ActiveSession(registration, persisted.holderName, persisted.dni)
            .also { _session.value = it }
    }

    /** Persists and activates a fresh registration. */
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

    /** Forgets everything: DataStore, Keystore entry, in-memory state. */
    suspend fun clear() {
        store.clear()
        keystore.clear()
        _session.value = null
    }

    private fun chainsToRa(cert: X509Certificate): Boolean =
        try { cert.verify(ca.certificate.publicKey); true } catch (e: Exception) { false }
}

/** [User] as the presentation layer sees the active session. */
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
