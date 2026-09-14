package com.example.tfgvpp.data.repository

import com.example.tfgvpp.data.remote.VppEndpoints
import com.example.tfgvpp.data.remote.vpp.RegistrationClient
import com.example.tfgvpp.data.security.CaProvider
import com.example.tfgvpp.data.security.KeystoreCredentials
import com.example.tfgvpp.di.IoDispatcher
import com.example.tfgvpp.domain.model.EidIdentity
import com.example.tfgvpp.domain.model.User
import com.example.tfgvpp.domain.repository.UserRepository
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class UserRepositoryImpl @Inject constructor(
    private val sessionManager: SessionManager,
    private val keystore: KeystoreCredentials,
    private val ca: CaProvider,
    private val endpoints: VppEndpoints,
    @IoDispatcher private val io: CoroutineDispatcher,
) : UserRepository {

    override val activeUser: Flow<User?> =
        sessionManager.session.map { it?.toUser() }

    override suspend fun restoreSession(): User? = withContext(io) {
        sessionManager.restore()?.toUser()
    }

    override suspend fun register(identity: EidIdentity?): Result<User> =
        withContext(io) {
            runCatching {
                // The certified CN is the real DNI after a DNIe login (U1);
                // otherwise a throwaway test identity (the emulator has no NFC).
                // TODO(TFG): pseudonymous CN — certify a derived identifier
                // instead of the raw DNI, keeping the DNI only at the RA.
                val cn = identity?.dni
                    ?: ("android-" + List(6) { "0123456789abcdef".random() }.joinToString(""))
                val client = RegistrationClient(ca.newInputStream())
                val registration = client.register(
                    cn, endpoints.raUrl, endpoints.baseUrl, keystore.generateKeyPair())
                sessionManager.activate(registration, identity).toUser()
            }
        }

    override suspend fun logout() = withContext(io) {
        sessionManager.clear()
    }
}
