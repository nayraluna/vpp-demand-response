package com.example.tfgvpp.domain.repository

import com.example.tfgvpp.domain.model.EidIdentity
import com.example.tfgvpp.domain.model.User
import kotlinx.coroutines.flow.Flow

interface UserRepository {

    /** The active user, or null while nobody is registered. */
    val activeUser: Flow<User?>

    /**
     * Rebuilds the session persisted on a previous run (certificates from
     * DataStore, private key from the Keystore). Returns the restored user or
     * null if nothing was persisted -- the splash screen routes on this.
     */
    suspend fun restoreSession(): User?

    /**
     * Registers the user: key pair -> CSR -> RA-issued certificate -> enroll
     * at the VPP. With a DNIe [identity] the certified CN is the real DNI
     * (requirement U1); without one a throwaway test identity is used (the
     * emulator has no NFC).
     */
    suspend fun register(identity: EidIdentity?): Result<User>

    /** Forgets the credential: DataStore, Keystore entry and in-memory state. */
    suspend fun logout()
}
