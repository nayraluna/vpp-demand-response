package com.example.tfgvpp.domain.repository

import com.example.tfgvpp.domain.model.EidIdentity
import com.example.tfgvpp.domain.model.User
import kotlinx.coroutines.flow.Flow

interface UserRepository {

    val activeUser: Flow<User?>

    suspend fun restoreSession(): User?

    /** With a DNIe [identity] the certified CN is the DNI; without one, a throwaway test identity. */
    suspend fun register(identity: EidIdentity?): Result<User>

    suspend fun logout()
}
