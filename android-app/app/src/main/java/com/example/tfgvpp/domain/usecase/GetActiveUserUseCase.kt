package com.example.tfgvpp.domain.usecase

import com.example.tfgvpp.domain.model.User
import com.example.tfgvpp.domain.repository.UserRepository
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class GetActiveUserUseCase @Inject constructor(
    private val users: UserRepository,
) {
    operator fun invoke(): Flow<User?> = users.activeUser
}
