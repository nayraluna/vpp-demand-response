package com.example.tfgvpp.domain.usecase

import com.example.tfgvpp.domain.model.EidIdentity
import com.example.tfgvpp.domain.model.User
import com.example.tfgvpp.domain.repository.UserRepository
import javax.inject.Inject

class RegisterUserUseCase @Inject constructor(
    private val users: UserRepository,
) {
    suspend operator fun invoke(identity: EidIdentity?): Result<User> =
        users.register(identity)
}
