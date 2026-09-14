package com.example.tfgvpp.domain.usecase

import com.example.tfgvpp.domain.model.User
import com.example.tfgvpp.domain.repository.UserRepository
import javax.inject.Inject

class RestoreSessionUseCase @Inject constructor(
    private val users: UserRepository,
) {
    suspend operator fun invoke(): User? = users.restoreSession()
}
