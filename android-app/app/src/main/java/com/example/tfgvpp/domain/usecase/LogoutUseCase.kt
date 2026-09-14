package com.example.tfgvpp.domain.usecase

import com.example.tfgvpp.domain.repository.UserRepository
import javax.inject.Inject

class LogoutUseCase @Inject constructor(
    private val users: UserRepository,
) {
    suspend operator fun invoke() = users.logout()
}
