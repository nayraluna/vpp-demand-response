package com.example.tfgvpp.presentation.screens.login

import com.example.tfgvpp.domain.model.EidIdentity

data class LoginUiState(
    val identity: EidIdentity? = null,
    val isRegistering: Boolean = false,
    val registered: Boolean = false,
    val error: String? = null,
)
