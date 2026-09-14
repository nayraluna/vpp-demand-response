package com.example.tfgvpp.presentation.screens.login

import com.example.tfgvpp.domain.model.EidIdentity

data class LoginUiState(
    val identity: EidIdentity? = null, // proven by the DNIe login, if it ran
    val isRegistering: Boolean = false,
    val registered: Boolean = false,   // the screen navigates to Home on this
    val error: String? = null,
)
