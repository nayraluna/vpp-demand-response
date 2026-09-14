package com.example.tfgvpp.presentation.screens.profile

import com.example.tfgvpp.domain.model.User

data class ProfileUiState(
    val user: User? = null,
    val loggedOut: Boolean = false, // the screen navigates back to Login on this
)
