package com.example.tfgvpp.presentation.screens.splash

data class SplashUiState(
    val destination: Destination? = null,
) {
    /** Routing decision after trying to restore the persisted session. */
    enum class Destination { LOGIN, HOME }
}
