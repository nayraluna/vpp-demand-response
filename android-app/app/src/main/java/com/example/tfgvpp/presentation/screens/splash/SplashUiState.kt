package com.example.tfgvpp.presentation.screens.splash

data class SplashUiState(
    val destination: Destination? = null,
) {
    enum class Destination { LOGIN, HOME }
}
