package com.example.tfgvpp.presentation.screens.appliancedetail

import com.example.tfgvpp.domain.model.Appliance

data class ApplianceDetailUiState(
    val isLoading: Boolean = true,
    val appliance: Appliance? = null, // null when the user does not own it
)
