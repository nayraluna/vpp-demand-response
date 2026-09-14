package com.example.tfgvpp.presentation.screens.home

import com.example.tfgvpp.domain.model.Appliance

data class HomeUiState(
    val isLoading: Boolean = false,
    val appliances: List<Appliance> = emptyList(), // cached; renders while refreshing
    val error: String? = null,
)
