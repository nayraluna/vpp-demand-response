package com.example.tfgvpp.presentation.screens.availability

import com.example.tfgvpp.domain.model.AvailabilitySchedule

data class AvailabilityUiState(
    val isLoading: Boolean = true,
    val schedule: AvailabilitySchedule? = null,
    val isSaving: Boolean = false,
    val saved: Boolean = false,
    val error: String? = null,
)
