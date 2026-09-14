package com.example.tfgvpp.presentation.screens.availability

import com.example.tfgvpp.domain.model.AvailabilitySchedule

data class AvailabilityUiState(
    val isLoading: Boolean = true,
    val schedule: AvailabilitySchedule? = null, // the 7 x 24 grid being edited
    val isSaving: Boolean = false,
    val saved: Boolean = false,
    val error: String? = null,
)
