package com.example.tfgvpp.presentation.screens.participation

import com.example.tfgvpp.domain.model.ParticipationSummary

data class ParticipationUiState(
    val isLoading: Boolean = true,
    val summary: ParticipationSummary? = null,
    val error: String? = null,
)
