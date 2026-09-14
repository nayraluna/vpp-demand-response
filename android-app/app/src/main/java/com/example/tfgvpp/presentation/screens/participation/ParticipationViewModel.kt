package com.example.tfgvpp.presentation.screens.participation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.tfgvpp.domain.usecase.GetParticipationHistoryUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class ParticipationViewModel @Inject constructor(
    private val getParticipationHistory: GetParticipationHistoryUseCase,
) : ViewModel() {

    private val _uiState = MutableStateFlow(ParticipationUiState())
    val uiState: StateFlow<ParticipationUiState> = _uiState.asStateFlow()

    init {
        refresh()
    }

    /** Re-reads the history from the VPP. */
    fun refresh() {
        _uiState.value = ParticipationUiState(isLoading = true)
        viewModelScope.launch {
            getParticipationHistory()
                .onSuccess { summary ->
                    _uiState.value = ParticipationUiState(isLoading = false, summary = summary)
                }
                .onFailure { e ->
                    _uiState.value = ParticipationUiState(
                        isLoading = false, error = e.message ?: e.javaClass.simpleName)
                }
        }
    }
}
