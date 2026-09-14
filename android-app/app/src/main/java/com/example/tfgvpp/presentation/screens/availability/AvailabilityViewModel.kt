package com.example.tfgvpp.presentation.screens.availability

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.tfgvpp.domain.model.AvailabilitySchedule
import com.example.tfgvpp.domain.usecase.GetAvailabilityUseCase
import com.example.tfgvpp.domain.usecase.UpdateAvailabilityUseCase
import com.example.tfgvpp.presentation.navigation.Route
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class AvailabilityViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val getAvailability: GetAvailabilityUseCase,
    private val updateAvailability: UpdateAvailabilityUseCase,
) : ViewModel() {

    private val ven: String = checkNotNull(savedStateHandle[Route.ARG_VEN])

    private val _uiState = MutableStateFlow(AvailabilityUiState())
    val uiState: StateFlow<AvailabilityUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            getAvailability(ven)
                .onSuccess { schedule ->
                    _uiState.update { it.copy(isLoading = false, schedule = schedule) }
                }
                .onFailure { e ->
                    // Editing starts from an empty grid if the fetch failed.
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            schedule = AvailabilitySchedule.empty(ven),
                            error = e.message ?: e.javaClass.simpleName,
                        )
                    }
                }
        }
    }

    /** Flips one hour cell of the grid. */
    fun toggle(day: String, hour: Int) {
        _uiState.update { state ->
            state.copy(schedule = state.schedule?.toggled(day, hour))
        }
    }

    /** Sets one cell to a fixed value; drag-to-paint calls this per cell crossed. */
    fun paint(day: String, hour: Int, available: Boolean) {
        _uiState.update { state ->
            state.copy(schedule = state.schedule?.withHour(day, hour, available))
        }
    }

    /** Fills the whole day, or clears it when every hour was already set. */
    fun toggleDay(day: String) {
        _uiState.update { state ->
            state.copy(schedule = state.schedule?.dayToggled(day))
        }
    }

    /** Declares the calendar at the VPP, signed with the user's credential. */
    fun save() {
        val schedule = _uiState.value.schedule ?: return
        if (_uiState.value.isSaving) return
        _uiState.update { it.copy(isSaving = true, error = null) }
        viewModelScope.launch {
            updateAvailability(schedule)
                .onSuccess { _uiState.update { it.copy(isSaving = false, saved = true) } }
                .onFailure { e ->
                    _uiState.update {
                        it.copy(isSaving = false, error = e.message ?: e.javaClass.simpleName)
                    }
                }
        }
    }

    fun consumeSaved() {
        _uiState.update { it.copy(saved = false) }
    }

    fun consumeError() {
        _uiState.update { it.copy(error = null) }
    }
}
