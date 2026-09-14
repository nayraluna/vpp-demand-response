package com.example.tfgvpp.presentation.screens.home

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.tfgvpp.domain.usecase.GetAppliancesUseCase
import com.example.tfgvpp.domain.usecase.RefreshAppliancesUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class HomeViewModel @Inject constructor(
    getAppliances: GetAppliancesUseCase,
    private val refreshAppliances: RefreshAppliancesUseCase,
) : ViewModel() {

    private val _uiState = MutableStateFlow(HomeUiState())
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            getAppliances().collect { list ->
                _uiState.update { it.copy(appliances = list) }
            }
        }
        refresh()
    }

    /** Re-reads the list from the VPP over mutual TLS. */
    fun refresh() {
        if (_uiState.value.isLoading) return
        _uiState.update { it.copy(isLoading = true, error = null) }
        viewModelScope.launch {
            refreshAppliances()
                .onSuccess { _uiState.update { it.copy(isLoading = false) } }
                .onFailure { e ->
                    _uiState.update {
                        it.copy(isLoading = false, error = e.message ?: e.javaClass.simpleName)
                    }
                }
        }
    }

    fun consumeError() {
        _uiState.update { it.copy(error = null) }
    }
}
