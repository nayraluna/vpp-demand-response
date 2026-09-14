package com.example.tfgvpp.presentation.screens.appliancedetail

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.tfgvpp.domain.usecase.GetApplianceDetailUseCase
import com.example.tfgvpp.presentation.navigation.Route
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class ApplianceDetailViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val getApplianceDetail: GetApplianceDetailUseCase,
) : ViewModel() {

    /** VEN subject from the route (Navigation already URL-decoded it). */
    val ven: String = checkNotNull(savedStateHandle[Route.ARG_VEN])

    private val _uiState = MutableStateFlow(ApplianceDetailUiState())
    val uiState: StateFlow<ApplianceDetailUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            val appliance = runCatching { getApplianceDetail(ven) }.getOrNull()
            _uiState.value = ApplianceDetailUiState(isLoading = false, appliance = appliance)
        }
    }
}
