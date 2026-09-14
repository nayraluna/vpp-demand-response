package com.example.tfgvpp.presentation.screens.profile

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.tfgvpp.domain.usecase.GetActiveUserUseCase
import com.example.tfgvpp.domain.usecase.LogoutUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class ProfileViewModel @Inject constructor(
    getActiveUser: GetActiveUserUseCase,
    private val logoutUser: LogoutUseCase,
) : ViewModel() {

    private val _uiState = MutableStateFlow(ProfileUiState())
    val uiState: StateFlow<ProfileUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            getActiveUser().collect { user ->
                _uiState.update { it.copy(user = user) }
            }
        }
    }

    fun logout() {
        viewModelScope.launch {
            logoutUser()
            _uiState.update { it.copy(loggedOut = true) }
        }
    }
}
