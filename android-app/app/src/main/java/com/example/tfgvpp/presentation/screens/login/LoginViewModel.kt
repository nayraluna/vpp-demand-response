package com.example.tfgvpp.presentation.screens.login

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.tfgvpp.domain.model.EidIdentity
import com.example.tfgvpp.domain.usecase.RegisterUserUseCase
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class LoginViewModel @Inject constructor(
    private val registerUser: RegisterUserUseCase,
) : ViewModel() {

    private val _uiState = MutableStateFlow(LoginUiState())
    val uiState: StateFlow<LoginUiState> = _uiState.asStateFlow()

    /** Called with the identity DnieLoginActivity returned (requirement U1). */
    fun onDnieIdentity(holderName: String, dni: String) {
        _uiState.update { it.copy(identity = EidIdentity(holderName, dni)) }
    }

    /** Discards the DNIe identity (register with a test identity instead). */
    fun clearIdentity() {
        _uiState.update { it.copy(identity = null) }
    }

    /** Issues the credential and enrolls at the VPP. */
    fun register() {
        if (_uiState.value.isRegistering) return
        _uiState.update { it.copy(isRegistering = true, error = null) }
        viewModelScope.launch {
            registerUser(_uiState.value.identity)
                .onSuccess { _uiState.update { it.copy(isRegistering = false, registered = true) } }
                .onFailure { e ->
                    _uiState.update {
                        it.copy(isRegistering = false, error = e.message ?: e.javaClass.simpleName)
                    }
                }
        }
    }

    fun consumeError() {
        _uiState.update { it.copy(error = null) }
    }
}
