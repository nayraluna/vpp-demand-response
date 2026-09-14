package com.example.tfgvpp.presentation.screens.pairing

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.tfgvpp.R
import com.example.tfgvpp.domain.model.EnrollmentStep
import com.example.tfgvpp.domain.model.OwnerProofChecks
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PairingScreen(
    onBack: () -> Unit,
    viewModel: PairingViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val scanPrompt = stringResource(R.string.pairing_scan_prompt)

    val qrLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        viewModel.onQrScanned(result.contents)
    }

    if (uiState.resetDone) {
        val message = stringResource(R.string.pairing_reset_done)
        LaunchedEffect(Unit) {
            snackbarHostState.showSnackbar(message)
            viewModel.consumeResetDone()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.pairing_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack,
                            stringResource(R.string.common_back))
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            when (uiState.phase) {
                PairingUiState.Phase.IDLE -> IdleContent(
                    onScan = {
                        qrLauncher.launch(
                            ScanOptions()
                                .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                .setPrompt(scanPrompt)
                                .setBeepEnabled(false)
                                .setOrientationLocked(true)
                        )
                    },
                    onUseDevAppliance = viewModel::useDevelopmentAppliance,
                )

                PairingUiState.Phase.RUNNING -> StepList(uiState)

                PairingUiState.Phase.SUCCESS -> SuccessContent(uiState, onDone = onBack)

                PairingUiState.Phase.ERROR -> ErrorContent(
                    uiState,
                    onRetry = viewModel::retry,
                    onFactoryReset = viewModel::factoryReset,
                )
            }
        }
    }
}

@Composable
private fun IdleContent(onScan: () -> Unit, onUseDevAppliance: () -> Unit) {
    Spacer(Modifier.height(24.dp))
    Surface(
        shape = RoundedCornerShape(24.dp),
        color = MaterialTheme.colorScheme.primaryContainer,
    ) {
        Icon(
            painter = painterResource(R.drawable.ic_qr_scan),
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onPrimaryContainer,
            modifier = Modifier.padding(24.dp).size(48.dp),
        )
    }
    Spacer(Modifier.height(24.dp))
    Text(
        text = stringResource(R.string.pairing_explanation),
        style = MaterialTheme.typography.bodyLarge,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(32.dp))
    Button(
        onClick = onScan,
        modifier = Modifier.fillMaxWidth().height(52.dp),
    ) {
        Text(stringResource(R.string.pairing_scan))
    }
    Spacer(Modifier.height(8.dp))
    OutlinedButton(
        onClick = onUseDevAppliance,
        modifier = Modifier.fillMaxWidth().height(52.dp),
    ) {
        Text(stringResource(R.string.pairing_dev_appliance))
    }
}

@Composable
private fun StepList(uiState: PairingUiState) {
    Column(
        Modifier.fillMaxWidth().padding(top = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        EnrollmentStep.entries.forEach { step ->
            val done = step in uiState.completedSteps
            val current = step == uiState.currentStep
            Row(verticalAlignment = Alignment.CenterVertically) {
                when {
                    done -> Icon(
                        Icons.Default.Check, null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp),
                    )
                    current -> CircularProgressIndicator(
                        modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                    // Pending steps stay visible as a dot.
                    else -> Box(
                        Modifier
                            .size(10.dp)
                            .clip(CircleShape)
                            .background(MaterialTheme.colorScheme.surfaceVariant)
                    )
                }
                Spacer(Modifier.width(if (done || current) 12.dp else 17.dp))
                Text(
                    stepLabel(step),
                    style = MaterialTheme.typography.bodyLarge,
                    color = when {
                        current -> MaterialTheme.colorScheme.onSurface
                        done -> MaterialTheme.colorScheme.onSurface
                        else -> MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
            }
        }
    }
}

@Composable
private fun SuccessContent(uiState: PairingUiState, onDone: () -> Unit) {
    Spacer(Modifier.height(16.dp))
    Surface(shape = CircleShape, color = MaterialTheme.colorScheme.primaryContainer) {
        Icon(
            Icons.Default.CheckCircle, null,
            tint = MaterialTheme.colorScheme.onPrimaryContainer,
            modifier = Modifier.padding(16.dp).size(48.dp),
        )
    }
    Spacer(Modifier.height(16.dp))
    Text(
        stringResource(R.string.pairing_success),
        style = MaterialTheme.typography.headlineSmall,
    )
    uiState.enrolled?.let { appliance ->
        Spacer(Modifier.height(4.dp))
        Text(appliance.name, style = MaterialTheme.typography.titleMedium)
        Text(
            stringResource(R.string.home_power_format, appliance.nominalPowerW),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    uiState.checks?.let { checks ->
        Spacer(Modifier.height(24.dp))
        ChecksCard(checks)
    }
    Spacer(Modifier.height(24.dp))
    Button(onClick = onDone, modifier = Modifier.fillMaxWidth().height(52.dp)) {
        Text(stringResource(R.string.pairing_done))
    }
}

@Composable
private fun ChecksCard(checks: OwnerProofChecks) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                stringResource(R.string.pairing_checks_title),
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            CheckRow(stringResource(R.string.check_signature), checks.signatureValid)
            CheckRow(stringResource(R.string.check_chain), checks.certChainsToRa)
            CheckRow(stringResource(R.string.check_owner), checks.ownerMatches)
            CheckRow(stringResource(R.string.check_power), checks.powerMatchesCertified)
        }
    }
}

@Composable
private fun CheckRow(label: String, passed: Boolean) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(
            if (passed) Icons.Default.Check else Icons.Default.Close,
            contentDescription = null,
            tint = if (passed) MaterialTheme.colorScheme.primary
            else MaterialTheme.colorScheme.error,
            modifier = Modifier.size(18.dp),
        )
        Spacer(Modifier.width(8.dp))
        Text(label, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun ErrorContent(
    uiState: PairingUiState,
    onRetry: () -> Unit,
    onFactoryReset: () -> Unit,
) {
    Spacer(Modifier.height(16.dp))
    Surface(shape = CircleShape, color = MaterialTheme.colorScheme.errorContainer) {
        Icon(
            Icons.Default.Close, null,
            tint = MaterialTheme.colorScheme.onErrorContainer,
            modifier = Modifier.padding(16.dp).size(48.dp),
        )
    }
    Spacer(Modifier.height(16.dp))
    Text(
        stringResource(R.string.pairing_error_title),
        style = MaterialTheme.typography.headlineSmall,
    )
    Spacer(Modifier.height(12.dp))
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Text(
            uiState.error ?: "",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onErrorContainer,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth().padding(16.dp),
        )
    }
    Spacer(Modifier.height(24.dp))
    if (uiState.alreadyPaired) {
        Button(onClick = onFactoryReset, modifier = Modifier.fillMaxWidth().height(52.dp)) {
            Text(stringResource(R.string.pairing_factory_reset))
        }
        Spacer(Modifier.height(8.dp))
    }
    OutlinedButton(onClick = onRetry, modifier = Modifier.fillMaxWidth().height(52.dp)) {
        Text(stringResource(R.string.common_retry))
    }
}

@Composable
private fun stepLabel(step: EnrollmentStep): String = stringResource(
    when (step) {
        EnrollmentStep.CONNECTING -> R.string.pairing_step_connecting
        EnrollmentStep.DELIVERING_CONFIGURATION -> R.string.pairing_step_delivering
        EnrollmentStep.VERIFYING_OWNER_PROOF -> R.string.pairing_step_verifying
        EnrollmentStep.REGISTERING_AT_VPP -> R.string.pairing_step_registering
        EnrollmentStep.REFRESHING -> R.string.pairing_step_refreshing
    }
)
