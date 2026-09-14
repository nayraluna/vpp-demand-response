package com.example.tfgvpp.presentation.screens.appliancedetail

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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.DateRange
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.tfgvpp.R
import com.example.tfgvpp.presentation.ui.readableLocalTime

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ApplianceDetailScreen(
    onBack: () -> Unit,
    onEditAvailability: (String) -> Unit,
    viewModel: ApplianceDetailViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.detail_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack,
                            stringResource(R.string.common_back))
                    }
                },
            )
        },
    ) { padding ->
        val appliance = uiState.appliance
        when {
            uiState.isLoading -> Box(
                Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center,
            ) { CircularProgressIndicator() }

            appliance == null -> Box(
                Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center,
            ) { Text(stringResource(R.string.detail_not_found)) }

            else -> Column(
                Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Surface(
                        shape = RoundedCornerShape(14.dp),
                        color = MaterialTheme.colorScheme.primaryContainer,
                    ) {
                        Icon(
                            painter = painterResource(R.drawable.ic_bolt),
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onPrimaryContainer,
                            modifier = Modifier.padding(12.dp).size(28.dp),
                        )
                    }
                    Spacer(Modifier.width(16.dp))
                    Column {
                        Text(appliance.name, style = MaterialTheme.typography.headlineSmall)
                        Text(
                            stringResource(R.string.detail_certified_caption),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }

                // One card for the certified parameters: they are read-only and
                // belong together, so dividers group them better than 5 cards.
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(vertical = 4.dp)) {
                        ParameterRow(
                            label = stringResource(R.string.detail_ven),
                            value = appliance.ven,
                        )
                        RowDivider()
                        ParameterRow(
                            label = stringResource(R.string.detail_power),
                            value = stringResource(
                                R.string.detail_power_value, appliance.nominalPowerW),
                        )
                        RowDivider()
                        ParameterRow(
                            label = stringResource(R.string.detail_max_curtail),
                            value = stringResource(
                                R.string.detail_minutes_value, appliance.maxCurtailmentMin),
                        )
                        RowDivider()
                        ParameterRow(
                            label = stringResource(R.string.detail_recovery),
                            value = stringResource(
                                R.string.detail_minutes_value, appliance.recoveryPeriodMin),
                        )
                        RowDivider()
                        ParameterRow(
                            label = stringResource(R.string.detail_availability),
                            value = if (appliance.availabilityDeclared)
                                stringResource(R.string.home_availability_declared) +
                                        (appliance.availabilityUpdatedAt
                                            ?.let { " (${readableLocalTime(it)})" } ?: "")
                            else stringResource(R.string.home_availability_missing),
                            highlight = appliance.availabilityDeclared,
                        )
                    }
                }

                Button(
                    onClick = { onEditAvailability(appliance.ven) },
                    modifier = Modifier.fillMaxWidth().height(52.dp),
                ) {
                    Icon(
                        Icons.Default.DateRange,
                        contentDescription = null,
                        modifier = Modifier.size(ButtonDefaults.IconSize),
                    )
                    Spacer(Modifier.width(ButtonDefaults.IconSpacing))
                    Text(stringResource(R.string.detail_availability_button))
                }
            }
        }
    }
}

@Composable
private fun ParameterRow(label: String, value: String, highlight: Boolean = false) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp)) {
        Text(
            label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            value,
            style = MaterialTheme.typography.bodyLarge,
            color = if (highlight) MaterialTheme.colorScheme.primary
            else MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Composable
private fun RowDivider() {
    HorizontalDivider(
        modifier = Modifier.padding(horizontal = 16.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
    )
}
