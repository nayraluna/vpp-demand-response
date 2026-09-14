package com.example.tfgvpp.presentation.screens.availability

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGesturesAfterLongPress
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.tfgvpp.R
import com.example.tfgvpp.domain.model.AvailabilitySchedule
import kotlin.math.floor

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AvailabilityScreen(
    onBack: () -> Unit,
    viewModel: AvailabilityViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    if (uiState.saved) {
        val message = stringResource(R.string.availability_saved)
        LaunchedEffect(Unit) {
            snackbarHostState.showSnackbar(message)
            viewModel.consumeSaved()
        }
    }
    uiState.error?.let { error ->
        val message = stringResource(R.string.error_generic, error)
        LaunchedEffect(error) {
            snackbarHostState.showSnackbar(message)
            viewModel.consumeError()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.availability_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack,
                            stringResource(R.string.common_back))
                    }
                },
            )
        },
        floatingActionButton = {
            if (!uiState.isLoading) {
                FloatingActionButton(onClick = viewModel::save) {
                    if (uiState.isSaving) {
                        CircularProgressIndicator(
                            modifier = Modifier.width(24.dp).height(24.dp),
                            strokeWidth = 2.dp,
                        )
                    } else {
                        Icon(Icons.Default.Check, stringResource(R.string.availability_save))
                    }
                }
            }
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        val schedule = uiState.schedule
        if (uiState.isLoading || schedule == null) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
        } else {
            Column(
                Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(horizontal = 16.dp)
                    .verticalScroll(rememberScrollState()),
            ) {
                Card(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.primaryContainer),
                ) {
                    Column(Modifier.padding(16.dp)) {
                        Text(
                            stringResource(R.string.availability_hours, schedule.totalHours),
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            stringResource(R.string.availability_help),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                    }
                }
                WeekGrid(
                    schedule,
                    onToggle = viewModel::toggle,
                    onPaint = viewModel::paint,
                    onToggleDay = viewModel::toggleDay,
                )
            }
        }
    }
}

private val dayLabelIds = listOf(
    R.string.day_mon, R.string.day_tue, R.string.day_wed, R.string.day_thu,
    R.string.day_fri, R.string.day_sat, R.string.day_sun,
)

// Shared by the grid layout and the drag hit-testing, so they cannot drift.
private val HourGutterWidth = 36.dp
private val CellHeight = 26.dp
private val CellVerticalPadding = 1.dp

@Composable
private fun WeekGrid(
    schedule: AvailabilitySchedule,
    onToggle: (day: String, hour: Int) -> Unit,
    onPaint: (day: String, hour: Int, available: Boolean) -> Unit,
    onToggleDay: (day: String) -> Unit,
) {
    // Colour is the only on/off cue in the grid, hence the legend.
    Row(
        Modifier.fillMaxWidth().padding(bottom = 12.dp),
        horizontalArrangement = Arrangement.spacedBy(16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        LegendItem(MaterialTheme.colorScheme.primary, R.string.availability_legend_on)
        LegendItem(MaterialTheme.colorScheme.surfaceVariant, R.string.availability_legend_off)
    }

    // Header: hour gutter + one letter per day (weekend tinted apart).
    // Tapping a letter fills the whole day, or clears it when already full.
    Row(Modifier.fillMaxWidth().padding(bottom = 6.dp)) {
        Box(Modifier.width(HourGutterWidth))
        dayLabelIds.forEachIndexed { index, id ->
            val day = AvailabilitySchedule.DAYS[index]
            Text(
                stringResource(id),
                modifier = Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(6.dp))
                    .clickable { onToggleDay(day) }
                    .padding(vertical = 2.dp),
                textAlign = TextAlign.Center,
                style = MaterialTheme.typography.labelLarge,
                color = if (index >= 5) MaterialTheme.colorScheme.primary
                else MaterialTheme.colorScheme.onSurface,
            )
        }
    }

    // One detector for the whole grid: after a long press, dragging paints every
    // cell crossed. Plain taps still reach each cell's own toggleable.
    val current by rememberUpdatedState(schedule)
    Column(
        Modifier
            .fillMaxWidth()
            .pointerInput(Unit) {
                val gutter = HourGutterWidth.toPx()
                val rowPitch = (CellHeight + CellVerticalPadding * 2).toPx()
                fun cellAt(position: Offset): Pair<String, Int>? {
                    val cellWidth =
                        (size.width - gutter) / AvailabilitySchedule.DAYS.size
                    val col = floor((position.x - gutter) / cellWidth).toInt()
                    val row = floor(position.y / rowPitch).toInt()
                    if (col !in AvailabilitySchedule.DAYS.indices) return null
                    if (row !in 0 until AvailabilitySchedule.HOURS_PER_DAY) return null
                    return AvailabilitySchedule.DAYS[col] to row
                }
                // The first cell is painted only once the finger moves, so a long
                // press that never drags stays a plain toggle.
                var paintValue = false
                detectDragGesturesAfterLongPress(
                    onDragStart = { start ->
                        cellAt(start)?.let { (day, hour) ->
                            paintValue = hour !in current.hours[day].orEmpty()
                        }
                    },
                    onDrag = { change, _ ->
                        cellAt(change.position)?.let { (day, hour) ->
                            onPaint(day, hour, paintValue)
                        }
                    },
                )
            },
    ) {
        for (hour in 0 until AvailabilitySchedule.HOURS_PER_DAY) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(vertical = CellVerticalPadding),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                // Label every 3rd hour only: 24 numbers in a column is unreadable,
                // and the gaps still give the eye a scale to count from.
                Text(
                    if (hour % 3 == 0) "%02d".format(hour) else "",
                    modifier = Modifier.width(HourGutterWidth),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                AvailabilitySchedule.DAYS.forEach { day ->
                    val selected = hour in schedule.hours[day].orEmpty()
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .height(CellHeight)
                            .padding(horizontal = 1.5.dp)
                            .clip(RoundedCornerShape(6.dp))
                            .background(
                                if (selected) MaterialTheme.colorScheme.primary
                                else MaterialTheme.colorScheme.surfaceVariant
                            )
                            .toggleable(
                                value = selected,
                                onValueChange = { onToggle(day, hour) },
                            )
                            .semantics {
                                contentDescription = "$day %02d:00".format(hour)
                            },
                    )
                }
            }
        }
    }
    Box(Modifier.height(80.dp)) // room for the FAB
}

@Composable
private fun LegendItem(color: Color, labelId: Int) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier
                .size(14.dp)
                .clip(RoundedCornerShape(4.dp))
                .background(color)
        )
        Spacer(Modifier.width(6.dp))
        Text(
            stringResource(labelId),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
