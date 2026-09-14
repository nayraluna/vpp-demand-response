package com.example.tfgvpp.presentation.ui

import android.text.format.DateFormat
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.time.format.FormatStyle
import java.util.Locale

internal fun readableLocalTime(iso: String): String = try {
    OffsetDateTime.parse(iso)
        .atZoneSameInstant(ZoneId.systemDefault())
        .format(
            DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM, FormatStyle.SHORT)
                .withLocale(Locale.getDefault())
        )
} catch (e: DateTimeParseException) {
    iso
}

/**
 * Day and month only, for a chart axis where a full timestamp would not fit
 * ("27/8" in Spain, "8/27" in the US). Empty when the timestamp does not
 * parse, so an unlabelled bar degrades better than a crashed screen.
 */
internal fun shortLocalDate(iso: String): String = try {
    val locale = Locale.getDefault()
    OffsetDateTime.parse(iso)
        .atZoneSameInstant(ZoneId.systemDefault())
        .format(
            DateTimeFormatter.ofPattern(
                DateFormat.getBestDateTimePattern(locale, "dM"), locale)
        )
} catch (e: Exception) {
    ""
}
