package com.example.tfgvpp.domain.model

data class AvailabilitySchedule(
    val applianceVen: String,
    val hours: Map<String, Set<Int>>,
) {
    /** Total number of authorised hours in the week. */
    val totalHours: Int get() = hours.values.sumOf { it.size }

    /** Copy with one cell of the weekly grid flipped. */
    fun toggled(day: String, hour: Int): AvailabilitySchedule {
        val current = hours[day].orEmpty()
        val updated = if (hour in current) current - hour else current + hour
        return copy(hours = hours + (day to updated))
    }

    /** Copy with one cell set to [available]; a no-op if it already is. */
    fun withHour(day: String, hour: Int, available: Boolean): AvailabilitySchedule {
        val current = hours[day].orEmpty()
        val updated = if (available) current + hour else current - hour
        return copy(hours = hours + (day to updated))
    }

    /** Copy with the day filled 0-23, or cleared when it was already full. */
    fun dayToggled(day: String): AvailabilitySchedule {
        val full = hours[day].orEmpty().size == HOURS_PER_DAY
        val updated = if (full) emptySet() else (0 until HOURS_PER_DAY).toSet()
        return copy(hours = hours + (day to updated))
    }

    companion object {
        /** Day keys in wire order, Monday first. */
        val DAYS = listOf("mon", "tue", "wed", "thu", "fri", "sat", "sun")

        /** Grid granularity: one slot per hour of the day. */
        const val HOURS_PER_DAY = 24

        /** A calendar with no authorised hours. */
        fun empty(applianceVen: String) =
            AvailabilitySchedule(applianceVen, DAYS.associateWith { emptySet() })
    }
}
