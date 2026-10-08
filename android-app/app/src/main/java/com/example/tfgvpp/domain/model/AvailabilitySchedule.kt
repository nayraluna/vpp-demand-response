package com.example.tfgvpp.domain.model

data class AvailabilitySchedule(
    val applianceVen: String,
    val hours: Map<String, Set<Int>>,
) {
    val totalHours: Int get() = hours.values.sumOf { it.size }

    fun toggled(day: String, hour: Int): AvailabilitySchedule {
        val current = hours[day].orEmpty()
        val updated = if (hour in current) current - hour else current + hour
        return copy(hours = hours + (day to updated))
    }

    fun withHour(day: String, hour: Int, available: Boolean): AvailabilitySchedule {
        val current = hours[day].orEmpty()
        val updated = if (available) current + hour else current - hour
        return copy(hours = hours + (day to updated))
    }

    /** Fills the day, or clears it when already full. */
    fun dayToggled(day: String): AvailabilitySchedule {
        val full = hours[day].orEmpty().size == HOURS_PER_DAY
        val updated = if (full) emptySet() else (0 until HOURS_PER_DAY).toSet()
        return copy(hours = hours + (day to updated))
    }

    companion object {
        val DAYS = listOf("mon", "tue", "wed", "thu", "fri", "sat", "sun")

        const val HOURS_PER_DAY = 24

        fun empty(applianceVen: String) =
            AvailabilitySchedule(applianceVen, DAYS.associateWith { emptySet() })
    }
}
