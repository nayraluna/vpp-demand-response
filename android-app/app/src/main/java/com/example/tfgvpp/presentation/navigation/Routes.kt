package com.example.tfgvpp.presentation.navigation

import android.net.Uri

sealed class Route(val route: String) {
    data object Splash : Route("splash")
    data object Login : Route("login")
    data object Home : Route("home")
    data object Pairing : Route("pairing")
    data object Participation : Route("participation")
    data object Profile : Route("profile")

    data object ApplianceDetail : Route("appliance/{$ARG_VEN}") {
        fun create(ven: String) = "appliance/${Uri.encode(ven)}"
    }

    data object Availability : Route("appliance/{$ARG_VEN}/availability") {
        fun create(ven: String) = "appliance/${Uri.encode(ven)}/availability"
    }

    companion object {
        /** Name of the VEN-subject argument shared by the appliance screens. */
        const val ARG_VEN = "ven"
    }
}
