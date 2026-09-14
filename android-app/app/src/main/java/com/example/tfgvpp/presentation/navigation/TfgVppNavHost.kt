package com.example.tfgvpp.presentation.navigation

import androidx.compose.runtime.Composable
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.example.tfgvpp.presentation.screens.appliancedetail.ApplianceDetailScreen
import com.example.tfgvpp.presentation.screens.availability.AvailabilityScreen
import com.example.tfgvpp.presentation.screens.home.HomeScreen
import com.example.tfgvpp.presentation.screens.login.LoginScreen
import com.example.tfgvpp.presentation.screens.pairing.PairingScreen
import com.example.tfgvpp.presentation.screens.participation.ParticipationScreen
import com.example.tfgvpp.presentation.screens.profile.ProfileScreen
import com.example.tfgvpp.presentation.screens.splash.SplashScreen

@Composable
fun TfgVppNavHost(
    navController: NavHostController = rememberNavController(),
) {
    NavHost(navController = navController, startDestination = Route.Splash.route) {

        composable(Route.Splash.route) {
            SplashScreen(
                onNavigateToLogin = {
                    navController.navigate(Route.Login.route) {
                        popUpTo(Route.Splash.route) { inclusive = true }
                    }
                },
                onNavigateToHome = {
                    navController.navigate(Route.Home.route) {
                        popUpTo(Route.Splash.route) { inclusive = true }
                    }
                },
            )
        }

        composable(Route.Login.route) {
            LoginScreen(
                onRegistered = {
                    navController.navigate(Route.Home.route) {
                        popUpTo(Route.Login.route) { inclusive = true }
                    }
                },
            )
        }

        composable(Route.Home.route) {
            HomeScreen(
                onAddAppliance = { navController.navigate(Route.Pairing.route) },
                onOpenAppliance = { ven ->
                    navController.navigate(Route.ApplianceDetail.create(ven))
                },
                onOpenHistory = { navController.navigate(Route.Participation.route) },
                onOpenProfile = { navController.navigate(Route.Profile.route) },
            )
        }

        composable(Route.Pairing.route) {
            PairingScreen(onBack = { navController.popBackStack() })
        }

        composable(Route.ApplianceDetail.route) {
            ApplianceDetailScreen(
                onBack = { navController.popBackStack() },
                onEditAvailability = { ven ->
                    navController.navigate(Route.Availability.create(ven))
                },
            )
        }

        composable(Route.Availability.route) {
            AvailabilityScreen(onBack = { navController.popBackStack() })
        }

        composable(Route.Participation.route) {
            ParticipationScreen(onBack = { navController.popBackStack() })
        }

        composable(Route.Profile.route) {
            ProfileScreen(
                onBack = { navController.popBackStack() },
                onLoggedOut = {
                    navController.navigate(Route.Login.route) {
                        popUpTo(0) { inclusive = true }
                    }
                },
            )
        }
    }
}
