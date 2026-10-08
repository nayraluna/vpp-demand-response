package com.example.tfgvpp

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.example.tfgvpp.presentation.navigation.TfgVppNavHost
import com.example.tfgvpp.presentation.ui.theme.TfgVppTheme
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        // Android 15+ draws behind the system bars regardless; this tints the bar icons from the system dark mode.
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            TfgVppTheme {
                TfgVppNavHost()
            }
        }
    }
}
