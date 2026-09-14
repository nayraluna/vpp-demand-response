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
        // Android 15+ draws the app behind the system bars whether we ask or
        // not, leaving the bar icons light: a white back arrow and clock over
        // this app's near-white surface. This tints them from the system dark
        // mode instead, the same signal TfgVppTheme follows.
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            TfgVppTheme {
                TfgVppNavHost()
            }
        }
    }
}
