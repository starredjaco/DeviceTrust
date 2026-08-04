package com.example.devicetrust.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val Scheme = darkColorScheme(
    primary = Color(0xFF5EE3B1),
    secondary = Color(0xFF8BB8FF),
    background = Color(0xFF091411),
    surface = Color(0xFF10231D),
    surfaceVariant = Color(0xFF193128),
)

@Composable fun DeviceTrustTheme(content: @Composable () -> Unit) = MaterialTheme(colorScheme = Scheme, content = content)
