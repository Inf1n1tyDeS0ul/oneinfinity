package com.oneinfinity.companion.config

import android.content.Context
import android.os.Build

/**
 * Configuration Manager - handles backend URL persistence and auto-detection
 *
 * Priority:
 * 1. Saved user config (SharedPreferences)
 * 2. Environment variable
 * 3. Platform defaults (emulator vs device detection)
 */
object ConfigManager {
    private const val PREFS_NAME = "oneinfinity_config"
    private const val KEY_BASE_URL = "base_url"
    private const val KEY_WS_URL = "ws_url"
    private const val KEY_API_KEY = "api_key"

    fun saveConfig(context: Context, config: BackendConfig) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit().apply {
            putString(KEY_BASE_URL, config.baseUrl)
            putString(KEY_WS_URL, config.wsUrl)
            putString(KEY_API_KEY, config.apiKey)
            apply()
        }
    }

    fun loadConfig(context: Context): BackendConfig? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val baseUrl = prefs.getString(KEY_BASE_URL, null) ?: return null
        val wsUrl = prefs.getString(KEY_WS_URL, null) ?: return null
        val apiKey = prefs.getString(KEY_API_KEY, null)

        return BackendConfig(baseUrl, wsUrl, apiKey)
    }

    fun clearConfig(context: Context) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit().clear().apply()
    }

    fun getDefaultConfig(): BackendConfig? {
        return if (isRunningInEmulator()) {
            BackendConfig(
                baseUrl = "http://10.0.2.2:8000",
                wsUrl = "ws://10.0.2.2:8000"
            )
        } else {
            null  // Real device: no hardcoded IP — user must scan QR code
        }
    }

    private fun isRunningInEmulator(): Boolean {
        return (Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MANUFACTURER.contains("Genymotion")
                || Build.BRAND.startsWith("generic")
                || Build.DEVICE.startsWith("generic"))
    }
}
