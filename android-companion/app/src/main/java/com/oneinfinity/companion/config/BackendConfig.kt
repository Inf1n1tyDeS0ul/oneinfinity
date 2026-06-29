package com.oneinfinity.companion.config

/**
 * Backend connection configuration
 *
 * Stores OneInfinity backend URLs and API key
 */
data class BackendConfig(
    val baseUrl: String,
    val wsUrl: String,
    val apiKey: String? = null
)
