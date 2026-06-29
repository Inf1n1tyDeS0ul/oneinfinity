package com.oneinfinity.companion.config

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.util.Log
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import kotlin.coroutines.resume

/**
 * mDNS Auto-Discovery for OneInfinity Backend
 *
 * Discovers backend on local network via Bonjour/mDNS.
 * Service type: _oneinfinity._tcp.
 */
object MdnsDiscovery {
    private const val TAG = "MdnsDiscovery"

    suspend fun discover(
        context: Context,
        serviceType: String = "_oneinfinity._tcp.",
        timeoutMs: Long = 10000
    ): BackendConfig? {
        return try {
            withTimeout(timeoutMs) {
                discoverService(context, serviceType)
            }
        } catch (e: Exception) {
            Log.w(TAG, "mDNS discovery failed: ${e.message}")
            null
        }
    }

    private suspend fun discoverService(
        context: Context,
        serviceType: String
    ): BackendConfig? = suspendCancellableCoroutine { continuation ->

        val nsdManager = context.getSystemService(Context.NSD_SERVICE) as NsdManager
        var resolved = false
        var listener: NsdManager.DiscoveryListener? = null

        listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) {
                Log.d(TAG, "mDNS discovery started: $serviceType")
            }

            override fun onServiceFound(service: NsdServiceInfo) {
                Log.d(TAG, "Service found: ${service.serviceName}")

                if (!resolved && service.serviceType.contains("oneinfinity")) {
                    resolved = true
                    nsdManager.resolveService(service, object : NsdManager.ResolveListener {
                        override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                            Log.w(TAG, "Resolve failed: $errorCode")
                            resolved = false
                        }

                        override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                            val host = serviceInfo.host.hostAddress ?: "127.0.0.1"
                            val port = serviceInfo.port

                            Log.i(TAG, "Backend discovered: $host:$port")

                            val config = BackendConfig(
                                baseUrl = "http://$host:$port",
                                wsUrl = "ws://$host:$port"
                            )

                            try {
                                listener?.let { nsdManager.stopServiceDiscovery(it) }
                            } catch (e: Exception) {
                                Log.w(TAG, "Failed to stop discovery: ${e.message}")
                            }
                            continuation.resume(config)
                        }
                    })
                }
            }

            override fun onServiceLost(service: NsdServiceInfo) {
                Log.d(TAG, "Service lost: ${service.serviceName}")
            }

            override fun onDiscoveryStopped(serviceType: String) {
                Log.d(TAG, "Discovery stopped")
            }

            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                Log.e(TAG, "Start discovery failed: $errorCode")
                if (!resolved) {
                    continuation.resume(null)
                }
            }

            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {
                Log.e(TAG, "Stop discovery failed: $errorCode")
            }
        }

        listener?.let { nsdManager.discoverServices(serviceType, NsdManager.PROTOCOL_DNS_SD, it) }

        continuation.invokeOnCancellation {
            try {
                listener?.let { nsdManager.stopServiceDiscovery(it) }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to stop discovery: ${e.message}")
            }
        }
    }
}
