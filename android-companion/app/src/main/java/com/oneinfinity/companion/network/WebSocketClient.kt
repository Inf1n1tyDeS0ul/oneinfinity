package com.oneinfinity.companion.network

import android.util.Log
import okhttp3.*
import org.json.JSONObject
import java.io.IOException

/**
 * WebSocket Client for bidirectional communication with OneInfinity backend
 *
 * Handles:
 * - Connection management
 * - Heartbeat keepalive
 * - Command reception from backend
 * - Data transmission to backend
 */
class WebSocketClient(
    private val wsUrl: String,
    private val deviceId: String,
    private val onMessage: (JSONObject) -> Unit
) {
    private val TAG = "WebSocketClient"
    private var webSocket: WebSocket? = null
    private val client = OkHttpClient()

    fun connect() {
        Log.i(TAG, "Connecting to: $wsUrl")
        val request = Request.Builder()
            .url(wsUrl)
            .build()

        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                Log.i(TAG, "WebSocket connected")
                startHeartbeat()
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                try {
                    val json = JSONObject(text)
                    onMessage(json)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to parse message: ${e.message}")
                }
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.e(TAG, "WebSocket error: ${t.message}")
                // Attempt reconnect after delay
                Thread.sleep(5000)
                connect()
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.i(TAG, "WebSocket closed: $reason")
            }
        })
    }

    fun disconnect() {
        webSocket?.close(1000, "Client disconnect")
        webSocket = null
    }

    fun sendMessage(msg: JSONObject) {
        webSocket?.send(msg.toString()) ?: Log.w(TAG, "WebSocket not connected")
    }

    private fun startHeartbeat() {
        Thread {
            while (webSocket != null) {
                sendHeartbeat()
                Thread.sleep(10000) // Every 10 seconds
            }
        }.start()
    }

    private fun sendHeartbeat() {
        val heartbeat = JSONObject().apply {
            put("type", "heartbeat")
            put("device_id", deviceId)
        }
        sendMessage(heartbeat)
    }

    fun sendTraffic(request: Map<String, Any>, response: Map<String, Any>) {
        val msg = JSONObject().apply {
            put("type", "traffic")
            put("request", JSONObject(request))
            put("response", JSONObject(response))
        }
        sendMessage(msg)
    }

    fun sendFinding(finding: Map<String, Any>) {
        val msg = JSONObject().apply {
            put("type", "vuln_found")
            put("finding", JSONObject(finding))
        }
        sendMessage(msg)
    }

    fun sendLog(message: String) {
        val msg = JSONObject().apply {
            put("type", "log")
            put("message", message)
        }
        sendMessage(msg)
    }
}
