package com.oneinfinity.companion.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.oneinfinity.companion.MainActivity
import com.oneinfinity.companion.network.PacketParser
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

/**
 * VPN Service for system-wide traffic interception
 *
 * Intercepts all device traffic using Android VpnService API.
 * Parses packets and forwards to backend for analysis.
 */
class VpnCaptureService : VpnService() {
    private val TAG = "VpnCaptureService"

    private var vpnInterface: ParcelFileDescriptor? = null
    private var captureJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private lateinit var packetParser: PacketParser
    private lateinit var packetForwarder: PacketForwarder
    private var onPacketCaptured: ((ByteArray) -> Unit)? = null

    // Traffic reassembly
    private val requestReassembler = com.oneinfinity.companion.network.HttpStreamReassembler()
    private val responseReassembler = com.oneinfinity.companion.network.HttpStreamReassembler()
    // Pending request per connection key (waiting to be paired with a response)
    private val pendingRequests = java.util.concurrent.ConcurrentHashMap<String, com.oneinfinity.companion.network.HttpMessage>()

    // Called by MainActivity after WebSocket is ready
    var onTraffic: ((request: org.json.JSONObject, response: org.json.JSONObject) -> Unit)? = null

    // Response data callback set by ConnectionPool wiring below
    fun onResponseData(connKey: String, data: ByteArray) {
        val fakeParsed = com.oneinfinity.companion.network.ParsedPacket(
            version = 4, protocol = 6,
            srcIp = connKey.substringAfter("-").substringBefore(":"),
            dstIp = connKey.substringBefore(":"),
            srcPort = connKey.substringAfter(":").substringBefore("-").toIntOrNull() ?: 0,
            dstPort = connKey.substringAfterLast(":").toIntOrNull() ?: 0,
            payload = data, rawPacket = data
        )
        val responseMsg = responseReassembler.processPacket(fakeParsed) ?: return
        val req = pendingRequests.remove(connKey)
        val reqJson = if (req != null) {
            org.json.JSONObject(req.toJson() as Map<*, *>)
        } else {
            org.json.JSONObject().apply { put("url", ""); put("method", ""); put("version", "") }
        }
        val respJson = org.json.JSONObject(responseMsg.toJson() as Map<*, *>)
        onTraffic?.invoke(reqJson, respJson)
    }

    private var onHttpRequestReassembled: ((method: String, url: String, headers: Map<String, String>, body: ByteArray) -> Unit)? = null

    fun setHttpRequestCallback(cb: (String, String, Map<String, String>, ByteArray) -> Unit) {
        onHttpRequestReassembled = cb
    }

    // Statistics
    private var packetsProcessed = 0L
    private var bytesProcessed = 0L

    companion object {
        const val ACTION_START = "com.oneinfinity.companion.START_VPN"
        const val ACTION_STOP = "com.oneinfinity.companion.STOP_VPN"
        const val NOTIFICATION_ID = 1001
        const val CHANNEL_ID = "vpn_capture"

        var isRunning = false
            private set

        var instance: VpnCaptureService? = null
            private set
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        packetParser = PacketParser()
        createNotificationChannel()
        Log.i(TAG, "VPN service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startCapture()
            ACTION_STOP -> stopCapture()
        }
        return START_STICKY
    }

    private fun startCapture() {
        if (isRunning) {
            Log.w(TAG, "VPN already running")
            return
        }

        try {
            // Configure VPN interface
            val builder = Builder()
                .setSession("OneInfinity Capture")
                .addAddress("10.8.0.1", 32)  // VPN interface IP
                .addRoute("0.0.0.0", 0)       // Route all traffic
                .addDnsServer("8.8.8.8")       // Google DNS
                .addDnsServer("8.8.4.4")
                .setMtu(1500)

            // Prevent VPN loop - exclude companion app from its own VPN tunnel
            try {
                builder.addDisallowedApplication(packageName)
                Log.i(TAG, "Excluding own app from VPN: $packageName")
            } catch (e: Exception) {
                Log.w(TAG, "Could not exclude own app from VPN: ${e.message}")
            }

            // Must be foreground before establish() on Android 10+
            startForeground(NOTIFICATION_ID, createNotification())

            // Set as system-wide VPN
            vpnInterface = builder.establish()

            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface - user may have denied permission")
                stopForeground(true)
                return
            }

            Log.i(TAG, "VPN interface established: fd=${vpnInterface?.fd}")

            // Initialize packet forwarder with VPN output
            val vpnOutput = FileOutputStream(vpnInterface!!.fileDescriptor)
            packetForwarder = PacketForwarder(this, vpnOutput)

            isRunning = true

            // Start packet capture loop
            captureJob = scope.launch {
                captureLoop()
            }

            Log.i(TAG, "VPN capture started, job launched")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VPN: ${e.message}")
            stopCapture()
        }
    }

    private fun stopCapture() {
        isRunning = false

        captureJob?.cancel()
        captureJob = null

        vpnInterface?.close()
        vpnInterface = null

        stopForeground(true)
        stopSelf()

        Log.i(TAG, "VPN capture stopped. Packets: $packetsProcessed, Bytes: $bytesProcessed")
    }

    private suspend fun captureLoop() = withContext(Dispatchers.IO) {
        val buffer = ByteBuffer.allocate(32768)  // 32KB buffer
        val vpnInput = FileInputStream(vpnInterface!!.fileDescriptor)
        val vpnOutput = FileOutputStream(vpnInterface!!.fileDescriptor)

        Log.i(TAG, "Capture loop started, waiting for packets...")

        try {
            while (isActive && isRunning) {
                buffer.clear()

                // Read packet from VPN interface
                val length = vpnInput.read(buffer.array())
                if (length <= 0) {
                    // No data available, yield briefly to avoid busy loop
                    yield()
                    continue
                }

                buffer.limit(length)
                val packet = ByteArray(length)
                buffer.get(packet)

                packetsProcessed++
                bytesProcessed += length

                if (packetsProcessed % 100 == 0L) {
                    Log.i(TAG, "Processed $packetsProcessed packets, $bytesProcessed bytes")
                }

                // Parse and process packet
                processPacket(packet, vpnOutput)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Capture loop error: ${e.message}", e)
        } finally {
            Log.i(TAG, "Capture loop exiting")
            vpnInput.close()
            vpnOutput.close()
        }
    }

    private suspend fun processPacket(packet: ByteArray, vpnOutput: FileOutputStream) {
        try {
            val parsedPacket = packetParser.parse(packet) ?: return

            onPacketCaptured?.invoke(packet)

            if (packetsProcessed % 50 == 0L) {
                Log.i(TAG, "Processed $packetsProcessed pkts: " +
                    "${parsedPacket.srcIp}:${parsedPacket.srcPort}->" +
                    "${parsedPacket.dstIp}:${parsedPacket.dstPort}")
            }

            // Emit connection metadata for every new TCP connection to port 80 or 443
            if (parsedPacket.protocol == 6 && (parsedPacket.dstPort == 80 || parsedPacket.dstPort == 443 || parsedPacket.srcPort == 80 || parsedPacket.srcPort == 443)) {
                Log.i(TAG, "HTTP/S TCP packet: ${parsedPacket.srcIp}:${parsedPacket.srcPort}->${parsedPacket.dstIp}:${parsedPacket.dstPort} isHttp=${parsedPacket.isHttp} isHttps=${parsedPacket.isHttps}")
            }
            if (parsedPacket.protocol == 6) {
                val connKey = "${parsedPacket.srcIp}:${parsedPacket.srcPort}-${parsedPacket.dstIp}:${parsedPacket.dstPort}"
                when {
                    parsedPacket.isHttp || parsedPacket.isHttp2 -> {
                        try {
                            val msg = requestReassembler.processPacket(parsedPacket)
                            if (msg != null && msg.type == com.oneinfinity.companion.network.HttpMessage.Type.REQUEST) {
                                pendingRequests[connKey] = msg
                                onHttpRequestReassembled?.invoke(
                                    msg.method ?: "GET", msg.url ?: "", msg.headers, msg.body.toByteArray()
                                )
                                val reqJson = org.json.JSONObject(msg.toJson() as Map<*, *>)
                                val respJson = org.json.JSONObject().apply {
                                    put("status_code", 0); put("status_message", "pending"); put("body", "")
                                }
                                onTraffic?.invoke(reqJson, respJson)
                            }
                        } catch (e: Exception) {
                            Log.d(TAG, "HTTP reassembly: ${e.message}")
                        }
                    }
                    parsedPacket.isHttps -> {
                        if (!pendingRequests.containsKey(connKey)) {
                            // Emit HTTPS connection metadata (SNI not decoded yet)
                            val reqJson = org.json.JSONObject().apply {
                                put("method", "CONNECT")
                                put("url", "https://${parsedPacket.dstIp}:${parsedPacket.dstPort}")
                                put("version", "TLS")
                                put("headers", org.json.JSONObject())
                                put("body", "")
                                put("encrypted", true)
                            }
                            val respJson = org.json.JSONObject().apply {
                                put("status_code", 0)
                                put("status_message", "encrypted — install CA cert to decrypt")
                                put("headers", org.json.JSONObject())
                                put("body", "")
                            }
                            onTraffic?.invoke(reqJson, respJson)
                            pendingRequests[connKey] =
                                com.oneinfinity.companion.network.HttpMessage(
                                    type = com.oneinfinity.companion.network.HttpMessage.Type.REQUEST,
                                    method = "CONNECT", url = "https://${parsedPacket.dstIp}",
                                    version = "TLS", statusCode = null, statusMessage = null,
                                    headers = emptyMap(), body = ""
                                )
                            Log.d(TAG, "HTTPS connection: ${parsedPacket.dstIp}:${parsedPacket.dstPort}")
                        }
                    }
                }
            }

            // Forward packet to real network
            packetForwarder.forwardPacket(parsedPacket)

        } catch (e: Exception) {
            Log.e(TAG, "Packet processing error: ${e.message}")
        }
    }

    fun setPacketCallback(callback: (ByteArray) -> Unit) {
        onPacketCaptured = callback
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "VPN Traffic Capture",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Capturing network traffic for security analysis"
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(this, VpnCaptureService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getService(
            this, 0, stopIntent,
            PendingIntent.FLAG_IMMUTABLE
        )

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("OneInfinity Traffic Capture")
                .setContentText("Capturing network traffic: $packetsProcessed packets")
                .setSmallIcon(android.R.drawable.ic_menu_upload)
                .setContentIntent(pendingIntent)
                .addAction(
                    android.R.drawable.ic_menu_close_clear_cancel,
                    "Stop",
                    stopPendingIntent
                )
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("OneInfinity Traffic Capture")
                .setContentText("Capturing network traffic")
                .setSmallIcon(android.R.drawable.ic_menu_upload)
                .setContentIntent(pendingIntent)
                .build()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        instance = null
        stopCapture()
        packetForwarder.shutdown()
        scope.cancel()
        Log.i(TAG, "VPN service destroyed")
    }
}
