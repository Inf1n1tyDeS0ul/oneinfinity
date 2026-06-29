package com.oneinfinity.companion.vpn

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import java.io.IOException
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel

/**
 * TCP Connection - proper bidirectional proxy
 *
 * Handles single TCP connection using NIO selector for efficiency
 */
class TcpConnection(
    private val vpnService: VpnService,
    val srcIp: String,
    val srcPort: Int,
    val dstIp: String,
    val dstPort: Int,
    private val onData: (ByteArray) -> Unit,
    private val onClose: () -> Unit
) {
    private val TAG = "TcpConnection"
    private var channel: SocketChannel? = null
    private var active = true

    val key = "$srcIp:$srcPort-$dstIp:$dstPort"

    suspend fun connect(): Boolean = withContext(Dispatchers.IO) {
        try {
            channel = SocketChannel.open()
            channel?.configureBlocking(true)  // Use blocking for simplicity
            channel?.socket()?.tcpNoDelay = true
            channel?.socket()?.keepAlive = true

            // Protect from VPN loop
            if (!vpnService.protect(channel!!.socket())) {
                Log.w(TAG, "Failed to protect: $key")
                return@withContext false
            }

            // Connect with timeout
            channel?.socket()?.connect(InetSocketAddress(dstIp, dstPort), 5000)

            if (channel?.isConnected == true) {
                Log.d(TAG, "Connected: $key")

                // Start read loop
                CoroutineScope(Dispatchers.IO).launch {
                    readLoop()
                }

                true
            } else {
                Log.w(TAG, "Connect failed: $key")
                false
            }

        } catch (e: Exception) {
            Log.e(TAG, "Connect error $key: ${e.message}")
            close()
            false
        }
    }

    suspend fun write(data: ByteArray) = withContext(Dispatchers.IO) {
        try {
            if (channel?.isConnected == true && data.isNotEmpty()) {
                val buffer = ByteBuffer.wrap(data)
                var written = 0
                while (buffer.hasRemaining() && written < 3) {
                    val n = channel?.write(buffer) ?: 0
                    if (n == 0) {
                        delay(10)
                        written++
                    }
                }
            }
        } catch (e: IOException) {
            Log.w(TAG, "Write error $key: ${e.message}")
            close()
        }
    }

    private suspend fun readLoop() = withContext(Dispatchers.IO) {
        val buffer = ByteBuffer.allocate(8192)

        try {
            while (active && channel?.isConnected == true) {
                buffer.clear()
                val n = channel?.read(buffer) ?: -1

                when {
                    n > 0 -> {
                        buffer.flip()
                        val data = ByteArray(n)
                        buffer.get(data)
                        onData(data)
                    }
                    n == -1 -> {
                        // Remote closed
                        break
                    }
                    else -> {
                        delay(10)
                    }
                }
            }
        } catch (e: IOException) {
            Log.d(TAG, "Read closed $key: ${e.message}")
        } finally {
            close()
        }
    }

    fun close() {
        if (active) {
            active = false
            try {
                channel?.close()
            } catch (e: Exception) {
                // Ignore
            }
            onClose()
            Log.d(TAG, "Closed: $key")
        }
    }

    fun isActive() = active && channel?.isConnected == true
}
