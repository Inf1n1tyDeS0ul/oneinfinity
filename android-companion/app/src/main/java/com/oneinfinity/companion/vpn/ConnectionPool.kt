package com.oneinfinity.companion.vpn

import android.net.VpnService
import android.util.Log
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap

/**
 * Connection Pool - manages TCP connections and builds response packets
 */
class ConnectionPool(
    private val vpnService: VpnService,
    private val onPacket: (ByteArray) -> Unit
) {
    private val TAG = "ConnectionPool"
    private val connections = ConcurrentHashMap<String, TcpConnection>()

    suspend fun handleTcpPacket(
        srcIp: String,
        srcPort: Int,
        dstIp: String,
        dstPort: Int,
        payload: ByteArray
    ) {
        val key = "$srcIp:$srcPort-$dstIp:$dstPort"

        var connection = connections[key]

        if (connection == null || !connection.isActive()) {
            // Create new connection
            connection = TcpConnection(
                vpnService = vpnService,
                srcIp = srcIp,
                srcPort = srcPort,
                dstIp = dstIp,
                dstPort = dstPort,
                onData = { data ->
                    // Build response packet when data received from server
                    val responsePacket = buildTcpResponsePacket(
                        srcIp = dstIp,
                        srcPort = dstPort,
                        dstIp = srcIp,
                        dstPort = srcPort,
                        payload = data
                    )
                    onPacket(responsePacket)
                },
                onClose = {
                    connections.remove(key)
                }
            )

            connections[key] = connection

            Log.d(TAG, "New connection: $key")

            if (!connection.connect()) {
                connections.remove(key)
                return
            }
        }

        // Forward payload to destination
        if (payload.isNotEmpty()) {
            connection.write(payload)
        }
    }

    private fun buildTcpResponsePacket(
        srcIp: String,
        srcPort: Int,
        dstIp: String,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val totalLength = 20 + 20 + payload.size
        val buffer = ByteBuffer.allocate(totalLength)

        // IP Header (20 bytes)
        buffer.put((0x45).toByte())  // Version 4, IHL 5
        buffer.put(0)  // DSCP/ECN
        buffer.putShort(totalLength.toShort())
        buffer.putShort(0)  // ID
        buffer.putShort(0x4000.toShort())  // Flags: DF
        buffer.put(64)  // TTL
        buffer.put(6)  // Protocol: TCP
        buffer.putShort(0)  // Checksum (kernel calculates)
        buffer.put(ipToBytes(srcIp))
        buffer.put(ipToBytes(dstIp))

        // TCP Header (20 bytes)
        buffer.putShort(srcPort.toShort())
        buffer.putShort(dstPort.toShort())
        buffer.putInt(0)  // Sequence (simplified)
        buffer.putInt(0)  // Ack (simplified)
        buffer.putShort(0x5018.toShort())  // Data offset 5, PSH+ACK flags
        buffer.putShort(65535.toShort())  // Window
        buffer.putShort(0)  // Checksum
        buffer.putShort(0)  // Urgent

        // Payload
        buffer.put(payload)

        return buffer.array()
    }

    private fun ipToBytes(ip: String): ByteArray {
        return ip.split(".").map { it.toInt().toByte() }.toByteArray()
    }

    fun closeAll() {
        Log.i(TAG, "Closing ${connections.size} connections")
        connections.values.forEach { it.close() }
        connections.clear()
    }
}
