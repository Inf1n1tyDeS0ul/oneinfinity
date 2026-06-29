package com.oneinfinity.companion.vpn

import android.net.VpnService
import android.util.Log
import com.oneinfinity.companion.network.ParsedPacket
import kotlinx.coroutines.*
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * Packet Forwarder - forwards VPN packets to real network
 *
 * Handles TCP (via connection pool) and UDP packet forwarding
 */
class PacketForwarder(
    private val vpnService: VpnService,
    private val vpnOutput: FileOutputStream
) {
    private val TAG = "PacketForwarder"
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val connectionPool = ConnectionPool(vpnService) { packet ->
        // Write response packet to VPN interface
        try {
            vpnOutput.write(packet)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to write response: ${e.message}")
        }
    }

    fun forwardPacket(parsedPacket: ParsedPacket) {
        scope.launch {
            try {
                Log.d(TAG, "Forwarding protocol ${parsedPacket.protocol}: ${parsedPacket.srcIp}:${parsedPacket.srcPort} -> ${parsedPacket.dstIp}:${parsedPacket.dstPort}")
                when (parsedPacket.protocol) {
                    6 -> forwardTCP(parsedPacket)   // TCP
                    17 -> forwardUDP(parsedPacket)  // UDP
                    1 -> forwardICMP(parsedPacket)  // ICMP (ping)
                    else -> {
                        Log.d(TAG, "Unsupported protocol: ${parsedPacket.protocol}")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Forward error: ${e.message}", e)
            }
        }
    }

    private suspend fun forwardTCP(packet: ParsedPacket) {
        Log.d(TAG, "TCP forward: ${packet.srcIp}:${packet.srcPort} -> ${packet.dstIp}:${packet.dstPort}, payload: ${packet.payload.size} bytes")
        connectionPool.handleTcpPacket(
            srcIp = packet.srcIp,
            srcPort = packet.srcPort,
            dstIp = packet.dstIp,
            dstPort = packet.dstPort,
            payload = packet.payload
        )
    }

    private suspend fun forwardUDP(packet: ParsedPacket) {
        withContext(Dispatchers.IO) {
            try {
                val socket = DatagramSocket()

                // Protect socket
                if (!vpnService.protect(socket)) {
                    Log.w(TAG, "Failed to protect UDP socket")
                    socket.close()
                    return@withContext
                }

                socket.soTimeout = 3000  // 3s timeout

                // Send packet
                val sendPacket = DatagramPacket(
                    packet.payload,
                    packet.payload.size,
                    InetAddress.getByName(packet.dstIp),
                    packet.dstPort
                )
                socket.send(sendPacket)

                // Receive response
                val receiveBuffer = ByteArray(32768)
                val receivePacket = DatagramPacket(receiveBuffer, receiveBuffer.size)
                socket.receive(receivePacket)

                // Build response packet
                val responsePacket = buildUdpResponsePacket(
                    srcIp = packet.dstIp,
                    srcPort = packet.dstPort,
                    dstIp = packet.srcIp,
                    dstPort = packet.srcPort,
                    payload = receivePacket.data.copyOf(receivePacket.length)
                )

                vpnOutput.write(responsePacket)
                socket.close()
            } catch (e: Exception) {
                Log.d(TAG, "UDP forward failed: ${e.message}")
            }
        }
    }

    private suspend fun forwardICMP(packet: ParsedPacket) {
        // ICMP requires raw sockets (requires root)
        Log.d(TAG, "ICMP forwarding not implemented (requires root)")
    }

    private fun buildUdpResponsePacket(
        srcIp: String,
        srcPort: Int,
        dstIp: String,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val udpLength = 8 + payload.size
        val totalLength = 20 + udpLength
        val buffer = ByteBuffer.allocate(totalLength)

        // IP Header (20 bytes)
        buffer.put((0x45).toByte())  // Version 4, IHL 5
        buffer.put(0)  // DSCP/ECN
        buffer.putShort(totalLength.toShort())  // Total length
        buffer.putShort(0)  // ID
        buffer.putShort(0x4000.toShort())  // Flags: DF
        buffer.put(64)  // TTL
        buffer.put(17)  // Protocol: UDP
        buffer.putShort(0)  // Checksum (calculated by kernel)
        buffer.put(ipToBytes(srcIp))  // Source IP
        buffer.put(ipToBytes(dstIp))  // Dest IP

        // UDP Header (8 bytes)
        buffer.putShort(srcPort.toShort())  // Source port
        buffer.putShort(dstPort.toShort())  // Dest port
        buffer.putShort(udpLength.toShort())  // Length
        buffer.putShort(0)  // Checksum (optional for IPv4)

        // Payload
        buffer.put(payload)

        return buffer.array()
    }

    private fun ipToBytes(ip: String): ByteArray {
        return ip.split(".").map { it.toInt().toByte() }.toByteArray()
    }

    fun shutdown() {
        connectionPool.closeAll()
        scope.cancel()
    }
}
