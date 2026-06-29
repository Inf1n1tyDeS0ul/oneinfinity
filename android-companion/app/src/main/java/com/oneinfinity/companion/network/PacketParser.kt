package com.oneinfinity.companion.network

import android.util.Log
import java.nio.ByteBuffer

/**
 * IP/TCP/UDP Packet Parser
 *
 * Parses raw network packets to extract protocol info.
 */
class PacketParser {
    private val TAG = "PacketParser"

    companion object {
        const val PROTOCOL_TCP = 6
        const val PROTOCOL_UDP = 17
    }

    fun parse(packet: ByteArray): ParsedPacket? {
        if (packet.size < 20) return null  // Minimum IP header size

        return try {
            val buffer = ByteBuffer.wrap(packet)

            // Parse IP header
            val versionAndHeaderLength = buffer.get().toInt() and 0xFF
            val version = (versionAndHeaderLength shr 4) and 0x0F
            val headerLength = (versionAndHeaderLength and 0x0F) * 4

            if (version != 4) {
                // IPv6 not supported yet
                return null
            }

            buffer.position(9)
            val protocol = buffer.get().toInt() and 0xFF

            buffer.position(12)
            val srcIp = readIpAddress(buffer)

            buffer.position(16)
            val dstIp = readIpAddress(buffer)

            // Parse TCP/UDP ports
            if (packet.size < headerLength + 4) return null

            buffer.position(headerLength)
            val srcPort = buffer.short.toInt() and 0xFFFF
            val dstPort = buffer.short.toInt() and 0xFFFF

            // Extract payload
            val payloadStart = when (protocol) {
                PROTOCOL_TCP -> {
                    // TCP header length is in data offset field
                    if (packet.size < headerLength + 12) return null
                    buffer.position(headerLength + 12)
                    val dataOffset = ((buffer.get().toInt() and 0xFF) shr 4) * 4
                    headerLength + dataOffset
                }
                PROTOCOL_UDP -> headerLength + 8  // UDP header is 8 bytes
                else -> headerLength
            }

            val payload = if (payloadStart < packet.size) {
                packet.copyOfRange(payloadStart, packet.size)
            } else {
                byteArrayOf()
            }

            ParsedPacket(
                version = version,
                protocol = protocol,
                srcIp = srcIp,
                dstIp = dstIp,
                srcPort = srcPort,
                dstPort = dstPort,
                payload = payload,
                rawPacket = packet
            )

        } catch (e: Exception) {
            Log.e(TAG, "Packet parsing error: ${e.message}")
            null
        }
    }

    private fun readIpAddress(buffer: ByteBuffer): String {
        val ip = ByteArray(4)
        buffer.get(ip)
        return "${ip[0].toInt() and 0xFF}.${ip[1].toInt() and 0xFF}." +
                "${ip[2].toInt() and 0xFF}.${ip[3].toInt() and 0xFF}"
    }
}

data class ParsedPacket(
    val version: Int,
    val protocol: Int,
    val srcIp: String,
    val dstIp: String,
    val srcPort: Int,
    val dstPort: Int,
    val payload: ByteArray,
    val rawPacket: ByteArray
) {
    val protocolName: String
        get() = when (protocol) {
            PacketParser.PROTOCOL_TCP -> "TCP"
            PacketParser.PROTOCOL_UDP -> "UDP"
            else -> "Unknown($protocol)"
        }

    val isHttp: Boolean
        get() = (dstPort == 80 || srcPort == 80) && protocol == PacketParser.PROTOCOL_TCP

    val isHttps: Boolean
        get() = (dstPort == 443 || srcPort == 443) && protocol == PacketParser.PROTOCOL_TCP

    // h2c plaintext: connection preface starts with "PRI * HTTP/2.0"
    val isHttp2: Boolean
        get() = protocol == PacketParser.PROTOCOL_TCP &&
                payload.size >= 14 &&
                String(payload, 0, 14, Charsets.US_ASCII) == "PRI * HTTP/2.0"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ParsedPacket

        if (version != other.version) return false
        if (protocol != other.protocol) return false
        if (srcIp != other.srcIp) return false
        if (dstIp != other.dstIp) return false
        if (srcPort != other.srcPort) return false
        if (dstPort != other.dstPort) return false

        return true
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + protocol
        result = 31 * result + srcIp.hashCode()
        result = 31 * result + dstIp.hashCode()
        result = 31 * result + srcPort
        result = 31 * result + dstPort
        return result
    }
}
