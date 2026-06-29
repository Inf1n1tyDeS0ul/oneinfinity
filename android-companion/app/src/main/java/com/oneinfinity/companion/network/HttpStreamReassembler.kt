package com.oneinfinity.companion.network

import android.util.Log
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

/**
 * HTTP Stream Reassembler
 *
 * Reassembles fragmented TCP packets into complete HTTP/1.x and HTTP/2 messages.
 *
 * HTTP/2 detection: checks for the client connection preface
 *   "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" (24 bytes)
 * followed by SETTINGS frame. HEADERS frames are decoded to pseudo-headers
 * (:method, :path, :authority) and forwarded as HttpMessage objects.
 */
class HttpStreamReassembler {
    private val TAG = "HttpReassembler"

    // HTTP/2 client connection preface (24 bytes)
    private val HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(StandardCharsets.US_ASCII)

    // Stream buffers keyed by connection (srcIp:srcPort->dstIp:dstPort)
    private val streams = mutableMapOf<String, StreamBuffer>()

    // Per-connection HTTP/2 state: tracks whether the connection is h2
    private val http2Connections = mutableSetOf<String>()

    // Per-connection HTTP/2 HPACK header table (simplified: store last seen headers)
    private val http2Headers = mutableMapOf<String, MutableMap<String, String>>()

    fun processPacket(packet: ParsedPacket): HttpMessage? {
        if (!packet.isHttp && !packet.isHttps) return null
        if (packet.payload.isEmpty()) return null

        val connKey = "${packet.srcIp}:${packet.srcPort}->${packet.dstIp}:${packet.dstPort}"

        // Detect HTTP/2 preface on first payload
        if (connKey !in http2Connections && isHttp2Preface(packet.payload)) {
            http2Connections.add(connKey)
            Log.d(TAG, "HTTP/2 connection detected: $connKey")
        }

        return if (connKey in http2Connections) {
            processHttp2Payload(packet.payload, connKey)
        } else {
            processHttp1Payload(packet.payload, connKey)
        }
    }

    fun reset() {
        streams.clear()
        http2Connections.clear()
        http2Headers.clear()
    }

    // ── HTTP/2 ────────────────────────────────────────────────────────────

    private fun isHttp2Preface(data: ByteArray): Boolean {
        if (data.size < HTTP2_PREFACE.size) return false
        return HTTP2_PREFACE.indices.all { data[it] == HTTP2_PREFACE[it] }
    }

    /**
     * Parse HTTP/2 frames from raw TCP payload.
     * Returns the first HEADERS frame found as an HttpMessage (simplified — no full HPACK).
     *
     * Frame format: 3-byte length | 1-byte type | 1-byte flags | 4-byte stream-id | payload
     * Type 0x1 = HEADERS, Type 0x0 = DATA
     */
    private fun processHttp2Payload(data: ByteArray, connKey: String): HttpMessage? {
        // Skip preface if present
        val start = if (isHttp2Preface(data)) HTTP2_PREFACE.size else 0
        if (data.size - start < 9) return null

        try {
            val buf = ByteBuffer.wrap(data, start, data.size - start)
            while (buf.remaining() >= 9) {
                val len = ((buf.get().toInt() and 0xFF) shl 16) or
                          ((buf.get().toInt() and 0xFF) shl 8) or
                           (buf.get().toInt() and 0xFF)
                val type = buf.get().toInt() and 0xFF
                val flags = buf.get().toInt() and 0xFF
                val streamId = buf.int and 0x7FFFFFFF  // clear reserved bit

                if (buf.remaining() < len) break

                val payload = ByteArray(len)
                buf.get(payload)

                when (type) {
                    0x1 -> {  // HEADERS frame
                        val msg = decodeHttp2Headers(payload, flags, streamId, connKey)
                        if (msg != null) return msg
                    }
                    0x0 -> {  // DATA frame — attach to last request in this connection
                        // Data frames carry the body; for now surface them as a response hint
                        Log.d(TAG, "HTTP/2 DATA frame: stream=$streamId len=$len")
                    }
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "HTTP/2 frame parse error on $connKey: ${e.message}")
        }
        return null
    }

    /**
     * Simplified HPACK decode — extracts literal header fields (no Huffman).
     * Sufficient for :method, :path, :authority, content-type etc.
     */
    private fun decodeHttp2Headers(
        payload: ByteArray, flags: Int, streamId: Int, connKey: String
    ): HttpMessage? {
        // Skip PADDED and PRIORITY flags overhead
        var offset = 0
        val padded = (flags and 0x8) != 0
        val priority = (flags and 0x20) != 0

        val padLength = if (padded && payload.isNotEmpty()) payload[offset++].toInt() and 0xFF else 0
        if (priority) offset += 5  // 4 bytes stream dep + 1 byte weight

        val headers = mutableMapOf<String, String>()
        val end = payload.size - padLength

        while (offset < end) {
            val b = payload[offset].toInt() and 0xFF

            when {
                // Indexed header (bit 7 set)
                b and 0x80 != 0 -> {
                    offset++
                    // Static table lookup — we only care about common pseudo-headers
                    when (b and 0x7F) {
                        2  -> headers[":method"] = "GET"
                        3  -> headers[":method"] = "POST"
                        4  -> headers[":method"] = "GET"  // :method GET (index 4)
                        5  -> headers[":method"] = "POST" // :method POST (index 5)
                        else -> { /* other static entries — skip */ }
                    }
                }
                // Literal with incremental indexing (bits 7-6 = 01)
                b and 0xC0 == 0x40 -> {
                    offset++
                    val (name, value, newOffset) = readLiteralHeader(payload, offset, b and 0x3F)
                    offset = newOffset
                    if (name.isNotEmpty()) headers[name] = value
                }
                // Literal without indexing (bits 7-4 = 0000)
                b and 0xF0 == 0x00 -> {
                    offset++
                    val (name, value, newOffset) = readLiteralHeader(payload, offset, b and 0x0F)
                    offset = newOffset
                    if (name.isNotEmpty()) headers[name] = value
                }
                // Literal never indexed (bits 7-4 = 0001)
                b and 0xF0 == 0x10 -> {
                    offset++
                    val (name, value, newOffset) = readLiteralHeader(payload, offset, b and 0x0F)
                    offset = newOffset
                    if (name.isNotEmpty()) headers[name] = value
                }
                else -> { offset++; }
            }
        }

        // Cache for this connection
        http2Headers.getOrPut(connKey) { mutableMapOf() }.putAll(headers)

        val method = headers[":method"] ?: return null
        val path = headers[":path"] ?: "/"
        val authority = headers[":authority"] ?: headers["host"] ?: ""
        val scheme = headers[":scheme"] ?: "https"
        val url = if (authority.isNotEmpty()) "$scheme://$authority$path" else path

        val normalHeaders = headers.filterKeys { !it.startsWith(":") }

        Log.d(TAG, "HTTP/2 HEADERS: $method $url stream=$streamId")

        return HttpMessage(
            type = HttpMessage.Type.REQUEST,
            method = method,
            url = url,
            version = "HTTP/2",
            statusCode = null,
            statusMessage = null,
            headers = normalHeaders,
            body = ""
        )
    }

    /** Read a HPACK literal header field (name + value) starting at offset. */
    private fun readLiteralHeader(
        payload: ByteArray, startOffset: Int, nameIndex: Int
    ): Triple<String, String, Int> {
        var offset = startOffset
        val name: String

        if (nameIndex == 0) {
            // New name follows
            if (offset >= payload.size) return Triple("", "", offset)
            val (n, newOff) = readHpackString(payload, offset)
            name = n; offset = newOff
        } else {
            // Static table name lookup (partial)
            name = HPACK_STATIC_NAMES.getOrElse(nameIndex) { "" }
        }

        if (offset >= payload.size) return Triple(name, "", offset)
        val (value, newOff) = readHpackString(payload, offset)
        return Triple(name, value, newOff)
    }

    /** Read a HPACK string (length-prefixed, no Huffman decode). */
    private fun readHpackString(payload: ByteArray, startOffset: Int): Pair<String, Int> {
        if (startOffset >= payload.size) return Pair("", startOffset)
        val b = payload[startOffset].toInt() and 0xFF
        // val huffman = (b and 0x80) != 0  // Huffman not implemented; treat as literal
        var offset = startOffset + 1
        val len = b and 0x7F
        if (offset + len > payload.size) return Pair("", payload.size)
        val str = String(payload, offset, len, StandardCharsets.UTF_8)
        return Pair(str, offset + len)
    }

    // ── HTTP/1.x ──────────────────────────────────────────────────────────

    private fun processHttp1Payload(data: ByteArray, connKey: String): HttpMessage? {
        val stream = streams.getOrPut(connKey) { StreamBuffer() }
        stream.append(data)

        val message = stream.extractMessage()
        if (message != null) {
            streams.remove(connKey)
        }
        return message
    }

    private class StreamBuffer {
        private val buffer = ByteArrayOutputStream()

        fun append(data: ByteArray) {
            buffer.write(data)
        }

        fun extractMessage(): HttpMessage? {
            val data = buffer.toByteArray()
            if (data.isEmpty()) return null

            val text = String(data, StandardCharsets.UTF_8)

            if (text.startsWith("GET ") || text.startsWith("POST ") ||
                text.startsWith("PUT ") || text.startsWith("DELETE ") ||
                text.startsWith("PATCH ") || text.startsWith("HEAD ") ||
                text.startsWith("OPTIONS ")
            ) {
                return parseHttpRequest(text)
            }

            if (text.startsWith("HTTP/")) {
                return parseHttpResponse(text)
            }

            return null
        }

        private fun parseHttpRequest(text: String): HttpMessage? {
            val lines = text.split("\r\n")
            if (lines.isEmpty()) return null

            val requestLine = lines[0].split(" ")
            if (requestLine.size < 3) return null

            val method = requestLine[0]
            val url = requestLine[1]
            val version = requestLine[2]

            val headers = mutableMapOf<String, String>()
            var bodyStartIndex = 1

            for (i in 1 until lines.size) {
                val line = lines[i]
                if (line.isEmpty()) { bodyStartIndex = i + 1; break }
                val colonIndex = line.indexOf(':')
                if (colonIndex > 0) {
                    headers[line.substring(0, colonIndex).trim()] = line.substring(colonIndex + 1).trim()
                }
            }

            val body = if (bodyStartIndex < lines.size)
                lines.subList(bodyStartIndex, lines.size).joinToString("\r\n") else ""

            return HttpMessage(
                type = HttpMessage.Type.REQUEST, method = method, url = url,
                version = version, statusCode = null, statusMessage = null,
                headers = headers, body = body
            )
        }

        private fun parseHttpResponse(text: String): HttpMessage? {
            val lines = text.split("\r\n")
            if (lines.isEmpty()) return null

            val statusLine = lines[0].split(" ", limit = 3)
            if (statusLine.size < 2) return null

            val version = statusLine[0]
            val statusCode = statusLine[1].toIntOrNull() ?: return null
            val statusMessage = if (statusLine.size >= 3) statusLine[2] else ""

            val headers = mutableMapOf<String, String>()
            var bodyStartIndex = 1

            for (i in 1 until lines.size) {
                val line = lines[i]
                if (line.isEmpty()) { bodyStartIndex = i + 1; break }
                val colonIndex = line.indexOf(':')
                if (colonIndex > 0) {
                    headers[line.substring(0, colonIndex).trim()] = line.substring(colonIndex + 1).trim()
                }
            }

            val body = if (bodyStartIndex < lines.size)
                lines.subList(bodyStartIndex, lines.size).joinToString("\r\n") else ""

            return HttpMessage(
                type = HttpMessage.Type.RESPONSE, method = null, url = null,
                version = version, statusCode = statusCode, statusMessage = statusMessage,
                headers = headers, body = body
            )
        }
    }

    companion object {
        // Partial HPACK static table — only names we care about
        private val HPACK_STATIC_NAMES = mapOf(
            1 to ":authority", 2 to ":method", 3 to ":method",
            4 to ":path", 5 to ":path", 6 to ":scheme", 7 to ":scheme",
            8 to ":status", 9 to ":status", 10 to ":status",
            11 to ":status", 12 to ":status", 13 to ":status", 14 to ":status",
            15 to "accept-charset", 16 to "accept-encoding", 17 to "accept-language",
            18 to "accept-ranges", 19 to "accept", 20 to "access-control-allow-origin",
            21 to "age", 22 to "allow", 23 to "authorization",
            24 to "cache-control", 25 to "content-disposition",
            26 to "content-encoding", 27 to "content-language",
            28 to "content-length", 29 to "content-location",
            30 to "content-range", 31 to "content-type",
            32 to "cookie", 33 to "date", 34 to "etag",
            35 to "expect", 36 to "expires", 37 to "from",
            38 to "host", 39 to "if-match", 40 to "if-modified-since",
            41 to "if-none-match", 42 to "if-range", 43 to "if-unmodified-since",
            44 to "last-modified", 45 to "link", 46 to "location",
            47 to "max-forwards", 48 to "proxy-authenticate",
            49 to "proxy-authorization", 50 to "range", 51 to "referer",
            52 to "refresh", 53 to "retry-after", 54 to "server",
            55 to "set-cookie", 56 to "strict-transport-security",
            57 to "transfer-encoding", 58 to "user-agent",
            59 to "vary", 60 to "via", 61 to "www-authenticate"
        )
    }
}

data class HttpMessage(
    val type: Type,
    val method: String?,
    val url: String?,
    val version: String,
    val statusCode: Int?,
    val statusMessage: String?,
    val headers: Map<String, String>,
    val body: String
) {
    enum class Type { REQUEST, RESPONSE }

    fun toJson(): Map<String, Any?> = mapOf(
        "type" to type.name.lowercase(),
        "method" to method,
        "url" to url,
        "version" to version,
        "status_code" to statusCode,
        "status_message" to statusMessage,
        "headers" to headers,
        "body" to body
    )

    override fun toString(): String = when (type) {
        Type.REQUEST -> "$method $url $version"
        Type.RESPONSE -> "$version $statusCode $statusMessage"
    }
}
