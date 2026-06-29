package com.oneinfinity.companion.rewrite

import android.util.Log
import kotlinx.coroutines.suspendCancellableCoroutine
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume

/**
 * Breakpoint Manager — mid-flight request pause/edit/resume
 *
 * When a captured request matches a breakpoint rule:
 *   1. The VpnCaptureService calls interceptAndWait() which suspends the coroutine
 *   2. A breakpoint_hit message is sent to the backend WebSocket
 *   3. The frontend shows the request in an editor
 *   4. The tester clicks "Release" → backend sends breakpoint_resume command
 *   5. MainActivity calls resume(bpId, modifiedBytes) which unblocks the coroutine
 *   6. VpnCaptureService forwards the (possibly modified) bytes
 */
class BreakpointManager(
    private val deviceId: String,
    private val onBreakpointHit: (JSONObject) -> Unit
) {
    private val TAG = "BreakpointManager"

    private val rules = CopyOnWriteArrayList<BreakpointRule>()
    private val pending = ConcurrentHashMap<String, Continuation<ByteArray>>()
    private val pendingOriginal = ConcurrentHashMap<String, ByteArray>()

    fun addRule(rule: BreakpointRule) {
        rules.removeAll { it.id == rule.id }
        rules.add(rule)
        Log.i(TAG, "Breakpoint rule added: ${rule.id} pattern=${rule.urlPattern} dir=${rule.direction}")
    }

    fun removeRule(id: String) {
        rules.removeAll { it.id == id }
        pending[id]?.resume(pendingOriginal[id] ?: byteArrayOf())  // unblock if waiting
        pending.remove(id)
        pendingOriginal.remove(id)
    }

    fun listRules(): List<BreakpointRule> = rules.toList()

    /**
     * Check if a URL+direction matches any active breakpoint rule.
     * Returns a unique breakpoint_hit_id, or null if no match.
     */
    fun shouldBreak(url: String, direction: BreakpointDirection): String? {
        val rule = rules.firstOrNull { r ->
            r.enabled &&
            (r.direction == direction || r.direction == BreakpointDirection.BOTH) &&
            (r.urlPattern.isEmpty() || url.contains(r.urlPattern, ignoreCase = true))
        } ?: return null
        return "${rule.id}-${System.currentTimeMillis()}"
    }

    /**
     * Suspend the current coroutine until resume() is called.
     * Sends a breakpoint_hit WS message immediately.
     * Returns the (possibly modified) bytes to forward.
     */
    suspend fun interceptAndWait(
        bpId: String,
        originalBytes: ByteArray,
        url: String,
        method: String,
        headers: Map<String, String>
    ): ByteArray {
        pendingOriginal[bpId] = originalBytes

        val hitMsg = JSONObject().apply {
            put("type", "breakpoint_hit")
            put("breakpoint_id", bpId)
            put("device_id", deviceId)
            put("url", url)
            put("method", method)
            put("raw_size", originalBytes.size)
            // Send headers for display in UI
            val hdrsJson = JSONObject()
            headers.forEach { (k, v) -> hdrsJson.put(k, v) }
            put("headers", hdrsJson)
        }
        onBreakpointHit(hitMsg)
        Log.i(TAG, "Breakpoint hit: $bpId url=$url — waiting for resume")

        return suspendCancellableCoroutine { cont ->
            pending[bpId] = cont
            cont.invokeOnCancellation {
                pending.remove(bpId)
                pendingOriginal.remove(bpId)
            }
        }
    }

    /**
     * Called from MainActivity when a breakpoint_resume command arrives.
     * modifiedBase64: optional base64-encoded modified request bytes from the frontend.
     * If null/empty, original bytes are used.
     */
    fun resume(bpId: String, modifiedBase64: String?) {
        val original = pendingOriginal.remove(bpId) ?: byteArrayOf()
        val cont = pending.remove(bpId) ?: run {
            Log.w(TAG, "Resume called for unknown breakpoint: $bpId")
            return
        }

        val bytes = if (!modifiedBase64.isNullOrEmpty()) {
            try {
                android.util.Base64.decode(modifiedBase64, android.util.Base64.DEFAULT)
            } catch (e: Exception) {
                Log.w(TAG, "Base64 decode failed, using original: ${e.message}")
                original
            }
        } else {
            original
        }

        Log.i(TAG, "Breakpoint resumed: $bpId (${bytes.size} bytes)")
        cont.resume(bytes)
    }

    fun pendingCount(): Int = pending.size
}

enum class BreakpointDirection {
    REQUEST, RESPONSE, BOTH;

    companion object {
        fun fromString(s: String) = when (s.lowercase()) {
            "response" -> RESPONSE
            "both"     -> BOTH
            else       -> REQUEST
        }
    }
}

data class BreakpointRule(
    val id: String,
    val urlPattern: String,
    val direction: BreakpointDirection,
    val enabled: Boolean = true
) {
    companion object {
        fun fromJson(json: JSONObject): BreakpointRule = BreakpointRule(
            id = json.optString("id", java.util.UUID.randomUUID().toString().take(8)),
            urlPattern = json.optString("url_pattern", ""),
            direction = BreakpointDirection.fromString(json.optString("direction", "request")),
            enabled = json.optBoolean("enabled", true)
        )
    }
}
