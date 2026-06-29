package com.oneinfinity.companion.attack

import android.util.Log
import org.json.JSONObject
import java.net.URL
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

/**
 * PayloadInjector — Mid-flight HTTP request modification
 *
 * Receives inject_payload commands from the OneInfinity backend.
 * When VpnCaptureService intercepts an HTTP request matching the registered
 * URL pattern, PayloadInjector modifies the packet payload before forwarding
 * it through the VPN tunnel. This achieves true in-app interception without
 * an external proxy — the modification happens inside the device itself.
 *
 * Command format received from backend:
 * {
 *   "type": "inject_payload",
 *   "injection_id": "abc123",
 *   "url_pattern": "api/login",
 *   "param": "username",
 *   "payload": "' OR '1'='1",
 *   "vuln_type": "sqli",
 *   "position": "body|query|header",
 *   "capture_response": true
 * }
 */
class PayloadInjector(
    private val deviceId: String,
    private val onResultReady: (result: InjectionResult) -> Unit
) {
    private val TAG = "PayloadInjector"

    // Active injections keyed by injection_id
    private val pendingInjections = ConcurrentHashMap<String, InjectionSpec>()

    // URL-pattern index for fast lookup during packet processing
    private val patternIndex = CopyOnWriteArrayList<InjectionSpec>()

    private val isActive = AtomicBoolean(false)

    // ── Public API ────────────────────────────────────────────────────────

    fun activate() {
        isActive.set(true)
        Log.i(TAG, "PayloadInjector activated")
    }

    fun deactivate() {
        isActive.set(false)
        pendingInjections.clear()
        patternIndex.clear()
        Log.i(TAG, "PayloadInjector deactivated")
    }

    /**
     * Register a new injection from a backend inject_payload command.
     * Returns the injection_id.
     */
    fun registerInjection(command: JSONObject): String {
        val spec = InjectionSpec(
            injectionId = command.optString("injection_id", generateId()),
            urlPattern = command.optString("url_pattern", ""),
            param = command.optString("param", ""),
            payload = command.optString("payload", ""),
            vulnType = command.optString("vuln_type", "unknown"),
            position = InjectionPosition.fromString(command.optString("position", "body")),
            captureResponse = command.optBoolean("capture_response", true),
            singleShot = command.optBoolean("single_shot", true)
        )

        pendingInjections[spec.injectionId] = spec
        patternIndex.add(spec)

        Log.i(TAG, "Registered injection ${spec.injectionId}: ${spec.vulnType} in ${spec.param} (${spec.position})")
        return spec.injectionId
    }

    /**
     * Called by VpnCaptureService / PacketParser for every captured HTTP request.
     * Returns modified request bytes if an injection matches, or null to pass through unchanged.
     */
    fun tryInject(
        method: String,
        url: String,
        headers: Map<String, String>,
        body: ByteArray
    ): InjectedRequest? {
        if (!isActive.get()) return null

        val spec = findMatchingSpec(url) ?: return null

        Log.i(TAG, "Injecting ${spec.vulnType} payload into $url [param=${spec.param}]")

        return when (spec.position) {
            InjectionPosition.QUERY -> injectIntoQuery(method, url, headers, body, spec)
            InjectionPosition.BODY -> injectIntoBody(method, url, headers, body, spec)
            InjectionPosition.HEADER -> injectIntoHeader(method, url, headers, body, spec)
        }
    }

    /**
     * Record the response for an injection that had capture_response=true.
     * Builds an InjectionResult and invokes the callback.
     */
    fun recordResponse(
        injectionId: String,
        responseStatus: Int,
        responseHeaders: Map<String, String>,
        responseBody: ByteArray,
        durationMs: Long
    ) {
        val spec = pendingInjections[injectionId] ?: return

        val result = InjectionResult(
            injectionId = injectionId,
            deviceId = deviceId,
            vulnType = spec.vulnType,
            param = spec.param,
            payload = spec.payload,
            responseStatus = responseStatus,
            responseBody = responseBody.toString(Charsets.UTF_8),
            responseHeaders = responseHeaders,
            durationMs = durationMs,
            indicators = detectIndicators(responseBody.toString(Charsets.UTF_8), spec.vulnType)
        )

        onResultReady(result)

        if (spec.singleShot) {
            pendingInjections.remove(injectionId)
            patternIndex.remove(spec)
            Log.d(TAG, "Single-shot injection ${injectionId} consumed")
        }
    }

    // ── Injection implementations ─────────────────────────────────────────

    private fun injectIntoQuery(
        method: String, url: String,
        headers: Map<String, String>, body: ByteArray,
        spec: InjectionSpec
    ): InjectedRequest {
        val modifiedUrl = if (spec.param.isNotEmpty()) {
            replaceOrAddQueryParam(url, spec.param, spec.payload)
        } else {
            val sep = if ("?" in url) "&" else "?"
            "$url${sep}q=${urlEncode(spec.payload)}"
        }

        return InjectedRequest(
            injectionId = spec.injectionId,
            method = method,
            url = modifiedUrl,
            headers = headers,
            body = body,
            originalUrl = url
        )
    }

    private fun injectIntoBody(
        method: String, url: String,
        headers: Map<String, String>, body: ByteArray,
        spec: InjectionSpec
    ): InjectedRequest {
        val bodyStr = body.toString(Charsets.UTF_8)
        val modifiedBody = when {
            bodyStr.trimStart().startsWith("{") -> injectIntoJson(bodyStr, spec.param, spec.payload)
            "&" in bodyStr || "=" in bodyStr -> injectIntoFormData(bodyStr, spec.param, spec.payload)
            else -> spec.payload.toByteArray()
        }

        val mutableHeaders = headers.toMutableMap()
        if (!headers.containsKey("Content-Type")) {
            mutableHeaders["Content-Type"] = "application/json"
        }
        mutableHeaders["Content-Length"] = modifiedBody.size.toString()

        return InjectedRequest(
            injectionId = spec.injectionId,
            method = method,
            url = url,
            headers = mutableHeaders,
            body = modifiedBody,
            originalUrl = url
        )
    }

    private fun injectIntoHeader(
        method: String, url: String,
        headers: Map<String, String>, body: ByteArray,
        spec: InjectionSpec
    ): InjectedRequest {
        val mutableHeaders = headers.toMutableMap()
        val headerName = spec.param.ifEmpty { "X-Custom-Header" }
        mutableHeaders[headerName] = spec.payload

        return InjectedRequest(
            injectionId = spec.injectionId,
            method = method,
            url = url,
            headers = mutableHeaders,
            body = body,
            originalUrl = url
        )
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private fun findMatchingSpec(url: String): InjectionSpec? {
        if (patternIndex.isEmpty()) return null
        return patternIndex.firstOrNull { spec ->
            spec.urlPattern.isEmpty() || url.contains(spec.urlPattern, ignoreCase = true)
        }
    }

    private fun replaceOrAddQueryParam(url: String, param: String, value: String): String {
        val qIdx = url.indexOf('?')
        if (qIdx < 0) return "$url?$param=${urlEncode(value)}"

        val base = url.substring(0, qIdx)
        val query = url.substring(qIdx + 1)
        val parts = query.split("&").toMutableList()
        var replaced = false

        val newParts = parts.map { part ->
            val eqIdx = part.indexOf('=')
            if (eqIdx >= 0 && part.substring(0, eqIdx) == param) {
                replaced = true
                "$param=${urlEncode(value)}"
            } else {
                part
            }
        }.toMutableList()

        if (!replaced) newParts.add("$param=${urlEncode(value)}")
        return "$base?${newParts.joinToString("&")}"
    }

    private fun injectIntoJson(bodyStr: String, param: String, value: String): ByteArray {
        return try {
            val json = JSONObject(bodyStr)
            if (param.isNotEmpty()) {
                json.put(param, value)
            } else {
                json.put("q", value)
                json.put("query", value)
            }
            json.toString().toByteArray(Charsets.UTF_8)
        } catch (e: Exception) {
            Log.w(TAG, "JSON injection failed, using raw: ${e.message}")
            """{"${param.ifEmpty { "q" }}":"${value.replace("\"", "\\\"")}"}""".toByteArray()
        }
    }

    private fun injectIntoFormData(bodyStr: String, param: String, value: String): ByteArray {
        val params = bodyStr.split("&").associate { part ->
            val idx = part.indexOf('=')
            if (idx >= 0) part.substring(0, idx) to part.substring(idx + 1) else part to ""
        }.toMutableMap()

        val targetParam = param.ifEmpty { params.keys.firstOrNull() ?: "q" }
        params[targetParam] = urlEncode(value)

        return params.entries.joinToString("&") { (k, v) -> "$k=$v" }.toByteArray()
    }

    private fun urlEncode(value: String): String =
        java.net.URLEncoder.encode(value, "UTF-8")

    private fun generateId(): String = java.util.UUID.randomUUID().toString().substring(0, 8)

    /**
     * Detect vulnerability indicators in a response body.
     */
    private fun detectIndicators(body: String, vulnType: String): List<String> {
        val indicators = mutableListOf<String>()

        // SQL errors
        val sqlPattern = Regex(
            "sql syntax|mysql_fetch|ORA-\\d+|pg_query|sqlite|SQLSTATE|syntax error",
            RegexOption.IGNORE_CASE
        )
        if (sqlPattern.containsMatchIn(body)) {
            indicators.add("sql_error_in_response")
        }

        // Stack traces
        if (body.contains("Traceback") || body.contains("at com.") || body.contains("NullPointerException")) {
            indicators.add("stack_trace_disclosed")
        }

        // SSRF success patterns
        if (body.contains("root:x:0:0") || body.contains("169.254.169.254") || body.contains("ami-id")) {
            indicators.add("ssrf_internal_data")
        }

        // Reflection (XSS)
        if (vulnType == "xss" && (body.contains("<script") || body.contains("onerror="))) {
            indicators.add("payload_reflected_unencoded")
        }

        // Sensitive field exposure
        val sensitivePattern = Regex(""""(password|api_key|secret|token)"\s*:\s*"[^"]+"""", RegexOption.IGNORE_CASE)
        if (sensitivePattern.containsMatchIn(body)) {
            indicators.add("sensitive_field_in_response")
        }

        return indicators
    }
}

// ── Data classes ──────────────────────────────────────────────────────────────

enum class InjectionPosition {
    QUERY, BODY, HEADER;

    companion object {
        fun fromString(s: String) = when (s.lowercase()) {
            "query" -> QUERY
            "header" -> HEADER
            else -> BODY
        }
    }
}

data class InjectionSpec(
    val injectionId: String,
    val urlPattern: String,
    val param: String,
    val payload: String,
    val vulnType: String,
    val position: InjectionPosition,
    val captureResponse: Boolean,
    val singleShot: Boolean = true
)

data class InjectedRequest(
    val injectionId: String,
    val method: String,
    val url: String,
    val headers: Map<String, String>,
    val body: ByteArray,
    val originalUrl: String
)

data class InjectionResult(
    val injectionId: String,
    val deviceId: String,
    val vulnType: String,
    val param: String,
    val payload: String,
    val responseStatus: Int,
    val responseBody: String,
    val responseHeaders: Map<String, String>,
    val durationMs: Long,
    val indicators: List<String>
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("type", "injection_result")
        put("injection_id", injectionId)
        put("device_id", deviceId)
        put("vuln_type", vulnType)
        put("param", param)
        put("payload", payload)
        put("response_status", responseStatus)
        put("response_body_preview", responseBody.take(500))
        put("duration_ms", durationMs)
        put("indicators", org.json.JSONArray(indicators))
        put("vulnerable", indicators.isNotEmpty())
    }
}
