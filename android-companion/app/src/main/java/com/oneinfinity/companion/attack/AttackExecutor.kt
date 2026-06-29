package com.oneinfinity.companion.attack

import android.util.Log
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * AttackExecutor — Android-side attack campaign orchestrator
 *
 * Receives attack commands from the OneInfinity backend via WebSocket and:
 *   1. Executes HTTP requests with injected payloads directly from the device
 *      (same network context as the target app — bypasses server-side IP blocks)
 *   2. Streams each result back to the backend in real-time
 *   3. Supports parallel attack execution with configurable concurrency
 *   4. Supports mid-flight injection via PayloadInjector coordination
 *
 * Command types handled:
 *   execute_attack  — run attack with payload list against endpoint
 *   inject_payload  — register mid-flight injection via PayloadInjector
 *   stop_attack     — cancel all running attacks
 *   ping            — liveness check
 */
class AttackExecutor(
    private val deviceId: String,
    private val baseUrl: String,
    private val payloadInjector: PayloadInjector,
    private val onResult: (JSONObject) -> Unit,
    private val onLog: (String) -> Unit
) {
    private val TAG = "AttackExecutor"

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .writeTimeout(15, TimeUnit.SECONDS)
        .followRedirects(true)
        .build()

    private val executor: ExecutorService = Executors.newFixedThreadPool(4)
    private val activeFutures = ConcurrentHashMap<String, Future<*>>()
    private val isStopped = AtomicBoolean(false)

    // ── Command dispatch ──────────────────────────────────────────────────

    fun handleCommand(cmd: JSONObject) {
        when (cmd.optString("type")) {
            "execute_attack"  -> handleExecuteAttack(cmd)
            "inject_payload"  -> handleInjectPayload(cmd)
            "stop_attack"     -> stopAll()
            "ping"            -> onResult(JSONObject().put("type", "pong").put("device_id", deviceId))
            else -> Log.d(TAG, "Unknown command type: ${cmd.optString("type")}")
        }
    }

    private fun handleExecuteAttack(cmd: JSONObject) {
        val attackId = cmd.optString("attack_id", generateId())
        val url = cmd.optString("url", "")
        val method = cmd.optString("method", "GET").uppercase()
        val payloads = cmd.optJSONArray("payloads") ?: JSONArray()
        val param = cmd.optString("param", "")
        val position = cmd.optString("position", "query")
        val headers = cmd.optJSONObject("headers") ?: JSONObject()
        val vulnType = cmd.optString("vuln_type", "unknown")
        val captureBaseline = cmd.optBoolean("capture_baseline", true)

        if (url.isEmpty()) {
            onLog("execute_attack: missing url")
            return
        }

        onLog("Starting attack $attackId: $vulnType on $url")
        notifyAttackStart(attackId, url, vulnType, payloads.length())

        val future = executor.submit {
            try {
                executeAttackTask(
                    attackId, url, method, payloads, param,
                    position, headers, vulnType, captureBaseline
                )
            } catch (e: Exception) {
                Log.e(TAG, "Attack $attackId error: ${e.message}")
                onLog("Attack $attackId failed: ${e.message}")
            }
            activeFutures.remove(attackId)
        }
        activeFutures[attackId] = future
    }

    private fun handleInjectPayload(cmd: JSONObject) {
        val injectionId = payloadInjector.registerInjection(cmd)
        payloadInjector.activate()
        onLog("Mid-flight injection $injectionId registered")
        onResult(JSONObject().apply {
            put("type", "injection_registered")
            put("injection_id", injectionId)
            put("device_id", deviceId)
        })
    }

    fun stopAll() {
        isStopped.set(true)
        activeFutures.values.forEach { it.cancel(true) }
        activeFutures.clear()
        payloadInjector.deactivate()
        onLog("All attacks stopped")
        isStopped.set(false)
    }

    // ── Attack execution ──────────────────────────────────────────────────

    private fun executeAttackTask(
        attackId: String,
        url: String,
        method: String,
        payloads: JSONArray,
        param: String,
        position: String,
        headers: JSONObject,
        vulnType: String,
        captureBaseline: Boolean
    ) {
        // 1. Capture baseline response
        var baselineStatus = 0
        var baselineBodyLen = 0
        var baselineMs = 0L

        if (captureBaseline) {
            val (bStatus, bBody, bMs) = makeRequest(method, url, headers, null)
            baselineStatus = bStatus
            baselineBodyLen = bBody.length
            baselineMs = bMs
        }

        // 2. Fire each payload
        var attackedCount = 0
        var foundCount = 0

        for (i in 0 until payloads.length()) {
            if (isStopped.get() || Thread.currentThread().isInterrupted) break

            val payload = payloads.optString(i, "")
            if (payload.isEmpty()) continue

            val (attackUrl, attackBody) = buildAttackRequest(url, method, param, payload, position)
            val (status, body, ms) = makeRequest(method, attackUrl, headers, attackBody)

            attackedCount++

            val indicators = detectIndicators(body, vulnType, ms, baselineMs)
            val vulnerable = indicators.isNotEmpty() ||
                (status != baselineStatus && status in listOf(200, 201, 500))

            if (vulnerable || status != baselineStatus) {
                foundCount++
                streamResult(attackId, url, method, param, payload, vulnType,
                    baselineStatus, status, baselineMs, ms, body, indicators)
            }
        }

        // 3. Report completion
        onResult(JSONObject().apply {
            put("type", "attack_complete")
            put("attack_id", attackId)
            put("device_id", deviceId)
            put("url", url)
            put("vuln_type", vulnType)
            put("payloads_tested", attackedCount)
            put("findings_count", foundCount)
        })

        onLog("Attack $attackId complete: $foundCount/$attackedCount findings on $url")
    }

    // ── HTTP request ──────────────────────────────────────────────────────

    private fun makeRequest(
        method: String,
        url: String,
        headers: JSONObject,
        body: String?
    ): Triple<Int, String, Long> {
        return try {
            val requestBuilder = Request.Builder().url(url)

            // Add headers
            for (key in headers.keys()) {
                requestBuilder.header(key, headers.getString(key))
            }
            if (!headers.has("User-Agent")) {
                requestBuilder.header("User-Agent", "OneInfinity-MobileAgent/2.0")
            }

            // Build body
            val reqBody: RequestBody? = if (body != null) {
                val ct = if (body.trimStart().startsWith("{")) "application/json" else "application/x-www-form-urlencoded"
                body.toRequestBody(ct.toMediaType())
            } else if (method in listOf("POST", "PUT", "PATCH")) {
                "".toRequestBody("application/json".toMediaType())
            } else null

            val request = requestBuilder.method(method, reqBody).build()

            val t0 = System.currentTimeMillis()
            httpClient.newCall(request).execute().use { response ->
                val ms = System.currentTimeMillis() - t0
                val responseBody = try {
                    response.body?.string()?.take(65536) ?: ""
                } catch (e: Exception) { "" }
                Triple(response.code, responseBody, ms)
            }
        } catch (e: IOException) {
            Log.d(TAG, "Request error: ${e.message}")
            Triple(0, "", 0L)
        } catch (e: Exception) {
            Log.d(TAG, "Unexpected error: ${e.message}")
            Triple(0, "", 0L)
        }
    }

    // ── Request builder ───────────────────────────────────────────────────

    private fun buildAttackRequest(
        url: String, method: String,
        param: String, payload: String, position: String
    ): Pair<String, String?> {
        return when (position.lowercase()) {
            "query" -> {
                val sep = if ("?" in url) "&" else "?"
                val targetParam = param.ifEmpty { "q" }
                Pair("$url$sep$targetParam=${urlEncode(payload)}", null)
            }
            "body" -> {
                val body = if (param.isNotEmpty()) {
                    """{"$param":"${payload.replace("\"", "\\\"")}"}"""
                } else {
                    """{"q":"${payload.replace("\"", "\\\"")}","query":"${payload.replace("\"", "\\\"")}"}"""
                }
                Pair(url, body)
            }
            "header" -> {
                // Header injection handled separately by injector; pass through
                Pair(url, null)
            }
            else -> Pair(url, null)
        }
    }

    // ── Result streaming ──────────────────────────────────────────────────

    private fun streamResult(
        attackId: String,
        url: String,
        method: String,
        param: String,
        payload: String,
        vulnType: String,
        baselineStatus: Int,
        attackStatus: Int,
        baselineMs: Long,
        attackMs: Long,
        responseBody: String,
        indicators: List<String>
    ) {
        val result = JSONObject().apply {
            put("type", "attack_finding")
            put("attack_id", attackId)
            put("device_id", deviceId)
            put("url", url)
            put("method", method)
            put("param", param)
            put("payload", payload)
            put("vuln_type", vulnType)
            put("baseline_status", baselineStatus)
            put("attack_status", attackStatus)
            put("baseline_ms", baselineMs)
            put("attack_ms", attackMs)
            put("response_preview", responseBody.take(300))
            put("indicators", JSONArray(indicators))
            put("vulnerable", indicators.isNotEmpty())
            put("timing_anomaly", attackMs > baselineMs * 3 && attackMs > 3000)
            put("timestamp", System.currentTimeMillis() / 1000L)
        }
        onResult(result)
    }

    private fun notifyAttackStart(attackId: String, url: String, vulnType: String, payloadCount: Int) {
        onResult(JSONObject().apply {
            put("type", "attack_started")
            put("attack_id", attackId)
            put("device_id", deviceId)
            put("url", url)
            put("vuln_type", vulnType)
            put("payload_count", payloadCount)
        })
    }

    // ── Vulnerability detection ───────────────────────────────────────────

    private fun detectIndicators(
        body: String, vulnType: String, attackMs: Long, baselineMs: Long
    ): List<String> {
        val indicators = mutableListOf<String>()

        // SQL errors
        if (Regex("sql syntax|mysql_fetch|ORA-\\d+|pg_query|sqlite|SQLSTATE|syntax error", RegexOption.IGNORE_CASE).containsMatchIn(body)) {
            indicators.add("sql_error")
        }

        // Stack traces
        if (body.contains("Traceback") || body.contains("at com.") || body.contains("NullPointerException")) {
            indicators.add("stack_trace")
        }

        // SSRF
        if (body.contains("root:x:0:0") || body.contains("169.254.169.254") || body.contains("ami-id")) {
            indicators.add("ssrf_success")
        }

        // XSS reflection
        if (vulnType == "xss" && (body.contains("<script") || body.contains("onerror="))) {
            indicators.add("xss_reflected")
        }

        // Sensitive data
        if (Regex(""""(password|api_key|secret|token)"\s*:\s*"[^"]+"""", RegexOption.IGNORE_CASE).containsMatchIn(body)) {
            indicators.add("sensitive_data_leak")
        }

        // NoSQL error
        if (Regex("mongodb|bson|CastError|ValidationError", RegexOption.IGNORE_CASE).containsMatchIn(body)) {
            indicators.add("nosql_error")
        }

        // Time-based blind (3× baseline)
        if (baselineMs > 0 && attackMs > baselineMs * 3 && attackMs > 3000) {
            indicators.add("timing_anomaly_${attackMs}ms")
        }

        return indicators
    }

    private fun urlEncode(value: String): String =
        java.net.URLEncoder.encode(value, "UTF-8")

    private fun generateId(): String =
        java.util.UUID.randomUUID().toString().substring(0, 8)

    fun shutdown() {
        stopAll()
        executor.shutdown()
        executor.awaitTermination(5, TimeUnit.SECONDS)
    }
}
