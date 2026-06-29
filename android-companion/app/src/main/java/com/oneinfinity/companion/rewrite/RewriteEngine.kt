package com.oneinfinity.companion.rewrite

import android.util.Log
import org.json.JSONObject
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Priority-Ordered Rewrite Engine
 *
 * Five modes evaluated in strict priority order:
 *   1. REDIRECT       — forward request to a different host/path
 *   2. REPLACE_REQUEST  — swap entire request body
 *   3. REPLACE_RESPONSE — swap entire response body (applied post-forward)
 *   4. MODIFY_REQUEST   — edit individual headers/params/body fields
 *   5. MODIFY_RESPONSE  — edit individual response headers/status
 *
 * Wildcard: if redirect destination ends with SLASH-STAR, the original request path
 * subdirectory is appended (e.g. dest=https://evil.com/new/ + path=/api/v1/login
 * produces https://evil.com/new/api/v1/login).
 */
class RewriteEngine {
    private val TAG = "RewriteEngine"

    private val rules = CopyOnWriteArrayList<RewriteRule>()

    fun addRule(rule: RewriteRule) {
        rules.removeAll { it.id == rule.id }  // deduplicate by id
        rules.add(rule)
        Log.i(TAG, "Rule added: ${rule.id} mode=${rule.mode} pattern=${rule.urlPattern}")
    }

    fun removeRule(id: String) {
        rules.removeAll { it.id == id }
        Log.i(TAG, "Rule removed: $id")
    }

    fun listRules(): List<RewriteRule> = rules.toList()

    /**
     * Apply matching rules to an outbound request.
     * Returns a RewriteResult if any rule matched, null to pass through unchanged.
     * Rules are evaluated in priority order: REDIRECT > REPLACE_REQUEST > MODIFY_REQUEST.
     */
    fun applyToRequest(
        method: String,
        url: String,
        headers: Map<String, String>,
        body: ByteArray
    ): RewriteResult? {
        val activeRules = rules.filter { it.enabled && matchesUrl(it.urlPattern, url) }
        if (activeRules.isEmpty()) return null

        // Priority 1: REDIRECT
        activeRules.firstOrNull { it.mode == RewriteMode.REDIRECT }?.let { rule ->
            val dest = rule.config.optString("destination", "")
            if (dest.isEmpty()) return@let
            val newUrl = buildRedirectUrl(dest, url)
            Log.i(TAG, "REDIRECT: $url → $newUrl")
            return RewriteResult(
                mode = RewriteMode.REDIRECT,
                method = method,
                url = newUrl,
                headers = headers,
                body = body,
                ruleId = rule.id
            )
        }

        // Priority 2: REPLACE_REQUEST
        activeRules.firstOrNull { it.mode == RewriteMode.REPLACE_REQUEST }?.let { rule ->
            val replacement = rule.config.optString("body", "")
            val newBody = replacement.toByteArray(Charsets.UTF_8)
            val newHeaders = headers.toMutableMap().apply {
                put("Content-Length", newBody.size.toString())
                rule.config.optString("content_type").takeIf { it.isNotEmpty() }?.let {
                    put("Content-Type", it)
                }
            }
            Log.i(TAG, "REPLACE_REQUEST: $url body replaced (${newBody.size} bytes)")
            return RewriteResult(
                mode = RewriteMode.REPLACE_REQUEST,
                method = method,
                url = url,
                headers = newHeaders,
                body = newBody,
                ruleId = rule.id
            )
        }

        // Priority 3: MODIFY_REQUEST
        activeRules.firstOrNull { it.mode == RewriteMode.MODIFY_REQUEST }?.let { rule ->
            var newUrl = url
            val newHeaders = headers.toMutableMap()
            var newBody = body

            // Modify query params
            rule.config.optJSONObject("params")?.let { params ->
                for (key in params.keys()) {
                    newUrl = replaceOrAddQueryParam(newUrl, key, params.getString(key))
                }
            }

            // Modify headers
            rule.config.optJSONObject("headers")?.let { hdrs ->
                for (key in hdrs.keys()) {
                    if (hdrs.getString(key).isEmpty()) {
                        newHeaders.remove(key)
                    } else {
                        newHeaders[key] = hdrs.getString(key)
                    }
                }
            }

            // Modify body field (JSON only)
            rule.config.optJSONObject("body_fields")?.let { fields ->
                try {
                    val json = JSONObject(String(body, Charsets.UTF_8))
                    for (key in fields.keys()) json.put(key, fields.get(key))
                    newBody = json.toString().toByteArray(Charsets.UTF_8)
                    newHeaders["Content-Length"] = newBody.size.toString()
                } catch (e: Exception) { Log.w(TAG, "Body field injection failed: ${e.message}") }
            }

            Log.i(TAG, "MODIFY_REQUEST: $url headers/params/body modified")
            return RewriteResult(
                mode = RewriteMode.MODIFY_REQUEST,
                method = method,
                url = newUrl,
                headers = newHeaders,
                body = newBody,
                ruleId = rule.id
            )
        }

        return null
    }

    /**
     * Apply REPLACE_RESPONSE / MODIFY_RESPONSE rules to an inbound response.
     * Returns modified body bytes, or null to pass through.
     */
    fun applyToResponse(
        url: String,
        statusCode: Int,
        headers: Map<String, String>,
        body: ByteArray
    ): ResponseRewriteResult? {
        val activeRules = rules.filter { it.enabled && matchesUrl(it.urlPattern, url) }

        // Priority 1: REPLACE_RESPONSE
        activeRules.firstOrNull { it.mode == RewriteMode.REPLACE_RESPONSE }?.let { rule ->
            val replacement = rule.config.optString("body", "")
            val newBody = replacement.toByteArray(Charsets.UTF_8)
            val newHeaders = headers.toMutableMap().apply {
                put("Content-Length", newBody.size.toString())
            }
            Log.i(TAG, "REPLACE_RESPONSE: $url body replaced")
            return ResponseRewriteResult(statusCode, newHeaders, newBody, rule.id)
        }

        // Priority 2: MODIFY_RESPONSE
        activeRules.firstOrNull { it.mode == RewriteMode.MODIFY_RESPONSE }?.let { rule ->
            val newHeaders = headers.toMutableMap()
            rule.config.optJSONObject("headers")?.let { hdrs ->
                for (key in hdrs.keys()) {
                    if (hdrs.getString(key).isEmpty()) newHeaders.remove(key)
                    else newHeaders[key] = hdrs.getString(key)
                }
            }
            val newStatus = rule.config.optInt("status_code", statusCode)
            return ResponseRewriteResult(newStatus, newHeaders, body, rule.id)
        }

        return null
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private fun matchesUrl(pattern: String, url: String): Boolean {
        if (pattern.isEmpty()) return true
        val normalized = pattern.trimStart('*').trimStart('/')
        return url.contains(normalized, ignoreCase = true)
    }

    private fun buildRedirectUrl(destination: String, originalUrl: String): String {
        if (!destination.endsWith("/*")) return destination
        return try {
            val base = destination.dropLast(2)  // remove /*
            val path = java.net.URL(originalUrl).path
            "$base$path"
        } catch (_: Exception) {
            destination.dropLast(2)
        }
    }

    private fun replaceOrAddQueryParam(url: String, param: String, value: String): String {
        val qIdx = url.indexOf('?')
        if (qIdx < 0) return "$url?$param=${encode(value)}"
        val base = url.substring(0, qIdx)
        val query = url.substring(qIdx + 1)
        val parts = query.split("&").toMutableList()
        var replaced = false
        val newParts = parts.map { part ->
            val eqIdx = part.indexOf('=')
            if (eqIdx >= 0 && part.substring(0, eqIdx) == param) {
                replaced = true; "$param=${encode(value)}"
            } else part
        }.toMutableList()
        if (!replaced) newParts.add("$param=${encode(value)}")
        return "$base?${newParts.joinToString("&")}"
    }

    private fun encode(v: String) = java.net.URLEncoder.encode(v, "UTF-8")
}

// ── Data classes ──────────────────────────────────────────────────────────────

enum class RewriteMode {
    REDIRECT, REPLACE_REQUEST, REPLACE_RESPONSE, MODIFY_REQUEST, MODIFY_RESPONSE;

    companion object {
        fun fromString(s: String) = when (s.lowercase()) {
            "redirect"         -> REDIRECT
            "replace_request"  -> REPLACE_REQUEST
            "replace_response" -> REPLACE_RESPONSE
            "modify_request"   -> MODIFY_REQUEST
            "modify_response"  -> MODIFY_RESPONSE
            else               -> MODIFY_REQUEST
        }
    }
}

data class RewriteRule(
    val id: String,
    val urlPattern: String,
    val mode: RewriteMode,
    val config: JSONObject,
    val enabled: Boolean = true
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("url_pattern", urlPattern)
        put("mode", mode.name.lowercase())
        put("config", config)
        put("enabled", enabled)
    }

    companion object {
        fun fromJson(json: JSONObject): RewriteRule = RewriteRule(
            id = json.optString("id", java.util.UUID.randomUUID().toString().take(8)),
            urlPattern = json.optString("url_pattern", ""),
            mode = RewriteMode.fromString(json.optString("mode", "modify_request")),
            config = json.optJSONObject("config") ?: JSONObject(),
            enabled = json.optBoolean("enabled", true)
        )
    }
}

data class RewriteResult(
    val mode: RewriteMode,
    val method: String,
    val url: String,
    val headers: Map<String, String>,
    val body: ByteArray,
    val ruleId: String
)

data class ResponseRewriteResult(
    val statusCode: Int,
    val headers: Map<String, String>,
    val body: ByteArray,
    val ruleId: String
)
