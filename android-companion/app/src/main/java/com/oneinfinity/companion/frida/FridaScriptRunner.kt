package com.oneinfinity.companion.frida

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject

/**
 * FridaScriptRunner — receives and forwards Frida output from the backend.
 *
 * ARCHITECTURE CORRECTION (Fix #11):
 * ─────────────────────────────────────────────────────────────────────────
 * The original implementation tried to execute:
 *   Runtime.getRuntime().exec(arrayOf("frida", "-U", "-f", pkg, "-l", script))
 *
 * This is ARCHITECTURALLY INCORRECT for two reasons:
 *   1. `frida` is a HOST-MACHINE CLI tool. It is NOT available inside an
 *      Android app process — it does not exist in the device's PATH.
 *   2. Even if it were available, running `frida -U` FROM the device would
 *      try to connect to a Frida server via USB from inside the device itself,
 *      which is a logical impossibility.
 *
 * CORRECT ARCHITECTURE:
 *   ┌─────────────┐   WebSocket   ┌────────────────────────────────────┐
 *   │  Android    │◄─────────────►│  OneInfinity Backend (host)        │
 *   │  Companion  │  frida_inject │  mobile_frida_api._inject_via_     │
 *   │             │  command      │  companion() sends to WebSocket     │
 *   └─────┬───────┘               └────────────┬───────────────────────┘
 *         │ frida-server                        │ frida -U -f <pkg> -l <script>
 *         │ running on device                   │ (runs on HOST, connects to
 *         │                                     │  device via adb/USB)
 *         └─────────────────────────────────────┘
 *              frida-server listens on :27042
 *
 * The Android companion's role:
 *   1. Keep frida-server running (FridaManager)
 *   2. Send {type:frida_server_ready} when ready for host to connect
 *   3. Receive {type:frida_output} from backend with findings
 *   4. Forward findings back via onFindingReady (for UI/logging)
 *
 * This class handles step 3-4: processing Frida output received FROM the backend.
 */
class FridaScriptRunner(
    private val deviceId: String,
    private val onFindingReady: (JSONObject) -> Unit,
    private val onLog: (String) -> Unit
) {
    private val TAG = "FridaScriptRunner"

    /**
     * Process a {type:frida_output} message received from the backend.
     * The backend ran `frida -U -f <pkg>` on the host side, parsed the output
     * using frida_wrapper._parse_frida_output(), and sent findings back here.
     */
    fun processBackendFridaOutput(msg: JSONObject) {
        val sessionId = msg.optString("session_id", "")
        val scriptName = msg.optString("script_name", "unknown")
        val output = msg.optString("output", "")
        val hasFinding = msg.optBoolean("has_finding", false)
        val finding = msg.optJSONObject("finding")

        // Log to local output
        if (output.isNotEmpty()) {
            onLog("[$scriptName] ${output.take(200)}")
        }

        // If a structured finding was included, relay it back
        if (finding != null) {
            val result = JSONObject().apply {
                put("type", "frida_finding_received")
                put("session_id", sessionId)
                put("device_id", deviceId)
                put("script_name", scriptName)
                put("finding", finding)
                put("timestamp", System.currentTimeMillis() / 1000L)
            }
            onFindingReady(result)

            val vuln = finding.optString("vulnerability", "finding")
            val severity = finding.optString("severity", "?")
            onLog("[$scriptName] FINDING [$severity]: $vuln")
        }

        // Session events
        val eventType = msg.optString("type", "")
        if (eventType == "frida_session_event") {
            val event = msg.optString("event", "")
            val count = msg.optInt("findings_count", 0)
            onLog("[$scriptName] Session $sessionId $event" +
                  (if (count > 0) " — $count findings" else ""))
        }
    }

    fun stopAll() {
        // Nothing to stop locally — execution is on the host
        onLog("[FridaScriptRunner] stop requested (host-side execution)")
    }
}
