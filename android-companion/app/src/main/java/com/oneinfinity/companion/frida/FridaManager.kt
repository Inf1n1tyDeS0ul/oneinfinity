package com.oneinfinity.companion.frida

import android.util.Log
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * FridaManager — frida-server lifecycle on the companion device.
 *
 * ARCHITECTURE NOTE (Fix #11):
 * The actual Frida script execution (`frida -U -f <pkg> -l <script>`) runs
 * on the HOST machine that has adb access, NOT inside this Android app.
 * The companion app's role is:
 *   1. Manage frida-server binary on the device (/data/local/tmp/frida-server)
 *   2. Receive {type:frida_inject} commands from the backend
 *   3. Acknowledge receipt — the BACKEND runs "frida -U" on the host side
 *   4. Stream {type:frida_output} results back from the backend to the app
 *
 * Fix #9: isFridaServerAvailable() uses `ps` via `su` instead of `frida-ps`
 *         (which is a host binary and doesn't exist on the Android device).
 * Fix #10: startFridaServer() and stopFridaServer() prefix commands with `su -c`
 *          since frida-server requires root on Android.
 */
class FridaManager(
    private val deviceId: String,
    private val onFindingReady: (JSONObject) -> Unit,
    private val onLog: (String) -> Unit
) {
    private val TAG = "FridaManager"

    private val serverPath = "/data/local/tmp/frida-server"
    private val serverRunning = AtomicBoolean(false)
    private val executor = Executors.newCachedThreadPool()

    // Exposed so MainActivity can route frida_output messages to it
    val scriptRunner = FridaScriptRunner(
        deviceId = deviceId,
        onFindingReady = onFindingReady,
        onLog = onLog
    )
    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()
    private var healthCheckFuture: ScheduledFuture<*>? = null

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    fun start() {
        if (!isFridaServerAvailable()) {
            startFridaServer()
        } else {
            serverRunning.set(true)
            onLog("[FridaManager] frida-server already running")
        }
        // Health check every 30s — auto-restart if crashed
        healthCheckFuture = scheduler.scheduleAtFixedRate({
            val nowRunning = isFridaServerAvailable()
            if (serverRunning.get() && !nowRunning) {
                onLog("[FridaManager] frida-server died, restarting…")
                startFridaServer()
            }
            serverRunning.set(nowRunning)
        }, 30, 30, TimeUnit.SECONDS)
    }

    fun stop() {
        healthCheckFuture?.cancel(false)
        stopFridaServer()
        executor.shutdown()
        onLog("[FridaManager] stopped")
    }

    // ── Command routing ───────────────────────────────────────────────────────

    fun handleCommand(cmd: JSONObject) {
        when (cmd.optString("type")) {
            "frida_inject" -> handleInject(cmd)
            "frida_stop"   -> stopFridaServer()
            "frida_status" -> sendStatus()
            else -> Log.d(TAG, "Unknown frida command: ${cmd.optString("type")}")
        }
    }

    private fun handleInject(cmd: JSONObject) {
        val sessionId = cmd.optString("session_id", "")
        val scriptName = cmd.optString("script_name", "custom")
        val packageName = cmd.optString("package_name", "")

        if (packageName.isEmpty()) {
            onLog("[FridaManager] inject rejected: missing package_name")
            return
        }

        // ARCHITECTURE (Fix #11): The Android app does NOT execute frida commands.
        // frida is a HOST tool. This app:
        //   1. Ensures frida-server is running on the device (so host can connect)
        //   2. Acknowledges the inject command back to the backend
        //
        // The BACKEND (host machine) then runs:
        //   frida -U -f <packageName> -l <scriptFile> --no-pause
        // and streams output back via WebSocket.

        // Ensure frida-server is running so host can connect
        if (!isFridaServerAvailable()) {
            onLog("[FridaManager] frida-server not running, starting for session $sessionId…")
            startFridaServer()
            // Give it 2s to start
            Thread.sleep(2000)
        }

        // Acknowledge to backend — it will now execute frida on the host side
        val ack = JSONObject().apply {
            put("type", "frida_server_ready")
            put("session_id", sessionId)
            put("device_id", deviceId)
            put("package_name", packageName)
            put("script_name", scriptName)
            put("server_running", isFridaServerAvailable())
            put("message", "frida-server ready on device — host can connect via frida -U")
            put("timestamp", System.currentTimeMillis() / 1000L)
        }
        onFindingReady(ack)
        onLog("[FridaManager] Session $sessionId: ready for ${packageName}")
    }

    private fun sendStatus() {
        val running = isFridaServerAvailable()
        serverRunning.set(running)
        val status = JSONObject().apply {
            put("type", "frida_status")
            put("device_id", deviceId)
            put("server_running", running)
            put("server_path", serverPath)
            put("server_binary_exists", File(serverPath).exists())
        }
        onFindingReady(status)
    }

    // ── frida-server process management ───────────────────────────────────────

    private fun startFridaServer() {
        if (!File(serverPath).exists()) {
            onLog("[FridaManager] frida-server binary not found at $serverPath")
            onLog("[FridaManager] Deploy it using: POST /api/mobile/frida/server/push")
            serverRunning.set(false)
            return
        }

        executor.submit {
            try {
                // FIX #10: Use `su -c` — frida-server requires root on Android
                val chmodResult = Runtime.getRuntime()
                    .exec(arrayOf("su", "-c", "chmod +x $serverPath"))
                chmodResult.waitFor(5, TimeUnit.SECONDS)

                // Start frida-server in background mode
                val startProc = Runtime.getRuntime()
                    .exec(arrayOf("su", "-c", "$serverPath -D"))
                serverRunning.set(true)
                onLog("[FridaManager] frida-server started at $serverPath")

                startProc.waitFor()
                serverRunning.set(false)
                onLog("[FridaManager] frida-server exited")

            } catch (e: Exception) {
                serverRunning.set(false)
                onLog("[FridaManager] frida-server start failed: ${e.message}")
                Log.e(TAG, "frida-server start failed", e)
            }
        }
    }

    private fun stopFridaServer() {
        try {
            // FIX #10: Use `su -c` for pkill too
            Runtime.getRuntime()
                .exec(arrayOf("su", "-c", "pkill -f frida-server"))
                .waitFor(5, TimeUnit.SECONDS)
            serverRunning.set(false)
            onLog("[FridaManager] frida-server stopped")
        } catch (e: Exception) {
            Log.w(TAG, "frida-server stop error: ${e.message}")
        }
    }

    /**
     * FIX #9: Use `su -c ps | grep frida-server` to check if the process is
     * running on the Android device. The original code used `frida-ps -U` which
     * is a HOST-MACHINE binary and does not exist in the Android app context.
     */
    fun isFridaServerAvailable(): Boolean {
        // Fast path: if we started it and haven't detected a crash, trust the flag
        if (serverRunning.get()) return true

        // Verify via `ps` (works on rooted devices without su for ps)
        return try {
            val proc = Runtime.getRuntime().exec(arrayOf("su", "-c", "ps -e"))
            val output = proc.inputStream.bufferedReader().readText()
            proc.waitFor(5, TimeUnit.SECONDS)
            output.contains("frida-server")
        } catch (e: Exception) {
            // ps may fail without root; fall back to serverRunning flag
            serverRunning.get()
        }
    }
}
