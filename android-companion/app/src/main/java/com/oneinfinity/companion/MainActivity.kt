package com.oneinfinity.companion

import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.text.method.ScrollingMovementMethod
import android.util.Log
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.ActivityResultLauncher
import androidx.appcompat.app.AppCompatActivity
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.oneinfinity.companion.attack.AttackExecutor
import com.oneinfinity.companion.attack.PayloadInjector
import com.oneinfinity.companion.capture.EbpfCaptureManager
import com.oneinfinity.companion.capture.FridaSslHookManager
import com.oneinfinity.companion.config.BackendConfig
import com.oneinfinity.companion.config.ConfigManager
import com.oneinfinity.companion.frida.FridaManager
import com.oneinfinity.companion.network.HttpStreamReassembler
import com.oneinfinity.companion.network.WebSocketClient
import com.oneinfinity.companion.rewrite.BreakpointManager
import com.oneinfinity.companion.rewrite.BreakpointRule
import com.oneinfinity.companion.rewrite.RewriteEngine
import com.oneinfinity.companion.rewrite.RewriteRule
import com.oneinfinity.companion.utils.RootChecker
import com.oneinfinity.companion.vpn.VpnCaptureService
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException

class MainActivity : AppCompatActivity() {
    private val TAG = "OneInfinity"
    private val mainHandler = Handler(Looper.getMainLooper())

    // ── Connection ────────────────────────────────────────────────────────────
    private lateinit var websocketClient: WebSocketClient
    private lateinit var config: BackendConfig
    private var deviceId: String = ""
    private var wsToken: String = ""

    // ── Capture managers ──────────────────────────────────────────────────────
    private lateinit var ebpfManager: EbpfCaptureManager
    private lateinit var fridaSslManager: FridaSslHookManager
    private val httpReassembler = HttpStreamReassembler()

    // ── Attack / Frida (existing) ─────────────────────────────────────────────
    private lateinit var payloadInjector: PayloadInjector
    private lateinit var attackExecutor: AttackExecutor
    private lateinit var fridaManager: FridaManager

    // ── Rewrite / Breakpoint ──────────────────────────────────────────────────
    val rewriteEngine = RewriteEngine()
    lateinit var breakpointManager: BreakpointManager

    // ── UI views ──────────────────────────────────────────────────────────────
    private lateinit var tvDeviceId: TextView
    private lateinit var tvBackendUrl: TextView
    private lateinit var tvStatus: TextView
    private lateinit var tvVpnStatus: TextView
    private lateinit var tvFridaStatus: TextView
    private lateinit var tvEbpfStatus: TextView
    private lateinit var tvPacketCount: TextView
    private lateinit var tvRequestCount: TextView
    private lateinit var tvFindingCount: TextView
    private lateinit var tvLog: TextView
    private lateinit var btnVpnToggle: Button
    private lateinit var btnFridaToggle: Button
    private lateinit var btnEbpfToggle: Button

    // ── Stats ─────────────────────────────────────────────────────────────────
    private var packetCount = 0L
    private var requestCount = 0L
    private var findingCount = 0L
    private val logBuffer = StringBuilder()

    // ── QR scanner ───────────────────────────────────────────────────────────
    private val qrScanLauncher: ActivityResultLauncher<ScanOptions> =
        registerForActivityResult(ScanContract()) { result ->
            result.contents?.let { applyQrConfig(it) }
        }

    companion object {
        const val VPN_REQUEST_CODE = 100
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        bindViews()

        deviceId = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)
        tvDeviceId.text = "Device ID: $deviceId"
        intent?.data?.let { applyQrConfig(it.toString()) }

        val saved = ConfigManager.loadConfig(this)
        val defaultCfg = ConfigManager.getDefaultConfig()
        config = saved ?: defaultCfg ?: run {
            // Real device, no saved config — wait for QR scan
            tvBackendUrl.text = "Backend: Not configured"
            updateStatus("⚪ Scan QR code to connect")
            initManagers()
            return
        }
        tvBackendUrl.text = "Backend: ${config.baseUrl}"
        updateStatus("⚪ Connecting…")

        initManagers()
        registerDevice()
    }

    private fun bindViews() {
        tvDeviceId     = findViewById(R.id.tvDeviceId)
        tvBackendUrl   = findViewById(R.id.tvBackendUrl)
        tvStatus       = findViewById(R.id.tvStatus)
        tvVpnStatus    = findViewById(R.id.tvVpnStatus)
        tvFridaStatus  = findViewById(R.id.tvFridaStatus)
        tvEbpfStatus   = findViewById(R.id.tvEbpfStatus)
        tvPacketCount  = findViewById(R.id.tvPacketCount)
        tvRequestCount = findViewById(R.id.tvRequestCount)
        tvFindingCount = findViewById(R.id.tvFindingCount)
        tvLog          = findViewById(R.id.tvLog)
        btnVpnToggle   = findViewById(R.id.btnVpnToggle)
        btnFridaToggle = findViewById(R.id.btnFridaToggle)
        btnEbpfToggle  = findViewById(R.id.btnEbpfToggle)

        tvLog.movementMethod = ScrollingMovementMethod()

        // Buttons
        findViewById<Button>(R.id.btnScanQr).setOnClickListener {
            qrScanLauncher.launch(ScanOptions().apply {
                setPrompt("Scan the OneInfinity setup QR code")
                setBeepEnabled(true)
                setOrientationLocked(false)
            })
        }

        btnVpnToggle.setOnClickListener { toggleVpnCapture() }
        btnFridaToggle.setOnClickListener { toggleFridaSslHook() }
        btnEbpfToggle.setOnClickListener { toggleEbpfCapture() }

        // Initial button states
        updateVpnButton(false)
        updateFridaButton(false)
        updateEbpfButton(false)
    }

    // ── Manager init ──────────────────────────────────────────────────────────

    private fun initManagers() {
        // eBPF manager — runs ecapture on device, streams via WebSocket
        ebpfManager = EbpfCaptureManager(
            deviceId = deviceId,
            onOutput = { msg ->
                if (::websocketClient.isInitialized) websocketClient.sendMessage(msg)
                val line = msg.optString("line", "")
                if (line.isNotEmpty()) appendLog("[eBPF] $line")
            },
            onLog = { msg ->
                appendLog(msg)
                if (::websocketClient.isInitialized) websocketClient.sendLog(msg)
            }
        )

        // Frida SSL hook manager
        fridaSslManager = FridaSslHookManager(
            deviceId = deviceId,
            onRequest = { msg ->
                if (::websocketClient.isInitialized) websocketClient.sendMessage(msg)
            },
            onLog = { msg ->
                appendLog(msg)
                if (::websocketClient.isInitialized) websocketClient.sendLog(msg)
            }
        )

        // Existing Frida session manager
        fridaManager = FridaManager(
            deviceId = deviceId,
            onFindingReady = { result ->
                if (::websocketClient.isInitialized) websocketClient.sendMessage(result)
                findingCount++
                updateStats()
            },
            onLog = { msg ->
                appendLog("[FridaManager] $msg")
                if (::websocketClient.isInitialized) websocketClient.sendLog("[FridaManager] $msg")
            }
        )

        // Check eBPF availability immediately
        if (ebpfManager.isBinaryAvailable()) {
            updateEbpfStatus("⚪ Ready (ecapture found)", available = true)
        } else {
            updateEbpfStatus("⚪ ecapture not found — push from backend", available = false)
        }
    }

    // ── VPN Capture ───────────────────────────────────────────────────────────

    private fun toggleVpnCapture() {
        if (VpnCaptureService.isRunning) {
            stopTrafficCapture()
        } else {
            startTrafficCapture()
        }
    }

    private fun startTrafficCapture() {
        val intent = VpnService.prepare(this)
        if (intent != null) startActivityForResult(intent, VPN_REQUEST_CODE)
        else startVpnService()
    }

    private fun stopTrafficCapture() {
        val intent = Intent(this, VpnCaptureService::class.java).apply {
            action = VpnCaptureService.ACTION_STOP
        }
        startService(intent)
        updateVpnButton(false)
        updateVpnStatus("⚪ Stopped")
    }

    private fun startVpnService() {
        val intent = Intent(this, VpnCaptureService::class.java).apply {
            action = VpnCaptureService.ACTION_START
        }
        startService(intent)
        updateVpnButton(true)
        updateVpnStatus("🟢 Capturing")
        appendLog("[VPN] Traffic capture started")

        mainHandler.postDelayed({
            VpnCaptureService.instance?.onTraffic = { req, resp ->
                requestCount++
                updateStats()
                val msg = JSONObject().apply {
                    put("type", "traffic")
                    put("device_id", deviceId)
                    put("request", req)
                    put("response", resp)
                }
                if (::websocketClient.isInitialized) websocketClient.sendMessage(msg)
            }
        }, 1000)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) startVpnService()
    }

    // ── Frida SSL Hook ────────────────────────────────────────────────────────

    private fun toggleFridaSslHook() {
        if (fridaSslManager.isActive) {
            fridaSslManager.stop()
            updateFridaButton(false)
            updateFridaStatus("⚪ Stopped")
        } else {
            updateFridaStatus("🔵 Starting frida-server…")
            fridaSslManager.start()
            // Status updates come via fridaSslManager.onLog callbacks
            updateFridaButton(true)

            // Poll for status updates
            mainHandler.postDelayed({ syncFridaStatus() }, 3000)
        }
    }

    private fun syncFridaStatus() {
        if (!fridaSslManager.isActive) return
        val s = fridaSslManager.getStatusJson()
        val count = s.optInt("injected_pid_count", 0)
        updateFridaStatus("🟢 Active — $count PIDs hooked")
        mainHandler.postDelayed({ syncFridaStatus() }, 5000)
    }

    // ── eBPF Capture ──────────────────────────────────────────────────────────

    private fun toggleEbpfCapture() {
        if (ebpfManager.isRunning) {
            ebpfManager.stop()
            updateEbpfButton(false)
            updateEbpfStatus("⚪ Stopped", available = ebpfManager.isBinaryAvailable())
        } else {
            if (!ebpfManager.isBinaryAvailable()) {
                Toast.makeText(this, "ecapture binary missing. Push from backend first.", Toast.LENGTH_LONG).show()
                // Request backend to push the binary
                if (::websocketClient.isInitialized) {
                    websocketClient.sendMessage(JSONObject().apply {
                        put("type", "request_ecapture_push")
                        put("device_id", deviceId)
                    })
                }
                return
            }
            updateEbpfStatus("🔵 Starting eBPF hooks…", available = true)
            ebpfManager.start()
            updateEbpfButton(true)

            // Poll status
            mainHandler.postDelayed({ syncEbpfStatus() }, 2000)
        }
    }

    private fun syncEbpfStatus() {
        if (!ebpfManager.isRunning) return
        val s = ebpfManager.getStatusJson()
        val lines = s.optInt("lines_captured", 0)
        updateEbpfStatus("🟢 Active — $lines records captured", available = true)
        mainHandler.postDelayed({ syncEbpfStatus() }, 3000)
    }

    // ── WebSocket command routing ──────────────────────────────────────────────

    private fun connectWebSocket() {
        val wsUrl = "${config.wsUrl}/ws/mobile/$deviceId"
        websocketClient = WebSocketClient(
            wsUrl = wsUrl,
            deviceId = deviceId,
            onMessage = { msg -> handleCommand(msg) }
        )
        breakpointManager = BreakpointManager(deviceId) { hitMsg ->
            websocketClient.sendMessage(hitMsg)
        }
        initAttackEngine()
        websocketClient.connect()
    }

    private fun handleCommand(cmd: JSONObject) {
        val type = cmd.optString("type")
        Log.i(TAG, "Command: $type")

        when (type) {
            "heartbeat_ack"         -> { /* handled by WebSocketClient */ }
            "request_reregister"    -> registerDevice()  // backend restarted — resend registration
            "start_capture"         -> startTrafficCapture()
            "stop_capture"          -> stopTrafficCapture()
            "clear_cache"           -> cacheDir.deleteRecursively()

            // Frida
            "frida_inject", "frida_stop", "frida_status" -> fridaManager.handleCommand(cmd)
            "frida_output", "frida_session_event", "frida_finding_received" ->
                fridaManager.scriptRunner.processBackendFridaOutput(cmd)

            // eBPF binary push completed — auto-start
            "ecapture_pushed" -> {
                appendLog("[eBPF] ecapture binary pushed — ready to start")
                updateEbpfStatus("⚪ Ready (ecapture found)", available = true)
            }

            // Backend requests eBPF start
            "start_ebpf" -> {
                if (!ebpfManager.isRunning) toggleEbpfCapture()
            }

            // Backend requests Frida SSL hook
            "start_frida_ssl" -> {
                if (!fridaSslManager.isActive) toggleFridaSslHook()
            }

            // Attack execution
            "inject_payload", "execute_attack", "stop_attack", "ping" ->
                attackExecutor.handleCommand(cmd)

            // Rewrite rule management
            "rewrite_rule_add" -> {
                rewriteEngine.addRule(RewriteRule.fromJson(cmd))
                websocketClient.sendMessage(JSONObject().apply {
                    put("type", "rewrite_rule_ack"); put("device_id", deviceId)
                    put("rule_id", cmd.optString("id")); put("status", "added")
                })
            }
            "rewrite_rule_remove" -> {
                rewriteEngine.removeRule(cmd.optString("id", ""))
                websocketClient.sendMessage(JSONObject().apply {
                    put("type", "rewrite_rule_ack"); put("device_id", deviceId)
                    put("rule_id", cmd.optString("id")); put("status", "removed")
                })
            }
            "rewrite_rule_list" -> {
                val arr = org.json.JSONArray()
                rewriteEngine.listRules().forEach { rule -> arr.put(rule.toJson()) }
                websocketClient.sendMessage(JSONObject().apply {
                    put("type", "rewrite_rules"); put("device_id", deviceId); put("rules", arr)
                })
            }

            // Breakpoints
            "breakpoint_add" -> {
                if (::breakpointManager.isInitialized) {
                    breakpointManager.addRule(BreakpointRule.fromJson(cmd))
                    websocketClient.sendMessage(JSONObject().apply {
                        put("type", "breakpoint_ack"); put("device_id", deviceId)
                        put("bp_id", cmd.optString("id")); put("status", "added")
                    })
                }
            }
            "breakpoint_remove" -> {
                if (::breakpointManager.isInitialized)
                    breakpointManager.removeRule(cmd.optString("id", ""))
            }
            "breakpoint_resume" -> {
                if (::breakpointManager.isInitialized)
                    breakpointManager.resume(
                        cmd.optString("breakpoint_id", ""),
                        cmd.optString("modified_bytes", null)
                    )
            }

            // MITM redirect — now handled backend-side via adb reverse + system proxy
            // No iptables rules needed on device
            "setup_mitm_redirect" -> {
                Log.i(TAG, "MITM redirect managed by backend via adb reverse")
            }

            // Reverse proxy
            "setup_reverse_proxy" -> setupReverseProxyRedirect(
                cmd.optString("target_host", ""), cmd.optInt("local_port", 0)
            )

            else -> Log.w(TAG, "Unknown command: $type")
        }
    }

    // ── Device registration ───────────────────────────────────────────────────

    private fun registerDevice() {
        val json = JSONObject().apply {
            put("device_id", deviceId)
            put("platform", "android")
            put("version", Build.VERSION.RELEASE)
            put("root_status", RootChecker.isRooted())
            put("capabilities", JSONArray(listOf("traffic", "proxy", "attack", "inject",
                "frida_ssl", if (ebpfManager.isBinaryAvailable()) "ebpf" else "ebpf_pending")))
        }
        val request = Request.Builder()
            .url("${config.baseUrl}/api/mobile/agent/register")
            .post(json.toString().toRequestBody("application/json".toMediaTypeOrNull()))
            .build()

        OkHttpClient.Builder()
            .connectTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
            .readTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
            .writeTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
            .build()
            .newCall(request).enqueue(object : Callback {
            override fun onResponse(call: Call, response: Response) {
                val body = response.body?.string()
                Log.i(TAG, "Registration: $body")
                if (response.isSuccessful && body != null) {
                    try { wsToken = JSONObject(body).optString("ws_token", "") } catch (_: Exception) {}
                    updateStatus("🟢 Registered")
                    connectWebSocket()
                } else {
                    updateStatus("🔴 Registration failed — retrying")
                    mainHandler.postDelayed({ registerDevice() }, 5000)
                }
            }
            override fun onFailure(call: Call, e: IOException) {
                Log.e(TAG, "Registration failed: ${e.message}")
                updateStatus("🔴 Connection failed — retrying")
                mainHandler.postDelayed({ registerDevice() }, 5000)
            }
        })
    }

    // ── Attack engine init ────────────────────────────────────────────────────

    private fun initAttackEngine() {
        payloadInjector = PayloadInjector(
            deviceId = deviceId,
            onResultReady = { result ->
                websocketClient.sendMessage(result.toJson())
            }
        )
        attackExecutor = AttackExecutor(
            deviceId = deviceId,
            baseUrl = config.baseUrl,
            payloadInjector = payloadInjector,
            onResult = { result -> websocketClient.sendMessage(result) },
            onLog = { msg -> websocketClient.sendLog("[AttackExecutor] $msg") }
        )
    }

    // ── MITM / Reverse proxy ──────────────────────────────────────────────────

    private fun setupMitmRedirect(proxyPort: Int, enabled: Boolean) {
        if (!RootChecker.isRooted()) {
            appendLog("[MITM] Root required for iptables")
            return
        }
        val cmds = if (enabled) listOf(
            "iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port $proxyPort",
            "iptables -t nat -A OUTPUT -p tcp --dport 80  -j REDIRECT --to-port $proxyPort"
        ) else listOf(
            "iptables -t nat -D OUTPUT -p tcp --dport 443 -j REDIRECT --to-port $proxyPort 2>/dev/null || true",
            "iptables -t nat -D OUTPUT -p tcp --dport 80  -j REDIRECT --to-port $proxyPort 2>/dev/null || true"
        )
        cmds.forEach { cmd ->
            try { Runtime.getRuntime().exec(arrayOf("su", "-c", cmd)).waitFor() }
            catch (e: Exception) { Log.e(TAG, "iptables error: ${e.message}") }
        }
        appendLog("[MITM] Redirect ${if (enabled) "enabled" else "disabled"} → port $proxyPort")
        websocketClient.sendLog("[MITM] Redirect ${if (enabled) "enabled" else "disabled"} → port $proxyPort")
    }

    private fun setupReverseProxyRedirect(targetHost: String, localPort: Int) {
        if (targetHost.isEmpty() || localPort == 0) return
        if (!RootChecker.isRooted()) {
            websocketClient.sendLog("[ReverseProxy] Root required")
            return
        }
        try {
            val cmd = "su -c \"grep -q '$targetHost' /etc/hosts || echo '127.0.0.1  $targetHost' >> /etc/hosts\""
            Runtime.getRuntime().exec(arrayOf("sh", "-c", cmd)).waitFor()
            appendLog("[ReverseProxy] $targetHost → 127.0.0.1:$localPort")
            websocketClient.sendLog("[ReverseProxy] Redirecting $targetHost → 127.0.0.1:$localPort")
        } catch (e: Exception) {
            Log.e(TAG, "Reverse proxy error: ${e.message}")
        }
    }

    // ── QR / deep-link ────────────────────────────────────────────────────────

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        intent?.data?.let { applyQrConfig(it.toString()) }
    }

    private fun applyQrConfig(raw: String) {
        try {
            val uri = Uri.parse(raw)
            if (uri.scheme != "oneinfinity" || uri.host != "setup") return
            val baseUrl = uri.getQueryParameter("base") ?: return
            val wsUrl = uri.getQueryParameter("ws") ?: "ws${baseUrl.removePrefix("http")}"
            val apiKey = uri.getQueryParameter("key")
            val newConfig = BackendConfig(baseUrl = baseUrl, wsUrl = wsUrl, apiKey = apiKey)
            ConfigManager.saveConfig(this, newConfig)
            config = newConfig
            tvBackendUrl.text = "Backend: $baseUrl"
            Toast.makeText(this, "✅ Backend: $baseUrl", Toast.LENGTH_SHORT).show()
            appendLog("[Config] Backend set to $baseUrl")
            if (::websocketClient.isInitialized) websocketClient.disconnect()
            wsToken = ""
            updateStatus("⚪ Connecting…")
            if (!::ebpfManager.isInitialized) initManagers()
            registerDevice()
        } catch (e: Exception) {
            Toast.makeText(this, "❌ Invalid QR", Toast.LENGTH_SHORT).show()
        }
    }

    // ── UI helpers ────────────────────────────────────────────────────────────

    private fun updateStatus(s: String) = runOnUiThread { tvStatus.text = s }

    private fun updateVpnStatus(s: String) = runOnUiThread { tvVpnStatus.text = s }
    private fun updateFridaStatus(s: String) = runOnUiThread { tvFridaStatus.text = s }
    private fun updateEbpfStatus(s: String, available: Boolean = true) = runOnUiThread {
        tvEbpfStatus.text = s
        btnEbpfToggle.isEnabled = available || ebpfManager.isRunning
    }

    private fun updateVpnButton(running: Boolean) = runOnUiThread {
        btnVpnToggle.text = if (running) "Stop" else "Start"
        btnVpnToggle.setTextColor(if (running) 0xFFFF4444.toInt() else 0xFF00FF88.toInt())
    }
    private fun updateFridaButton(running: Boolean) = runOnUiThread {
        btnFridaToggle.text = if (running) "Stop" else "Start"
        btnFridaToggle.setTextColor(if (running) 0xFFFF4444.toInt() else 0xFF00AAFF.toInt())
    }
    private fun updateEbpfButton(running: Boolean) = runOnUiThread {
        btnEbpfToggle.text = if (running) "Stop" else "Start"
        btnEbpfToggle.setTextColor(if (running) 0xFFFF4444.toInt() else 0xFFAA44FF.toInt())
    }

    private fun updateStats() = runOnUiThread {
        tvPacketCount.text = packetCount.toString()
        tvRequestCount.text = requestCount.toString()
        tvFindingCount.text = findingCount.toString()
    }

    private val MAX_LOG_LINES = 200
    private fun appendLog(msg: String) = runOnUiThread {
        val lines = logBuffer.lines()
        if (lines.size > MAX_LOG_LINES) {
            logBuffer.clear()
            logBuffer.append(lines.takeLast(MAX_LOG_LINES).joinToString("\n"))
            logBuffer.append("\n")
        }
        logBuffer.append(msg.take(120)).append("\n")
        tvLog.text = logBuffer.toString()
        // Scroll to bottom
        val scrollAmount = tvLog.layout?.getLineTop(tvLog.lineCount) ?: 0
        val scrollDiff = scrollAmount - tvLog.height
        if (scrollDiff > 0) tvLog.scrollTo(0, scrollDiff)
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    override fun onDestroy() {
        super.onDestroy()
        ebpfManager.shutdown()
        fridaSslManager.stop()
        fridaManager.stop()
        if (::attackExecutor.isInitialized) attackExecutor.shutdown()
        if (::websocketClient.isInitialized) websocketClient.disconnect()
        VpnCaptureService.instance?.onTraffic = null
    }
}
