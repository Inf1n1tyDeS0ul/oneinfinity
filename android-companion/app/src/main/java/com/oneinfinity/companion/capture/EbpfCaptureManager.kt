package com.oneinfinity.companion.capture

import android.util.Log
import org.json.JSONObject
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.atomic.AtomicBoolean

/**
 * eBPF Capture Manager — runs ecapture directly on the device.
 *
 * ecapture uses eBPF uprobes to hook SSL_write/SSL_read across ALL processes
 * and ALL SSL libraries (including Chrome's bundled BoringSSL). This gives
 * 100% TLS plaintext visibility with zero certificate interaction.
 *
 * Architecture:
 *   1. Check if ecapture binary exists at ECAPTURE_PATH
 *   2. Run: su -c 'ecapture tls -i wlan0' as a root subprocess
 *   3. Stream stdout line by line — each line is a decrypted TLS record
 *   4. Send as {type:"ebpf_output"} via WebSocket to backend
 *   5. Backend's mobile_ebpf_capture.py parses and stores to SQLite
 *
 * ecapture download: https://github.com/gojue/ecapture/releases
 * Place ARM64 Android binary at: /data/local/tmp/ecapture
 */
class EbpfCaptureManager(
    private val deviceId: String,
    private val onOutput: (JSONObject) -> Unit,
    private val onLog: (String) -> Unit
) {
    private val TAG = "EbpfCapture"
    val ECAPTURE_PATH = "/data/local/tmp/ecapture"
    val KEYLOG_PATH   = "/data/local/tmp/oi_ssl_keys.log"

    private val running = AtomicBoolean(false)
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    private var captureFuture: Future<*>? = null
    private var process: Process? = null
    private var lineCount = 0

    val isRunning get() = running.get()

    fun isBinaryAvailable(): Boolean = File(ECAPTURE_PATH).exists()

    fun start(interface_: String = "wlan0") {
        if (running.get()) {
            onLog("[eBPF] Already running")
            return
        }
        if (!isBinaryAvailable()) {
            onLog("[eBPF] ecapture binary not found at $ECAPTURE_PATH")
            onLog("[eBPF] Push it from backend: POST /api/mobile/intercept/push_ecapture")
            notifyStatus("binary_missing")
            return
        }

        running.set(true)
        notifyStatus("starting")

        captureFuture = executor.submit {
            runCapture(interface_)
        }
    }

    fun stop() {
        running.set(false)
        process?.destroy()
        captureFuture?.cancel(true)
        notifyStatus("stopped")
        onLog("[eBPF] Stopped")
    }

    private fun runCapture(interface_: String) {
        try {
            // chmod +x first
            Runtime.getRuntime().exec(arrayOf("su", "-c", "chmod +x $ECAPTURE_PATH")).waitFor()

            // -m text (default) outputs decrypted TLS payload as plaintext
        val cmd = "su -c '$ECAPTURE_PATH tls -i $interface_ -m text --keylogfile $KEYLOG_PATH 2>&1'"
            process = Runtime.getRuntime().exec(arrayOf("sh", "-c", cmd))
            val reader = BufferedReader(InputStreamReader(process!!.inputStream))

            notifyStatus("running")
            onLog("[eBPF] Started — hooking SSL_write/SSL_read across all processes")

            var line: String?
            while (running.get()) {
                line = reader.readLine() ?: break
                lineCount++

                // Send raw output line to backend
                val msg = JSONObject().apply {
                    put("type", "ebpf_output")
                    put("device_id", deviceId)
                    put("line", line)
                    put("line_num", lineCount)
                }
                onOutput(msg)

                // Log significant events locally
                if (line.contains("SSL_write") || line.contains("SSL_read") ||
                    line.contains("http") || line.contains("HTTP")) {
                    Log.d(TAG, "eBPF: $line")
                }
            }

        } catch (e: Exception) {
            if (running.get()) {
                Log.e(TAG, "eBPF capture error: ${e.message}")
                onLog("[eBPF] Error: ${e.message}")
                notifyStatus("error")
            }
        } finally {
            running.set(false)
            process = null
        }
    }

    private fun notifyStatus(status: String) {
        val msg = JSONObject().apply {
            put("type", "ebpf_status")
            put("device_id", deviceId)
            put("status", status)
            put("binary_path", ECAPTURE_PATH)
            put("binary_exists", isBinaryAvailable())
            put("lines_captured", lineCount)
        }
        onOutput(msg)
    }

    fun getStatusJson(): JSONObject = JSONObject().apply {
        put("running", running.get())
        put("binary_available", isBinaryAvailable())
        put("lines_captured", lineCount)
        put("keylog_path", KEYLOG_PATH)
    }

    fun shutdown() {
        stop()
        executor.shutdown()
    }
}
