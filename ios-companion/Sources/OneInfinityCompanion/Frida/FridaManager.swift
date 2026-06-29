// FridaManager.swift — Frida server management for jailbroken iOS devices
// Phase 4: iOS Support
//
// Architecture (same as Android FridaManager.kt after Fix #11):
//   1. Manages frida-server binary at /usr/bin/frida-server (jailbroken devices)
//   2. Receives {type:frida_inject} commands from backend via WebSocket
//   3. Ensures frida-server is running, sends acknowledgment
//   4. Backend (host) runs `frida -U -f <bundle_id>` against this device
//   5. Receives {type:frida_output} with findings from backend
//
// Requires: jailbroken device with frida-server installed
//           (via Cydia: https://build.frida.re/)

import Foundation

// MARK: - FridaManager

@MainActor
public final class FridaManager: ObservableObject {
    @Published public var serverRunning = false
    @Published public var logs: [String] = []

    private let serverPath = "/usr/sbin/frida-server"
    private let altServerPath = "/usr/bin/frida-server"  // Cydia install location
    private var serverProcess: Process?
    private var healthCheckTimer: Timer?
    private weak var wsManager: WebSocketManager?

    // FridaScriptRunner for processing backend output
    public let scriptRunner = FridaScriptRunner()

    public init(wsManager: WebSocketManager? = nil) {
        self.wsManager = wsManager
    }

    // MARK: Lifecycle

    public func start() {
        if isServerAvailable() {
            serverRunning = true
            appendLog("frida-server already running")
        } else {
            startFridaServer()
        }

        // Health check every 30s
        healthCheckTimer = Timer.scheduledTimer(withTimeInterval: 30.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self = self else { return }
                let running = self.isServerAvailable()
                if self.serverRunning && !running {
                    self.appendLog("frida-server died, restarting…")
                    self.startFridaServer()
                }
                self.serverRunning = running
            }
        }
    }

    public func stop() {
        healthCheckTimer?.invalidate()
        stopFridaServer()
        scriptRunner.stopAll()
    }

    // MARK: Command handling

    public func handleCommand(_ json: [String: Any]) {
        let type = json["type"] as? String ?? ""
        switch type {
        case "frida_inject":     handleInject(json)
        case "frida_stop":       stopFridaServer()
        case "frida_status":     sendStatus()
        case "frida_output",
             "frida_session_event",
             "frida_finding_received":
            scriptRunner.processBackendOutput(json, onLog: appendLog(_:))
        default:
            appendLog("Unknown frida command: \(type)")
        }
    }

    private func handleInject(_ json: [String: Any]) {
        let sessionId  = json["session_id"] as? String ?? ""
        let scriptName = json["script_name"] as? String ?? "custom"
        let bundleId   = json["package_name"] as? String ?? ""

        guard !bundleId.isEmpty else {
            appendLog("frida_inject rejected: missing package_name (bundle ID)")
            return
        }

        let needsStart = !isServerAvailable()
        if needsStart {
            appendLog("frida-server not running, starting for session \(sessionId)…")
            startFridaServer()
        }

        // Use async Task.sleep instead of Thread.sleep — never block MainActor.
        // Delay ack by 2s only if we just started the server.
        Task {
            if needsStart {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
            let running = self.isServerAvailable()
            let ack: [String: Any] = [
                "type": "frida_server_ready",
                "session_id": sessionId,
                "device_id": self.deviceIdentifier(),
                "package_name": bundleId,
                "script_name": scriptName,
                "server_running": running,
                "platform": "ios",
                "message": "frida-server ready — host can connect via frida -U -f \(bundleId)",
                "timestamp": Date().timeIntervalSince1970
            ]
            await MainActor.run {
                self.wsManager?.sendFinding(ack)
                self.appendLog("Session \(sessionId): ready for \(bundleId)")
            }
        }
    }

    private func sendStatus() {
        let running = isServerAvailable()
        serverRunning = running
        let status: [String: Any] = [
            "type": "frida_status",
            "device_id": deviceIdentifier(),
            "server_running": running,
            "server_path": resolvedServerPath() ?? "not found",
            "platform": "ios",
            "is_jailbroken": isJailbroken()
        ]
        wsManager?.sendFinding(status)
    }

    // MARK: frida-server process

    private func startFridaServer() {
        guard let path = resolvedServerPath() else {
            appendLog("frida-server not found at \(serverPath) or \(altServerPath)")
            appendLog("Install via Cydia: https://build.frida.re/")
            serverRunning = false
            return
        }

        DispatchQueue.global(qos: .background).async { [weak self] in
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: path)
            proc.arguments = ["-D"]  // background / daemonize

            do {
                try proc.run()
                self?.serverProcess = proc
                DispatchQueue.main.async {
                    self?.serverRunning = true
                    self?.appendLog("frida-server started at \(path)")
                }
                proc.waitUntilExit()
                DispatchQueue.main.async {
                    self?.serverRunning = false
                    self?.appendLog("frida-server exited")
                }
            } catch {
                DispatchQueue.main.async {
                    self?.serverRunning = false
                    self?.appendLog("frida-server start failed: \(error.localizedDescription)")
                }
            }
        }
    }

    private func stopFridaServer() {
        serverProcess?.terminate()
        serverProcess = nil
        serverRunning = false
        appendLog("frida-server stopped")
    }

    // MARK: Helpers

    public func isServerAvailable() -> Bool {
        if serverRunning { return true }
        // Check via ps
        let ps = Process()
        ps.executableURL = URL(fileURLWithPath: "/bin/ps")
        ps.arguments = ["-e"]
        let pipe = Pipe()
        ps.standardOutput = pipe
        try? ps.run()
        ps.waitUntilExit()
        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return output.contains("frida-server")
    }

    private func resolvedServerPath() -> String? {
        if FileManager.default.fileExists(atPath: serverPath) { return serverPath }
        if FileManager.default.fileExists(atPath: altServerPath) { return altServerPath }
        return nil
    }

    public func isJailbroken() -> Bool {
        let jbPaths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/private/var/lib/apt"
        ]
        return jbPaths.contains { FileManager.default.fileExists(atPath: $0) }
    }

    private func deviceIdentifier() -> String {
        UIDevice.current.identifierForVendor?.uuidString ?? "ios-unknown"
    }

    private func appendLog(_ msg: String) {
        logs.append("[\(Date().formatted(date: .omitted, time: .standard))] \(msg)")
        if logs.count > 200 { logs.removeFirst() }
        print("[FridaManager] \(msg)")
    }
}

// MARK: - FridaScriptRunner

/// Processes Frida output messages received FROM the backend.
/// Architecture: frida runs on HOST, results come back via WebSocket.
public final class FridaScriptRunner {
    public func processBackendOutput(_ json: [String: Any], onLog: (String) -> Void) {
        let sessionId  = json["session_id"] as? String ?? ""
        let scriptName = json["script_name"] as? String ?? "unknown"
        let output     = json["output"] as? String ?? ""
        let hasFinding = json["has_finding"] as? Bool ?? false

        if !output.isEmpty {
            onLog("[\(scriptName)] \(output.prefix(200))")
        }

        if let finding = json["finding"] as? [String: Any] {
            let vuln     = finding["vulnerability"] as? String ?? "finding"
            let severity = finding["severity"] as? String ?? "?"
            onLog("[\(scriptName)] FINDING [\(severity)]: \(vuln)")
        }

        if json["type"] as? String == "frida_session_event" {
            let event = json["event"] as? String ?? ""
            let count = json["findings_count"] as? Int ?? 0
            onLog("[\(scriptName)] Session \(sessionId) \(event)\(count > 0 ? " — \(count) findings" : "")")
        }
    }

    public func stopAll() {
        // Nothing to stop locally — execution is on the host
    }
}
