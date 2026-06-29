// ContentView.swift — SwiftUI main UI for iOS Companion
// Phase 4: iOS Support

import SwiftUI
import NetworkExtension

// MARK: - CompanionViewModel

@MainActor
public final class CompanionViewModel: ObservableObject {
    @Published public var status: String = "⚪ Not connected"
    @Published public var deviceId: String = ""
    @Published public var backendURL: String = ""
    @Published public var isVPNRunning: Bool = false
    @Published public var capturedCount: Int = 0
    @Published public var findings: [FindingItem] = []
    @Published public var logs: [String] = []
    @Published public var serverRunning: Bool = false
    @Published public var isJailbroken: Bool = false
    @Published public var activeTab: Tab = .devices

    public enum Tab { case devices, traffic, frida, attack }

    let wsManager: WebSocketManager
    let fridaManager: FridaManager
    let config: BackendConfig

    public init() {
        let id = UIDevice.current.identifierForVendor?.uuidString ?? UUID().uuidString
        self.deviceId = id

        let cfg = ConfigManager.load() ?? ConfigManager.defaultConfig()
        self.config = cfg
        self.backendURL = cfg.baseURL.absoluteString

        self.wsManager = WebSocketManager(deviceId: id)
        self.fridaManager = FridaManager(wsManager: wsManager)
        self.isJailbroken = fridaManager.isJailbroken()

        setupHandlers()
    }

    // Bundle ID of the Network Extension target — must match Xcode target + entitlement
    private let tunnelBundleId = "com.oneinfinity.companion.tunnel"

    private func setupHandlers() {
        wsManager.onCommand = { [weak self] type, json in
            DispatchQueue.main.async {
                switch type {
                case "start_capture":  self?.startVPN()
                case "stop_capture":   self?.stopVPN()
                case "clear_cache":    self?.clearCache()
                // Gap E: execute deeplink fuzz cases sent from backend
                case "deeplink_fuzz":
                    self?.executeDeeplinkFuzz(json["fuzz_cases"] as? [[String: Any]] ?? [])
                default: break
                }
            }
        }

        wsManager.onFridaInject = { [weak self] json in
            DispatchQueue.main.async {
                self?.fridaManager.handleCommand(json)
            }
        }
    }

    public func connect() {
        status = "⚙️ Connecting…"
        registerWithBackend { [weak self] success in
            DispatchQueue.main.async {
                if success {
                    self?.wsManager.connect(to: self!.config)
                    self?.status = "🟢 Connected"
                } else {
                    self?.status = "🔴 Registration failed"
                }
            }
        }
    }

    private func registerWithBackend(completion: @escaping (Bool) -> Void) {
        var request = URLRequest(url: config.baseURL.appendingPathComponent("api/mobile/agent/register"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body: [String: Any] = [
            "device_id": deviceId,
            "platform": "ios",
            "version": UIDevice.current.systemVersion,
            "root_status": isJailbroken,
            "capabilities": isJailbroken
                ? ["traffic", "frida", "attack", "inject"]
                : ["traffic", "attack"]
        ]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)

        URLSession.shared.dataTask(with: request) { _, response, error in
            let success = (response as? HTTPURLResponse)?.statusCode == 200 && error == nil
            completion(success)
        }.resume()
    }

    // Gap B: actually start the NEPacketTunnelProvider via NEVPNManager
    public func startVPN() {
        NEVPNManager.shared().loadFromPreferences { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                self.appendLog("VPN load failed: \(error.localizedDescription)")
                return
            }
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = self.tunnelBundleId
            proto.serverAddress = self.config.baseURL.host ?? "oneinfinity-backend"
            proto.providerConfiguration = [
                "ws_url": self.config.wsURL.absoluteString,
                "api_key": self.config.apiKey ?? "",
            ]
            NEVPNManager.shared().protocolConfiguration = proto
            NEVPNManager.shared().localizedDescription = "OneInfinity Traffic Capture"
            NEVPNManager.shared().isEnabled = true

            NEVPNManager.shared().saveToPreferences { [weak self] saveError in
                guard let self = self else { return }
                if let saveError = saveError {
                    self.appendLog("VPN save failed: \(saveError.localizedDescription)")
                    return
                }
                do {
                    try NEVPNManager.shared().connection.startVPNTunnel()
                    DispatchQueue.main.async {
                        self.isVPNRunning = true
                        self.status = "🔵 Capturing traffic…"
                        self.appendLog("VPN capture started")
                    }
                } catch {
                    DispatchQueue.main.async {
                        self.appendLog("VPN start failed: \(error.localizedDescription)")
                    }
                }
            }
        }
    }

    public func stopVPN() {
        NEVPNManager.shared().connection.stopVPNTunnel()
        isVPNRunning = false
        status = "🟢 Connected"
        appendLog("VPN capture stopped")
    }

    // Gap E: execute deeplink fuzz cases by opening each URL scheme on-device
    private func executeDeeplinkFuzz(_ cases: [[String: Any]]) {
        appendLog("Deeplink fuzz: \(cases.count) case(s) received")
        for fuzzCase in cases.prefix(50) {
            guard let urlString = fuzzCase["url"] as? String,
                  let url = URL(string: urlString),
                  UIApplication.shared.canOpenURL(url) else { continue }
            UIApplication.shared.open(url, options: [:]) { [weak self] opened in
                let payload = fuzzCase["payload"] as? String ?? ""
                let result: [String: Any] = [
                    "type": "deeplink_fuzz_result",
                    "url": urlString,
                    "payload": payload,
                    "opened": opened,
                    "severity": opened ? "medium" : "info",
                    "evidence": opened
                        ? "Deep-link \(urlString) was successfully opened — app handled injected payload"
                        : "Deep-link \(urlString) was rejected (canOpenURL returned false)",
                    "vuln_type": opened ? "deeplink_injection" : "deeplink_rejected",
                ]
                self?.wsManager.sendFinding(result)
            }
        }
    }

    public func clearCache() {
        URLCache.shared.removeAllCachedResponses()
        appendLog("Cache cleared")
    }

    public func appendLog(_ msg: String) {
        let entry = "[\(Date().formatted(date: .omitted, time: .standard))] \(msg)"
        logs.insert(entry, at: 0)
        if logs.count > 100 { logs.removeLast() }
    }
}

public struct FindingItem: Identifiable {
    public let id = UUID()
    public let vulnerability: String
    public let severity: String
    public let evidence: String
}

// MARK: - ContentView

public struct ContentView: View {
    @StateObject private var vm = CompanionViewModel()

    public init() {}

    public var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                // Header
                VStack(spacing: 4) {
                    Text("OneInfinity Companion")
                        .font(.system(.headline, design: .monospaced))
                        .fontWeight(.black)
                        .foregroundColor(.red)
                    Text(vm.status)
                        .font(.system(.caption, design: .monospaced))
                    Text("iOS \(UIDevice.current.systemVersion) · \(vm.isJailbroken ? "🔓 Jailbroken" : "🔒 Stock")")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.secondary)
                }
                .padding()
                .background(Color(.systemBackground))

                // Tab bar
                Picker("Tab", selection: $vm.activeTab) {
                    Text("📱 Status").tag(CompanionViewModel.Tab.devices)
                    Text("🌐 Traffic").tag(CompanionViewModel.Tab.traffic)
                    if vm.isJailbroken {
                        Text("🔬 Frida").tag(CompanionViewModel.Tab.frida)
                    }
                    Text("⚡ Attack").tag(CompanionViewModel.Tab.attack)
                }
                .pickerStyle(.segmented)
                .padding(.horizontal)

                // Tab content
                switch vm.activeTab {
                case .devices:  StatusTab(vm: vm)
                case .traffic:  TrafficTab(vm: vm)
                case .frida:    FridaTab(vm: vm)
                case .attack:   AttackTab(vm: vm)
                }
            }
            .navigationBarHidden(true)
        }
        .onAppear { vm.connect() }
    }
}

// MARK: - Status Tab

private struct StatusTab: View {
    @ObservedObject var vm: CompanionViewModel

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                // Connection card
                GroupBox("Backend") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Image(systemName: vm.wsManager.isConnected ? "wifi" : "wifi.slash")
                                .foregroundColor(vm.wsManager.isConnected ? .green : .red)
                            Text(vm.backendURL)
                                .font(.system(.caption, design: .monospaced))
                        }
                        Text("Device: \(vm.deviceId.prefix(8))…")
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundColor(.secondary)
                    }
                }

                // Capabilities
                GroupBox("Capabilities") {
                    HStack(spacing: 12) {
                        CapBadge(icon: "network", label: "Traffic", active: true)
                        CapBadge(icon: "bolt", label: "Attack", active: true)
                        CapBadge(icon: "doc.text.magnifyingglass", label: "Frida",
                                 active: vm.isJailbroken)
                    }
                }

                // Action buttons
                HStack(spacing: 12) {
                    Button(action: { vm.isVPNRunning ? vm.stopVPN() : vm.startVPN() }) {
                        Label(vm.isVPNRunning ? "Stop Capture" : "Start Capture",
                              systemImage: vm.isVPNRunning ? "stop.fill" : "record.circle")
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(vm.isVPNRunning ? .orange : .blue)
                }

                // Log
                GroupBox("Log (\(vm.logs.count))") {
                    LazyVStack(alignment: .leading) {
                        ForEach(vm.logs.prefix(20), id: \.self) { entry in
                            Text(entry)
                                .font(.system(size: 9, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }
            .padding()
        }
    }
}

private struct CapBadge: View {
    let icon: String
    let label: String
    let active: Bool

    var body: some View {
        VStack(spacing: 4) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundColor(active ? .blue : .secondary)
            Text(label).font(.caption2)
                .foregroundColor(active ? .primary : .secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(8)
        .background(active ? Color.blue.opacity(0.1) : Color(.secondarySystemBackground))
        .cornerRadius(8)
    }
}

// MARK: - Traffic Tab

private struct TrafficTab: View {
    @ObservedObject var vm: CompanionViewModel
    var body: some View {
        VStack {
            HStack {
                Text("Captured: \(vm.capturedCount)")
                    .font(.system(.caption, design: .monospaced))
                Spacer()
                Button("Clear") { vm.capturedCount = 0 }
                    .font(.caption)
            }
            .padding(.horizontal)
            Text("Traffic capture requires VPN to be running.\nStart capture from Status tab.")
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding()
        }
    }
}

// MARK: - Frida Tab

private struct FridaTab: View {
    @ObservedObject var vm: CompanionViewModel

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                GroupBox("frida-server") {
                    HStack {
                        Circle()
                            .fill(vm.serverRunning ? Color.green : Color.red)
                            .frame(width: 10, height: 10)
                        Text(vm.serverRunning ? "Running" : "Stopped")
                            .font(.system(.caption, design: .monospaced))
                        Spacer()
                        Button(vm.serverRunning ? "Stop" : "Start") {
                            if vm.serverRunning {
                                vm.fridaManager.stop()
                                vm.serverRunning = false
                            } else {
                                vm.fridaManager.start()
                                vm.serverRunning = vm.fridaManager.serverRunning
                            }
                        }
                        .font(.caption)
                        .buttonStyle(.bordered)
                    }
                }

                GroupBox("Frida Logs") {
                    LazyVStack(alignment: .leading) {
                        ForEach(vm.fridaManager.logs.prefix(15), id: \.self) { log in
                            Text(log).font(.system(size: 9, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                    }
                }

                Text("Scripts are executed on the host machine via frida -U.\nEnsure frida-server is running on this device.")
                    .font(.caption2)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding()
        }
    }
}

// MARK: - Attack Tab

private struct AttackTab: View {
    @ObservedObject var vm: CompanionViewModel

    var body: some View {
        VStack {
            Text("⚡ Attack campaigns are launched from the\nOneInfinity Web UI.")
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding()
            Text("Connect to the backend and navigate to\n/mobile-agent → Attack Launcher")
                .font(.system(.caption2, design: .monospaced))
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
    }
}
