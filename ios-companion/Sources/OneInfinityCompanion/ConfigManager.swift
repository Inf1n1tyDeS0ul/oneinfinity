// ConfigManager.swift — Backend URL discovery for iOS Companion
// Phase 4: iOS Support
//
// Priority order (mirrors Android ConfigManager.kt):
//   1. Saved config (UserDefaults) — persistent across launches
//   2. QR code scan — instant setup
//   3. mDNS discovery — auto-discovery on same WiFi
//   4. Manual entry — fallback

import Foundation
import Network

// MARK: - BackendConfig

public struct BackendConfig: Codable, Equatable {
    public let baseURL: URL
    public let wsURL: URL
    public let apiKey: String?

    public init(baseURL: URL, wsURL: URL, apiKey: String? = nil) {
        self.baseURL = baseURL
        self.wsURL = wsURL
        self.apiKey = apiKey
    }
}

// MARK: - ConfigManager

public final class ConfigManager {
    private static let suiteKey = "group.oneinfinity.companion"
    private static let configKey = "backend_config"

    // MARK: Persistence

    public static func save(_ config: BackendConfig) {
        let defaults = UserDefaults(suiteName: suiteKey) ?? UserDefaults.standard
        if let encoded = try? JSONEncoder().encode(config) {
            defaults.set(encoded, forKey: configKey)
        }
    }

    public static func load() -> BackendConfig? {
        let defaults = UserDefaults(suiteName: suiteKey) ?? UserDefaults.standard
        guard let data = defaults.data(forKey: configKey),
              let config = try? JSONDecoder().decode(BackendConfig.self, from: data)
        else { return nil }
        return config
    }

    public static func clear() {
        let defaults = UserDefaults(suiteName: suiteKey) ?? UserDefaults.standard
        defaults.removeObject(forKey: configKey)
    }

    // MARK: QR Code parsing

    /// Parse a OneInfinity QR code URL: oneinfinity://setup?base=http://...&ws=ws://...
    public static func parseQRCode(_ qrString: String) -> BackendConfig? {
        guard let url = URL(string: qrString),
              url.scheme == "oneinfinity",
              url.host == "setup" else { return nil }

        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let params = Dictionary(
            uniqueKeysWithValues: (components?.queryItems ?? []).compactMap { item in
                item.value.map { (item.name, $0) }
            }
        )

        guard let baseString = params["base"],
              let wsString = params["ws"],
              let baseURL = URL(string: baseString),
              let wsURL = URL(string: wsString)
        else { return nil }

        return BackendConfig(baseURL: baseURL, wsURL: wsURL, apiKey: params["api_key"])
    }

    // MARK: Default config (simulator/development)

    public static func defaultConfig() -> BackendConfig {
        // Simulator: connect to host machine on localhost equivalent
        let isSimulator = ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil
        let host = isSimulator ? "localhost" : "192.168.1.100"
        return BackendConfig(
            baseURL: URL(string: "http://\(host):8000")!,
            wsURL: URL(string: "ws://\(host):8000")!
        )
    }
}

// MARK: - mDNS Discovery

/// Discovers the OneInfinity backend on the local network via mDNS.
/// The backend advertises as `_oneinfinity._tcp.` (see mdns_advertiser.py).
public final class MDNSDiscovery: NSObject {
    private let browser = NWBrowser(for: .bonjourWithTXTRecord(type: "_oneinfinity._tcp.", domain: "local."), using: .tcp)
    public var onDiscovered: ((BackendConfig) -> Void)?
    private var found = false

    public func start() {
        browser.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready: break
            case .failed(let err):
                print("[mDNS] Browser failed: \(err)")
            default: break
            }
        }

        browser.browseResultsChangedHandler = { [weak self] results, _ in
            guard let self = self, !self.found else { return }
            for result in results {
                if case .service(let name, _, _, _) = result.endpoint {
                    print("[mDNS] Found service: \(name)")
                    self.resolve(result)
                }
            }
        }

        browser.start(queue: .main)
    }

    public func stop() {
        browser.cancel()
    }

    private func resolve(_ result: NWBrowser.Result) {
        guard case .service(let name, let type_, let domain, _) = result.endpoint else { return }

        let connection = NWConnection(
            to: .service(name: name, type: type_, domain: domain, interface: nil),
            using: .tcp
        )
        connection.stateUpdateHandler = { [weak self] state in
            if case .ready = state {
                if let endpoint = connection.currentPath?.remoteEndpoint,
                   case .hostPort(let host, let port) = endpoint {
                    let hostStr = "\(host)"
                    let config = BackendConfig(
                        baseURL: URL(string: "http://\(hostStr):\(port)")!,
                        wsURL: URL(string: "ws://\(hostStr):\(port)")!
                    )
                    DispatchQueue.main.async {
                        self?.found = true
                        self?.onDiscovered?(config)
                    }
                }
                connection.cancel()
            }
        }
        connection.start(queue: .main)
    }
}
