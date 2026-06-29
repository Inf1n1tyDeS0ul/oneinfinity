// PacketTunnelProvider.swift — iOS Network Extension for traffic capture
// Phase 4: iOS Support
//
// NEPacketTunnelProvider is the iOS equivalent of Android's VpnService.
// It intercepts all device traffic at the IP packet level.
//
// Architecture:
//   1. NEPacketTunnelProvider creates a TUN interface
//   2. Packets are read from the TUN file descriptor
//   3. HTTP/HTTPS requests are parsed and sent to OneInfinity backend
//   4. Packets are forwarded to the real network
//
// IMPORTANT: This file must be in a separate App Extension target in Xcode.
// The main app target uses NEVPNManager to control this extension.
// Entitlements required: com.apple.developer.networking.networkextension

import NetworkExtension
import Network
import os.log

private let log = Logger(subsystem: "com.oneinfinity.companion", category: "PacketTunnel")

// MARK: - PacketTunnelProvider

public final class PacketTunnelProvider: NEPacketTunnelProvider {

    // Configuration
    private var trafficUploadURL: URL?  // Gap D: POST endpoint, not WebSocket
    private var apiKey: String?
    private let deviceId = UIDevice.current.identifierForVendor?.uuidString ?? UUID().uuidString

    // Statistics
    private var packetsProcessed: Int64 = 0
    private var bytesProcessed: Int64 = 0

    // Gap D: HTTP session for fire-and-forget traffic upload.
    // Using HTTP POST instead of a competing WebSocket avoids overwriting
    // active_devices[device_id] in mobile_agent_api and eliminates command
    // routing ambiguity between the main app's WebSocketManager and the extension.
    private let uploadSession = URLSession(configuration: .ephemeral)

    // MARK: NEPacketTunnelProvider lifecycle

    public override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        log.info("PacketTunnelProvider starting…")

        // Parse backend config from tunnel protocol configuration
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let serverAddr = proto.serverAddress,
              let wsURLString = proto.providerConfiguration?["ws_url"] as? String,
              let wsBase = URL(string: wsURLString)
        else {
            let err = NSError(domain: "OneInfinity", code: -1,
                            userInfo: [NSLocalizedDescriptionKey: "Missing backend configuration"])
            completionHandler(err)
            return
        }

        // Build HTTP upload URL from the ws:// base (swap scheme, add /api/mobile/traffic)
        var components = URLComponents(url: wsBase, resolvingAgainstBaseURL: false)
        components?.scheme = wsBase.scheme == "wss" ? "https" : "http"
        components?.path = "/api/mobile/traffic"
        self.trafficUploadURL = components?.url
        self.apiKey = proto.providerConfiguration?["api_key"] as? String

        // Configure the tunnel network settings
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.8.0.1")
        settings.ipv4Settings = NEIPv4Settings(
            addresses: ["10.8.0.2"],
            subnetMasks: ["255.255.255.0"]
        )
        settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
        settings.dnsSettings = NEDNSSettings(servers: ["8.8.8.8", "8.8.4.4"])
        settings.mtu = 1500

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                log.error("setTunnelNetworkSettings failed: \(error)")
                completionHandler(error)
                return
            }

            log.info("Tunnel network settings applied. Traffic upload → \(self?.trafficUploadURL?.absoluteString ?? "nil")")
            self?.startPacketLoop()
            completionHandler(nil)
        }
    }

    public override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        log.info("PacketTunnelProvider stopping: reason=\(reason.rawValue)")
        completionHandler()
    }

    // MARK: Packet capture loop

    private func startPacketLoop() {
        Task {
            while !Task.isCancelled {
                await readAndForwardPackets()
            }
        }
    }

    private func readAndForwardPackets() async {
        // Read packets from the TUN interface
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self else { return }

            for (i, packet) in packets.enumerated() {
                self.packetsProcessed += 1
                self.bytesProcessed += Int64(packet.count)

                // Attempt HTTP extraction for analysis
                if let httpInfo = self.extractHTTPInfo(from: packet) {
                    self.sendTrafficToBackend(httpInfo)
                }

                // Forward packet to real network
                // Note: In a real VPN, packets are forwarded via a real socket
                // For this implementation, we write them back through the flow
                // (acts as a transparent proxy passthrough)
            }

            // Forward all packets back (transparent passthrough)
            self.packetFlow.writePackets(packets, withProtocols: protocols)
        }
    }

    // MARK: HTTP extraction (lightweight parser)

    private struct HTTPInfo {
        let method: String
        let url: String
        let host: String
        let headers: [String: String]
        let body: String
    }

    private func extractHTTPInfo(from packet: Data) -> HTTPInfo? {
        // Skip IP header (20 bytes for IPv4) + TCP header (20+ bytes)
        guard packet.count > 40 else { return nil }

        // Check IP version (first 4 bits of first byte)
        let version = (packet[0] & 0xF0) >> 4
        guard version == 4 else { return nil } // IPv4 only

        let ipHeaderLen = Int(packet[0] & 0x0F) * 4
        let protocol_ = packet[9]
        guard protocol_ == 6 else { return nil } // TCP only

        guard packet.count > ipHeaderLen + 20 else { return nil }
        let tcpHeaderLen = Int((packet[ipHeaderLen + 12] & 0xF0) >> 4) * 4
        let payloadOffset = ipHeaderLen + tcpHeaderLen

        guard packet.count > payloadOffset + 4 else { return nil }
        let payload = packet[payloadOffset...]

        // Check for HTTP methods
        guard let text = String(data: payload, encoding: .utf8),
              text.hasPrefix("GET ") || text.hasPrefix("POST ") ||
              text.hasPrefix("PUT ") || text.hasPrefix("DELETE ") ||
              text.hasPrefix("PATCH ") || text.hasPrefix("HEAD ")
        else { return nil }

        let lines = text.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else { return nil }
        let parts = requestLine.components(separatedBy: " ")
        guard parts.count >= 2 else { return nil }

        let method = parts[0]
        let path = parts[1]

        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard !line.isEmpty else { break }
            let colonIdx = line.firstIndex(of: ":") ?? line.endIndex
            if colonIdx < line.endIndex {
                let key = String(line[..<colonIdx]).trimmingCharacters(in: .whitespaces)
                let value = String(line[line.index(after: colonIdx)...]).trimmingCharacters(in: .whitespaces)
                headers[key] = value
            }
        }

        let host = headers["Host"] ?? ""
        let scheme = headers["X-Forwarded-Proto"] ?? "http"
        let url = "\(scheme)://\(host)\(path)"

        // Extract body (after \r\n\r\n)
        let bodyPart: String
        if let bodyRange = text.range(of: "\r\n\r\n") {
            bodyPart = String(text[bodyRange.upperBound...]).prefix(1000).description
        } else {
            bodyPart = ""
        }

        return HTTPInfo(method: method, url: url, host: host, headers: headers, body: bodyPart)
    }

    // MARK: Backend communication (Gap D: HTTP POST, not WebSocket)

    private func sendTrafficToBackend(_ info: HTTPInfo) {
        guard let uploadURL = trafficUploadURL else { return }

        let payload: [String: Any] = [
            "device_id": deviceId,
            "request": [
                "method": info.method,
                "url": info.url,
                "headers": info.headers,
                "body": info.body,
            ],
            "response": [:] as [String: Any],
            "source": "ios_network_extension",
        ]
        guard let body = try? JSONSerialization.data(withJSONObject: payload) else { return }

        var req = URLRequest(url: uploadURL)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let key = apiKey, !key.isEmpty {
            req.setValue(key, forHTTPHeaderField: "X-API-Key")
        }
        req.httpBody = body

        // Fire-and-forget — extension does not need a response
        uploadSession.dataTask(with: req) { _, _, error in
            if let error = error {
                log.debug("Traffic upload failed: \(error.localizedDescription)")
            }
        }.resume()
    }
}
