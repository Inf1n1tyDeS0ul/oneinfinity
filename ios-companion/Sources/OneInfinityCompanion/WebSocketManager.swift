// WebSocketManager.swift — WebSocket client for iOS Companion
// Phase 4: iOS Support
//
// Bidirectional WebSocket communication with OneInfinity backend.
// Handles: connection, heartbeat, command dispatch, result streaming.
// Uses URLSessionWebSocketTask (iOS 13+) — no third-party dependencies.

import Foundation
import Combine

// MARK: - Message types

public struct BackendMessage: Codable {
    public let type: String
    public let payload: [String: AnyCodable]?

    public init(type: String, payload: [String: AnyCodable]? = nil) {
        self.type = type
        self.payload = payload
    }
}

// AnyCodable for heterogeneous JSON
public struct AnyCodable: Codable {
    public let value: Any

    public init(_ value: Any) { self.value = value }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let v = try? container.decode(Bool.self)   { value = v; return }
        if let v = try? container.decode(Int.self)    { value = v; return }
        if let v = try? container.decode(Double.self) { value = v; return }
        if let v = try? container.decode(String.self) { value = v; return }
        if let v = try? container.decode([String: AnyCodable].self) { value = v; return }
        if let v = try? container.decode([AnyCodable].self) { value = v; return }
        value = NSNull()
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch value {
        case let v as Bool:                     try container.encode(v)
        case let v as Int:                      try container.encode(v)
        case let v as Double:                   try container.encode(v)
        case let v as String:                   try container.encode(v)
        case let v as [String: AnyCodable]:     try container.encode(v)
        case let v as [AnyCodable]:             try container.encode(v)
        default:                                try container.encodeNil()
        }
    }
}

// MARK: - WebSocketManager

@MainActor
public final class WebSocketManager: NSObject, ObservableObject {
    @Published public var isConnected = false
    @Published public var lastError: String?

    private let deviceId: String
    private var wsURL: URL?
    private var session: URLSession?
    private var task: URLSessionWebSocketTask?
    private var heartbeatTimer: Timer?
    private var reconnectDelay: TimeInterval = 2.0

    // Command dispatch handlers — set by callers
    public var onCommand: ((String, [String: Any]) -> Void)?
    public var onFridaInject: (([String: Any]) -> Void)?
    public var onAttackCommand: (([String: Any]) -> Void)?

    public init(deviceId: String) {
        self.deviceId = deviceId
        super.init()
        self.session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
    }

    // MARK: Connection lifecycle

    public func connect(to config: BackendConfig) {
        let wsEndpoint = config.wsURL.appendingPathComponent("ws/mobile/\(deviceId)")
        self.wsURL = wsEndpoint
        openConnection(to: wsEndpoint)
    }

    private func openConnection(to url: URL) {
        task?.cancel()
        let newTask = session!.webSocketTask(with: url)
        self.task = newTask
        newTask.resume()
        scheduleReceive()
        startHeartbeat()
        isConnected = true
        lastError = nil
        print("[WebSocket] Connecting to \(url)")
    }

    public func disconnect() {
        heartbeatTimer?.invalidate()
        task?.cancel(with: .normalClosure, reason: nil)
        task = nil
        isConnected = false
    }

    // MARK: Send

    public func send(_ json: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: json),
              let text = String(data: data, encoding: .utf8) else { return }
        task?.send(.string(text)) { [weak self] error in
            if let error = error {
                print("[WebSocket] Send error: \(error)")
                self?.scheduleReconnect()
            }
        }
    }

    public func sendHeartbeat() {
        send(["type": "heartbeat", "device_id": deviceId])
    }

    public func sendFinding(_ finding: [String: Any]) {
        var msg = finding
        msg["device_id"] = deviceId
        send(msg)
    }

    public func sendLog(_ message: String) {
        send(["type": "log", "device_id": deviceId, "message": message])
    }

    public func sendTraffic(request: [String: Any], response: [String: Any]) {
        send([
            "type": "traffic",
            "device_id": deviceId,
            "request": request,
            "response": response
        ])
    }

    // MARK: Receive loop

    private func scheduleReceive() {
        task?.receive { [weak self] result in
            guard let self = self else { return }
            switch result {
            case .success(let message):
                switch message {
                case .string(let text):
                    self.handleMessage(text)
                case .data(let data):
                    if let text = String(data: data, encoding: .utf8) {
                        self.handleMessage(text)
                    }
                @unknown default: break
                }
                self.scheduleReceive()  // reschedule

            case .failure(let error):
                print("[WebSocket] Receive error: \(error)")
                Task { @MainActor in
                    self.isConnected = false
                    self.lastError = error.localizedDescription
                    self.scheduleReconnect()
                }
            }
        }
    }

    private func handleMessage(_ text: String) {
        guard let data = text.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return }

        let type = json["type"] as? String ?? ""
        print("[WebSocket] Received: \(type)")

        DispatchQueue.main.async { [weak self] in
            switch type {
            case "heartbeat_ack":
                break

            case "frida_inject", "frida_stop", "frida_status":
                self?.onFridaInject?(json)

            case "inject_payload", "execute_attack", "stop_attack", "ping":
                self?.onAttackCommand?(json)

            case "frida_output", "frida_session_event":
                self?.onFridaInject?(json)

            default:
                self?.onCommand?(type, json)
            }
        }
    }

    // MARK: Heartbeat

    private func startHeartbeat() {
        heartbeatTimer?.invalidate()
        heartbeatTimer = Timer.scheduledTimer(withTimeInterval: 10.0, repeats: true) { [weak self] _ in
            self?.sendHeartbeat()
        }
    }

    // MARK: Reconnection

    private func scheduleReconnect() {
        guard let url = wsURL else { return }
        print("[WebSocket] Reconnecting in \(reconnectDelay)s…")
        DispatchQueue.main.asyncAfter(deadline: .now() + reconnectDelay) { [weak self] in
            self?.openConnection(to: url)
            self?.reconnectDelay = min((self?.reconnectDelay ?? 2) * 2, 30)
        }
    }
}

// MARK: URLSessionWebSocketDelegate

extension WebSocketManager: URLSessionWebSocketDelegate {
    nonisolated public func urlSession(
        _ session: URLSession,
        webSocketTask: URLSessionWebSocketTask,
        didOpenWithProtocol protocol: String?
    ) {
        Task { @MainActor in
            isConnected = true
            reconnectDelay = 2.0
            print("[WebSocket] Connected")
        }
    }

    nonisolated public func urlSession(
        _ session: URLSession,
        webSocketTask: URLSessionWebSocketTask,
        didCloseWith closeCode: URLSessionWebSocketTask.CloseCode,
        reason: Data?
    ) {
        Task { @MainActor in
            isConnected = false
            print("[WebSocket] Disconnected: \(closeCode)")
            scheduleReconnect()
        }
    }
}
