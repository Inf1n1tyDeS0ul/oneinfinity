# OneInfinity iOS Companion — Phase 4

iOS companion app for traffic capture and security testing.

## Requirements
- iOS 16.0+
- Xcode 15.0+
- For Frida features: jailbroken device with frida-server from build.frida.re

## Capabilities
- **All devices**: Network Extension traffic capture, WebSocket backend connection, Attack Launcher integration
- **Jailbroken devices**: Frida instrumentation (frida-server), SSL bypass, jailbreak bypass, keychain hooks

## Project Structure
```
ios-companion/
├── Package.swift
└── Sources/OneInfinityCompanion/
    ├── ConfigManager.swift       — backend URL discovery (QR, mDNS, manual)
    ├── WebSocketManager.swift    — WebSocket + heartbeat + command dispatch
    ├── ContentView.swift         — SwiftUI main UI (Status, Traffic, Frida, Attack tabs)
    ├── NetworkExtension/
    │   └── PacketTunnelProvider.swift  — NEPacketTunnelProvider (VPN traffic capture)
    └── Frida/
        └── FridaManager.swift    — frida-server lifecycle + script runner
```

## Build (Xcode)
1. Open Xcode → Create new project → App + Network Extension target
2. Copy Swift files into project targets
3. Add required entitlements:
   - `com.apple.developer.networking.networkextension` (App + Extension)
   - `com.apple.developer.networking.vpn.api` (Extension)
4. Enable Network Extension in Signing & Capabilities
5. Set deployment target to iOS 16.0

## Setup
1. Build and install via Xcode on device
2. Grant VPN permission when prompted
3. Scan QR code from `/api/setup/qr` endpoint or enter backend URL manually
4. Tap "Start Capture" to begin traffic interception

## frida-server Installation (Jailbroken)
```
# Via Cydia (add repo: https://build.frida.re)
# Or manually:
adb # Not needed for iOS — use iproxy
iproxy 27042 27042 &   # USB tunnel for frida on iOS
frida-ps -U            # Should list iOS apps
```

## Architecture Notes
- Traffic capture uses NEPacketTunnelProvider (Network Extension)
- Frida execution happens on the HOST machine, not the device
- The companion ensures frida-server is running, backend runs `frida -U -f <bundle_id>`
- WebSocket: `ws://<backend>:8000/ws/mobile/<device_id>`
