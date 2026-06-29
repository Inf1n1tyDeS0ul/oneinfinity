# OneInfinity Mobile Companion - Android

**Phase 0: Foundation** (Implemented)

## Overview

Android companion app for OneInfinity security testing platform. Provides:
- Traffic interception and forwarding
- Attack payload injection
- Frida runtime hooking integration
- WebSocket bidirectional communication with backend

## Current Status: Phase 0 Complete ✅

### Implemented Features

#### Backend Configuration
- `ConfigManager.kt` - Persistent backend URL storage
- `MdnsDiscovery.kt` - Auto-discovery via mDNS/Bonjour
- `BackendConfig.kt` - Configuration data model
- Emulator detection (10.0.2.2 auto-mapping)

#### Network Communication
- `WebSocketClient.kt` - Bidirectional WebSocket
- Heartbeat keepalive (10s interval)
- Command reception from backend
- Traffic/finding transmission to backend

#### Main Application
- `MainActivity.kt` - Device registration
- Root detection (`RootChecker.kt`)
- Command handler stubs

### Project Structure

```
android-companion/
├── app/
│   ├── src/main/
│   │   ├── java/com/oneinfinity/companion/
│   │   │   ├── config/
│   │   │   │   ├── BackendConfig.kt
│   │   │   │   ├── ConfigManager.kt
│   │   │   │   └── MdnsDiscovery.kt
│   │   │   ├── network/
│   │   │   │   └── WebSocketClient.kt
│   │   │   ├── utils/
│   │   │   │   └── RootChecker.kt
│   │   │   └── MainActivity.kt
│   │   ├── res/
│   │   └── AndroidManifest.xml
│   └── build.gradle
├── build.gradle
├── settings.gradle
└── gradle.properties
```

## Build Instructions

### Prerequisites

- Android Studio Hedgehog (2023.1.1) or later
- Android SDK 24+ (Android 7.0+)
- Kotlin 1.9.20
- Gradle 8.2.0

### Build APK

```bash
cd android-companion

# Debug build
./gradlew assembleDebug

# Release build (unsigned)
./gradlew assembleRelease
```

Output: `app/build/outputs/apk/debug/app-debug.apk`

### Install on Device/Emulator

```bash
# Via ADB
adb install app/build/outputs/apk/debug/app-debug.apk

# Or drag-and-drop APK onto emulator
```

## Testing Phase 0

### 1. Start Backend

```bash
cd /Users/devendrayadav/Tools/oneinfinity
python web/backend/main.py
```

Backend will:
- Listen on `http://localhost:8000`
- Advertise via mDNS as `_oneinfinity._tcp.`
- Serve QR code at `/api/setup/qr`

### 2. Launch Android App

**Emulator:**
```bash
# Backend auto-detected at 10.0.2.2:8000
adb logcat | grep OneInfinity
```

**Real Device (Same WiFi):**
```bash
# mDNS auto-discovery should find backend
adb logcat | grep MdnsDiscovery
```

### 3. Verify Connection

**Backend logs:**
```
[mDNS] Advertising backend at 192.168.1.100:8000
[mobile-agent] Device connected: abc123...
```

**Android logs:**
```
I/OneInfinity: Device ID: abc123...
I/OneInfinity: Backend URL: http://10.0.2.2:8000
I/OneInfinity: Registration response: {"status":"registered",...}
I/WebSocketClient: WebSocket connected
```

**Web UI:**
- Navigate to `http://localhost:3000/mobile-agent`
- Device should appear in "Connected Devices" list
- Status: 🟢 Online

### 4. Test Commands

From Web UI:
1. Click "Start Traffic Capture" → logs "Starting traffic capture"
2. Click "Inject Test Payload" → logs "Injecting payload"
3. Click "Clear Cache" → cache directory cleared

**Android logs:**
```
I/OneInfinity: Received command: start_capture
I/OneInfinity: Starting traffic capture (Phase 1 implementation)
```

## Configuration Methods

### Method 1: QR Code (Recommended)

1. Open `http://localhost:8000/api/setup/qr` in browser
2. Scan QR with app (Phase 1 - camera permission required)
3. Config auto-saved

### Method 2: mDNS Auto-Discovery

1. Ensure device on same WiFi as backend
2. App auto-discovers backend on launch
3. No manual configuration needed

### Method 3: Manual Entry

1. Open app settings (Phase 1 - UI not yet implemented)
2. Enter backend URL: `http://192.168.1.100:8000`
3. Save config

## Next Steps: Phase 1

**Traffic Capture (Week 3-5)**

Files to implement:
- `vpn/VpnCaptureService.kt` - Android VpnService
- `network/PacketParser.kt` - IP/TCP/UDP parsing
- `network/HttpStreamReassembler.kt` - HTTP request/response extraction
- Frontend: `TrafficViewer.jsx`

Features:
- System-wide traffic interception
- HTTP/HTTPS parsing
- Live streaming to Web UI
- Packet filtering (target app only)

## Dependencies

**Current (Phase 0):**
- `okhttp3:4.12.0` - WebSocket client
- `kotlinx-coroutines:1.7.3` - Async operations
- AndroidX core libraries

**Future (Phase 1+):**
- VpnService API (system)
- mitmproxy integration
- Frida server binary

## Troubleshooting

### Device Not Appearing in UI

1. Check backend running: `curl http://localhost:8000/health`
2. Check Android logs: `adb logcat | grep OneInfinity`
3. Verify network: Same WiFi for mDNS

### WebSocket Connection Failed

1. Check firewall (port 8000 open)
2. Emulator: Use `10.0.2.2` not `localhost`
3. Real device: Use LAN IP `192.168.x.x`

### mDNS Discovery Not Working

1. Ensure `zeroconf` installed: `pip install zeroconf`
2. Check backend logs for "Advertising backend"
3. Try manual configuration as fallback

## License

MIT License - See root project LICENSE file
