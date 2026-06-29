# Quick Install Guide - OneInfinity Companion

Fastest way to install APK on your Android device.

---

## Option 1: Android Studio (Recommended)

**Best for:** First-time builders

```bash
# 1. Install Android Studio (if not already installed)
brew install --cask android-studio

# 2. Open project
# File → Open → Select 'android-companion' folder

# 3. Build APK
# Build → Build Bundle(s) / APK(s) → Build APK(s)

# 4. Install
# Connect device via USB → Click Run ▶️
```

**Time:** 10-15 min (first time setup)  
**Output:** APK auto-installed on device

---

## Option 2: Command-Line Build

**Best for:** Developers with Android SDK

### Quick Setup

```bash
# Install dependencies (macOS)
brew install openjdk@17 gradle android-sdk

# Set environment
export ANDROID_HOME=$HOME/Library/Android/sdk
export PATH=$PATH:$ANDROID_HOME/platform-tools

# Install SDK components
sdkmanager "platform-tools" "platforms;android-34" "build-tools;34.0.0"
```

### Build & Install

```bash
cd android-companion

# Build APK
./gradlew assembleDebug

# Install on device
adb install app/build/outputs/apk/debug/app-debug.apk
```

**Time:** 5 min (after setup)  
**Output:** `app/build/outputs/apk/debug/app-debug.apk`

---

## Option 3: Manual APK Transfer

**Best for:** No build environment available

### Steps

1. **Build on another machine** (with Android Studio)
2. **Copy APK to device:**
   ```bash
   # Via ADB
   adb push app-debug.apk /sdcard/Download/
   
   # Or via email/cloud
   # Email APK to yourself, download on device
   ```

3. **Install on device:**
   - Open Files app
   - Navigate to Downloads
   - Tap `app-debug.apk`
   - Settings → Security → Enable "Install from Unknown Sources"
   - Tap "Install"

**Time:** 2 min  
**Requires:** Pre-built APK

---

## Post-Install Setup

After APK installed:

### 1. Launch App
Tap "OneInfinity Companion" icon

### 2. Configure Backend

**Method A: QR Code (Easiest)**
- Web UI: http://localhost:3000/mobile-agent
- Scan QR code displayed on page

**Method B: Auto-Discovery**
- Ensure device on same WiFi as computer
- Tap "Auto-Discover" in app
- Backend found automatically

**Method C: Manual Entry**
- Tap "Manual Setup"
- Enter backend URL: `http://192.168.1.XXX:8000`
  - Replace XXX with your computer's local IP
  - Find IP: `ifconfig en0 | grep "inet " | awk '{print $2}'`

### 3. Grant VPN Permission
- Tap "Start Traffic Capture" from Web UI
- Accept VPN permission dialog on device
- Notification appears: "OneInfinity Traffic Capture"

### 4. Verify Connection
- Web UI shows device: 🟢 Online
- Device ID, platform, root status visible
- Can send commands from UI

---

## Troubleshooting

### "App not installed" error
```bash
# Uninstall old version first
adb uninstall com.oneinfinity.companion

# Reinstall
adb install app-debug.apk
```

### ADB not recognized
```bash
# macOS
brew install android-platform-tools

# Verify
adb version
```

### Device not showing in Web UI
1. Check backend running: `curl http://localhost:8000/health`
2. Check device logs: `adb logcat | grep OneInfinity`
3. Verify WiFi: Device and computer on same network

### VPN permission denied
- Android 7+: VPN permission required for system-wide capture
- Grant permission when prompted
- If accidentally denied, reinstall app

---

## Quick Commands Reference

```bash
# Build APK
cd android-companion && ./gradlew assembleDebug

# Install APK
adb install app/build/outputs/apk/debug/app-debug.apk

# View logs
adb logcat | grep -E "OneInfinity|VpnCapture"

# Uninstall
adb uninstall com.oneinfinity.companion

# Push APK to device
adb push app-debug.apk /sdcard/Download/

# Check connected devices
adb devices

# Get device IP (on device via adb)
adb shell ip addr show wlan0 | grep inet
```

---

## System Requirements

- **Android Version:** 7.0 (API 24) or higher
- **Storage:** 50MB free
- **Network:** WiFi connection
- **Permissions:** Internet, VPN, Network State

---

## Next Steps

After installation complete:
1. Start backend: `python web/backend/main.py`
2. Open Web UI: http://localhost:3000/mobile-agent
3. Configure device (QR/Auto-discover/Manual)
4. Start traffic capture
5. View live traffic in TrafficViewer

See `README.md` for full feature documentation.
