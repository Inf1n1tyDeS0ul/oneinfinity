# Build OneInfinity Companion APK

Two methods: Android Studio (recommended) or command-line Gradle.

---

## Method 1: Android Studio (Easiest)

### Prerequisites
- macOS 10.14+ / Windows 10+ / Linux
- 8GB RAM minimum
- 20GB disk space

### Steps

1. **Install Android Studio**
   ```bash
   # macOS
   brew install --cask android-studio
   
   # Or download: https://developer.android.com/studio
   ```

2. **Open Project**
   - Launch Android Studio
   - File → Open → Select `android-companion` folder
   - Wait for Gradle sync (5-10 min first time)

3. **Build APK**
   - Build → Build Bundle(s) / APK(s) → Build APK(s)
   - Wait for build to complete
   - Click "locate" link in notification

   **Output:** `app/build/outputs/apk/debug/app-debug.apk`

4. **Install on Device**
   - Enable USB Debugging on Android device:
     - Settings → About Phone → Tap "Build Number" 7 times
     - Settings → Developer Options → Enable USB Debugging
   - Connect device via USB
   - Click "Run" ▶️ button in Android Studio
   
   **Or via ADB:**
   ```bash
   adb install app/build/outputs/apk/debug/app-debug.apk
   ```

---

## Method 2: Command-Line Gradle

### Prerequisites

1. **Install Java JDK 17**
   ```bash
   # macOS
   brew install openjdk@17
   
   # Verify
   java -version  # Should show 17.x
   ```

2. **Install Android SDK**
   ```bash
   # macOS
   brew install --cask android-sdk
   
   # Set environment variables
   echo 'export ANDROID_HOME=$HOME/Library/Android/sdk' >> ~/.zshrc
   echo 'export PATH=$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin' >> ~/.zshrc
   source ~/.zshrc
   ```

3. **Install SDK Components**
   ```bash
   sdkmanager "platform-tools" "platforms;android-34" "build-tools;34.0.0"
   ```

4. **Install Gradle**
   ```bash
   brew install gradle
   ```

### Build APK

```bash
cd android-companion

# Initialize Gradle wrapper (first time only)
gradle wrapper --gradle-version 8.2

# Build debug APK
./gradlew assembleDebug

# Output: app/build/outputs/apk/debug/app-debug.apk
```

### Install APK

```bash
# Via ADB
adb install app/build/outputs/apk/debug/app-debug.apk

# Or transfer APK to device and install manually
```

---

## Method 3: Pre-Built APK (Quick Start)

If build environment setup too complex, use pre-built APK:

**⚠️ Security Note:** Only install APKs from trusted sources. Building yourself is recommended.

```bash
# Download from GitHub releases (when available)
# curl -L https://github.com/oneinfinity/companion/releases/latest/download/app-debug.apk -o oneinfinity-companion.apk

# Install
# adb install oneinfinity-companion.apk
```

---

## Troubleshooting

### Gradle Sync Failed
```bash
# Clear Gradle cache
rm -rf ~/.gradle/caches/
./gradlew clean
```

### SDK Not Found
```bash
# Verify ANDROID_HOME
echo $ANDROID_HOME

# Should point to SDK location (e.g., ~/Library/Android/sdk)
# If not set:
export ANDROID_HOME=$HOME/Library/Android/sdk
```

### Build Tools Missing
```bash
sdkmanager --list | grep build-tools
sdkmanager "build-tools;34.0.0"
```

### Permission Denied on gradlew
```bash
chmod +x gradlew
./gradlew assembleDebug
```

### ADB Device Not Found
```bash
# List devices
adb devices

# If empty:
# 1. Enable USB Debugging on device
# 2. Accept "Allow USB Debugging" prompt on device
# 3. Try different USB cable/port
```

---

## Device Requirements

- **Android Version:** 7.0 (API 24) or higher
- **Storage:** 50MB free space
- **Permissions Required:**
  - Internet access
  - VPN permission (for traffic capture)
  - Network state access

---

## Post-Installation

1. **Launch App**
   - Tap "OneInfinity Companion" icon

2. **Configure Backend**
   - Scan QR code from Web UI (`http://localhost:3000/mobile-agent`)
   - OR tap "Auto-Discover" (same WiFi network)
   - OR manually enter: `http://192.168.1.100:8000`

3. **Grant VPN Permission**
   - Tap "Start Traffic Capture"
   - Accept VPN permission dialog
   - Persistent notification appears

4. **Verify Connection**
   - Device appears in Web UI as 🟢 Online
   - Can send commands from UI
   - Traffic appears in TrafficViewer

---

## Development Build (Hot Reload)

For active development:

```bash
# Run with hot reload
./gradlew installDebug
adb shell am start -n com.oneinfinity.companion/.MainActivity

# View logs
adb logcat | grep -E "OneInfinity|VpnCapture"
```

---

## Release Build (Production)

For production release:

1. **Generate Keystore**
   ```bash
   keytool -genkey -v -keystore oneinfinity-release.keystore \
     -alias oneinfinity -keyalg RSA -keysize 2048 -validity 10000
   ```

2. **Build Release APK**
   ```bash
   ./gradlew assembleRelease
   ```

3. **Sign APK**
   ```bash
   jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 \
     -keystore oneinfinity-release.keystore \
     app/build/outputs/apk/release/app-release-unsigned.apk oneinfinity
   
   zipalign -v 4 app/build/outputs/apk/release/app-release-unsigned.apk \
     oneinfinity-companion-v1.0.apk
   ```

---

## Next Steps

After installation:
- See `README.md` for usage guide
- See `MOBILE_COMPANION_IMPLEMENTATION_PLAN.md` for features
- See Web UI at `http://localhost:3000/mobile-agent`
