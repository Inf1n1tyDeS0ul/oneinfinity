// swift-tools-version: 5.9
// OneInfinity iOS Companion — Phase 4
// Minimum deployment: iOS 16.0 (Network Extension requires iOS 14+)

import PackageDescription

let package = Package(
    name: "OneInfinityCompanion",
    platforms: [
        .iOS(.v16),
    ],
    products: [
        .library(name: "OneInfinityCompanion", targets: ["OneInfinityCompanion"]),
    ],
    dependencies: [
        // No external dependencies — uses only Apple system frameworks
        // NetworkExtension, Network, CryptoKit, Security
    ],
    targets: [
        .target(
            name: "OneInfinityCompanion",
            dependencies: [],
            path: "Sources/OneInfinityCompanion",
            swiftSettings: [
                .unsafeFlags(["-enable-bare-slash-regex"])
            ]
        ),
    ]
)
