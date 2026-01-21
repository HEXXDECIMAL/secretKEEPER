// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SecretKeeper",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "SecretKeeper", targets: ["SecretKeeper"])
    ],
    targets: [
        .executableTarget(
            name: "SecretKeeper",
            path: "Sources/SecretKeeper"
        )
    ]
)
