// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SecretKeeper",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "SecretKeeperLib", targets: ["SecretKeeperLib"]),
        .executable(name: "SecretKeeper", targets: ["SecretKeeper"])
    ],
    targets: [
        .target(
            name: "SecretKeeperLib",
            path: "Sources/SecretKeeperLib"
        ),
        .executableTarget(
            name: "SecretKeeper",
            dependencies: ["SecretKeeperLib"],
            path: "Sources/SecretKeeper"
        ),
        .testTarget(
            name: "SecretKeeperTests",
            dependencies: ["SecretKeeperLib"],
            path: "Tests/SecretKeeperTests"
        )
    ]
)
