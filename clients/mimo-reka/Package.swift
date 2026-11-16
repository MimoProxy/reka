// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "MimoReka",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "MimoReka", targets: ["MimoReka"]), .executable(name: "MimoRekaHost", targets: ["MimoRekaHost"])],
    dependencies: [.package(path: "Vendor/Yams")],
    targets: [
        .executableTarget(name: "MimoReka", dependencies: ["Yams"]),
        .executableTarget(name: "MimoRekaHost"),
        .testTarget(name: "MimoRekaTests", dependencies: ["MimoReka"])
    ],
    swiftLanguageModes: [.v5]
)
