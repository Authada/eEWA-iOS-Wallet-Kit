// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "EudiWalletKit",
	platforms: [.macOS(.v13), .iOS(.v14)],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "EudiWalletKit",
            targets: ["EudiWalletKit"]),
    ],
    dependencies: [
		.package(url: "https://github.com/apple/swift-docc-plugin", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.3"),
		.package(url: "https://github.com/Authada/eEWA-iOS-Iso18013-Data-Transfer.git", exact: "0.2.0"),
		.package(url: "https://github.com/Authada/eEWA-iOS-Wallet-Storage.git", exact: "0.2.0"),
        .package(url: "https://github.com/Authada/eEWA-iOS-Siop-Openid4vp-Swift.git", exact: "0.2.0"),
		.package(url: "https://github.com/Authada/eEWA-iOS-Openid4vci.git", exact: "0.2.0"),
        .package(url: "https://github.com/Authada/eEWA-iOS-Sdjwt-Swift.git", exact: "0.2.0")
	],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "EudiWalletKit", dependencies: [
		    	.product(name: "MdocDataTransfer18013", package: "eewa-ios-iso18013-data-transfer"),
				.product(name: "WalletStorage", package: "eewa-ios-wallet-storage"),
				.product(name: "SiopOpenID4VP", package: "eewa-ios-siop-openid4vp-swift"),
				.product(name: "OpenID4VCI", package: "eewa-ios-openid4vci"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "eudi-lib-sdjwt-swift", package: "eewa-ios-sdjwt-swift"),
            ]
        ),
        .testTarget(
            name: "EudiWalletKitTests",
            dependencies: ["EudiWalletKit"],
						resources: [.process("Resources")]
						)
    ]
)
