import Foundation
import XCTest
@testable import MimoReka

@MainActor
final class KernelLifecycleTests: XCTestCase {
    func testLongProfilePathUsesShortSocketAndSupervisedShutdown() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let core = environment["MIMO_REKA_KERNEL_BINARY"] ?? environment["REKA_MAC_KERNEL_BINARY"],
              let host = environment["MIMO_REKA_HOST_BINARY"],
              FileManager.default.isExecutableFile(atPath: core), FileManager.default.isExecutableFile(atPath: host) else {
            throw XCTSkip("Set MIMO_REKA_KERNEL_BINARY and MIMO_REKA_HOST_BINARY for the production-kernel lifecycle test.")
        }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mimo-reka-long-profile-" + UUID().uuidString)
        let state = directory.appendingPathComponent("Library/Application Support/MimoReka/profiles/" + UUID().uuidString)
        let kernel = KernelProcess(stateRoot: state)
        defer { if !kernel.isRunning { try? FileManager.default.removeItem(at: directory) } }
        do {
            XCTAssertGreaterThan(state.appendingPathComponent("control.sock").path.utf8.count, 103)
            XCTAssertLessThan(kernel.socketPath.utf8.count, 104)
            try await kernel.start()
            XCTAssertTrue(kernel.isRunning)
            XCTAssertNotNil(kernel.corePID)
            let client = RekaControlClient(socketPath: kernel.socketPath)
            let status = try await client.call("GetStatus")
            XCTAssertEqual(status["runtime"]["network"]["mode"].stringValue, "off")
            await kernel.stop()
            XCTAssertFalse(kernel.isRunning)
            XCTAssertFalse(FileManager.default.fileExists(atPath: kernel.socketPath))
        } catch {
            await kernel.stop()
            throw error
        }
    }

    func testSecretReferencePromotionIsRejectedBeforeStoppingNormalRuntime() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment["MIMO_REKA_KERNEL_BINARY"] != nil, environment["MIMO_REKA_HOST_BINARY"] != nil else {
            throw XCTSkip("Set MIMO_REKA_KERNEL_BINARY and MIMO_REKA_HOST_BINARY.")
        }
        let directory = URL(fileURLWithPath: "/tmp/mr-secret-" + String(UUID().uuidString.prefix(8)))
        let kernel = KernelProcess(stateRoot: directory)
        defer { if !kernel.isRunning { try? FileManager.default.removeItem(at: directory) } }
        do {
            try await kernel.start()
            let originalPID = kernel.corePID
            let input: JSONValue = .object([
                "effective": .object(["network": .object(["mode": .string("off")])]),
                "profile": .string("password: secret://test/password"),
                "local": .string("network: {mode: off}"), "sources": .string(""), "overlay": .string("")
            ])
            do { try await kernel.promote(configuration: input); XCTFail("Expected a blocked secret migration") }
            catch { XCTAssertTrue(error.localizedDescription.contains("secret://")) }
            XCTAssertTrue(kernel.isRunning)
            XCTAssertFalse(kernel.isPrivileged)
            XCTAssertEqual(kernel.corePID, originalPID)
            await kernel.stop()
            XCTAssertFalse(kernel.isRunning)
        } catch {
            await kernel.stop()
            throw error
        }
    }
}
