import Foundation
import XCTest
@testable import MimoReka

@MainActor
final class StartupRecoveryTests: XCTestCase {
    func testUnknownPendingTakeoverIsArchivedWithoutExecution() async throws {
        try await withKernel { kernel, root in
            let client = RekaControlClient(socketPath: kernel.socketPath)
            let config = try await client.call("GetConfiguration")
            let pending = root.appendingPathComponent("client/pending-operation.json")
            try FileManager.default.createDirectory(at: pending.deletingLastPathComponent(), withIntermediateDirectories: true)
            let request: [String: JSONValue] = [
                "operation_id": .string(UUID().uuidString), "plan_hash": .string("unconfirmed"), "base_revision": config["revision"],
                "local_patch": .array([.object(["op": .string("set"), "path": .string("/network"), "value": .object(["mode": .string("tun")])])])
            ]
            try JSONEncoder().encode(request).write(to: pending)
            let service = ConfigurationService(client: client, pendingURL: pending)
            let deferred = try await service.recoverPendingForStartup()
            XCTAssertTrue(deferred)
            XCTAssertFalse(FileManager.default.fileExists(atPath: pending.path))
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: pending.deletingLastPathComponent().path).filter { $0.hasPrefix("deferred-network-operation-") }.count, 1)
            let after = try await client.call("GetConfiguration")
            XCTAssertEqual(after["revision"], config["revision"])
            XCTAssertEqual(after["effective"]["network"]["mode"].stringValue, "off")
        }
    }

    func testRecordedPendingLocalEditIsResolvedWithoutReplaying() async throws {
        try await withKernel { kernel, root in
            let client = RekaControlClient(socketPath: kernel.socketPath)
            let service = ConfigurationService(client: client)
            let candidate = try await service.prepare(["local": .string("network: {mode: off}\nlog: {level: warn}\n")], summary: "confirmed local edit")
            var request = candidate.change
            request["operation_id"] = .string(candidate.id.uuidString)
            request["plan_hash"] = .string(candidate.planHash)
            let committed = try await client.call("CommitConfiguration", params: request)
            XCTAssertEqual(committed["state"].stringValue, "committed")
            let pending = root.appendingPathComponent("pending.json")
            try JSONEncoder().encode(request).write(to: pending)
            let recovering = ConfigurationService(client: client, pendingURL: pending)
            let deferred = try await recovering.recoverPendingForStartup()
            XCTAssertFalse(deferred)
            let after = try await client.call("GetConfiguration")
            XCTAssertEqual(after["revision"], committed["revision"])
            XCTAssertFalse(FileManager.default.fileExists(atPath: pending.path))
        }
    }

    private func withKernel(_ work: (KernelProcess, URL) async throws -> Void) async throws {
        guard ProcessInfo.processInfo.environment["MIMO_REKA_KERNEL_BINARY"] != nil,
              ProcessInfo.processInfo.environment["MIMO_REKA_HOST_BINARY"] != nil else { throw XCTSkip("Set core and host paths") }
        let root = URL(fileURLWithPath: "/tmp/mr-start-" + String(UUID().uuidString.prefix(8)))
        let kernel = KernelProcess(stateRoot: root)
        do {
            try await kernel.start()
            try await work(kernel, root)
            await kernel.stop()
            XCTAssertFalse(kernel.isRunning)
        } catch { await kernel.stop(); throw error }
        if !kernel.isRunning { try? FileManager.default.removeItem(at: root) }
    }
}
