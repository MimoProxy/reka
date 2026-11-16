import Foundation
import XCTest
@testable import MimoReka

@MainActor
final class ProcessClientIntegrationTests: XCTestCase {
    func testAlwaysModeExposesRealMacApplicationTrafficWithoutProcessRules() async throws {
        guard ProcessInfo.processInfo.environment["MIMO_REKA_KERNEL_BINARY"] != nil,
              ProcessInfo.processInfo.environment["MIMO_REKA_HOST_BINARY"] != nil else { throw XCTSkip("Set native core and host paths") }
        let root = URL(fileURLWithPath: "/tmp/mr-owner-" + String(UUID().uuidString.prefix(8)))
        let store = AppStore(home: root)
        await store.start()
        do {
            guard store.isOnline else { throw ClientError.message(store.errorMessage ?? "startup failed") }
            let http = try SubscriptionHTTPFixture(root: root)
            addTeardownBlock { await http.stop() }
            let saved = await store.previewProcessMode("always", revision: store.revision, save: true)
            XCTAssertTrue(saved)
            XCTAssertNil(store.errorMessage)
            XCTAssertEqual(store.processMode, "always")
            let request = Process()
            request.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
            request.arguments = ["--silent", "--max-time", "5", "--noproxy", "", "--proxy", "http://" + store.listenerAddress, http.url]
            request.standardOutput = FileHandle.nullDevice; request.standardError = FileHandle.nullDevice
            try request.run()
            defer { if request.isRunning { request.terminate() } }
            for _ in 0..<120 {
                if !request.isRunning { break }
                try await Task.sleep(for: .milliseconds(50))
            }
            XCTAssertFalse(request.isRunning)
            XCTAssertEqual(request.terminationStatus, 0)
            await store.refreshProcessTraffic()
            let application = try XCTUnwrap(store.operations.processRows.first { $0.path.hasSuffix("/curl") })
            XCTAssertGreaterThan(application.upload, 0)
            XCTAssertGreaterThan(application.download, 0)
            XCTAssertFalse(application.unknown)
            XCTAssertNotNil(application.uid)
            let before = application.download
            _ = try await store.client.call("CloseConnections", params: ["all": .bool(true)])
            for _ in 0..<80 {
                await store.refreshProcessTraffic()
                if store.operations.processRows.first(where: { $0.id == application.id })?.active == 0 { break }
                try await Task.sleep(for: .milliseconds(50))
            }
            let closed = try XCTUnwrap(store.operations.processRows.first { $0.id == application.id })
            XCTAssertEqual(closed.download, before)
            XCTAssertEqual(closed.active, 0)
            XCTAssertEqual(store.networkMode, "off")
        } catch { await store.stop(); throw error }
        await store.stop(); XCTAssertFalse(store.kernel.isRunning)
        if !store.kernel.isRunning { try? FileManager.default.removeItem(at: root) }
    }
}
