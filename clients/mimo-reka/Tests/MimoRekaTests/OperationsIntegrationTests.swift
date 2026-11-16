import Foundation
import XCTest
@testable import MimoReka

@MainActor
final class OperationsIntegrationTests: XCTestCase {
    func testProbeTrafficAndRoutingUseNativeCoreWithoutChangingNetworkTakeover() async throws {
        guard ProcessInfo.processInfo.environment["MIMO_REKA_KERNEL_BINARY"] != nil,
              ProcessInfo.processInfo.environment["MIMO_REKA_HOST_BINARY"] != nil else {
            throw XCTSkip("Set current core and supervisor paths for isolated integration checks.")
        }
        let root = URL(fileURLWithPath: "/tmp/mr-ops-" + String(UUID().uuidString.prefix(8)))
        let store = AppStore(home: root)
        defer { if !store.kernel.isRunning { try? FileManager.default.removeItem(at: root) } }
        await store.start()
        let http = try SubscriptionHTTPFixture(root: root)
        addTeardownBlock { await http.stop() }
        do {
            XCTAssertNil(store.errorMessage)
            XCTAssertTrue(store.isOnline)
            XCTAssertEqual(store.networkMode, "off")
            guard store.supportsMethod("ProbeOutbound") else { throw XCTSkip("Requires the expanded core.") }
            let selection = try XCTUnwrap(store.groups.first { $0.id == "proxy" }?.selected)
            let revision = store.revision
            store.operations.probeURL = http.url
            await store.probeOutbound("proxy")
            let observation = try XCTUnwrap(store.operations.probes["proxy"])
            XCTAssertNil(observation.error)
            XCTAssertGreaterThan(observation.delayMS ?? 0, 0)
            XCTAssertEqual(observation.resolvedOutbound, "direct")
            await store.refresh()
            XCTAssertEqual(store.groups.first { $0.id == "proxy" }?.selected, selection)
            XCTAssertEqual(store.revision, revision)

            let before = try await store.client.call("GetTraffic")
            try await makeProxyRequest(proxy: store.listenerAddress, url: http.url)
            // A completed HTTP request may leave a half-closed TCP relay in
            // its drain grace period. Close only this fixture's exact flow IDs,
            // then check cumulative bytes after the active list is empty.
            var active = try await store.client.call("ListConnections")
            let fixtureFlows = (active["connections"].arrayValue ?? []).compactMap { row -> JSONValue? in
                guard row["source"].stringValue?.hasPrefix("127.0.0.1:") == true else { return nil }
                return row["id"]
            }
            if !fixtureFlows.isEmpty {
                _ = try await store.client.call("CloseConnections", params: ["ids": .array(fixtureFlows)])
            }
            for _ in 0..<40 {
                active = try await store.client.call("ListConnections")
                if active["total"].intValue == 0 { break }
                try await Task.sleep(for: .milliseconds(50))
            }
            XCTAssertEqual(active["total"].intValue, 0)
            let after = try await store.client.call("GetTraffic")
            XCTAssertGreaterThan(after["upload_total"].numberValue ?? 0, before["upload_total"].numberValue ?? 0)
            XCTAssertGreaterThan(after["download_total"].numberValue ?? 0, before["download_total"].numberValue ?? 0)
            XCTAssertEqual(after["epoch"], before["epoch"])
            await store.refreshLiveOperations()
            XCTAssertEqual(store.operations.traffic?.download, after["download_total"].numberValue)

            let profile = store.documents[.profile]
            await store.previewRoutingMode("global", global: "", baseRevision: store.revision)
            XCTAssertNotNil(store.errorMessage)
            XCTAssertNil(store.preparedChange)
            for (mode, target) in [("global", "proxy"), ("direct", ""), ("rule", "")] {
                let saved = await store.previewRoutingMode(mode, global: target, baseRevision: store.revision, save: true)
                XCTAssertTrue(saved)
                XCTAssertNil(store.preparedChange)
                XCTAssertNil(store.errorMessage)
                XCTAssertEqual(store.routingMode, mode)
                XCTAssertEqual(store.documents[.profile], profile, "Changing routing mode must preserve stored rules and selections.")
                XCTAssertEqual(store.groups.first { $0.id == "proxy" }?.selected, selection)
                XCTAssertEqual(store.networkMode, "off")
                let page = try await store.client.call("GetRules")
                XCTAssertEqual(page["mode"].stringValue, mode)
            }
            await store.stop()
            XCTAssertFalse(store.kernel.isRunning)
        } catch {
            await store.stop()
            if store.kernel.isRunning { await store.kernel.stop() }
            throw error
        }
    }

    private func makeProxyRequest(proxy: String, url: String) async throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        process.arguments = ["--silent", "--show-error", "--max-time", "5", "--noproxy", "", "--proxy", "http://" + proxy, url]
        process.standardOutput = FileHandle.nullDevice
        let errors = Pipe(); process.standardError = errors
        try process.run()
        defer { if process.isRunning { process.terminate() } }
        for _ in 0..<160 {
            if !process.isRunning { break }
            try await Task.sleep(for: .milliseconds(50))
        }
        guard !process.isRunning else { throw ClientError.message("Local proxy fixture request timed out") }
        guard process.terminationStatus == 0 else {
            let detail = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            throw ClientError.message("Local proxy request failed: " + detail)
        }
    }
}
