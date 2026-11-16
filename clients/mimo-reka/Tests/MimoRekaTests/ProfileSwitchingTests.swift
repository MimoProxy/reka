import CryptoKit
import Darwin
import Foundation
import XCTest
@testable import MimoReka

@MainActor
final class ProfileSwitchingTests: XCTestCase {
    func testInactiveHistoryArchiveInstallsAllRevisionsAndResourcesWithoutRestart() async throws {
        try requireBinaries()
        let root = URL(fileURLWithPath: "/tmp/mr-history-" + String(UUID().uuidString.prefix(8)))
        let store = AppStore(home: root)
        defer { if !store.kernel.isRunning { try? FileManager.default.removeItem(at: root) } }
        do {
            await store.start(); XCTAssertNil(store.errorMessage)
            let first = store.activeProfileID
            let http = try SubscriptionHTTPFixture(root: root)
            addTeardownBlock { await http.stop() }
            await store.addSubscription(name: "Independent subscription", url: http.url, interval: 3600, nodesOnly: true)
            XCTAssertNil(store.errorMessage)
            let sourceID = try XCTUnwrap(store.sources.first?.id)
            let originalRevision = store.revision
            let originalDirectory = AppStore.profileDirectory(root: root, id: first)
            XCTAssertThrowsError(try ProfileArchiveService.prepare(root: originalDirectory))
            await store.createProfile(name: "Second profile")
            XCTAssertNil(store.errorMessage); XCTAssertTrue(store.sources.isEmpty)
            await store.stop(); XCTAssertFalse(store.kernel.isRunning)
            let archive = try XCTUnwrap(ProfileArchiveService.prepare(root: originalDirectory))
            defer { try? FileManager.default.removeItem(at: archive.file) }
            XCTAssertFalse(archive.resources.isEmpty)
            let encoded = try JSONDecoder().decode(JSONValue.self, from: Data(contentsOf: archive.file))
            XCTAssertEqual(encoded["active"]["revision"].intValue, originalRevision)
            XCTAssertNotNil(encoded["subscriptions"][sourceID].objectValue)
            await store.start(); XCTAssertNil(store.errorMessage)
            let pid = store.kernel.corePID
            let clone = UUID()
            var catalog = store.catalog
            catalog.profiles.append(ClientProfile(id: clone, name: "Imported full history"))
            try catalog.save(to: root)
            store.catalog = catalog; store.profiles = catalog.profiles
            for item in archive.resources {
                let hash = try await ResourceImportService.stage(file: item.file, client: store.client, profileID: clone.uuidString.lowercased())
                XCTAssertEqual(hash, item.hash)
            }
            let hash = try await ResourceImportService.stage(file: archive.file, client: store.client)
            let installed = try await store.client.call("InstallProfile", params: ["profile_id": .string(clone.uuidString.lowercased()), "archive_hash": .string(hash)])
            XCTAssertEqual(installed["target_revision"].intValue, originalRevision)
            await store.switchProfile(clone)
            XCTAssertNil(store.errorMessage); XCTAssertEqual(store.kernel.corePID, pid)
            XCTAssertEqual(store.revision, originalRevision)
            XCTAssertEqual(store.sources.first?.id, sourceID)
            XCTAssertEqual(store.revisions.count, encoded["revisions"].arrayValue?.count)
            await store.switchProfile(first)
            XCTAssertNil(store.errorMessage); XCTAssertEqual(store.kernel.corePID, pid)
            XCTAssertEqual(store.sources.first?.name, "Independent subscription")
            await store.stop(); XCTAssertFalse(store.kernel.isRunning)
        } catch { await store.kernel.stop(); throw error }
    }

    func testInvalidTargetKeepsCurrentProfilePIDAndHistory() async throws {
        try requireBinaries()
        let root = URL(fileURLWithPath: "/tmp/mr-rollback-" + String(UUID().uuidString.prefix(8)))
        let store = AppStore(home: root)
        defer { if !store.kernel.isRunning { try? FileManager.default.removeItem(at: root) } }
        do {
            await store.start(); XCTAssertNil(store.errorMessage)
            let first = store.activeProfileID
            await store.createProfile(name: "Broken target")
            let broken = store.activeProfileID
            let targetRevision = store.revision
            await store.switchProfile(first)
            await store.stop(); XCTAssertFalse(store.kernel.isRunning)
            let directory = AppStore.profileDirectory(root: root, id: broken)
            let version = directory.appendingPathComponent("revisions/" + String(format: "%010d", targetRevision))
            let data = Data("schema-version: 1\nrules: [{match: {all: true}, outbound: missing-policy}]\n".utf8)
            try data.write(to: version.appendingPathComponent("profile.yaml"))
            let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            for file in [version.appendingPathComponent("meta.json"), directory.appendingPathComponent("active.json")] {
                var object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
                object["profile_sha256"] = hash
                try JSONSerialization.data(withJSONObject: object).write(to: file)
            }
            await store.start(); XCTAssertNil(store.errorMessage)
            let pid = store.kernel.corePID, revision = store.revision
            let documents = store.documents
            await store.switchProfile(broken)
            XCTAssertNotNil(store.errorMessage)
            XCTAssertTrue(store.isOnline)
            XCTAssertEqual(store.activeProfileID, first)
            XCTAssertEqual(store.kernel.corePID, pid)
            XCTAssertEqual(store.revision, revision)
            XCTAssertEqual(store.documents, documents)
            XCTAssertEqual(try ProfileCatalog.load(from: root).activeProfileID, first)
            let after = try await store.client.call("GetProfileState")
            XCTAssertEqual(after["profile_id"].stringValue, first.uuidString.lowercased())
            await store.stop(); XCTAssertFalse(store.kernel.isRunning)
        } catch { await store.kernel.stop(); throw error }
    }

    private func requireBinaries() throws {
        guard ProcessInfo.processInfo.environment["MIMO_REKA_KERNEL_BINARY"] != nil,
              ProcessInfo.processInfo.environment["MIMO_REKA_HOST_BINARY"] != nil else { throw XCTSkip("Set core and host paths") }
    }
}
