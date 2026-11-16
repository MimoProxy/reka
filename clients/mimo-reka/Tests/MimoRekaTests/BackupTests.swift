import Foundation
import CryptoKit
import XCTest
@testable import MimoReka

final class BackupTests: XCTestCase {
    func testBackupValidatesResourceDigestAndRestoresWithNetworkOff() throws {
        let bytes = Data("example.test\n".utf8)
        let hash = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        let backup = fixture(resources: [hash: bytes])
        let decoded = try BackupService.decode(BackupService.encode(backup))
        let change = try BackupService.restorationChange(decoded, revision: 9)
        XCTAssertEqual(change["base_revision"], .number(9))
        let local = try YAMLDocument.object(change["local"]?.stringValue ?? "")
        XCTAssertEqual(local["network"]?["mode"], .string("off"))
        XCTAssertEqual(local["log"]?["level"], .string("debug"))
        XCTAssertEqual(decoded.resources[hash], bytes)
        XCTAssertThrowsError(try BackupService.decode(BackupService.encode(fixture(resources: [hash: Data("corrupt".utf8)]))))
    }
    func testBackupFileIsPrivateAndAtomicReplacementWorks() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("mr-backup-file-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("backup.rekabackup")
        try BackupService.write(fixture(), to: file)
        try BackupService.write(fixture(), to: file)
        let permissions = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(permissions?.intValue, 0o600)
        XCTAssertNoThrow(try BackupService.decode(Data(contentsOf: file)))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), ["backup.rekabackup"])
    }
    private func fixture(resources: [String: Data] = [:]) -> NativeBackup {
        NativeBackup(format: "mimo-reka-backup", version: 1, createdAt: Date(), profileName: "Test", revision: 1,
            documents: ["profile": "schema-version: 1\n", "local": "network: {mode: tun}\nlog: {level: debug}\n", "sources": "", "overlay": ""], resources: resources, sourceNames: [:])
    }
}

@MainActor
final class BackupIntegrationTests: XCTestCase {
    func testExportAndRestoreFourLayersAndLockedResourcesIntoIndependentProfile() async throws {
        guard ProcessInfo.processInfo.environment["MIMO_REKA_KERNEL_BINARY"] != nil,
              ProcessInfo.processInfo.environment["MIMO_REKA_HOST_BINARY"] != nil else { throw XCTSkip("Set native kernel and supervisor paths") }
        let root = URL(fileURLWithPath: "/tmp/mr-backup-" + String(UUID().uuidString.prefix(8)))
        let source = AppStore(home: root.appendingPathComponent("one")), destination = AppStore(home: root.appendingPathComponent("two"))
        await source.start(); await destination.start()
        do {
            guard source.isOnline, destination.isOnline else { throw ClientError.message(source.errorMessage ?? destination.errorMessage ?? "test startup failed") }
            let data = Data("provider.example.test\n".utf8)
            let hash = try await ResourceImportService.stage(data: data, client: source.client)
            await source.previewImport(data: """
            proxies: [{name: local, type: socks5, server: 127.0.0.1, port: 9, username: Alice, password: private-test}]
            rule-providers: {domains: {type: file, path: never-read.txt, behavior: domain, format: text}}
            rules: ["RULE-SET,domains,REJECT"]
            """, format: "clash", nodesOnly: false, sourceName: "Saved source", providerResources: ["rule-providers/domains": hash])
            await source.applyPrepared(); XCTAssertNil(source.errorMessage)
            let sourceConfig = try await source.client.call("GetConfiguration", params: ["reveal": .bool(true)])
            let backup = try await BackupService.export(client: source.client, name: "Portable", sourceNames: ["test": "Saved source"])
            XCTAssertFalse(backup.resources.isEmpty)
            XCTAssertEqual(backup.resources[hash], data)
            XCTAssertEqual(backup.documents["sources"], sourceConfig["sources"].stringValue)
            let validated = try BackupService.decode(BackupService.encode(backup))
            try await BackupService.stage(validated, client: destination.client)
            let originalRevision = destination.revision
            await destination.previewVisualChange(try BackupService.restorationChange(validated, revision: originalRevision), summary: "Check occupied backup listener")
            XCTAssertNil(destination.errorMessage)
            XCTAssertNotNil(destination.preparedChange)
            await destination.applyPrepared()
            XCTAssertNotNil(destination.errorMessage, "Commit must reject the listener port still owned by the original instance.")
            XCTAssertEqual(destination.revision, originalRevision)
            await source.stop()
            await destination.previewVisualChange(try BackupService.restorationChange(validated, revision: destination.revision), summary: "Restore isolated backup")
            XCTAssertNil(destination.errorMessage); XCTAssertNotNil(destination.preparedChange)
            await destination.applyPrepared(); XCTAssertNil(destination.errorMessage)
            let restored = try await destination.client.call("GetConfiguration", params: ["reveal": .bool(true)])
            XCTAssertEqual(restored["profile"].stringValue, backup.documents["profile"])
            XCTAssertEqual(restored["sources"].stringValue, backup.documents["sources"])
            XCTAssertEqual(restored["overlay"].stringValue ?? "", backup.documents["overlay"])
            XCTAssertEqual(restored["effective"]["network"]["mode"], .string("off"))
            let explain = try await destination.client.call("ExplainRoute", params: ["destination": .string("provider.example.test:443")])
            XCTAssertEqual(explain["outbound"], .string("reject"))
        } catch { await source.stop(); await destination.stop(); throw error }
        await source.stop(); await destination.stop()
        XCTAssertFalse(source.kernel.isRunning); XCTAssertFalse(destination.kernel.isRunning)
        if !source.kernel.isRunning && !destination.kernel.isRunning { try? FileManager.default.removeItem(at: root) }
    }
}
