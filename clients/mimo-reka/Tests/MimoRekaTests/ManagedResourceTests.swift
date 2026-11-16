import Foundation
import XCTest
@testable import MimoReka

@MainActor
final class ManagedResourceIntegrationTests: XCTestCase {
    func testURLImportConditionalUpdateInvalidContentAndAutomaticRefresh() async throws {
        try await withStore { store, root in
            let server = try ResourceHTTPFixture(root: root)
            addTeardownBlock { await server.stop() }
            try Data("+.first.test\n".utf8).write(to: server.body)
            var draft = ManagedResourceDraft(); draft.identifier = "remote-domains"; draft.url = server.url; draft.interval = 300
            let saved = await store.saveResource(draft)
            XCTAssertTrue(saved, store.errorMessage ?? "URL save failed")
            let first = try XCTUnwrap(store.managedResources.first)
            XCTAssertTrue(first.automatic)
            await store.previewRule(definition: ["id": .string("remote-rule"), "match": .object(["rule-set": .string(first.identifier)]), "outbound": .string("reject")], record: nil, baseRevision: store.revision, save: true)
            XCTAssertNil(store.errorMessage)
            let oldRevision = store.revision
            let unchanged = await store.saveResource(ManagedResourceDraft(resource: first), force: true)
            XCTAssertTrue(unchanged, store.errorMessage ?? "Conditional check failed")
            XCTAssertEqual(store.revision, oldRevision, "304 checks must not create configuration revisions.")
            let headers = try String(contentsOf: server.requests, encoding: .utf8)
            XCTAssertTrue(headers.contains("If-None-Match"))
            try Data("invalid/domain/value\n".utf8).write(to: server.body)
            let invalid = await store.saveResource(ManagedResourceDraft(resource: first), force: true)
            XCTAssertFalse(invalid)
            XCTAssertNotNil(store.resourceUpdates.statuses[first.id]?.failure)
            XCTAssertEqual(store.managedResources.first?.hash, first.hash)
            XCTAssertEqual(store.revision, oldRevision)
            let oldRoute = try await store.client.call("ExplainRoute", params: ["destination": .string("x.first.test:443")])
            XCTAssertEqual(oldRoute["outbound"].stringValue, "reject")
            store.errorMessage = nil
            try Data("+.second.test\n".utf8).write(to: server.body)
            store.resourceUpdates.statuses[first.id]?.checkedAt = Date().addingTimeInterval(-400)
            await store.refreshResourcesIfDue()
            XCTAssertNil(store.errorMessage)
            XCTAssertNil(store.resourceUpdates.statuses[first.id]?.failure)
            XCTAssertNotEqual(store.managedResources.first?.hash, first.hash)
            let updatedRoute = try await store.client.call("ExplainRoute", params: ["destination": .string("x.second.test:443")])
            XCTAssertEqual(updatedRoute["outbound"].stringValue, "reject")
            let after = try XCTUnwrap(store.managedResources.first)
            var paused = ManagedResourceDraft(resource: after); paused.automatic = false
            let disabled = await store.saveResource(paused)
            XCTAssertTrue(disabled)
            let requestsBefore = try String(contentsOf: server.requests, encoding: .utf8)
            store.resourceUpdates.statuses[first.id]?.checkedAt = .distantPast
            await store.refreshResourcesIfDue()
            XCTAssertEqual(try String(contentsOf: server.requests, encoding: .utf8), requestsBefore)
            await store.stop(); await store.start()
            XCTAssertFalse(try XCTUnwrap(store.managedResources.first).automatic)
            XCTAssertNotNil(store.resourceUpdates.statuses[first.id]?.checkedAt)
        }
    }

    func testLocalResourceOver16MiBExportsBacksUpAndRestores() async throws {
        try await withStore { store, root in
            let file = root.appendingPathComponent("large-domains.txt")
            var data = Data(); let comment = Data(("#" + String(repeating: "x", count: 4094) + "\n").utf8)
            for _ in 0..<4353 { data.append(comment) }
            data.append(Data("+.large.test\n".utf8)); try data.write(to: file)
            XCTAssertGreaterThan(data.count, 16 * 1024 * 1024)
            var draft = ManagedResourceDraft(); draft.identifier = "large-resource"; draft.input = "file"; draft.localFile = file
            let saved = await store.saveResource(draft)
            XCTAssertTrue(saved, store.errorMessage ?? "Large import failed")
            await store.previewRule(definition: ["id": .string("large-rule"), "match": .object(["rule-set": .string(draft.identifier)]), "outbound": .string("reject")], record: nil, baseRevision: store.revision, save: true)
            XCTAssertNil(store.errorMessage)
            let backup = try await BackupService.export(client: store.client, name: "Large", sourceNames: [:])
            XCTAssertTrue(backup.resources.values.contains { $0.count == data.count })
            let validated = try BackupService.decode(BackupService.encode(backup))
            await store.createProfile(name: "Restore large resource")
            XCTAssertTrue(store.isOnline)
            try await BackupService.stage(validated, client: store.client)
            let restored = await store.previewVisualChange(try BackupService.restorationChange(validated, revision: store.revision), summary: "Restore large resource", save: true)
            XCTAssertTrue(restored, store.errorMessage ?? "Large restore failed")
            let route = try await store.client.call("ExplainRoute", params: ["destination": .string("x.large.test:443")])
            XCTAssertEqual(route["outbound"].stringValue, "reject")
        }
    }

    func testNativeDatabaseImportsASNGeoIPGeoSiteRulesAndReferencedDeletionProtection() async throws {
        try await withStore { store, _ in
            for (kind, name) in [("asn", "asn.mmdb"), ("geoip", "geoip.dat"), ("geosite", "geosite.dat")] {
                var draft = ManagedResourceDraft(database: kind); draft.input = "file"; draft.localFile = Self.fixture(name)
                let saved = await store.saveResource(draft)
                XCTAssertTrue(saved, store.errorMessage ?? "Database import failed")
            }
            let server = try ResourceHTTPFixture(root: store.homeURL)
            addTeardownBlock { await server.stop() }
            try Data(contentsOf: Self.fixture("asn.mmdb")).write(to: server.body)
            var remoteASN = ManagedResourceDraft(resource: try XCTUnwrap(store.managedResources.first { $0.identifier == "asn" }))
            remoteASN.input = "url"; remoteASN.url = server.url; remoteASN.automatic = true
            let configured = await store.saveResource(remoteASN)
            XCTAssertTrue(configured, store.errorMessage ?? "ASN URL configuration failed")
            let checked = store.resourceUpdates.statuses["geodata/asn"]?.checkedAt
            let requests = try String(contentsOf: server.requests, encoding: .utf8)
            try Data("invalid database".utf8).write(to: server.body)
            var disabled = ManagedResourceDraft(resource: try XCTUnwrap(store.managedResources.first { $0.identifier == "asn" }))
            disabled.automatic = false
            let paused = await store.saveResource(disabled)
            XCTAssertTrue(paused, store.errorMessage ?? "Turning off updates must work without a new download")
            XCTAssertEqual(store.resourceUpdates.statuses["geodata/asn"]?.checkedAt, checked)
            XCTAssertEqual(try String(contentsOf: server.requests, encoding: .utf8), requests)
            for (kind, value, destination) in [("geosite", "test", "suffix.test:443"), ("geoip", "CN", "192.0.2.42:443"), ("ip-asn", "AS13335", "192.0.2.42:443")] {
                var draft = RuleDraft(); draft.condition = kind; draft.valuesText = value; draft.outbound = "reject"
                let saved = await store.previewRule(definition: try draft.definition(), record: nil, baseRevision: store.revision, save: true)
                XCTAssertTrue(saved, store.errorMessage ?? "Geo rule save failed")
                let route = try await store.client.call("ExplainRoute", params: ["destination": .string(destination)])
                XCTAssertEqual(route["outbound"].stringValue, "reject")
            }
            let manifest = try await store.client.call("ExportManifest", params: ["reveal": .bool(true)])
            XCTAssertEqual(manifest["resources"].arrayValue?.count, 3)
            let asn = try XCTUnwrap(store.managedResources.first { $0.identifier == "asn" })
            let oldRevision = store.revision
            let deleted = await store.deleteManagedResource(asn, baseRevision: oldRevision)
            XCTAssertFalse(deleted)
            XCTAssertEqual(store.revision, oldRevision)
            XCTAssertTrue(store.managedResources.contains { $0.identifier == "asn" })
        }
    }

    func testDefaultCDNDatabaseDownloadsWhenExplicitlyEnabled() async throws {
        guard ProcessInfo.processInfo.environment["MIMO_REKA_LIVE_GEODATA"] == "1" else { throw XCTSkip("Opt-in real CDN acceptance.") }
        try await withStore { store, _ in
            for kind in ["geoip", "geosite", "asn"] {
                let saved = await store.saveResource(ManagedResourceDraft(database: kind))
                XCTAssertTrue(saved, store.errorMessage ?? "CDN download failed")
            }
            for (kind, value) in [("geoip", "CN"), ("geosite", "cn"), ("ip-asn", "13335")] {
                var draft = RuleDraft(); draft.condition = kind; draft.valuesText = value; draft.outbound = "reject"
                let saved = await store.previewRule(definition: try draft.definition(), record: nil, baseRevision: store.revision, save: true)
                XCTAssertTrue(saved, store.errorMessage ?? "Real database selector failed")
            }
        }
    }

    private static func fixture(_ name: String) -> URL { URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../../../testdata/rules/" + name).standardizedFileURL }
    private func withStore(_ work: (AppStore, URL) async throws -> Void) async throws {
        guard ProcessInfo.processInfo.environment["MIMO_REKA_KERNEL_BINARY"] != nil,
              ProcessInfo.processInfo.environment["MIMO_REKA_HOST_BINARY"] != nil else { throw XCTSkip("Set production kernel and supervisor paths.") }
        let root = URL(fileURLWithPath: "/tmp/mr-managed-" + String(UUID().uuidString.prefix(8)))
        let store = AppStore(home: root); await store.start()
        do {
            guard store.isOnline else { throw ClientError.message(store.errorMessage ?? "Startup failed") }
            try await work(store, root); await store.stop()
        } catch { await store.stop(); if store.kernel.isRunning { await store.kernel.stop() }; throw error }
        XCTAssertFalse(store.kernel.isRunning)
        if !store.kernel.isRunning { try? FileManager.default.removeItem(at: root) }
    }
}

private final class ResourceHTTPFixture: @unchecked Sendable {
    let body: URL
    let requests: URL
    let url: String
    private let process: Process
    init(root: URL) throws {
        body = root.appendingPathComponent("resource.txt"); requests = root.appendingPathComponent("resource-requests.txt")
        try Data().write(to: body); try Data().write(to: requests)
        process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = ["-u", "-c", """
        import hashlib, pathlib, sys
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        body, log = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                data = body.read_bytes()
                etag = '"' + hashlib.sha256(data).hexdigest() + '"'
                with log.open('a') as f: f.write(str(dict(self.headers)) + '\\n')
                if self.headers.get('If-None-Match') == etag:
                    self.send_response(304); self.send_header('ETag', etag); self.end_headers(); return
                self.send_response(200); self.send_header('ETag', etag)
                self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        print(server.server_port, flush=True); server.serve_forever()
        """, body.path, requests.path]
        let output = Pipe(); process.standardOutput = output; process.standardError = FileHandle.nullDevice
        try process.run()
        let line = String(decoding: output.fileHandleForReading.availableData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard let port = Int(line), port > 0 else { throw ClientError.message("Resource fixture did not start") }
        url = "http://127.0.0.1:\(port)/resource"
    }
    func stop() async {
        if process.isRunning { process.terminate() }
        for _ in 0..<50 where process.isRunning { try? await Task.sleep(for: .milliseconds(20)) }
        if process.isRunning { kill(process.processIdentifier, SIGKILL) }
    }
}
