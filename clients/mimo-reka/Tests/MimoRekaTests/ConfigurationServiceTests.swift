import Foundation
import Darwin
import XCTest
@testable import MimoReka

final class ConfigurationServiceTests: XCTestCase, @unchecked Sendable {
    func testYAMLDocumentRetainsTypedValuesAndNestedRules() throws {
        let object = try YAMLDocument.object("""
        schema-version: 1
        rules:
          - id: final
            match: {all: true}
            outbound: direct
        enabled: false
        names: [One, Two]
        """)
        XCTAssertEqual(object["schema-version"], .number(1))
        XCTAssertEqual(object["enabled"], .bool(false))
        XCTAssertEqual(object["rules"]?.arrayValue?.first?["match"]["all"], .bool(true))
        XCTAssertEqual(try YAMLDocument.object(YAMLDocument.stringify(object)), object)
    }

    func testMultipleSourcesPreserveSelectionsCommentsAndOverlay() async throws {
        let fixture = try await ConfigurationKernelFixture()
        addTeardownBlock { await fixture.stop() }
        let service = ConfigurationService(client: fixture.client, pendingURL: fixture.root.appendingPathComponent("client-pending.json"))
        let alpha = """
        proxies:
          - {name: Alpha, type: socks5, server: 127.0.0.1, port: 9}
          - {name: Alternate, type: socks5, server: 127.0.0.1, port: 10}
        """
        let first = try await service.previewImport(data: alpha, format: "clash", nodesOnly: true, sourceID: "alpha", name: "Alpha source")
        _ = try await service.commit(first)
        let initial = try await fixture.client.call("GetConfiguration")
        let proxy = try XCTUnwrap(initial["effective"]["groups"].arrayValue?.first { $0["ID"].stringValue == "proxy" })
        let selected = try XCTUnwrap(proxy["Selected"].stringValue)
        XCTAssertTrue(selected.hasPrefix("alpha/"))
        let profileWithComment = try XCTUnwrap(initial["profile"].stringValue)
        XCTAssertTrue(profileWithComment.contains("Keep this user comment"))

        let nodeID = try XCTUnwrap(initial["effective"]["outbounds"].arrayValue?.first { $0["name"].stringValue == "Alpha" }?["id"].stringValue)
        let path = "/outbounds/\(ConfigurationService.escape(nodeID))/name"
        let edit = try await service.prepare(["overlay_patch": .array([.object([
            "op": .string("insert"), "path": .string("/patches"),
            "value": .object(["op": .string("set"), "path": .string(path), "value": .string("My Alpha")])
        ])])], summary: "Rename display label")
        _ = try await service.commit(edit)
        let withOverlay = try await fixture.client.call("GetConfiguration")

        let beta = """
        proxies:
          - {name: Beta, type: socks5, server: 127.0.0.1, port: 11}
          - {name: Backup, type: socks5, server: 127.0.0.1, port: 12}
        proxy-groups:
          - {name: Choice, type: select, proxies: [Beta, Backup]}
        rules:
          - MATCH,Choice
        """
        let second = try await service.previewImport(data: beta, format: "clash", nodesOnly: false, sourceID: "beta", name: "Beta source")
        _ = try await service.commit(second)
        let config = try await fixture.client.call("GetConfiguration")
        XCTAssertEqual(config["overlay"], withOverlay["overlay"])
        XCTAssertEqual(config["local"], withOverlay["local"])
        let sources = try YAMLDocument.array(config["sources"].stringValue ?? "", key: "sources")
        XCTAssertEqual(Set(sources.compactMap { $0["id"].stringValue }), Set(["alpha", "beta"]))
        let profile = try YAMLDocument.object(config["profile"].stringValue ?? "")
        let afterProxy = try XCTUnwrap(profile["groups"]?.arrayValue?.first { $0["id"].stringValue == "proxy" })
        XCTAssertEqual(afterProxy["selected"].stringValue, selected)
        XCTAssertTrue((config["profile"].stringValue ?? "").contains("Keep this user comment"))
        XCTAssertTrue(config["effective"]["outbounds"].arrayValue?.contains { $0["name"].stringValue == "My Alpha" } == true)

        let group = try XCTUnwrap(config["effective"]["groups"].arrayValue?.first { ($0["ID"].stringValue ?? "").hasPrefix("beta/") })
        let groupID = try XCTUnwrap(group["ID"].stringValue)
        let members = try XCTUnwrap(group["Members"].arrayValue?.compactMap(\.stringValue))
        try await service.select(groupID: groupID, member: members.last!)
        try await service.select(groupID: groupID, member: members.first!)
        let afterSelect = try await fixture.client.call("GetConfiguration")
        let overlay = try YAMLDocument.object(afterSelect["overlay"].stringValue ?? "")
        let selectionPath = "/groups/\(ConfigurationService.escape(groupID))/selected"
        XCTAssertEqual(overlay["patches"]?.arrayValue?.filter { $0["path"].stringValue == selectionPath }.count, 1)

        let revision = afterSelect["revision"]
        do {
            _ = try await service.previewImport(data: "proxies: [{name: Renamed, type: socks5, server: 127.0.0.1, port: 9}]",
                                                format: "clash", nodesOnly: true, sourceID: "alpha", name: "Replacement")
            XCTFail("Removing referenced nodes must reject the candidate.")
        } catch { }
        let retained = try await fixture.client.call("GetConfiguration")
        XCTAssertEqual(retained["revision"], revision)
    }

    func testStalePlanAndDurableUncertainCommitRecovery() async throws {
        let fixture = try await ConfigurationKernelFixture()
        addTeardownBlock { await fixture.stop() }
        let pending = fixture.root.appendingPathComponent("pending.json")
        let service = ConfigurationService(client: fixture.client, pendingURL: pending)
        let stale = try await service.prepare(["local_patch": .array([.object([
            "op": .string("set"), "path": .string("/log"), "value": .object(["level": .string("debug")])
        ])])], summary: "Stale log draft")
        let other = try await service.prepare(["local_patch": .array([.object([
            "op": .string("set"), "path": .string("/log"), "value": .object(["level": .string("warn")])
        ])])], summary: "Concurrent log edit")
        _ = try await service.commit(other)
        do { _ = try await service.commit(stale); XCTFail("Expected a stale-revision conflict") }
        catch { XCTAssertTrue(error.localizedDescription.contains("版本")) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: pending.path))

        let prepared = try await service.prepare(["local_patch": .array([.object([
            "op": .string("set"), "path": .string("/log"), "value": .object(["level": .string("info")])
        ])])], summary: "Recovered operation")
        var request = prepared.change
        request["plan_hash"] = .string(prepared.planHash)
        request["operation_id"] = .string(prepared.id.uuidString)
        request["source"] = .string("mimo-reka")
        request["message"] = .string(prepared.summary)
        let result = try await fixture.client.call("CommitConfiguration", params: request)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        try encoder.encode(request).write(to: pending)
        let recovered = ConfigurationService(client: fixture.client, pendingURL: pending)
        try await recovered.recoverPending()
        let config = try await fixture.client.call("GetConfiguration")
        XCTAssertEqual(config["revision"], result["revision"])
        XCTAssertFalse(FileManager.default.fileExists(atPath: pending.path))
    }

    func testCoreSubscriptionRefreshActivatesSourceAndRetainsLastGoodSnapshot() async throws {
        let fixture = try await ConfigurationKernelFixture()
        addTeardownBlock { await fixture.stop() }
        let http = try SubscriptionHTTPFixture(root: fixture.root)
        addTeardownBlock { await http.stop() }
        let service = ConfigurationService(client: fixture.client)
        _ = try await service.configureSubscription(sourceID: "subscription", url: http.url, interval: 3600, nodesOnly: true)
        let status = try await service.refreshSubscription(sourceID: "subscription")
        XCTAssertEqual(status["state"].stringValue, "current")
        let activation = try await service.prepareSourceActivation(sourceID: "subscription", nodesOnly: true)
        _ = try await service.commit(activation)
        let current = try await fixture.client.call("GetConfiguration")
        XCTAssertEqual(current["effective"]["source_hashes"].objectValue?.count, 1)
        XCTAssertTrue(current["effective"]["outbounds"].arrayValue?.contains { $0["name"].stringValue == "Downloaded" } == true)

        try "proxies: [{name: Broken, type: definitely-unsupported}]".write(to: http.document, atomically: true, encoding: .utf8)
        do { _ = try await service.refreshSubscription(sourceID: "subscription"); XCTFail("Expected subscription conversion refusal") }
        catch { XCTAssertFalse(error.localizedDescription.contains(http.url)) }
        let afterFailure = try await fixture.client.call("GetConfiguration")
        XCTAssertEqual(afterFailure["revision"], current["revision"])
        XCTAssertEqual(afterFailure["sources"], current["sources"])
    }
}

private final class ConfigurationKernelFixture {
    let root: URL
    let process: Process
    let client: RekaControlClient

    init() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let binary = environment["MIMO_REKA_KERNEL_BINARY"] ?? environment["REKA_MAC_KERNEL_BINARY"],
              FileManager.default.isExecutableFile(atPath: binary) else {
            throw XCTSkip("Set MIMO_REKA_KERNEL_BINARY to an executable Reka 1.0 core.")
        }
        root = URL(fileURLWithPath: "/tmp/mr-cfg-" + String(UUID().uuidString.prefix(8)), isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let profile = root.appendingPathComponent("initial-profile.yaml")
        let local = root.appendingPathComponent("initial-local.yaml")
        try """
        schema-version: 1
        # Keep this user comment while adding unrelated sources.
        groups:
          - {id: proxy, type: select, members: [direct], selected: direct}
        rules:
          - {id: final, match: {all: true}, outbound: proxy}
        """.write(to: profile, atomically: true, encoding: .utf8)
        try "network: {mode: off}\n".write(to: local, atomically: true, encoding: .utf8)
        process = Process()
        process.executableURL = URL(fileURLWithPath: binary)
        process.arguments = ["-state-root", root.path, "-profile", profile.path, "-local", local.path, "-edit-dir", "-"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        client = RekaControlClient(socketPath: root.appendingPathComponent("control.sock").path, timeout: 2)
        try process.run()
        for _ in 0..<60 {
            if !process.isRunning { break }
            if (try? await client.call("GetStatus")) != nil { return }
            try await Task.sleep(for: .milliseconds(50))
        }
        await stop()
        throw ConfigurationError.message("Isolated Reka kernel did not start.")
    }

    func stop() async {
        await stopFixtureProcess(process)
        if !process.isRunning { try? FileManager.default.removeItem(at: root) }
    }
}

final class SubscriptionHTTPFixture {
    let document: URL
    let url: String
    private let process: Process

    init(root: URL) throws {
        document = root.appendingPathComponent("subscription.yaml")
        try "proxies: [{name: Downloaded, type: socks5, server: 127.0.0.1, port: 9}]\n".write(to: document, atomically: true, encoding: .utf8)
        process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = ["-u", "-c", """
        import pathlib, sys
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        document = pathlib.Path(sys.argv[1])
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = document.read_bytes()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        print(server.server_port, flush=True)
        server.serve_forever()
        """, document.path]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        let line = String(decoding: output.fileHandleForReading.availableData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard let port = Int(line), port > 0 else {
            if process.isRunning { process.terminate(); process.waitUntilExit() }
            throw ConfigurationError.message("Local subscription HTTP fixture did not start.")
        }
        url = "http://127.0.0.1:\(port)/subscription"
    }

    func stop() async { await stopFixtureProcess(process) }
}

private func stopFixtureProcess(_ process: Process) async {
    if process.isRunning { process.terminate() }
    for _ in 0..<100 {
        if !process.isRunning { return }
        try? await Task.sleep(for: .milliseconds(50))
    }
    if process.isRunning { kill(process.processIdentifier, SIGKILL) }
    for _ in 0..<40 {
        if !process.isRunning { return }
        try? await Task.sleep(for: .milliseconds(50))
    }
    XCTAssertFalse(process.isRunning, "The isolated fixture must exit during teardown.")
}
