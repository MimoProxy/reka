import Foundation
import XCTest
@testable import MimoReka

@MainActor
final class ExpandedConfigurationIntegrationTests: XCTestCase {
    func testVisualExpandedConfigurationCommitsAgainstCurrentKernel() async throws {
        guard ProcessInfo.processInfo.environment["MIMO_REKA_KERNEL_BINARY"] != nil,
              ProcessInfo.processInfo.environment["MIMO_REKA_HOST_BINARY"] != nil else { throw XCTSkip("Set core and host paths") }
        let root = URL(fileURLWithPath: "/tmp/mr-forms-" + String(UUID().uuidString.prefix(8)))
        let kernel = KernelProcess(stateRoot: root)
        do {
            try await kernel.start()
            let client = RekaControlClient(socketPath: kernel.socketPath)
            let config = try await client.call("GetConfiguration")
            let documents = Dictionary(uniqueKeysWithValues: ConfigurationLayer.allCases.map { ($0, config[$0.rawValue].stringValue ?? "") })
            var draft = try VisualConfigurationDraft(documents: documents, sourceNames: [:])
            draft.sniff = ["enabled": .bool(true), "protocols": .array([.string("http"), .string("tls"), .string("quic")]), "timeout-ms": .number(300), "max-bytes": .number(65536), "max-packets": .number(8), "override-destination": .bool(false)]
            draft.dnsEnabled = true
            draft.dns = ["nameserver": .array([.string("127.0.0.1:9")]), "default-nameserver": .array([.string("127.0.0.1:9")]), "max-concurrent-upstreams": .number(3), "cache-stale-ttl": .number(120)]
            XCTAssertFalse(draft.listeners.isEmpty)
            draft.listeners[0].fields["users"] = .array([.object(["username": .string("Alice"), "password": .string("local-form-test")])])
            let node: [String: JSONValue] = [
                "id": .string("visual-xhttp"), "type": .string("vless"), "server": .string("127.0.0.1"), "port": .number(9), "uuid": .string("b831381d-6324-4d53-ad4f-8cda48b30811"),
                "tls": .object(["server-name": .string("upload.example"), "alpn": .array([.string("h2")])]),
                "transport": .object(["type": .string("xhttp"), "host": .string("upload.example"), "path": .string("/split"), "headers": .array([.object(["name": .string("X-Upload-Key"), "value": .string("upload-test")])]),
                    "xhttp": .object(["mode": .string("packet-up"), "x-padding-bytes": .string("100-200"), "xmux": .object(["max-connections": .string("2")]), "download-settings": .object([
                        "server": .string("127.0.0.1"), "port": .number(9), "host": .string("download.example"), "path": .string("/download"),
                        "tls": .object(["server-name": .string("download.example"), "alpn": .array([.string("h2")])]),
                        "headers": .array([.object(["name": .string("X-Download-Key"), "value": .string("download-test")])]), "xmux": .object(["max-concurrency": .string("2-4"), "h-keep-alive-period": .string("10")])
                    ])])])
            ]
            var change = draft.change(baseRevision: config["revision"].intValue ?? 0)
            var patches = change["patch"]?.arrayValue ?? []
            patches.append(.object(["op": .string("insert"), "path": .string("/outbounds"), "value": .object(node)]))
            change["patch"] = .array(patches)
            let service = ConfigurationService(client: client)
            let prepared = try await service.prepare(change, summary: "原生表单新增配置验收")
            _ = try await service.commit(prepared)
            let after = try await client.call("GetConfiguration", params: ["reveal": .bool(true)])
            let profile = try YAMLDocument.object(after["profile"].stringValue ?? "")
            let local = try YAMLDocument.object(after["local"].stringValue ?? "")
            XCTAssertEqual(profile["sniff"]?["protocols"].arrayValue?.count, 3)
            XCTAssertEqual(profile["dns"]?["max-concurrent-upstreams"], .number(3))
            XCTAssertEqual(profile["dns"]?["cache-stale-ttl"], .number(120))
            XCTAssertEqual(local["listeners"]?.arrayValue?.first?["users"].arrayValue?.first?["password"], .string("local-form-test"))
            let saved = try XCTUnwrap(profile["outbounds"]?.arrayValue?.first { $0["id"].stringValue == "visual-xhttp" })
            XCTAssertEqual(saved["transport"]["xhttp"]["mode"], .string("packet-up"))
            XCTAssertEqual(saved["transport"]["xhttp"]["download-settings"]["tls"]["server-name"], .string("download.example"))
            XCTAssertEqual(saved["transport"]["xhttp"]["download-settings"]["xmux"]["max-concurrency"], .string("2-4"))
            XCTAssertEqual(after["effective"]["network"]["mode"], .string("off"))
            await kernel.stop()
            XCTAssertFalse(kernel.isRunning)
        } catch { await kernel.stop(); throw error }
        if !kernel.isRunning { try? FileManager.default.removeItem(at: root) }
    }
}
