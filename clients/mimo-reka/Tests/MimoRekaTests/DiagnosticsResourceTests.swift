import Foundation
import XCTest
@testable import MimoReka

final class DiagnosticsDraftTests: XCTestCase {
    func testRouteDraftPreservesExplicitZeroUIDAndRejectsOverflow() throws {
        var draft = RouteDiagnosticDraft()
        draft.uid = "0"; draft.inboundPort = "17891"; draft.inboundUser = "Alice"; draft.inboundType = "SOCKS5"
        XCTAssertEqual(try draft.parameters()["process_uid"], .number(0))
        XCTAssertEqual(try draft.parameters()["inbound_port"], .number(17891))
        XCTAssertEqual(try draft.parameters()["inbound_type"], .string("SOCKS5"))
        draft.uid = "4294967296"
        XCTAssertThrowsError(try draft.parameters())
        draft.uid = ""; draft.inboundPort = "65536"
        XCTAssertThrowsError(try draft.parameters())
    }

    func testResourceMappingUsesExactProviderScopeAndRejectsDuplicates() throws {
        let data = Data("example.test\n".utf8)
        let rule = ResourceAttachment(kind: "rule-providers", name: "shared", filename: "domains.txt", data: data)
        let proxy = ResourceAttachment(kind: "proxy-providers", name: "shared", filename: "nodes.yaml", data: data)
        let geo = ResourceAttachment(kind: "geosite", filename: "geosite.dat", data: data)
        let maps = try ResourceAttachment.mappings([rule, proxy, geo])
        XCTAssertEqual(Set(maps.providers.keys), Set(["rule-providers/shared", "proxy-providers/shared"]))
        XCTAssertEqual(maps.geodata["geosite"], geo.hash)
        XCTAssertEqual(rule.hash.count, 64)
        XCTAssertThrowsError(try ResourceAttachment.mappings([rule, rule]))
    }

    func testAdvancedRulesRetainScalarValuesAndCanChangeTargets() throws {
        for kind in ["process-path", "process-path-regex", "process-path-wildcard", "process-name-wildcard", "uid", "in-name", "in-type", "in-port", "in-user"] {
            var draft = RuleDraft()
            draft.condition = kind; draft.valuesText = RuleDraft.example(kind); draft.outbound = "reject"
            let value = try draft.definition()
            XCTAssertNotNil(value["match"]?[kind])
            XCTAssertEqual(value["outbound"], .string("reject"))
        }
    }
}

@MainActor
final class DiagnosticsResourceIntegrationTests: XCTestCase {
    func testStagedProviderGeodataImportAndEffectiveRouteExplanations() async throws {
        try await withStore { store in
            let methods = store.capabilities["methods"].arrayValue ?? []
            guard methods.contains(.string("StageResource")) else { throw XCTSkip("Core with native operations is required.") }
            let chunked = Data(repeating: 7, count: 2 * 1024 * 1024 + 17)
            let staged = try await ResourceImportService.stage(data: chunked, client: store.client)
            XCTAssertEqual(staged.count, 64)
            let provider = ResourceAttachment(name: "domains", filename: "domains.txt", data: Data("provider.example.test\n".utf8))
            let providerHash = try await ResourceImportService.stage(data: provider.data, client: store.client)
            await store.previewImport(data: """
            proxies: [{name: local, type: socks5, server: 127.0.0.1, port: 9}]
            rule-providers: {domains: {type: file, path: never-read.txt, behavior: domain, format: text}}
            rules: ["RULE-SET,domains,REJECT"]
            """, format: "clash", nodesOnly: false, sourceName: "Provider", providerResources: ["rule-providers/domains": providerHash])
            XCTAssertNil(store.errorMessage)
            XCTAssertNotNil(store.preparedChange)
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            let explanation = try await store.client.call("ExplainRoute", params: ["destination": .string("provider.example.test:443")])
            XCTAssertEqual(explanation["outbound"], .string("reject"))
            let firstPage = try await store.client.call("GetRules", params: ["offset": .number(0), "limit": .number(1)])
            XCTAssertEqual(firstPage["rules"].arrayValue?.count, 1)
            XCTAssertGreaterThan(firstPage["total"].intValue ?? 0, 1)
            let secondPage = try await store.client.call("GetRules", params: ["offset": .number(1), "limit": .number(1)])
            XCTAssertEqual(secondPage["rules"].arrayValue?.first?["index"], .number(1))
            let geoURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../../../testdata/rules/geosite.dat").standardizedFileURL
            let geo = try Data(contentsOf: geoURL)
            let geoHash = try await ResourceImportService.stage(data: geo, client: store.client)
            await store.previewImport(data: """
            proxies: [{name: geo-local, type: socks5, server: 127.0.0.1, port: 10}]
            rules: ["GEOSITE,test,REJECT"]
            """, format: "clash", nodesOnly: false, sourceName: "Geodata", geodataResources: ["geosite": geoHash])
            XCTAssertNil(store.errorMessage)
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            let geoExplanation = try await store.client.call("ExplainRoute", params: ["destination": .string("suffix.test:443")])
            XCTAssertEqual(geoExplanation["outbound"], .string("reject"))
        }
    }

    func testDNSDiagnosticsUseStaticHostsAndMaintenancePreservesConfiguration() async throws {
        try await withStore { store in
            guard (store.capabilities["methods"].arrayValue ?? []).contains(.string("QueryDNS")) else { throw XCTSkip("New native operations are required.") }
            let prepared = try await store.configurationService.prepare(["patch": .array([.object([
                "op": .string("set"), "path": .string("/dns"), "value": .object([
                    "nameserver": .array([.string("127.0.0.1:9")]), "default-nameserver": .array([.string("127.0.0.1:9")]),
                    "use-hosts": .bool(true), "hosts": .array([.object(["id": .string("diagnostic.test"), "addresses": .array([.string("192.0.2.8")])])])
                ])
            ])])], summary: "Isolated DNS diagnostics")
            _ = try await store.configurationService.commit(prepared)
            let revision = try await store.client.call("GetConfiguration")["revision"]
            let query = try await store.client.call("QueryDNS", params: ["name": .string("diagnostic.test"), "type": .string("A"), "scope": .string("normal"), "fake": .bool(false)])
            XCTAssertEqual(query["rcode"], .number(0))
            XCTAssertTrue((query["answer"].arrayValue ?? []).contains { $0.stringValue?.contains("192.0.2.8") == true })
            _ = try await store.client.call("FlushDNSCache")
            _ = try await store.client.call("ResetNetwork")
            let after = try await store.client.call("GetConfiguration")
            XCTAssertEqual(after["revision"], revision)
            let status = try await store.client.call("GetStatus")
            XCTAssertEqual(status["runtime"]["network"]["mode"], .string("off"))
        }
    }

    private func withStore(_ work: (AppStore) async throws -> Void) async throws {
        guard ProcessInfo.processInfo.environment["MIMO_REKA_KERNEL_BINARY"] != nil,
              ProcessInfo.processInfo.environment["MIMO_REKA_HOST_BINARY"] != nil else { throw XCTSkip("Set isolated kernel and host paths.") }
        let root = URL(fileURLWithPath: "/tmp/mr-diag-" + String(UUID().uuidString.prefix(8)))
        let store = AppStore(home: root)
        defer { if !store.kernel.isRunning { try? FileManager.default.removeItem(at: root) } }
        await store.start()
        do {
            guard store.isOnline else { throw ClientError.message(store.errorMessage ?? "Isolated kernel failed") }
            try await work(store)
            await store.stop()
            XCTAssertFalse(store.kernel.isRunning)
        } catch {
            await store.stop()
            if store.kernel.isRunning { await store.kernel.stop() }
            throw error
        }
    }
}
