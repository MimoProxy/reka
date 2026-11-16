import Foundation
import XCTest
@testable import MimoReka

@MainActor
final class SourceDeletionIntegrationTests: XCTestCase {
    func testFailedEmptySubscriptionCanBeDeletedAndStaysDeletedAfterRestart() async throws {
        try await withStore { store, root in
            XCTAssertTrue(store.sources.isEmpty, "A fresh profile must not create a default source.")
            let server = try SubscriptionHTTPFixture(root: root)
            addTeardownBlock { await server.stop() }
            try "proxies: [{name: Broken, type: unsupported-protocol, server: 127.0.0.1, port: 9}]".write(to: server.document, atomically: true, encoding: .utf8)
            await store.addSubscription(name: "Failed source", url: server.url, interval: 3600, nodesOnly: true)
            XCTAssertNotNil(store.errorMessage)
            let source = try XCTUnwrap(store.sources.first)
            XCTAssertEqual(source.nodeCount, 0)
            XCTAssertNil(source.lastSuccess)
            let deleted = await store.deleteSource(source, baseRevision: store.revision)
            XCTAssertTrue(deleted, store.errorMessage ?? "Delete failed")
            XCTAssertTrue(store.sources.isEmpty)
            XCTAssertNil(store.catalog.sourceNames[store.activeProfileID.uuidString]?[source.id])
            let statuses = try await store.client.call("ListSubscriptions")
            XCTAssertTrue((statuses.arrayValue ?? statuses["subscriptions"].arrayValue ?? []).isEmpty)
            await store.stop(); await store.start()
            XCTAssertTrue(store.isOnline)
            XCTAssertTrue(store.sources.isEmpty)
            XCTAssertEqual(store.networkMode, "off")
        }
    }

    func testDeletingActiveSourceCleansMarkersSelectionsAndOverlaysAndPreservesOtherSource() async throws {
        try await withStore { store, _ in
            await store.previewImport(data: """
            proxies: [{name: Alpha, type: socks5, server: 127.0.0.1, port: 9}]
            proxy-groups: [{name: AlphaGroup, type: select, proxies: [Alpha]}]
            rules: ["DOMAIN-SUFFIX,alpha.test,AlphaGroup"]
            """, format: "clash", nodesOnly: false, sourceName: "Alpha", save: true)
            XCTAssertNil(store.errorMessage)
            let alpha = try XCTUnwrap(store.sources.first)
            let alphaNode = try XCTUnwrap(store.outbounds.first { $0.sourceID == alpha.id })
            await store.previewImport(data: """
            proxies: [{name: Beta, type: socks5, server: 127.0.0.1, port: 10, username: isolated-test-user, password: isolated-test-password}]
            """, format: "clash", nodesOnly: true, sourceName: "Beta", save: true)
            XCTAssertNil(store.errorMessage)
            let beta = try XCTUnwrap(store.sources.first { $0.id != alpha.id })
            let betaNode = try XCTUnwrap(store.outbounds.first { $0.sourceID == beta.id })
            for node in [alphaNode, betaNode] {
                var definition = try VisualConfigurationService.resource(kind: "outbounds", id: node.id, documents: store.documents, effective: store.effectiveConfiguration).definition
                definition["name"] = .string(node.name + " renamed")
                await store.previewResource(kind: "outbounds", id: node.id, definition: definition, baseRevision: store.revision, save: true)
                XCTAssertNil(store.errorMessage)
            }
            for (id, members) in [("mixed", [alphaNode.id, betaNode.id, "direct"]), ("only-alpha", [alphaNode.id])] {
                let definition: [String: JSONValue] = ["id": .string(id), "name": .string(id), "type": .string("select"), "members": .array(members.map(JSONValue.string)), "selected": .string(alphaNode.id)]
                let change = try VisualConfigurationService.groupChange(resource: nil, value: definition, baseRevision: store.revision, documents: store.documents)
                await store.previewVisualChange(change, summary: "Test membership", save: true)
                XCTAssertNil(store.errorMessage)
            }
            let edits: [JSONValue] = [
                .object(["op": .string("set"), "path": .string("/groups/mixed/members"), "value": .array([.string(alphaNode.id), .string(betaNode.id)])]),
                .object(["op": .string("set"), "path": .string("/groups/mixed/members/#0"), "value": .string(alphaNode.id)]),
                .object(["op": .string("set"), "path": .string("/groups/mixed/selected"), "value": .string(alphaNode.id)])
            ]
            let overlay = try await store.configurationService.prepare(["overlay_patch": .array(edits.map { .object(["op": .string("insert"), "path": .string("/patches"), "value": $0]) })], summary: "Advanced membership overlays")
            _ = try await store.configurationService.commit(overlay)
            await store.refresh()
            let before = try await store.client.call("GetConfiguration", params: ["reveal": .bool(true)])
            let betaBefore = try YAMLDocument.array(before["sources"].stringValue ?? "", key: "sources").first { $0["id"].stringValue == beta.id }
            let deleted = await store.deleteSource(alpha, baseRevision: store.revision)
            XCTAssertTrue(deleted, store.errorMessage ?? "Delete failed")
            XCTAssertEqual(store.sources.map(\.id), [beta.id])
            XCTAssertEqual(store.sources.first?.name, "Beta")
            XCTAssertFalse(store.outbounds.contains { $0.sourceID == alpha.id })
            XCTAssertFalse(store.groups.contains { $0.id.hasPrefix(alpha.id + "/") || $0.members.contains { $0.hasPrefix(alpha.id + "/") } })
            XCTAssertEqual(store.groups.first { $0.id == "mixed" }?.members, [betaNode.id])
            XCTAssertEqual(store.groups.first { $0.id == "mixed" }?.selected, betaNode.id)
            XCTAssertEqual(store.groups.first { $0.id == "only-alpha" }?.members, ["direct"])
            XCTAssertEqual(store.groups.first { $0.id == "only-alpha" }?.selected, "direct")
            XCTAssertFalse(store.ruleRecords.contains { $0.sourceID == alpha.id || $0.definition["source"]?.stringValue == alpha.id })
            XCTAssertFalse((store.documents[.overlay] ?? "").contains(alpha.id))
            XCTAssertTrue((store.documents[.overlay] ?? "").contains(beta.id))
            let after = try await store.client.call("GetConfiguration", params: ["reveal": .bool(true)])
            let betaAfter = try YAMLDocument.array(after["sources"].stringValue ?? "", key: "sources").first { $0["id"].stringValue == beta.id }
            XCTAssertEqual(betaAfter, betaBefore, "The remaining source and its credentials must be unchanged.")
            XCTAssertEqual(store.networkMode, "off")
        }
    }

    func testCustomRuleAndDNSReferencesBlockDeletionAndStaleConfirmationCannotOverwrite() async throws {
        try await withStore { store, _ in
            await store.previewImport(data: """
            proxies: [{name: Alpha, type: socks5, server: 127.0.0.1, port: 9}]
            dns: {enable: true, nameserver: [1.1.1.1]}
            """, format: "clash", nodesOnly: true, sourceName: "Referenced", save: true)
            XCTAssertNil(store.errorMessage)
            let source = try XCTUnwrap(store.sources.first)
            let node = try XCTUnwrap(store.outbounds.first { $0.sourceID == source.id })
            await store.previewRule(definition: ["id": .string("custom-reference"), "match": .object(["domain-suffix": .array([.string("custom.test")])]), "outbound": .string(node.id)], record: nil, baseRevision: store.revision, save: true)
            XCTAssertNil(store.errorMessage)
            let oldRevision = store.revision
            let blocked = await store.deleteSource(source, baseRevision: oldRevision)
            XCTAssertFalse(blocked)
            XCTAssertNotNil(store.errorMessage)
            XCTAssertEqual(store.revision, oldRevision)
            XCTAssertEqual(store.sources.first?.name, "Referenced")
            XCTAssertTrue(store.outbounds.contains { $0.id == node.id })
            let rule = try XCTUnwrap(store.ruleRecords.first { $0.definition["id"]?.stringValue == "custom-reference" })
            await store.removeRule(rule, baseRevision: store.revision, save: true)
            XCTAssertNil(store.errorMessage)
            await store.previewVisualChange(["patch": .array([.object(["op": .string("set"), "path": .string("/dns"), "value": .object(["from": .string(source.id)])])])], summary: "Use source DNS", save: true)
            XCTAssertNil(store.errorMessage)
            let dnsRevision = store.revision
            let dnsBlocked = await store.deleteSource(source, baseRevision: dnsRevision)
            XCTAssertFalse(dnsBlocked)
            XCTAssertEqual(store.revision, dnsRevision)
            XCTAssertNotNil(store.errorMessage)
            await store.previewVisualChange(["patch": .array([.object(["op": .string("remove"), "path": .string("/dns")])])], summary: "Stop using source DNS", save: true)
            XCTAssertNil(store.errorMessage)
            let currentRevision = store.revision
            let stale = await store.deleteSource(source, baseRevision: oldRevision)
            XCTAssertFalse(stale)
            XCTAssertTrue(store.errorMessage?.contains("配置版本已变化") == true)
            XCTAssertEqual(store.revision, currentRevision)
            XCTAssertEqual(store.sources.count, 1)
            let deleted = await store.deleteSource(source, baseRevision: store.revision)
            XCTAssertTrue(deleted, store.errorMessage ?? "Delete failed")
            XCTAssertTrue(store.sources.isEmpty)
        }
    }

    private func withStore(_ work: (AppStore, URL) async throws -> Void) async throws {
        guard ProcessInfo.processInfo.environment["MIMO_REKA_KERNEL_BINARY"] != nil,
              ProcessInfo.processInfo.environment["MIMO_REKA_HOST_BINARY"] != nil else { throw XCTSkip("Set production core and supervisor paths.") }
        let root = URL(fileURLWithPath: "/tmp/mr-source-delete-" + String(UUID().uuidString.prefix(8)))
        let store = AppStore(home: root)
        await store.start()
        do {
            guard store.isOnline else { throw ClientError.message(store.errorMessage ?? "Isolated startup failed") }
            try await work(store, root)
            await store.stop()
        } catch {
            await store.stop()
            if store.kernel.isRunning { await store.kernel.stop() }
            throw error
        }
        XCTAssertFalse(store.kernel.isRunning)
        if !store.kernel.isRunning { try? FileManager.default.removeItem(at: root) }
    }
}
