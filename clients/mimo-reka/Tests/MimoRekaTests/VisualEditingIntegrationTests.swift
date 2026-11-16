import Foundation
import XCTest
@testable import MimoReka

@MainActor
final class VisualEditingIntegrationTests: XCTestCase {
    func testVisualPolicyNodeAndRuleCRUDOrderAndReferenceProtection() async throws {
        try await withStore { store in
            let group: [String: JSONValue] = ["id": .string("custom"), "name": .string("可视化策略"), "type": .string("select"), "members": .array([.string("direct"), .string("reject")]), "selected": .string("direct")]
            let added = try VisualConfigurationService.groupChange(resource: nil, value: group, baseRevision: store.revision, documents: store.documents)
            await store.previewVisualChange(added, summary: "新增策略")
            XCTAssertNil(store.errorMessage)
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            XCTAssertEqual(store.groups.first { $0.id == "custom" }?.name, "可视化策略")
            let childOverride = try await store.configurationService.prepare(["overlay_patch": .array([.object([
                "op": .string("insert"), "path": .string("/patches"), "value": .object([
                    "op": .string("set"), "path": .string("/groups/custom/members/#0"), "value": .string("direct")
                ])
            ])])], summary: "已有子字段覆盖")
            _ = try await store.configurationService.commit(childOverride)
            await store.refresh()
            let resource = try VisualConfigurationService.group(id: "custom", documents: store.documents, effective: store.effectiveConfiguration)
            var edited = resource.definition
            edited["name"] = .string("改名后的策略")
            edited["members"] = .array([.string("reject"), .string("direct")])
            let change = try VisualConfigurationService.groupChange(resource: resource, value: edited, baseRevision: store.revision, documents: store.documents)
            await store.previewVisualChange(change, summary: "修改策略")
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            XCTAssertEqual(store.groups.first { $0.id == "custom" }?.members, ["reject", "direct"])
            let move = try VisualConfigurationService.moveGroupChange(resource: resource, direction: -1, baseRevision: store.revision, documents: store.documents)
            await store.previewVisualChange(move, summary: "调整策略顺序")
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            XCTAssertEqual(try YAMLDocument.array(store.documents[.profile] ?? "", key: "groups").first?["id"].stringValue, "custom")

            let node: [String: JSONValue] = ["id": .string("local-socks"), "name": .string("本地 SOCKS"), "type": .string("socks"), "server": .string("127.0.0.1"), "port": .number(9), "udp": .bool(true)]
            await store.previewResource(kind: "outbounds", id: nil, definition: node, baseRevision: store.revision)
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            XCTAssertTrue(store.outbounds.contains { $0.id == "local-socks" })
            let rule: [String: JSONValue] = ["id": .string("visual-rule"), "match": .object(["domain-suffix": .array([.string("example.test"), .string("example.org")])]), "outbound": .string("custom")]
            await store.previewRule(definition: rule, record: nil, baseRevision: store.revision)
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            let savedRule = try XCTUnwrap(store.ruleRecords.first { $0.definition["id"]?.stringValue == "visual-rule" })
            XCTAssertEqual(savedRule.definition["outbound"], .string("custom"))
            XCTAssertTrue(savedRule.movable)
            await store.moveRule(savedRule, direction: -1, baseRevision: store.revision)
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            XCTAssertEqual(try YAMLDocument.array(store.documents[.profile] ?? "", key: "rules")[1]["id"].stringValue, "visual-rule")

            let referenced = try VisualConfigurationService.group(id: "custom", documents: store.documents, effective: store.effectiveConfiguration)
            let revision = store.revision
            let blocked = try VisualConfigurationService.removeGroupChange(resource: referenced, baseRevision: revision, documents: store.documents)
            await store.previewVisualChange(blocked, summary: "删除被引用策略")
            XCTAssertNotNil(store.errorMessage)
            XCTAssertNil(store.preparedChange)
            XCTAssertEqual(store.revision, revision)
            let currentRule = try XCTUnwrap(store.ruleRecords.first { $0.definition["id"]?.stringValue == "visual-rule" })
            await store.removeRule(currentRule, baseRevision: store.revision)
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            let deletion = try VisualConfigurationService.removeGroupChange(resource: referenced, baseRevision: store.revision, documents: store.documents)
            await store.previewVisualChange(deletion, summary: "删除策略")
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            XCTAssertFalse(store.groups.contains { $0.id == "custom" })
            await store.removeResource(kind: "outbounds", id: "local-socks", baseRevision: store.revision)
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            XCTAssertFalse(store.outbounds.contains { $0.id == "local-socks" })
        }
    }

    func testImportedVisualEditsStayInOverlayAndPreserveCredentialsAndAdvancedValues() async throws {
        try await withStore { store in
            let yaml = """
            proxies:
              - {name: Secret node, type: socks5, server: 127.0.0.1, port: 9, username: local-user, password: local-test-password}
              - {name: Other node, type: socks5, server: 127.0.0.1, port: 10}
            proxy-groups:
              - {name: Choice, type: select, proxies: [Secret node, Other node]}
            rules:
              - MATCH,Choice
            """
            await store.previewImport(data: yaml, format: "clash", nodesOnly: false, sourceName: "原始订阅")
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            let sourcesBefore = store.documents[.sources]
            let groupID = try XCTUnwrap(store.groups.first { $0.id.contains("/") }?.id)
            let group = try VisualConfigurationService.group(id: groupID, documents: store.documents, effective: store.effectiveConfiguration)
            XCTAssertTrue(group.isImported)
            XCTAssertTrue(group.definition["members"]?.arrayValue?.allSatisfy { $0.stringValue?.contains("/") == true } == true)
            var groupDefinition = group.definition
            groupDefinition["name"] = .string("我的来源策略")
            groupDefinition["selected"] = group.definition["members"]?.arrayValue?.last
            let groupChange = try VisualConfigurationService.groupChange(resource: group, value: groupDefinition, baseRevision: store.revision, documents: store.documents)
            await store.previewVisualChange(groupChange, summary: "覆盖来源策略")
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            XCTAssertEqual(store.groups.first { $0.id == groupID }?.name, "我的来源策略")
            XCTAssertEqual(store.documents[.sources], sourcesBefore)
            let membersPath = "/groups/\(ConfigurationService.escape(groupID))/members"
            let advanced = try await store.configurationService.prepare(["overlay_patch": .array([
                .object(["op": .string("insert"), "path": .string("/patches"), "value": .object([
                    "op": .string("set"), "path": .string(membersPath), "value": group.definition["members"]!
                ])]),
                .object(["op": .string("insert"), "path": .string("/patches"), "value": .object([
                    "op": .string("set"), "path": .string(membersPath + "/#0"), "value": .string("direct")
                ])])
            ])], summary: "保留高级成员覆盖")
            _ = try await store.configurationService.commit(advanced)
            await store.refresh()
            let composed = try VisualConfigurationService.group(id: groupID, documents: store.documents, effective: store.effectiveConfiguration)
            XCTAssertEqual(composed.definition["members"]?.arrayValue?.first, .string("direct"))
            let lastMember = try XCTUnwrap(composed.definition["members"]?.arrayValue?.last)
            var reordered = composed.definition
            reordered["members"] = .array([lastMember, .string("direct")])
            await store.previewResource(kind: "groups", id: groupID, definition: reordered, baseRevision: store.revision)
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            XCTAssertEqual(store.groups.first { $0.id == groupID }?.members, [lastMember.stringValue!, "direct"], "表单成员顺序应覆盖较早的子字段覆盖。")

            let nodeID = try XCTUnwrap(store.outbounds.first { $0.name == "Secret node" }?.id)
            var resource = try VisualConfigurationService.resource(kind: "outbounds", id: nodeID, documents: store.documents, effective: store.effectiveConfiguration)
            var definition = resource.definition
            definition["name"] = .string("第一次改名")
            await store.previewResource(kind: "outbounds", id: nodeID, definition: definition, baseRevision: store.revision)
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            resource = try VisualConfigurationService.resource(kind: "outbounds", id: nodeID, documents: store.documents, effective: store.effectiveConfiguration)
            definition = resource.definition
            definition["name"] = .string("第二次改名")
            await store.previewResource(kind: "outbounds", id: nodeID, definition: definition, baseRevision: store.revision)
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            XCTAssertEqual(store.documents[.sources], sourcesBefore)
            let overlays = try YAMLDocument.array(store.documents[.overlay] ?? "", key: "patches")
            let namePath = "/outbounds/\(ConfigurationService.escape(nodeID))/name"
            XCTAssertEqual(overlays.filter { $0["path"].stringValue == namePath }.count, 1)
            let config = try await store.client.call("GetConfiguration", params: ["reveal": .bool(true)])
            let unmasked = try YAMLDocument.array(config["sources"].stringValue ?? "", key: "sources")
            XCTAssertEqual(unmasked.first?["outbounds"].arrayValue?.first?["password"].stringValue, "local-test-password")

            let record = try XCTUnwrap(store.ruleRecords.first { !$0.sourceMarker && $0.sourceID != nil })
            XCTAssertFalse(record.movable)
            var rule = record.definition
            rule["outbound"] = .string("reject")
            await store.previewRule(definition: rule, record: record, baseRevision: store.revision)
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            XCTAssertEqual(store.ruleRecords.first { $0.id == record.id }?.definition["outbound"], .string("reject"))
            XCTAssertEqual(store.documents[.sources], sourcesBefore)
            let explanation = try await store.client.call("ExplainRoute", params: ["destination": .string("example.test:443")])
            XCTAssertEqual(explanation["outbound"].stringValue, "reject")

            let marker = try XCTUnwrap(store.ruleRecords.first { $0.sourceMarker })
            await store.moveRule(marker, direction: -1, baseRevision: store.revision)
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            XCTAssertTrue(store.ruleRecords.contains { $0.sourceMarker && $0.definition["id"] != nil })
            let wrapper = try VisualConfigurationService.group(id: "proxy", documents: store.documents, effective: store.effectiveConfiguration)
            let selection = try XCTUnwrap(wrapper.definition["selected"])
            var manual = wrapper.definition
            manual["members"] = .array([selection])
            let manualChange = try VisualConfigurationService.groupChange(resource: wrapper, value: manual, baseRevision: store.revision, documents: store.documents)
            await store.previewVisualChange(manualChange, summary: "手动筛选策略成员")
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            let raw = try YAMLDocument.array(store.documents[.profile] ?? "", key: "groups").first { $0["id"].stringValue == "proxy" }
            XCTAssertEqual(raw?["include-all"].boolValue, false)
            let sourceID = try XCTUnwrap(store.sources.first?.id)
            let refresh = try await store.configurationService.prepareSourceActivation(sourceID: sourceID, nodesOnly: false)
            _ = try await store.configurationService.commit(refresh)
            await store.refresh()
            XCTAssertEqual(store.groups.first { $0.id == "proxy" }?.members, [selection.stringValue!], "刷新不能把可视化排除的成员加回。")
        }
    }

    func testNativeVisualFormPreservesAdvancedDNSAndStalePlanCannotOverwriteLiveEdit() async throws {
        try await withStore { store in
            var draft = try VisualConfigurationDraft(documents: store.documents, sourceNames: [:])
            draft.dnsEnabled = true
            draft.dns = ["nameserver": .array([.string("1.1.1.1")]), "default-nameserver": .array([.string("1.1.1.1")]), "ipv6": .bool(false), "cache-size": .number(512)]
            draft.logLevel = "debug"
            await store.previewVisualChange(draft.change(baseRevision: store.revision), summary: "表单配置 DNS 与日志")
            XCTAssertNil(store.errorMessage)
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            XCTAssertEqual(try YAMLDocument.object(store.documents[.profile] ?? "")["dns"]?["cache-size"], .number(512))
            XCTAssertEqual(try YAMLDocument.object(store.documents[.local] ?? "")["log"]?["level"], .string("debug"))
            let capturedRevision = store.revision
            let capturedDocuments = store.documents
            let original = try VisualConfigurationService.group(id: "proxy", documents: capturedDocuments, effective: store.effectiveConfiguration)
            var edited = original.definition
            edited["name"] = .string("过时的修改")
            let stale = try VisualConfigurationService.groupChange(resource: original, value: edited, baseRevision: capturedRevision, documents: capturedDocuments)
            draft = try VisualConfigurationDraft(documents: store.documents, sourceNames: [:])
            draft.logLevel = "warn"
            await store.previewVisualChange(draft.change(baseRevision: store.revision), summary: "另一客户端的修改")
            await store.applyPrepared()
            let current = store.revision
            await store.previewVisualChange(stale, summary: "尝试覆盖旧配置")
            XCTAssertNotNil(store.errorMessage)
            XCTAssertNil(store.preparedChange)
            XCTAssertEqual(store.revision, current)
            XCTAssertNotEqual(store.groups.first { $0.id == "proxy" }?.name, "过时的修改")
        }
    }

    func testDirectSavesValidateCommitAndRejectStaleDraftsWithoutASeparateApply() async throws {
        try await withStore { store in
            let node: [String: JSONValue] = ["id": .string("one-click"), "name": .string("一次保存"), "type": .string("socks"), "server": .string("127.0.0.1"), "port": .number(9)]
            let added = await store.previewResource(kind: "outbounds", id: nil, definition: node, baseRevision: store.revision, save: true)
            XCTAssertTrue(added)
            XCTAssertNil(store.preparedChange)
            XCTAssertTrue(store.outbounds.contains { $0.id == "one-click" })
            let rule: [String: JSONValue] = ["id": .string("one-click-rule"), "match": .object(["domain-suffix": .array([.string("example.test")])]), "outbound": .string("one-click")]
            let ruleSaved = await store.previewRule(definition: rule, record: nil, baseRevision: store.revision, save: true)
            XCTAssertTrue(ruleSaved)
            let referencedRevision = store.revision
            let blocked = await store.removeResource(kind: "outbounds", id: "one-click", baseRevision: referencedRevision, save: true)
            XCTAssertFalse(blocked)
            XCTAssertNotNil(store.errorMessage)
            XCTAssertEqual(store.revision, referencedRevision)
            XCTAssertTrue(store.outbounds.contains { $0.id == "one-click" })

            let staleRevision = store.revision
            let staleDocument = store.documents[.local] ?? ""
            let modeSaved = await store.previewProcessMode("always", revision: store.revision, save: true)
            XCTAssertTrue(modeSaved)
            let currentRevision = store.revision
            let staleSaved = await store.previewDocument(layer: .local, text: staleDocument, baseRevision: staleRevision, save: true)
            XCTAssertFalse(staleSaved)
            XCTAssertNotNil(store.errorMessage)
            XCTAssertEqual(store.revision, currentRevision)
            XCTAssertEqual(store.processMode, "always")

            let local = (store.documents[.local] ?? "") + "\nlog: {level: debug}\n"
            let documentSaved = await store.previewDocument(layer: .local, text: local, baseRevision: store.revision, save: true)
            XCTAssertTrue(documentSaved, store.errorMessage ?? "Missing save result")
            XCTAssertNil(store.preparedChange)
            XCTAssertEqual(try YAMLDocument.object(store.documents[.local] ?? "")["log"]?["level"], .string("debug"))
            let validRevision = store.revision
            let invalidSaved = await store.previewDocument(layer: .local, text: "network: [", baseRevision: validRevision, save: true)
            XCTAssertFalse(invalidSaved)
            XCTAssertNotNil(store.errorMessage)
            XCTAssertEqual(store.revision, validRevision)
            let unauthorized = await store.previewVisualChange(["base_revision": .number(Double(validRevision)), "local_patch": .array([
                .object(["op": .string("set"), "path": .string("/network"), "value": .object(["mode": .string("tun")])])
            ])], summary: "不能绕过授权", save: true)
            XCTAssertFalse(unauthorized)
            XCTAssertEqual(store.networkMode, "off")
            XCTAssertEqual(store.revision, validRevision)

            let savedRule = try XCTUnwrap(store.ruleRecords.first { $0.definition["id"]?.stringValue == "one-click-rule" })
            let moved = await store.moveRule(savedRule, direction: -1, baseRevision: store.revision, save: true)
            XCTAssertTrue(moved)
            XCTAssertNil(store.preparedChange)
            let movedRule = try XCTUnwrap(store.ruleRecords.first { $0.definition["id"]?.stringValue == "one-click-rule" })
            let removedRule = await store.removeRule(movedRule, baseRevision: store.revision, save: true)
            XCTAssertTrue(removedRule)
            let removedNode = await store.removeResource(kind: "outbounds", id: "one-click", baseRevision: store.revision, save: true)
            XCTAssertTrue(removedNode)
            XCTAssertFalse(store.outbounds.contains { $0.id == "one-click" })
            XCTAssertNil(store.preparedChange)

            // A busy/offline guard must never be mistaken for a successful save.
            store.isBusy = true
            let skipped = await store.previewProcessMode("off", revision: store.revision, save: true)
            store.isBusy = false
            XCTAssertFalse(skipped)
            XCTAssertEqual(store.processMode, "always")
        }
    }

    private func withStore(_ work: (AppStore) async throws -> Void) async throws {
        guard ProcessInfo.processInfo.environment["MIMO_REKA_KERNEL_BINARY"] != nil,
              ProcessInfo.processInfo.environment["MIMO_REKA_HOST_BINARY"] != nil else { throw XCTSkip("Set production kernel and supervisor paths.") }
        let root = URL(fileURLWithPath: "/tmp/mr-visual-" + String(UUID().uuidString.prefix(8)))
        let store = AppStore(home: root)
        defer { if !store.kernel.isRunning { try? FileManager.default.removeItem(at: root) } }
        await store.start()
        do {
            guard store.isOnline else { throw ClientError.message(store.errorMessage ?? "Isolated kernel failed to start") }
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
