import Foundation
import XCTest
@testable import MimoReka

@MainActor
final class AppStoreIntegrationTests: XCTestCase {
    func testBackgroundSubscriptionAddsMembersWithoutChangingSelectionOrActivatingOtherSources() async throws {
        guard ProcessInfo.processInfo.environment["MIMO_REKA_KERNEL_BINARY"] != nil,
              ProcessInfo.processInfo.environment["MIMO_REKA_HOST_BINARY"] != nil else {
            throw XCTSkip("Set production core and host paths.")
        }
        let root = URL(fileURLWithPath: "/tmp/mr-auto-" + String(UUID().uuidString.prefix(8)), isDirectory: true)
        let store = AppStore(home: root)
        defer { if !store.kernel.isRunning { try? FileManager.default.removeItem(at: root) } }
        do {
            await store.start()
            XCTAssertNil(store.errorMessage)
            let http = try SubscriptionHTTPFixture(root: root)
            addTeardownBlock { await http.stop() }
            await store.addSubscription(name: "Managed subscription", url: http.url, interval: 3600, nodesOnly: true)
            XCTAssertNil(store.errorMessage)
            let source = try XCTUnwrap(store.sources.first)
            let selected = try XCTUnwrap(store.groups.first { $0.id == "proxy" }?.selected)
            let wrapperResource = try VisualConfigurationService.group(id: "proxy", documents: store.documents, effective: store.effectiveConfiguration)
            var renamed = wrapperResource.definition
            renamed["name"] = .string("我的默认策略")
            await store.previewResource(kind: "groups", id: "proxy", definition: renamed, baseRevision: store.revision)
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            let before = store.revision
            try """
            proxies:
              - {name: Downloaded, type: socks5, server: 127.0.0.1, port: 9}
              - {name: Added in background, type: socks5, server: 127.0.0.1, port: 10}
            """.write(to: http.document, atomically: true, encoding: .utf8)
            let client = RekaControlClient(socketPath: store.kernel.socketPath)
            let otherController = ConfigurationService(client: client)
            _ = try await otherController.refreshSubscription(sourceID: source.id)
            await store.refresh()
            XCTAssertNil(store.errorMessage)
            let newNode = try XCTUnwrap(store.outbounds.first { $0.name == "Added in background" })
            let wrapper = try XCTUnwrap(store.groups.first { $0.id == "proxy" })
            XCTAssertTrue(wrapper.members.contains(newNode.id))
            XCTAssertEqual(wrapper.selected, selected)
            XCTAssertGreaterThan(store.revision, before)
            let reconciledRevision = store.revision
            await store.refresh()
            XCTAssertEqual(store.revision, reconciledRevision, "Unchanged source hashes must not create repeated revisions.")

            _ = try await otherController.configureSubscription(sourceID: "unactivated", url: http.url, interval: 3600, nodesOnly: true)
            _ = try await otherController.refreshSubscription(sourceID: "unactivated")
            await store.refresh()
            XCTAssertTrue(store.sources.contains { $0.id == "unactivated" })
            XCTAssertFalse(store.groups.first { $0.id == "proxy" }?.members.contains { $0.hasPrefix("unactivated/") } ?? true)
            XCTAssertEqual(store.groups.first { $0.id == "proxy" }?.selected, selected)
            await store.stop()
            XCTAssertFalse(store.kernel.isRunning)
        } catch {
            await store.stop()
            if store.kernel.isRunning { await store.kernel.stop() }
            throw error
        }
    }

    func testStartupConfigurationErrorRemainsEditableAndCanBeRepaired() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let core = environment["MIMO_REKA_KERNEL_BINARY"], environment["MIMO_REKA_HOST_BINARY"] != nil else {
            throw XCTSkip("Set production core and host paths.")
        }
        let root = URL(fileURLWithPath: "/tmp/mr-repair-" + String(UUID().uuidString.prefix(8)), isDirectory: true)
        let store = AppStore(home: root)
        let state = store.kernel.stateRoot
        try FileManager.default.createDirectory(at: state, withIntermediateDirectories: true)
        let profile = root.appendingPathComponent("initial.yaml"), local = root.appendingPathComponent("local.yaml")
        try """
        schema-version: 1
        outbounds:
          - {id: broken, type: shadowsocks, server: 127.0.0.1, port: 9, method: aes-128-gcm, password: secret://missing/password}
        groups:
          - {id: proxy, name: 默认策略, type: select, members: [broken], selected: broken}
        rules:
          - {id: final, match: {all: true}, outbound: proxy}
        """.write(to: profile, atomically: true, encoding: .utf8)
        try "network: {mode: off}\n".write(to: local, atomically: true, encoding: .utf8)
        let seed = Process()
        seed.executableURL = URL(fileURLWithPath: core)
        let socket = root.appendingPathComponent("seed.sock").path
        seed.arguments = ["-state-root", state.path, "-control", "unix://" + socket, "-profile", profile.path, "-local", local.path, "-edit-dir", "-"]
        seed.standardOutput = FileHandle.nullDevice; seed.standardError = FileHandle.nullDevice
        defer {
            if seed.isRunning { seed.terminate(); seed.waitUntilExit() }
            if !store.kernel.isRunning { try? FileManager.default.removeItem(at: root) }
        }
        do {
            try seed.run()
            let seedClient = RekaControlClient(socketPath: socket, timeout: 1)
            var seedStatus: JSONValue = .null
            for _ in 0..<80 {
                if let status = try? await seedClient.call("GetStatus") { seedStatus = status; break }
                try await Task.sleep(for: .milliseconds(50))
            }
            XCTAssertNotEqual(seedStatus["start_error"].stringValue ?? "", "")
            seed.terminate(); seed.waitUntilExit()
            await store.start()
            XCTAssertNil(store.errorMessage)
            XCTAssertTrue(store.isOnline, "The control daemon remains available for repair.")
            XCTAssertEqual(store.networkState, "配置未运行")
            XCTAssertFalse(store.documents[.profile]?.isEmpty ?? true)
            XCTAssertFalse(store.revisions.isEmpty)
            await store.previewDocument(layer: .profile, text: """
            schema-version: 1
            groups: [{id: proxy, name: 默认策略, type: select, members: [direct], selected: direct}]
            rules: [{id: final, match: {all: true}, outbound: proxy}]
            """, baseRevision: store.revision)
            XCTAssertNil(store.errorMessage)
            await store.applyPrepared()
            XCTAssertNil(store.errorMessage)
            XCTAssertTrue(store.isOnline)
            XCTAssertEqual(store.networkState, "未接管系统网络")
            XCTAssertEqual(store.groups.first { $0.id == "proxy" }?.selected, "direct")
            await store.stop()
            XCTAssertFalse(store.kernel.isRunning)
        } catch {
            await store.stop()
            if store.kernel.isRunning { await store.kernel.stop() }
            throw error
        }
    }

    func testProfilesImportSelectionRestartAndCatalogRemainIndependent() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let binary = environment["MIMO_REKA_KERNEL_BINARY"], let host = environment["MIMO_REKA_HOST_BINARY"],
              FileManager.default.isExecutableFile(atPath: binary), FileManager.default.isExecutableFile(atPath: host) else {
            throw XCTSkip("Set MIMO_REKA_KERNEL_BINARY and MIMO_REKA_HOST_BINARY for the isolated app integration test.")
        }
        let root = URL(fileURLWithPath: "/tmp/mr-store-" + String(UUID().uuidString.prefix(8)), isDirectory: true)
        let store = AppStore(home: root)
        defer { if !store.kernel.isRunning { try? FileManager.default.removeItem(at: root) } }
        do {
            await store.start()
            XCTAssertNil(store.errorMessage)
            XCTAssertTrue(store.isOnline)
            XCTAssertEqual(store.networkMode, "off")
            XCTAssertEqual(store.profiles.count, 1)
            let firstProfile = store.activeProfileID
            let originalStateRoot = store.kernel.stateRoot
            let firstData = """
            proxies:
              - {name: First, type: socks5, server: 127.0.0.1, port: 9}
              - {name: Second, type: socks5, server: 127.0.0.1, port: 10}
            """
            let imported = await store.previewImport(data: firstData, format: "clash", nodesOnly: true, sourceName: "First profile nodes", save: true)
            XCTAssertTrue(imported)
            XCTAssertNil(store.preparedChange)
            XCTAssertNil(store.errorMessage)
            XCTAssertEqual(store.sources.count, 1)
            XCTAssertEqual(store.sources.first?.name, "First profile nodes")
            XCTAssertEqual(store.outbounds.filter { !$0.sourceID.isEmpty }.count, 2)
            let group = try XCTUnwrap(store.groups.first { $0.id == "proxy" })
            let selected = try XCTUnwrap(store.outbounds.first { $0.name == "Second" }?.id)
            await store.select(group: group, member: selected)
            XCTAssertNil(store.errorMessage)
            XCTAssertEqual(store.groups.first { $0.id == "proxy" }?.selected, selected)
            let firstRevision = store.revision
            XCTAssertEqual(store.revisions.filter(\.active).count, 1)

            await store.createProfile(name: "Second isolated profile")
            XCTAssertNil(store.errorMessage)
            XCTAssertTrue(store.isOnline)
            XCTAssertNotEqual(store.activeProfileID, firstProfile)
            XCTAssertEqual(store.profiles.count, 2)
            XCTAssertEqual(store.sources.count, 0)
            XCTAssertNotEqual(store.kernel.stateRoot, originalStateRoot)
            XCTAssertEqual(store.networkMode, "off")
            let secondProfile = store.activeProfileID
            let secondData = "proxies: [{name: Third, type: socks5, server: 127.0.0.1, port: 11}]"
            await store.previewImport(data: secondData, format: "clash", nodesOnly: true, sourceName: "Second profile nodes", save: true)
            XCTAssertNil(store.errorMessage)
            XCTAssertTrue(store.outbounds.contains { $0.name == "Third" })
            XCTAssertFalse(store.outbounds.contains { $0.name == "First" })

            await store.switchProfile(firstProfile)
            XCTAssertNil(store.errorMessage)
            XCTAssertEqual(store.activeProfileID, firstProfile)
            XCTAssertEqual(store.kernel.stateRoot, originalStateRoot)
            XCTAssertEqual(store.revision, firstRevision)
            XCTAssertEqual(store.groups.first { $0.id == "proxy" }?.selected, selected)
            XCTAssertEqual(store.sources.first?.name, "First profile nodes")
            XCTAssertFalse(store.outbounds.contains { $0.name == "Third" })
            XCTAssertEqual(store.revisions.filter(\.active).count, 1)

            let staleRevision = store.revision
            let originalText = store.documents[.profile] ?? ""
            let currentGroup = try XCTUnwrap(store.groups.first { $0.id == "proxy" })
            await store.select(group: currentGroup, member: "direct")
            await store.previewDocument(layer: .profile, text: originalText, baseRevision: staleRevision)
            XCTAssertNotNil(store.errorMessage)
            XCTAssertNil(store.preparedChange)
            XCTAssertEqual(store.groups.first { $0.id == "proxy" }?.selected, "direct")

            await store.stop()
            XCTAssertFalse(store.kernel.isRunning)
            await store.start()
            XCTAssertNil(store.errorMessage)
            XCTAssertTrue(store.isOnline)
            XCTAssertEqual(store.networkMode, "off")
            XCTAssertEqual(store.groups.first { $0.id == "proxy" }?.selected, "direct")
            await store.stop()
            XCTAssertFalse(store.kernel.isRunning)
            let reloaded = AppStore(home: root)
            XCTAssertEqual(reloaded.activeProfileID, firstProfile)
            XCTAssertEqual(reloaded.profiles.count, 2)
            XCTAssertTrue(reloaded.profiles.contains { $0.id == secondProfile })
            XCTAssertEqual(reloaded.catalog.sourceNames[firstProfile.uuidString]?.values.first, "First profile nodes")
        } catch {
            await store.stop()
            if store.kernel.isRunning { await store.kernel.stop() }
            throw error
        }
    }
}
