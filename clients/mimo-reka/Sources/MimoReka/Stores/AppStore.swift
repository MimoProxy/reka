import AppKit
import Foundation
import Observation
import UniformTypeIdentifiers

@MainActor @Observable
final class AppStore {
    var kernel: KernelProcess
    var kernelVersion = "Reka"
    var startupPhase = "未启动"
    var operations = LiveOperationsState()
    var profiles: [ClientProfile]
    var activeProfileID: UUID
    var isBusy = false
    var isOnline = false
    var errorMessage: String?
    var notice: String?
    var showImport = false
    var showBackup = false
    var showVisualConfiguration = false
    var visualSection = "general"
    var editingLayer: ConfigurationLayer?
    var preparedChange: PreparedChange?
    var importPreview: String?
    var revision = 0
    var generation = 0
    var connectionCount = 0
    var uploaded = 0
    var downloaded = 0
    var listenerAddress = "—"
    var networkState = "未接管系统网络"
    var networkMode = "off"
    var networkIPv6 = false
    var networkService = NetworkServiceResolver.activeService()
    var tunStack = "mixed"
    var groups: [PolicyGroup] = []
    var outbounds: [OutboundRow] = []
    var connections: [ConnectionRow] = []
    var sources: [SourceRow] = []
    var revisions: [RevisionRow] = []
    var documents: [ConfigurationLayer: String] = [:]
    var capabilities: JSONValue = .null
    var sourceSummary = "尚未导入来源；当前配置使用直连。"
    var appMemoryBytes: Int?
    var coreMemoryBytes: Int?
    var uptime: TimeInterval?
    let homeURL: URL
    var activeProfile: ClientProfile? { profiles.first { $0.id == activeProfileID } }

    @ObservationIgnored var catalog: ProfileCatalog
    @ObservationIgnored var client: RekaControlClient
    @ObservationIgnored var configurationService: ConfigurationService
    @ObservationIgnored var snapshot: JSONValue = .null
    @ObservationIgnored var pollTask: Task<Void, Never>?
    @ObservationIgnored var refreshing = false
    @ObservationIgnored var startedAt: Date?
    @ObservationIgnored var pendingSourceName: (id: String, name: String)?
    @ObservationIgnored private var catalogHealthy = true

    init(home: URL? = nil) {
        let root = home ?? ProcessInfo.processInfo.environment["MIMO_REKA_HOME"].map { URL(fileURLWithPath: $0, isDirectory: true) }
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/MimoReka", isDirectory: true)
        homeURL = root
        let loaded: ProfileCatalog
        do { loaded = try ProfileCatalog.load(from: root) }
        catch { loaded = .initial(); catalogHealthy = false; errorMessage = error.localizedDescription }
        catalog = loaded
        profiles = loaded.profiles
        activeProfileID = loaded.activeProfileID
        let directory = Self.profileDirectory(root: root, id: loaded.activeProfileID)
        let process = KernelProcess(stateRoot: directory, privileged: loaded.profiles.first { $0.id == loaded.activeProfileID }?.privileged ?? false)
        kernel = process
        let control = RekaControlClient(socketPath: process.socketPath)
        client = control
        configurationService = ConfigurationService(client: control, pendingURL: directory.appendingPathComponent("client/pending-operation.json"))
    }

    func start() async {
        guard !isBusy else { return }
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }
        do {
            guard catalogHealthy else { throw ClientError.message("配置索引需要修复，原始文件已保留。") }
            try catalog.save(to: homeURL)
            try await startCurrentRuntime()
        } catch { errorMessage = error.localizedDescription }
    }

    func stop() async {
        guard !isBusy else { return }
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }
        do { try await stopCurrentRuntime() }
        catch { errorMessage = error.localizedDescription }
    }

    func shutdown() async {
        for _ in 0..<600 where isBusy { try? await Task.sleep(for: .milliseconds(100)) }
        guard !isBusy else { errorMessage = "操作仍在进行，请等待完成后退出。"; return }
        await stop()
    }

    func refresh(silent: Bool = false) async {
        guard !isBusy, !refreshing else { return }
        guard kernel.isRunning else {
            isOnline = false
            connectionCount = 0; connections = []; uploaded = 0; downloaded = 0
            networkMode = "off"; networkState = "内核已停止"; uptime = nil; coreMemoryBytes = nil
            return
        }
        refreshing = true
        defer { refreshing = false }
        do {
            try await configurationService.recoverPending()
            try await loadSnapshot()
        } catch {
            guard !Task.isCancelled, kernel.isRunning else { return }
            isOnline = false
            if silent { notice = "控制连接暂时不可用，正在重新连接。" }
            else { errorMessage = error.localizedDescription }
        }
    }

    func previewImport(data: String, format: String, nodesOnly: Bool, sourceName: String, providerResources: [String: String] = [:], geodataResources: [String: String] = [:]) async {
        await perform {
            self.preparedChange = nil; self.importPreview = nil; self.pendingSourceName = nil
            let sourceID = "s-" + UUID().uuidString.lowercased()
            let result = try await self.configurationService.previewImport(data: data, format: format, nodesOnly: nodesOnly,
                                                                           sourceID: sourceID, name: sourceName, providerResources: providerResources, geodataResources: geodataResources)
            self.preparedChange = result
            self.importPreview = result.report
            if format != "native" { self.pendingSourceName = (sourceID, sourceName) }
        }
    }

    func previewDocument(layer: ConfigurationLayer, text: String, baseRevision: Int) async {
        await perform {
            self.preparedChange = nil; self.pendingSourceName = nil
            // The settings flow must acquire a privileged runtime before a
            // network-on document can be applied from the generic editor.
            if layer == .local, !self.kernel.isPrivileged {
                let local = try YAMLDocument.object(text)
                let mode = local["network"]?["mode"].stringValue ?? "off"
                guard mode == "off" else { throw ClientError.message("请先在设置中授权并启用网络模式，再编辑接管参数。") }
            }
            self.preparedChange = try await self.configurationService.prepare([
                "base_revision": .number(Double(baseRevision)), layer.rawValue: .string(text)
            ], summary: "更新\(layer.title)")
        }
    }

    func applyPrepared() async {
        await perform {
            guard let prepared = self.preparedChange else { throw ClientError.message("请先预览当前变更。") }
            _ = try await self.configurationService.commit(prepared)
            if let source = self.pendingSourceName {
                self.catalog.sourceNames[self.activeProfileID.uuidString, default: [:]][source.id] = source.name
                try self.catalog.save(to: self.homeURL)
            }
            self.preparedChange = nil; self.pendingSourceName = nil; self.importPreview = nil
            self.showImport = false; self.editingLayer = nil
            self.showVisualConfiguration = false
            self.notice = "配置已提交并生效。"
        }
    }

    func addSubscription(name: String, url: String, interval: Int, nodesOnly: Bool) async {
        await perform {
            let sourceID = "s-" + UUID().uuidString.lowercased()
            _ = try await self.configurationService.configureSubscription(sourceID: sourceID, url: url, interval: interval, nodesOnly: nodesOnly)
            self.catalog.sourceNames[self.activeProfileID.uuidString, default: [:]][sourceID] = name
            try self.catalog.save(to: self.homeURL)
            _ = try await self.configurationService.refreshSubscription(sourceID: sourceID)
            let activation = try await self.configurationService.prepareSourceActivation(sourceID: sourceID, nodesOnly: nodesOnly)
            _ = try await self.configurationService.commit(activation)
            self.showImport = false
            self.notice = "订阅已添加，后续由 Reka 按设定间隔刷新。"
        }
    }

    func refreshSubscription(_ source: SourceRow) async {
        await perform {
            _ = try await self.configurationService.refreshSubscription(sourceID: source.id)
            let config = try await self.client.call("GetConfiguration")
            let rawSources = try YAMLDocument.array(config["sources"].stringValue ?? "", key: "sources")
            let raw = rawSources.first { $0["id"].stringValue == source.id }
            let nodesOnly = raw?["subscription"]["nodes-only"].boolValue ?? false
            let activation = try await self.configurationService.prepareSourceActivation(sourceID: source.id, nodesOnly: nodesOnly)
            _ = try await self.configurationService.commit(activation)
            self.notice = "订阅已刷新，原有用户覆盖继续保留。"
        }
    }

    func setSubscriptionPaused(_ source: SourceRow, paused: Bool) async {
        await perform {
            let config = try await self.client.call("GetConfiguration")
            let sources = try YAMLDocument.array(config["sources"].stringValue ?? "", key: "sources")
            guard var subscription = sources.first(where: { $0["id"].stringValue == source.id })?["subscription"].objectValue else {
                throw ClientError.message("没有找到此来源的订阅定义。")
            }
            // YAML and JSON spellings differ for these fields. Preserve every
            // masked value while translating only the wire field names.
            for (yaml, json) in [("nodes-only", "nodes_only"), ("allow-partial", "allow_partial"),
                                 ("provider-directory", "provider_directory"), ("certificate-files", "certificate_files")] {
                if let value = subscription.removeValue(forKey: yaml) { subscription[json] = value }
            }
            subscription["paused"] = .bool(paused)
            let result = try await self.client.call("ConfigureSubscription", params: [
                "source_id": .string(source.id), "base_revision": config["revision"], "subscription": .object(subscription)
            ])
            guard result["state"].stringValue == "committed" else { throw ClientError.message(ConfigurationService.diagnostics(result)) }
        }
    }

    func select(group: PolicyGroup, member: String) async {
        await perform {
            try await self.configurationService.select(groupID: group.id, member: member)
            self.notice = "已选择 \(self.displayName(member))；已有连接继续使用原出口。"
        }
    }

    func closeConnection(_ id: String) async {
        await perform {
            guard let numeric = Double(id) else { throw ClientError.message("连接标识无效。") }
            _ = try await self.client.call("CloseConnections", params: ["ids": .array([.number(numeric)])])
        }
    }

    func closeConnections() async {
        await perform { _ = try await self.client.call("CloseConnections", params: ["all": .bool(true)]) }
    }

    func restoreRevision(_ revision: RevisionRow) async {
        await perform {
            let config = try await self.client.call("GetConfiguration")
            let result = try await self.client.call("RestoreRevision", params: ["revision": .number(Double(revision.id)),
                "base_revision": config["revision"], "operation_id": .string(UUID().uuidString)])
            guard result["state"].stringValue == "committed" else { throw ClientError.message(ConfigurationService.diagnostics(result)) }
            self.notice = "已将 r\(revision.id) 恢复为新的配置版本。"
        }
    }

    func createProfile(name: String) async {
        guard !isBusy else { return }
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { return }
        let profile = ClientProfile(name: name)
        do {
            var candidate = catalog
            candidate.profiles.append(profile)
            try candidate.save(to: homeURL)
            catalog = candidate; profiles = candidate.profiles
            await switchProfile(profile.id)
        } catch { errorMessage = error.localizedDescription }
    }

    func switchProfile(_ id: UUID) async {
        guard !isBusy, id != activeProfileID, profiles.contains(where: { $0.id == id }) else { return }
        isBusy = true; errorMessage = nil
        defer { isBusy = false }
        let previous = activeProfileID
        let previousNetwork = snapshot["effective"]["network"]
        let wasRunning = kernel.isRunning
        do {
            try await stopCurrentRuntime()
            configureProfile(id)
            try await startCurrentRuntime()
            catalog.activeProfileID = id
            try catalog.save(to: homeURL)
            notice = "已切换配置，网络接管保持关闭。"
        } catch {
            let failure = error
            if kernel.isRunning { await kernel.stop() }
            guard !kernel.isRunning else { errorMessage = "切换未完成，新运行时仍在清理。"; return }
            configureProfile(previous)
            do {
                if wasRunning {
                    try await startCurrentRuntime()
                    if previousNetwork["mode"].stringValue != "off", previousNetwork.objectValue != nil {
                        let back = try await configurationService.prepare(["local_patch": .array([.object([
                            "op": .string("set"), "path": .string("/network"), "value": previousNetwork
                        ])])], summary: "恢复原网络模式")
                        _ = try await configurationService.commit(back)
                        try await loadSnapshot(force: true)
                    }
                }
                errorMessage = "切换失败，已恢复原配置：\(failure.localizedDescription)"
            } catch { errorMessage = "切换失败；原配置恢复仍需处理：\(error.localizedDescription)" }
        }
    }

    func deleteProfile(_ profile: ClientProfile) async {
        guard !isBusy else { return }
        guard profile.id != activeProfileID, profiles.count > 1 else { errorMessage = "请先切换到其他配置再移除。"; return }
        guard !profile.privileged else { errorMessage = "此配置有独立的管理员运行时。试用版保留其受保护的数据，请先保留该配置。"; return }
        do {
            let directory = Self.profileDirectory(root: homeURL, id: profile.id)
            if FileManager.default.fileExists(atPath: directory.path) { try FileManager.default.removeItem(at: directory) }
            catalog.profiles.removeAll { $0.id == profile.id }
            catalog.sourceNames.removeValue(forKey: profile.id.uuidString)
            try catalog.save(to: homeURL)
            profiles = catalog.profiles
        } catch { errorMessage = error.localizedDescription }
    }

    func requestNetworkMode(_ mode: String) async {
        await perform {
            guard ["off", "system-proxy", "tun"].contains(mode),
                  (self.capabilities["network_modes"].arrayValue ?? []).contains(.string(mode)) else {
                throw ClientError.message("当前内核不支持此网络模式。")
            }
            if mode != "off", !self.kernel.isPrivileged {
                let reveal = try await self.client.call("GetConfiguration", params: ["reveal": .bool(true)])
                self.operations.reset()
                try await self.kernel.promote(configuration: reveal)
                // Promotion changes the control socket immediately. Keep stop
                // and recovery usable even if catalog persistence later fails.
                self.rebuildController()
                if let index = self.catalog.profiles.firstIndex(where: { $0.id == self.activeProfileID }) {
                    self.catalog.profiles[index].privileged = true
                }
                self.profiles = self.catalog.profiles
                try self.catalog.save(to: self.homeURL)
                self.startedAt = Date()
                self.snapshot = .null
                self.capabilities = try await self.client.call("GetCapabilities")
                try await self.loadSnapshot(force: true)
            }
            let network: JSONValue
            var change: [String: JSONValue] = [:]
            if mode == "off" { network = .object(["mode": .string("off")]) }
            else if mode == "system-proxy" {
                let listeners = self.snapshot["effective"]["listeners"].arrayValue ?? []
                guard let listener = listeners.first(where: { $0["type"].stringValue == "mixed" })?["id"].stringValue else {
                    throw ClientError.message("系统代理需要一个 mixed 监听器，请先在本机设置中配置。")
                }
                network = .object(["mode": .string(mode), "proxy-listener": .string(listener), "service": .string(self.networkService)])
            } else {
                var patch: [JSONValue] = []
                let profile = try YAMLDocument.object(self.documents[.profile] ?? "")
                if profile["dns"]?.objectValue == nil {
                    patch.append(.object(["op": .string("set"), "path": .string("/dns"), "value": .object([
                        "nameserver": .array([.string("https://1.1.1.1/dns-query")]),
                        "default-nameserver": .array([.string("1.1.1.1")]),
                        "proxy-server-nameserver": .array([.string("1.1.1.1")]), "ipv6": .bool(false)
                    ])]))
                    self.notice = "增强模式已配置 1.1.1.1 DNS，可在规则与 DNS 页面修改。"
                }
                if !patch.isEmpty { change["patch"] = .array(patch) }
                network = .object(["mode": .string("tun"), "service": .string(self.networkService), "tun": .object([
                    "stack": .string(self.tunStack), "mtu": .number(1500), "address4": .string("172.29.0.1/30"), "dns-hijack": .bool(true)
                ])])
            }
            change["local_patch"] = .array([.object(["op": .string("set"), "path": .string("/network"), "value": network])])
            let prepared = try await self.configurationService.prepare(change, summary: mode == "off" ? "关闭网络接管" : "启用网络接管")
            _ = try await self.configurationService.commit(prepared)
        }
    }

    func displayName(_ id: String) -> String {
        if id == "direct" { return "直连" }
        if id == "reject" { return "拒绝" }
        return outbounds.first { $0.id == id }?.name ?? groups.first { $0.id == id }?.name ?? id
    }

    func copyProxyCommand() {
        guard listenerAddress != "—" else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString("export http_proxy=http://\(listenerAddress) https_proxy=http://\(listenerAddress) all_proxy=socks5h://\(listenerAddress)", forType: .string)
        notice = "终端代理命令已复制。"
    }

    func revealDataFolder() { NSWorkspace.shared.open(homeURL) }

    func exportConfiguration() {
        guard let text = documents[.profile] else { return }
        let panel = NSSavePanel()
        panel.title = "导出主配置"
        panel.message = "导出当前主配置；敏感字段保持遮罩。来源和用户覆盖可在各自的配置编辑器中查看。"
        panel.nameFieldStringValue = "profile.yaml"
        panel.allowedContentTypes = [.yaml, .plainText]
        guard panel.runModal() == .OK, let target = panel.url else { return }
        do { try text.write(to: target, atomically: true, encoding: .utf8) }
        catch { errorMessage = error.localizedDescription }
    }

    func perform(_ body: () async throws -> Void) async {
        guard !isBusy, isOnline else { return }
        isBusy = true; errorMessage = nil
        defer { isBusy = false }
        do { try await body(); try await loadSnapshot(force: true) }
        catch {
            errorMessage = error.localizedDescription
            if kernel.isRunning { try? await loadSnapshot(force: true) }
        }
    }

    private func startCurrentRuntime() async throws {
        operations.reset()
        startupPhase = "正在启动待机内核"
        try await kernel.start()
        rebuildController()
        let deferred = try await configurationService.recoverPendingForStartup()
        if deferred { notice = "上次未确认的网络变更已留档，请在就绪后重新选择网络模式。" }
        startupPhase = "校验配置与恢复选组"
        capabilities = try await client.call("GetCapabilities")
        let hello = try await client.call("Hello", params: ["versions": .array([.number(1)])])
        kernelVersion = hello["server"].stringValue?.replacingOccurrences(of: "reka/", with: "Reka ") ?? "Reka"
        startedAt = Date()
        try await loadSnapshot(force: true)
        let readiness = try await client.call("GetStatus")
        guard networkMode == "off" else {
            await kernel.stop()
            throw ClientError.message("待机校验未通过，已停止独立内核。")
        }
        startupPhase = (readiness["start_error"].stringValue ?? "").isEmpty ? "就绪 · 网络接管关闭" : "配置待修复 · 网络接管关闭"
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(2))
                guard !Task.isCancelled, let self else { return }
                await self.refresh(silent: true)
            }
        }
    }

    private func stopCurrentRuntime() async throws {
        if kernel.isRunning {
            let config = try await client.call("GetConfiguration")
            if let mode = config["effective"]["network"]["mode"].stringValue, mode != "off" {
                let off = try await configurationService.prepare(["base_revision": config["revision"], "local_patch": .array([
                    .object(["op": .string("set"), "path": .string("/network"), "value": .object(["mode": .string("off")])])
                ])], summary: "停止前恢复系统网络")
                _ = try await configurationService.commit(off)
            }
            await kernel.stop()
            guard !kernel.isRunning else { throw ClientError.message("内核仍在恢复系统设置，请稍后再试。") }
        }
        pollTask?.cancel(); pollTask = nil
        operations.reset()
        startupPhase = "已停止"
        isOnline = false; networkMode = "off"; networkState = "未接管系统网络"
        connections = []; connectionCount = 0; uploaded = 0; downloaded = 0; uptime = nil; coreMemoryBytes = nil
    }

    private func configureProfile(_ id: UUID) {
        operations.reset()
        activeProfileID = id
        let directory = Self.profileDirectory(root: homeURL, id: id)
        kernel = KernelProcess(stateRoot: directory, privileged: profiles.first { $0.id == id }?.privileged ?? false)
        rebuildController()
        snapshot = .null; revision = 0; generation = 0
        groups = []; outbounds = []; sources = []; revisions = []; documents = [:]
        preparedChange = nil; pendingSourceName = nil; editingLayer = nil; importPreview = nil
    }

    private func rebuildController() {
        client = RekaControlClient(socketPath: kernel.socketPath)
        configurationService = ConfigurationService(client: client, pendingURL: kernel.stateRoot.appendingPathComponent("client/pending-operation.json"))
    }

    private static func profileDirectory(root: URL, id: UUID) -> URL {
        root.appendingPathComponent("profiles", isDirectory: true).appendingPathComponent(id.uuidString.lowercased(), isDirectory: true)
    }
}
