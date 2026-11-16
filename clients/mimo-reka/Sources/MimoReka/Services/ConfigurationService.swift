import Foundation

enum ConfigurationError: LocalizedError, Sendable {
    case message(String)
    var errorDescription: String? {
        switch self { case .message(let message): return message }
    }
}

/// The only writer of runtime configuration. A prepared candidate binds its
/// revision and plan hash, and uncertain commits retain their operation identity.
actor ConfigurationService {
    private let client: RekaControlClient
    private let pendingURL: URL?
    private var pendingRequest: [String: JSONValue]?

    init(client: RekaControlClient, pendingURL: URL? = nil) {
        self.client = client
        self.pendingURL = pendingURL
        if let pendingURL, let data = try? Data(contentsOf: pendingURL) {
            pendingRequest = try? JSONDecoder().decode([String: JSONValue].self, from: data)
        }
    }

    func prepare(_ input: [String: JSONValue], summary: String) async throws -> PreparedChange {
        try await recoverPending()
        var change = input
        if change["base_revision"] == nil {
            change["base_revision"] = try await configuration()["revision"]
        }
        let plan = try await client.call("PlanConfiguration", params: change)
        guard plan["valid"].boolValue == true, let hash = plan["plan_hash"].stringValue else {
            throw ConfigurationError.message(Self.diagnostics(plan))
        }
        return PreparedChange(id: UUID(), change: change, planHash: hash, summary: summary,
                              report: Self.describePlan(plan["plan"]), plan: plan["plan"])
    }

    func commit(_ prepared: PreparedChange) async throws -> JSONValue {
        try await recoverPending()
        var request = prepared.change
        request["plan_hash"] = .string(prepared.planHash)
        request["operation_id"] = .string(prepared.id.uuidString)
        request["source"] = .string("mimo-reka")
        request["message"] = .string(prepared.summary)
        try persistPending(request)
        pendingRequest = request
        do {
            let result = try await client.call("CommitConfiguration", params: request)
            try finish(result)
            return result
        } catch let error as ConfigurationError {
            throw error
        } catch {
            // Both calls have identical payload and operation ID. A lost response
            // cannot turn one user action into a second configuration change.
            do {
                let result = try await client.call("CommitConfiguration", params: request)
                try finish(result)
                return result
            } catch let error as ConfigurationError { throw error }
            catch { throw ConfigurationError.message("连接中断，提交结果尚未确认。恢复连接后刷新状态即可继续核对。") }
        }
    }

    func recoverPending() async throws {
        guard let request = pendingRequest else { return }
        let result = try await client.call("CommitConfiguration", params: request)
        try finish(result)
    }

    func previewImport(data: String, format: String, nodesOnly: Bool,
                       sourceID: String, name: String) async throws -> PreparedChange {
        let text = data.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, text.utf8.count <= 12 * 1024 * 1024 else {
            throw ConfigurationError.message("请输入有效配置，内容不能超过 12 MiB。")
        }
        let config = try await configuration()
        if format == "native" {
            return try await prepare(["base_revision": config["revision"], "profile": .string(text)],
                                     summary: "更新原生主配置")
        }
        try Self.validateSourceID(sourceID)
        let currentSources = try YAMLDocument.array(config["sources"].stringValue ?? "", key: "sources")
        if let existing = currentSources.first(where: { $0["id"].stringValue == sourceID }),
           existing["subscription"].objectValue != nil {
            throw ConfigurationError.message("此来源已关联自动订阅，请使用刷新订阅；本地文件可另存为新来源。")
        }
        let request = Self.importRequest(data: text, format: format, nodesOnly: nodesOnly, sourceID: sourceID)
        let preview = try await client.call("ImportSource", params: ["import": request, "reveal": .bool(false)])
        let report = preview["report"]
        guard report["can_apply"].boolValue == true else {
            throw ConfigurationError.message("导入被阻止：\n" + Self.diagnostics(report))
        }
        let normalized = try YAMLDocument.array(preview["sources"].stringValue ?? "", key: "sources")
        guard let source = normalized.first(where: { $0["id"].stringValue == sourceID }) else {
            throw ConfigurationError.message("内核没有返回有效的来源快照。")
        }
        let patch = try Self.activationPatches(config: config, source: source, nodesOnly: nodesOnly)
        var change: [String: JSONValue] = ["base_revision": config["revision"], "import": request]
        if !patch.isEmpty { change["patch"] = .array(patch) }
        var prepared = try await prepare(change, summary: "导入来源 · \(name)")
        prepared = PreparedChange(id: prepared.id, change: prepared.change, planHash: prepared.planHash,
                                  summary: prepared.summary,
                                  report: Self.importReport(report, nodesOnly: nodesOnly) + "\n\n" + prepared.report,
                                  plan: prepared.plan)
        return prepared
    }

    /// Subscription fetching first materializes its isolated source. Activation
    /// is a separate, previewable transaction and never rewrites an active source.
    func prepareSourceActivation(sourceID: String, nodesOnly: Bool) async throws -> PreparedChange {
        try Self.validateSourceID(sourceID)
        let config = try await configuration()
        let sources = try YAMLDocument.array(config["sources"].stringValue ?? "", key: "sources")
        guard let source = sources.first(where: { $0["id"].stringValue == sourceID }),
              !(source["outbounds"].arrayValue ?? []).isEmpty || !(source["groups"].arrayValue ?? []).isEmpty else {
            throw ConfigurationError.message("来源尚无可激活的节点或策略组，请先刷新订阅。")
        }
        let patch = try Self.activationPatches(config: config, source: source, nodesOnly: nodesOnly)
        return try await prepare(["base_revision": config["revision"], "patch": .array(patch)],
                                 summary: "激活订阅来源")
    }

    @discardableResult
    func configureSubscription(sourceID: String, url: String, interval: Int,
                               nodesOnly: Bool, format: String = "auto") async throws -> JSONValue {
        try Self.validateSourceID(sourceID)
        let value = url.trimmingCharacters(in: .whitespacesAndNewlines)
        let isSecret = value.hasPrefix("secret://")
        guard isSecret || URL(string: value).map({ ["http", "https"].contains($0.scheme?.lowercased() ?? "") && $0.host != nil }) == true else {
            throw ConfigurationError.message("请输入有效的 HTTP(S) 订阅地址。")
        }
        guard interval == 0 || (30...604800).contains(interval) else {
            throw ConfigurationError.message("订阅刷新间隔必须为 30 秒至 7 天。")
        }
        try await recoverPending()
        let config = try await configuration()
        let result = try await client.call("ConfigureSubscription", params: [
            "source_id": .string(sourceID), "base_revision": config["revision"],
            "subscription": .object(["url": .string(value), "format": .string(format),
                                      "interval": .number(Double(interval)), "nodes_only": .bool(nodesOnly),
                                      "allow_partial": .bool(false), "paused": .bool(false)])
        ])
        try Self.requireCommitted(result)
        return result
    }

    func refreshSubscription(sourceID: String) async throws -> JSONValue {
        _ = try await client.call("RefreshSubscription", params: ["source_id": .string(sourceID), "wait": .bool(false)])
        let deadline = Date().addingTimeInterval(65)
        while Date() < deadline {
            try Task.checkCancellation()
            let all = try await client.call("ListSubscriptions")
            let statuses = all.arrayValue ?? all["subscriptions"].arrayValue ?? []
            if let status = statuses.first(where: { $0["source_id"].stringValue == sourceID }) {
                switch status["state"].stringValue ?? "" {
                case "current": return status
                case "failed", "stale":
                    throw ConfigurationError.message("订阅刷新失败（\(status["error_code"].stringValue ?? "unknown")），之前的快照保持不变。")
                case "paused": throw ConfigurationError.message("订阅已暂停。")
                default: break
                }
            }
            try await Task.sleep(for: .milliseconds(400))
        }
        throw ConfigurationError.message("订阅仍在刷新，可稍后查看来源状态。")
    }

    func select(groupID: String, member: String) async throws {
        let config = try await configuration()
        let path = "/groups/\(Self.escape(groupID))/selected"
        var change: [String: JSONValue] = ["base_revision": config["revision"]]
        if groupID.contains("/") {
            let overlay = try YAMLDocument.object(config["overlay"].stringValue ?? "")
            let index = (overlay["patches"]?.arrayValue ?? []).lastIndex {
                $0["op"].stringValue == "set" && $0["path"].stringValue == path
            }
            if let index {
                change["overlay_patch"] = .array([Self.operation("set", "/patches/#\(index)/value", .string(member))])
            } else {
                let selection: JSONValue = .object(["op": .string("set"), "path": .string(path), "value": .string(member)])
                change["overlay_patch"] = .array([Self.operation("insert", "/patches", selection)])
            }
        } else {
            change["patch"] = .array([Self.operation("set", path, .string(member))])
        }
        let prepared = try await prepare(change, summary: "切换策略选择")
        _ = try await commit(prepared)
    }

    private func configuration() async throws -> JSONValue {
        try await client.call("GetConfiguration")
    }

    private func finish(_ result: JSONValue) throws {
        guard ["committed", "rejected", "failed"].contains(result["state"].stringValue ?? "") else {
            throw ConfigurationError.message("内核尚未确认操作结果，请刷新后重试。")
        }
        pendingRequest = nil
        if let pendingURL { try? FileManager.default.removeItem(at: pendingURL) }
        try Self.requireCommitted(result)
    }

    private func persistPending(_ request: [String: JSONValue]) throws {
        guard let pendingURL else { return }
        let manager = FileManager.default
        try manager.createDirectory(at: pendingURL.deletingLastPathComponent(), withIntermediateDirectories: true,
                                    attributes: [.posixPermissions: 0o700])
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(request)
        try data.write(to: pendingURL, options: .atomic)
        try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pendingURL.path)
    }

    private static func activationPatches(config: JSONValue, source: JSONValue, nodesOnly: Bool) throws -> [JSONValue] {
        guard let sourceID = source["id"].stringValue else { throw ConfigurationError.message("来源标识缺失。") }
        let profile = try YAMLDocument.object(config["profile"].stringValue ?? "")
        var patch: [JSONValue] = []
        let imports = profile["imports"]?.arrayValue ?? []
        let importValue: JSONValue = .object(["source": .string(sourceID), "outbounds": .bool(true), "groups": .bool(!nodesOnly)])
        if let index = imports.firstIndex(where: { $0["source"].stringValue == sourceID }) {
            // An existing import may include explicit rule/sub-rule flags.
            var replacement = imports[index].objectValue ?? [:]
            replacement["outbounds"] = .bool(true)
            replacement["groups"] = .bool(!nodesOnly)
            if .object(replacement) != imports[index] {
                patch.append(operation("set", "/imports/#\(index)", .object(replacement)))
            }
        } else { patch.append(operation("insert", "/imports", importValue)) }

        let nodes = (source["outbounds"].arrayValue ?? []).compactMap { $0["id"].stringValue }.map { sourceID + "/" + $0 }
        let importedGroups = nodesOnly ? [] : (source["groups"].arrayValue ?? []).compactMap { $0["id"].stringValue }.map { sourceID + "/" + $0 }
        let additions = importedGroups + nodes
        guard !additions.isEmpty else { throw ConfigurationError.message("此来源没有可用节点或策略组。") }
        let groups = profile["groups"]?.arrayValue ?? []
        if let wrapper = groups.first(where: { $0["id"].stringValue == "proxy" }) {
            guard wrapper["type"].stringValue == "select" else {
                throw ConfigurationError.message("主配置中的 proxy 组不是手动选择组，请先在原生配置中调整后导入。")
            }
            let previous = (wrapper["members"].arrayValue ?? []).compactMap(\.stringValue)
            let retained = previous.filter { !$0.hasPrefix(sourceID + "/") || additions.contains($0) }
            var members: [String] = []
            for member in retained + additions where !members.contains(member) { members.append(member) }
            if !members.contains("direct") { members.append("direct") }
            if members != previous {
                patch.append(operation("set", "/groups/proxy/members", .array(members.map(JSONValue.string))))
            }
            let previousSelection = wrapper["selected"].stringValue ?? previous.first ?? "direct"
            // The initial all-direct starter adopts its first imported node.
            // Every existing nonempty policy retains its selection, including DIRECT.
            if previous.allSatisfy({ $0 == "direct" || $0 == "reject" }) && previousSelection == "direct" {
                patch.append(operation("set", "/groups/proxy/selected", .string(additions[0])))
            }
        } else {
            let wrapper: JSONValue = .object(["id": .string("proxy"), "name": .string("代理策略"),
                "type": .string("select"), "members": .array((additions + ["direct"]).map(JSONValue.string)),
                "selected": .string(additions[0])])
            patch.append(operation("insert", "/groups", wrapper))
        }

        let rules = profile["rules"]?.arrayValue ?? []
        let sourceRuleIndices = rules.indices.filter { rules[$0]["source"].stringValue == sourceID }
        if nodesOnly {
            for index in sourceRuleIndices.reversed() { patch.append(operation("remove", "/rules/#\(index)")) }
        } else if sourceRuleIndices.isEmpty && !(source["rules"].arrayValue ?? []).isEmpty {
            var marker = operation("insert", "/rules", .object(["source": .string(sourceID)])).objectValue!
            if let finalIndex = rules.firstIndex(where: { $0["match"]["all"].boolValue == true }) {
                marker["before"] = .string(rules[finalIndex]["id"].stringValue ?? "#\(finalIndex)")
            }
            patch.append(.object(marker))
        }
        if rules.isEmpty {
            patch.append(operation("insert", "/rules", .object(["id": .string("final"),
                "match": .object(["all": .bool(true)]), "outbound": .string("proxy")])))
        }
        return patch
    }

    private static func importRequest(data: String, format: String, nodesOnly: Bool, sourceID: String) -> JSONValue {
        .object(["source_id": .string(sourceID), "format": .string(format), "data": .string(data),
                 "nodes_only": .bool(nodesOnly), "allow_partial": .bool(false)])
    }

    private static func operation(_ op: String, _ path: String, _ value: JSONValue? = nil) -> JSONValue {
        var object: [String: JSONValue] = ["op": .string(op), "path": .string(path)]
        if let value { object["value"] = value }
        return .object(object)
    }

    static func escape(_ value: String) -> String {
        value.replacingOccurrences(of: "~", with: "~0").replacingOccurrences(of: "/", with: "~1")
    }

    private static func validateSourceID(_ sourceID: String) throws {
        guard sourceID.range(of: #"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"#, options: .regularExpression) != nil else {
            throw ConfigurationError.message("来源标识格式无效。")
        }
    }

    private static func requireCommitted(_ result: JSONValue) throws {
        guard result["state"].stringValue == "committed" else {
            throw ConfigurationError.message(diagnostics(result))
        }
    }

    static func diagnostics(_ value: JSONValue) -> String {
        if value["conflict"].objectValue != nil { return "配置版本已变化，请刷新并重新预览。" }
        var lines: [String] = []
        if let message = value["error"]["message"].stringValue { lines.append(message) }
        for item in value["diagnostics"].arrayValue ?? [] {
            guard let message = item["message"].stringValue else { continue }
            let path = item["path"].stringValue ?? ""
            lines.append(path.isEmpty ? message : "\(path)：\(message)")
        }
        return lines.isEmpty ? "配置未通过内核校验，当前运行配置保持不变。" : lines.joined(separator: "\n")
    }

    private static func importReport(_ report: JSONValue, nodesOnly: Bool) -> String {
        let nodes = report["nodes"]["imported"].intValue ?? 0
        let groups = report["groups"]["imported"].intValue ?? 0
        let rules = report["rules"]["imported"].intValue ?? 0
        var lines = ["兼容检查通过：\(nodes) 个节点、\(groups) 个策略组、\(rules) 条规则。",
                     "其他来源、已有选组、本机设置和手动覆盖保持不变。"]
        if nodesOnly { lines.append("本次仅导入节点，不导入来源中的策略组、规则和 DNS。") }
        else { lines.append("规则按来源顺序加入现有规则；来源 DNS 不自动启用。") }
        for ignored in report["ignored"].arrayValue ?? [] {
            if let text = ignored.stringValue { lines.append("兼容提示：\(text)") }
        }
        for item in report["diagnostics"].arrayValue ?? [] {
            if let message = item["message"].stringValue { lines.append(message) }
        }
        return lines.joined(separator: "\n")
    }

    private static func describePlan(_ plan: JSONValue) -> String {
        var lines = ["变更后的规则数：\(plan["rules"].intValue ?? 0)"]
        if plan["network_changed"].boolValue == true { lines.append("系统网络接管设置将更新。") }
        if plan["dns_changed"].boolValue == true { lines.append("DNS 配置将更新。") }
        if plan["interrupts"].boolValue == true { lines.append("此变更可能中断现有网络接管连接。") }
        if let note = plan["network_note"].stringValue, !note.isEmpty { lines.append(note) }
        let restarts = (plan["restart_required"].arrayValue ?? []).compactMap(\.stringValue)
        if !restarts.isEmpty { lines.append("需要重启：" + restarts.joined(separator: "、")) }
        return lines.joined(separator: "\n")
    }
}
