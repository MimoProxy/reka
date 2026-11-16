import Foundation

extension AppStore {
    func loadSnapshot(force: Bool = false) async throws {
        var status = try await client.call("GetStatus")
        let startError = status["start_error"].stringValue ?? ""
        let reportedRevision = status["revision"].intValue ?? 0
        let configurationChanged = force || snapshot == .null || reportedRevision != revision
        var config = configurationChanged ? try await client.call("GetConfiguration") : snapshot
        if configurationChanged, startError.isEmpty {
            do {
                let reconciled = try await reconcileSubscriptionMembers(config)
                if reconciled != config {
                    config = reconciled
                    status = try await client.call("GetStatus")
                }
            } catch {
                notice = "来源已更新，默认策略成员仍需同步：\(error.localizedDescription)"
            }
        }
        let observed = startError.isEmpty ? try await client.call("GetGroupStatus") : .array([])
        // The subscription manager intentionally rejects ListSubscriptions
        // while the active configuration cannot compile. Documents and history
        // remain readable and must still reach the repair UI.
        let subscriptionResult = startError.isEmpty ? try await client.call("ListSubscriptions") : .array([])
        let subscriptionStatuses = subscriptionResult.arrayValue ?? subscriptionResult["subscriptions"].arrayValue ?? []
        var active: [JSONValue] = []
        var offset = 0
        var total = 0
        repeat {
            let page = try await client.call("ListConnections", params: ["offset": .number(Double(offset)), "limit": .number(1000)])
            let rows = page["connections"].arrayValue ?? []
            total = page["total"].intValue ?? 0
            active.append(contentsOf: rows)
            offset += rows.count
            if rows.isEmpty { break }
        } while offset < total && offset < 25_000
        guard kernel.isRunning, !Task.isCancelled else { return }

        snapshot = config
        revision = config["revision"].intValue ?? reportedRevision
        generation = status["runtime"]["generation"].intValue ?? 0
        connectionCount = total
        let network = status["runtime"]["network"]
        networkIPv6 = network["ipv6"].boolValue ?? false
        let effective = config["effective"]
        networkMode = effective["network"]["mode"].stringValue ?? "off"
        let state = network["state"].stringValue ?? "Stopped"
        if !startError.isEmpty {
            networkState = "配置未运行"
            notice = "当前配置尚未运行，可编辑配置或恢复历史版本：\(startError)"
        }
        else if let error = network["error"].stringValue, !error.isEmpty { networkState = "\(state)：\(error)" }
        else if state == "Running" { networkState = network["mode"].stringValue == "tun" ? "增强模式运行中" : "系统代理已开启" }
        else { networkState = networkMode == "off" ? "未接管系统网络" : state }
        if configurationChanged {
            for layer in ConfigurationLayer.allCases { documents[layer] = config[layer.rawValue].stringValue ?? "" }
            if let service = effective["network"]["service"].stringValue, !service.isEmpty { networkService = service }
            if let stack = effective["network"]["tun"]["stack"].stringValue, !stack.isEmpty { tunStack = stack }
        }
        let listeners = status["runtime"]["listeners"].arrayValue ?? []
        listenerAddress = listeners.first(where: { $0["id"].stringValue == "mixed" })?["listen"].stringValue
            ?? listeners.first?["listen"].stringValue ?? "—"
        outbounds = (effective["outbounds"].arrayValue ?? []).map {
            let id = $0["id"].stringValue ?? ""
            return OutboundRow(id: id, name: $0["name"].stringValue ?? (id == "direct" ? "直连" : id == "reject" ? "拒绝" : id),
                               type: $0["type"].stringValue ?? "", server: $0["server"].stringValue ?? "", port: $0["port"].intValue,
                               sourceID: id.contains("/") ? String(id.prefix { $0 != "/" }) : "")
        }
        let automatic = effective["automatic-groups"].arrayValue ?? []
        let statuses = observed.arrayValue ?? observed["groups"].arrayValue ?? []
        groups = (effective["groups"].arrayValue ?? []).map { group in
            let id = group["ID"].stringValue ?? group["id"].stringValue ?? ""
            let auto = automatic.first { $0["ID"].stringValue == id }
            let current = statuses.first { $0["id"].stringValue == id }
            let members = (group["Members"].arrayValue ?? []).compactMap(\.stringValue)
            var health: [String: String] = [:]
            for result in current?["results"].arrayValue ?? [] {
                guard let member = result["member"].stringValue else { continue }
                let checked = Self.parseDate(result["checked"].stringValue)
                health[member] = checked == nil ? "未检测" : result["alive"].boolValue == true ? "\(result["delay_ms"].intValue ?? 0) ms" : "不可用"
            }
            return PolicyGroup(id: id, name: effective["group_metadata"][id]["name"].stringValue ?? (id == "proxy" ? "代理策略" : id),
                               type: auto?["Type"].stringValue ?? "select",
                               selected: current?["selected"].stringValue ?? group["Selected"].stringValue ?? members.first ?? "",
                               members: members, health: health)
        }
        var seen: Set<String> = []
        connections = active.compactMap {
            let id = String($0["id"].intValue ?? 0)
            guard seen.insert(id).inserted else { return nil }
            return ConnectionRow(id: id, destination: $0["destination"].stringValue ?? "", network: $0["network"].stringValue ?? "",
                outbound: $0["outbound"].stringValue ?? "", source: $0["source"].stringValue ?? "", uploaded: $0["upload"].intValue ?? 0,
                downloaded: $0["download"].intValue ?? 0, rule: $0["rule"].stringValue ?? $0["rule_id"].stringValue ?? "",
                chain: ($0["chain"].arrayValue ?? []).compactMap(\.stringValue))
        }
        uploaded = connections.reduce(0) { $0 + $1.uploaded }
        downloaded = connections.reduce(0) { $0 + $1.downloaded }
        if total > 25_000 { notice = "活动连接超过 25,000 条，列表与活动字节暂只展示前 25,000 条。" }

        let sourceItems = try YAMLDocument.array(documents[.sources] ?? "", key: "sources")
        sources = sourceItems.map { source in
            let id = source["id"].stringValue ?? ""
            let subscription = source["subscription"]
            let observed = subscriptionStatuses.first { $0["source_id"].stringValue == id }
            return SourceRow(id: id, name: catalog.sourceNames[activeProfileID.uuidString]?[id] ?? id,
                nodeCount: source["outbounds"].arrayValue?.count ?? 0, groupCount: source["groups"].arrayValue?.count ?? 0,
                hasSubscription: subscription.objectValue != nil, paused: subscription["paused"].boolValue ?? false,
                subscriptionState: observed?["state"].stringValue, lastSuccess: Self.parseDate(observed?["last_success"].stringValue),
                nextAttempt: Self.parseDate(observed?["next_attempt"].stringValue), errorCode: observed?["error_code"].stringValue)
        }
        sourceSummary = sources.isEmpty ? "尚未导入来源；当前配置使用本地出站。" : "\(sources.count) 个来源 · \(sources.reduce(0) { $0 + $1.nodeCount }) 个节点 · \(sources.filter(\.hasSubscription).count) 个自动订阅"
        if configurationChanged {
            let history = try await client.call("ListRevisions")
            let activeRevision = history["active"].intValue ?? revision
            revisions = (history["revisions"].arrayValue ?? []).map {
                let id = $0["revision"].intValue ?? 0
                return RevisionRow(id: id, timestamp: Self.parseDate($0["created"].stringValue), message: $0["message"].stringValue ?? "配置提交",
                                   source: $0["source"].stringValue ?? "", active: id == activeRevision)
            }
        }
        appMemoryBytes = ProcessResourceSampler.residentBytes(pid: ProcessInfo.processInfo.processIdentifier)
        coreMemoryBytes = kernel.corePID.flatMap(ProcessResourceSampler.residentBytes)
        uptime = startedAt.map { Date().timeIntervalSince($0) }
        isOnline = true
    }

    /// A subscription owns its source, while the app owns the generated proxy
    /// group's membership. Only an already referenced subscription can extend
    /// that group; unactivated or failed new subscriptions remain isolated.
    private func reconcileSubscriptionMembers(_ input: JSONValue) async throws -> JSONValue {
        let profile = try YAMLDocument.object(input["profile"].stringValue ?? "")
        guard let wrapper = profile["groups"]?.arrayValue?.first(where: { $0["id"].stringValue == "proxy" }),
              wrapper["type"].stringValue == "select",
              ["默认策略", "代理策略"].contains(wrapper["name"].stringValue ?? "") else { return input }
        let referenced = Set((profile["imports"]?.arrayValue ?? []).compactMap { $0["source"].stringValue })
        let previousHashes = snapshot["effective"]["source_hashes"].objectValue ?? [:]
        let currentHashes = input["effective"]["source_hashes"].objectValue ?? [:]
        let raw = try YAMLDocument.array(input["sources"].stringValue ?? "", key: "sources")
        let changed = raw.filter { source in
            guard let id = source["id"].stringValue, referenced.contains(id), source["subscription"].objectValue != nil else { return false }
            return previousHashes[id] != currentHashes[id]
        }
        guard !changed.isEmpty else { return input }
        let alreadyBusy = isBusy
        isBusy = true
        defer { isBusy = alreadyBusy }
        var didCommit = false
        for source in changed {
            guard let id = source["id"].stringValue else { continue }
            let prepared = try await configurationService.prepareSourceActivation(sourceID: id,
                nodesOnly: source["subscription"]["nodes-only"].boolValue ?? false)
            if !(prepared.change["patch"]?.arrayValue ?? []).isEmpty {
                _ = try await configurationService.commit(prepared)
                didCommit = true
            }
        }
        return didCommit ? try await client.call("GetConfiguration") : input
    }

    static func parseDate(_ value: String?) -> Date? {
        guard let value, !value.hasPrefix("0001-") else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let result = formatter.date(from: value) { return result }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: value)
    }
}
