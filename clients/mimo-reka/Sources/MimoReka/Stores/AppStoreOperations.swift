import Foundation

extension AppStore {
    func supportsMethod(_ name: String) -> Bool {
        (capabilities["methods"].arrayValue ?? []).contains(.string(name))
    }
    var routingMode: String { effectiveConfiguration["routing"]["mode"].stringValue ?? "rule" }
    var globalRoutingTarget: String { effectiveConfiguration["routing"]["global"].stringValue ?? "" }
    static func routingTitle(_ mode: String) -> String {
        switch mode { case "global": "全局"; case "direct": "直连"; default: "规则" }
    }

    /// Independent bounded reads. A transient optional operation cannot make the
    /// main control connection appear offline or overwrite a configuration error.
    func refreshLiveOperations() async {
        let session = operations.session, profile = activeProfileID, control = client
        guard isOnline, operations.refreshSession != session else { return }
        operations.refreshSession = session
        defer { if operations.refreshSession == session { operations.refreshSession = nil } }
        if supportsMethod("GetTraffic") {
            do {
                let value = try await control.call("GetTraffic")
                guard session == operations.session, profile == activeProfileID, isOnline else { return }
                guard let sample = TrafficSample(value: value) else { throw ClientError.message("内核返回的流量采样无效。") }
                operations.acceptTraffic(sample)
            } catch {
                if session == operations.session { operations.trafficError = error.localizedDescription }
            }
        }
        if supportsMethod("GetLogs") {
            do {
                let value = try await control.call("GetLogs", params: ["limit": .number(256)])
                guard session == operations.session, profile == activeProfileID, isOnline else { return }
                operations.logs = (value["events"].arrayValue ?? []).compactMap(CoreLogRow.init(event:))
                operations.logsError = nil
            } catch {
                if session == operations.session { operations.logsError = error.localizedDescription }
            }
        }
    }

    func probeOutbound(_ id: String) async {
        guard isOnline, supportsMethod("ProbeOutbound"), !operations.probing.contains(id) else { return }
        let session = operations.session, profile = activeProfileID
        let url = operations.probeURL.trimmingCharacters(in: .whitespacesAndNewlines)
        let timeout = operations.probeTimeoutMS
        operations.probing.insert(id)
        defer { if session == operations.session { operations.probing.remove(id) } }
        do {
            guard let parsed = URL(string: url), ["http", "https"].contains(parsed.scheme?.lowercased() ?? ""),
                  parsed.host != nil, parsed.user == nil, parsed.password == nil else {
                throw ClientError.message("测试地址需要是无账号密码的 HTTP(S) URL。")
            }
            let control = RekaControlClient(socketPath: kernel.socketPath, timeout: Double(timeout) / 1000 + 3)
            let result = try await control.call("ProbeOutbound", params: ["outbound": .string(id), "url": .string(url), "timeout_ms": .number(Double(timeout))])
            guard session == operations.session, profile == activeProfileID, isOnline else { return }
            operations.probes[id] = ProbeObservation(delayMS: result["delay_ms"].intValue,
                resolvedOutbound: result["resolved_outbound"].stringValue, checkedAt: Date())
        } catch {
            if session == operations.session, profile == activeProfileID {
                operations.probes[id] = ProbeObservation(error: error.localizedDescription, checkedAt: Date())
            }
        }
    }

    func previewRoutingMode(_ mode: String, global: String, baseRevision: Int) async {
        guard supportsMethod("GetRules") else { errorMessage = "当前内核不支持切换路由模式。"; return }
        var routing: [String: JSONValue] = ["mode": .string(mode)]
        if mode == "global" { routing["global"] = .string(global) }
        await previewVisualChange(["base_revision": .number(Double(baseRevision)), "local_patch": .array([
            .object(["op": .string("set"), "path": .string("/routing"), "value": .object(routing)])
        ])], summary: "路由模式 · \(Self.routingTitle(mode))")
    }
}
