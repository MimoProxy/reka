import Foundation

extension AppStore {
    var processMode: String { effectiveConfiguration["process"]["mode"].stringValue ?? "rule" }
    static func processModeTitle(_ mode: String) -> String {
        switch mode { case "always": "所有新连接"; case "off": "关闭"; default: "按规则需要" }
    }
    func refreshProcessTraffic(offset: Int? = nil) async {
        guard isOnline, supportsMethod("GetProcessTraffic") else { return }
        let session = operations.session, profile = activeProfileID, requested = offset ?? operations.processOffset
        let request = UUID()
        operations.processRequest = request
        do {
            let result = try await client.call("GetProcessTraffic", params: ["offset": .number(Double(requested)), "limit": .number(100)])
            guard session == operations.session, profile == activeProfileID, request == operations.processRequest, isOnline else { return }
            operations.processRows = (result["rows"].arrayValue ?? []).compactMap(ProcessTrafficRow.init(value:))
            operations.processOffset = requested; operations.processTotal = result["total"].intValue ?? 0
            operations.processEpoch = result["epoch"].stringValue ?? ""; operations.processError = nil
        } catch { if session == operations.session, request == operations.processRequest { operations.processError = error.localizedDescription } }
    }
    @discardableResult
    func previewProcessMode(_ mode: String, revision: Int, save: Bool = false) async -> Bool {
        return await previewVisualChange(["base_revision": .number(Double(revision)), "local_patch": .array([
            .object(["op": .string("set"), "path": .string("/process"), "value": .object(["mode": .string(mode)])])
        ])], summary: "进程识别 · " + Self.processModeTitle(mode), save: save)
    }
}
