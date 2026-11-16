import Foundation

extension AppStore {
    var effectiveConfiguration: JSONValue { snapshot["effective"] }
    var ruleRecords: [RuleRecord] { (try? VisualConfigurationService.rules(documents: documents, effective: effectiveConfiguration)) ?? [] }

    func previewVisualChange(_ change: [String: JSONValue], summary: String) async {
        await perform {
            self.preparedChange = nil
            self.pendingSourceName = nil
            if !self.kernel.isPrivileged {
                let local = change["local"]?.stringValue.flatMap { try? YAMLDocument.object($0) }
                if let mode = local?["network"]?["mode"].stringValue, mode != "off" {
                    throw ClientError.message("请先在网络设置中授权开启接管，再调整网络参数。")
                }
                for item in change["local_patch"]?.arrayValue ?? [] where item["path"].stringValue == "/network" {
                    if item["value"]["mode"].stringValue != "off" { throw ClientError.message("请在网络设置中主动授权开启接管。") }
                }
            }
            self.preparedChange = try await self.configurationService.prepare(change, summary: summary)
        }
    }
    func previewResource(kind: String, id: String?, definition: [String: JSONValue], baseRevision: Int) async {
        do {
            let resource = try id.map { try VisualConfigurationService.resource(kind: kind, id: $0, documents: documents, effective: effectiveConfiguration) }
            let change = try VisualConfigurationService.resourceChange(kind: kind, resource: resource, value: definition, baseRevision: baseRevision, documents: documents)
            await previewVisualChange(change, summary: id == nil ? "新增节点" : "编辑节点")
        } catch { preparedChange = nil; errorMessage = error.localizedDescription }
    }
    func removeResource(kind: String, id: String, baseRevision: Int) async {
        do {
            let resource = try VisualConfigurationService.resource(kind: kind, id: id, documents: documents, effective: effectiveConfiguration)
            let change = try VisualConfigurationService.removeResourceChange(resource: resource, baseRevision: baseRevision, documents: documents)
            await previewVisualChange(change, summary: "删除节点")
        } catch { preparedChange = nil; errorMessage = error.localizedDescription }
    }
    func previewRule(definition: [String: JSONValue], record: RuleRecord?, baseRevision: Int) async {
        do {
            let change = try VisualConfigurationService.ruleChange(definition: definition, record: record, baseRevision: baseRevision, documents: documents)
            await previewVisualChange(change, summary: record == nil ? "新增规则" : "编辑规则")
        } catch { preparedChange = nil; errorMessage = error.localizedDescription }
    }
    func removeRule(_ record: RuleRecord, baseRevision: Int) async {
        do {
            let change = try VisualConfigurationService.removeRuleChange(record, baseRevision: baseRevision, documents: documents)
            await previewVisualChange(change, summary: "删除规则")
        } catch { preparedChange = nil; errorMessage = error.localizedDescription }
    }
    func moveRule(_ record: RuleRecord, direction: Int, baseRevision: Int) async {
        do {
            let change = try VisualConfigurationService.moveRuleChange(record, direction: direction, baseRevision: baseRevision, documents: documents)
            await previewVisualChange(change, summary: direction < 0 ? "上移规则" : "下移规则")
        } catch { preparedChange = nil; errorMessage = error.localizedDescription }
    }
}
