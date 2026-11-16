import Foundation

/// A form draft retains the original rule so editing its target cannot flatten
/// a logical condition or remove fields the form does not expose.
struct RuleDraft: Equatable {
    var ruleID: String
    var condition: String
    var valuesText: String
    var noResolve: Bool
    var outbound: String
    var call: String
    var action: String
    var sourceMarker: String
    var isSourceMarker: Bool
    var replaceComplexMatch = false
    let originalDefinition: [String: JSONValue]
    private let originalCondition: String
    private let originalValuesText: String
    private let originalNoResolve: Bool
    private let isNew: Bool

    init(definition: [String: JSONValue] = [:], sourceMarker: Bool = false) {
        originalDefinition = definition
        isNew = definition.isEmpty
        ruleID = definition["id"]?.stringValue ?? (definition.isEmpty ? "rule-" + UUID().uuidString.prefix(12).lowercased() : "")
        let match = definition["match"]?.objectValue ?? [:]
        let kind = match.keys.first(where: { $0 != "no-resolve" }) ?? "domain-suffix"
        condition = kind
        originalCondition = kind
        let value = match[kind]
        let text: String
        if kind == "all" { text = "" }
        else if let array = value?.arrayValue { text = array.map(Self.text).joined(separator: "\n") }
        else { text = value.map(Self.text) ?? "" }
        valuesText = text
        originalValuesText = text
        noResolve = match["no-resolve"]?.boolValue ?? false
        originalNoResolve = noResolve
        outbound = definition["outbound"]?.stringValue ?? "direct"
        call = definition["call"]?.stringValue ?? ""
        action = (definition["call"]?.stringValue ?? "").isEmpty ? "outbound" : "call"
        self.sourceMarker = definition["source"]?.stringValue ?? ""
        isSourceMarker = sourceMarker || definition["source"]?.stringValue != nil
    }

    var hasComplexMatch: Bool {
        !Self.simpleConditions.contains(originalCondition) || ["and", "or", "not"].contains(originalCondition)
    }
    var preservesComplexMatch: Bool { hasComplexMatch && !replaceComplexMatch }
    var supportsNoResolve: Bool { ["ip-cidr", "geoip", "rule-set"].contains(condition) }

    func definition() throws -> [String: JSONValue] {
        var result = originalDefinition
        if isNew {
            let value = ruleID.trimmingCharacters(in: .whitespacesAndNewlines)
            guard value.range(of: #"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"#, options: .regularExpression) != nil else {
                throw ClientError.message("规则标识只能使用字母、数字、点、下划线或连字符，且不超过 64 字符。")
            }
            result["id"] = .string(value)
        }
        if isSourceMarker {
            guard !sourceMarker.isEmpty else { throw ClientError.message("请选择规则来源。") }
            result["source"] = .string(sourceMarker)
            result.removeValue(forKey: "match")
            result.removeValue(forKey: "outbound")
            result.removeValue(forKey: "call")
            return result
        }
        result.removeValue(forKey: "source")
        let matchUnchanged = originalDefinition["match"] != nil && condition == originalCondition
            && valuesText == originalValuesText && noResolve == originalNoResolve && !replaceComplexMatch
        if !preservesComplexMatch && !matchUnchanged {
            var match: [String: JSONValue] = [:]
            if condition == "all" { match["all"] = .bool(true) }
            else {
                let isRegex = condition.contains("regex")
                let values = valuesText.components(separatedBy: .newlines).map {
                    isRegex ? $0 : $0.trimmingCharacters(in: .whitespacesAndNewlines)
                }.filter { !$0.isEmpty }
                guard !values.isEmpty else { throw ClientError.message("请输入至少一个匹配值。") }
                match[condition] = values.count == 1 ? .string(values[0]) : .array(values.map(JSONValue.string))
                if supportsNoResolve && noResolve { match["no-resolve"] = .bool(true) }
            }
            result["match"] = .object(match)
        }
        if action == "call" {
            let target = call.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !target.isEmpty else { throw ClientError.message("请选择子规则。") }
            result["call"] = .string(target)
            result.removeValue(forKey: "outbound")
        } else {
            guard !outbound.isEmpty else { throw ClientError.message("请选择规则出口。") }
            result["outbound"] = .string(outbound)
            result.removeValue(forKey: "call")
        }
        return result
    }

    static let simpleConditions = ["domain", "domain-suffix", "domain-keyword", "domain-regex", "domain-pattern", "ip-cidr", "src-ip-cidr", "dst-port", "src-port", "network", "process-name", "process-name-regex", "rule-set", "geoip", "all"]
    static func title(_ condition: String) -> String {
        switch condition {
        case "domain": "完整域名"
        case "domain-suffix": "域名后缀"
        case "domain-keyword": "域名关键词"
        case "domain-regex": "域名正则"
        case "domain-pattern": "域名通配符"
        case "ip-cidr": "目标 IP 网段"
        case "src-ip-cidr": "来源 IP 网段"
        case "dst-port": "目标端口"
        case "src-port": "来源端口"
        case "network": "网络协议"
        case "process-name": "进程名称"
        case "process-name-regex": "进程正则"
        case "rule-set": "规则集"
        case "geoip": "本地网络分类"
        case "all": "全部流量（MATCH）"
        default: condition
        }
    }
    static func example(_ condition: String) -> String {
        switch condition {
        case "domain", "domain-suffix": "example.com"
        case "domain-keyword": "example"
        case "domain-regex": #"(^|\.)example\.com$"#
        case "domain-pattern": "*.example.com"
        case "ip-cidr", "src-ip-cidr": "192.168.0.0/16"
        case "dst-port", "src-port": "443\n8000-8080"
        case "network": "tcp\nudp"
        case "process-name": "Safari"
        case "process-name-regex": "(?i)safari"
        case "rule-set": "规则集 ID"
        case "geoip": "LAN"
        default: ""
        }
    }
    private static func text(_ value: JSONValue) -> String {
        value.stringValue ?? value.numberValue.map { $0.rounded() == $0 ? String(Int($0)) : String($0) } ?? value.prettyPrinted
    }
}
