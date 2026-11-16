import Foundation

/// Visual editors describe small structural changes. Kernel validation remains
/// authoritative, and source changes are retained as explicit user overlays.
enum VisualConfigurationService {
    static func group(id: String, documents: [ConfigurationLayer: String], effective: JSONValue) throws -> EditableResource {
        try resource(kind: "groups", id: id, documents: documents, effective: effective)
    }

    static func resource(kind: String, id: String, documents: [ConfigurationLayer: String], effective: JSONValue) throws -> EditableResource {
        guard ["groups", "outbounds"].contains(kind) else { throw ClientError.message("不支持的资源类型。") }
        let profile = try YAMLDocument.object(documents[.profile] ?? "")
        let own = profile[kind]?.arrayValue ?? []
        var definition: [String: JSONValue]?
        let ownIndex = own.firstIndex { $0["id"].stringValue == id }
        if let ownIndex { definition = own[ownIndex].objectValue }
        if definition == nil, let slash = id.firstIndex(of: "/") {
            let sourceID = String(id[..<slash]), localID = String(id[id.index(after: slash)...])
            let sources = try YAMLDocument.array(documents[.sources] ?? "", key: "sources")
            if let source = sources.first(where: { $0["id"].stringValue == sourceID }),
               var raw = source[kind].arrayValue?.first(where: { $0["id"].stringValue == localID })?.objectValue {
                raw["id"] = .string(id)
                if kind == "groups" {
                    if let members = raw["members"]?.arrayValue {
                        raw["members"] = .array(members.map { .string(scoped($0.stringValue ?? "", source: sourceID, definition: source)) })
                    }
                    if let selected = raw["selected"]?.stringValue, !selected.isEmpty {
                        raw["selected"] = .string(scoped(selected, source: sourceID, definition: source))
                    }
                }
                definition = raw
            }
        }
        let overlay = try overlayOperations(documents)
        let path = "/\(kind)/\(escape(id))"
        for operation in overlay {
            let op = operation["op"].stringValue, target = operation["path"].stringValue ?? ""
            if op == "insert", target == "/\(kind)", operation["value"]["id"].stringValue == id {
                definition = operation["value"].objectValue
            } else if target == path {
                if op == "remove" { definition = nil }
                if op == "set" { definition = operation["value"].objectValue }
            } else if target.hasPrefix(path + "/"), let current = definition {
                let segments = pointer(String(target.dropFirst(path.count)))
                definition = try (op == "insert" ? insert(.object(current), segments: segments, operation: operation) : edit(.object(current), segments: segments, value: operation["value"], remove: op == "remove")).objectValue
            }
        }
        guard let definition else { throw ClientError.message("该资源没有可编辑定义，内置直连和拒绝动作不需要编辑。") }
        return EditableResource(id: id, definition: definition, isImported: ownIndex == nil, collection: kind, profileIndex: ownIndex)
    }

    static func groupChange(resource: EditableResource?, value: [String: JSONValue], baseRevision: Int, documents: [ConfigurationLayer: String]) throws -> [String: JSONValue] {
        try resourceChange(kind: "groups", resource: resource, value: value, baseRevision: baseRevision, documents: documents)
    }

    static func removeGroupChange(resource: EditableResource, baseRevision: Int, documents: [ConfigurationLayer: String]) throws -> [String: JSONValue] {
        try removeResourceChange(resource: resource, baseRevision: baseRevision, documents: documents)
    }

    static func moveGroupChange(resource: EditableResource, direction: Int, baseRevision: Int, documents: [ConfigurationLayer: String]) throws -> [String: JSONValue] {
        let groups = try YAMLDocument.array(documents[.profile] ?? "", key: "groups")
        guard let index = resource.profileIndex, abs(direction) == 1, groups.indices.contains(index + direction),
              let target = groups[index + direction]["id"].stringValue,
              let original = groups[index].objectValue else { throw ClientError.message("来源策略组的顺序由来源管理，或已到达列表边界。") }
        var insertion = op("insert", "/groups", .object(original)).objectValue!
        insertion[direction < 0 ? "before" : "after"] = .string(target)
        return ["base_revision": .number(Double(baseRevision)), "patch": .array([
            op("remove", "/groups/\(escape(resource.id))"), .object(insertion)
        ])]
    }

    static func resourceChange(kind: String, resource: EditableResource?, value: [String: JSONValue], baseRevision: Int, documents: [ConfigurationLayer: String]) throws -> [String: JSONValue] {
        var change: [String: JSONValue] = ["base_revision": .number(Double(baseRevision))]
        guard let resource else {
            guard let id = value["id"]?.stringValue, validID(id) else { throw ClientError.message("标识需以字母或数字开头，长度不超过 64，只能包含字母、数字、点、横线和下划线。") }
            change["patch"] = .array([op("insert", "/\(kind)", .object(value))])
            return change
        }
        guard value["id"]?.stringValue == resource.id else { throw ClientError.message("已有资源的标识不能直接修改。") }
        var value = value
        if kind == "groups", resource.id == "proxy", value["members"] != resource.definition["members"],
           value["include-all"]?.boolValue != true {
            // An explicit visual member list is a manual policy. Background
            // source reconciliation must not add excluded members back.
            value["include-all"] = .bool(false)
        }
        let root = "/\(kind)/\(escape(resource.id))"
        var profileEdits: [JSONValue] = [], overlayEdits: [JSONValue] = []
        var overlay = try overlayOperations(documents)
        for difference in differences(resource.definition, value, path: root) {
            if resource.isImported || overlay.contains(where: { pathsOverlap(difference.path, $0["path"].stringValue ?? "") }) {
                upsertOverlay(path: difference.path, value: difference.value, remove: difference.remove, overlay: &overlay, edits: &overlayEdits)
            } else { profileEdits.append(op(difference.remove ? "remove" : "set", difference.path, difference.remove ? nil : difference.value)) }
        }
        if !profileEdits.isEmpty { change["patch"] = .array(profileEdits) }
        if !overlayEdits.isEmpty { change["overlay_patch"] = .array(overlayEdits) }
        return change
    }

    static func removeResourceChange(resource: EditableResource, baseRevision: Int, documents: [ConfigurationLayer: String]) throws -> [String: JSONValue] {
        let path = "/\(resource.collection)/\(escape(resource.id))"
        if resource.isImported {
            return ["base_revision": .number(Double(baseRevision)), "overlay_patch": .array([op("insert", "/patches", .object(["op": .string("remove"), "path": .string(path)]))])]
        }
        let overlay = try overlayOperations(documents)
        let removals = overlay.indices.reversed().filter { index in
            let p = overlay[index]["path"].stringValue ?? ""
            return p == path || p.hasPrefix(path + "/")
        }.map { op("remove", "/patches/#\($0)") }
        var change: [String: JSONValue] = ["base_revision": .number(Double(baseRevision)), "patch": .array([op("remove", path)])]
        if !removals.isEmpty { change["overlay_patch"] = .array(removals) }
        return change
    }

    static func rules(documents: [ConfigurationLayer: String], effective: JSONValue) throws -> [RuleRecord] {
        let raw = try YAMLDocument.array(documents[.profile] ?? "", key: "rules")
        let sources = try YAMLDocument.array(documents[.sources] ?? "", key: "sources")
        var records: [RuleRecord] = []
        for (index, value) in raw.enumerated() {
            guard let definition = value.objectValue else { continue }
            if let sourceID = definition["source"]?.stringValue {
                records.append(RuleRecord(id: "marker:\(index):\(sourceID)", definition: definition, origin: "来源规则块 · \(sourceID)", sourceID: sourceID, profileIndex: index, sourceMarker: true, editable: true, movable: true, number: 0))
                if let source = sources.first(where: { $0["id"].stringValue == sourceID }) {
                    for item in source["rules"].arrayValue ?? [] {
                        guard var rule = item.objectValue, let id = rule["id"]?.stringValue else { continue }
                        rule["id"] = .string(sourceID + "/" + id)
                        if let outbound = rule["outbound"]?.stringValue { rule["outbound"] = .string(scoped(outbound, source: sourceID, definition: source)) }
                        if let call = rule["call"]?.stringValue { rule["call"] = .string(sourceID + "/" + call) }
                        if let match = rule["match"] { rule["match"] = scopedMatch(match, source: sourceID) }
                        records.append(RuleRecord(id: sourceID + "/" + id, definition: rule, origin: "来源 · \(sourceID)", sourceID: sourceID, profileIndex: nil, sourceMarker: false, editable: true, movable: false, number: 0))
                    }
                }
            } else {
                let id = definition["id"]?.stringValue ?? "#\(index)"
                records.append(RuleRecord(id: "profile:\(id)", definition: definition, origin: "主配置", sourceID: nil, profileIndex: index, sourceMarker: false, editable: true, movable: true, number: 0))
            }
        }
        for operation in try overlayOperations(documents) {
            let action = operation["op"].stringValue ?? ""
            let path = operation["path"].stringValue ?? ""
            if action == "insert", path == "/rules", let rule = operation["value"].objectValue, let id = rule["id"]?.stringValue {
                let record = RuleRecord(id: "overlay:" + id, definition: rule, origin: "用户覆盖", sourceID: nil, profileIndex: nil, sourceMarker: false, editable: true, movable: false, number: 0)
                var at = records.count
                if let before = operation["before"].stringValue, let found = records.firstIndex(where: { $0.definition["id"]?.stringValue == before }) { at = found }
                else if let after = operation["after"].stringValue, let found = records.firstIndex(where: { $0.definition["id"]?.stringValue == after }) { at = found + 1 }
                records.insert(record, at: at)
                continue
            }
            let segments = pointer(path)
            guard segments.count >= 2, segments[0] == "rules" else { continue }
            let key = segments[1]
            guard let index = records.firstIndex(where: { !$0.sourceMarker && ($0.definition["id"]?.stringValue == key || (key.hasPrefix("#") && $0.profileIndex == Int(key.dropFirst()) && $0.sourceID == nil)) }) else { continue }
            if segments.count == 2 {
                if action == "remove" { records.remove(at: index) }
                else if action == "set", let definition = operation["value"].objectValue { records[index].definition = definition }
            } else {
                let rest = Array(segments.dropFirst(2))
                let current = JSONValue.object(records[index].definition)
                records[index].definition = try (action == "insert" ? insert(current, segments: rest, operation: operation) : edit(current, segments: rest, value: operation["value"], remove: action == "remove")).objectValue ?? records[index].definition
            }
        }
        for index in records.indices { records[index].number = index + 1 }
        return records
    }

    static func ruleChange(definition: [String: JSONValue], record: RuleRecord?, baseRevision: Int, documents: [ConfigurationLayer: String]) throws -> [String: JSONValue] {
        var change: [String: JSONValue] = ["base_revision": .number(Double(baseRevision))]
        if let record, let index = record.profileIndex {
            let key = record.definition["id"]?.stringValue.map(escape) ?? "#\(index)"
            var edits: [JSONValue] = [], overlayEdits: [JSONValue] = []
            var overlay = try overlayOperations(documents)
            for diff in differences(record.definition, definition, path: "/rules/\(key)", ignoreID: false) {
                if overlay.contains(where: { pathsOverlap(diff.path, $0["path"].stringValue ?? "") }) {
                    upsertOverlay(path: diff.path, value: diff.value, remove: diff.remove, overlay: &overlay, edits: &overlayEdits)
                } else { edits.append(op(diff.remove ? "remove" : "set", diff.path, diff.remove ? nil : diff.value)) }
            }
            if !edits.isEmpty { change["patch"] = .array(edits) }
            if !overlayEdits.isEmpty { change["overlay_patch"] = .array(overlayEdits) }
        } else if let record {
            guard let id = record.definition["id"]?.stringValue, definition["id"]?.stringValue == id else { throw ClientError.message("来源规则的标识不能更改。") }
            var overlay = try overlayOperations(documents), edits: [JSONValue] = []
            for diff in differences(record.definition, definition, path: "/rules/\(escape(id))") {
                upsertOverlay(path: diff.path, value: diff.value, remove: diff.remove, overlay: &overlay, edits: &edits)
            }
            if !edits.isEmpty { change["overlay_patch"] = .array(edits) }
        } else {
            var definition = definition
            if definition["id"]?.stringValue?.isEmpty != false { definition["id"] = .string("rule-" + String(UUID().uuidString.prefix(12)).lowercased()) }
            let rules = try YAMLDocument.array(documents[.profile] ?? "", key: "rules")
            var insertion = op("insert", "/rules", .object(definition)).objectValue!
            if let index = rules.firstIndex(where: { $0["source"].stringValue != nil || $0["match"]["all"].boolValue == true }) {
                insertion["before"] = .string(rules[index]["id"].stringValue ?? "#\(index)")
            }
            change["patch"] = .array([.object(insertion)])
        }
        return change
    }

    static func removeRuleChange(_ record: RuleRecord, baseRevision: Int, documents: [ConfigurationLayer: String]) throws -> [String: JSONValue] {
        if let index = record.profileIndex {
            let path = "/rules/\(record.definition["id"]?.stringValue.map(escape) ?? "#\(index)")"
            var change: [String: JSONValue] = ["base_revision": .number(Double(baseRevision)), "patch": .array([op("remove", path)])]
            let overlay = try overlayOperations(documents)
            let removals = overlay.indices.reversed().filter { let p = overlay[$0]["path"].stringValue ?? ""; return p == path || p.hasPrefix(path + "/") }.map { op("remove", "/patches/#\($0)") }
            if !removals.isEmpty { change["overlay_patch"] = .array(removals) }
            return change
        }
        guard let id = record.definition["id"]?.stringValue else { throw ClientError.message("规则标识缺失。") }
        return ["base_revision": .number(Double(baseRevision)), "overlay_patch": .array([op("insert", "/patches", .object(["op": .string("remove"), "path": .string("/rules/\(escape(id))")]))])]
    }

    static func moveRuleChange(_ record: RuleRecord, direction: Int, baseRevision: Int, documents: [ConfigurationLayer: String]) throws -> [String: JSONValue] {
        let rules = try YAMLDocument.array(documents[.profile] ?? "", key: "rules")
        guard let index = record.profileIndex, abs(direction) == 1, rules.indices.contains(index + direction) else { throw ClientError.message("该规则不能继续移动。") }
        let target = index + direction
        var moved = rules[index].objectValue ?? [:], edits: [JSONValue] = []
        let movedID = moved["id"]?.stringValue ?? "rule-" + String(UUID().uuidString.prefix(12)).lowercased()
        if moved["id"] == nil { edits.append(op("set", "/rules/#\(index)/id", .string(movedID))); moved["id"] = .string(movedID) }
        let targetID = rules[target]["id"].stringValue ?? "rule-" + String(UUID().uuidString.prefix(12)).lowercased()
        if rules[target]["id"].stringValue == nil { edits.append(op("set", "/rules/#\(target)/id", .string(targetID))) }
        edits.append(op("remove", "/rules/\(escape(movedID))"))
        var insert = op("insert", "/rules", .object(moved)).objectValue!
        insert[direction < 0 ? "before" : "after"] = .string(targetID)
        edits.append(.object(insert))
        return ["base_revision": .number(Double(baseRevision)), "patch": .array(edits)]
    }

    private struct Difference { let path: String; let value: JSONValue; let remove: Bool }
    private static func differences(_ original: [String: JSONValue], _ changed: [String: JSONValue], path: String, ignoreID: Bool = true) -> [Difference] {
        var result: [Difference] = []
        for key in Set(original.keys).union(changed.keys).sorted() where !ignoreID || key != "id" {
            guard original[key] != changed[key] else { continue }
            let field = path + "/" + escape(key)
            if let old = original[key]?.objectValue, let new = changed[key]?.objectValue {
                result += differences(old, new, path: field, ignoreID: false)
            } else { result.append(Difference(path: field, value: changed[key] ?? .null, remove: changed[key] == nil)) }
        }
        return result
    }

    private static func upsertOverlay(path: String, value: JSONValue, remove: Bool, overlay: inout [JSONValue], edits: inout [JSONValue]) {
        if let index = overlay.lastIndex(where: { $0["path"].stringValue == path && $0["op"].stringValue == (remove ? "remove" : "set") }),
           !overlay.dropFirst(index + 1).contains(where: { pathsOverlap(path, $0["path"].stringValue ?? "") }) {
            if !remove {
                edits.append(op("set", "/patches/#\(index)/value", value))
                var object = overlay[index].objectValue!; object["value"] = value; overlay[index] = .object(object)
            }
        } else {
            let entry = op(remove ? "remove" : "set", path, remove ? nil : value)
            edits.append(op("insert", "/patches", entry)); overlay.append(entry)
        }
    }

    /// A change to a collection and an override of one of its children overlap
    /// in either direction. Updating an earlier parent set would otherwise let
    /// a later child override silently undo the visual form's new value.
    private static func pathsOverlap(_ left: String, _ right: String) -> Bool {
        guard !left.isEmpty, !right.isEmpty else { return false }
        return left == right || left.hasPrefix(right + "/") || right.hasPrefix(left + "/")
    }

    private static func scoped(_ target: String, source: String, definition: JSONValue) -> String {
        if target.isEmpty || target.hasPrefix(source + "/") { return target }
        let local = (definition["outbounds"].arrayValue ?? []) + (definition["groups"].arrayValue ?? [])
        if ["direct", "reject"].contains(target), !local.contains(where: { $0["id"].stringValue == target }) { return target }
        return source + "/" + target
    }
    private static func scopedMatch(_ match: JSONValue, source: String) -> JSONValue {
        guard var object = match.objectValue else { return match }
        if let value = object["rule-set"] {
            if let string = value.stringValue { object["rule-set"] = .string(source + "/" + string) }
            if let values = value.arrayValue { object["rule-set"] = .array(values.map { .string(source + "/" + ($0.stringValue ?? "")) }) }
        }
        for key in ["and", "or", "not"] {
            if let children = object[key]?.arrayValue { object[key] = .array(children.map { scopedMatch($0, source: source) }) }
            else if let child = object[key], child.objectValue != nil { object[key] = scopedMatch(child, source: source) }
        }
        return .object(object)
    }
    private static func overlayOperations(_ documents: [ConfigurationLayer: String]) throws -> [JSONValue] { try YAMLDocument.array(documents[.overlay] ?? "", key: "patches") }
    private static func validID(_ id: String) -> Bool { id.range(of: #"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"#, options: .regularExpression) != nil }
    private static func escape(_ value: String) -> String { ConfigurationService.escape(value) }
    private static func pointer(_ path: String) -> [String] { path.split(separator: "/").map { String($0).replacingOccurrences(of: "~1", with: "/").replacingOccurrences(of: "~0", with: "~") } }
    private static func op(_ action: String, _ path: String, _ value: JSONValue? = nil) -> JSONValue {
        var object: [String: JSONValue] = ["op": .string(action), "path": .string(path)]
        if let value { object["value"] = value }
        return .object(object)
    }
    private static func edit(_ input: JSONValue, segments: [String], value: JSONValue, remove: Bool) throws -> JSONValue {
        guard let first = segments.first else { return remove ? .null : value }
        let remaining = Array(segments.dropFirst())
        if var array = input.arrayValue {
            let index = Int(first.hasPrefix("#") ? String(first.dropFirst()) : first)
                ?? array.firstIndex(where: { $0["id"].stringValue == first })
            guard let index, array.indices.contains(index) else { return input }
            if remaining.isEmpty, remove { array.remove(at: index) }
            else { array[index] = try edit(array[index], segments: remaining, value: value, remove: remove) }
            return .array(array)
        }
        var object = input.objectValue ?? [:]
        if remaining.isEmpty, remove { object.removeValue(forKey: first) }
        else { object[first] = try edit(object[first] ?? .object([:]), segments: remaining, value: value, remove: remove) }
        return .object(object)
    }
    private static func insert(_ input: JSONValue, segments: [String], operation: JSONValue) throws -> JSONValue {
        guard let first = segments.first else {
            var values = input.arrayValue ?? []
            var index = values.count
            for (key, offset) in [("before", 0), ("after", 1)] {
                guard let target = operation[key].stringValue else { continue }
                let found = target.hasPrefix("#") ? Int(target.dropFirst()) : values.firstIndex { $0["id"].stringValue == target }
                if let found { index = min(values.count, max(0, found + offset)) }
            }
            values.insert(operation["value"], at: index)
            return .array(values)
        }
        let rest = Array(segments.dropFirst())
        if var values = input.arrayValue {
            let index = first.hasPrefix("#") ? Int(first.dropFirst()) : values.firstIndex { $0["id"].stringValue == first }
            guard let index, values.indices.contains(index) else { return input }
            values[index] = try insert(values[index], segments: rest, operation: operation)
            return .array(values)
        }
        var object = input.objectValue ?? [:]
        object[first] = try insert(object[first] ?? .array([]), segments: rest, operation: operation)
        return .object(object)
    }
}
