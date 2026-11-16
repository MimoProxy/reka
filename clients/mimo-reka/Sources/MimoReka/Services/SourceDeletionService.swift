import Foundation

/// Remove a source and its import wiring in one version-bound transaction.
/// Custom routing/DNS references remain subject to the kernel's validation.
enum SourceDeletionService {
    static func change(sourceID: String, revision: Int, documents: [ConfigurationLayer: String], effective: JSONValue) throws -> [String: JSONValue] {
        let sources = try YAMLDocument.array(documents[.sources] ?? "", key: "sources")
        guard sources.contains(where: { $0["id"].stringValue == sourceID }) else { throw ClientError.message("来源已不存在，请刷新列表。") }
        let profile = try YAMLDocument.object(documents[.profile] ?? "")
        let overlay = try YAMLDocument.array(documents[.overlay] ?? "", key: "patches")
        let owns: (String) -> Bool = { $0.hasPrefix(sourceID + "/") }
        var patch: [JSONValue] = [], overlayEdits: [JSONValue] = [], additions: [JSONValue] = []
        var removed = Set<Int>()
        let imports = profile["imports"]?.arrayValue ?? []
        for index in imports.indices.reversed() where imports[index]["source"].stringValue == sourceID {
            patch.append(op("remove", "/imports/#\(index)"))
        }
        let rules = profile["rules"]?.arrayValue ?? []
        let markers = Set(rules.filter { $0["source"].stringValue == sourceID }.compactMap { $0["id"].stringValue })
        for index in rules.indices.reversed() where rules[index]["source"].stringValue == sourceID {
            patch.append(op("remove", "/rules/#\(index)"))
        }
        let collections = Set(["outbounds", "groups", "rules", "rule-sets", "sub-rules"])
        for (index, entry) in overlay.enumerated() {
            let path = pointer(entry["path"].stringValue ?? "")
            if path.count >= 2, collections.contains(path[0]), owns(path[1]) || (path[0] == "rules" && markers.contains(path[1])) {
                removed.insert(index)
            }
        }

        let groups = profile["groups"]?.arrayValue ?? []
        var groupIDs = Set(groups.compactMap { $0["id"].stringValue })
        groupIDs.formUnion((effective["groups"].arrayValue ?? []).compactMap { $0["ID"].stringValue ?? $0["id"].stringValue })
        for id in groupIDs.sorted() where !owns(id) {
            let groupPath = "/groups/" + ConfigurationService.escape(id)
            let original = groups.first { $0["id"].stringValue == id }
            let relevant = overlay.indices.filter { index in
                guard !removed.contains(index) else { return false }
                let path = pointer(overlay[index]["path"].stringValue ?? "")
                return path.first == "groups" && ((path.count >= 2 && path[1] == id) || (path.count == 1 && overlay[index]["op"].stringValue == "insert" && overlay[index]["value"]["id"].stringValue == id))
            }
            guard let resource = try? VisualConfigurationService.group(id: id, documents: documents, effective: effective) else { continue }
            let definition = JSONValue.object(resource.definition)
            let affected = hasRemovedMember(original ?? .null, owns: owns) || hasRemovedMember(definition, owns: owns) || relevant.contains { index in
                let entry = overlay[index], path = pointer(entry["path"].stringValue ?? "")
                if path.count <= 2 { return hasRemovedMember(entry["value"], owns: owns) }
                return ["members", "selected"].contains(path[2]) && containsReference(entry["value"], owns: owns)
            }
            guard affected else { continue }
            if let original, hasRemovedMember(original, owns: owns) {
                let members = retainedMembers(original, owns: owns)
                patch.append(op("set", groupPath + "/members", .array(members.map(JSONValue.string))))
                if owns(original["selected"].stringValue ?? "") {
                    patch.append(op("set", groupPath + "/selected", .string(selection(original, members: members, owns: owns))))
                }
            }
            var membershipOverlay = false
            for index in relevant {
                let entry = overlay[index], path = pointer(entry["path"].stringValue ?? "")
                if path.count <= 2, entry["value"].objectValue != nil {
                    membershipOverlay = true
                    if hasRemovedMember(entry["value"], owns: owns) {
                        var replacement = entry["value"].objectValue ?? [:]
                        let members = retainedMembers(entry["value"], owns: owns)
                        replacement["members"] = .array(members.map(JSONValue.string))
                        if owns(replacement["selected"]?.stringValue ?? "") {
                            replacement["selected"] = .string(selection(entry["value"], members: members, owns: owns))
                        }
                        overlayEdits.append(op("set", "/patches/#\(index)/value", .object(replacement)))
                    }
                } else if path.count >= 3, ["members", "selected"].contains(path[2]) {
                    // Rebuild the final membership once, so indexed child edits
                    // cannot silently change meaning after a member is removed.
                    membershipOverlay = true; removed.insert(index)
                }
            }
            if membershipOverlay {
                let members = retainedMembers(definition, owns: owns)
                additions.append(op("set", groupPath + "/members", .array(members.map(JSONValue.string))))
                additions.append(op("set", groupPath + "/selected", .string(selection(definition, members: members, owns: owns))))
            }
        }
        for index in removed.sorted(by: >) { overlayEdits.append(op("remove", "/patches/#\(index)")) }
        overlayEdits += additions.map { op("insert", "/patches", $0) }
        var change: [String: JSONValue] = ["base_revision": .number(Double(revision)), "sources_patch": .array([
            op("remove", "/sources/" + ConfigurationService.escape(sourceID))
        ])]
        if !patch.isEmpty { change["patch"] = .array(patch) }
        if !overlayEdits.isEmpty { change["overlay_patch"] = .array(overlayEdits) }
        return change
    }

    private static func retainedMembers(_ group: JSONValue, owns: (String) -> Bool) -> [String] {
        let kept = (group["members"].arrayValue ?? []).compactMap(\.stringValue).filter { !owns($0) }
        return kept.isEmpty ? ["direct"] : kept
    }
    private static func selection(_ group: JSONValue, members: [String], owns: (String) -> Bool) -> String {
        if let selected = group["selected"].stringValue, !selected.isEmpty, !owns(selected) { return selected }
        return group["type"].stringValue == "select" ? (members.first ?? "direct") : ""
    }
    private static func hasRemovedMember(_ group: JSONValue, owns: (String) -> Bool) -> Bool {
        owns(group["selected"].stringValue ?? "") || (group["members"].arrayValue ?? []).contains { owns($0.stringValue ?? "") }
    }
    private static func containsReference(_ value: JSONValue, owns: (String) -> Bool) -> Bool {
        if let text = value.stringValue { return owns(text) }
        return (value.arrayValue ?? []).contains { containsReference($0, owns: owns) }
    }
    private static func pointer(_ path: String) -> [String] {
        path.split(separator: "/").map { $0.replacingOccurrences(of: "~1", with: "/").replacingOccurrences(of: "~0", with: "~") }
    }
    private static func op(_ operation: String, _ path: String, _ value: JSONValue? = nil) -> JSONValue {
        var fields: [String: JSONValue] = ["op": .string(operation), "path": .string(path)]
        if let value { fields["value"] = value }
        return .object(fields)
    }
}
