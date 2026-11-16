import Foundation

struct ListenerDraft: Identifiable, Equatable {
    let id: UUID
    var fields: [String: JSONValue]
    var identifier: String { get { fields["id"]?.stringValue ?? "" } set { fields["id"] = .string(newValue) } }
    var type: String { get { fields["type"]?.stringValue ?? "mixed" } set { fields["type"] = .string(newValue) } }
    var listen: String { get { fields["listen"]?.stringValue ?? "127.0.0.1:17891" } set { fields["listen"] = .string(newValue) } }
    var udp: Bool { get { fields["udp"]?.boolValue ?? true } set { fields["udp"] = .bool(newValue) } }
    init(fields: [String: JSONValue]) { id = UUID(); self.fields = fields }
}

struct ImportReferenceDraft: Identifiable, Equatable {
    let id: String
    let name: String
    var fields: [String: JSONValue]
    var enabled: Bool
    var outbounds: Bool { get { fields["outbounds"]?.boolValue ?? true } set { fields["outbounds"] = .bool(newValue) } }
    var ruleSets: Bool { get { fields["rule-sets"]?.boolValue ?? false } set { fields["rule-sets"] = .bool(newValue) } }
    var subRules: Bool { get { fields["sub-rules"]?.boolValue ?? false } set { fields["sub-rules"] = .bool(newValue) } }
    var groups: Bool { get { fields["groups"]?.boolValue ?? false } set { fields["groups"] = .bool(newValue) } }
}

/// The draft retains every original field. Controls change their own keys only.
struct VisualConfigurationDraft: Equatable {
    let profile: [String: JSONValue]
    let local: [String: JSONValue]
    var listeners: [ListenerDraft]
    var imports: [ImportReferenceDraft]
    var logLevel: String
    var dnsEnabled: Bool
    var dns: [String: JSONValue]
    let sniffLayer: ConfigurationLayer
    var sniff: [String: JSONValue]

    init(documents: [ConfigurationLayer: String], sourceNames: [String: String]) throws {
        profile = try YAMLDocument.object(documents[.profile] ?? "")
        local = try YAMLDocument.object(documents[.local] ?? "")
        listeners = (local["listeners"]?.arrayValue ?? []).compactMap { $0.objectValue }.map(ListenerDraft.init)
        logLevel = local["log"]?["level"].stringValue ?? "info"
        dnsEnabled = profile["dns"]?.objectValue != nil
        dns = profile["dns"]?.objectValue ?? [:]
        sniffLayer = local["sniff"] != nil ? .local : .profile
        sniff = (local["sniff"] ?? profile["sniff"])?.objectValue ?? [:]
        let current = profile["imports"]?.arrayValue ?? []
        imports = current.compactMap { value in
            guard let id = value["source"].stringValue else { return nil }
            return ImportReferenceDraft(id: id, name: sourceNames[id] ?? id, fields: value.objectValue ?? [:], enabled: true)
        }
        for id in sourceNames.keys.sorted() where !imports.contains(where: { $0.id == id }) {
            imports.append(ImportReferenceDraft(id: id, name: sourceNames[id] ?? id,
                fields: ["source": .string(id), "outbounds": .bool(true), "groups": .bool(false)], enabled: false))
        }
    }

    func change(baseRevision: Int) -> [String: JSONValue] {
        var profilePatch: [JSONValue] = []
        var localPatch: [JSONValue] = []
        let originalListeners = local["listeners"]?.arrayValue ?? []
        let nextListeners = listeners.map { JSONValue.object($0.fields) }
        if nextListeners != originalListeners { localPatch.append(Self.set("/listeners", .array(nextListeners))) }
        if logLevel != (local["log"]?["level"].stringValue ?? "info") {
            var log = local["log"]?.objectValue ?? [:]
            log["level"] = .string(logLevel)
            localPatch.append(Self.set("/log", .object(log)))
        }
        let nextImports = imports.filter(\.enabled).map { JSONValue.object($0.fields) }
        if nextImports != (profile["imports"]?.arrayValue ?? []) { profilePatch.append(Self.set("/imports", .array(nextImports))) }
        if dnsEnabled {
            if .object(dns) != profile["dns"] { profilePatch.append(Self.set("/dns", .object(dns))) }
        } else if profile["dns"] != nil {
            profilePatch.append(.object(["op": .string("remove"), "path": .string("/dns")]))
        }
        let originalSniff = (sniffLayer == .local ? local : profile)["sniff"]?.objectValue ?? [:]
        if sniff != originalSniff {
            let edit = Self.set("/sniff", .object(sniff))
            if sniffLayer == .local { localPatch.append(edit) } else { profilePatch.append(edit) }
        }
        var result: [String: JSONValue] = ["base_revision": .number(Double(baseRevision))]
        if !profilePatch.isEmpty { result["patch"] = .array(profilePatch) }
        if !localPatch.isEmpty { result["local_patch"] = .array(localPatch) }
        return result
    }
    private static func set(_ path: String, _ value: JSONValue) -> JSONValue {
        .object(["op": .string("set"), "path": .string(path), "value": value])
    }
}
