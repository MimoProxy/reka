import Foundation

/// Changes a single native field without rebuilding or dropping siblings.
enum NativeFieldEditing {
    static func value(_ fields: [String: JSONValue], path: [String]) -> JSONValue {
        path.reduce(JSONValue.object(fields)) { $0[$1] }
    }
    static func set(_ fields: inout [String: JSONValue], path: [String], value: JSONValue?) {
        guard let first = path.first else { return }
        if path.count == 1 { fields[first] = value; return }
        var nested = fields[first]?.objectValue ?? [:]
        set(&nested, path: Array(path.dropFirst()), value: value)
        if nested.isEmpty { fields.removeValue(forKey: first) } else { fields[first] = .object(nested) }
    }
}
