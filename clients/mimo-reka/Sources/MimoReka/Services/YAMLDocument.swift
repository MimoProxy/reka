import CoreFoundation
import Foundation
import Yams

/// Read the kernel's masked YAML documents without imposing a second schema.
/// Network changes are always validated by Reka, never accepted by this parser alone.
enum YAMLDocument {
    static func object(_ text: String) throws -> [String: JSONValue] {
        guard text.utf8.count <= 16 * 1024 * 1024 else {
            throw ConfigurationError.message("配置文档超过 16 MiB。")
        }
        if text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return [:] }
        guard let loaded = try Yams.load(yaml: text),
              let value = try convert(loaded, depth: 0).objectValue else {
            throw ConfigurationError.message("配置文档的顶层必须是映射。")
        }
        return value
    }

    /// JSON is a valid YAML subset and gives drafts a deterministic representation.
    static func stringify(_ object: [String: JSONValue]) throws -> String {
        JSONValue.object(object).prettyPrinted + "\n"
    }

    static func array(_ text: String, key: String) throws -> [JSONValue] {
        try object(text)[key]?.arrayValue ?? []
    }

    private static func convert(_ value: Any, depth: Int) throws -> JSONValue {
        guard depth <= 48 else { throw ConfigurationError.message("配置层级过深。") }
        if value is NSNull { return .null }
        if let fields = value as? [String: Any] {
            return .object(try fields.mapValues { try convert($0, depth: depth + 1) })
        }
        if let array = value as? [Any] {
            return .array(try array.map { try convert($0, depth: depth + 1) })
        }
        if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() { return .bool(number.boolValue) }
            let double = number.doubleValue
            guard double.isFinite else { throw ConfigurationError.message("配置含有无效数值。") }
            return .number(double)
        }
        if let string = value as? String { return .string(string) }
        if let date = value as? Date { return .string(ISO8601DateFormatter().string(from: date)) }
        throw ConfigurationError.message("配置含有无法读取的 YAML 值。")
    }
}
