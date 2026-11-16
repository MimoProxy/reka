import Foundation

struct RouteDiagnosticDraft {
    var destination = "example.com:443"
    var network = "tcp"
    var source = ""
    var inbound = ""
    var inboundType = ""
    var inboundPort = ""
    var inboundUser = ""
    var process = ""
    var uid = ""
    var addresses = ""
    var resolve = false

    func parameters() throws -> [String: JSONValue] {
        guard !destination.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw ClientError.message("请输入目标域名或 IP 及端口。") }
        var value: [String: JSONValue] = ["destination": .string(destination), "network": .string(network), "resolve": .bool(resolve)]
        for (key, text) in [("source", source), ("inbound", inbound), ("inbound_type", inboundType), ("inbound_user", inboundUser), ("process", process)] where !text.isEmpty { value[key] = .string(text) }
        if !inboundPort.isEmpty {
            guard let port = UInt16(inboundPort), port > 0 else { throw ClientError.message("入口端口需要为 1–65535。") }
            value["inbound_port"] = .number(Double(port))
        }
        if !uid.isEmpty {
            guard let number = UInt32(uid) else { throw ClientError.message("UID 需要为有效的非负整数。") }
            value["process_uid"] = .number(Double(number))
        }
        let ips = addresses.split(whereSeparator: { $0.isWhitespace || $0 == "," }).map(String.init)
        if !ips.isEmpty { value["addresses"] = .array(ips.map(JSONValue.string)) }
        return value
    }
}
