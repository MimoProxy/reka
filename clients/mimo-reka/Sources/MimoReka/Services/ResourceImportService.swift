import CryptoKit
import Foundation

struct ResourceAttachment: Identifiable, Equatable {
    let id = UUID()
    var kind = "rule-providers"
    var name = ""
    let filename: String
    let data: Data
    var hash: String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    var key: String { ["geoip", "geosite"].contains(kind) ? kind : kind + "/" + name.trimmingCharacters(in: .whitespacesAndNewlines) }
    var isGeodata: Bool { ["geoip", "geosite"].contains(kind) }

    static func mappings(_ attachments: [ResourceAttachment]) throws -> (providers: [String: String], geodata: [String: String]) {
        guard attachments.reduce(0, { $0 + $1.data.count }) <= 32 * 1024 * 1024 else { throw ClientError.message("资源合计不能超过 32 MiB。") }
        var providers: [String: String] = [:], geodata: [String: String] = [:]
        for item in attachments {
            guard item.data.count <= 16 * 1024 * 1024 else { throw ClientError.message("单个资源不能超过 16 MiB。") }
            guard item.isGeodata || !item.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw ClientError.message("请填写配置中的提供者名称。") }
            if item.isGeodata {
                guard geodata[item.key] == nil else { throw ClientError.message("重复的地理数据库：\(item.key)。") }
                geodata[item.key] = item.hash
            } else {
                guard providers[item.key] == nil else { throw ClientError.message("重复的提供者：\(item.key)。") }
                providers[item.key] = item.hash
            }
        }
        return (providers, geodata)
    }
}

enum ResourceImportService {
    static func stage(data: Data, client: RekaControlClient, progress: @Sendable (Int, Int) async -> Void = { _, _ in }) async throws -> String {
        guard data.count <= 16 * 1024 * 1024 else { throw ClientError.message("资源不能超过 16 MiB。") }
        let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        var offset = 0
        repeat {
            try Task.checkCancellation()
            let end = min(offset + 1024 * 1024, data.count)
            let result = try await client.call("StageResource", params: [
                "hash": .string(hash), "size": .number(Double(data.count)), "offset": .number(Double(offset)),
                "data": .string(data.subdata(in: offset..<end).base64EncodedString())
            ])
            guard result["hash"].stringValue == hash, let received = result["received"].intValue,
                  received >= end, received <= data.count else { throw ClientError.message("资源上传响应不一致。") }
            await progress(received, data.count)
            if result["ready"].boolValue == true {
                guard received == data.count else { throw ClientError.message("资源尚未完整校验。") }
                return hash
            }
            guard received > offset else { throw ClientError.message("资源上传未取得进展。") }
            offset = received
        } while offset < data.count
        throw ClientError.message("资源 SHA-256 校验未完成。")
    }
}

extension ConfigurationService {
    static func attachResources(_ request: JSONValue, providers: [String: String], geodata: [String: String]) -> JSONValue {
        var value = request.objectValue ?? [:]
        if !providers.isEmpty { value["provider_resources"] = .object(providers.mapValues(JSONValue.string)) }
        if !geodata.isEmpty { value["geodata_resources"] = .object(geodata.mapValues(JSONValue.string)) }
        return .object(value)
    }
}
