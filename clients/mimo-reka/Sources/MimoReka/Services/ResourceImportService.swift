import CryptoKit
import Foundation

struct ResourceAttachment: Identifiable, Equatable {
    let id = UUID()
    var kind = "rule-providers"
    var name = ""
    let filename: String
    let data: Data
    var hash: String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    var key: String { ["geoip", "geosite", "asn"].contains(kind) ? kind : kind + "/" + name.trimmingCharacters(in: .whitespacesAndNewlines) }
    var isGeodata: Bool { ["geoip", "geosite", "asn"].contains(kind) }

    static func mappings(_ attachments: [ResourceAttachment]) throws -> (providers: [String: String], geodata: [String: String]) {
        guard attachments.reduce(0, { $0 + $1.data.count }) <= ResourceLimits.totalBytes else { throw ClientError.message("资源合计不能超过 384 MiB。") }
        var providers: [String: String] = [:], geodata: [String: String] = [:]
        for item in attachments {
            guard item.data.count <= ResourceLimits.fileBytes else { throw ClientError.message("单个资源不能超过 128 MiB。") }
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
        guard data.count <= ResourceLimits.fileBytes else { throw ClientError.message("资源不能超过 128 MiB。") }
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
    static func digest(file: URL) throws -> (hash: String, size: Int) {
        let size = try file.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
        guard size > 0, size <= ResourceLimits.fileBytes else { throw ClientError.message("资源为空或超过 128 MiB。") }
        let handle = try FileHandle(forReadingFrom: file); defer { try? handle.close() }
        var digest = SHA256(); var read = 0
        while let chunk = try handle.read(upToCount: 1024 * 1024), !chunk.isEmpty {
            read += chunk.count
            guard read <= size else { throw ClientError.message("资源文件在读取时发生变化。") }
            digest.update(data: chunk)
        }
        guard read == size else { throw ClientError.message("资源文件读取不完整。") }
        return (digest.finalize().map { String(format: "%02x", $0) }.joined(), size)
    }
    static func stage(file: URL, client: RekaControlClient, profileID: String? = nil, progress: @Sendable (Int, Int) async -> Void = { _, _ in }) async throws -> String {
        let info = try digest(file: file)
        let handle = try FileHandle(forReadingFrom: file); defer { try? handle.close() }
        var offset = 0
        while offset < info.size {
            try Task.checkCancellation()
            let count = min(1024 * 1024, info.size - offset)
            guard let chunk = try handle.read(upToCount: count), chunk.count == count else { throw ClientError.message("资源文件发生变化，请重新选择。") }
            var params: [String: JSONValue] = ["hash": .string(info.hash), "size": .number(Double(info.size)), "offset": .number(Double(offset)), "data": .string(chunk.base64EncodedString())]
            if let profileID { params["profile_id"] = .string(profileID) }
            let result = try await client.call("StageResource", params: params)
            let received = result["received"].intValue ?? -1
            guard result["hash"].stringValue == info.hash, received >= offset + chunk.count, received <= info.size else { throw ClientError.message("资源上传响应不一致。") }
            await progress(received, info.size)
            if result["ready"].boolValue == true {
                guard received == info.size else { throw ClientError.message("资源尚未完整校验。") }
                return info.hash
            }
            guard received == offset + chunk.count else { throw ClientError.message("分块上传偏移不一致。") }
            offset = received
        }
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
