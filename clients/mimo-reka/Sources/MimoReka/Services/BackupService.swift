import CryptoKit
import Foundation
import Darwin

struct NativeBackup: Codable {
    let format: String
    let version: Int
    let createdAt: Date
    let profileName: String
    let revision: Int
    let documents: [String: String]
    let resources: [String: Data]
    let sourceNames: [String: String]
}

enum BackupService {
    static let maximumResourceBytes = 512 * 1024 * 1024
    static let maximumFileBytes = 768 * 1024 * 1024
    static func export(client: RekaControlClient, name: String, sourceNames: [String: String], progress: @Sendable (String) async -> Void = { _ in }) async throws -> NativeBackup {
        let manifest = try await client.call("ExportManifest", params: ["reveal": .bool(true)])
        guard manifest["schema_version"].intValue == 1, let revision = manifest["revision"].intValue, manifest["masked"].intValue == 0 else { throw ClientError.message("内核没有返回可恢复的备份清单。") }
        var documents: [String: String] = [:]
        for layer in ConfigurationLayer.allCases {
            guard let text = manifest[layer.rawValue].stringValue else { throw ClientError.message("备份缺少配置层。") }
            documents[layer.rawValue] = text
        }
        let descriptors = manifest["resources"].arrayValue ?? []
        guard descriptors.count <= 128 else { throw ClientError.message("当前备份最多包含 128 个资源。") }
        var resources: [String: Data] = [:], total = 0
        for (index, descriptor) in descriptors.enumerated() {
            guard let hash = descriptor["hash"].stringValue, validHash(hash), let size = descriptor["size"].intValue,
                  (0...ResourceLimits.fileBytes).contains(size), resources[hash] == nil else { throw ClientError.message("备份资源清单无效。") }
            total += size
            guard total <= maximumResourceBytes else { throw ClientError.message("备份资源合计不能超过 512 MiB。") }
            await progress("读取资源 \(index + 1)/\(descriptors.count)")
            var data = Data()
            repeat {
                try Task.checkCancellation()
                let result: JSONValue
                do {
                    result = try await client.call("ReadResource", params: ["base_revision": .number(Double(revision)), "hash": .string(hash), "offset": .number(Double(data.count)), "limit": .number(1024 * 1024), "reveal": .bool(true)])
                } catch RekaControlError.server(let code, _) where code == "conflict" {
                    throw ClientError.message("配置在备份期间发生变化，请重新导出整份备份。")
                }
                guard result["revision"].intValue == revision, result["hash"].stringValue == hash,
                      result["offset"].intValue == data.count, result["size"].intValue == size,
                      let encoded = result["data"].stringValue, let chunk = Data(base64Encoded: encoded),
                      chunk.count <= 1024 * 1024, data.count + chunk.count <= size else { throw ClientError.message("资源下载响应不一致。") }
                data.append(chunk)
                if result["eof"].boolValue == true {
                    guard data.count == size else { throw ClientError.message("备份资源下载不完整。") }
                    break
                }
                guard !chunk.isEmpty else { throw ClientError.message("资源下载未取得进展。") }
            } while data.count < size
            guard digest(data) == hash else { throw ClientError.message("备份资源 SHA-256 校验失败。") }
            resources[hash] = data
        }
        return NativeBackup(format: "mimo-reka-backup", version: 1, createdAt: Date(), profileName: name, revision: revision, documents: documents, resources: resources, sourceNames: sourceNames)
    }
    static func encode(_ backup: NativeBackup) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(backup)
        guard data.count <= maximumFileBytes else { throw ClientError.message("备份文件过大。") }
        return data
    }
    static func decode(_ data: Data) throws -> NativeBackup {
        guard data.count <= maximumFileBytes else { throw ClientError.message("备份文件不能超过 192 MiB。") }
        let value = try JSONDecoder().decode(NativeBackup.self, from: data)
        guard value.format == "mimo-reka-backup", value.version == 1, value.resources.count <= 128 else { throw ClientError.message("不支持此备份格式。") }
        var size = 0
        for layer in ConfigurationLayer.allCases {
            guard let text = value.documents[layer.rawValue], text.utf8.count <= 16 * 1024 * 1024 else { throw ClientError.message("备份配置层缺失或超过大小限制。") }
        }
        for (hash, bytes) in value.resources {
            size += bytes.count
            guard validHash(hash), bytes.count <= ResourceLimits.fileBytes, size <= maximumResourceBytes, digest(bytes) == hash else { throw ClientError.message("备份资源损坏或超过大小限制。") }
        }
        return value
    }
    static func write(_ backup: NativeBackup, to destination: URL) throws {
        let data = try encode(backup)
        let temporary = destination.deletingLastPathComponent().appendingPathComponent(".mimo-reka-backup-" + UUID().uuidString)
        let descriptor = Darwin.open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close(); try? FileManager.default.removeItem(at: temporary) }
        try handle.write(contentsOf: data); try handle.synchronize(); try handle.close()
        guard Darwin.rename(temporary.path, destination.path) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }
    static func restorationChange(_ backup: NativeBackup, revision: Int) throws -> [String: JSONValue] {
        var change = backup.documents.filter { ConfigurationLayer(rawValue: $0.key) != nil }.mapValues(JSONValue.string)
        var local = try YAMLDocument.object(backup.documents["local"] ?? "")
        var network = local["network"]?.objectValue ?? [:]; network["mode"] = .string("off"); local["network"] = .object(network)
        change["local"] = .string(try YAMLDocument.stringify(local))
        change["base_revision"] = .number(Double(revision))
        return change
    }
    static func stage(_ backup: NativeBackup, client: RekaControlClient, progress: @Sendable (String) async -> Void = { _ in }) async throws {
        for (index, entry) in backup.resources.sorted(by: { $0.key < $1.key }).enumerated() {
            await progress("校验并上传资源 \(index + 1)/\(backup.resources.count)")
            let hash = try await ResourceImportService.stage(data: entry.value, client: client)
            guard hash == entry.key else { throw ClientError.message("恢复资源校验失败。") }
        }
    }
    private static func validHash(_ hash: String) -> Bool { hash.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }
    private static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
}
