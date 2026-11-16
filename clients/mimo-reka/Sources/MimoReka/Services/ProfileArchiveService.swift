import Darwin
import Foundation

struct PreparedProfileArchive: Sendable {
    let file: URL
    let resources: [(hash: String, file: URL)]
}

/// Read an inactive user-owned namespace without launching a second kernel.
/// The old directory remains a rollback archive after administrator migration.
enum ProfileArchiveService {
    static func prepare(root: URL) throws -> PreparedProfileArchive? {
        let manager = FileManager.default
        guard manager.fileExists(atPath: root.appendingPathComponent("active.json").path) else { return nil }
        try directory(root)
        let lock = Darwin.open(root.appendingPathComponent("daemon.lock").path, O_RDWR | O_NOFOLLOW)
        guard lock >= 0 else { throw ClientError.message("无法锁定待迁移配置目录。") }
        defer { flock(lock, LOCK_UN); Darwin.close(lock) }
        guard flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw ClientError.message("此配置仍被另一个内核使用，请先停止该实例。") }
        let active = try json(root.appendingPathComponent("active.json"))
        guard let revision = active["revision"].intValue, revision > 0 else { throw ClientError.message("配置索引无效。") }
        let folder = root.appendingPathComponent("revisions")
        try directory(folder)
        var versions: [JSONValue] = [], hashes = Set<String>(), inputBytes = 0
        for url in try manager.contentsOfDirectory(at: folder, includingPropertiesForKeys: [.isDirectoryKey]).sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
            guard let number = Int(url.lastPathComponent), number > 0, number <= revision else { continue }
            try directory(url)
            let meta = try json(url.appendingPathComponent("meta.json"))
            guard meta["revision"].intValue == number || meta["number"].intValue == number else { throw ClientError.message("配置历史编号不一致。") }
            var fields: [String: JSONValue] = ["meta": meta]
            for layer in ConfigurationLayer.allCases {
                let data = try read(url.appendingPathComponent(layer.rawValue + ".yaml"), maximum: 16 * 1024 * 1024)
                guard let text = String(data: data, encoding: .utf8) else { throw ClientError.message("配置历史不是有效 UTF-8。") }
                inputBytes += data.count
                guard inputBytes <= 96 * 1024 * 1024, versions.count < 2000 else { throw ClientError.message("配置历史超过迁移容量，请先导出并精简历史。") }
                fields[layer.rawValue] = .string(text)
                collectHashes(try YAMLDocument.object(text), into: &hashes)
            }
            versions.append(.object(fields))
        }
        var operations: [JSONValue] = []
        let operationRoot = root.appendingPathComponent("operations")
        if manager.fileExists(atPath: operationRoot.path) {
            try directory(operationRoot)
            for file in try manager.contentsOfDirectory(at: operationRoot, includingPropertiesForKeys: nil) where file.pathExtension == "json" {
                let value = try json(file)
                if let number = value["revision"].intValue, number > revision { continue }
                operations.append(value)
                guard operations.count <= 10000 else { throw ClientError.message("配置操作历史超过迁移容量。") }
            }
        }
        var subscriptions: [String: JSONValue] = [:]
        let subscriptionRoot = root.appendingPathComponent("subscriptions")
        if manager.fileExists(atPath: subscriptionRoot.path) {
            try directory(subscriptionRoot)
            for file in try manager.contentsOfDirectory(at: subscriptionRoot, includingPropertiesForKeys: nil) where file.pathExtension == "json" {
                subscriptions[file.deletingPathExtension().lastPathComponent] = try json(file, maximum: 2 * 1024 * 1024)
                guard subscriptions.count <= 1024 else { throw ClientError.message("订阅缓存超过迁移容量。") }
            }
        }
        guard hashes.count <= 4096 else { throw ClientError.message("配置引用资源过多。") }
        var resources: [(hash: String, file: URL)] = [], total = 0
        let resourceRoot = root.appendingPathComponent("resources/sha256")
        if !hashes.isEmpty { try directory(resourceRoot) }
        for hash in hashes.sorted() {
            let file = resourceRoot.appendingPathComponent(hash)
            let info = try regularFile(file, maximum: ResourceLimits.fileBytes)
            total += info
            guard total <= 512 * 1024 * 1024 else { throw ClientError.message("配置历史资源合计超过 512 MiB。") }
            resources.append((hash, file))
        }
        let archive: JSONValue = .object(["version": .number(1), "active": active, "revisions": .array(versions), "operations": .array(operations), "subscriptions": .object(subscriptions)])
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(archive)
        guard data.count <= ResourceLimits.fileBytes, total + data.count <= 512 * 1024 * 1024 else { throw ClientError.message("历史档案超过 128 MiB。") }
        let file = manager.temporaryDirectory.appendingPathComponent("mimo-reka-profile-archive-" + UUID().uuidString)
        let descriptor = Darwin.open(file.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw ClientError.message("无法创建迁移档案。") }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var succeeded = false
        defer { try? handle.close(); if !succeeded { try? manager.removeItem(at: file) } }
        try handle.write(contentsOf: data); try handle.synchronize()
        succeeded = true
        return PreparedProfileArchive(file: file, resources: resources)
    }
    private static func directory(_ url: URL) throws {
        var info = stat()
        guard lstat(url.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR, info.st_uid == getuid(), info.st_mode & 0o022 == 0 else { throw ClientError.message("配置迁移目录的所有权或类型不正确。") }
    }
    private static func regularFile(_ url: URL, maximum: Int) throws -> Int {
        var info = stat()
        guard lstat(url.path, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid(), info.st_size >= 0, info.st_size <= maximum else { throw ClientError.message("配置文件或资源缺失、过大或不属于当前用户。") }
        return Int(info.st_size)
    }
    private static func read(_ url: URL, maximum: Int) throws -> Data {
        _ = try regularFile(url, maximum: maximum)
        let descriptor = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW)
        guard descriptor >= 0 else { throw ClientError.message("无法读取配置历史。") }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }
        let data = try handle.readToEnd() ?? Data()
        guard data.count <= maximum else { throw ClientError.message("配置文件在读取时发生变化。") }
        return data
    }
    private static func json(_ file: URL, maximum: Int = 16 * 1024 * 1024) throws -> JSONValue { try JSONDecoder().decode(JSONValue.self, from: read(file, maximum: maximum)) }
    private static func collectHashes(_ fields: [String: JSONValue], into hashes: inout Set<String>) {
        for (key, value) in fields {
            if ["hash", "root"].contains(key), let hash = value.stringValue, hash.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil { hashes.insert(hash) }
            if let object = value.objectValue { collectHashes(object, into: &hashes) }
            for item in value.arrayValue ?? [] { if let object = item.objectValue { collectHashes(object, into: &hashes) } }
        }
        if fields["path"]?.stringValue?.hasSuffix("/hash") == true, let hash = fields["value"]?.stringValue, hash.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil { hashes.insert(hash) }
    }
}
