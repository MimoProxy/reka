import Foundation

struct ProfileCatalog: Codable {
    var profiles: [ClientProfile]
    var activeProfileID: UUID
    var sourceNames: [String: [String: String]] = [:]

    static func initial() -> Self {
        let profile = ClientProfile(name: "默认配置")
        return Self(profiles: [profile], activeProfileID: profile.id)
    }

    static func load(from root: URL) throws -> Self {
        let file = root.appendingPathComponent("catalog.json")
        guard FileManager.default.fileExists(atPath: file.path) else { return .initial() }
        let catalog = try JSONDecoder().decode(Self.self, from: Data(contentsOf: file))
        guard !catalog.profiles.isEmpty, Set(catalog.profiles.map(\.id)).count == catalog.profiles.count,
              catalog.profiles.contains(where: { $0.id == catalog.activeProfileID }) else {
            throw ClientError.message("配置目录索引损坏，原文件已保留。")
        }
        return catalog
    }

    func save(to root: URL) throws {
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let file = root.appendingPathComponent("catalog.json")
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(self).write(to: file, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    }
}
