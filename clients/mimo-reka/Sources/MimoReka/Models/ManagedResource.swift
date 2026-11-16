import CryptoKit
import Foundation
import Observation

enum ResourceLimits {
    static let fileBytes = 128 * 1024 * 1024
    static let totalBytes = 384 * 1024 * 1024
    static let fileDescription = "128 MiB"
}

struct ManagedResource: Identifiable, Equatable {
    let collection: String
    let fields: [String: JSONValue]
    var identifier: String { fields["id"]?.stringValue ?? "" }
    var id: String { collection + "/" + identifier }
    var isDatabase: Bool { collection == "geodata" }
    var title: String { isDatabase ? Self.databaseTitle(identifier) : identifier }
    var hash: String { fields["hash"]?.stringValue ?? "" }
    var url: String { fields["download"]?["url"].stringValue ?? "" }
    var automatic: Bool { fields["download"]?["automatic"].boolValue ?? false }
    var interval: Int { fields["download"]?["interval"].intValue ?? 86400 }
    static let defaultBase = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/"
    static func defaultURL(_ kind: String, format: String = "dat") -> String {
        defaultBase + (kind == "asn" ? "GeoLite2-ASN.mmdb" : kind == "geosite" ? "geosite.dat" : format == "mmdb" ? "country.mmdb" : "geoip.dat")
    }
    static func databaseTitle(_ kind: String) -> String {
        switch kind { case "geoip": "GeoIP"; case "geosite": "GeoSite"; case "asn": "ASN"; default: kind }
    }
    static func read(_ documents: [ConfigurationLayer: String]) -> [Self] {
        let profile = (try? YAMLDocument.object(documents[.profile] ?? "")) ?? [:]
        return ["geodata", "rule-sets"].flatMap { collection in
            (profile[collection]?.arrayValue ?? []).compactMap { value in
                guard let fields = value.objectValue, fields["id"]?.stringValue != nil else { return nil }
                return Self(collection: collection, fields: fields)
            }
        }
    }
}

struct ManagedResourceDraft: Identifiable {
    let id = UUID()
    var original: ManagedResource?
    var isDatabase = false
    var identifier = ""
    var behavior = "domain"
    var format = "text"
    var code = ""
    var input = "url"
    var url = ""
    var automatic = true
    var interval = 86400
    var localFile: URL?
    var fileName = ""
    init(resource: ManagedResource? = nil, database: String? = nil) {
        original = resource
        if let resource {
            isDatabase = resource.isDatabase; identifier = resource.identifier
            behavior = resource.fields["behavior"]?.stringValue ?? "domain"
            format = resource.fields["format"]?.stringValue ?? "text"; code = resource.fields["code"]?.stringValue ?? ""
            url = resource.url; input = url.isEmpty ? "file" : "url"
            automatic = resource.automatic; interval = resource.interval
        } else if let database {
            isDatabase = true; identifier = database; format = database == "asn" ? "mmdb" : "dat"
            url = ManagedResource.defaultURL(database)
        }
    }
    var collection: String { isDatabase ? "geodata" : "rule-sets" }
    var key: String { collection + "/" + identifier }
    func definition(hash: String) throws -> [String: JSONValue] {
        guard identifier.range(of: #"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"#, options: .regularExpression) != nil else { throw ClientError.message("资源标识需为 1–64 位字母、数字、点、下划线或连字符。") }
        var fields = original?.fields ?? [:]
        fields["id"] = .string(identifier); fields["format"] = .string(format); fields["hash"] = .string(hash)
        if !isDatabase {
            fields["behavior"] = .string(behavior)
            if code.isEmpty { fields.removeValue(forKey: "code") } else { fields["code"] = .string(code) }
        }
        if input == "url" {
            let address = url.trimmingCharacters(in: .whitespacesAndNewlines)
            guard address == "********" || URL(string: address).map({ ["http", "https"].contains($0.scheme?.lowercased() ?? "") && $0.host != nil && $0.user == nil && $0.password == nil }) == true else { throw ClientError.message("请输入不含内嵌用户名密码的 HTTP(S) 资源地址。") }
            fields["download"] = .object(["url": .string(address), "interval": .number(Double(interval)), "automatic": .bool(automatic)])
        } else { fields.removeValue(forKey: "download") }
        return fields
    }
}

struct ResourceUpdateStatus: Codable, Equatable {
    var checkedAt: Date?
    var updatedAt: Date?
    var etag: String?
    var modified: String?
    var identity = ""
    var failure: String?
}

@MainActor @Observable
final class ManagedResourceState {
    var statuses: [String: ResourceUpdateStatus] = [:]
    var busyKeys: Set<String> = []
    var progress: [String: String] = [:]
    @ObservationIgnored var downloader: ResourceDownloadService?
    private var profile: UUID?
    func load(profile: UUID, home: URL) {
        guard self.profile != profile else { return }
        downloader?.cancel()
        self.profile = profile
        statuses = (try? JSONDecoder().decode([String: ResourceUpdateStatus].self, from: Data(contentsOf: file(profile: profile, home: home)))) ?? [:]
    }
    func persist(profile: UUID, home: URL) throws {
        guard self.profile == profile else { return }
        let destination = file(profile: profile, home: home)
        try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try JSONEncoder().encode(statuses).write(to: destination, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
    }
    static func identity(url: String, hash: String) -> String {
        SHA256.hash(data: Data((url + "\n" + hash).utf8)).map { String(format: "%02x", $0) }.joined()
    }
    private func file(profile: UUID, home: URL) -> URL { home.appendingPathComponent("resource-status/" + profile.uuidString + ".json") }
}
