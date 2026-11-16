import Foundation

struct PreparedChange: Identifiable, Codable, Sendable {
    let id: UUID
    let change: [String: JSONValue]
    let planHash: String
    let summary: String
    let report: String
    let plan: JSONValue
}

enum ConfigurationLayer: String, CaseIterable, Identifiable, Codable {
    case profile, local, sources, overlay
    var id: String { rawValue }
    var title: String {
        switch self {
        case .profile: "主配置"
        case .local: "本机设置"
        case .sources: "来源快照"
        case .overlay: "用户覆盖"
        }
    }
    var detail: String {
        switch self {
        case .profile: "策略组、路由规则与 DNS"
        case .local: "监听端口、日志与网络接管"
        case .sources: "订阅和导入的节点、策略与规则"
        case .overlay: "保留在订阅刷新之上的用户修改"
        }
    }
}

struct ClientProfile: Identifiable, Codable, Equatable {
    var id = UUID()
    var name: String
    var createdAt = Date()
    var privileged = false
}

struct PolicyGroup: Identifiable, Equatable {
    let id: String
    let name: String
    let type: String
    let selected: String
    let members: [String]
    let health: [String: String]
}

struct OutboundRow: Identifiable, Equatable {
    let id: String
    let name: String
    let type: String
    var server = ""
    var port: Int?
    var sourceID = ""
}

struct ConnectionRow: Identifiable, Equatable {
    let id: String
    let destination: String
    let network: String
    let outbound: String
    let source: String
    let uploaded: Int
    let downloaded: Int
    var rule = ""
    var chain: [String] = []
}

struct SourceRow: Identifiable, Equatable {
    let id: String
    let name: String
    let nodeCount: Int
    let groupCount: Int
    var hasSubscription = false
    var paused = false
    var subscriptionState: String?
    var lastSuccess: Date?
    var nextAttempt: Date?
    var errorCode: String?
}

struct RevisionRow: Identifiable, Equatable {
    let id: Int
    let timestamp: Date?
    let message: String
    let source: String
    let active: Bool
}

enum ClientError: LocalizedError {
    case message(String)
    var errorDescription: String? { switch self { case .message(let text): text } }
}
