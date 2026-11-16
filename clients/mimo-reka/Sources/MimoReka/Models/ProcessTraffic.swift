import Foundation

struct ProcessTrafficRow: Identifiable, Equatable {
    let id: String
    let path: String
    let uid: Int?
    let unknown: Bool
    let overflow: Bool
    let upload: Double
    let download: Double
    let active: Int
    let total: Int
    var name: String {
        if overflow { return "其他应用（统计容量已满）" }
        if unknown { return "未识别进程" }
        if path.isEmpty { return uid.map { "用户 \($0)（路径未知）" } ?? "未识别进程" }
        return URL(fileURLWithPath: path).lastPathComponent
    }
    init?(value: JSONValue) {
        guard let id = value["id"].stringValue else { return nil }
        self.id = id; path = value["process_path"].stringValue ?? ""
        uid = value["process_uid"].intValue; unknown = value["unknown"].boolValue ?? false
        overflow = value["overflow"].boolValue ?? false
        upload = value["upload_total"].numberValue ?? 0; download = value["download_total"].numberValue ?? 0
        active = value["active_connections"].intValue ?? 0; total = value["total_connections"].intValue ?? 0
    }
}
