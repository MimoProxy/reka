import Foundation

/// Provider-declared account usage. Missing values remain unknown, and these
/// counters are never combined with this Mac's process or session traffic.
struct SubscriptionPlanUsage: Equatable {
    let upload: Double?
    let download: Double?
    let total: Double?
    let expireUnix: Double?
    let observedAt: Date?
    let invalidFields: [String]

    init?(value: JSONValue) {
        guard value.objectValue != nil else { return nil }
        func unsigned(_ key: String, maximum: Double = Double(UInt64.max)) -> Double? {
            guard let number = value[key].numberValue, number.isFinite, number >= 0,
                  number <= maximum, number.rounded(.towardZero) == number else { return nil }
            return number
        }
        upload = unsigned("upload"); download = unsigned("download"); total = unsigned("total")
        expireUnix = unsigned("expire_unix", maximum: 253402300799)
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let rawDate = value["observed_at"].stringValue ?? ""
        if let date = formatter.date(from: rawDate) { observedAt = date }
        else { formatter.formatOptions = [.withInternetDateTime]; observedAt = formatter.date(from: rawDate) }
        invalidFields = (value["invalid_fields"].arrayValue ?? []).compactMap(\.stringValue)
    }

    var used: Double? {
        guard let upload, let download, (upload + download).isFinite else { return nil }
        return upload + download
    }
    var remaining: Double? {
        guard let total, total > 0, let used else { return nil }
        return max(0, total - used)
    }
    var fractionUsed: Double? {
        guard let total, total > 0, let used else { return nil }
        return min(1, max(0, used / total))
    }
    var expiresAt: Date? {
        guard let expireUnix, expireUnix > 0 else { return nil }
        return Date(timeIntervalSince1970: expireUnix)
    }
    static func bytes(_ value: Double) -> String {
        let units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"]
        var amount = value, unit = 0
        while amount >= 1024 && unit < units.count - 1 { amount /= 1024; unit += 1 }
        let format = unit == 0 || amount >= 100 ? "%.0f %@" : amount >= 10 ? "%.1f %@" : "%.2f %@"
        return String(format: format, amount, units[unit])
    }
}
