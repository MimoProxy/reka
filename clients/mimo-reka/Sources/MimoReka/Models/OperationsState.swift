import Foundation
import Observation

struct TrafficSample: Equatable {
    let epoch: String
    let upload: Double
    let download: Double
    let sampledAt: Date

    init?(value: JSONValue) {
        guard let epoch = value["epoch"].stringValue, !epoch.isEmpty,
              let upload = value["upload_total"].numberValue, upload >= 0, upload.isFinite,
              let download = value["download_total"].numberValue, download >= 0, download.isFinite,
              let sampledAt = Self.parseDate(value["sampled_at"].stringValue) else { return nil }
        self.epoch = epoch; self.upload = upload; self.download = download; self.sampledAt = sampledAt
    }

    private static func parseDate(_ value: String?) -> Date? {
        guard let value else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: value) { return date }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: value)
    }

    func rates(since previous: TrafficSample?) -> (upload: Double, download: Double)? {
        guard let previous, epoch == previous.epoch,
              upload >= previous.upload, download >= previous.download else { return nil }
        let elapsed = sampledAt.timeIntervalSince(previous.sampledAt)
        guard elapsed > 0 else { return nil }
        return ((upload - previous.upload) / elapsed, (download - previous.download) / elapsed)
    }
}

struct ProbeObservation: Equatable {
    var delayMS: Int?
    var resolvedOutbound: String?
    var error: String?
    let checkedAt: Date
}

struct CoreLogRow: Identifiable, Equatable {
    let id: String
    let timestamp: String
    let level: String
    let message: String

    init?(event: JSONValue) {
        guard event["type"].stringValue == "log", let epoch = event["epoch"].stringValue,
              let sequence = event["seq"].numberValue, let message = event["data"]["message"].stringValue else { return nil }
        id = epoch + ":" + String(format: "%.0f", sequence)
        timestamp = event["data"]["time"].stringValue ?? event["time"].stringValue ?? ""
        level = event["data"]["level"].stringValue ?? "info"
        self.message = message
    }
    var text: String { "\(timestamp) [\(level.uppercased())] \(message)" }
}

@MainActor @Observable
final class LiveOperationsState {
    var traffic: TrafficSample?
    var uploadRate: Double?
    var downloadRate: Double?
    var trafficError: String?
    var logs: [CoreLogRow] = []
    var logsError: String?
    var probes: [String: ProbeObservation] = [:]
    var probing: Set<String> = []
    var probeURL = "https://www.gstatic.com/generate_204"
    var probeTimeoutMS = 5000
    var refreshSession: UUID?
    var session = UUID()
    var processRows: [ProcessTrafficRow] = []
    var processOffset = 0
    var processTotal = 0
    var processEpoch = ""
    var processError: String?
    var processRequest: UUID?

    func acceptTraffic(_ next: TrafficSample) {
        let rates = next.rates(since: traffic)
        uploadRate = rates?.upload; downloadRate = rates?.download
        traffic = next; trafficError = nil
    }
    func reset() {
        session = UUID(); refreshSession = nil
        traffic = nil; uploadRate = nil; downloadRate = nil; trafficError = nil
        logs = []; logsError = nil; probes = [:]; probing = []
        processRows = []; processOffset = 0; processTotal = 0; processEpoch = ""; processError = nil; processRequest = nil
    }
    static func displayAmount(_ amount: Double) -> String {
        DisplayFormat.bytes(Int(min(Double(Int.max / 2), max(0, amount))))
    }
}
