import SwiftUI

private struct EffectiveRuleRow: Identifiable {
    let id: String
    let index: Int
    let type: String
    let payload: String
    let outbound: String
    let description: String
}

@MainActor
struct EffectiveRulesSheet: View {
    let store: AppStore
    @Environment(\.dismiss) private var dismiss
    @State private var rows: [EffectiveRuleRow] = []
    @State private var offset = 0
    @State private var total = 0
    @State private var revision = 0
    @State private var generation = 0
    @State private var mode = "rule"
    @State private var failure: String?
    @State private var busy = false
    private let pageSize = 100

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            SheetHeader(symbol: "list.bullet.rectangle", title: "实际生效规则")
            Text("r\(revision) · generation \(generation) · \(mode) · 共 \(total) 条")
                .font(.caption).foregroundStyle(.secondary)
            Table(rows) {
                TableColumn("序号") { Text("\($0.index + 1)").monospacedDigit() }.width(50)
                TableColumn("类型", value: \.type).width(130)
                TableColumn("匹配值", value: \.payload).width(min: 180)
                TableColumn("出口") { Text(store.displayName($0.outbound)) }.width(min: 100)
            }.overlay { if rows.isEmpty && !busy { EmptyState(title: "暂无生效规则", symbol: "list.bullet.rectangle") } }
            if let failure { Text(failure).font(.caption).foregroundStyle(.red).textSelection(.enabled) }
            HStack {
                if busy { ProgressView().controlSize(.small) }
                Button("刷新") { Task { await load(at: 0) } }
                Spacer()
                Button("上一页") { Task { await load(at: max(0, offset - pageSize)) } }.disabled(offset == 0)
                Text(total == 0 ? "0 / 0" : "\(offset + 1)–\(min(offset + pageSize, total)) / \(total)").font(.caption).monospacedDigit()
                Button("下一页") { Task { await load(at: offset + pageSize) } }.disabled(offset + pageSize >= total)
                Button("完成") { dismiss() }.keyboardShortcut(.cancelAction)
            }.disabled(busy)
        }.padding(24).frame(width: 840, height: 600).task { await load(at: 0) }
    }
    private func load(at requestedOffset: Int) async {
        busy = true; failure = nil
        defer { busy = false }
        do {
            let result = try await store.client.call("GetRules", params: ["offset": .number(Double(requestedOffset)), "limit": .number(Double(pageSize))])
            let nextGeneration = result["generation"].intValue ?? 0
            if requestedOffset > 0, nextGeneration != generation { await reloadAfterChange(); return }
            offset = requestedOffset; generation = nextGeneration; revision = result["revision"].intValue ?? 0
            total = result["total"].intValue ?? 0; mode = result["mode"].stringValue ?? "rule"
            rows = (result["rules"].arrayValue ?? []).map { item in
                let index = item["index"].intValue ?? 0
                return EffectiveRuleRow(id: "\(generation):\(index)", index: index, type: item["type"].stringValue ?? "", payload: item["payload"].stringValue ?? "", outbound: item["outbound"].stringValue ?? "", description: item["description"].stringValue ?? "")
            }
        } catch { failure = error.localizedDescription }
    }
    private func reloadAfterChange() async { await load(at: 0) }
}
