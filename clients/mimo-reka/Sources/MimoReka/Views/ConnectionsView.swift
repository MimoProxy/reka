import SwiftUI

@MainActor
struct ConnectionsView: View {
    let store: AppStore
    var search: String
    @State private var selection: String?
    @State private var closeAll = false
    @State private var section = "connections"
    @State private var showProcessSettings = false

    private var rows: [ConnectionRow] {
        store.connections.filter { search.isEmpty || [$0.destination, $0.source, $0.outbound, $0.rule, $0.sniffedDomain, $0.protocolName, $0.processPath].contains { $0.localizedCaseInsensitiveContains(search) } }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                if store.supportsMethod("GetProcessTraffic") {
                    Picker("查看", selection: $section) { Text("活动连接").tag("connections"); Text("应用流量").tag("processes") }.pickerStyle(.segmented).frame(width: 220)
                    Button("进程识别…") { showProcessSettings = true }.disabled(!store.isOnline || store.isBusy)
                }
                Text("\(store.connectionCount) 个活动连接").font(.callout).foregroundStyle(.secondary)
                Spacer()
                Button("关闭所选") { if let selection { Task { await store.closeConnection(selection) } } }
                    .disabled(selection == nil || store.isBusy || !store.isOnline)
                Button("关闭全部", role: .destructive) { closeAll = true }
                    .disabled(store.connections.isEmpty || store.isBusy || !store.isOnline)
            }
            if section == "processes" { ProcessTrafficView(store: store, search: search) }
            else {
            Table(rows, selection: $selection) {
                TableColumn("目标", value: \.destination).width(min: 160, ideal: 250)
                TableColumn("协议") { row in Text(row.protocolName.isEmpty ? row.network : row.network + "/" + row.protocolName) }.width(80)
                TableColumn("出口") { row in Text(store.displayName(row.outbound)) }.width(min: 90, ideal: 130)
                TableColumn("上传") { row in Text(DisplayFormat.bytes(row.uploaded)).monospacedDigit() }.width(75)
                TableColumn("下载") { row in Text(DisplayFormat.bytes(row.downloaded)).monospacedDigit() }.width(75)
                TableColumn("进程") { Text($0.processPath.isEmpty ? "—" : URL(fileURLWithPath: $0.processPath).lastPathComponent) }.width(min: 100, ideal: 140)
                TableColumn("来源", value: \.source).width(min: 90, ideal: 130)
            }.overlay {
                if rows.isEmpty { EmptyState(title: search.isEmpty ? "暂无活动连接" : "没有匹配的连接", symbol: "network") }
            }.pageCardInset()
            if let selected = rows.first(where: { $0.id == selection }) {
                HStack(alignment: .top, spacing: 16) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("路由规则").font(.caption).foregroundStyle(.tertiary)
                        Text(selected.rule.isEmpty ? "—" : selected.rule).font(.callout).textSelection(.enabled)
                    }
                    Spacer()
                    VStack(alignment: .trailing, spacing: 6) {
                        Text("出口链").font(.caption).foregroundStyle(.tertiary)
                        Text(selected.chain.map(store.displayName).joined(separator: " → ")).font(.callout).textSelection(.enabled)
                    }
                }.panel()
                HStack(alignment: .top, spacing: 16) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("嗅探域名").font(.caption).foregroundStyle(.tertiary)
                        Text(selected.sniffedDomain.isEmpty ? "未识别" : selected.sniffedDomain).font(.callout).textSelection(.enabled)
                    }
                    Spacer()
                    VStack(alignment: .trailing, spacing: 6) {
                        Text("进程归属").font(.caption).foregroundStyle(.tertiary)
                        Text(selected.processPath.isEmpty ? "未获取" : selected.processPath).font(.callout).textSelection(.enabled).lineLimit(2)
                        if let pid = selected.processPID { Text("PID \(pid)").font(.caption).foregroundStyle(.secondary) }
                        if let uid = selected.processUID { Text("UID \(uid)").font(.caption).foregroundStyle(.secondary) }
                    }
                }.panel()
            }
            }
        }.padding(.horizontal, 20).padding(.top, Theme.pageTopInset).padding(.bottom, 20)
            .task(id: store.isOnline) {
                guard store.isOnline else { return }
                let preview = ProcessInfo.processInfo.environment["MIMO_REKA_PREVIEW_EDITOR"]
                if preview == "process-settings" { showProcessSettings = true }
                if preview == "processes" { section = "processes" }
            }
            .sheet(isPresented: $showProcessSettings) { ProcessSettingsSheet(store: store) }
            .confirmationDialog("关闭所有活动连接？", isPresented: $closeAll) {
                Button("关闭全部连接", role: .destructive) { Task { await store.closeConnections() } }
            } message: { Text("正在进行的请求会中断，应用可以重新建立连接。") }
    }
}
