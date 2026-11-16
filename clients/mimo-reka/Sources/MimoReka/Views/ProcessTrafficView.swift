import SwiftUI

@MainActor
struct ProcessTrafficView: View {
    let store: AppStore
    var search: String
    private var rows: [ProcessTrafficRow] {
        store.operations.processRows.filter { search.isEmpty || $0.name.localizedCaseInsensitiveContains(search) || $0.path.localizedCaseInsensitiveContains(search) }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("本次内核运行累计 · 包含已关闭连接 · 采集：\(AppStore.processModeTitle(store.processMode))")
                .font(.caption).foregroundStyle(.secondary)
            Table(rows) {
                TableColumn("应用", value: \.name).width(min: 150)
                TableColumn("用户") { Text($0.uid.map(String.init) ?? "—") }.width(60)
                TableColumn("累计上传") { Text(LiveOperationsState.displayAmount($0.upload)).monospacedDigit() }.width(90)
                TableColumn("累计下载") { Text(LiveOperationsState.displayAmount($0.download)).monospacedDigit() }.width(90)
                TableColumn("活动") { Text("\($0.active)") }.width(50)
                TableColumn("总连接") { Text("\($0.total)") }.width(60)
                TableColumn("路径", value: \.path).width(min: 140)
            }.overlay { if rows.isEmpty { EmptyState(title: "暂无应用流量", symbol: "chart.bar", detail: "启用“所有新连接”后建立连接即可查看应用归属。") } }
            if let error = store.operations.processError { Text(error).font(.caption).foregroundStyle(.red) }
            HStack {
                Button("刷新") { Task { await store.refreshProcessTraffic() } }
                Spacer()
                Button("上一页") { Task { await store.refreshProcessTraffic(offset: max(0, store.operations.processOffset - 100)) } }.disabled(store.operations.processOffset == 0)
                Text("\(store.operations.processTotal) 项").font(.caption)
                Button("下一页") { Task { await store.refreshProcessTraffic(offset: store.operations.processOffset + 100) } }.disabled(store.operations.processOffset + 100 >= store.operations.processTotal)
            }
        }.task { await store.refreshProcessTraffic() }
    }
}
