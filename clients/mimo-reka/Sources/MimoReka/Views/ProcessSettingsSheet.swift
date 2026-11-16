import SwiftUI

@MainActor
struct ProcessSettingsSheet: View {
    @Bindable var store: AppStore
    @Environment(\.dismiss) private var dismiss
    @State private var mode: String
    @State private var revision: Int
    init(store: AppStore) {
        self.store = store; _mode = State(initialValue: store.processMode); _revision = State(initialValue: store.revision)
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            SheetHeader(symbol: "app.connected.to.app.below.fill", title: "进程识别")
            Picker("采集策略", selection: $mode) {
                Text("所有新连接").tag("always"); Text("按规则需要").tag("rule"); Text("关闭").tag("off")
            }.pickerStyle(.segmented)
            Text("“所有新连接”主动识别应用，不依赖进程规则。“按规则需要”只在规则判断需要时查询。“关闭”会使实际连接的进程规则无法获取归属。")
                .font(.callout).foregroundStyle(.secondary)
            Text("变更影响之后建立的连接。应用累计流量保留本次内核运行中已完成的连接；无法识别和超出统计容量的流量单独归类。")
                .font(.caption).foregroundStyle(.secondary)
            if store.capabilities["process_lookup"].boolValue != true { Label("当前运行平台无法查询进程归属。", systemImage: "info.circle").foregroundStyle(.orange) }
            if let error = store.errorMessage { Text(error).font(.caption).foregroundStyle(.red) }
            HStack {
                Spacer()
                Button("取消", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("保存") { Task { if await store.previewProcessMode(mode, revision: revision, save: true) { dismiss() } } }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(!store.isOnline)
            }
        }.padding(24).frame(width: 640).disabled(store.isBusy).interactiveDismissDisabled(store.isBusy)
            .onAppear { store.preparedChange = nil }
            .onDisappear { store.preparedChange = nil }
            .onChange(of: mode) { store.preparedChange = nil }
    }
}
