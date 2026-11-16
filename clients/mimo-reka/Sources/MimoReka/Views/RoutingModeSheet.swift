import SwiftUI

@MainActor
struct RoutingModeControl: View {
    let store: AppStore
    @State private var showing = false
    var body: some View {
        Button { showing = true } label: {
            Label("路由：\(AppStore.routingTitle(store.routingMode))", systemImage: "arrow.triangle.branch")
        }.disabled(!store.isOnline || store.isBusy || !store.supportsMethod("GetRules"))
            .help("切换规则、全局或直连路由")
            .sheet(isPresented: $showing) { RoutingModeSheet(store: store) }
    }
}

@MainActor
struct RoutingModeSheet: View {
    let store: AppStore
    @Environment(\.dismiss) private var dismiss
    @State private var mode: String
    @State private var global: String
    private let baseRevision: Int
    init(store: AppStore) {
        self.store = store; baseRevision = store.revision
        _mode = State(initialValue: store.routingMode)
        _global = State(initialValue: store.globalRoutingTarget.isEmpty ? (store.groups.first?.id ?? "direct") : store.globalRoutingTarget)
    }
    private var targets: [(id: String, name: String)] {
        var seen = Set<String>()
        return (store.groups.map { (id: $0.id, name: $0.name) } + store.outbounds.map { (id: $0.id, name: $0.name) })
            .filter { seen.insert($0.id).inserted }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            SheetHeader(symbol: "arrow.triangle.branch", title: "路由模式")
            Picker("模式", selection: $mode) {
                Text("规则").tag("rule"); Text("全局").tag("global"); Text("直连").tag("direct")
            }.pickerStyle(.segmented)
            if mode == "global" {
                Picker("全局出口", selection: $global) {
                    ForEach(targets, id: \.id) { target in Text(target.name).tag(target.id) }
                    if !targets.contains(where: { $0.id == global }) { Text(global).tag(global) }
                }
            }
            Text(mode == "rule" ? "按配置中的规则顺序匹配出口。" : mode == "global" ? "所有流量使用指定策略或节点，已有规则继续保留。" : "所有流量通过直连出口，已有规则继续保留。")
                .font(.callout).foregroundStyle(.secondary)
            Text("路由模式决定流量出口；系统代理和 TUN 在网络设置中控制。")
                .font(.caption).foregroundStyle(.secondary)
            if let prepared = store.preparedChange { ChangePlanView(prepared: prepared).frame(height: 120) }
            Divider()
            HStack {
                Text("基于 r\(baseRevision)").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("取消", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("预览变更") { Task { await store.previewRoutingMode(mode, global: global, baseRevision: baseRevision) } }
                Button("应用") { Task { await store.applyPrepared(); if store.errorMessage == nil { dismiss() } } }
                    .buttonStyle(.borderedProminent).disabled(store.preparedChange == nil)
            }
        }.padding(24).frame(width: 620).disabled(store.isBusy)
            .onAppear { store.preparedChange = nil }
            .onDisappear { store.preparedChange = nil }
            .onChange(of: mode) { store.preparedChange = nil }
            .onChange(of: global) { store.preparedChange = nil }
            .alert("模式未应用", isPresented: Binding(get: { store.errorMessage != nil }, set: { if !$0 { store.errorMessage = nil } })) {
                Button("好", role: .cancel) { store.errorMessage = nil }
            } message: { Text(store.errorMessage ?? "") }
    }
}
