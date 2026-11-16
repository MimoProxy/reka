import SwiftUI

@MainActor
struct DashboardView: View {
    let store: AppStore
    var navigate: (Page) -> Void

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                HStack(spacing: 8) {
                    StatusLamp(lit: store.isOnline)
                    Text(store.networkState == "配置未运行" ? "配置待修复" : store.isOnline ? "Reka 运行中" : store.isBusy ? store.startupPhase : "内核未运行")
                        .font(.callout.weight(.medium)).foregroundStyle(.secondary)
                    Spacer()
                    RoutingModeControl(store: store).controlSize(.small)
                    Button { navigate(.connections) } label: {
                        Label("\(store.connectionCount) 个连接", systemImage: "link")
                    }.buttonStyle(.plain).foregroundStyle(.secondary)
                }.padding(.horizontal, 4)

                HStack(spacing: 16) {
                    TrafficCard(title: "本次运行累计上传", symbol: "arrow.up", amount: store.operations.traffic?.upload, rate: store.operations.uploadRate, color: .primary)
                    TrafficCard(title: "本次运行累计下载", symbol: "arrow.down", amount: store.operations.traffic?.download, rate: store.operations.downloadRate, color: Theme.accent)
                }

                if let error = store.operations.trafficError {
                    Text("流量采样暂不可用：\(error)").font(.caption).foregroundStyle(.secondary)
                } else if !store.supportsMethod("GetTraffic") {
                    Text("当前内核不提供累计流量，请更新内核。").font(.caption).foregroundStyle(.secondary)
                }
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], alignment: .leading, spacing: 16) {
                    networkPanel
                    configurationPanel
                    groupsPanel
                    sourcesPanel
                }
                HStack(spacing: 8) {
                    Image(systemName: "cpu")
                    Text(store.kernelVersion)
                    if let memory = store.coreMemoryBytes { Text("内核 \(DisplayFormat.bytes(memory))") }
                    if let memory = store.appMemoryBytes { Text("应用 \(DisplayFormat.bytes(memory))") }
                    Spacer()
                    Text(store.isOnline ? "已运行 \(store.uptime.map(DisplayFormat.duration) ?? "—") · r\(store.revision)" : "等待内核启动")
                }.font(.caption).foregroundStyle(.secondary).padding(.horizontal, 4)
            }
            .padding(.horizontal, 20).padding(.top, Theme.pageTopInset).padding(.bottom, 32)
        }
    }

    private var networkPanel: some View {
        VStack(alignment: .leading, spacing: 14) {
            PanelHeader(title: "网络")
            information("本地代理", store.listenerAddress)
            Divider()
            information("接管状态", store.networkState)
            if store.networkMode == "tun" {
                information("接管范围", store.networkIPv6 ? "IPv4 / IPv6" : "IPv4（IPv6 未接管）")
            }
            information("网络服务", store.networkService)
            HStack {
                Button("复制终端命令", systemImage: "terminal") { store.copyProxyCommand() }
                    .controlSize(.small)
                Spacer()
                SettingsLink { Image(systemName: "slider.horizontal.3") }.labelStyle(.iconOnly).help("网络设置")
            }
        }.frame(maxWidth: .infinity, minHeight: 180, alignment: .topLeading).panel()
    }

    private var configurationPanel: some View {
        VStack(alignment: .leading, spacing: 14) {
            PanelHeader(title: "当前配置") {
                Button { navigate(.profiles) } label: { Image(systemName: "chevron.right") }
                    .buttonStyle(.borderless).help("配置列表")
            }
            information("代理节点", "\(store.outbounds.filter { $0.id != "direct" && $0.id != "reject" }.count)")
            information("策略组", "\(store.groups.count)")
            information("活动连接", "\(store.connectionCount)")
            Divider()
            Button("编辑配置", systemImage: "slider.horizontal.3") {
                store.visualSection = "general"
                store.showVisualConfiguration = true
            }.controlSize(.small).disabled(!store.isOnline || store.isBusy)
        }.frame(maxWidth: .infinity, minHeight: 180, alignment: .topLeading).panel()
    }

    private var groupsPanel: some View {
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(title: "策略组") {
                Button { navigate(.groups) } label: { Image(systemName: "chevron.right") }
                    .buttonStyle(.borderless).help("查看代理")
            }
            if store.groups.isEmpty {
                EmptyState(title: "暂无策略组", symbol: "arrow.triangle.branch", minHeight: 108)
            } else {
                ForEach(Array(store.groups.prefix(4))) { group in
                    Button { navigate(.groups) } label: {
                        HStack(spacing: 10) {
                            Image(systemName: group.type == "select" ? "arrow.triangle.branch" : "waveform.path")
                                .foregroundStyle(.secondary).frame(width: 22)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(group.name).font(.callout.weight(.medium))
                                Text(store.displayName(group.selected)).font(.caption).foregroundStyle(.secondary)
                            }.lineLimit(1)
                            Spacer(minLength: 0)
                            Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
                        }.padding(8).background(Theme.track, in: RoundedRectangle(cornerRadius: 8))
                    }.buttonStyle(PressableStyle())
                }
            }
            Spacer(minLength: 0)
        }.frame(maxWidth: .infinity, minHeight: 190, alignment: .topLeading).panel()
    }

    private var sourcesPanel: some View {
        VStack(alignment: .leading, spacing: 14) {
            PanelHeader(title: "配置来源") {
                Button { navigate(.sources) } label: { Image(systemName: "chevron.right") }
                    .buttonStyle(.borderless).help("查看来源与订阅")
            }
            Text(store.sourceSummary).font(.callout).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
            Spacer(minLength: 8)
            Button("导入配置…", systemImage: "plus") { store.showImport = true }
                .disabled(!store.isOnline || store.isBusy)
                .controlSize(.small)
        }.frame(maxWidth: .infinity, minHeight: 190, alignment: .topLeading).panel()
    }

    private func information(_ title: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(title).foregroundStyle(.secondary)
            Spacer(minLength: 8)
            Text(value).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
        }.font(.callout)
    }
}

private struct TrafficCard: View {
    var title: String
    var symbol: String
    var amount: Double?
    var rate: Double?
    var color: Color
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(title, systemImage: symbol).font(.callout.weight(.medium)).foregroundStyle(.secondary)
            Text(amount.map(LiveOperationsState.displayAmount) ?? "—").font(.system(size: 32, weight: .medium)).monospacedDigit().foregroundStyle(color)
            HStack {
                Text(rate.map { LiveOperationsState.displayAmount($0) + "/s" } ?? "等待速率采样")
                Spacer()
                Text("含已关闭连接")
            }.font(.caption).foregroundStyle(.secondary).monospacedDigit()
        }.frame(maxWidth: .infinity, alignment: .leading).padding(20).surface()
    }
}
