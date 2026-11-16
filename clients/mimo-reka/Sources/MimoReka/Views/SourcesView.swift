import SwiftUI

@MainActor
struct SourcesView: View {
    let store: AppStore
    var search: String

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                if store.sources.isEmpty {
                    VStack(spacing: 12) {
                        EmptyState(title: "还没有来源", symbol: "tray.and.arrow.down", detail: "导入配置、分享链接，或添加自动刷新的订阅。", minHeight: 140)
                        Button("导入或添加订阅…", systemImage: "plus") { store.showImport = true }
                            .disabled(!store.isOnline || store.isBusy)
                    }.padding(20).frame(maxWidth: .infinity).surface()
                } else {
                    ForEach(store.sources.filter { search.isEmpty || $0.name.localizedCaseInsensitiveContains(search) || $0.id.localizedCaseInsensitiveContains(search) }) { source in
                        sourceCard(source)
                    }
                }
                HStack {
                    Text("来源与用户覆盖分别保存，刷新不会直接替换你的主配置。")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer(minLength: 8)
                    Button("查看来源快照") { store.editingLayer = .sources }.controlSize(.small)
                        .disabled(!store.isOnline || store.isBusy)
                }.padding(.horizontal, 4)
            }.padding(.horizontal, 20).padding(.top, Theme.pageTopInset).padding(.bottom, 32)
        }
    }

    private func sourceCard(_ source: SourceRow) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                SymbolBadge(symbol: source.hasSubscription ? "arrow.triangle.2.circlepath" : "tray.full", size: 38)
                VStack(alignment: .leading, spacing: 4) {
                    Text(source.name).font(.headline)
                    Text("\(source.nodeCount) 个节点 · \(source.groupCount) 个策略组").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                if source.hasSubscription {
                    Text(status(source)).font(.caption).foregroundStyle(source.errorCode == nil ? Color.secondary : Color.orange)
                } else { Text("本地导入").font(.caption).foregroundStyle(.secondary) }
            }
            if source.hasSubscription {
                Divider()
                HStack(spacing: 16) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("上次成功").font(.caption).foregroundStyle(.tertiary)
                        Text(source.lastSuccess?.formatted(date: .abbreviated, time: .shortened) ?? "—").font(.callout)
                    }
                    Spacer()
                    if let next = source.nextAttempt, !source.paused {
                        VStack(alignment: .trailing, spacing: 3) {
                            Text("下次检查").font(.caption).foregroundStyle(.tertiary)
                            Text(next.formatted(date: .omitted, time: .shortened)).font(.callout)
                        }
                    }
                    Button(source.paused ? "恢复刷新" : "暂停") {
                        Task { await store.setSubscriptionPaused(source, paused: !source.paused) }
                    }.controlSize(.small)
                    Button("刷新", systemImage: "arrow.clockwise") { Task { await store.refreshSubscription(source) } }
                        .controlSize(.small)
                }.disabled(!store.isOnline || store.isBusy)
                if let error = source.errorCode, !error.isEmpty {
                    Label("刷新失败：\(error)。继续使用上次成功的内容。", systemImage: "exclamationmark.triangle")
                        .font(.caption).foregroundStyle(.orange)
                }
            }
        }.panel()
    }

    private func status(_ source: SourceRow) -> String {
        if source.paused { return "已暂停" }
        switch source.subscriptionState {
        case "refreshing": return "正在刷新"
        case "current": return "已更新"
        case "failed": return "刷新失败"
        default: return source.subscriptionState ?? "等待检查"
        }
    }
}
