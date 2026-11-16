import SwiftUI

@MainActor
struct SourcesView: View {
    let store: AppStore
    var search: String
    @State private var confirmingDelete = false
    @State private var deletingSource: SourceRow? = nil
    @State private var deletionRevision = 0

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
        .confirmationDialog("删除此来源？", isPresented: $confirmingDelete, presenting: deletingSource) { source in
            Button("删除来源", role: .destructive) {
                Task { await store.deleteSource(source, baseRevision: deletionRevision) }
            }
            Button("取消", role: .cancel) {}
        } message: { source in
            Text("将删除“\(source.name)”的 \(source.nodeCount) 个节点、\(source.groupCount) 个策略组及导入规则，并移除对应覆盖和刷新任务。选中的节点若被删除，会改用策略组内剩余的首个成员；没有剩余成员时使用直连。仍被自定义规则或 DNS 引用时会拒绝删除。")
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
                Button(role: .destructive) {
                    deletingSource = source; deletionRevision = store.revision; confirmingDelete = true
                } label: { Image(systemName: "trash") }
                    .buttonStyle(.borderless).help("删除来源“\(source.name)”")
                    .accessibilityLabel("删除来源“\(source.name)”")
                    .disabled(!store.isOnline || store.isBusy)
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
                usagePanel(source)
                if let error = source.errorCode, !error.isEmpty {
                    Label(source.lastSuccess == nil ? "刷新失败：\(error)。尚无成功快照，可重试或删除此来源。" : "刷新失败：\(error)。继续使用上次成功的内容。", systemImage: "exclamationmark.triangle")
                        .font(.caption).foregroundStyle(.orange)
                }
            }
        }.panel()
    }

    private func usagePanel(_ source: SourceRow) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("订阅套餐").font(.callout.weight(.medium))
                Spacer()
                if source.planUsage != nil, source.usageStale { Text("上次成功的数据").font(.caption).foregroundStyle(.orange) }
            }
            if let usage = source.planUsage {
                HStack {
                    Text(usage.used.map { "已用 " + SubscriptionPlanUsage.bytes($0) } ?? "已用流量未提供")
                    Spacer()
                    if let total = usage.total {
                        Text(total == 0 ? "服务方未设置限额" : "总量 " + SubscriptionPlanUsage.bytes(total))
                    } else { Text("总量未提供") }
                }.font(.callout).foregroundStyle(.secondary)
                if let progress = usage.fractionUsed { ProgressView(value: progress).progressViewStyle(.linear) }
                HStack {
                    if let remaining = usage.remaining { Text("剩余 " + SubscriptionPlanUsage.bytes(remaining)) }
                    Spacer()
                    if let expiry = usage.expiresAt {
                        Text((expiry < Date() ? "已于 " : "到期 ") + expiry.formatted(date: .abbreviated, time: .shortened))
                            .foregroundStyle(expiry < Date() ? Color.orange : Color.secondary)
                    } else { Text(usage.expireUnix == 0 ? "服务方未设置到期时间" : "到期时间未提供") }
                }.font(.caption).foregroundStyle(.secondary)
                if !usage.invalidFields.isEmpty {
                    Text("部分套餐声明无效，已按未知值处理。") .font(.caption).foregroundStyle(.orange)
                }
                if let observed = usage.observedAt {
                    Text("服务方声明 · " + observed.formatted(date: .abbreviated, time: .shortened))
                        .font(.caption2).foregroundStyle(.tertiary)
                }
            } else {
                Text("服务方未提供套餐用量和到期时间。") .font(.caption).foregroundStyle(.secondary)
            }
        }.padding(14).background(Theme.track, in: RoundedRectangle(cornerRadius: 10))
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
