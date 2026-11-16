import SwiftUI

@MainActor
struct RevisionsView: View {
    let store: AppStore
    var search: String
    @State private var restoring: RevisionRow?

    var body: some View {
        ScrollView {
            LazyVStack(spacing: 12) {
                ForEach(store.revisions.filter { search.isEmpty || "\($0.id) \($0.message) \($0.source)".localizedCaseInsensitiveContains(search) }) { revision in
                    HStack(alignment: .top, spacing: 14) {
                        Text("r\(revision.id)").font(.system(.title3, design: .monospaced).weight(.medium))
                            .foregroundStyle(revision.active ? Theme.accent : Color.primary).frame(width: 64, alignment: .leading)
                        VStack(alignment: .leading, spacing: 7) {
                            Text(revision.message.isEmpty ? "配置变更" : revision.message).font(.callout.weight(.medium))
                            HStack(spacing: 12) {
                                Text(revision.timestamp?.formatted(date: .abbreviated, time: .shortened) ?? "—")
                                Text(revision.source)
                            }.font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if revision.active {
                            Label("当前版本", systemImage: "checkmark.circle.fill").font(.caption).foregroundStyle(Theme.accent)
                        } else {
                            Button("恢复") { restoring = revision }.controlSize(.small).disabled(!store.isOnline || store.isBusy)
                        }
                    }.panel()
                }
                if store.revisions.isEmpty { EmptyState(title: "暂无版本历史", symbol: "clock.arrow.circlepath").surface() }
            }.padding(.horizontal, 20).padding(.top, Theme.pageTopInset).padding(.bottom, 24)
        }
        .confirmationDialog("恢复到 r\(restoring?.id ?? 0)？", isPresented: Binding(get: { restoring != nil }, set: { if !$0 { restoring = nil } })) {
            Button("恢复此版本") {
                if let restoring { Task { await store.restoreRevision(restoring) } }
                restoring = nil
            }
        } message: { Text("主配置、来源、本机设置与用户覆盖将作为新版本恢复。网络设置变化可能中断连接。") }
    }
}
