import SwiftUI

@MainActor
struct ProxyBrowserView: View {
    let store: AppStore
    var search: String
    @State private var selectedGroup: String?

    private var groups: [PolicyGroup] { store.groups.filter { search.isEmpty || $0.name.localizedCaseInsensitiveContains(search) || $0.members.contains { store.displayName($0).localizedCaseInsensitiveContains(search) } } }
    private var current: PolicyGroup? { groups.first { $0.id == selectedGroup } ?? groups.first }

    var body: some View {
        HSplitView {
            groupList.frame(minWidth: 190, idealWidth: 220, maxWidth: 280)
            memberList.frame(minWidth: 360, maxWidth: .infinity, maxHeight: .infinity)
        }.padding(.horizontal, 20).padding(.top, Theme.pageTopInset).padding(.bottom, 20)
    }

    private var groupList: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("策略组").font(.headline)
                Spacer()
                Text("\(groups.count)").font(.caption).foregroundStyle(.secondary)
            }.padding(16)
            Divider()
            if groups.isEmpty { EmptyState(title: "暂无策略组", symbol: "arrow.triangle.branch") }
            else {
                List(selection: Binding(get: { current?.id }, set: { selectedGroup = $0 })) {
                    ForEach(groups) { group in
                        HStack(spacing: 10) {
                            Image(systemName: group.type == "select" ? "arrow.triangle.branch" : "waveform.path").foregroundStyle(.secondary)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(group.name).font(.callout.weight(.medium)).lineLimit(1)
                                Text(store.displayName(group.selected)).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            }
                        }.padding(.vertical, 5).tag(group.id)
                    }
                }.listStyle(.inset).scrollContentBackground(.hidden)
            }
        }.background(Theme.surface).pageCardInset()
    }

    @ViewBuilder private var memberList: some View {
        if let current {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    VStack(alignment: .leading, spacing: 5) {
                        Text(current.name).font(.title2.weight(.semibold))
                        Text("\(current.type) · \(current.members.count) 个选项").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button { store.editingLayer = .profile } label: { Image(systemName: "slider.horizontal.3") }
                        .buttonStyle(.borderless).help("编辑策略配置").disabled(!store.isOnline || store.isBusy)
                }
                if current.type != "select" {
                    Label("由内核根据健康检查自动选择", systemImage: "waveform.path")
                        .font(.caption).foregroundStyle(.secondary)
                }
                ScrollView {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 205), spacing: 12)], spacing: 12) {
                        ForEach(current.members.filter { search.isEmpty || store.displayName($0).localizedCaseInsensitiveContains(search) }, id: \.self) { member in
                            memberCard(member, group: current)
                        }
                    }
                }
            }.padding(.leading, 16)
        } else {
            EmptyState(title: search.isEmpty ? "导入配置后选择代理节点" : "没有匹配的策略", symbol: "server.rack")
        }
    }

    private func memberCard(_ id: String, group: PolicyGroup) -> some View {
        let selected = group.selected == id
        let outbound = store.outbounds.first { $0.id == id }
        return Button {
            if group.type == "select" { Task { await store.select(group: group, member: id) } }
        } label: {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .top, spacing: 8) {
                    Text(store.displayName(id)).font(.callout.weight(.medium)).lineLimit(2).frame(maxWidth: .infinity, alignment: .leading)
                    Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                        .foregroundStyle(selected ? Theme.accent : Color.secondary.opacity(0.4))
                }
                HStack {
                    Text(outbound?.type ?? store.groups.first { $0.id == id }?.type ?? "direct")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer(minLength: 8)
                    if let health = group.health[id] { Text(health).font(.caption.monospacedDigit()).foregroundStyle(.secondary) }
                }
            }.padding(14).frame(maxWidth: .infinity, minHeight: 78, alignment: .topLeading)
                .background(selected ? Theme.selectedFill : .clear, in: RoundedRectangle(cornerRadius: 12))
                .surface(cornerRadius: 12)
                .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(selected ? Theme.accent.opacity(0.6) : .clear, lineWidth: 1))
        }.buttonStyle(PressableStyle()).disabled(store.isBusy || !store.isOnline)
            .accessibilityLabel("\(store.displayName(id))\(selected ? "，当前已选中" : "")")
    }
}
