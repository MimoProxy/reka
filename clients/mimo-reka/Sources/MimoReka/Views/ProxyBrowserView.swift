import SwiftUI

private struct PolicyNodeEditRequest: Identifiable {
    let id = UUID()
    let nodeID: String
}

@MainActor
struct ProxyBrowserView: View {
    let store: AppStore
    var search: String
    @State private var selectedGroup: String?
    @State private var editingPolicy: PolicyEditorRequest?
    @State private var editingNode: PolicyNodeEditRequest?

    private var groups: [PolicyGroup] { store.groups.filter { search.isEmpty || $0.name.localizedCaseInsensitiveContains(search) || $0.members.contains { store.displayName($0).localizedCaseInsensitiveContains(search) } } }
    private var current: PolicyGroup? { groups.first { $0.id == selectedGroup } ?? groups.first }

    var body: some View {
        HSplitView {
            groupList.frame(minWidth: 190, idealWidth: 220, maxWidth: 280)
            memberList.frame(minWidth: 360, maxWidth: .infinity, maxHeight: .infinity)
        }.padding(.horizontal, 20).padding(.top, Theme.pageTopInset).padding(.bottom, 20)
            .sheet(item: $editingPolicy) { request in PolicyEditorSheet(store: store, groupID: request.groupID) }
            .sheet(item: $editingNode) { request in NodeEditorSheet(store: store, nodeID: request.nodeID) }
            .task(id: store.isOnline) {
                if store.isOnline, ProcessInfo.processInfo.environment["MIMO_REKA_PREVIEW_EDITOR"] == "policy" {
                    editingPolicy = PolicyEditorRequest(groupID: current?.id)
                }
                if store.isOnline, ProcessInfo.processInfo.environment["MIMO_REKA_PREVIEW_EDITOR"] == "node",
                   let node = store.outbounds.first(where: { !["direct", "reject"].contains($0.id) }) {
                    editingNode = PolicyNodeEditRequest(nodeID: node.id)
                }
            }
    }

    private var groupList: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("策略组").font(.headline)
                Spacer()
                Text("\(groups.count)").font(.caption).foregroundStyle(.secondary)
                Button { editingPolicy = PolicyEditorRequest(groupID: nil) } label: { Image(systemName: "plus") }
                    .buttonStyle(.borderless).help("新建策略组").disabled(!store.isOnline || store.isBusy)
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
                            .contextMenu {
                                Button("编辑策略组…") { editingPolicy = PolicyEditorRequest(groupID: group.id) }
                                    .disabled(!store.isOnline || store.isBusy)
                            }
                    }
                }.listStyle(.inset).scrollContentBackground(.hidden)
            }
        }.background(Theme.surface).pageCardInset()
    }

    @ViewBuilder private var memberList: some View {
        if let current {
            VStack(alignment: .leading, spacing: 16) {
                DisclosureGroup("延迟测试设置") {
                    VStack(alignment: .leading, spacing: 8) {
                        TextField("HTTP(S) 测试地址", text: Binding(get: { store.operations.probeURL }, set: { store.operations.probeURL = $0 }))
                            .textFieldStyle(.roundedBorder)
                        Picker("超时", selection: Binding(get: { store.operations.probeTimeoutMS }, set: { store.operations.probeTimeoutMS = $0 })) {
                            Text("3 秒").tag(3000); Text("5 秒").tag(5000); Text("10 秒").tag(10000); Text("30 秒").tag(30000)
                        }.frame(maxWidth: 220)
                        Text("测量 HTTP 请求延迟，不改变策略选择。").font(.caption).foregroundStyle(.secondary)
                    }.padding(.top, 8)
                }.disabled(!store.supportsMethod("ProbeOutbound"))
                HStack {
                    VStack(alignment: .leading, spacing: 5) {
                        Text(current.name).font(.title2.weight(.semibold))
                        Text("\(current.type) · \(current.members.count) 个选项").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button { Task { await store.probeOutbound(current.id) } } label: {
                        Label("测试策略", systemImage: "speedometer")
                    }.disabled(!store.isOnline || !store.supportsMethod("ProbeOutbound") || store.operations.probing.contains(current.id))
                    Button { editingPolicy = PolicyEditorRequest(groupID: current.id) } label: { Label("编辑", systemImage: "slider.horizontal.3") }
                        .buttonStyle(.borderless).help("可视化编辑策略组").disabled(!store.isOnline || store.isBusy)
                }
                if store.operations.probes[current.id] != nil || store.operations.probing.contains(current.id) {
                    probeResult(current.id)
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
        return VStack(alignment: .leading, spacing: 7) {
            Button {
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
            .contextMenu {
                if outbound != nil && !["direct", "reject"].contains(id) {
                    Button("编辑节点…") { editingNode = PolicyNodeEditRequest(nodeID: id) }
                } else if store.groups.contains(where: { $0.id == id }) {
                    Button("编辑策略组…") { editingPolicy = PolicyEditorRequest(groupID: id) }
                }
            }
            HStack(spacing: 6) {
                probeResult(id)
                Spacer(minLength: 0)
                Button("测试", systemImage: "speedometer") { Task { await store.probeOutbound(id) } }
                    .labelStyle(.iconOnly).buttonStyle(.borderless)
                    .help("测试 HTTP 请求延迟")
                    .disabled(!store.isOnline || !store.supportsMethod("ProbeOutbound") || store.operations.probing.contains(id))
            }.padding(.horizontal, 6)
        }
    }

    @ViewBuilder private func probeResult(_ id: String) -> some View {
        if store.operations.probing.contains(id) {
            HStack(spacing: 5) { ProgressView().controlSize(.mini); Text("测试中…").font(.caption).foregroundStyle(.secondary) }
        } else if let result = store.operations.probes[id] {
            if let error = result.error {
                Text("测试失败").font(.caption).foregroundStyle(.red).help(error)
            } else if let delay = result.delayMS {
                Text("\(delay) ms").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                    .help("HTTP 请求延迟 · \(result.checkedAt.formatted())" + (result.resolvedOutbound.map { " · " + store.displayName($0) } ?? ""))
            }
        } else {
            Text("未测试").font(.caption).foregroundStyle(.tertiary)
        }
    }
}
