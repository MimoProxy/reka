import SwiftUI

@MainActor
struct ProfilesView: View {
    let store: AppStore
    var search: String
    @State private var creating = false
    @State private var name = ""
    @State private var removing: ClientProfile?
    @State private var switching: ClientProfile?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 275), spacing: 16)], spacing: 16) {
                    ForEach(store.profiles.filter { search.isEmpty || $0.name.localizedCaseInsensitiveContains(search) }) { profile in
                        profileCard(profile)
                    }
                }
                Button { name = ""; creating = true } label: {
                    Label("新建配置", systemImage: "plus")
                        .frame(maxWidth: .infinity, minHeight: 60)
                        .foregroundStyle(.secondary).surface()
                }.buttonStyle(.plain).disabled(store.isBusy)
                VStack(alignment: .leading, spacing: 12) {
                    PanelHeader(title: "当前配置")
                    ForEach(ConfigurationLayer.allCases) { layer in
                        Button { openEditor(layer) } label: {
                            HStack(spacing: 12) {
                                Image(systemName: layer == .profile ? "doc.text" : layer == .local ? "slider.horizontal.3" : layer == .sources ? "tray.full" : "square.stack")
                                    .foregroundStyle(.secondary).frame(width: 22)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(layer == .sources ? "来源引用" : layer == .overlay ? "高级用户覆盖（YAML）" : layer.title).font(.callout.weight(.medium))
                                    Text(layer.detail).font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
                            }.padding(.vertical, 8).contentShape(Rectangle())
                        }.buttonStyle(.plain).disabled(!store.isOnline || store.isBusy)
                        if layer != ConfigurationLayer.allCases.last { Divider() }
                    }
                }.panel()
            }.padding(.horizontal, 20).padding(.top, Theme.pageTopInset).padding(.bottom, 32)
        }
        .alert("新建配置", isPresented: $creating) {
            TextField("配置名称", text: $name)
            Button("取消", role: .cancel) {}
            Button("创建") { Task { await store.createProfile(name: name) } }
                .disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        } message: { Text("创建后切换到新配置，当前连接会结束。新配置初始使用直连，网络接管保持关闭。") }
        .confirmationDialog("移除“\(removing?.name ?? "")”？", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } })) {
            Button("移除配置", role: .destructive) {
                if let removing { Task { await store.deleteProfile(removing) } }
                removing = nil
            }
        } message: { Text("此配置及其版本历史将被移除。") }
        .confirmationDialog("切换到“\(switching?.name ?? "")”？", isPresented: Binding(get: { switching != nil }, set: { if !$0 { switching = nil } })) {
            Button("切换配置") {
                if let switching { Task { await store.switchProfile(switching.id) } }
                switching = nil
            }
        } message: { Text("当前连接会结束，新配置启动后可重新开启网络接管。") }
    }

    private func openEditor(_ layer: ConfigurationLayer) {
        if layer == .overlay { store.editingLayer = .overlay; return }
        store.visualSection = layer == .local ? "listeners" : layer == .sources ? "imports" : "general"
        store.showVisualConfiguration = true
    }

    private func profileCard(_ profile: ClientProfile) -> some View {
        let active = store.activeProfileID == profile.id
        return VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                SymbolBadge(symbol: "doc.text", color: active ? Theme.accent : .secondary, size: 38)
                VStack(alignment: .leading, spacing: 4) {
                    Text(profile.name).font(.headline).lineLimit(1)
                    Text(active ? "当前配置" : "Reka 配置").font(.caption).foregroundStyle(.secondary)
                }
                Spacer(minLength: 4)
                Menu {
                    if active {
                        Button("可视化编辑") { openEditor(.profile) }
                        Button("导出主配置") { store.exportConfiguration() }
                        if store.supportsMethod("ExportManifest") { Button("完整备份与恢复…") { store.showBackup = true } }
                    } else {
                        Button("使用此配置") { switching = profile }
                    }
                    if !active && !profile.privileged {
                        Divider()
                        Button("移除…", role: .destructive) { removing = profile }
                    }
                } label: { Image(systemName: "ellipsis") }.menuStyle(.borderlessButton).fixedSize()
            }
            Divider()
            HStack {
                Text(profile.createdAt.formatted(date: .abbreviated, time: .omitted))
                    .font(.caption).foregroundStyle(.tertiary)
                Spacer()
                if active {
                    Label("已选择", systemImage: "checkmark.circle.fill").font(.caption).foregroundStyle(Theme.accent)
                } else {
                    Button("使用") { switching = profile }.controlSize(.small).disabled(store.isBusy)
                }
            }
        }.padding(18).surface()
            .overlay(RoundedRectangle(cornerRadius: Theme.radius).strokeBorder(active ? Theme.accent.opacity(0.55) : .clear, lineWidth: 1))
            .contextMenu {
                if active { Button("可视化编辑") { openEditor(.profile) } }
                else { Button("使用此配置") { switching = profile } }
            }
    }
}
