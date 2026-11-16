import SwiftUI

@MainActor
struct ManagedResourcesView: View {
    let store: AppStore
    var search: String
    @State private var editing: ManagedResourceDraft? = nil
    @State private var deleting: ManagedResource? = nil
    @State private var confirmingDelete = false
    @State private var deletionRevision = 0
    private var resources: [ManagedResource] { store.managedResources }
    private var locked: Bool { !store.isOnline || store.isBusy || !store.resourceUpdates.busyKeys.isEmpty }
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("规则集与地理数据库").font(.title2.weight(.semibold))
                        Text("支持本地文件和 URL；自动更新在客户端运行时执行，失败继续使用旧版本。")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("添加规则集", systemImage: "plus") { editing = ManagedResourceDraft() }.disabled(locked)
                }
                VStack(alignment: .leading, spacing: 14) {
                    PanelHeader(title: "GeoIP · GeoSite · ASN")
                    Text("默认使用 Mimo 的 jsDelivr 源。下载后，可在规则编辑器直接选择国家代码、站点分类或 ASN。")
                        .font(.caption).foregroundStyle(.secondary)
                    ForEach(["geoip", "geosite", "asn"], id: \.self) { kind in
                        if let resource = resources.first(where: { $0.isDatabase && $0.identifier == kind }) {
                            resourceRow(resource)
                        } else {
                            HStack {
                                Label(ManagedResource.databaseTitle(kind), systemImage: "globe").font(.callout.weight(.medium))
                                if let progress = store.resourceUpdates.progress["geodata/" + kind] { ProgressView().controlSize(.small); Text(progress).font(.caption) }
                                else { Text("未下载").font(.caption).foregroundStyle(.secondary) }
                                Spacer()
                                Button("下载默认数据库", systemImage: "arrow.down.circle") {
                                    Task { await store.saveResource(ManagedResourceDraft(database: kind)) }
                                }.disabled(locked)
                                Button("自定义…") { editing = ManagedResourceDraft(database: kind) }.disabled(locked)
                            }.padding(.vertical, 6)
                            if let error = store.resourceUpdates.statuses["geodata/" + kind]?.failure { Label(error, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange) }
                        }
                        if kind != "asn" { Divider() }
                    }
                }.panel()
                VStack(alignment: .leading, spacing: 14) {
                    PanelHeader(title: "本地与 URL 规则集")
                    let sets = resources.filter { !$0.isDatabase && (search.isEmpty || $0.identifier.localizedCaseInsensitiveContains(search)) }
                    if sets.isEmpty { Text("添加域名、IP 网段、经典规则，或按分类使用数据库资源。") .font(.callout).foregroundStyle(.secondary) }
                    ForEach(sets) { resource in resourceRow(resource); if resource.id != sets.last?.id { Divider() } }
                }.panel()
                if !importedResources.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        PanelHeader(title: "来源规则集")
                        Text("以下资源由对应来源管理，随订阅刷新。删除或调整来源请前往“来源与订阅”。").font(.caption).foregroundStyle(.secondary)
                        ForEach(importedResources, id: \.self) { id in Text(id).font(.callout.monospaced()).textSelection(.enabled) }
                    }.panel()
                }
                HStack {
                    Text("单个资源最多 128 MiB，按 1 MiB 分块上传和校验。规则配置与资源一起备份。")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()

                }
            }.padding(20)
        }
        .sheet(item: $editing) { draft in ManagedResourceEditorSheet(store: store, initial: draft) }
        .confirmationDialog("删除此资源？", isPresented: $confirmingDelete, presenting: deleting) { resource in
            Button("删除资源", role: .destructive) { Task { await store.deleteManagedResource(resource, baseRevision: deletionRevision) } }
            Button("取消", role: .cancel) {}
        } message: { resource in Text("将删除“\(resource.title)”。规则或 DNS 仍在引用时会拒绝删除。") }
        .task(id: store.isOnline) {
            if store.isOnline, ProcessInfo.processInfo.environment["MIMO_REKA_PREVIEW_EDITOR"] == "resource-url" { editing = ManagedResourceDraft(database: "asn") }
        }
        .task(id: store.activeProfileID) { store.resourceUpdates.load(profile: store.activeProfileID, home: store.homeURL) }
    }
    private var importedResources: [String] {
        let sources = (try? YAMLDocument.array(store.documents[.sources] ?? "", key: "sources")) ?? []
        return sources.flatMap { source in
            (source["rule-sets"].arrayValue ?? []).compactMap { set in
                guard let name = set["id"].stringValue, let id = source["id"].stringValue else { return nil }
                return id + "/" + name
            }
        }
    }
    private func resourceRow(_ resource: ManagedResource) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 5) {
                    Text(resource.title).font(.callout.weight(.medium))
                    Text((resource.fields["behavior"]?.stringValue.map { $0 + " · " } ?? "") + (resource.fields["format"]?.stringValue ?? "内联") + " · " + (resource.url.isEmpty ? "本地文件" : resource.automatic ? "自动更新 · 每 \(resource.interval >= 3600 ? "\(resource.interval / 3600) 小时" : "\(resource.interval / 60) 分钟")" : "URL · 手动更新"))
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                if !resource.url.isEmpty {
                    Button("更新", systemImage: "arrow.clockwise") { Task { await store.saveResource(ManagedResourceDraft(resource: resource), force: true) } }.disabled(locked)
                }
                if resource.hash.isEmpty { Text("在主配置 YAML 中编辑").font(.caption).foregroundStyle(.secondary) }
                else { Button("编辑") { editing = ManagedResourceDraft(resource: resource) }.disabled(locked) }
                Button(role: .destructive) { deleting = resource; deletionRevision = store.revision; confirmingDelete = true } label: { Image(systemName: "trash") }
                    .buttonStyle(.borderless).help("删除“\(resource.title)”").disabled(locked)
            }
            if let progress = store.resourceUpdates.progress[resource.id] { HStack { ProgressView().controlSize(.small); Text(progress).font(.caption) } }
            if let status = store.resourceUpdates.statuses[resource.id] {
                if let error = status.failure { Label(error, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange).textSelection(.enabled) }
                HStack(spacing: 18) {
                    if let date = status.checkedAt { Text("上次检查 " + date.formatted(date: .abbreviated, time: .shortened)) }
                    if let date = status.updatedAt { Text("资源更新 " + date.formatted(date: .abbreviated, time: .shortened)) }
                }.font(.caption2).foregroundStyle(.secondary)
            }
            if !resource.hash.isEmpty { Text("SHA-256 · " + resource.hash).font(.caption2.monospaced()).foregroundStyle(.tertiary).textSelection(.enabled).lineLimit(1) }
        }.padding(.vertical, 4)
    }
}
