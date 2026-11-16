import SwiftUI
import UniformTypeIdentifiers

@MainActor
struct RuleResourcesSheet: View {
    let store: AppStore
    @Environment(\.dismiss) private var dismiss
    @State private var identifier = ""
    @State private var original: [String: JSONValue] = [:]
    @State private var behavior = "domain"
    @State private var format = "text"
    @State private var code = ""
    @State private var hash = ""
    @State private var filename = ""
    @State private var bytes: Data?
    @State private var picking = false
    @State private var busy = false
    @State private var failure: String?
    @State private var status = ""
    @State private var baseRevision: Int
    @State private var deleting = false

    init(store: AppStore) { self.store = store; _baseRevision = State(initialValue: store.revision) }
    private var localResources: [JSONValue] { (try? YAMLDocument.array(store.documents[.profile] ?? "", key: "rule-sets")) ?? [] }
    private var importedResources: [(id: String, hash: String)] {
        let sources = (try? YAMLDocument.array(store.documents[.sources] ?? "", key: "sources")) ?? []
        return sources.flatMap { source in
            (source["rule-sets"].arrayValue ?? []).map { (id: (source["id"].stringValue ?? "") + "/" + ($0["id"].stringValue ?? ""), hash: $0["hash"].stringValue ?? "内联") }
        }
    }
    private var formats: [String] {
        if behavior == "geoip" { return ["dat", "mmdb"] }
        if behavior == "geosite" { return ["dat"] }
        return behavior == "classical" ? ["text", "yaml"] : ["text", "yaml", "mrs"]
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            SheetHeader(symbol: "shippingbox", title: "规则集资源")
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    existingResources
                    resourceForm
                    if let prepared = store.preparedChange { ChangePlanView(prepared: prepared).frame(height: 110) }
                    if let failure { Text(failure).font(.caption).foregroundStyle(.red).textSelection(.enabled) }
                }
            }
            Divider()
            HStack {
                if busy || store.isBusy { ProgressView().controlSize(.small); Text(status).font(.caption).foregroundStyle(.secondary) }
                Spacer()
                Button("完成") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("预览资源变更") { Task { await preview() } }.disabled(identifier.isEmpty || (hash.isEmpty && bytes == nil))
                Button(deleting ? "确认删除" : "应用") {
                    Task { await store.applyPrepared(); if store.errorMessage == nil { reset() } }
                }.buttonStyle(.borderedProminent).disabled(store.preparedChange == nil)
            }.disabled(busy || store.isBusy || !store.isOnline)
        }.padding(24).frame(width: 790, height: 690)
            .interactiveDismissDisabled(busy || store.isBusy)
            .onAppear { store.preparedChange = nil }
            .onDisappear { store.preparedChange = nil }
            .onChange(of: identifier) { invalidate() }
            .onChange(of: behavior) { if !formats.contains(format) { format = formats[0] }; invalidate() }
            .onChange(of: format) { invalidate() }
            .onChange(of: code) { invalidate() }
            .fileImporter(isPresented: $picking, allowedContentTypes: [.data]) { result in load(result) }
            .alert("资源未应用", isPresented: Binding(get: { store.errorMessage != nil }, set: { if !$0 { store.errorMessage = nil } })) {
                Button("好", role: .cancel) { store.errorMessage = nil }
            } message: { Text(store.errorMessage ?? "") }
    }

    private var existingResources: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack { PanelHeader(title: "已有规则集"); Button("新建", systemImage: "plus") { reset() } }
            ForEach(localResources.compactMap { $0["id"].stringValue }, id: \.self) { id in
                let resource = localResources.first { $0["id"].stringValue == id } ?? .null
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(resource["id"].stringValue ?? "").font(.callout.weight(.medium))
                        Text(resource["hash"].stringValue ?? "内联规则").font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                    }
                    Spacer()
                    if resource["hash"].stringValue != nil { Button("编辑") { edit(resource) } }
                    Button(role: .destructive) { Task { await remove(resource) } } label: { Image(systemName: "trash") }.buttonStyle(.borderless)
                }
            }
            ForEach(importedResources, id: \.id) { resource in
                HStack { Text(resource.id).font(.callout); Spacer(); Text("来源 · " + resource.hash).font(.caption).foregroundStyle(.secondary).lineLimit(1) }
            }
            if localResources.isEmpty && importedResources.isEmpty { Text("暂无规则集。导入后可在规则编辑器选择“规则集”并引用标识。") .font(.caption).foregroundStyle(.secondary) }
            Text("来源规则集随原配置导入；提供者和 GeoIP/GeoSite 文件可在“导入配置”中绑定。删除仍被引用的规则集会被内核拒绝。")
                .font(.caption).foregroundStyle(.secondary)
        }.panel().disabled(busy || store.isBusy)
    }

    private var resourceForm: some View {
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(title: original.isEmpty ? "新建本地规则集" : "编辑本地规则集")
            FieldRow(title: "标识") { TextField("例如 local-domains", text: $identifier).trackField().disabled(!original.isEmpty) }
            HStack {
                Picker("内容", selection: $behavior) {
                    Text("域名").tag("domain"); Text("IP 网段").tag("ipcidr"); Text("经典规则").tag("classical"); Text("GeoIP").tag("geoip"); Text("GeoSite").tag("geosite")
                }
                Picker("格式", selection: $format) { ForEach(formats, id: \.self) { Text($0).tag($0) } }
            }
            if ["geoip", "geosite"].contains(behavior) { FieldRow(title: "分类代码") { TextField("例如 CN 或 category-ads-all", text: $code).trackField() } }
            HStack {
                Button("选择资源文件…", systemImage: "doc") { picking = true }
                Text(filename.isEmpty ? (hash.isEmpty ? "尚未选择" : "沿用已锁定资源") : filename).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            if !hash.isEmpty { Text("SHA-256: " + hash).font(.caption2.monospaced()).textSelection(.enabled) }
        }.panel().disabled(busy || store.isBusy)
    }
    private func invalidate() { store.preparedChange = nil; deleting = false }
    private func reset() {
        identifier = ""; original = [:]; behavior = "domain"; format = "text"; code = ""; hash = ""; bytes = nil; filename = ""; failure = nil
        baseRevision = store.revision; invalidate()
    }
    private func edit(_ resource: JSONValue) {
        original = resource.objectValue ?? [:]; identifier = resource["id"].stringValue ?? ""
        behavior = resource["behavior"].stringValue ?? "domain"; format = resource["format"].stringValue ?? "text"
        code = resource["code"].stringValue ?? ""; hash = resource["hash"].stringValue ?? ""; bytes = nil; filename = ""
        baseRevision = store.revision; invalidate()
    }
    private func load(_ result: Result<URL, Error>) {
        do {
            let file = try result.get(), scoped = file.startAccessingSecurityScopedResource()
            defer { if scoped { file.stopAccessingSecurityScopedResource() } }
            guard (try file.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0) <= 16 * 1024 * 1024 else { throw ClientError.message("资源不能超过 16 MiB。") }
            bytes = try Data(contentsOf: file); filename = file.lastPathComponent; invalidate()
        } catch { if (error as NSError).code != NSUserCancelledError { failure = error.localizedDescription } }
    }
    private func preview() async {
        busy = true; failure = nil
        defer { busy = false; status = "" }
        do {
            guard identifier.range(of: #"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"#, options: .regularExpression) != nil else { throw ClientError.message("标识需为 1–64 位字母、数字、点、下划线或连字符。") }
            if let bytes { hash = try await ResourceImportService.stage(data: bytes, client: store.client) { received, total in await MainActor.run { status = "上传并校验 · \(total == 0 ? 100 : received * 100 / total)%" } } }
            var value = original
            value["id"] = .string(identifier); value["behavior"] = .string(behavior); value["format"] = .string(format); value["hash"] = .string(hash)
            if code.isEmpty { value.removeValue(forKey: "code") } else { value["code"] = .string(code) }
            let operation: JSONValue = .object(["op": .string(original.isEmpty ? "insert" : "set"), "path": .string(original.isEmpty ? "/rule-sets" : "/rule-sets/" + ConfigurationService.escape(identifier)), "value": .object(value)])
            await store.previewVisualChange(["base_revision": .number(Double(baseRevision)), "patch": .array([operation])], summary: "保存规则集 · " + identifier)
        } catch { failure = error.localizedDescription }
    }
    private func remove(_ resource: JSONValue) async {
        guard let id = resource["id"].stringValue else { return }
        await store.previewVisualChange(["base_revision": .number(Double(store.revision)), "patch": .array([.object(["op": .string("remove"), "path": .string("/rule-sets/" + ConfigurationService.escape(id))])])], summary: "删除规则集 · " + id)
        deleting = store.preparedChange != nil
    }
}
