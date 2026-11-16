import SwiftUI
import UniformTypeIdentifiers

@MainActor
struct ManagedResourceEditorSheet: View {
    let store: AppStore
    @Environment(\.dismiss) private var dismiss
    @State private var draft: ManagedResourceDraft
    @State private var picking = false
    @State private var failure: String? = nil
    init(store: AppStore, initial: ManagedResourceDraft) { self.store = store; _draft = State(initialValue: initial) }
    private var formats: [String] {
        let kind = draft.isDatabase ? draft.identifier : draft.behavior
        if kind == "asn" { return ["mmdb"] }
        if kind == "geosite" { return ["dat"] }
        if kind == "geoip" { return ["dat", "mmdb"] }
        return kind == "classical" ? ["text", "yaml"] : ["text", "yaml", "mrs"]
    }
    private var busy: Bool { store.resourceUpdates.busyKeys.contains(draft.key) || store.isBusy }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            SheetHeader(symbol: "shippingbox", title: draft.isDatabase ? "地理数据库 · " + ManagedResource.databaseTitle(draft.identifier) : draft.original == nil ? "添加规则集" : "编辑规则集")
            VStack(spacing: 0) {
                if !draft.isDatabase {
                    FieldRow(title: "标识") { TextField("例如 ads 或 private-networks", text: $draft.identifier).trackField().disabled(draft.original != nil) }
                    Divider()
                    FieldRow(title: "内容") {
                        Picker("内容", selection: $draft.behavior) {
                            Text("域名").tag("domain"); Text("IP 网段").tag("ipcidr"); Text("经典规则").tag("classical")
                            Text("GeoIP 分类").tag("geoip"); Text("GeoSite 分类").tag("geosite"); Text("ASN 分类").tag("asn")
                        }.labelsHidden()
                    }
                    Divider()
                }
                FieldRow(title: "格式") { Picker("格式", selection: $draft.format) { ForEach(formats, id: \.self) { Text($0.uppercased()).tag($0) } }.labelsHidden() }
                if !draft.isDatabase, ["geoip", "geosite", "asn"].contains(draft.behavior) {
                    Divider()
                    FieldRow(title: "分类") { TextField(draft.behavior == "asn" ? "例如 13335" : "例如 CN 或 category-ads-all", text: $draft.code).trackField() }
                }
            }.padding(.horizontal, 16).surface()
            Picker("导入方式", selection: $draft.input) { Text("URL 下载").tag("url"); Text("本地文件").tag("file") }.pickerStyle(.segmented)
            if draft.input == "url" {
                TextField("https://…", text: $draft.url).trackField(monospaced: true).accessibilityLabel("资源下载地址")
                if draft.isDatabase || ["geoip", "geosite", "asn"].contains(draft.behavior) { Button("使用 Mimo jsDelivr 默认地址") { draft.url = ManagedResource.defaultURL(draft.isDatabase ? draft.identifier : draft.behavior, format: draft.format) } }
                Toggle("自动更新（客户端运行时）", isOn: $draft.automatic)
                Picker("检查间隔", selection: $draft.interval) {
                    Text("每小时").tag(3600); Text("每 6 小时").tag(21600); Text("每天").tag(86400); Text("每周").tag(604800)
                    if ![3600, 21600, 86400, 604800].contains(draft.interval) { Text("每 \(draft.interval) 秒").tag(draft.interval) }
                }.disabled(!draft.automatic)
            } else {
                HStack { Button("选择资源文件…", systemImage: "doc") { picking = true }; Text(draft.fileName.isEmpty ? (draft.original == nil ? "尚未选择" : "沿用已保存资源") : draft.fileName).font(.callout).foregroundStyle(.secondary) }
            }
            Text("最多 128 MiB。保存时校验格式与资源摘要，失败不会替换旧版本。") .font(.caption).foregroundStyle(.secondary)
            if let failure { Text(failure).font(.caption).foregroundStyle(.red).textSelection(.enabled) }
            if let progress = store.resourceUpdates.progress[draft.key] { HStack { ProgressView().controlSize(.small); Text(progress).font(.caption) } }
            Divider()
            HStack {
                Spacer()
                Button("取消", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button(draft.input == "url" && draft.original == nil ? "下载并保存" : "保存") {
                    Task {
                        failure = nil
                        if await store.saveResource(draft) { dismiss() }
                        else { failure = store.resourceUpdates.statuses[draft.key]?.failure ?? store.errorMessage ?? "未能保存，请稍后重试。"; store.errorMessage = nil }
                    }
                }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .disabled(!store.isOnline || draft.identifier.isEmpty || (draft.input == "url" ? draft.url.isEmpty : draft.original == nil && draft.localFile == nil))
            }
        }.padding(24).frame(width: 740).disabled(busy).interactiveDismissDisabled(busy)
            .onChange(of: draft.behavior) { if !formats.contains(draft.format) { draft.format = formats[0] } }
            .onChange(of: draft.format) { previous, next in
                let kind = draft.isDatabase ? draft.identifier : draft.behavior
                if draft.url == ManagedResource.defaultURL(kind, format: previous) { draft.url = ManagedResource.defaultURL(kind, format: next) }
            }
            .fileImporter(isPresented: $picking, allowedContentTypes: [.data]) { result in
                do {
                    let source = try result.get(), scoped = source.startAccessingSecurityScopedResource()
                    defer { if scoped { source.stopAccessingSecurityScopedResource() } }
                    let size = try source.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
                    guard size > 0, size <= ResourceLimits.fileBytes else { throw ClientError.message("资源为空或超过 128 MiB。") }
                    let copy = FileManager.default.temporaryDirectory.appendingPathComponent("mimo-reka-local-" + UUID().uuidString)
                    try FileManager.default.copyItem(at: source, to: copy)
                    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: copy.path)
                    if let old = draft.localFile { try? FileManager.default.removeItem(at: old) }
                    draft.localFile = copy; draft.fileName = source.lastPathComponent; failure = nil
                } catch { if (error as NSError).code != NSUserCancelledError { failure = error.localizedDescription } }
            }
            .onDisappear { if let file = draft.localFile { try? FileManager.default.removeItem(at: file) } }
    }
}
