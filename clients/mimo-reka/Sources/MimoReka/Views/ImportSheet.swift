import SwiftUI
import UniformTypeIdentifiers

@MainActor
struct ImportSheet: View {
    @Bindable var store: AppStore
    @Environment(\.dismiss) private var dismiss
    @State private var input = "text"
    @State private var name = "导入来源"
    @State private var data = ""
    @State private var url = ""
    @State private var format = "auto"
    @State private var nodesOnly = false
    @State private var interval = 3600
    @State private var showFilePicker = false
    @State private var choosingResource = false
    @State private var attachments: [ResourceAttachment] = []
    @State private var confirmingReplace = false
    @State private var uploading = false
    @State private var uploadProgress = ""
    private var canStageResources: Bool { (store.capabilities["methods"].arrayValue ?? []).contains(.string("StageResource")) }

    private var canSubmit: Bool {
        !store.isBusy && !uploading && store.isOnline && !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
        !(input == "text" ? data : url).trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            SheetHeader(symbol: "tray.and.arrow.down", title: "导入配置与订阅")
            Picker("导入方式", selection: $input) {
                Text("文件或文本").tag("text")
                Text("订阅地址").tag("url")
            }.pickerStyle(.segmented)
            VStack(spacing: 0) {
                FieldRow(title: "名称") { TextField("来源名称", text: $name).trackField() }
                if input == "url" {
                    Divider()
                    FieldRow(title: "订阅地址") { TextField("https://example.com/subscription", text: $url).trackField(monospaced: true) }
                    Divider()
                    FieldRow(title: "自动刷新") {
                        Picker("自动刷新", selection: $interval) {
                            Text("每小时").tag(3600)
                            Text("每 6 小时").tag(21600)
                            Text("每天").tag(86400)
                        }.labelsHidden().frame(maxWidth: 180)
                        Spacer()
                    }
                }
            }.padding(.horizontal, 16).surface()
            if input == "text" {
                HStack {
                    Picker("格式", selection: $format) {
                        Text("自动识别").tag("auto")
                        Text("Clash YAML").tag("clash")
                        Text("分享链接").tag("links")
                        Text("Reka 原生主配置").tag("native")
                    }.frame(maxWidth: 330)
                    Spacer()
                    Button("选择文件…", systemImage: "doc") { choosingResource = false; showFilePicker = true }
                }
                TextEditor(text: $data).trackEditor().frame(minHeight: 105, maxHeight: .infinity)
                    .accessibilityLabel("待导入的配置或分享链接")
            }
            if input == "text", format != "native", canStageResources { resourceAttachments }
            if format != "native" || input == "url" {
                Toggle("仅导入节点", isOn: $nodesOnly)
                Text(nodesOnly ? "创建代理选择组；来源中的规则与 DNS 不会启用。" : "严格转换节点、策略组与规则。导入规则优先生效，请在对应来源策略组中选节点；来源 DNS 需另行启用。")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Text("原生配置会替换当前主配置，保留本机设置、来源和用户覆盖。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if input == "url" {
                Text("由 Reka 下载并管理订阅。刷新失败时保留上次成功的内容。")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer(minLength: 0)
            }
            Divider()
            HStack(spacing: 12) {
                if store.isBusy || uploading { ProgressView().controlSize(.small); Text(uploading ? uploadProgress : "正在处理…").font(.caption).foregroundStyle(.secondary) }
                Spacer()
                Button("取消", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).disabled(store.isBusy)
                if input == "text" {
                    Button(format == "native" ? "替换主配置…" : "导入") {
                        if format == "native" { confirmingReplace = true }
                        else { Task { await saveWithResources() } }
                    }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(!canSubmit)
                } else {
                    Button("添加并刷新") {
                        Task {
                            await store.addSubscription(name: name, url: url, interval: interval, nodesOnly: nodesOnly)
                            if store.errorMessage == nil { dismiss() }
                        }
                    }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(!canSubmit)
                }
            }
        }.padding(24).frame(width: 720, height: 650)
            .interactiveDismissDisabled(store.isBusy || uploading)
            .disabled(store.isBusy || uploading)
            .confirmationDialog("替换当前主配置？", isPresented: $confirmingReplace) {
                Button("替换主配置", role: .destructive) { Task { await saveWithResources() } }
                Button("取消", role: .cancel) {}
            } message: {
                Text("将替换“\(store.activeProfile?.name ?? "当前配置")”的完整主配置。本机设置、来源和用户覆盖会保留；校验失败时保留现有配置。")
            }
            .fileImporter(isPresented: $showFilePicker, allowedContentTypes: [.data]) { result in load(result) }
            .onChange(of: data) { invalidate() }
            .onChange(of: format) { invalidate() }
            .onChange(of: nodesOnly) { invalidate() }
            .onChange(of: name) { invalidate() }
            .onChange(of: attachments) { invalidate() }
            .onChange(of: input) { invalidate() }
            .onAppear { invalidate() }
            .alert("导入未完成", isPresented: Binding(get: { store.errorMessage != nil }, set: { if !$0 { store.errorMessage = nil } })) {
                Button("好", role: .cancel) { store.errorMessage = nil }
            } message: { Text(store.errorMessage ?? "") }
    }


    private var resourceAttachments: some View {
        DisclosureGroup("规则提供者与地理数据库（\(attachments.count) 个资源）") {
            VStack(alignment: .leading, spacing: 8) {
                Text("为配置中的 rule-providers / proxy-providers 绑定本地文件，或选择 geoip / geosite 数据库。资源先分块上传并校验 SHA-256，再自动校验并导入。")
                    .font(.caption).foregroundStyle(.secondary)
                ScrollView {
                    VStack(spacing: 8) {
                        ForEach($attachments) { $item in
                            HStack {
                                Picker("资源类型", selection: $item.kind) {
                                    Text("规则提供者").tag("rule-providers"); Text("节点提供者").tag("proxy-providers")
                                    Text("GeoIP").tag("geoip"); Text("GeoSite").tag("geosite")
                                }.labelsHidden().frame(width: 140)
                                if !item.isGeodata { TextField("配置中的提供者名称", text: $item.name).textFieldStyle(.roundedBorder) }
                                Text(item.filename).font(.caption).lineLimit(1).help("SHA-256: " + item.hash)
                                Button(role: .destructive) { attachments.removeAll { $0.id == item.id } } label: { Image(systemName: "trash") }.buttonStyle(.borderless)
                            }
                        }
                    }
                }.frame(maxHeight: attachments.isEmpty ? 0 : 100)
                Button("添加资源文件…", systemImage: "paperclip") { choosingResource = true; showFilePicker = true }
                Text("单个文件最多 16 MiB，合计最多 32 MiB。提供者名称必须与配置一致。")
                    .font(.caption2).foregroundStyle(.secondary)
            }.padding(.top, 8)
        }
    }

    private func loadResource(_ file: URL) throws {
        let scoped = file.startAccessingSecurityScopedResource()
        defer { if scoped { file.stopAccessingSecurityScopedResource() } }
        guard (try file.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0) <= 16 * 1024 * 1024 else { throw ClientError.message("单个资源不能超过 16 MiB。") }
        let bytes = try Data(contentsOf: file)
        guard attachments.reduce(bytes.count, { $0 + $1.data.count }) <= 32 * 1024 * 1024 else { throw ClientError.message("资源合计不能超过 32 MiB。") }
        attachments.append(ResourceAttachment(name: file.deletingPathExtension().lastPathComponent, filename: file.lastPathComponent, data: bytes))
    }

    private func saveWithResources() async {
        guard !uploading else { return }
        do {
            let selected = format == "native" ? [] : attachments
            let mappings = try ResourceAttachment.mappings(selected)
            uploading = true
            defer { uploading = false; uploadProgress = "" }
            for item in selected {
                uploadProgress = "上传 \(item.filename)…"
                _ = try await ResourceImportService.stage(data: item.data, client: store.client) { received, total in
                    await MainActor.run { uploadProgress = "上传 \(item.filename) · \(total == 0 ? 100 : received * 100 / total)%" }
                }
            }
            if await store.previewImport(data: data, format: format, nodesOnly: nodesOnly, sourceName: name,
                                      providerResources: mappings.providers, geodataResources: mappings.geodata, save: true) { dismiss() }
        } catch { store.errorMessage = error.localizedDescription }
    }

    private func invalidate() { store.preparedChange = nil }
    private func load(_ result: Result<URL, Error>) {
        do {
            let file = try result.get()
            if choosingResource { try loadResource(file); return }
            let scoped = file.startAccessingSecurityScopedResource()
            defer { if scoped { file.stopAccessingSecurityScopedResource() } }
            guard (try file.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0) <= 8 * 1024 * 1024 else {
                store.errorMessage = "配置文件不能超过 8 MiB。"; return
            }
            data = try String(contentsOf: file, encoding: .utf8)
            if name == "导入来源" { name = file.deletingPathExtension().lastPathComponent }
        } catch {
            if (error as NSError).code != NSUserCancelledError { store.errorMessage = error.localizedDescription }
        }
    }
}
