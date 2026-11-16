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

    private var canSubmit: Bool {
        !store.isBusy && store.isOnline && !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
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
                    Button("选择文件…", systemImage: "doc") { showFilePicker = true }
                }
                TextEditor(text: $data).trackEditor().frame(minHeight: 105, maxHeight: .infinity)
                    .accessibilityLabel("待导入的配置或分享链接")
            }
            if format != "native" || input == "url" {
                Toggle("仅导入节点", isOn: $nodesOnly)
                Text(nodesOnly ? "创建代理选择组；来源中的规则与 DNS 不会启用。" : "严格转换节点、策略组与规则。导入规则优先生效，请在对应来源策略组中选节点；来源 DNS 需另行启用。")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Text("原生配置会替换当前主配置，保留本机设置、来源和用户覆盖。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if let prepared = store.preparedChange, input == "text" {
                ChangePlanView(prepared: prepared).frame(maxHeight: 150)
            } else if let report = store.importPreview, input == "text" {
                ScrollView { Text(report).font(.caption.monospaced()).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                    .frame(maxHeight: 130).padding(12).surface()
            } else if input == "url" {
                Text("由 Reka 下载并管理订阅。刷新失败时保留上次成功的内容。")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer(minLength: 0)
            }
            Divider()
            HStack(spacing: 12) {
                if store.isBusy { ProgressView().controlSize(.small); Text("正在处理…").font(.caption).foregroundStyle(.secondary) }
                Spacer()
                Button("取消", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).disabled(store.isBusy)
                if input == "text" {
                    Button("预览") {
                        Task { await store.previewImport(data: data, format: format, nodesOnly: nodesOnly, sourceName: name) }
                    }.disabled(!canSubmit)
                    Button("应用配置") {
                        Task {
                            await store.applyPrepared()
                            if store.errorMessage == nil { dismiss() }
                        }
                    }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                        .disabled(!canSubmit || store.preparedChange == nil)
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
            .interactiveDismissDisabled(store.isBusy)
            .disabled(store.isBusy)
            .fileImporter(isPresented: $showFilePicker, allowedContentTypes: [.data]) { result in load(result) }
            .onChange(of: data) { invalidate() }
            .onChange(of: format) { invalidate() }
            .onChange(of: nodesOnly) { invalidate() }
            .onChange(of: name) { invalidate() }
            .onChange(of: input) { invalidate() }
            .onAppear { invalidate() }
            .alert("导入未完成", isPresented: Binding(get: { store.errorMessage != nil }, set: { if !$0 { store.errorMessage = nil } })) {
                Button("好", role: .cancel) { store.errorMessage = nil }
            } message: { Text(store.errorMessage ?? "") }
    }

    private func invalidate() { store.preparedChange = nil; store.importPreview = nil }
    private func load(_ result: Result<URL, Error>) {
        do {
            let file = try result.get()
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

struct ChangePlanView: View {
    let prepared: PreparedChange
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                Label(prepared.summary, systemImage: "checkmark.circle").font(.callout.weight(.medium))
                if prepared.plan["interrupts"].boolValue == true {
                    Label("这次变更可能中断现有连接。", systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange)
                }
                if let note = prepared.plan["network_note"].stringValue, !note.isEmpty {
                    Text(note).font(.caption).foregroundStyle(.secondary)
                }
                if !prepared.report.isEmpty {
                    Text(prepared.report).font(.caption.monospaced()).textSelection(.enabled).foregroundStyle(.secondary)
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
        }.padding(12).surface()
    }
}
