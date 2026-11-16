import SwiftUI
import AppKit
import UniformTypeIdentifiers

@MainActor
struct BackupSheet: View {
    @Bindable var store: AppStore
    @Environment(\.dismiss) private var dismiss
    @State private var backup: NativeBackup?
    @State private var busy = false
    @State private var picking = false
    @State private var status = ""
    @State private var failure: String?
    @State private var baseRevision: Int
    init(store: AppStore) { self.store = store; _baseRevision = State(initialValue: store.revision) }
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            SheetHeader(symbol: "externaldrive", title: "完整配置备份")
            Text("备份当前配置的四个配置层、选组和引用资源。文件包含订阅地址与内联账号密码，请保存到可信位置。钥匙串 secret:// 引用会保留引用，不包含钥匙串里的秘密值。")
                .font(.callout).foregroundStyle(.secondary)
            HStack {
                Button("导出备份（含凭据）…", systemImage: "square.and.arrow.up") { export() }
                Button("选择备份恢复…", systemImage: "square.and.arrow.down") { picking = true }
            }
            if let backup {
                VStack(alignment: .leading, spacing: 10) {
                    LabeledContent("备份配置", value: backup.profileName)
                    LabeledContent("创建时间", value: backup.createdAt.formatted())
                    LabeledContent("引用资源", value: "\(backup.resources.count) 个")
                    Text("恢复将替换当前配置的四个层和来源名称。网络接管保持关闭；应用前请核对内核生成的计划。") .font(.caption).foregroundStyle(.secondary)
                    Button("预览恢复") { Task { await previewRestore() } }
                }.panel()
            }
            if let prepared = store.preparedChange { ChangePlanView(prepared: prepared).frame(height: 130) }
            if !status.isEmpty { Text(status).font(.caption).foregroundStyle(.secondary) }
            if let failure { Text(failure).font(.caption).foregroundStyle(.red).textSelection(.enabled) }
            if let error = store.errorMessage { Text(error).font(.caption).foregroundStyle(.red) }
            HStack {
                if busy || store.isBusy { ProgressView().controlSize(.small) }
                Spacer()
                Button("完成") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("应用恢复") { Task { await applyRestore() } }.buttonStyle(.borderedProminent).disabled(backup == nil || store.preparedChange == nil)
            }
        }.padding(24).frame(width: 730).disabled(busy || store.isBusy || !store.isOnline)
            .interactiveDismissDisabled(busy || store.isBusy)
            .onAppear { store.preparedChange = nil }
            .onDisappear { store.preparedChange = nil }
            .fileImporter(isPresented: $picking, allowedContentTypes: [.data]) { load($0) }
    }
    private func export() {
        let panel = NSSavePanel(); panel.nameFieldStringValue = "Mimo-Reka.rekabackup"; panel.title = "导出包含凭据的完整配置备份"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        busy = true; failure = nil; status = "读取版本绑定的配置清单…"
        let client = store.client, name = store.activeProfile?.name ?? "当前配置", names = store.catalog.sourceNames[store.activeProfileID.uuidString] ?? [:]
        Task {
            defer { busy = false }
            do {
                let value = try await BackupService.export(client: client, name: name, sourceNames: names) { value in await MainActor.run { status = value } }
                try BackupService.write(value, to: url)
                status = "备份已保存，\(value.resources.count) 个资源已校验。"
            } catch { failure = error.localizedDescription; status = "" }
        }
    }
    private func load(_ result: Result<URL, Error>) {
        backup = nil; store.preparedChange = nil; failure = nil; status = ""
        do {
            let url = try result.get(), scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            guard (try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0) <= BackupService.maximumFileBytes else { throw ClientError.message("备份文件过大。") }
            backup = try BackupService.decode(Data(contentsOf: url)); baseRevision = store.revision
            store.preparedChange = nil; failure = nil; status = "备份文件及资源校验通过。"
        } catch { if (error as NSError).code != NSUserCancelledError { failure = error.localizedDescription } }
    }
    private func previewRestore() async {
        guard let backup else { return }
        busy = true; failure = nil
        defer { busy = false }
        do {
            try await BackupService.stage(backup, client: store.client) { value in await MainActor.run { status = value } }
            await store.previewVisualChange(try BackupService.restorationChange(backup, revision: baseRevision), summary: "恢复完整备份 · " + backup.profileName)
        } catch { failure = error.localizedDescription }
    }
    private func applyRestore() async {
        guard let backup else { return }
        await store.applyPrepared()
        guard store.errorMessage == nil else { return }
        do {
            store.catalog.sourceNames[store.activeProfileID.uuidString] = backup.sourceNames
            try store.catalog.save(to: store.homeURL)
            await store.refresh()
            self.backup = nil; baseRevision = store.revision; status = "备份已恢复，网络接管保持关闭。"
        } catch { failure = "配置已恢复，来源名称保存失败：" + error.localizedDescription }
    }
}
