import SwiftUI

@MainActor
struct DocumentEditorSheet: View {
    @Bindable var store: AppStore
    @Environment(\.dismiss) private var dismiss
    @State private var layer: ConfigurationLayer
    @State private var text: String
    @State private var original: String
    @State private var baseRevision: Int
    @State private var pendingLayer: ConfigurationLayer?
    @State private var showDiscard = false

    init(store: AppStore, layer: ConfigurationLayer) {
        self.store = store
        self.layer = layer
        let value = store.documents[layer] ?? ""
        self.text = value
        self.original = value
        self.baseRevision = store.revision
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            SheetHeader(symbol: "slider.horizontal.3", title: "编辑配置")
            HStack(alignment: .top, spacing: 18) {
                VStack(spacing: 4) {
                    ForEach(ConfigurationLayer.allCases) { item in
                        Button { switchLayer(item) } label: {
                            HStack {
                                Text(item.title).font(.callout)
                                Spacer()
                            }.padding(.horizontal, 12).frame(height: 36)
                                .background(layer == item ? Theme.selectedFill : .clear, in: RoundedRectangle(cornerRadius: 8))
                        }.buttonStyle(.plain)
                    }
                    Spacer()
                }.frame(width: 145)
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text(layer.title).font(.headline)
                        Spacer()
                        Text("基于 r\(baseRevision)").font(.caption).foregroundStyle(.tertiary)
                    }
                    Text(layer.detail).font(.caption).foregroundStyle(.secondary)
                    TextEditor(text: $text).trackEditor().accessibilityLabel("\(layer.title) YAML 编辑器")
                    if let prepared = store.preparedChange {
                        ChangePlanView(prepared: prepared).frame(height: 120)
                    }
                    Text("保存前先预览。隐藏的凭据保持为星号时会保留原值。")
                        .font(.caption).foregroundStyle(.tertiary)
                }
            }
            Divider()
            HStack {
                if text != original { Text("有未提交的修改").font(.caption).foregroundStyle(.secondary) }
                if store.isBusy { ProgressView().controlSize(.small) }
                Spacer()
                Button("取消", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("预览变更") { Task { await store.previewDocument(layer: layer, text: text, baseRevision: baseRevision) } }
                    .disabled(!store.isOnline)
                Button("应用") {
                    Task {
                        await store.applyPrepared()
                        if store.errorMessage == nil { dismiss() }
                    }
                }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(store.preparedChange == nil || !store.isOnline)
            }
        }.padding(24).frame(width: 900, height: 650)
            .disabled(store.isBusy).interactiveDismissDisabled(store.isBusy || text != original)
            .onChange(of: text) { store.preparedChange = nil }
            .onAppear { store.preparedChange = nil }
            .confirmationDialog("放弃未提交的修改？", isPresented: $showDiscard) {
                Button("放弃修改", role: .destructive) { if let pendingLayer { load(pendingLayer) } }
                Button("继续编辑", role: .cancel) { pendingLayer = nil }
            }
            .alert("配置未应用", isPresented: Binding(get: { store.errorMessage != nil }, set: { if !$0 { store.errorMessage = nil } })) {
                Button("好", role: .cancel) { store.errorMessage = nil }
            } message: { Text(store.errorMessage ?? "") }
    }

    private func switchLayer(_ item: ConfigurationLayer) {
        guard item != layer else { return }
        if text != original { pendingLayer = item; showDiscard = true }
        else { load(item) }
    }
    private func load(_ item: ConfigurationLayer) {
        layer = item
        text = store.documents[item] ?? ""
        original = text
        baseRevision = store.revision
        pendingLayer = nil
        store.preparedChange = nil
    }
}
