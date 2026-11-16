import SwiftUI
import Yams

@MainActor
struct RulesDNSView: View {
    let store: AppStore
    var search: String
    @State private var section = "rules"
    @State private var editing: RuleEditRequest?
    @State private var showingPlan = false

    private struct RuleEditRequest: Identifiable {
        let id = UUID()
        let record: RuleRecord?
        var sourceMarker = false
    }
    private var filteredRules: [RuleRecord] {
        store.ruleRecords.filter {
            search.isEmpty || "\(matchTitle($0)) \(targetTitle($0)) \($0.origin)".localizedCaseInsensitiveContains(search)
        }
    }

    var body: some View {
        VStack(spacing: 16) {
            HStack {
                Picker("分类", selection: $section) { Text("路由规则").tag("rules"); Text("DNS").tag("dns") }
                    .pickerStyle(.segmented).frame(width: 230)
                Spacer()
                if section == "rules" {
                    Button("新增规则", systemImage: "plus") { editing = RuleEditRequest(record: nil) }
                        .disabled(!store.isOnline || store.isBusy)
                    Menu {
                        Button("插入来源规则块") { editing = RuleEditRequest(record: nil, sourceMarker: true) }
                            .disabled(store.sources.isEmpty)
                        Divider()
                        Button("高级 YAML 编辑") { store.editingLayer = .profile }
                        Button("查看用户覆盖") { store.editingLayer = .overlay }
                    } label: { Image(systemName: "ellipsis.circle") }
                    .menuStyle(.borderlessButton).fixedSize().disabled(!store.isOnline || store.isBusy)
                } else {
                    Button("编辑 DNS", systemImage: "slider.horizontal.3") { openVisual("dns") }
                        .disabled(!store.isOnline || store.isBusy)
                }
            }
            if section == "rules" {
                HStack {
                    Text("从上到下匹配，第一条命中规则生效。")
                    Spacer()
                    Text("\(store.ruleRecords.count) 项")
                }.font(.caption).foregroundStyle(.secondary)
                rulesContent
            } else { dnsContent }
        }.padding(.horizontal, 20).padding(.top, Theme.pageTopInset).padding(.bottom, 20)
            .onAppear { if ProcessInfo.processInfo.environment["MIMO_REKA_PREVIEW_PAGE"] == "dns" { section = "dns" } }
            .sheet(item: $editing, onDismiss: { store.preparedChange = nil }) { request in
                RuleEditorSheet(store: store, record: request.record, sourceMarker: request.sourceMarker)
            }
            .sheet(isPresented: $showingPlan, onDismiss: { store.preparedChange = nil }) { RuleChangeSheet(store: store) }
            .task(id: store.isOnline) {
                if store.isOnline, ProcessInfo.processInfo.environment["MIMO_REKA_PREVIEW_EDITOR"] == "rule" {
                    editing = RuleEditRequest(record: nil)
                }
            }
    }

    private var rulesContent: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(filteredRules) { rule in
                    ruleRow(rule)
                    if rule.id != filteredRules.last?.id { Divider().padding(.leading, 58) }
                }
                if filteredRules.isEmpty {
                    EmptyState(title: search.isEmpty ? "暂无路由规则" : "没有匹配的规则", symbol: "list.bullet.rectangle",
                               detail: search.isEmpty ? "新增一条规则，选择匹配条件与出口。" : nil)
                }
            }.surface()
        }
    }

    private func ruleRow(_ rule: RuleRecord) -> some View {
        HStack(spacing: 12) {
            Text("\(rule.number)").font(.caption.monospacedDigit()).foregroundStyle(.tertiary)
                .frame(width: 28, alignment: .trailing)
            if rule.sourceMarker { Image(systemName: "tray.full").foregroundStyle(.secondary).frame(width: 20) }
            VStack(alignment: .leading, spacing: 6) {
                Text(matchTitle(rule)).font(.callout.weight(rule.sourceMarker ? .medium : .regular))
                    .textSelection(.enabled).lineLimit(3)
                HStack(spacing: 8) {
                    Text(rule.origin)
                    if rule.sourceID != nil && rule.profileIndex == nil { Text("编辑保留为覆盖") }
                }.font(.caption).foregroundStyle(.tertiary)
            }.frame(maxWidth: .infinity, alignment: .leading)
            if !rule.sourceMarker {
                Text(targetTitle(rule)).font(.callout).foregroundStyle(.secondary)
                    .lineLimit(2).frame(maxWidth: 140, alignment: .trailing)
            }
            HStack(spacing: 8) {
                if rule.movable {
                    Button { move(rule, direction: -1) } label: { Image(systemName: "chevron.up") }
                        .disabled(!canMove(rule, direction: -1)).help("上移规则")
                    Button { move(rule, direction: 1) } label: { Image(systemName: "chevron.down") }
                        .disabled(!canMove(rule, direction: 1)).help("下移规则")
                }
                Button { edit(rule) } label: { Image(systemName: "pencil") }
                    .disabled(!rule.editable).help("编辑规则")
                Button(role: .destructive) { remove(rule) } label: { Image(systemName: "trash") }
                    .disabled(!rule.editable).help(rule.sourceID == nil ? "删除规则" : "用覆盖移除此规则")
            }.buttonStyle(.borderless).controlSize(.small).disabled(!store.isOnline || store.isBusy)
        }.padding(.horizontal, 14).padding(.vertical, 14)
            .contextMenu {
                Button("编辑规则") { edit(rule) }.disabled(!rule.editable || !store.isOnline || store.isBusy)
                if rule.movable {
                    Button("上移") { move(rule, direction: -1) }.disabled(!canMove(rule, direction: -1))
                    Button("下移") { move(rule, direction: 1) }.disabled(!canMove(rule, direction: 1))
                }
                Divider()
                Button("删除…", role: .destructive) { remove(rule) }.disabled(!rule.editable || !store.isOnline || store.isBusy)
            }
    }

    private func canMove(_ rule: RuleRecord, direction: Int) -> Bool {
        guard search.isEmpty, rule.movable, let index = rule.profileIndex, store.isOnline, !store.isBusy else { return false }
        let count = ((try? YAMLDocument.array(store.documents[.profile] ?? "", key: "rules")) ?? []).count
        return (0..<count).contains(index + direction)
    }
    private func edit(_ rule: RuleRecord) { editing = RuleEditRequest(record: rule, sourceMarker: rule.sourceMarker) }
    private func remove(_ rule: RuleRecord) {
        let base = store.revision
        store.preparedChange = nil
        Task {
            await store.removeRule(rule, baseRevision: base)
            if store.preparedChange != nil { showingPlan = true }
        }
    }
    private func move(_ rule: RuleRecord, direction: Int) {
        let base = store.revision
        store.preparedChange = nil
        Task {
            await store.moveRule(rule, direction: direction, baseRevision: base)
            if store.preparedChange != nil { showingPlan = true }
        }
    }
    private func openVisual(_ section: String) { store.visualSection = section; store.showVisualConfiguration = true }
    private func matchTitle(_ rule: RuleRecord) -> String {
        if rule.sourceMarker {
            let id = rule.definition["source"]?.stringValue ?? ""
            return "来源规则 · " + (store.sources.first { $0.id == id }?.name ?? id)
        }
        let match = rule.definition["match"]?.objectValue ?? [:]
        if match["all"]?.boolValue == true { return "MATCH · 全部流量" }
        return match.keys.sorted().filter { $0 != "no-resolve" }.map { key in
            let value = match[key] ?? .null
            let text = value.stringValue ?? value.arrayValue?.map { $0.stringValue ?? $0.prettyPrinted }.joined(separator: ", ") ?? value.prettyPrinted
            return "\(RuleDraft.title(key)) · \(text)"
        }.joined(separator: " · ")
    }
    private func targetTitle(_ rule: RuleRecord) -> String {
        if let call = rule.definition["call"]?.stringValue { return "子规则 · " + call }
        return store.displayName(rule.definition["outbound"]?.stringValue ?? "direct")
    }

    private var dnsContent: some View {
        let profile = document(.profile)
        let dns = profile["dns"] as? [String: Any] ?? [:]
        let sourceID = dns["from"] as? String
        let sourceList = document(.sources)["sources"] as? [[String: Any]] ?? []
        let sourceDNS = sourceList.first { $0["id"] as? String == sourceID }?["dns"] as? [String: Any]
        let resolved = sourceDNS ?? dns
        return ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                VStack(alignment: .leading, spacing: 14) {
                    PanelHeader(title: "DNS 配置")
                    if resolved.isEmpty {
                        Text("当前未配置独立 DNS。普通代理连接使用内核的默认解析行为。")
                            .font(.callout).foregroundStyle(.secondary)
                    } else {
                        if let sourceID { LabeledContent("配置来源", value: store.sources.first { $0.id == sourceID }?.name ?? sourceID) }
                        Text(yaml(resolved)).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    Button("可视化编辑 DNS", systemImage: "slider.horizontal.3") { openVisual("dns") }
                        .disabled(!store.isOnline || store.isBusy)
                }.panel()
                VStack(alignment: .leading, spacing: 12) {
                    PanelHeader(title: "本机网络")
                    LabeledContent("运行状态", value: store.networkState)
                    LabeledContent("网络服务", value: store.networkService)
                    Button("可视化编辑本机设置") { openVisual("network") }.disabled(!store.isOnline || store.isBusy)
                }.panel()
            }
        }
    }
    private func document(_ layer: ConfigurationLayer) -> [String: Any] {
        (try? Yams.load(yaml: store.documents[layer] ?? "")) as? [String: Any] ?? [:]
    }
    private func yaml(_ value: Any) -> String {
        ((try? Yams.dump(object: value, sortKeys: true)) ?? String(describing: value)).trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

@MainActor
private struct RuleChangeSheet: View {
    @Bindable var store: AppStore
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            SheetHeader(symbol: "list.bullet.rectangle", title: store.preparedChange?.summary ?? "规则变更")
            if let prepared = store.preparedChange { ChangePlanView(prepared: prepared).frame(minHeight: 150, maxHeight: 230) }
            Text("规则按顺序匹配。调整顺序或删除规则会改变后续新连接的路由。")
                .font(.caption).foregroundStyle(.secondary)
            Divider()
            HStack {
                if store.isBusy { ProgressView().controlSize(.small) }
                Spacer()
                Button("取消", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("应用变更") {
                    Task { await store.applyPrepared(); if store.errorMessage == nil { dismiss() } }
                }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(store.preparedChange == nil)
            }
        }.padding(24).frame(width: 590).disabled(store.isBusy).interactiveDismissDisabled(store.isBusy)
            .alert("规则未应用", isPresented: Binding(get: { store.errorMessage != nil }, set: { if !$0 { store.errorMessage = nil } })) {
                Button("好", role: .cancel) { store.errorMessage = nil }
            } message: { Text(store.errorMessage ?? "") }
    }
}
