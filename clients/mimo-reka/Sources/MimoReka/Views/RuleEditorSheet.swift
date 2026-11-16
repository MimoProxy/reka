import SwiftUI

@MainActor
struct RuleEditorSheet: View {
    @Bindable var store: AppStore
    let record: RuleRecord?
    @Environment(\.dismiss) private var dismiss
    @State private var draft: RuleDraft
    @State private var baseRevision: Int
    @State private var localError: String?

    init(store: AppStore, record: RuleRecord? = nil, sourceMarker: Bool = false) {
        self.store = store
        self.record = record
        var initial = RuleDraft(definition: record?.definition ?? [:], sourceMarker: sourceMarker)
        if initial.isSourceMarker && initial.sourceMarker.isEmpty { initial.sourceMarker = store.sources.first?.id ?? "" }
        draft = initial
        baseRevision = store.revision
    }

    private var conditionOptions: [String] {
        let advertised = (store.capabilities["rule_conditions"].arrayValue ?? []).compactMap(\.stringValue)
        return RuleDraft.simpleConditions.filter { advertised.isEmpty || advertised.contains($0) || $0 == draft.condition }
    }
    private var destinations: [(id: String, name: String)] {
        var seen = Set<String>()
        return (store.groups.map { (id: $0.id, name: $0.name) } + store.outbounds.map { (id: $0.id, name: $0.name) }
            + [("direct", "直连"), ("reject", "拒绝")]).filter { seen.insert($0.id).inserted }
    }
    private var subRules: [String] {
        let profile = (try? YAMLDocument.object(store.documents[.profile] ?? "")) ?? [:]
        var values = (profile["sub-rules"]?.arrayValue ?? []).compactMap { $0["id"].stringValue }
        let sources = (try? YAMLDocument.array(store.documents[.sources] ?? "", key: "sources")) ?? []
        for source in sources {
            guard let id = source["id"].stringValue else { continue }
            values += (source["sub-rules"].arrayValue ?? []).compactMap { $0["id"].stringValue }.map { id + "/" + $0 }
        }
        if !draft.call.isEmpty && !values.contains(draft.call) { values.append(draft.call) }
        return values
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            SheetHeader(symbol: draft.isSourceMarker ? "tray.and.arrow.down" : "list.bullet.rectangle", title: record == nil ? (draft.isSourceMarker ? "添加来源规则" : "新增规则") : "编辑规则")
            HStack {
                Text("基于 r\(baseRevision)").font(.caption).foregroundStyle(.secondary)
                Spacer()
                if let record { Text(record.origin).font(.caption).foregroundStyle(.secondary) }
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if draft.isSourceMarker { sourceForm } else { matchForm; targetForm }
                    DisclosureGroup("规则标识") {
                        TextField("规则 ID", text: $draft.ruleID).trackField(monospaced: true).disabled(record != nil)
                        Text(record == nil ? "用于稳定引用；名称只接受字母、数字、点、下划线与连字符。" : "已有规则的稳定标识保持不变。")
                            .font(.caption).foregroundStyle(.secondary)
                    }.padding(16).surface()
                    if let record, record.sourceID != nil, record.profileIndex == nil {
                        Label("修改保存在用户覆盖层，订阅刷新后继续保留。", systemImage: "square.stack")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            if let localError { Text(localError).font(.caption).foregroundStyle(.red).textSelection(.enabled) }
            Divider()
            HStack {
                if store.isBusy { ProgressView().controlSize(.small) }
                Spacer()
                Button("取消", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("保存") { save() }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .disabled(!store.isOnline)
            }
        }.padding(24).frame(width: 720, height: 650)
            .disabled(store.isBusy).interactiveDismissDisabled(store.isBusy)
            .onChange(of: draft) { store.preparedChange = nil; localError = nil }
            .onChange(of: draft.replaceComplexMatch) {
                if draft.replaceComplexMatch && !RuleDraft.simpleConditions.contains(draft.condition) {
                    draft.condition = "domain-suffix"; draft.valuesText = ""; draft.noResolve = false
                }
            }
            .onAppear { store.preparedChange = nil }
            .onDisappear { store.preparedChange = nil }
            .alert("规则未应用", isPresented: Binding(get: { store.errorMessage != nil }, set: { if !$0 { store.errorMessage = nil } })) {
                Button("好", role: .cancel) { store.errorMessage = nil }
            } message: { Text(store.errorMessage ?? "") }
    }

    private var sourceForm: some View {
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(title: "来源规则块")
            Picker("规则来源", selection: $draft.sourceMarker) {
                if draft.sourceMarker.isEmpty { Text("请选择").tag("") }
                ForEach(store.sources) { source in Text(source.name).tag(source.id) }
            }
            Text("在此位置展开所选来源的规则。可在列表中移动整个规则块，调整其匹配优先级。")
                .font(.caption).foregroundStyle(.secondary)
        }.panel()
    }

    private var matchForm: some View {
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(title: "匹配条件")
            if draft.hasComplexMatch {
                Label("当前包含复合或高级条件，保持原样时可以单独修改出口。", systemImage: "point.3.connected.trianglepath.dotted")
                    .font(.callout).foregroundStyle(.secondary)
                Toggle("替换为简单匹配条件", isOn: $draft.replaceComplexMatch)
                if draft.preservesComplexMatch {
                    Text(draft.originalDefinition["match"]?.prettyPrinted ?? "")
                        .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                }
            }
            if !draft.preservesComplexMatch {
                Picker("条件类型", selection: $draft.condition) {
                    ForEach(conditionOptions, id: \.self) { condition in Text(RuleDraft.title(condition)).tag(condition) }
                }
                if draft.condition == "all" {
                    Text("匹配后续全部流量。请将兜底规则放在其他规则之后。")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Text("匹配值（每行一项，任意一项匹配即生效）").font(.callout).foregroundStyle(.secondary)
                    TextEditor(text: $draft.valuesText).trackEditor().frame(minHeight: 80, maxHeight: 140)
                        .accessibilityLabel("规则匹配值")
                    Text("例如：\(RuleDraft.example(draft.condition))").font(.caption).foregroundStyle(.tertiary)
                    if draft.supportsNoResolve { Toggle("不额外解析域名（no-resolve）", isOn: $draft.noResolve) }
                }
            }
        }.panel()
    }

    private var targetForm: some View {
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(title: "匹配后的操作")
            Picker("操作", selection: $draft.action) {
                Text("选择出口").tag("outbound")
                if !subRules.isEmpty || draft.action == "call" { Text("调用子规则").tag("call") }
            }.pickerStyle(.segmented)
            if draft.action == "call" {
                Picker("子规则", selection: $draft.call) {
                    if draft.call.isEmpty { Text("请选择").tag("") }
                    ForEach(subRules, id: \.self) { Text($0).tag($0) }
                }
            } else {
                Picker("策略或节点", selection: $draft.outbound) {
                    ForEach(destinations, id: \.id) { destination in Text(destination.name).tag(destination.id) }
                    if !destinations.contains(where: { $0.id == draft.outbound }) { Text(draft.outbound).tag(draft.outbound) }
                }
            }
        }.panel()
    }

    private func save() {
        do {
            let definition = try draft.definition()
            localError = nil
            Task { if await store.previewRule(definition: definition, record: record, baseRevision: baseRevision, save: true) { dismiss() } }
        } catch { localError = error.localizedDescription }
    }
}
