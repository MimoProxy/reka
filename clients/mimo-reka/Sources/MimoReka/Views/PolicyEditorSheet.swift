import SwiftUI

struct PolicyEditorRequest: Identifiable {
    let id = UUID()
    var groupID: String?
}

private struct PolicyMemberDraft: Identifiable, Equatable {
    let id = UUID()
    let resourceID: String
}

/// A native form edits only the fields the user changes. The resource resolver
/// keeps source identities and overlay values separate from display names.
@MainActor
struct PolicyEditorSheet: View {
    @Bindable var store: AppStore
    @Environment(\.dismiss) private var dismiss
    @State private var resource: EditableResource?
    @State private var definition: [String: JSONValue]
    @State private var members: [PolicyMemberDraft]
    @State private var baseRevision: Int
    @State private var localError: String?
    @State private var memberSearch = ""
    @State private var confirmingDelete = false
    @State private var showAdvanced = false
    @State private var hasChanges = false

    init(store: AppStore, groupID: String?) {
        self.store = store
        let found: EditableResource?
        let value: [String: JSONValue]
        let initialError: String?
        do {
            if let groupID {
                found = try VisualConfigurationService.group(id: groupID, documents: store.documents, effective: store.effectiveConfiguration)
                value = found!.definition
            } else {
                found = nil
                value = ["id": .string("group-" + String(UUID().uuidString.lowercased().prefix(8))),
                         "name": .string("新策略组"), "type": .string("select"),
                         "members": .array([.string("direct")]), "selected": .string("direct")]
            }
            initialError = nil
        } catch {
            found = nil
            value = [:]
            initialError = error.localizedDescription
        }
        self._resource = State(initialValue: found)
        self.definition = value
        self.members = (value["members"]?.arrayValue ?? []).compactMap(\.stringValue).map(PolicyMemberDraft.init(resourceID:))
        self.baseRevision = store.revision
        self._localError = State(initialValue: initialError)
    }

    private var groupType: String { definition["type"]?.stringValue ?? "select" }
    private var automatic: Bool { groupType != "select" }
    private var supportedTypes: [String] {
        var types = (store.capabilities["group_types"].arrayValue ?? []).compactMap(\.stringValue)
        if types.isEmpty { types = ["select", "url-test", "fallback", "load-balance"] }
        if !types.contains(groupType) { types.append(groupType) }
        return types
    }
    private var currentID: String { definition["id"]?.stringValue ?? "" }
    private var candidates: [String] {
        var ids: [String] = []
        for value in store.outbounds.map(\.id) + store.groups.map(\.id) + ["direct", "reject"] + members.map(\.resourceID)
            where value != currentID && !ids.contains(value) { ids.append(value) }
        return ids.filter { memberSearch.isEmpty || store.displayName($0).localizedCaseInsensitiveContains(memberSearch) || $0.localizedCaseInsensitiveContains(memberSearch) }
    }
    private var selectedMemberIDs: [String] { members.map(\.resourceID) }
    private var errorText: String? { localError ?? store.errorMessage }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            SheetHeader(symbol: "arrow.triangle.branch", title: resource == nil ? "新建策略组" : "编辑策略组")
            if resource?.isImported == true {
                Label("此策略的修改保存在用户覆盖中，来源刷新时继续保留。", systemImage: "square.stack")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if resource?.id == "proxy", resource?.definition["include-all"] == nil {
                Text("默认策略会随来源补充节点；修改成员后改为手动管理，排除的节点不会被刷新加回。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    identitySection
                    membersSection
                    if automatic { healthSection }
                    advancedSection
                }
                .padding(.trailing, 4)
            }
            if let errorText, !errorText.isEmpty {
                Text(errorText).font(.caption).foregroundStyle(.red).textSelection(.enabled).lineLimit(4)
            }
            Divider()
            footer
        }
        .padding(24)
        .frame(width: 780, height: 690)
        .disabled(store.isBusy)
        .interactiveDismissDisabled(store.isBusy || hasChanges)
        .onAppear { store.preparedChange = nil; store.errorMessage = nil }
        .onDisappear { store.preparedChange = nil }
        .onChange(of: definition) { invalidatePreview() }
        .onChange(of: groupType) { previous, next in
            if previous == "select", next != "select" {
                // An inherited manual choice must not silently pin a newly
                // automatic policy. Existing automatic overrides stay intact.
                definition.removeValue(forKey: "selected")
            }
        }
        .onChange(of: members) {
            definition["members"] = .array(members.map { .string($0.resourceID) })
            invalidatePreview()
        }
        .confirmationDialog("删除此策略组？", isPresented: $confirmingDelete) {
            Button("删除策略组", role: .destructive) { Task { await deleteGroup() } }
            Button("取消", role: .cancel) {}
        } message: {
            Text("Reka 会检查引用。若规则或其他策略组仍然使用它，删除将被拒绝，当前配置保持不变。")
        }
    }

    private var identitySection: some View {
        VStack(spacing: 0) {
            FieldRow(title: "名称") { TextField("策略组名称", text: string("name")).trackField() }
            Divider()
            FieldRow(title: "类型") {
                Picker("类型", selection: string("type", fallback: "select")) {
                    ForEach(supportedTypes, id: \.self) { value in Text(Self.typeTitle(value)).tag(value) }
                }.labelsHidden().frame(width: 220)
                Spacer()
            }
            Divider()
            FieldRow(title: automatic ? "固定选择" : "初始选择") {
                Picker("初始选择", selection: string("selected")) {
                    Text(automatic ? "自动选择" : "使用首个成员").tag("")
                    ForEach(selectionChoices, id: \.self) { member in Text(choiceName(member)).tag(member) }
                }.labelsHidden().frame(maxWidth: 360)
                Spacer()
            }
            if automatic {
                Text("固定选择会优先于自动策略；选择“自动选择”即可交由健康检查决定。")
                    .font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).padding(.bottom, 12)
            }
            if let index = resource?.profileIndex {
                Divider()
                FieldRow(title: "显示顺序") {
                    Button("上移", systemImage: "arrow.up") { Task { await moveGroup(-1) } }
                        .disabled(index == 0 || hasChanges)
                    Button("下移", systemImage: "arrow.down") { Task { await moveGroup(1) } }
                        .disabled(index >= profileGroupCount - 1 || hasChanges)
                    Spacer()
                    if hasChanges { Text("先保存表单修改").font(.caption).foregroundStyle(.secondary) }
                }
            }
        }.padding(.horizontal, 16).surface()
    }

    private var selectionChoices: [String] {
        var ids = selectedMemberIDs
        if definition["include-all"]?.boolValue == true {
            for id in store.outbounds.map(\.id) where !ids.contains(id) { ids.append(id) }
        }
        if let selected = definition["selected"]?.stringValue, !selected.isEmpty, !ids.contains(selected) { ids.append(selected) }
        return ids
    }

    private var membersSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(title: "成员与顺序") {
                Text("\(members.count) 个显式成员").font(.caption).foregroundStyle(.secondary)
            }
            if !members.isEmpty {
                VStack(spacing: 0) {
                    ForEach(members) { member in
                        HStack(spacing: 10) {
                            Text(choiceName(member.resourceID)).font(.callout).lineLimit(1)
                            Spacer()
                            Button { move(member.id, by: -1) } label: { Image(systemName: "chevron.up") }
                                .disabled(members.first?.id == member.id).help("向前移动")
                                .accessibilityLabel("向前移动成员 \(choiceName(member.resourceID))")
                            Button { move(member.id, by: 1) } label: { Image(systemName: "chevron.down") }
                                .disabled(members.last?.id == member.id).help("向后移动")
                                .accessibilityLabel("向后移动成员 \(choiceName(member.resourceID))")
                            Button { toggleMember(member.resourceID, selected: false) } label: { Image(systemName: "minus.circle") }
                                .help("移除此成员")
                                .accessibilityLabel("移除成员 \(choiceName(member.resourceID))")
                        }.buttonStyle(.borderless).padding(.vertical, 7)
                        if members.last?.id != member.id { Divider() }
                    }
                }
                Divider()
            }
            TextField("搜索节点或其他策略组", text: $memberSearch).textFieldStyle(.roundedBorder)
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 210), alignment: .leading)], alignment: .leading, spacing: 10) {
                ForEach(candidates, id: \.self) { id in
                    Toggle(isOn: Binding(get: { selectedMemberIDs.contains(id) }, set: { toggleMember(id, selected: $0) })) {
                        Text(choiceName(id)).font(.callout).lineLimit(1)
                    }.toggleStyle(.checkbox)
                }
            }
            Text("故障转移按成员顺序尝试；保存时会检查并拒绝组间循环引用。")
                .font(.caption).foregroundStyle(.secondary)
        }.panel()
    }

    private var healthSection: some View {
        VStack(spacing: 0) {
            FieldRow(title: "检测地址") { TextField("https://www.gstatic.com/generate_204", text: string("url")).trackField(monospaced: true) }
            Divider()
            FieldRow(title: "检测间隔") { number("interval", fallback: 300); Text("秒").foregroundStyle(.secondary); Spacer() }
            Divider()
            FieldRow(title: "超时") { number("timeout", fallback: 5000); Text("毫秒").foregroundStyle(.secondary); Spacer() }
            if groupType == "url-test" {
                Divider()
                FieldRow(title: "切换容差") { number("tolerance", fallback: 0); Text("毫秒").foregroundStyle(.secondary); Spacer() }
            }
            if groupType == "load-balance" {
                Divider()
                FieldRow(title: "负载策略") {
                    Picker("负载策略", selection: string("strategy", fallback: "consistent-hashing")) {
                        Text("一致性哈希").tag("consistent-hashing")
                        Text("轮询").tag("round-robin")
                    }.labelsHidden().frame(width: 220)
                    Spacer()
                }
            }
            Divider()
            FieldRow(title: "按需检测") { Toggle("成员被使用后开始健康检查", isOn: boolean("lazy", fallback: true)).toggleStyle(.checkbox); Spacer() }
        }.padding(.horizontal, 16).surface()
    }

    private var advancedSection: some View {
        DisclosureGroup("高级选项", isExpanded: $showAdvanced) {
            VStack(spacing: 0) {
                FieldRow(title: "标识") {
                    if resource == nil { TextField("稳定标识", text: string("id")).trackField(monospaced: true) }
                    else { Text(currentID).font(.caption.monospaced()).textSelection(.enabled); Spacer() }
                }
                Divider()
                FieldRow(title: "包含全部") { Toggle("自动包含作用域中的节点", isOn: boolean("include-all")).toggleStyle(.checkbox); Spacer() }
                Divider()
                FieldRow(title: "包含筛选") { TextField("节点名称正则表达式", text: string("filter")).trackField() }
                Divider()
                FieldRow(title: "排除筛选") { TextField("节点名称正则表达式", text: string("exclude-filter")).trackField() }
                Divider()
                FieldRow(title: "UDP") { Toggle("禁用经此策略组的 UDP", isOn: boolean("disable-udp")).toggleStyle(.checkbox); Spacer() }
                if automatic {
                    Divider()
                    FieldRow(title: "成功状态码") { TextField("默认 200–399", text: string("expected-status")).trackField(monospaced: true) }
                }
                Divider()
                Text("未在表单中展示的现有字段会保留。标识用于配置引用，已有策略组不能在这里更改标识。")
                    .font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 12)
            }
        }.panel()
    }

    private var footer: some View {
        HStack(spacing: 12) {
            if resource != nil {
                Button("删除策略组…", role: .destructive) { confirmingDelete = true }
            }
            Spacer()
            if store.isBusy { ProgressView().controlSize(.small) }
            Button("取消", role: .cancel) { store.preparedChange = nil; dismiss() }.keyboardShortcut(.cancelAction)
            Button("保存") { Task { await save() } }
                .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                .disabled(definition.isEmpty || !store.isOnline)
        }
    }

    private func string(_ key: String, fallback: String = "") -> Binding<String> {
        Binding(get: { definition[key]?.stringValue ?? fallback }, set: { definition[key] = .string($0) })
    }
    private func boolean(_ key: String, fallback: Bool = false) -> Binding<Bool> {
        Binding(get: { definition[key]?.boolValue ?? fallback }, set: { definition[key] = .bool($0) })
    }
    private func number(_ key: String, fallback: Int) -> some View {
        TextField("", value: Binding(get: { definition[key]?.intValue ?? fallback }, set: { definition[key] = .number(Double($0)) }), format: .number.grouping(.never))
            .trackField(monospaced: true).frame(width: 130)
    }
    private func toggleMember(_ id: String, selected: Bool) {
        if selected {
            if !members.contains(where: { $0.resourceID == id }) { members.append(PolicyMemberDraft(resourceID: id)) }
        } else {
            members.removeAll { $0.resourceID == id }
            if definition["selected"]?.stringValue == id && definition["include-all"]?.boolValue != true {
                definition["selected"] = .string(groupType == "select" ? members.first?.resourceID ?? "" : "")
            }
        }
    }
    private func move(_ id: UUID, by distance: Int) {
        guard let index = members.firstIndex(where: { $0.id == id }), members.indices.contains(index + distance) else { return }
        members.swapAt(index, index + distance)
    }
    private func invalidatePreview() {
        store.preparedChange = nil
        localError = nil
        hasChanges = true
    }
    private func save() async {
        localError = nil
        do {
            let change = try VisualConfigurationService.groupChange(resource: resource, value: definition, baseRevision: baseRevision, documents: store.documents)
            if await store.previewVisualChange(change, summary: resource == nil ? "新增策略组" : "修改策略组", save: true) { dismiss() }
        } catch { localError = error.localizedDescription }
    }
    private func deleteGroup() async {
        guard let resource else { return }
        localError = nil
        do {
            let change = try VisualConfigurationService.removeGroupChange(resource: resource, baseRevision: baseRevision, documents: store.documents)
            if await store.previewVisualChange(change, summary: "删除策略组", save: true) { dismiss() }
        } catch { localError = error.localizedDescription }
    }
    private var profileGroupCount: Int {
        (try? YAMLDocument.array(store.documents[.profile] ?? "", key: "groups").count) ?? 0
    }
    private func moveGroup(_ direction: Int) async {
        guard let resource else { return }
        localError = nil
        do {
            let change = try VisualConfigurationService.moveGroupChange(resource: resource, direction: direction, baseRevision: baseRevision, documents: store.documents)
            if await store.previewVisualChange(change, summary: direction < 0 ? "上移策略组" : "下移策略组", save: true) { dismiss() }
        } catch { localError = error.localizedDescription }
    }
    private func choiceName(_ id: String) -> String {
        let name = store.displayName(id)
        let duplicates = (store.outbounds.map(\.id) + store.groups.map(\.id)).filter { store.displayName($0) == name }
        guard duplicates.count > 1, let sourceID = id.split(separator: "/").first, id.contains("/") else { return name }
        let source = store.sources.first { $0.id == String(sourceID) }?.name ?? String(sourceID)
        return "\(name) · \(source)"
    }
    private static func typeTitle(_ type: String) -> String {
        switch type {
        case "select": "手动选择 · select"
        case "url-test": "自动测速 · url-test"
        case "fallback": "故障转移 · fallback"
        case "load-balance": "负载均衡 · load-balance"
        default: type
        }
    }
}
