import SwiftUI

@MainActor
struct VisualConfigurationSheet: View {
    @Bindable var store: AppStore
    @Environment(\.dismiss) private var dismiss
    @State private var section: String
    @State private var draft: VisualConfigurationDraft?
    @State private var baseRevision: Int
    @State private var failure: String?
    @State private var editingNode: NodeEditorRequest?

    init(store: AppStore) {
        self.store = store
        section = store.visualSection == "network" ? "listeners" : store.visualSection
        baseRevision = store.revision
        do {
            _draft = State(initialValue: try VisualConfigurationDraft(documents: store.documents, sourceNames: Dictionary(uniqueKeysWithValues: store.sources.map { ($0.id, $0.name) })))
            _failure = State(initialValue: nil)
        } catch {
            _draft = State(initialValue: nil)
            _failure = State(initialValue: error.localizedDescription)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            SheetHeader(symbol: "slider.horizontal.3", title: "可视化编辑配置")
            HStack(alignment: .top, spacing: 20) {
                VStack(spacing: 4) {
                    category("general", "基本", "doc.text")
                    category("listeners", "监听与日志", "network")
                    category("dns", "DNS", "globe")
                    category("imports", "来源引用", "tray.full")
                    category("nodes", "节点", "server.rack")
                    category("advanced", "高级", "curlybraces")
                    Spacer()
                }.frame(width: 155)
                ScrollView {
                    VStack(alignment: .leading, spacing: 18) {
                        if let failure { Text(failure).foregroundStyle(.red) }
                        if draft != nil {
                            switch section {
                            case "listeners": listenerContent
                            case "dns": dnsContent
                            case "imports": importContent
                            case "nodes": nodeContent
                            case "advanced": advancedContent
                            default: generalContent
                            }
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(.trailing, 3)
                }
            }
            if let prepared = store.preparedChange { ChangePlanView(prepared: prepared).frame(height: 112) }
            Divider()
            HStack {
                Text("基于 r\(baseRevision)").font(.caption).foregroundStyle(.secondary)
                if store.isBusy { ProgressView().controlSize(.small) }
                Spacer()
                Button("取消", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("预览变更") { preview() }.disabled(draft == nil || !store.isOnline)
                Button("应用") {
                    Task { await store.applyPrepared(); if store.errorMessage == nil { dismiss() } }
                }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .disabled(store.preparedChange == nil || !store.isOnline)
            }
        }.padding(24).frame(width: 900, height: 680)
            .disabled(store.isBusy).interactiveDismissDisabled(store.isBusy)
            .onChange(of: draft) { store.preparedChange = nil }
            .onAppear { store.preparedChange = nil }
            .onDisappear { store.preparedChange = nil }
            .sheet(item: $editingNode) { request in NodeEditorSheet(store: store, nodeID: request.nodeID) }
            .alert("配置未应用", isPresented: Binding(get: { store.errorMessage != nil }, set: { if !$0 { store.errorMessage = nil } })) {
                Button("好", role: .cancel) { store.errorMessage = nil }
            } message: { Text(store.errorMessage ?? "") }
    }

    private func category(_ value: String, _ title: String, _ icon: String) -> some View {
        Button { section = value; store.preparedChange = nil } label: {
            Label(title, systemImage: icon).font(.callout).frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 12).frame(height: 38)
                .background(section == value ? Theme.selectedFill : .clear, in: RoundedRectangle(cornerRadius: 9))
        }.buttonStyle(.plain)
    }

    private var generalContent: some View {
        VStack(alignment: .leading, spacing: 14) {
            PanelHeader(title: store.activeProfile?.name ?? "当前配置")
            LabeledContent("配置格式", value: "Reka · schema 1")
            LabeledContent("配置版本", value: "r\(baseRevision)")
            LabeledContent("策略组", value: "\(store.groups.count)")
            LabeledContent("节点", value: "\(store.outbounds.filter { !["direct", "reject"].contains($0.id) }.count)")
            Divider()
            Text("在左侧编辑监听、DNS、来源引用和节点。策略组与路由规则在各自页面编辑，保存前会显示内核校验和变更计划。")
                .font(.callout).foregroundStyle(.secondary)
            Text("未显示的高级字段会保留。")
                .font(.caption).foregroundStyle(.secondary)
        }.panel()
    }

    private var listenerContent: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                PanelHeader(title: "监听器")
                Button("新增", systemImage: "plus") {
                    draft?.listeners.append(ListenerDraft(fields: ["id": .string("listener-" + String(UUID().uuidString.prefix(8)).lowercased()), "type": .string("mixed"), "listen": .string("127.0.0.1:17892")]))
                }
            }
            ForEach(draft?.listeners ?? []) { listener in
                listenerRow(listener.id)
            }
            if draft?.listeners.isEmpty == true { Text("本机设置未定义监听器；主配置中的监听器仍按原配置生效。") .font(.caption).foregroundStyle(.secondary) }
            VStack(alignment: .leading, spacing: 12) {
                PanelHeader(title: "日志")
                Picker("级别", selection: Binding(get: { draft?.logLevel ?? "info" }, set: { draft?.logLevel = $0 })) {
                    ForEach(["debug", "info", "warn", "error"], id: \.self) { Text($0).tag($0) }
                }.frame(maxWidth: 300)
            }.panel()
        }
    }

    private func listenerRow(_ id: UUID) -> some View {
        VStack(spacing: 10) {
            HStack {
                TextField("标识", text: listenerBinding(id, \.identifier)).trackField()
                Button(role: .destructive) { draft?.listeners.removeAll { $0.id == id } } label: { Image(systemName: "trash") }
                    .buttonStyle(.borderless).help("移除监听器")
            }
            HStack(spacing: 12) {
                Picker("类型", selection: listenerBinding(id, \.type)) {
                    Text("HTTP + SOCKS").tag("mixed"); Text("SOCKS").tag("socks"); Text("HTTP").tag("http")
                }.frame(width: 220)
                Toggle("UDP", isOn: listenerUDPBinding(id)).toggleStyle(.checkbox)
                Spacer()
            }
            FieldRow(title: "监听地址") { TextField("127.0.0.1:17891", text: listenerBinding(id, \.listen)).trackField(monospaced: true) }
        }.panel()
    }

    private var dnsContent: some View {
        VStack(alignment: .leading, spacing: 16) {
            Toggle("启用 DNS 配置", isOn: Binding(get: { draft?.dnsEnabled ?? false }, set: { enabled in
                draft?.dnsEnabled = enabled
                if enabled, draft?.dns.isEmpty == true {
                    draft?.dns = ["nameserver": .array([.string("https://1.1.1.1/dns-query")]), "default-nameserver": .array([.string("1.1.1.1")])]
                }
            })).font(.headline)
            if draft?.dnsEnabled == true {
                VStack(alignment: .leading, spacing: 12) {
                    PanelHeader(title: "解析与来源")
                    Picker("DNS 来源", selection: dnsString("from")) {
                        Text("本配置").tag("")
                        ForEach(dnsSources, id: \.id) { Text($0.name).tag($0.id) }
                    }
                    Text("选择来源后，本表单已有的显式字段仍作为覆盖。清空某一项即可使用来源中的对应设置。")
                        .font(.caption).foregroundStyle(.secondary)
                    FieldRow(title: "本地监听") { TextField("可选，例如 127.0.0.1:15353", text: dnsString("listen")).trackField(monospaced: true) }
                    dnsList("上游服务器", key: "nameserver", prompt: "每行一个：1.1.1.1 或 https://1.1.1.1/dns-query")
                    dnsList("引导解析", key: "default-nameserver", prompt: "每行一个 IP DNS 地址")
                    dnsList("代理节点解析", key: "proxy-server-nameserver", prompt: "可选，每行一个服务器")
                    dnsList("直连解析", key: "direct-nameserver", prompt: "可选，每行一个服务器")
                    dnsList("备用解析", key: "fallback", prompt: "可选，每行一个服务器")
                }.panel()
                VStack(alignment: .leading, spacing: 12) {
                    PanelHeader(title: "Fake IP 与缓存")
                    Picker("解析模式", selection: dnsString("enhanced-mode", fallback: "redir-host")) {
                        Text("真实 IP").tag("redir-host"); Text("Fake IP").tag("fake-ip")
                    }
                    if draft?.dns["enhanced-mode"]?.stringValue == "fake-ip" {
                        FieldRow(title: "IPv4 地址池") { TextField("198.18.0.0/16", text: dnsString("fake-ip-range")).trackField(monospaced: true) }
                        FieldRow(title: "IPv6 地址池") { TextField("fc00::/18", text: dnsString("fake-ip-range6")).trackField(monospaced: true) }
                        Picker("过滤方式", selection: dnsString("fake-ip-filter-mode", fallback: "blacklist")) {
                            Text("黑名单").tag("blacklist"); Text("白名单").tag("whitelist")
                        }
                        dnsList("过滤域名", key: "fake-ip-filter", prompt: "每行一个域名模式，例如 +.lan")
                    }
                    FieldRow(title: "缓存条数") { TextField("4096（默认）", text: dnsNumber("cache-size")).trackField() }
                    FieldRow(title: "Fake IP TTL") { TextField("60（默认）", text: dnsNumber("fake-ip-ttl")).trackField() }
                    Toggle("返回 IPv6 解析结果", isOn: dnsBool("ipv6"))
                    Toggle("解析遵循路由规则", isOn: dnsBool("respect-rules"))
                    Toggle("读取系统 hosts", isOn: dnsBool("use-system-hosts"))
                    Toggle("优先使用 HTTP/3", isOn: dnsBool("prefer-h3"))
                }.panel()
            }
        }
    }

    private var importContent: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("选择本配置可以引用的来源。移除仍被规则或策略引用的内容时，内核会拒绝变更并保留原配置。")
                .font(.caption).foregroundStyle(.secondary)
            ForEach(draft?.imports ?? []) { item in
                VStack(alignment: .leading, spacing: 12) {
                    Toggle(item.name, isOn: importBinding(item.id, \.enabled)).font(.headline)
                    HStack(spacing: 18) {
                        Toggle("节点", isOn: importBinding(item.id, \.outbounds))
                        Toggle("策略组", isOn: importBinding(item.id, \.groups))
                    }.toggleStyle(.checkbox).disabled(!item.enabled)
                }.panel()
            }
            if draft?.imports.isEmpty == true { EmptyState(title: "先添加订阅或导入来源", symbol: "tray.full") }
        }
    }

    private var nodeContent: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                PanelHeader(title: "节点")
                Button("新增节点", systemImage: "plus") { editingNode = NodeEditorRequest(nodeID: nil) }.disabled(hasDraftChanges)
            }
            ForEach(store.outbounds.filter { !["direct", "reject"].contains($0.id) }) { node in
                Button { editingNode = NodeEditorRequest(nodeID: node.id) } label: {
                    HStack {
                        VStack(alignment: .leading, spacing: 5) {
                            Text(node.name).font(.callout.weight(.medium))
                            Text("\(node.type) · \(node.server)\(node.port.map { ":\($0)" } ?? "")").font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Image(systemName: "slider.horizontal.3").foregroundStyle(.secondary)
                    }.padding(14).surface()
                }.buttonStyle(.plain).disabled(hasDraftChanges)
            }
            if store.outbounds.filter({ !["direct", "reject"].contains($0.id) }).isEmpty {
                EmptyState(title: "暂无节点", symbol: "server.rack", detail: "新增本地节点，或导入订阅。")
            }
            if hasDraftChanges { Text("请先应用或取消其他配置修改，再编辑节点。") .font(.caption).foregroundStyle(.secondary) }
        }
    }

    private var advancedContent: some View {
        VStack(alignment: .leading, spacing: 14) {
            PanelHeader(title: "高级 YAML")
            Text("可视化表单保留已有的高级字段。逻辑规则、DNS 分域策略和协议扩展参数也可以在 YAML 中编辑。")
                .font(.callout).foregroundStyle(.secondary)
            ForEach(ConfigurationLayer.allCases) { layer in
                Button("编辑\(layer.title) YAML") {
                    dismiss()
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { store.editingLayer = layer }
                }
            }
        }.panel()
    }

    private var dnsSources: [SourceRow] {
        let sourceDefinitions = (try? YAMLDocument.array(store.documents[.sources] ?? "", key: "sources")) ?? []
        return store.sources.filter { row in sourceDefinitions.contains { $0["id"].stringValue == row.id && $0["dns"].objectValue != nil } }
    }
    private var hasDraftChanges: Bool { (draft?.change(baseRevision: baseRevision).count ?? 1) > 1 }
    private func listenerBinding(_ id: UUID, _ path: WritableKeyPath<ListenerDraft, String>) -> Binding<String> {
        Binding(get: { draft?.listeners.first { $0.id == id }?[keyPath: path] ?? "" }, set: { value in
            if let index = draft?.listeners.firstIndex(where: { $0.id == id }) { draft?.listeners[index][keyPath: path] = value }
        })
    }
    private func listenerUDPBinding(_ id: UUID) -> Binding<Bool> {
        Binding(get: { draft?.listeners.first { $0.id == id }?.udp ?? true }, set: { value in
            if let index = draft?.listeners.firstIndex(where: { $0.id == id }) { draft?.listeners[index].udp = value }
        })
    }
    private func importBinding(_ id: String, _ path: WritableKeyPath<ImportReferenceDraft, Bool>) -> Binding<Bool> {
        Binding(get: { draft?.imports.first { $0.id == id }?[keyPath: path] ?? false }, set: { value in
            if let index = draft?.imports.firstIndex(where: { $0.id == id }) { draft?.imports[index][keyPath: path] = value }
        })
    }
    private func dnsString(_ key: String, fallback: String = "") -> Binding<String> {
        Binding(get: { draft?.dns[key]?.stringValue ?? fallback }, set: { value in
            if value.isEmpty { draft?.dns.removeValue(forKey: key) } else { draft?.dns[key] = .string(value) }
        })
    }
    private func dnsNumber(_ key: String) -> Binding<String> {
        Binding(get: { draft?.dns[key]?.intValue.map(String.init) ?? "" }, set: { value in
            if value.isEmpty { draft?.dns.removeValue(forKey: key) }
            else if let number = Double(value) { draft?.dns[key] = .number(number) }
        })
    }
    private func dnsBool(_ key: String) -> Binding<Bool> {
        Binding(get: { draft?.dns[key]?.boolValue ?? false }, set: { draft?.dns[key] = .bool($0) })
    }
    private func dnsList(_ title: String, key: String, prompt: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.callout).foregroundStyle(.secondary)
            TextEditor(text: Binding(get: { (draft?.dns[key]?.arrayValue ?? []).compactMap(\.stringValue).joined(separator: "\n") }, set: { text in
                let values = text.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
                if values.isEmpty { draft?.dns.removeValue(forKey: key) } else { draft?.dns[key] = .array(values.map(JSONValue.string)) }
            })).trackEditor().frame(height: 66).accessibilityLabel(title)
            Text(prompt).font(.caption).foregroundStyle(.tertiary)
        }
    }
    private func preview() {
        guard let draft else { return }
        Task { await store.previewVisualChange(draft.change(baseRevision: baseRevision), summary: "更新可视化配置") }
    }
}

private struct NodeEditorRequest: Identifiable {
    let id = UUID()
    let nodeID: String?
}
