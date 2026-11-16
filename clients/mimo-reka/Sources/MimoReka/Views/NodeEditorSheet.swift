import SwiftUI

@MainActor
struct NodeEditorSheet: View {
    @Bindable var store: AppStore
    let nodeID: String?
    @Environment(\.dismiss) private var dismiss
    @State private var fields: [String: JSONValue]
    @State private var original: [String: JSONValue]
    @State private var baseRevision: Int
    @State private var failure: String?
    @State private var confirmingDelete = false
    @State private var deleting = false

    init(store: AppStore, nodeID: String? = nil) {
        self.store = store
        self.nodeID = nodeID
        baseRevision = store.revision
        do {
            let definition: [String: JSONValue]
            if let nodeID {
                definition = try VisualConfigurationService.resource(kind: "outbounds", id: nodeID,
                    documents: store.documents, effective: store.effectiveConfiguration).definition
            } else {
                definition = ["id": .string("node-" + String(UUID().uuidString.prefix(8)).lowercased()),
                              "name": .string("新节点"), "type": .string("socks"), "server": .string(""), "port": .number(1080)]
            }
            fields = definition
            original = definition
            _failure = State(initialValue: nil)
        } catch {
            fields = [:]; original = [:]; _failure = State(initialValue: error.localizedDescription)
        }
    }

    private var type: String { fields["type"]?.stringValue ?? "socks" }
    private var hasEndpoint: Bool { !["direct", "reject"].contains(type) }
    private var passwordType: Bool { ["http", "socks", "shadowsocks", "trojan", "hysteria2", "tuic", "snell"].contains(type) }
    private var uuidType: Bool { ["vless", "vmess", "tuic"].contains(type) }
    private var tls: [String: JSONValue]? { fields["tls"]?.objectValue }
    private var protocols: [String] {
        let actual = (store.capabilities["outbound_types"].arrayValue ?? []).compactMap(\.stringValue)
        return Array(Set(actual + [type])).sorted()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            SheetHeader(symbol: "server.rack", title: nodeID == nil ? "新增节点" : "编辑节点")
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if let failure { Text(failure).foregroundStyle(.red) }
                    if failure == nil {
                        identityContent
                        if hasEndpoint { endpointContent }
                        if ["http", "vless", "vmess", "trojan", "hysteria2", "tuic"].contains(type) { tlsContent }
                        if ["vless", "vmess", "trojan"].contains(type) { transportContent }
                        Text("密码、UUID 等星号遮罩保持不变时会保留原值。已有的协议扩展、插件和多路复用参数也会保留。")
                            .font(.caption).foregroundStyle(.secondary)
                        if nodeID != nil, fields["type"] != original["type"] {
                            Text("切换协议会清除不适用的基础字段；保留的高级参数若与新协议不兼容，内核会明确拒绝变更。")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        if nodeID?.contains("/") == true {
                            Label("来源节点的修改保存到用户覆盖，订阅原文保持不变。", systemImage: "square.stack")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }.padding(.trailing, 3)
            }
            if let prepared = store.preparedChange { ChangePlanView(prepared: prepared).frame(height: 110) }
            Divider()
            HStack {
                if let nodeID {
                    Button("删除节点…", role: .destructive) { confirmingDelete = true }
                        .disabled(!store.isOnline || failure != nil)
                        .help(nodeID)
                }
                Text("基于 r\(baseRevision)").font(.caption).foregroundStyle(.tertiary)
                if store.isBusy { ProgressView().controlSize(.small) }
                Spacer()
                Button("取消", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("预览变更") {
                    deleting = false
                    Task { await store.previewResource(kind: "outbounds", id: nodeID, definition: fields, baseRevision: baseRevision) }
                }.disabled(!store.isOnline || failure != nil)
                Button(deleting ? "确认删除" : "应用") {
                    Task { await store.applyPrepared(); if store.errorMessage == nil { dismiss() } }
                }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .disabled(!store.isOnline || store.preparedChange == nil)
            }
        }.padding(24).frame(width: 760, height: 690)
            .disabled(store.isBusy).interactiveDismissDisabled(store.isBusy)
            .onChange(of: fields) { store.preparedChange = nil; deleting = false }
            .onAppear { store.preparedChange = nil }
            .onDisappear { store.preparedChange = nil }
            .confirmationDialog("删除这个节点？", isPresented: $confirmingDelete) {
                Button("预览删除", role: .destructive) {
                    if let nodeID {
                        Task { await store.removeResource(kind: "outbounds", id: nodeID, baseRevision: baseRevision); deleting = store.preparedChange != nil }
                    }
                }
            } message: { Text("仍被策略或规则引用的节点无法删除。内核会先检查引用，原配置在提交成功前保持不变。") }
            .alert("节点未应用", isPresented: Binding(get: { store.errorMessage != nil }, set: { if !$0 { store.errorMessage = nil } })) {
                Button("好", role: .cancel) { store.errorMessage = nil }
            } message: { Text(store.errorMessage ?? "") }
    }

    private var identityContent: some View {
        VStack(spacing: 0) {
            FieldRow(title: "名称") { TextField("节点名称", text: string("name")).trackField() }
            Divider()
            FieldRow(title: "标识") { TextField("稳定标识", text: string("id")).trackField(monospaced: true).disabled(nodeID != nil) }
            Divider()
            FieldRow(title: "类型") {
                Picker("类型", selection: string("type")) {
                    ForEach(protocols, id: \.self) { Text($0).tag($0) }
                }.labelsHidden().frame(width: 200)
                Spacer()
            }
        }.padding(.horizontal, 16).surface()
    }

    private var endpointContent: some View {
        VStack(alignment: .leading, spacing: 8) {
            FieldRow(title: "服务器") { TextField("域名或 IP", text: string("server")).trackField(monospaced: true) }
            FieldRow(title: "端口") { TextField("1–65535", text: number("port")).trackField().frame(width: 150); Spacer() }
            if ["http", "socks"].contains(type) {
                FieldRow(title: "用户名") { TextField("可选", text: string("username")).trackField() }
            }
            if passwordType {
                FieldRow(title: type == "snell" ? "PSK" : "密码") {
                    SecureField("密码", text: string("password")).trackField()
                }
            }
            if uuidType {
                FieldRow(title: "UUID") { TextField("UUID", text: string("uuid")).trackField(monospaced: true) }
            }
            if type == "shadowsocks" {
                FieldRow(title: "加密方法") {
                    Picker("加密方法", selection: string("method", fallback: "aes-128-gcm")) {
                        ForEach(shadowsocksMethods, id: \.self) { Text($0).tag($0) }
                    }.labelsHidden().frame(maxWidth: .infinity)
                }
            }
            if type == "vless" {
                FieldRow(title: "Flow") {
                    Picker("Flow", selection: string("flow")) { Text("无").tag(""); Text("Vision").tag("xtls-rprx-vision") }
                        .labelsHidden().frame(width: 200)
                    Spacer()
                }
            }
            if type == "snell" {
                FieldRow(title: "协议版本") {
                    Picker("版本", selection: nestedNumber("protocol", "version", fallback: 5)) { Text("5").tag(5); Text("6").tag(6) }.labelsHidden().frame(width: 160)
                    Spacer()
                }
            }
            if type == "vmess" {
                FieldRow(title: "Security") {
                    Picker("Security", selection: nestedString("protocol", "security", fallback: "auto")) {
                        ForEach(["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"], id: \.self) { Text($0).tag($0) }
                    }.labelsHidden().frame(width: 200)
                    Spacer()
                }
            }
            Toggle("启用 UDP", isOn: boolean("udp", fallback: true)).toggleStyle(.checkbox)
        }.panel()
    }

    private var tlsContent: some View {
        VStack(alignment: .leading, spacing: 10) {
            Toggle("TLS", isOn: Binding(get: { tls != nil }, set: { enabled in
                if enabled { fields["tls"] = .object([:]) } else { fields.removeValue(forKey: "tls") }
            })).font(.headline)
            if tls != nil {
                FieldRow(title: "服务器名称") { TextField("SNI，可选", text: nestedString("tls", "server-name")).trackField() }
                FieldRow(title: "指纹") {
                    Picker("指纹", selection: nestedString("tls", "fingerprint")) {
                        Text("默认").tag("")
                        ForEach((store.capabilities["tls_fingerprints"].arrayValue ?? []).compactMap(\.stringValue), id: \.self) { Text($0).tag($0) }
                    }.labelsHidden().frame(width: 200)
                    Spacer()
                }
                Toggle("跳过证书校验", isOn: nestedBool("tls", "insecure"))
                if tls?["reality"] != nil {
                    Label("此节点保留已有 REALITY 参数。修改公钥等扩展参数请使用高级 YAML。", systemImage: "lock.shield")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }.panel()
    }

    private var transportContent: some View {
        VStack(alignment: .leading, spacing: 10) {
            PanelHeader(title: "传输")
            Picker("类型", selection: Binding(get: { fields["transport"]?["type"].stringValue ?? "" }, set: { value in
                if value.isEmpty { fields.removeValue(forKey: "transport") }
                else {
                    var transport = fields["transport"]?.objectValue ?? [:]
                    if transport["type"]?.stringValue != value {
                        for key in ["path", "paths", "host", "hosts", "service-name"] { transport.removeValue(forKey: key) }
                    }
                    transport["type"] = .string(value); fields["transport"] = .object(transport)
                    if value == "h2", fields["tls"] == nil { fields["tls"] = .object([:]) }
                }
            })) {
                Text("TCP").tag(""); Text("WebSocket").tag("ws"); Text("gRPC").tag("grpc"); Text("HTTP Upgrade").tag("httpupgrade")
                if type != "trojan" { Text("HTTP").tag("http"); Text("HTTP/2").tag("h2") }
            }.frame(maxWidth: 330)
            let kind = fields["transport"]?["type"].stringValue ?? ""
            if kind == "grpc" {
                FieldRow(title: "服务名称") { TextField("gRPC service-name", text: nestedString("transport", "service-name")).trackField() }
            } else if kind == "h2" {
                FieldRow(title: "路径") { TextField("/", text: nestedString("transport", "path")).trackField() }
                FieldRow(title: "Hosts") { TextField("多个主机用逗号分隔", text: nestedList("transport", "hosts")).trackField() }
            } else if kind == "http" {
                FieldRow(title: "路径") { TextField("多个路径用逗号分隔", text: nestedList("transport", "paths")).trackField() }
                FieldRow(title: "Host") { TextField("可选", text: nestedString("transport", "host")).trackField() }
            } else if !kind.isEmpty {
                FieldRow(title: "路径") { TextField("/", text: nestedString("transport", "path")).trackField() }
                FieldRow(title: "Host") { TextField("可选", text: nestedString("transport", "host")).trackField() }
            }
        }.panel()
    }

    private var shadowsocksMethods: [String] {
        let values = (store.capabilities["shadowsocks_methods"].arrayValue ?? []).compactMap(\.stringValue)
        return Array(Set(values + [fields["method"]?.stringValue ?? "aes-128-gcm"])).sorted()
    }
    private func string(_ key: String, fallback: String = "") -> Binding<String> {
        Binding(get: { fields[key]?.stringValue ?? fallback }, set: { value in
            if value.isEmpty { fields.removeValue(forKey: key) } else { fields[key] = .string(value) }
            if key == "type" { applyTypeDefaults(value) }
        })
    }
    private func number(_ key: String) -> Binding<String> {
        Binding(get: { fields[key]?.intValue.map(String.init) ?? "" }, set: { value in
            if value.isEmpty { fields.removeValue(forKey: key) } else if let number = Double(value) { fields[key] = .number(number) }
        })
    }
    private func boolean(_ key: String, fallback: Bool = false) -> Binding<Bool> {
        Binding(get: { fields[key]?.boolValue ?? fallback }, set: { fields[key] = .bool($0) })
    }
    private func nestedString(_ parent: String, _ key: String, fallback: String = "") -> Binding<String> {
        Binding(get: { fields[parent]?[key].stringValue ?? fallback }, set: { value in
            var object = fields[parent]?.objectValue ?? [:]
            if value.isEmpty { object.removeValue(forKey: key) } else { object[key] = .string(value) }
            fields[parent] = .object(object)
        })
    }
    private func nestedBool(_ parent: String, _ key: String) -> Binding<Bool> {
        Binding(get: { fields[parent]?[key].boolValue ?? false }, set: { value in
            var object = fields[parent]?.objectValue ?? [:]; object[key] = .bool(value); fields[parent] = .object(object)
        })
    }
    private func nestedNumber(_ parent: String, _ key: String, fallback: Int) -> Binding<Int> {
        Binding(get: { fields[parent]?[key].intValue ?? fallback }, set: { value in
            var object = fields[parent]?.objectValue ?? [:]; object[key] = .number(Double(value)); fields[parent] = .object(object)
        })
    }
    private func nestedList(_ parent: String, _ key: String) -> Binding<String> {
        Binding(get: { (fields[parent]?[key].arrayValue ?? []).compactMap(\.stringValue).joined(separator: ", ") }, set: { text in
            let values = text.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
            var object = fields[parent]?.objectValue ?? [:]
            if values.isEmpty { object.removeValue(forKey: key) } else { object[key] = .array(values.map(JSONValue.string)) }
            fields[parent] = .object(object)
        })
    }

    private func applyTypeDefaults(_ type: String) {
        let endpoint = !["direct", "reject"].contains(type)
        if !endpoint {
            for key in ["server", "port", "username", "password", "uuid", "method", "tls", "transport", "flow", "protocol", "packet-encoding"] { fields.removeValue(forKey: key) }
        } else {
            if fields["port"] == nil { fields["port"] = .number(1080) }
            if !["http", "socks"].contains(type) { fields.removeValue(forKey: "username") }
            if !["http", "socks", "shadowsocks", "trojan", "hysteria2", "tuic", "snell"].contains(type) { fields.removeValue(forKey: "password") }
            if !["vless", "vmess", "tuic"].contains(type) { fields.removeValue(forKey: "uuid") }
            if type != "shadowsocks" { fields.removeValue(forKey: "method") }
            else if fields["method"] == nil { fields["method"] = .string("aes-128-gcm") }
            if type != "vless" { fields.removeValue(forKey: "flow"); fields.removeValue(forKey: "packet-encoding") }
            if ["trojan", "hysteria2", "tuic"].contains(type), fields["tls"] == nil { fields["tls"] = .object([:]) }
            if type == "snell", fields["protocol"]?["version"].intValue == nil {
                var value = fields["protocol"]?.objectValue ?? [:]; value["version"] = .number(5); fields["protocol"] = .object(value)
            }
            if type == "vmess", fields["protocol"]?["security"].stringValue == nil {
                var value = fields["protocol"]?.objectValue ?? [:]; value["security"] = .string("auto"); value["alter-id"] = .number(0); fields["protocol"] = .object(value)
            }
        }
    }
}
