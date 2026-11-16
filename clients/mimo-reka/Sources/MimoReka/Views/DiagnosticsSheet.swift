import SwiftUI

@MainActor
struct DiagnosticsSheet: View {
    let store: AppStore
    var initialSection = "route"
    @Environment(\.dismiss) private var dismiss
    @State private var section: String
    @State private var route = RouteDiagnosticDraft()
    @State private var domain = "example.com"
    @State private var questionType = "A"
    @State private var scope = "normal"
    @State private var fake = false
    @State private var output: JSONValue = .null
    @State private var failure: String?
    @State private var busy = false
    @State private var confirmingReset = false

    init(store: AppStore, initialSection: String = "route") {
        self.store = store; self.initialSection = initialSection
        _section = State(initialValue: initialSection)
    }
    private func supports(_ method: String) -> Bool { (store.capabilities["methods"].arrayValue ?? []).contains(.string(method)) }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            SheetHeader(symbol: "stethoscope", title: "网络诊断")
            Picker("诊断", selection: $section) {
                Text("路由测试").tag("route")
                if supports("QueryDNS") { Text("DNS 查询").tag("dns") }
            }.pickerStyle(.segmented).frame(maxWidth: 360)
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if section == "dns" { dnsForm } else { routeForm }
                    if let failure { Text(failure).foregroundStyle(.red).textSelection(.enabled) }
                    if output != .null { resultView }
                }
            }
            Divider()
            HStack {
                if busy { ProgressView().controlSize(.small) }
                Spacer()
                Button("完成") { dismiss() }.keyboardShortcut(.cancelAction).disabled(busy)
                Button(section == "dns" ? "查询 DNS" : "解释路由") { Task { await query() } }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(busy || !store.isOnline)
            }
        }.padding(24).frame(width: 760, height: 690)
            .interactiveDismissDisabled(busy)
            .onChange(of: section) { output = .null; failure = nil }
            .confirmationDialog("重置空闲网络连接？", isPresented: $confirmingReset) {
                Button("重置") { Task { await maintenance("ResetNetwork") } }
                Button("取消", role: .cancel) {}
            } message: { Text("清除普通 DNS 缓存并关闭空闲 DNS/出站连接。现有活动连接和 Fake IP 映射保留。") }
    }

    private var routeForm: some View {
        VStack(alignment: .leading, spacing: 12) {
            FieldRow(title: "目标") { TextField("example.com:443 或 [::1]:443", text: $route.destination).trackField(monospaced: true) }
            Picker("网络", selection: $route.network) { Text("TCP").tag("tcp"); Text("UDP").tag("udp") }.frame(maxWidth: 250)
            Toggle("允许为 IP 规则查询 DNS", isOn: $route.resolve)
            Text("使用当前路由配置解释一次假设请求；不会建立代理连接或修改策略选择。")
                .font(.caption).foregroundStyle(.secondary)
            DisclosureGroup("模拟进程与入口") {
                VStack(spacing: 10) {
                    diagnosticField("进程路径", text: $route.process, prompt: "/Applications/Safari.app/Contents/MacOS/Safari")
                    diagnosticField("进程 UID", text: $route.uid, prompt: "可选，例如 501")
                    diagnosticField("来源地址", text: $route.source, prompt: "可选，例如 127.0.0.1:51000")
                    diagnosticField("入口名称", text: $route.inbound, prompt: "监听器 ID，例如 mixed")
                    Picker("入口协议", selection: $route.inboundType) {
                        Text("未指定").tag(""); ForEach(["HTTP", "SOCKS4", "SOCKS5", "TUN"], id: \.self) { Text($0).tag($0) }
                    }
                    diagnosticField("入口端口", text: $route.inboundPort, prompt: "监听端口，例如 17891")
                    diagnosticField("入口用户", text: $route.inboundUser, prompt: "认证用户名")
                    diagnosticField("已知 IP", text: $route.addresses, prompt: "可选，多个 IP 用空格分隔")
                }.padding(.top, 10)
            }
        }.panel().disabled(busy)
    }

    private func diagnosticField(_ title: String, text: Binding<String>, prompt: String) -> some View {
        FieldRow(title: title) { TextField(prompt, text: text).trackField(monospaced: true) }
    }

    private var dnsForm: some View {
        VStack(alignment: .leading, spacing: 12) {
            FieldRow(title: "域名") { TextField("example.com", text: $domain).trackField() }
            HStack {
                Picker("类型", selection: $questionType) { ForEach(["A", "AAAA", "HTTPS", "TXT", "MX", "NS", "CNAME", "SOA", "SRV", "PTR"], id: \.self) { Text($0).tag($0) } }
                Picker("解析范围", selection: $scope) {
                    Text("普通").tag("normal"); Text("代理节点").tag("proxy"); Text("直连").tag("direct"); Text("引导").tag("bootstrap")
                }
            }
            Toggle("明确请求 Fake IP 结果", isOn: $fake)
            Text("默认查询真实解析结果。只有启用 Fake IP 请求时才允许分配映射。")
                .font(.caption).foregroundStyle(.secondary)
            Divider()
            HStack {
                if supports("FlushDNSCache") { Button("清除 DNS 缓存") { Task { await maintenance("FlushDNSCache") } } }
                if supports("ResetNetwork") { Button("重置空闲网络连接…") { confirmingReset = true } }
            }
            Text("清缓存保留 Fake IP 映射和活动连接。")
                .font(.caption).foregroundStyle(.secondary)
        }.panel().disabled(busy)
    }

    private var resultView: some View {
        VStack(alignment: .leading, spacing: 10) {
            PanelHeader(title: "结果")
            if section == "route", output["outbound"].stringValue != nil {
                LabeledContent("出口", value: store.displayName(output["outbound"].stringValue ?? ""))
                if let rule = output["rule"].stringValue { LabeledContent("命中规则", value: rule) }
                if let chain = output["chain"].arrayValue { LabeledContent("出口链", value: chain.compactMap(\.stringValue).map(store.displayName).joined(separator: " → ")) }
                if let undetermined = output["undetermined"].stringValue { Text(undetermined).foregroundStyle(.orange) }
            }
            Text(output.prettyPrinted).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
        }.panel()
    }

    private func query() async {
        busy = true; failure = nil; output = .null
        defer { busy = false }
        do {
            if section == "dns" {
                output = try await store.client.call("QueryDNS", params: ["name": .string(domain.trimmingCharacters(in: .whitespacesAndNewlines)), "type": .string(questionType), "scope": .string(scope), "fake": .bool(fake)])
            } else { output = try await store.client.call("ExplainRoute", params: route.parameters()) }
        } catch { failure = error.localizedDescription }
    }
    private func maintenance(_ method: String) async {
        busy = true; failure = nil
        defer { busy = false }
        do { output = try await store.client.call(method) }
        catch { failure = error.localizedDescription }
    }
}
