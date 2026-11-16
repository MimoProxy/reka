import SwiftUI

struct NativeTLSOptionsEditor: View {
    @Binding var value: [String: JSONValue]
    let fingerprints: [String]
    var allowsReality = true
    var allowsCarrier = true
    private var form: NativeFormFields { NativeFormFields(fields: $value) }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            row("服务器名称", "server-name", "SNI，可选")
            Picker("ClientHello 指纹", selection: form.string(["fingerprint"])) {
                Text("系统默认").tag("")
                ForEach(Array(Set(fingerprints + [form.value(["fingerprint"]).stringValue ?? ""])).filter { !$0.isEmpty }.sorted(), id: \.self) { Text($0).tag($0) }
            }
            FieldRow(title: "ALPN") { TextField("例如 h2；XHTTP 只接受单一协议", text: form.list(["alpn"])).trackField() }
            Toggle("跳过证书校验", isOn: form.bool(["insecure"]))
            DisclosureGroup("证书校验与客户端证书") {
                VStack(spacing: 10) {
                    row("校验名称", "verify-name", "可选")
                    row("证书 SHA-256", "certificate-sha256", "完整十六进制摘要")
                    Text("客户端证书 PEM 或 secret:// 引用").font(.caption).foregroundStyle(.secondary)
                    TextEditor(text: form.string(["certificate"])).trackEditor().frame(height: 66)
                    Text("私钥 PEM 或 secret:// 引用").font(.caption).foregroundStyle(.secondary)
                    TextEditor(text: form.string(["private-key"])).trackEditor().frame(height: 66)
                }
            }
            if allowsReality {
                DisclosureGroup("REALITY") {
                    VStack(alignment: .leading, spacing: 10) {
                        Toggle("启用 REALITY", isOn: objectToggle("reality"))
                        if value["reality"] != nil {
                            FieldRow(title: "公钥") { TextField("base64url 公钥", text: form.string(["reality", "public-key"])).trackField() }
                            FieldRow(title: "Short ID") { TextField("十六进制", text: form.string(["reality", "short-id"])).trackField() }
                            Toggle("X25519MLKEM768", isOn: form.bool(["reality", "x25519mlkem768"]))
                        }
                    }
                }
            }
            DisclosureGroup("ECH") {
                VStack(alignment: .leading, spacing: 10) {
                    Toggle("启用 ECH", isOn: Binding(get: { form.value(["ech", "enabled"]).boolValue ?? false }, set: { enabled in
                        if enabled { form.assign(["ech", "enabled"], .bool(true)) } else { form.assign(["ech"], nil) }
                    }))
                    if form.value(["ech", "enabled"]).boolValue == true {
                        FieldRow(title: "配置") { TextField("可选，base64 ECHConfigList", text: form.string(["ech", "config"])).trackField() }
                        FieldRow(title: "查询名称") { TextField("可选", text: form.string(["ech", "query-server-name"])).trackField() }
                    }
                }
            }
            if allowsCarrier { DisclosureGroup("TLS 安全载体") {
                VStack(alignment: .leading, spacing: 10) {
                    Picker("载体", selection: Binding(get: { form.value(["carrier", "type"]).stringValue ?? "" }, set: { type in
                        if type.isEmpty { form.assign(["carrier"], nil) }
                        else if type != form.value(["carrier", "type"]).stringValue { form.assign(["carrier"], .object(["type": .string(type)])) }
                    })) {
                        Text("普通 TLS").tag(""); Text("ShadowTLS").tag("shadow-tls"); Text("Restls").tag("restls"); Text("JLS").tag("jls")
                    }
                    if let type = form.value(["carrier", "type"]).stringValue, !type.isEmpty {
                        if type == "jls" { FieldRow(title: "用户名") { TextField("用户名", text: form.string(["carrier", "username"])).trackField() } }
                        FieldRow(title: "密码") { SecureField("密码", text: form.string(["carrier", "password"])).trackField() }
                        if type == "shadow-tls" { FieldRow(title: "版本") { TextField("1–3，默认 2", text: form.number(["carrier", "version"])).trackField() } }
                        if type == "restls" {
                            FieldRow(title: "版本提示") { TextField("version-hint", text: form.string(["carrier", "version-hint"])).trackField() }
                            FieldRow(title: "记录脚本") { TextField("script", text: form.string(["carrier", "script"])).trackField() }
                        }
                    }
                    Text("安全载体与 REALITY、ECH 互斥；组合由内核在预览时校验。") .font(.caption).foregroundStyle(.secondary)
                }
            } }
        }
    }
    private func objectToggle(_ key: String) -> Binding<Bool> {
        Binding(get: { value[key]?.objectValue != nil }, set: { enabled in
            if enabled { value[key] = .object([:]) } else { value.removeValue(forKey: key) }
        })
    }
    private func row(_ title: String, _ key: String, _ prompt: String) -> some View {
        FieldRow(title: title) { TextField(prompt, text: form.string([key])).trackField() }
    }
}
