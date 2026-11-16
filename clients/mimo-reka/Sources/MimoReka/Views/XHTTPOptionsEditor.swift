import SwiftUI

struct XHTTPOptionsEditor: View {
    @Binding var transport: [String: JSONValue]
    let fingerprints: [String]
    private var form: NativeFormFields { NativeFormFields(fields: $transport) }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("HTTP/1.1、HTTP/2 或 HTTP/3 由 TLS ALPN 选择；HTTP/3 不支持 REALITY、安全载体和预设指纹。")
                .font(.caption).foregroundStyle(.secondary)
            DisclosureGroup("上传请求头") { NativePairList(value: form.array(["headers"])) }
            XHTTPBehaviorEditor(value: form.object(["xhttp"]))
            Toggle("使用独立下载端点", isOn: Binding(get: { form.value(["xhttp", "download-settings"]).objectValue != nil }, set: { enabled in
                form.assign(["xhttp", "download-settings"], enabled ? .object([:]) : nil)
            }))
            if form.value(["xhttp", "download-settings"]).objectValue != nil {
                XHTTPDownloadEditor(value: form.object(["xhttp", "download-settings"]), fingerprints: fingerprints)
            }
        }
    }
}

private struct XHTTPDownloadEditor: View {
    @Binding var value: [String: JSONValue]
    let fingerprints: [String]
    private var form: NativeFormFields { NativeFormFields(fields: $value) }
    private var tlsMode: String { value["disable-tls"]?.boolValue == true ? "off" : value["tls"]?.objectValue != nil ? "custom" : "inherit" }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("独立下载端点").font(.headline)
            row("服务器", "server", "留空继承上传服务器")
            FieldRow(title: "端口") { TextField("留空继承，1–65535", text: form.number(["port"])).trackField() }
            row("Host", "host", "留空继承上传 Host")
            row("路径", "path", "留空继承上传路径")
            DisclosureGroup("下载请求头") { NativePairList(value: form.array(["headers"])) }
            Picker("下载 TLS", selection: Binding(get: { tlsMode }, set: { mode in
                form.assign(["disable-tls"], mode == "off" ? .bool(true) : nil)
                if mode == "custom" { if value["tls"] == nil { value["tls"] = .object([:]) } }
                else { value.removeValue(forKey: "tls") }
            })) {
                Text("继承上传 TLS").tag("inherit"); Text("独立 TLS").tag("custom"); Text("禁用 TLS").tag("off")
            }
            if tlsMode == "custom" { NativeTLSOptionsEditor(value: form.object(["tls"]), fingerprints: fingerprints) }
            XHTTPBehaviorEditor(value: $value)
        }.padding(14).surface()
    }
    private func row(_ title: String, _ key: String, _ prompt: String) -> some View {
        FieldRow(title: title) { TextField(prompt, text: form.string([key])).trackField() }
    }
}

private struct XHTTPBehaviorEditor: View {
    @Binding var value: [String: JSONValue]
    private var form: NativeFormFields { NativeFormFields(fields: $value) }
    private let advancedFields = ["x-padding-bytes", "x-padding-key", "x-padding-header", "x-padding-placement", "x-padding-method", "uplink-http-method", "session-placement", "session-key", "session-table", "session-length", "seq-placement", "seq-key", "uplink-data-placement", "uplink-data-key", "uplink-chunk-size", "sc-max-each-post-bytes", "sc-min-posts-interval-ms"]
    private let reuseFields = ["h-keep-alive-period", "max-concurrency", "max-connections", "c-max-reuse-times", "h-max-request-times", "h-max-reusable-secs"]
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Picker("XHTTP 模式", selection: form.string(["mode"], fallback: "auto")) {
                ForEach(["auto", "packet-up", "stream-up", "stream-one"], id: \.self) { Text($0).tag($0) }
            }
            DisclosureGroup("复用（XMUX）") {
                VStack(spacing: 8) {
                    ForEach(reuseFields, id: \.self) { key in
                        FieldRow(title: key, labelWidth: 210) { TextField("留空使用默认值", text: form.string(["xmux", key])).trackField() }
                    }
                }
            }
            DisclosureGroup("填充与上传控制") {
                VStack(alignment: .leading, spacing: 8) {
                    Toggle("省略 gRPC 请求头", isOn: form.bool(["no-grpc-header"]))
                    Toggle("填充混淆", isOn: form.bool(["x-padding-obfs-mode"]))
                    ForEach(advancedFields, id: \.self) { key in
                        FieldRow(title: key, labelWidth: 210) { TextField("留空使用默认值", text: form.string([key])).trackField() }
                    }
                    Text("范围值保持内核原生格式，例如 10-20；所有参数在应用前由内核校验。") .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }
}
