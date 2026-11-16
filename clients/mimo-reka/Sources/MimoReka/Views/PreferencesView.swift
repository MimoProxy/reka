import SwiftUI
import AppKit

@MainActor
struct PreferencesView: View {
    @Bindable var store: AppStore
    @Environment(\.controlActiveState) private var activeState
    @AppStorage("appearance") private var appearance = "system"
    @State private var category = "network"

    private var networkModes: [String] { (store.capabilities["network_modes"].arrayValue ?? []).compactMap(\.stringValue) }

    var body: some View {
        HStack(alignment: .top, spacing: 20) {
            VStack(spacing: 5) {
                categoryButton("network", title: "网络", symbol: "network")
                categoryButton("appearance", title: "外观", symbol: "paintbrush")
                categoryButton("data", title: "配置与数据", symbol: "folder")
                categoryButton("about", title: "关于", symbol: "info.circle")
                Spacer()
            }.frame(width: 150)
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    switch category {
                    case "network": networkContent
                    case "appearance": appearanceContent
                    case "data": dataContent
                    default: aboutContent
                    }
                }.frame(maxWidth: .infinity, alignment: .leading).padding(.bottom, 20)
            }
        }.padding(24).frame(width: 820, height: 580).canvasBackground()
            .onChange(of: appearance) { applyAppearance() }
            .onAppear { applyAppearance() }
            .alert("操作未完成", isPresented: Binding(get: { store.errorMessage != nil && activeState == .key }, set: { if !$0 { store.errorMessage = nil } })) {
                Button("好", role: .cancel) { store.errorMessage = nil }
            } message: { Text(store.errorMessage ?? "") }
    }

    private func categoryButton(_ value: String, title: String, symbol: String) -> some View {
        Button { category = value } label: {
            Label { Text(title) } icon: { Image(systemName: symbol).foregroundStyle(.secondary) }
                .font(.callout).frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 12).frame(height: 38)
                .background(category == value ? Theme.selectedFill : .clear, in: RoundedRectangle(cornerRadius: 10))
        }.buttonStyle(.plain)
    }

    private var networkContent: some View {
        Group {
            VStack(alignment: .leading, spacing: 12) {
                PanelHeader(title: "代理模式")
                HStack(spacing: 10) {
                    modeToggle("system-proxy", title: "系统代理", symbol: "globe", supported: networkModes.contains("system-proxy"))
                    modeToggle("tun", title: "增强模式", symbol: "shield.lefthalf.filled", supported: networkModes.contains("tun"))
                    Spacer()
                }
                LabeledContent("运行状态", value: store.networkState).font(.callout)
                Text("由 Reka 管理系统代理、TUN 与 DNS，关闭时恢复此前设置。首次启用需要管理员授权。当前增强模式接管 IPv4；IPv6 不接管。")
                    .font(.caption).foregroundStyle(.secondary)
            }.panel()
            VStack(spacing: 0) {
                FieldRow(title: "网络服务") { TextField("Wi-Fi 或 Ethernet", text: $store.networkService).trackField() }
                Divider()
                FieldRow(title: "TUN 协议栈") {
                    Picker("TUN 协议栈", selection: $store.tunStack) {
                        Text("mixed").tag("mixed")
                        Text("system").tag("system")
                        Text("gvisor").tag("gvisor")
                    }.labelsHidden().frame(width: 180)
                    Spacer()
                }
                Divider()
                FieldRow(title: "本地代理") { Text(store.listenerAddress).font(.callout.monospaced()).textSelection(.enabled); Spacer() }
            }.padding(.horizontal, 16).surface().disabled(store.isBusy || store.networkMode != "off")
            HStack {
                Button("复制终端代理命令", systemImage: "terminal") { store.copyProxyCommand() }
                Spacer()
                Button("编辑本机配置") { store.editingLayer = .local }
                    .disabled(!store.isOnline || store.isBusy)
            }
        }
    }

    private func modeToggle(_ mode: String, title: String, symbol: String, supported: Bool) -> some View {
        Toggle(isOn: Binding(get: { store.networkMode == mode }, set: { enabled in
            Task { await store.requestNetworkMode(enabled ? mode : "off") }
        })) { Label(title, systemImage: symbol) }
            .toggleStyle(.button).disabled(!store.isOnline || store.isBusy || !supported)
    }

    private var appearanceContent: some View {
        VStack(alignment: .leading, spacing: 14) {
            PanelHeader(title: "外观")
            Picker("主题", selection: $appearance) {
                Text("跟随系统").tag("system")
                Text("浅色").tag("light")
                Text("深色").tag("dark")
            }.pickerStyle(.segmented)
            Text("强调色跟随 macOS 的系统设置。")
                .font(.caption).foregroundStyle(.secondary)
        }.panel()
    }

    private var dataContent: some View {
        Group {
            VStack(alignment: .leading, spacing: 14) {
                PanelHeader(title: "配置与数据")
                LabeledContent("当前配置", value: store.activeProfile?.name ?? "—")
                LabeledContent("配置版本", value: "r\(store.revision)")
                Text(store.kernel.stateRoot.path).font(.caption.monospaced()).textSelection(.enabled).foregroundStyle(.secondary)
                HStack {
                    Button("在访达中显示", systemImage: "folder") { store.revealDataFolder() }
                    Spacer()
                    Button("导出主配置", systemImage: "square.and.arrow.up") { store.exportConfiguration() }
                        .disabled(!store.isOnline || store.isBusy)
                }
            }.panel()
            VStack(alignment: .leading, spacing: 12) {
                PanelHeader(title: "编辑配置")
                ForEach(ConfigurationLayer.allCases) { layer in
                    Button { store.editingLayer = layer } label: {
                        HStack {
                            Text(layer.title)
                            Spacer()
                            Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
                        }.font(.callout).padding(.vertical, 5)
                    }.buttonStyle(.plain).disabled(!store.isOnline || store.isBusy)
                }
            }.panel()
        }
    }

    private var aboutContent: some View {
        VStack(alignment: .leading, spacing: 14) {
            PanelHeader(title: "Mimo Reka")
            LabeledContent("客户端", value: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "试用版")
            LabeledContent("内核", value: "Reka 1.0.0")
            Text("独立的单 Reka 内核 macOS 客户端。")
                .font(.callout).foregroundStyle(.secondary)
        }.panel()
    }

    private func applyAppearance() {
        switch ProcessInfo.processInfo.environment["MIMO_REKA_APPEARANCE"] ?? appearance {
        case "light": NSApp.appearance = NSAppearance(named: .aqua)
        case "dark": NSApp.appearance = NSAppearance(named: .darkAqua)
        default: NSApp.appearance = nil
        }
    }
}
