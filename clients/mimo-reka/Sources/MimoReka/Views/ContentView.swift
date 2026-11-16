import SwiftUI
import AppKit

enum Page: String, CaseIterable, Identifiable {
    case overview = "仪表盘", groups = "代理", rules = "规则与 DNS", profiles = "配置列表"
    case sources = "来源与订阅", connections = "连接", revisions = "配置历史", logs = "日志", about = "关于"
    var id: Self { self }
    var title: String { rawValue }
    var icon: String {
        switch self {
        case .overview: "gauge.with.needle"
        case .groups: "arrow.triangle.branch"
        case .rules: "list.bullet.rectangle"
        case .profiles: "doc.text"
        case .sources: "tray.and.arrow.down"
        case .connections: "network"
        case .revisions: "clock.arrow.circlepath"
        case .logs: "text.alignleft"
        case .about: "info.circle"
        }
    }
    var scrollsUnderToolbar: Bool { [.overview, .profiles, .sources, .about].contains(self) }
    static func previewPage(_ value: String) -> Page? {
        switch value {
        case "overview": .overview
        case "groups", "proxies": .groups
        case "rules", "dns": .rules
        case "profiles": .profiles
        case "sources", "subscriptions": .sources
        case "connections": .connections
        case "revisions": .revisions
        case "logs": .logs
        case "about": .about
        default: Page(rawValue: value)
        }
    }
}

@MainActor
struct ContentView: View {
    @Bindable var store: AppStore
    @Environment(\.controlActiveState) private var activeState
    @State private var page = Page.overview
    @State private var search = ""

    var body: some View {
        NavigationSplitView {
            List(selection: $page) {
                Section { row(.overview) }
                Section { ForEach([Page.groups, .rules, .profiles, .sources]) { row($0) } }
                Section { ForEach([Page.connections, .revisions, .logs, .about]) { row($0) } }
            }
            .listStyle(.sidebar)
            .listItemTint(.monochrome)
            .environment(\.sidebarRowSize, .large)
            .toolbar(removing: .sidebarToggle)
            .navigationSplitViewColumnWidth(min: 180, ideal: 240, max: 240)
            .safeAreaInset(edge: .bottom, spacing: 0) {
                HStack(spacing: 8) {
                    StatusLamp(lit: store.isOnline)
                    Text("Mimo Reka").font(.callout)
                    Spacer()
                    SettingsLink { Image(systemName: "gearshape") }.labelStyle(.iconOnly).buttonStyle(.plain)
                }.foregroundStyle(.secondary).padding(.horizontal, 20).frame(height: 44)
            }
        } detail: {
            activePage
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .canvasBackground(scrollsUnderToolbar: page.scrollsUnderToolbar)
                .navigationTitle(page.title)
                .toolbar { toolbar }
                .animation(nil, value: page)
        }
        .frame(minWidth: 962, minHeight: 644)
        .sheet(isPresented: $store.showImport) { ImportSheet(store: store) }
        .sheet(isPresented: $store.showVisualConfiguration) { VisualConfigurationSheet(store: store) }
        .sheet(item: $store.editingLayer) { layer in DocumentEditorSheet(store: store, layer: layer) }
        .alert("需要处理", isPresented: Binding(get: { store.errorMessage != nil && !store.showImport && !store.showVisualConfiguration && store.editingLayer == nil && activeState == .key }, set: { if !$0 { store.errorMessage = nil } })) {
            Button("好", role: .cancel) { store.errorMessage = nil }
        } message: { Text(store.errorMessage ?? "") }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            if let notice = store.notice {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.circle")
                    Text(notice).lineLimit(2)
                    Spacer(minLength: 8)
                    Button { store.notice = nil } label: { Image(systemName: "xmark") }
                        .buttonStyle(.plain).help("关闭提示")
                }.font(.callout).foregroundStyle(.secondary).padding(.horizontal, 20).padding(.vertical, 10).background(.bar)
            }
        }
        .onChange(of: page) {
            search = ""
            DispatchQueue.main.async { NSApp.keyWindow?.makeFirstResponder(nil) }
        }
        .onAppear {
            if let preview = ProcessInfo.processInfo.environment["MIMO_REKA_PREVIEW_PAGE"], let requested = Page.previewPage(preview) {
                page = requested
            }
        }
    }

    private func row(_ item: Page) -> some View {
        Label {
            Text(item.title)
        } icon: {
            Image(systemName: item.icon).foregroundStyle(.secondary)
        }.tag(item)
    }

    @ViewBuilder private var activePage: some View {
        switch page {
        case .overview: DashboardView(store: store, navigate: { page = $0 })
        case .groups: ProxyBrowserView(store: store, search: search)
        case .profiles: ProfilesView(store: store, search: search)
        case .sources: SourcesView(store: store, search: search)
        case .rules: RulesDNSView(store: store, search: search)
        case .connections: ConnectionsView(store: store, search: search)
        case .revisions: RevisionsView(store: store, search: search)
        case .logs: LogsView(store: store, search: search)
        case .about: AboutView(store: store)
        }
    }

    @ToolbarContentBuilder private var toolbar: some ToolbarContent {
        if store.isBusy {
            ToolbarItem(placement: .primaryAction) { ProgressView().controlSize(.small).frame(width: 20, height: 20) }
        }
        if page == .overview {
            NativeToolbarGroup {
                Picker("当前配置", selection: Binding(get: { store.activeProfileID }, set: { id in Task { await store.switchProfile(id) } })) {
                    ForEach(store.profiles) { Text($0.name).tag($0.id) }
                }.frame(maxWidth: 170).disabled(store.isBusy)
            }
            NativeToolbarGroup {
                networkToggle("system-proxy", title: "系统代理", symbol: "globe")
                networkToggle("tun", title: "增强模式", symbol: "shield.lefthalf.filled")
            }
        }
        NativeToolbarGroup {
            Button { store.showImport = true } label: { Label("导入", systemImage: "plus") }
                .disabled(!store.isOnline || store.isBusy).help("导入配置或添加订阅")
            Button { Task { await store.refresh() } } label: { Label("刷新", systemImage: "arrow.clockwise") }
                .disabled(!store.kernel.isRunning || store.isBusy)
            Button {
                Task { if store.kernel.isRunning { await store.stop() } else { await store.start() } }
            } label: {
                Label(store.kernel.isRunning ? "停止内核" : "启动内核", systemImage: store.kernel.isRunning ? "stop.fill" : "play.fill")
            }.disabled(store.isBusy)
        }
        if page != .overview && page != .about { ToolbarSearch(prompt: "搜索\(page.title)", text: $search) }
    }

    private func networkToggle(_ mode: String, title: String, symbol: String) -> some View {
        Toggle(isOn: Binding(get: { store.networkMode == mode }, set: { enabled in
            Task { await store.requestNetworkMode(enabled ? mode : "off") }
        })) { Label(title, systemImage: symbol) }
            .toggleStyle(.button)
            .disabled(store.isBusy || !store.isOnline || !(store.capabilities["network_modes"].arrayValue ?? []).contains(.string(mode)))
    }
}

@MainActor
private struct AboutView: View {
    let store: AppStore
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack(spacing: 16) {
                    SymbolBadge(symbol: "arrow.triangle.branch", size: 64)
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Mimo Reka").font(.largeTitle.weight(.semibold))
                        Text("熟悉的 Mimo 界面，原生 Reka 内核。 ").foregroundStyle(.secondary)
                    }
                }.padding(.vertical, 12)
                VStack(alignment: .leading, spacing: 14) {
                    PanelHeader(title: "版本")
                    LabeledContent("客户端", value: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "试用版")
                    LabeledContent("代理内核", value: "Reka 1.0.0")
                    LabeledContent("系统要求", value: "macOS 14 或更新版本")
                }.panel()
                VStack(alignment: .leading, spacing: 12) {
                    PanelHeader(title: "独立运行")
                    Text("配置、订阅、版本历史和网络恢复记录保存在本应用的数据目录。")
                        .font(.callout).foregroundStyle(.secondary)
                    Text(store.kernel.stateRoot.path).font(.caption.monospaced()).textSelection(.enabled).foregroundStyle(.secondary)
                    Button("在访达中显示", systemImage: "folder") { store.revealDataFolder() }
                }.panel()
                Text("Reka · GPL-3.0").font(.caption).foregroundStyle(.tertiary)
            }.padding(24).frame(maxWidth: 800, alignment: .leading).frame(maxWidth: .infinity)
        }
    }
}
