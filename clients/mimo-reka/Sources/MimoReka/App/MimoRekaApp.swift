import AppKit
import SwiftUI

@main
struct MimoRekaApp: App {
    @NSApplicationDelegateAdaptor(MimoRekaDelegate.self) private var delegate
    @State private var store = AppStore()

    var body: some Scene {
        WindowGroup("Mimo Reka", id: "main") {
            ContentView(store: store)
                .task {
                    delegate.store = store
                    if !store.kernel.isRunning { await store.start() }
                    if ProcessInfo.processInfo.environment["MIMO_REKA_PREVIEW_EDITOR"] == "configuration", store.isOnline {
                        store.visualSection = ProcessInfo.processInfo.environment["MIMO_REKA_VISUAL_SECTION"] ?? "general"
                        store.showVisualConfiguration = true
                    }
                    if ProcessInfo.processInfo.environment["MIMO_REKA_PREVIEW_EDITOR"] == "backup", store.isOnline { store.showBackup = true }
                    AppProof.scheduleIfRequested()
                }
        }
        .defaultSize(width: 1120, height: 780)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unified)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("导入配置或添加订阅…") { store.showImport = true }
                    .keyboardShortcut("o").disabled(!store.isOnline || store.isBusy)
            }
            CommandMenu("代理") {
                Button(store.kernel.isRunning ? "停止内核" : "启动内核") {
                    Task { if store.kernel.isRunning { await store.stop() } else { await store.start() } }
                }.keyboardShortcut("k", modifiers: [.command, .shift]).disabled(store.isBusy)
                Button("关闭网络接管") { Task { await store.requestNetworkMode("off") } }
                    .disabled(!store.isOnline || store.isBusy || store.networkMode == "off")
                Divider()
                Button("刷新状态") { Task { await store.refresh() } }
                    .keyboardShortcut("r").disabled(!store.kernel.isRunning || store.isBusy)
                Button("复制终端代理命令") { store.copyProxyCommand() }
                Button("导出主配置…") { store.exportConfiguration() }.disabled(!store.isOnline)
                Button("打开数据文件夹") { store.revealDataFolder() }
            }
        }

        Settings { PreferencesView(store: store) }
            .windowResizability(.contentMinSize)

        MenuBarExtra {
            StatusMenu(store: store)
        } label: {
            Image(nsImage: store.networkMode == "off" ? MimoLogo.inactiveMenuBarImage : MimoLogo.menuBarImage)
                .help("Mimo Reka · \(store.networkState)")
        }
    }
}

private struct StatusMenu: View {
    let store: AppStore
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        Text("Mimo Reka · \(store.isOnline ? "运行中" : "已停止")")
        Text(store.listenerAddress)
        Divider()
        Button("显示主窗口") {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
        Button(store.kernel.isRunning ? "停止内核" : "启动内核") {
            Task { if store.kernel.isRunning { await store.stop() } else { await store.start() } }
        }.disabled(store.isBusy)
        SettingsLink { Text("设置…") }
        Divider()
        Button("退出 Mimo Reka") { NSApp.terminate(nil) }.keyboardShortcut("q")
    }
}

@MainActor
final class MimoRekaDelegate: NSObject, NSApplicationDelegate {
    weak var store: AppStore?
    private var terminating = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        let appearance = ProcessInfo.processInfo.environment["MIMO_REKA_APPEARANCE"] ?? UserDefaults.standard.string(forKey: "appearance") ?? "system"
        if appearance == "dark" { NSApp.appearance = NSAppearance(named: .darkAqua) }
        else if appearance == "light" { NSApp.appearance = NSAppearance(named: .aqua) }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if let window = sender.windows.first(where: { $0.canBecomeMain && !$0.isSheet }) {
            window.makeKeyAndOrderFront(nil)
        }
        return true
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !terminating else { return .terminateLater }
        guard let store, store.kernel.isRunning else { return .terminateNow }
        terminating = true
        Task {
            await store.shutdown()
            let stopped = !store.kernel.isRunning
            terminating = false
            sender.reply(toApplicationShouldTerminate: stopped)
        }
        return .terminateLater
    }
}
