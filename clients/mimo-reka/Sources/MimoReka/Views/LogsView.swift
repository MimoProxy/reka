import SwiftUI
import AppKit

@MainActor
struct LogsView: View {
    let store: AppStore
    var search: String
    @State private var following = true
    @State private var source = "events"
    @State private var level = "all"

    private var rows: [CoreLogRow] {
        store.operations.logs.filter { row in
            (level == "all" || row.level == level) && (search.isEmpty || row.text.localizedCaseInsensitiveContains(search))
        }
    }
    private var startupLines: String {
        store.kernel.logText.components(separatedBy: .newlines)
            .filter { search.isEmpty || $0.localizedCaseInsensitiveContains(search) }.joined(separator: "\n")
    }
    private var copiedLines: String { source == "events" ? rows.map(\.text).joined(separator: "\n") : startupLines }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Picker("日志来源", selection: $source) {
                    Text("内核事件").tag("events"); Text("启动输出").tag("startup")
                }.pickerStyle(.segmented).frame(width: 220)
                if source == "events" {
                    Picker("级别", selection: $level) {
                        Text("全部级别").tag("all")
                        ForEach(["debug", "info", "warn", "error"], id: \.self) { Text($0.uppercased()).tag($0) }
                    }.labelsHidden().frame(width: 130)
                }
                Spacer()
                Toggle("跟随", isOn: $following).toggleStyle(.button).controlSize(.small)
                Button("刷新", systemImage: "arrow.clockwise") { Task { await store.refreshLiveOperations() } }
                    .controlSize(.small).disabled(!store.isOnline)
                Button("复制", systemImage: "doc.on.doc") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(copiedLines, forType: .string)
                }.controlSize(.small).disabled(copiedLines.isEmpty)
            }
            if source == "events" {
                HStack {
                    Text("最近最多 256 条真实日志 · 按内核配置的日志级别记录").font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    if let error = store.operations.logsError { Text(error).font(.caption).foregroundStyle(.red).lineLimit(1).help(error) }
                }
            }
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        if source == "events" {
                            if !store.supportsMethod("GetLogs") {
                                EmptyState(title: "当前内核不支持事件日志", symbol: "doc.text", detail: "可切换到启动输出查看运行记录。")
                            } else if rows.isEmpty {
                                EmptyState(title: search.isEmpty && level == "all" ? "暂无事件日志" : "没有匹配的日志", symbol: "doc.text")
                            }
                            ForEach(rows) { row in logRow(row) }
                        } else {
                            Text(startupLines.isEmpty ? "暂无启动输出" : startupLines)
                                .font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .topLeading).padding(16)
                        }
                        Color.clear.frame(height: 1).id("log-bottom")
                    }
                }.background(Theme.surface).pageCardInset()
                    .onChange(of: store.operations.logs.last?.id) { if following && source == "events" { proxy.scrollTo("log-bottom", anchor: .bottom) } }
                    .onChange(of: store.kernel.logText) { if following && source == "startup" { proxy.scrollTo("log-bottom", anchor: .bottom) } }
                    .onChange(of: following) { if following { proxy.scrollTo("log-bottom", anchor: .bottom) } }
            }
        }.padding(.horizontal, 20).padding(.top, Theme.pageTopInset).padding(.bottom, 20)
    }
    private func logRow(_ row: CoreLogRow) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text(AppStore.parseDate(row.timestamp)?.formatted(date: .omitted, time: .standard) ?? row.timestamp)
                .foregroundStyle(.secondary).frame(width: 85, alignment: .leading)
            Text(row.level.uppercased()).foregroundStyle(row.level == "error" ? Color.red : row.level == "warn" ? Color.orange : Color.secondary)
                .frame(width: 50, alignment: .leading)
            Text(row.message).frame(maxWidth: .infinity, alignment: .leading)
        }.font(.system(size: 12, design: .monospaced)).textSelection(.enabled).padding(.horizontal, 16).padding(.vertical, 8)
    }
}
