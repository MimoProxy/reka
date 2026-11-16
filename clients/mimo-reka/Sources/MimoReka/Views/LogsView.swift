import SwiftUI
import AppKit

@MainActor
struct LogsView: View {
    let store: AppStore
    var search: String
    @State private var following = true
    private var lines: String {
        guard !search.isEmpty else { return store.kernel.logText }
        return store.kernel.logText.components(separatedBy: .newlines).filter { $0.localizedCaseInsensitiveContains(search) }.joined(separator: "\n")
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("内核运行日志").font(.callout).foregroundStyle(.secondary)
                Spacer()
                Toggle("跟随", isOn: $following).toggleStyle(.button).controlSize(.small)
                Button("复制", systemImage: "doc.on.doc") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(lines, forType: .string)
                }.controlSize(.small).disabled(lines.isEmpty)
            }
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        Text(lines.isEmpty ? "暂无日志" : lines)
                            .font(.system(size: 12, design: .monospaced))
                            .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .topLeading)
                        Color.clear.frame(height: 1).id("log-bottom")
                    }.padding(16)
                }.background(Theme.surface).pageCardInset()
                    .onChange(of: store.kernel.logText) { if following { proxy.scrollTo("log-bottom", anchor: .bottom) } }
                    .onChange(of: following) { if following { proxy.scrollTo("log-bottom", anchor: .bottom) } }
            }
        }.padding(.horizontal, 20).padding(.top, Theme.pageTopInset).padding(.bottom, 20)
    }
}
