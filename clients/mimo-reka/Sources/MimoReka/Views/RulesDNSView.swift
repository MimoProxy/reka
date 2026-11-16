import SwiftUI
import Yams

@MainActor
struct RulesDNSView: View {
    let store: AppStore
    var search: String
    @State private var section = "rules"

    var body: some View {
        VStack(spacing: 16) {
            HStack {
                Picker("分类", selection: $section) { Text("路由规则").tag("rules"); Text("DNS").tag("dns") }
                    .pickerStyle(.segmented).frame(width: 230)
                Spacer()
                Button("编辑\(section == "rules" ? "规则" : "DNS")", systemImage: "slider.horizontal.3") { store.editingLayer = .profile }
                    .disabled(!store.isOnline || store.isBusy)
            }
            if section == "rules" {
                HStack {
                    Text("主配置与来源规则").font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    if hasRuleOverrides {
                        Button("查看规则覆盖", systemImage: "square.stack") { store.editingLayer = .overlay }
                            .font(.caption).buttonStyle(.borderless)
                    }
                }
            }
            if section == "rules" { rulesContent } else { dnsContent }
        }.padding(.horizontal, 20).padding(.top, Theme.pageTopInset).padding(.bottom, 20)
            .onAppear {
                if ProcessInfo.processInfo.environment["MIMO_REKA_PREVIEW_PAGE"] == "dns" { section = "dns" }
            }
    }

    private var rulesContent: some View {
        let rows = displayedRules.filter { search.isEmpty || "\($0.match) \($0.target) \($0.origin)".localizedCaseInsensitiveContains(search) }
        return ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(rows) { rule in
                    HStack(alignment: .top, spacing: 14) {
                        Text("\(rule.number)").font(.caption.monospacedDigit()).foregroundStyle(.tertiary).frame(width: 28, alignment: .trailing)
                        VStack(alignment: .leading, spacing: 6) {
                            Text(rule.match).font(.callout).textSelection(.enabled)
                            if !rule.origin.isEmpty { Text(rule.origin).font(.caption).foregroundStyle(.tertiary) }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                        Text(store.displayName(rule.target)).font(.callout).foregroundStyle(.secondary).lineLimit(1).frame(maxWidth: 160, alignment: .trailing)
                    }.padding(.horizontal, 16).padding(.vertical, 14)
                    if rule.id != rows.last?.id { Divider().padding(.leading, 58) }
                }
                if rows.isEmpty { EmptyState(title: search.isEmpty ? "暂无路由规则" : "没有匹配的规则", symbol: "list.bullet.rectangle") }
            }.surface()
        }
    }

    private var dnsContent: some View {
        let profile = document(.profile)
        let dns = profile["dns"] as? [String: Any] ?? [:]
        let sourceID = dns["from"] as? String
        let sourceList = document(.sources)["sources"] as? [[String: Any]] ?? []
        let sourceDNS = sourceList.first { $0["id"] as? String == sourceID }?["dns"] as? [String: Any]
        let resolved = sourceDNS ?? dns
        return ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                VStack(alignment: .leading, spacing: 14) {
                    PanelHeader(title: "DNS 配置")
                    if resolved.isEmpty {
                        Text("当前未配置独立 DNS。普通代理连接使用内核的默认解析行为。")
                            .font(.callout).foregroundStyle(.secondary)
                    } else {
                        if let sourceID { LabeledContent("配置来源", value: store.sources.first { $0.id == sourceID }?.name ?? sourceID) }
                        Text(yaml(resolved)).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }.panel()
                VStack(alignment: .leading, spacing: 12) {
                    PanelHeader(title: "本机网络")
                    LabeledContent("运行状态", value: store.networkState)
                    LabeledContent("网络服务", value: store.networkService)
                    Button("编辑本机设置") { store.editingLayer = .local }
                        .disabled(!store.isOnline || store.isBusy)
                }.panel()
            }
        }
    }

    private struct Rule: Identifiable {
        let id: String
        let number: Int
        let match: String
        let target: String
        let origin: String
    }
    private var hasRuleOverrides: Bool {
        (document(.overlay)["patches"] as? [[String: Any]] ?? []).contains { ($0["path"] as? String ?? "").hasPrefix("/rules") }
    }
    private var displayedRules: [Rule] {
        let profileRules = document(.profile)["rules"] as? [[String: Any]] ?? []
        let sources = document(.sources)["sources"] as? [[String: Any]] ?? []
        var result: [Rule] = []
        var occurrences: [String: Int] = [:]
        func append(_ rule: [String: Any], source: String = "") {
            let match = rule["match"] as? [String: Any] ?? [:]
            let display = match["all"] as? Bool == true ? "MATCH" : match.keys.sorted().map { key in "\(key): \(yaml(match[key] ?? ""))" }.joined(separator: " · ")
            let target = rule["outbound"] as? String ?? "direct"
            let sourceOutbounds = sources.first { $0["id"] as? String == source }?["outbounds"] as? [[String: Any]] ?? []
            let sourceDefinesTarget = sourceOutbounds.contains { $0["id"] as? String == target }
            let builtin = ["direct", "reject"].contains(target) && !sourceDefinesTarget
            let scoped = source.isEmpty || builtin ? target : source + "/" + target
            let identity = source + ":" + (rule["id"] as? String ?? display + ":" + target)
            let count = occurrences[identity, default: 0]
            occurrences[identity] = count + 1
            result.append(Rule(id: identity + ":\(count)", number: result.count + 1, match: display, target: scoped,
                               origin: source.isEmpty ? "主配置" : store.sources.first { $0.id == source }?.name ?? source))
        }
        for rule in profileRules {
            if let source = rule["source"] as? String {
                for item in sources.first(where: { $0["id"] as? String == source })?["rules"] as? [[String: Any]] ?? [] { append(item, source: source) }
            } else { append(rule) }
        }
        return result
    }
    private func document(_ layer: ConfigurationLayer) -> [String: Any] {
        (try? Yams.load(yaml: store.documents[layer] ?? "")) as? [String: Any] ?? [:]
    }
    private func yaml(_ value: Any) -> String {
        ((try? Yams.dump(object: value, sortKeys: true)) ?? String(describing: value)).trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
