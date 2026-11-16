// Adapted from Mimo's native macOS design system.
import SwiftUI
import AppKit

enum Theme {
    static let radius: CGFloat = 16
    static let pageTopInset: CGFloat = 24
    static let canvas = Color(nsColor: .textBackgroundColor)
    static let surface = adaptive(0xFFFFFF, 0x2A2A2A)
    static let accent = Color.accentColor
    static let track = Color.primary.opacity(0.06)
    static let upload = Color.primary.opacity(0.3)
    static let selectedText = Color.primary
    static let selectedFill = Color.primary.opacity(0.07)
    static let hairline = Color.primary.opacity(0.1)
    static func adaptive(_ light: Int, _ dark: Int) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            let value = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light
            return NSColor(srgbRed: CGFloat((value >> 16) & 255) / 255,
                           green: CGFloat((value >> 8) & 255) / 255,
                           blue: CGFloat(value & 255) / 255, alpha: 1)
        })
    }
}

struct CardSurface: ViewModifier {
    var cornerRadius: CGFloat = Theme.radius
    @Environment(\.colorSchemeContrast) private var contrast
    func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        content.background(Theme.surface, in: shape)
            .overlay(shape.strokeBorder(contrast == .increased ? Color.primary.opacity(0.4) : Theme.hairline,
                                        lineWidth: contrast == .increased ? 1 : 0.5))
    }
}

extension View {
    func surface(cornerRadius: CGFloat = Theme.radius) -> some View { modifier(CardSurface(cornerRadius: cornerRadius)) }
    func panel(padding: CGFloat = 16) -> some View { self.padding(padding).surface() }
    func pageCardInset() -> some View { clipShape(RoundedRectangle(cornerRadius: Theme.radius)).surface() }
    func canvasBackground(scrollsUnderToolbar: Bool = false) -> some View {
        background { Theme.canvas.ignoresSafeArea() }
            .toolbarBackground(scrollsUnderToolbar ? .automatic : .hidden, for: .windowToolbar)
    }
    @ViewBuilder func liquidButton(prominent: Bool = false) -> some View {
        if prominent { buttonStyle(.borderedProminent) } else { buttonStyle(.bordered) }
    }
    func trackField(height: CGFloat = 32, monospaced: Bool = false) -> some View {
        textFieldStyle(.plain).font(.system(size: 13, design: monospaced ? .monospaced : .default))
            .padding(.horizontal, 10).frame(height: height)
            .background(Theme.track, in: RoundedRectangle(cornerRadius: 10))
    }
    func trackEditor() -> some View {
        font(.system(size: 12, design: .monospaced)).scrollContentBackground(.hidden).padding(8)
            .background(Color(nsColor: .textBackgroundColor).opacity(0.75), in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Theme.hairline, lineWidth: 0.5))
    }
}

struct PanelHeader<Trailing: View>: View {
    var title: String
    @ViewBuilder var trailing: Trailing
    var body: some View {
        HStack {
            Text(title).font(.system(size: 15, weight: .semibold))
            Spacer(minLength: 8)
            trailing
        }.frame(minHeight: 26)
    }
}
extension PanelHeader where Trailing == EmptyView {
    init(title: String) { self.title = title; trailing = EmptyView() }
}

struct SymbolBadge: View {
    var symbol: String
    var color: Color = Theme.accent
    var size: CGFloat = 42
    var body: some View {
        Image(systemName: symbol).font(.system(size: size * 0.4, weight: .semibold)).foregroundStyle(color)
            .frame(width: size, height: size)
            .background(color.opacity(0.13), in: RoundedRectangle(cornerRadius: size * 0.28))
            .accessibilityHidden(true)
    }
}

struct StatusLamp: View {
    var lit: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var body: some View {
        let lamp = Circle().fill(lit ? Theme.accent : Color.secondary.opacity(0.35)).frame(width: 8, height: 8)
        if lit && !reduceMotion {
            lamp.phaseAnimator([1.0, 0.4]) { view, opacity in view.opacity(opacity) } animation: { _ in .easeInOut(duration: 1.6) }
        } else { lamp }
    }
}

struct NativeToolbarGroup<Content: View>: ToolbarContent {
    @ViewBuilder var content: Content
    var body: some ToolbarContent { ToolbarItemGroup(placement: .primaryAction) { content } }
}

struct ToolbarSearch: ToolbarContent {
    var prompt: String
    @Binding var text: String
    var body: some ToolbarContent {
        if #available(macOS 26.0, *) { ToolbarSpacer(.fixed, placement: .primaryAction) }
        ToolbarItem(placement: .primaryAction) {
            NativeToolbarSearchField(prompt: prompt, text: $text).frame(width: 200, height: 28)
        }
    }
}

private struct NativeToolbarSearchField: NSViewRepresentable {
    var prompt: String
    @Binding var text: String
    @Environment(\.isEnabled) private var enabled
    func makeCoordinator() -> Coordinator { Coordinator(text: $text) }
    func makeNSView(context: Context) -> NSSearchField {
        let field = NSSearchField()
        field.controlSize = .regular
        field.stringValue = text
        field.sendsWholeSearchString = false
        field.sendsSearchStringImmediately = true
        field.target = context.coordinator
        field.action = #selector(Coordinator.search(_:))
        return field
    }
    func updateNSView(_ field: NSSearchField, context: Context) {
        context.coordinator.text = $text
        field.placeholderString = prompt
        field.setAccessibilityLabel(prompt)
        field.isEnabled = enabled
        if context.coordinator.lastText != text {
            context.coordinator.lastText = text
            field.stringValue = text
        }
    }
    @MainActor final class Coordinator: NSObject {
        var text: Binding<String>
        var lastText: String
        init(text: Binding<String>) { self.text = text; lastText = text.wrappedValue }
        @objc func search(_ sender: NSSearchField) { lastText = sender.stringValue; text.wrappedValue = sender.stringValue }
    }
}

struct SheetHeader: View {
    var symbol: String
    var title: String
    var body: some View {
        HStack(spacing: 12) {
            SymbolBadge(symbol: symbol, size: 36)
            Text(title).font(.system(size: 19, weight: .semibold))
            Spacer(minLength: 8)
        }
    }
}

struct FieldRow<Content: View>: View {
    var title: String
    var labelWidth: CGFloat = 88
    @ViewBuilder var content: Content
    var body: some View {
        HStack(spacing: 14) {
            Text(title).foregroundStyle(.secondary).frame(width: labelWidth, alignment: .leading)
            content
        }.frame(minHeight: 44)
    }
}

struct EmptyState: View {
    var title: String
    var symbol: String
    var detail: String? = nil
    var minHeight: CGFloat = 160
    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: symbol).font(.system(size: 28, weight: .light)).foregroundStyle(.tertiary)
            Text(title).font(.callout).foregroundStyle(.secondary)
            if let detail { Text(detail).font(.caption).foregroundStyle(.tertiary).multilineTextAlignment(.center) }
        }.frame(maxWidth: .infinity, minHeight: minHeight)
    }
}

struct PressableStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.scaleEffect(configuration.isPressed ? 0.98 : 1).animation(.snappy(duration: 0.15), value: configuration.isPressed)
    }
}

enum DisplayFormat {
    static func bytes(_ amount: Int) -> String {
        amount < 1024 ? "\(max(0, amount)) B" : ByteCountFormatter.string(fromByteCount: Int64(amount), countStyle: .binary)
    }
    static func duration(_ seconds: TimeInterval) -> String {
        let total = max(0, Int(seconds))
        if total < 60 { return "\(total) s" }
        if total < 3600 { return String(format: "%d:%02d", total / 60, total % 60) }
        return String(format: "%d:%02d:%02d", total / 3600, total / 60 % 60, total % 60)
    }
}
