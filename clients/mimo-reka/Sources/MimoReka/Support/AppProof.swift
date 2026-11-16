import AppKit
import Foundation

/// Development-only capture of this app's own content, without screen access.
@MainActor
enum AppProof {
    private static var scheduled = false
    static func scheduleIfRequested() {
        guard !scheduled, let path = ProcessInfo.processInfo.environment["MIMO_REKA_PROOF_PATH"] else { return }
        scheduled = true
        Task {
            try? await Task.sleep(for: .seconds(2))
            guard let window = NSApp.windows.first(where: { $0.canBecomeMain && !$0.isSheet }), let content = window.contentView else { return }
            if ProcessInfo.processInfo.environment["MIMO_REKA_MIN_WINDOW"] == "1" {
                window.setContentSize(NSSize(width: 962, height: 644))
                try? await Task.sleep(for: .milliseconds(300))
            }
            let view = content.superview ?? content
            view.layoutSubtreeIfNeeded()
            guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
            window.effectiveAppearance.performAsCurrentDrawingAppearance {
                view.cacheDisplay(in: view.bounds, to: bitmap)
            }
            if let data = bitmap.representation(using: .png, properties: [:]) {
                try? data.write(to: URL(fileURLWithPath: path), options: .atomic)
            }
        }
    }
}
