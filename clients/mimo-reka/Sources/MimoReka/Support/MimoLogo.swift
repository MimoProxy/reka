import AppKit

/// A monochrome outline of the selected flowing m, for system-tinted menu bar items.
enum MimoLogo {
    static let menuBarImage = makeMenuBarImage(opacity: 1)
    static let inactiveMenuBarImage = makeMenuBarImage(opacity: 0.4)

    private static func makeMenuBarImage(opacity: CGFloat) -> NSImage {
        let image = NSImage(size: NSSize(width: 18, height: 18), flipped: true) { _ in
            let path = NSBezierPath()
            path.move(to: NSPoint(x: 190, y: 650))
            path.curve(to: NSPoint(x: 430, y: 391), controlPoint1: NSPoint(x: 190, y: 507), controlPoint2: NSPoint(x: 287, y: 391))
            path.curve(to: NSPoint(x: 626, y: 520), controlPoint1: NSPoint(x: 525, y: 391), controlPoint2: NSPoint(x: 590, y: 441))
            path.curve(to: NSPoint(x: 820, y: 391), controlPoint1: NSPoint(x: 666, y: 441), controlPoint2: NSPoint(x: 725, y: 391))
            path.curve(to: NSPoint(x: 1062, y: 650), controlPoint1: NSPoint(x: 965, y: 391), controlPoint2: NSPoint(x: 1062, y: 507))
            path.line(to: NSPoint(x: 1062, y: 814))
            path.curve(to: NSPoint(x: 922, y: 814), controlPoint1: NSPoint(x: 1062, y: 907), controlPoint2: NSPoint(x: 922, y: 907))
            path.line(to: NSPoint(x: 922, y: 650))
            path.curve(to: NSPoint(x: 820, y: 515), controlPoint1: NSPoint(x: 922, y: 570), controlPoint2: NSPoint(x: 873, y: 515))
            path.curve(to: NSPoint(x: 735, y: 650), controlPoint1: NSPoint(x: 758, y: 515), controlPoint2: NSPoint(x: 752, y: 575))
            path.line(to: NSPoint(x: 707, y: 730))
            path.curve(to: NSPoint(x: 626, y: 804), controlPoint1: NSPoint(x: 695, y: 782), controlPoint2: NSPoint(x: 671, y: 804))
            path.curve(to: NSPoint(x: 545, y: 730), controlPoint1: NSPoint(x: 581, y: 804), controlPoint2: NSPoint(x: 557, y: 782))
            path.line(to: NSPoint(x: 518, y: 606))
            path.curve(to: NSPoint(x: 430, y: 515), controlPoint1: NSPoint(x: 501, y: 545), controlPoint2: NSPoint(x: 472, y: 515))
            path.curve(to: NSPoint(x: 330, y: 650), controlPoint1: NSPoint(x: 377, y: 515), controlPoint2: NSPoint(x: 330, y: 570))
            path.line(to: NSPoint(x: 330, y: 814))
            path.curve(to: NSPoint(x: 190, y: 814), controlPoint1: NSPoint(x: 330, y: 907), controlPoint2: NSPoint(x: 190, y: 907))
            path.close()
            let scale: CGFloat = 18 / 872
            path.transform(using: AffineTransform(m11: scale, m12: 0, m21: 0, m22: scale,
                tX: -190 * scale, tY: (18 - 493 * scale) / 2 - 391 * scale))
            NSColor.black.withAlphaComponent(opacity).setFill()
            path.fill()
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = "Mimo"
        return image
    }
}
