// The menu bar icon and its menu, while Show in Menu Bar is on.
import AppKit
import SwiftUI

enum MenuBarIcon {
    static func label(_ mark: MenuBarMark) -> String {
        switch mark {
        case .open: return "Loose Keys, items to review"
        case .full: return "Loose Keys, review list full"
        case .problem: return "Loose Keys, review list could not be read"
        case .unknown: return "Loose Keys, reading review list"
        case .plain: return "Loose Keys"
        }
    }

    /// Always a template image, so macOS draws it for the menu bar's look.
    static func image(_ mark: MenuBarMark) -> NSImage {
        switch mark {
        case .problem: return symbol("exclamationmark.triangle", label(mark))
        case .open, .full: return dotted(label(mark))
        case .plain, .unknown: return symbol("key", label(mark))
        }
    }

    private static func symbol(_ name: String, _ label: String) -> NSImage {
        let image = NSImage(systemSymbolName: name, accessibilityDescription: label) ?? NSImage()
        image.isTemplate = true
        return image
    }

    /// The key with a small dot at its top right. SF Symbols has no key
    /// with a badge.
    private static func dotted(_ label: String) -> NSImage {
        let key = symbol("key", label)
        let dot = (key.size.height * 0.4).rounded()
        let size = NSSize(width: key.size.width + dot / 2, height: key.size.height)
        let image = NSImage(size: size, flipped: false) { rect in
            key.draw(in: NSRect(origin: .zero, size: key.size))
            let spot = NSRect(x: rect.maxX - dot, y: rect.maxY - dot, width: dot, height: dot)
            // A clear ring keeps the dot apart from the key.
            NSGraphicsContext.current?.compositingOperation = .clear
            NSBezierPath(ovalIn: spot.insetBy(dx: -1.5, dy: -1.5)).fill()
            NSGraphicsContext.current?.compositingOperation = .sourceOver
            NSColor.black.setFill()
            NSBezierPath(ovalIn: spot).fill()
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = label
        return image
    }
}

/// The icon. It lives as long as the option is on, so its `openWindow`
/// still works once the main window has closed.
struct MenuBarLabel: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Image(nsImage: MenuBarIcon.image(model.menuBarMark))
            .accessibilityLabel(MenuBarIcon.label(model.menuBarMark))
            .onAppear { model.openMainWindow = { openWindow(id: "main") } }
    }
}

/// Fixed words and a count. Nothing here changes a finding or a setting.
struct MenuBarMenu: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow
    #if compiler(>=6.0)
    @Environment(\.openSettings) private var openSettings
    #endif

    var body: some View {
        Text(model.menuBarLine)
        if let line = model.menuBarCheckLine {
            Text(line)
        }
        Divider()
        Button("Open Loose Keys") {
            model.openMainWindow = { openWindow(id: "main") }
            model.showWindow(review: true)
        }
        #if compiler(>=6.0)
        Button("Settings…") {
            // An app with no Dock icon opens Settings behind the app in front.
            model.comeForward()
            openSettings()
        }
        .keyboardShortcut(",")
        #else
        SettingsLink { Text("Settings…") }
        #endif
        Divider()
        Button("Quit Loose Keys") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }
}
