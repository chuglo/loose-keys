// The app: one window, a Settings window, a menu bar icon when asked for,
// and the engine behind them.
import AppKit
import SwiftUI

@main
enum Main {
    static func main() {
        #if !PREVIEW
        // The same executable is the background agent. It must not start an app.
        if CommandLine.arguments.contains("--agent") {
            ch_agent_main()
        }
        #endif
        LooseKeysApp.main()
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    @MainActor static var model: AppModel?
    /// Opened by macOS at login: in the menu bar, with no window.
    @MainActor private var quiet = false

    /// The same test as `login_event` in notifications.m. Which of the two
    /// launch calls sees the event is unverified, so both ask.
    private static func launchedAtLogin() -> Bool {
        guard let event = NSAppleEventManager.shared().currentAppleEvent else { return false }
        return event.eventClass == AEEventClass(kCoreEventClass) && event.eventID == AEEventID(kAEOpenApplication)
            && event.paramDescriptor(forKeyword: AEKeyword(keyAEPropData))?.enumCodeValue == OSType(keyAELaunchedAsLogInItem)
    }

    @MainActor private func goQuiet() {
        // A copy already open, started by the person or by a notification,
        // is the one to keep. The helper is not an application to macOS.
        let others = NSRunningApplication.runningApplications(withBundleIdentifier: Bundle.main.bundleIdentifier ?? "")
        if others.contains(where: { $0.processIdentifier != getpid() }) { exit(0) }
        quiet = true
        AppDelegate.model?.quietLaunch = true
        NSApp.setActivationPolicy(.accessory)
    }

    func applicationWillFinishLaunching(_ notification: Notification) {
        MainActor.assumeIsolated {
            if Self.launchedAtLogin() { goQuiet() }
            AppDelegate.model?.start(reviewRoute: CommandLine.arguments.contains("--review"))
        }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        MainActor.assumeIsolated {
            // With Show in Menu Bar on, the Dock icon goes with the last window.
            NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: nil, queue: .main) { note in
                guard let window = note.object as? NSWindow, window.styleMask.contains(.titled) else { return }
                let closing = window.windowNumber
                DispatchQueue.main.async { MainActor.assumeIsolated { AppDelegate.windowClosed(closing) } }
            }
            #if PREVIEW || SNAPSHOTS
            Snapshots.runIfAsked()
            Checks.runIfAsked()
            #else
            if !quiet, Self.launchedAtLogin() { goQuiet() }
            if quiet {
                // macOS 14 has no way to start a scene without its window
                // (defaultLaunchBehavior is macOS 15), so each window is put
                // away once made, also one made or restored later, until the
                // person opens a menu or a window.
                NotificationCenter.default.addObserver(forName: NSWindow.didChangeOcclusionStateNotification, object: nil, queue: .main) { note in
                    MainActor.assumeIsolated {
                        guard AppDelegate.model?.quietLaunch == true, let window = note.object as? NSWindow else { return }
                        AppDelegate.putAway(window)
                    }
                }
                NotificationCenter.default.addObserver(forName: NSMenu.didBeginTrackingNotification, object: nil, queue: .main) { _ in
                    MainActor.assumeIsolated { AppDelegate.model?.quietLaunch = false }
                }
                DispatchQueue.main.async { MainActor.assumeIsolated { NSApp.windows.forEach(AppDelegate.putAway) } }
            } else {
                // Opened from Finder or with open, the app is already in front. Its
                // executable started by itself is not, and the window then opens
                // behind whatever is, where it looks as if no window opened.
                NSApp.activate(ignoringOtherApps: true)
            }
            #endif
        }
    }

    @MainActor private static func putAway(_ window: NSWindow) {
        if window.isVisible, window.styleMask.contains(.titled) { window.orderOut(nil) }
    }

    /// The app leaves the Dock and the front once no window is open, so the
    /// helper does not take it for one being looked at.
    @MainActor private static func windowClosed(_ closing: Int) {
        guard model?.menuBarOn == true, !AppModel.windowOpen(in: NSApp.windows, except: closing) else { return }
        NSApp.setActivationPolicy(.accessory)
        NSApp.hide(nil)
    }

    /// The Dock or Finder. The system's own reopen goes ahead too, in case
    /// the window this opens from has gone: there is one main window, so
    /// the two cannot make a second.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        if !hasVisibleWindows {
            MainActor.assumeIsolated { AppDelegate.model?.showWindow(review: false) }
        }
        return true
    }

    func applicationDidBecomeActive(_ notification: Notification) {
        MainActor.assumeIsolated { AppDelegate.model?.becameActive() }
    }

    func applicationDidResignActive(_ notification: Notification) {
        MainActor.assumeIsolated { AppDelegate.model?.becameInactive() }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        MainActor.assumeIsolated { !(AppDelegate.model?.menuBarOn ?? false) }
    }

    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated { AppDelegate.model?.prepareToQuit() }
    }
}

struct LooseKeysApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model: AppModel

    init() {
        #if PREVIEW
        let model = AppModel(engine: SampleEngine())
        #else
        let model = AppModel(engine: LiveEngine())
        #endif
        _model = StateObject(wrappedValue: model)
        AppDelegate.model = model
    }

    var body: some Scene {
        // The app's name is never translated.
        Window(Text(verbatim: "Loose Keys"), id: "main") {
            MainView()
                .environmentObject(model)
                .frame(minWidth: 760, minHeight: 480)
        }
        .defaultSize(width: 1180, height: 720)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Scan Now") { model.startScan() }
                    .keyboardShortcut("r")
                    .disabled(model.phase == .scanning)
                Divider()
                Button("Save Report…") { model.save(feedback: false) }
                    .keyboardShortcut("s")
                    .disabled(model.results == nil)
                Button("Save Counts Only…") { model.save(feedback: true) }
                    .disabled(model.results == nil)
            }
        }

        Settings {
            SettingsView()
                .environmentObject(model)
        }

        MenuBarExtra(isInserted: menuBarShown) {
            MenuBarMenu()
                .environmentObject(model)
        } label: {
            MenuBarLabel()
                .environmentObject(model)
        }
        .menuBarExtraStyle(.menu)
    }

    /// Also set when the person drags the icon out of the menu bar.
    private var menuBarShown: Binding<Bool> {
        Binding(get: { model.menuBarOn }, set: { if $0 != model.menuBarOn { model.setMenuBar($0) } })
    }
}
