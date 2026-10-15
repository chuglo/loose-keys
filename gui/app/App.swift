// The app: one window, a Settings window, and the engine behind them.
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

    func applicationWillFinishLaunching(_ notification: Notification) {
        MainActor.assumeIsolated {
            AppDelegate.model?.start(reviewRoute: CommandLine.arguments.contains("--review"))
        }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        #if PREVIEW || SNAPSHOTS
        MainActor.assumeIsolated {
            Snapshots.runIfAsked()
            Checks.runIfAsked()
        }
        #else
        // Opened from Finder or with open, the app is already in front. Its
        // executable started by itself is not, and the window then opens
        // behind whatever is, where it looks as if no window opened.
        NSApp.activate(ignoringOtherApps: true)
        #endif
    }

    func applicationDidBecomeActive(_ notification: Notification) {
        MainActor.assumeIsolated { AppDelegate.model?.becameActive() }
    }

    func applicationDidResignActive(_ notification: Notification) {
        MainActor.assumeIsolated { AppDelegate.model?.becameInactive() }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
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
        Window("Loose Keys", id: "main") {
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
    }
}
