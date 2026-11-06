// What Check for Updates… found. Quitting must not require answering it.
// SwiftUI's dialog termination override needs macOS 15.4. Use the native
// alert's equivalent on every supported macOS, scoped to this alert alone.
import AppKit
import SwiftUI

struct UpdateAlertPresenter: NSViewRepresentable {
    let value: UpdateResult?
    let makeAlert: (UpdateResult) -> NSAlert
    let respond: (UpdateResult, NSApplication.ModalResponse) -> Void

    func makeNSView(context: Context) -> Anchor { Anchor() }

    func updateNSView(_ view: Anchor, context: Context) {
        view.refresh = { [weak view] in
            view?.present(value, makeAlert: makeAlert, respond: respond)
        }
        // Present outside SwiftUI's view update, and after the anchor has
        // joined its window. A later sheet dismissal retries a queued alert.
        DispatchQueue.main.async { [weak view] in view?.refresh?() }
    }

    final class Anchor: NSView {
        var refresh: (() -> Void)?
        private var shown: (UpdateResult, NSAlert)?
        private var sheetEnded: NSObjectProtocol?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if let sheetEnded { NotificationCenter.default.removeObserver(sheetEnded) }
            sheetEnded = nil
            guard let window else { return }
            sheetEnded = NotificationCenter.default.addObserver(
                forName: NSWindow.didEndSheetNotification, object: window, queue: .main
            ) { [weak self] _ in
                DispatchQueue.main.async { self?.refresh?() }
            }
            DispatchQueue.main.async { [weak self] in self?.refresh?() }
        }

        deinit {
            if let sheetEnded { NotificationCenter.default.removeObserver(sheetEnded) }
        }

        func present(_ value: UpdateResult?, makeAlert: (UpdateResult) -> NSAlert,
                     respond: @escaping (UpdateResult, NSApplication.ModalResponse) -> Void) {
            guard shown?.0 != value else { return }
            if let previous = shown {
                shown = nil
                previous.1.window.sheetParent?.endSheet(previous.1.window, returnCode: .abort)
            }
            guard let value, let window, window.attachedSheet == nil else { return }
            let alert = makeAlert(value)
            alert.window.preventsApplicationTerminationWhenModal = false
            shown = (value, alert)
            alert.beginSheetModal(for: window) { [weak self, weak alert] response in
                guard let self, let alert, self.shown?.1 === alert else { return }
                self.shown = nil
                // System dismissal, including Quit, is not an answer. Only
                // one of the explicit buttons may open a URL.
                if response == .alertFirstButtonReturn || response == .alertSecondButtonReturn {
                    respond(value, response)
                }
            }
        }
    }
}
