// The menu bar's commands: every toolbar button, and what the inspector and
// a row's context menu do to the chosen item, since the toolbar can be
// hidden and neither of the others is the only way to a command.
import SwiftUI

struct AppCommands: Commands {
    @ObservedObject var model: AppModel

    var body: some Commands {
        CommandGroup(after: .appInfo) {
            Button("Check for Updates…") { model.checkForUpdates() }
                .disabled(model.checkingUpdates)
        }
        CommandGroup(replacing: .newItem) {
            Button("Scan Now") { model.startScan() }
                .keyboardShortcut("r")
                .disabled(model.phase == .scanning)
            Button("Stop Scan") { model.cancelScan() }
                .keyboardShortcut(".")
                .disabled(model.phase != .scanning)
            Divider()
            Button("Save Report…") { model.save(feedback: false) }
                .keyboardShortcut("s")
                .disabled(model.results == nil)
            Button("Save Counts Only…") { model.save(feedback: true) }
                .disabled(model.results == nil)
            Button("Copy Summary") { model.copySummary() }
                .disabled(model.results == nil || model.phase == .scanning)
        }
        // The first page hides the toolbar and its sidebar button. The
        // system's SidebarCommands did not open the sidebar there, against
        // the first page's hiding, so this sets what the window reads.
        CommandGroup(replacing: .sidebar) {
            Button(model.sidebarShown ? "Hide Sidebar" : "Show Sidebar") { model.toggleSidebar() }
                .keyboardShortcut("s", modifiers: [.control, .command])
        }
        CommandGroup(after: .sidebar) {
            Button(model.inspectorShown && model.hasInspector ? "Hide Inspector" : "Show Inspector") {
                model.toggleInspector()
            }
            .keyboardShortcut("i", modifiers: [.command, .option])
            .disabled(!model.hasInspector)
        }
        CommandMenu(Text("Item", comment: "A menu in the menu bar: what can be done to the finding or sign-in chosen in the list.")) {
            Button("Show in Finder") {
                if let file = model.chosenFile { model.showInFinder(file.index, review: file.review) }
            }
            .disabled(model.chosenFile == nil)
            // Finder's own shortcut for Copy as Pathname.
            Button("Copy Path") {
                if let file = model.chosenFile { model.copyPath(file.index, review: file.review) }
            }
            .keyboardShortcut("c", modifiers: [.command, .option])
            .disabled(model.chosenFile == nil)
            Divider()
            if model.pane == .setAside {
                Button("Move to Worth Reviewing") { model.returnChosen() }
                    .disabled(model.currentReviews.isEmpty || model.decidingSelection)
            } else {
                Menu(String(localized: "command.set-aside", defaultValue: "Set Aside",
                            comment: "A submenu of the Item menu: set the chosen findings aside, for a reason chosen from it. A verb.")) {
                    ForEach(SetAsideReason.all) { reason in
                        Button(reason.label) { model.setAsideChosen(reason: reason.id) }
                    }
                }
                .disabled(!model.canSetAsideChosen)
            }
        }
    }
}

extension AppModel {
    /// The first page's question needs no sidebar: every list is empty. A
    /// sidebar the person opens there stays theirs.
    var welcomeHidesSidebar: Bool {
        showsWelcome && pane == .overview && !sidebarAsked
    }

    var sidebarShown: Bool {
        !welcomeHidesSidebar && columns != .detailOnly
    }

    func toggleSidebar() {
        if sidebarShown {
            columns = .detailOnly
        } else {
            sidebarAsked = true
            columns = .all
        }
    }

    /// Only lists have something to inspect.
    var hasInspector: Bool {
        pane == .review || pane == .setAside || pane == .stored
    }

    /// The file of the one row chosen, unless its name is one the app does
    /// not act on: as the inspector, never an arbitrary one of several.
    var chosenFile: (index: Int, review: Bool)? {
        switch pane {
        case .review, .setAside:
            guard let item = currentReview, item.actionable != false else { return nil }
            return (item.id, true)
        case .stored:
            guard let row = currentStored, row.file.actionable else { return nil }
            return (row.file.index, false)
        default:
            return nil
        }
    }

    /// Some chosen finding on Worth Reviewing still needs a decision.
    var canSetAsideChosen: Bool {
        pane == .review && !decidingSelection && currentReviews.contains { $0.status == "open" }
    }

    /// Set Aside for the chosen findings, as the inspector does it.
    func setAsideChosen(reason: String) {
        if let item = currentReview { decide(item, reason: reason) } else { decideSelection(reason: reason) }
    }

    /// Move to Worth Reviewing for the chosen findings, as the inspector does it.
    func returnChosen() {
        if let item = currentReview { decide(item, reason: nil) } else { decideSelection(reason: nil) }
    }
}
