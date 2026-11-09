// The window: a sidebar, the selected list, and an inspector.
import AppKit
import SwiftUI

struct MainView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        NavigationSplitView(columnVisibility: columns) {
            Sidebar()
                .navigationSplitViewColumnWidth(min: 190, ideal: 215, max: 280)
        } detail: {
            detail
                .navigationTitle(title)
                .navigationSubtitle(model.notice ?? subtitle)
                .toolbar { toolbar }
                .inspector(isPresented: inspectorShown) {
                    Inspector()
                        .inspectorColumnWidth(min: 270, ideal: 320, max: 460)
                }
                .background(UpdateAlertPresenter(value: updateAlert, makeAlert: makeUpdateAlert,
                                                 respond: answerUpdateAlert))
                // The first page's one step is its own Scan Now, so the toolbar
                // is hidden there with all it holds.
                .toolbar(welcomeShown ? .hidden : .visible, for: .windowToolbar)
        }
        // A sidebar the person has used is not hidden from them again: not on
        // coming back to Overview, nor when the first page's question returns.
        .onChange(of: model.pane) { _, pane in
            if pane != .overview { model.sidebarAsked = true }
        }
        .onChange(of: model.showsWelcome) { was, now in
            if was && !now { model.sidebarAsked = true }
        }
        #if (PREVIEW || SNAPSHOTS) && compiler(>=6.0)
        .modifier(SettingsOpener())
        #endif
        // The title says what failed, the message why.
        .alert(Text(model.failure?.title ?? ""), isPresented: failureShown, presenting: model.failure) { _ in
            Button("OK") { model.failure = nil }
        } message: { failure in
            Text(failure.reason)
        }
        // For a notification click or the Dock once this window has closed.
        .onAppear { model.openMainWindow = { openWindow(id: "main") } }
    }

    /// What Check for Updates… found, until its alert is closed. The question
    /// whether to check automatically is a row on the Overview, not an alert.
    private var updateAlert: UpdateResult? { model.updateResult }

    private func updateTitle(_ result: UpdateResult) -> String {
        switch result {
        case .newer(let release):
            return String(localized: "Loose Keys \(release.newer ?? "") Is Available",
                          comment: "Overview and the alert after Check for Updates…: a newer version is out. %@ is its version number, such as 0.7.0.")
        case .upToDate:
            return String(localized: "You’re up to date.",
                          comment: "The title of the alert after Check for Updates… when no newer version is out.")
        case .failed:
            return String(localized: "Couldn't Check for Updates",
                          comment: "The title of the alert after Check for Updates… when the check failed.")
        }
    }

    private func updateMessage(_ result: UpdateResult) -> String {
        switch result {
        case .newer(let release):
            return String(localized: "You're using version \(release.current).",
                          comment: "Overview and the alert after Check for Updates…: the version this app is. %@ is a version number, such as 0.6.0.")
        case .upToDate:
            return ""
        case .failed(let reason):
            return reason
        }
    }

    private func makeUpdateAlert(_ result: UpdateResult) -> NSAlert {
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = updateTitle(result)
        alert.informativeText = updateMessage(result)
        if case .newer = result {
            alert.addButton(withTitle: String(localized: "Download"))
            alert.addButton(withTitle: String(localized: "Not Now")).keyEquivalent = "\u{1b}"
        } else {
            alert.addButton(withTitle: String(localized: "OK"))
        }
        return alert
    }

    private func answerUpdateAlert(_ result: UpdateResult, _ response: NSApplication.ModalResponse) {
        model.updateResult = nil
        if case .newer = result, response == .alertFirstButtonReturn { model.openURL(Releases.page) }
    }

    private var inspectorShown: Binding<Bool> {
        // Leaving a list closes the inspector. Only a change made on a list
        // is the person's choice, and not one reported just after the page
        // changed: that is the close asked for on the page before. Taken for
        // a choice, it left the inspector hidden on coming back to a list.
        // Nor one reported just after the toolbar button was pressed: that is
        // the end of what the press before it asked for.
        Binding(get: { model.inspectorShown && model.hasInspector },
                set: { if model.hasInspector, model.paneSettled, model.inspectorSettled { model.inspectorShown = $0 } })
    }

    /// The first page is showing.
    private var welcomeShown: Bool {
        model.showsWelcome && !model.preparingAccess && model.pane == .overview
    }

    private var columns: Binding<NavigationSplitViewVisibility> {
        // A sidebar the person opens on the first page stays theirs.
        Binding(get: { model.welcomeHidesSidebar ? .detailOnly : model.columns },
                set: { visibility in
                    if !model.welcomeHidesSidebar {
                        model.columns = visibility
                    } else if visibility != .detailOnly {
                        model.sidebarAsked = true
                        model.columns = visibility
                    }
                })
    }

    private var failureShown: Binding<Bool> {
        Binding(get: { model.failure != nil }, set: { if !$0 { model.failure = nil } })
    }

    @ViewBuilder private var detail: some View {
        switch model.pane ?? .overview {
        case .overview: OverviewView()
        case .review, .setAside, .stored: ReviewTable()
        }
    }

    private var title: String {
        switch model.pane ?? .overview {
        // The app's name is never translated.
        case .overview: return "Loose Keys"
        case .review: return String(localized: "Worth Reviewing", comment: "The name of the list of findings, in the sidebar and as its page's title.")
        case .setAside: return String(localized: "Set Aside", comment: "The name of the list of findings the person set aside, in the sidebar and as its page's title.")
        case .stored: return String(localized: "Stored Sign-ins", comment: "The name of the list of stored sign-ins, in the sidebar and as its page's title.")
        }
    }

    private var subtitle: String {
        // The Overview's heading says that a scan or its preparation runs,
        // and when the last scan ran. "Scan incomplete" would show after
        // nearly every scan, for places macOS keeps private.
        if (model.pane ?? .overview) == .overview { return "" }
        if model.preparingAccess {
            return String(localized: "Preparing folder access…", comment: "Window subtitle while the app asks macOS for access to protected folders.")
        }
        if model.phase == .scanning { return String(localized: "Scanning…", comment: "Window subtitle while a scan runs.") }
        switch model.pane ?? .overview {
        case .review:
            return model.reviewSummary
        case .setAside:
            return model.reviewProblem == nil && model.review != nil
                ? String(localized: "\(model.setAsideCount) items · Still included in scan results",
                         comment: "Subtitle of the Set Aside page: how many findings it lists, and that they still count in scan results.")
                : ""
        case .stored:
            guard model.reviewProblem == nil, model.review != nil else { return "" }
            let count = String(localized: "\(model.storedCount) items", comment: "Subtitle of Stored Sign-ins: how many sign-ins the list shows.")
            return model.review?.storedFull == true
                ? count + ", " + String(localized: "list full, so some sign-ins are missing",
                                        comment: "Last part of the Stored Sign-ins subtitle, after the count and a comma: the list had no room for some sign-ins.")
                : count
        case .overview:
            return ""
        }
    }

    @ToolbarContentBuilder private var toolbar: some ToolbarContent {
        // Words, not symbols: a toolbar shows a symbol alone, and the reload
        // arrow this once had left people guessing what it did. Scan Now is
        // also the command's name in the File menu and on the Overview.
        ToolbarItem(placement: .primaryAction) {
            if model.phase == .scanning {
                Button("Stop Scan") { model.cancelScan() }
                    .help("Stop the scan")
            } else {
                Button("Scan Now") { model.startScan() }
                    .help("Scan this Mac now")
                    .disabled(!model.canStartScan)
            }
        }
        ToolbarItem {
            Menu {
                Button("Save Report…") { model.save(feedback: false) }
                Button("Save Counts Only…") { model.save(feedback: true) }
                Divider()
                Button("Copy Summary") { model.copySummary() }
            } label: {
                // Named here because assistive software reads the symbol's
                // own name for a toolbar menu, and this symbol's is "Share".
                Label {
                    Text("Export")
                } icon: {
                    Image(nsImage: NSImage(systemSymbolName: "square.and.arrow.up",
                                           accessibilityDescription: String(localized: "Export", comment: "The toolbar menu that saves or copies the results.")) ?? NSImage())
                }
            }
            .help("Save or copy the results")
            .disabled(model.results == nil || model.phase == .scanning)
        }
        if model.hasInspector {
            ToolbarItem {
                Button { model.toggleInspector() } label: {
                    Label("Inspector", systemImage: "sidebar.trailing")
                }
                .help("Show or hide the inspector")
            }
        }
        // Only on the lists it filters: the Overview has nothing to filter.
        if model.pane != .overview {
            ToolbarItem {
                FilterField(text: $model.search)
                    .frame(width: 180)
            }
        }
    }
}

// `openSettings` is not in the SDK of GitHub's macOS 14 runner, whose compiler
// is older than 6.0. There the window check still builds, and the
// picture-taking code leaves out the picture of Settings.
#if (PREVIEW || SNAPSHOTS) && compiler(>=6.0)
/// Lets the picture-taking code open Settings. The app itself uses SettingsLink.
private struct SettingsOpener: ViewModifier {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openSettings) private var openSettings

    func body(content: Content) -> some View {
        content.onAppear { model.openSettings = { openSettings() } }
    }
}
#endif

struct Sidebar: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        List(selection: $model.pane) {
            Label("Overview", systemImage: "house")
                .tag(Pane.overview)
            Section("Findings") {
                Label("Worth Reviewing", systemImage: "exclamationmark.triangle")
                    .badge(model.reviewCount)
                    .tag(Pane.review)
                Label("Stored Sign-ins", systemImage: "key")
                    .badge(model.storedCount)
                    .tag(Pane.stored)
                Label("Set Aside", systemImage: "archivebox")
                    .badge(model.setAsideCount)
                    .tag(Pane.setAside)
            }
        }
    }
}

/// A risk level as a small coloured mark and a word. Never colour alone.
struct RiskLabel: View {
    let severity: String

    var body: some View {
        Label {
            Text(riskText(severity))
        } icon: {
            Image(systemName: severity == "high" ? "exclamationmark.triangle.fill" : "exclamationmark.circle.fill")
                .foregroundStyle(severity == "high" ? Color.red : severity == "medium" ? Color.orange : Color.secondary)
        }
    }
}

/// A path split so the file name reads first and the folder stays visible.
struct PathText: View {
    let path: String

    var body: some View {
        let name = (path as NSString).lastPathComponent
        let folder = (path as NSString).deletingLastPathComponent
        VStack(alignment: .leading, spacing: 1) {
            Text(name).lineLimit(1).truncationMode(.middle)
            if !folder.isEmpty {
                Text(folder).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.head)
            }
        }
    }
}

/// AppKit's search field in an ordinary toolbar item, so it can come and go
/// with the page as the Inspector button does. Not `.searchable`: its toolbar
/// item stopped the app when taken out and put back, as AppKit refuses a
/// second one and the first was not always gone by then.
struct FilterField: NSViewRepresentable {
    @Binding var text: String

    func makeNSView(context: Context) -> NSSearchField {
        let field = NSSearchField()
        field.placeholderString = String(localized: "Filter", comment: "The placeholder of the toolbar field that filters the list.")
        field.sendsSearchStringImmediately = true
        field.stringValue = text
        field.target = context.coordinator
        field.action = #selector(Coordinator.changed(_:))
        return field
    }

    func updateNSView(_ field: NSSearchField, context: Context) {
        context.coordinator.text = $text
        if field.stringValue != text { field.stringValue = text }
    }

    func makeCoordinator() -> Coordinator { Coordinator(text: $text) }

    final class Coordinator: NSObject {
        var text: Binding<String>
        init(text: Binding<String>) { self.text = text }

        /// Each keystroke, and the field's clear button.
        @objc func changed(_ field: NSSearchField) { text.wrappedValue = field.stringValue }
    }
}
