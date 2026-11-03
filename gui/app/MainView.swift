// The window: a sidebar, the selected list, and an inspector.
import AppKit
import SwiftUI

/// What the update alert asks or says.
enum UpdateAlert: Equatable {
    case question
    case result(UpdateResult)
}

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
                // The Filter field stays in the toolbar on every page. Taken out
                // and put back as the page changes, it has stopped the app:
                // AppKit refuses a second one, and the first is not always
                // gone by then.
                .searchable(text: $model.search, prompt: "Filter")
                .inspector(isPresented: inspectorShown) {
                    Inspector()
                        .inspectorColumnWidth(min: 270, ideal: 320, max: 460)
                }
                .background(UpdateAlertPresenter(value: updateAlert, makeAlert: makeUpdateAlert,
                                                 respond: answerUpdateAlert))
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
        .alert(Text(verbatim: "Loose Keys"), isPresented: failureShown, presenting: model.failure) { _ in
            Button("OK") { model.failure = nil }
        } message: { text in
            Text(text)
        }
        // For a notification click or the Dock once this window has closed.
        .onAppear { model.openMainWindow = { openWindow(id: "main") } }
    }

    /// What the update alert is showing: a result first, then the question.
    private var updateAlert: UpdateAlert? {
        if let result = model.updateResult { return .result(result) }
        return model.shouldAskAboutUpdates ? .question : nil
    }

    private func updateTitle(_ alert: UpdateAlert) -> String {
        switch alert {
        case .question:
            return String(localized: "Check for Updates Automatically?",
                          comment: "The title of the alert the first time the window opens, asking whether the app may check GitHub for a newer version.")
        case .result(.newer(let release)):
            return String(localized: "Loose Keys \(release.newer ?? "") Is Available",
                          comment: "Overview and the alert after Check for Updates…: a newer version is out. %@ is its version number, such as 0.7.0.")
        case .result(.upToDate):
            return String(localized: "Loose Keys Is Up to Date",
                          comment: "The title of the alert after Check for Updates… when no newer version is out.")
        case .result(.failed):
            return String(localized: "Could Not Check for Updates",
                          comment: "The title of the alert after Check for Updates… when the check failed.")
        }
    }

    private func updateMessage(_ alert: UpdateAlert) -> String {
        switch alert {
        case .question:
            return String(localized: "Loose Keys can ask GitHub once a day whether a newer version is out. No paths or findings are sent. GitHub sees the request and your IP address.",
                          comment: "Under the title of the alert asking whether the app may check for updates.")
        case .result(.newer(let release)), .result(.upToDate(let release)):
            return String(localized: "You have \(release.current).",
                          comment: "Overview and the alert after Check for Updates…: the version this app is. %@ is a version number, such as 0.6.0.")
        case .result(.failed(let reason)):
            return reason
        }
    }

    private func makeUpdateAlert(_ value: UpdateAlert) -> NSAlert {
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = updateTitle(value)
        alert.informativeText = updateMessage(value)
        switch value {
        case .question:
            alert.addButton(withTitle: String(localized: "Check Automatically"))
            alert.addButton(withTitle: String(localized: "Don’t Check")).keyEquivalent = "\u{1b}"
        case .result(.newer):
            alert.addButton(withTitle: String(localized: "Download"))
            alert.addButton(withTitle: String(localized: "Not Now")).keyEquivalent = "\u{1b}"
        case .result:
            alert.addButton(withTitle: String(localized: "OK"))
        }
        return alert
    }

    private func answerUpdateAlert(_ alert: UpdateAlert, _ response: NSApplication.ModalResponse) {
        switch alert {
        case .question:
            model.answerUpdateQuestion(response == .alertFirstButtonReturn)
        case .result(.newer):
            model.updateResult = nil
            if response == .alertFirstButtonReturn { model.openURL(Releases.page) }
        case .result:
            model.updateResult = nil
        }
    }

    /// Only lists have something to inspect.
    private var hasInspector: Bool {
        model.pane == .review || model.pane == .setAside || model.pane == .stored
    }

    private var inspectorShown: Binding<Bool> {
        // Leaving a list closes the inspector. Only a change made on a list
        // is the person's choice, and not one reported just after the page
        // changed: that is the close asked for on the page before. Taken for
        // a choice, it left the inspector hidden on coming back to a list.
        // Nor one reported just after the toolbar button was pressed: that is
        // the end of what the press before it asked for.
        Binding(get: { model.inspectorShown && hasInspector },
                set: { if hasInspector, model.paneSettled, model.inspectorSettled { model.inspectorShown = $0 } })
    }

    /// The first page's question needs no sidebar: every list is empty.
    private var welcomeHides: Bool {
        model.showsWelcome && model.pane == .overview && !model.sidebarAsked
    }

    private var columns: Binding<NavigationSplitViewVisibility> {
        // A sidebar the person opens on the first page stays theirs.
        Binding(get: { welcomeHides ? .detailOnly : model.columns },
                set: { visibility in
                    if !welcomeHides {
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
        case .review, .setAside: ReviewTable()
        case .stored: StoredTable()
        case .gaps: GapsView()
        }
    }

    private var title: String {
        switch model.pane ?? .overview {
        // The app's name is never translated.
        case .overview: return "Loose Keys"
        case .review: return String(localized: "Worth Reviewing", comment: "The name of the list of findings, in the sidebar and as its page's title.")
        case .setAside: return String(localized: "Set Aside", comment: "The name of the list of findings the person set aside, in the sidebar and as its page's title.")
        case .stored: return String(localized: "Stored Sign-ins", comment: "The name of the list of stored sign-ins, in the sidebar and as its page's title.")
        case .gaps: return String(localized: "Not Checked", comment: "The name of the page that lists what a scan could not check, in the sidebar and as its title.")
        }
    }

    private var subtitle: String {
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
            return model.results == nil ? ""
                : String(localized: "\(model.storedShown.count) items", comment: "Subtitle of Stored Sign-ins: how many sign-ins the list shows.")
        case .gaps:
            let places = model.gapsCount.map {
                String(localized: "\($0) places", comment: "Subtitle of Not Checked: how many places the last scan could not check. A comma may follow.")
            }
            let skipped = model.reviewProblem == nil ? model.review?.skipped?.count ?? 0 : 0
            let left = skipped > 0
                ? String(localized: "\(skipped) folders left out", comment: "Part of the subtitle of Not Checked, after a comma: how many folders the person chose to stop checking.")
                : nil
            return [places, left].compactMap { $0 }.joined(separator: ", ")
        default:
            guard let results = model.results else { return "" }
            let time = localTime(results.generatedAt)
            return results.status == "complete"
                ? String(localized: "Scan complete, \(time)", comment: "Overview subtitle: the last scan read every place it was asked to. %@ is when it ran, a date and time.")
                : String(localized: "Scan incomplete, \(time)", comment: "Overview subtitle: the last scan could not read some places. %@ is when it ran, a date and time.")
        }
    }

    @ToolbarContentBuilder private var toolbar: some ToolbarContent {
        // Words, not symbols: a toolbar shows a symbol alone, and the reload
        // arrow this once had left people guessing what it did. Scan Now is
        // also the command's name in the File menu and on the Overview.
        ToolbarItem(placement: .primaryAction) {
            if model.phase == .scanning {
                Button("Stop") { model.cancelScan() }
                    .help("Stop the scan")
            } else {
                Button("Scan Now") { model.startScan() }
                    .help("Scan this Mac now")
                    .disabled(model.places?.home == nil || model.preparingAccess)
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
        if hasInspector {
            ToolbarItem {
                Button { model.toggleInspector() } label: {
                    Label("Inspector", systemImage: "sidebar.trailing")
                }
                .help("Show or hide the inspector")
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
            Label("Overview", systemImage: "shield.lefthalf.filled")
                .tag(Pane.overview)
            Section("Findings") {
                Label("Worth Reviewing", systemImage: "exclamationmark.triangle")
                    .badge(model.reviewCount)
                    .tag(Pane.review)
                Label("Stored Sign-ins", systemImage: "key")
                    .badge(model.results?.stored ?? 0)
                    .tag(Pane.stored)
                Label("Not Checked", systemImage: "eye.slash")
                    .badge(model.gapsCount ?? 0)
                    .tag(Pane.gaps)
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
