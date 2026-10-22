// The window: a sidebar, the selected list, and an inspector.
import SwiftUI

struct MainView: View {
    @EnvironmentObject private var model: AppModel

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
        .alert("Loose Keys", isPresented: failureShown, presenting: model.failure) { _ in
            Button("OK") { model.failure = nil }
        } message: { text in
            Text(text)
        }
    }

    /// Only lists have something to inspect.
    private var hasInspector: Bool {
        model.pane == .review || model.pane == .stored
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
        case .review: ReviewTable()
        case .stored: StoredTable()
        case .gaps: GapsView()
        }
    }

    private var title: String {
        switch model.pane ?? .overview {
        case .overview: return "Loose Keys"
        case .review: return "Worth Reviewing"
        case .stored: return "Stored Sign-ins"
        case .gaps: return "Not Checked"
        }
    }

    private var subtitle: String {
        if model.preparingAccess { return "Preparing folder access…" }
        if model.phase == .scanning { return "Scanning…" }
        switch model.pane ?? .overview {
        case .review:
            return model.reviewSummary
        case .stored:
            return model.results == nil ? "" : plural(model.storedShown.count, "item", "items")
        case .gaps:
            let places = model.results.map { plural($0.notChecked, "place", "places") }
            let skipped = model.reviewProblem == nil ? model.review?.skipped?.count ?? 0 : 0
            let left = skipped > 0 ? "\(plural(skipped, "folder", "folders")) left out" : nil
            return [places, left].compactMap { $0 }.joined(separator: ", ")
        default:
            guard let results = model.results else { return "" }
            let state = results.status == "complete" ? "Scan complete" : "Scan incomplete"
            return "\(state), \(localTime(results.generatedAt))"
        }
    }

    @ToolbarContentBuilder private var toolbar: some ToolbarContent {
        ToolbarItem(placement: .primaryAction) {
            if model.phase == .scanning {
                Button { model.cancelScan() } label: { Label("Stop", systemImage: "stop.fill") }
                    .help("Stop the scan")
            } else {
                Button { model.startScan() } label: { Label("Scan", systemImage: "arrow.clockwise") }
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
                    Image(nsImage: NSImage(systemSymbolName: "square.and.arrow.up", accessibilityDescription: "Export") ?? NSImage())
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
                    .badge(model.results?.notChecked ?? 0)
                    .tag(Pane.gaps)
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
