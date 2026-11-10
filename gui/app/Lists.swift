// The lists the sidebar opens: what to review, what is stored, what was set
// aside, and what was not checked.
import SwiftUI

/// Keep the table and its column headings in place while explaining a
/// filter. Read failures and genuinely empty source lists never use this.
private struct FilterPresentation: ViewModifier {
    @EnvironmentObject private var model: AppModel

    func body(content: Content) -> some View {
        VStack(spacing: 0) {
            if let summary = model.filterSummary {
                HStack {
                    Text(summary).foregroundStyle(.secondary)
                    Spacer()
                    Button("Clear Filter") { model.search = "" }
                }
                .padding(12)
            }
            content.overlay {
                if model.filterHasNoMatches {
                    ContentUnavailableView {
                        Label("No Matches", systemImage: "magnifyingglass")
                    } description: {
                        Text("No items in this list match the filter. Clear it to see all items.")
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(.background)
                }
            }
        }
    }
}

/// Worth Reviewing, Stored Sign-ins and Set Aside: one saved list, each page
/// showing its part.
struct ReviewTable: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        if let error = model.reviewProblem {
            // Never "nothing to review" for a list that could not be read, saved or got.
            ContentUnavailableView {
                Label(FailureTitle.openList(model.pane), systemImage: "exclamationmark.triangle")
            } description: {
                // The engine keeps its own failure until the app is opened
                // again, when it reads the list afresh. A request of this
                // window's that failed clears with the next one that works,
                // and the advice still holds. Only a window that has a scan's
                // results has a report to save.
                Text(verbatim: model.results == nil
                     ? String(localized: "\(error) Quit and reopen the app to try again.",
                              comment: "Worth Reviewing, Stored Sign-ins or Set Aside, when the saved list could not be read or saved and this window has not scanned. %@ is the reason, one or more sentences from the engine or macOS.")
                     : String(localized: "\(error) Quit and reopen the app to try again. Save the report to see the last scan's findings.",
                              comment: "Worth Reviewing, Stored Sign-ins or Set Aside, when the saved list could not be read or saved after a scan. %@ is the reason, one or more sentences from the engine or macOS."))
            }
        } else if model.review == nil {
            // The first answer has not come. The engine waits for the list
            // while the helper is saving what a background check found.
            ContentUnavailableView {
                Label("Reading the List", systemImage: "hourglass")
            } description: {
                Text("This can take a little longer while new findings are being saved.")
            }
        } else if model.reviewPaneItems.isEmpty {
            let empty = self.empty
            ContentUnavailableView {
                Label(empty.title, systemImage: empty.symbol)
            } description: {
                if !empty.text.isEmpty { Text(empty.text) }
            }
        } else if model.pane == .stored {
            Table(model.reviewRows, selection: $model.selectedReviews, sortOrder: $model.storedSort) {
                TableColumn("Sign-in", value: \.shownTitle) { (item: ReviewItem) in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(item.shownTitle).lineLimit(1)
                        if let about = item.shownAbout {
                            Text(about).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        }
                    }
                }
                .width(min: 180, ideal: 300)
                TableColumn("Where", value: \.path) { (item: ReviewItem) in
                    ReviewWhere(path: item.path, matches: model.matchingReviewPaths(item))
                }
                .width(min: 140, ideal: 240)
            }
            .fileMenu(model)
            .modifier(FilterPresentation())
        } else {
            Table(model.reviewRows, selection: $model.selectedReviews, sortOrder: $model.reviewSort) {
                TableColumn("Finding", value: \.shownTitle) { (item: ReviewItem) in
                    // Most rows are open, and Set Aside lists only set-aside
                    // ones, so only a fixed row says what it is.
                    VStack(alignment: .leading, spacing: 2) {
                        if item.status == "fixed" {
                            HStack(spacing: 8) {
                                Text(item.shownTitle).lineLimit(1)
                                Text(item.statusText).fixedSize()
                            }
                            .foregroundStyle(.secondary)
                        } else {
                            Text(item.shownTitle).lineLimit(1)
                        }
                        if let hint = item.copyHint {
                            Text(hint).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                .width(min: 180, ideal: 320)
                TableColumn("Where", value: \.path) { (item: ReviewItem) in
                    ReviewWhere(path: item.path, matches: model.matchingReviewPaths(item))
                }
                .width(min: 130, ideal: 190)
                // The first click puts the highest risk at the top.
                TableColumn("Risk", sortUsing: KeyPathComparator(\ReviewItem.riskLevel, order: .reverse)) { (item: ReviewItem) in
                    RiskLabel(severity: item.severity)
                }
                .width(min: 92, ideal: 96, max: 120)
                // The first click puts the newest at the top.
                TableColumn("First Seen", sortUsing: KeyPathComparator(\ReviewItem.firstSeenOrder, order: .reverse)) { (item: ReviewItem) in
                    Text(localDay(item.firstSeen))
                }
                .width(min: 90, ideal: 110, max: 160)
            }
            .fileMenu(model)
            .modifier(FilterPresentation())
        }
    }
}

extension Table {
    /// A row's context menu, and Show in Finder on a double-click.
    @MainActor fileprivate func fileMenu(_ model: AppModel) -> some View {
        contextMenu(forSelectionType: ReviewItem.ID.self) { ids in
            // Not for a file whose name the app does not act on.
            if ids.count == 1, let id = ids.first, model.reviewEntry(id)?.actionable == true {
                Button("Show in Finder") { model.showInFinder(id) }
                Button("Copy Path") { model.copyPath(id) }
            }
        } primaryAction: { ids in
            if ids.count == 1, let id = ids.first, model.reviewEntry(id)?.actionable == true {
                model.showInFinder(id)
            }
        }
    }
}

/// A row's file, and under it each other copy's file the Filter field
/// matches, so a row kept by another copy says why. Table cells don't reach
/// the window's environment object, so the matches are passed in.
private struct ReviewWhere: View {
    let path: String
    let matches: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            PathText(path: path)
            ForEach(matches, id: \.self) { path in
                Text(String(localized: "Matches: \(path)",
                            comment: "Under a grouped finding's representative path: another copy's path matches the Filter field."))
                    .font(.caption).foregroundStyle(.secondary)
                    .lineLimit(2).truncationMode(.middle)
                    .help(path)
            }
        }
    }
}

extension ReviewTable {
    /// What an empty list says. "Nothing to Review" with a tick is only for
    /// a scan that read every place it was asked to and found nothing.
    fileprivate var empty: (title: String, symbol: String, text: String) {
        if model.pane == .setAside {
            return (String(localized: "No Items Set Aside", comment: "The Set Aside page's heading when it lists nothing."), "archivebox",
                    String(localized: "Findings you set aside appear here.",
                           comment: "The Set Aside page, empty."))
        }
        if model.pane == .stored { return storedEmpty }
        if model.setAside(stored: false) > 0 {
            // Without a manual scan, describe the automatic pass's coverage.
            let rest: String
            if let results = model.results, results.notChecked > 0 {
                rest = NotCheckedText.some
            } else if model.results == nil, let monitor = model.monitor, monitor.enabled, monitor.health.fullPass == nil {
                rest = String(localized: "New findings show up here as Loose Keys checks your files.",
                              comment: "Worth Reviewing, empty because every finding is set aside, while automatic scanning has not yet read every file once.")
            } else if model.results == nil, let monitor = model.monitor, monitor.enabled, (monitor.health.unread ?? 0) > 0 {
                rest = NotCheckedText.some
            } else {
                rest = String(localized: "Use Scan Now to look again.",
                              comment: "Worth Reviewing, empty because every finding is set aside: the sentence after the one saying so. Scan Now is a button's name.")
            }
            // Two whole sentences, the second chosen above.
            return (String(localized: "No Items Waiting for Review", comment: "Worth Reviewing's heading when every finding is set aside."), "tray",
                    String(localized: "You set aside everything the scan found.",
                           comment: "Worth Reviewing, empty because every finding is set aside. Another sentence follows.")
                        + " " + rest)
        }
        guard let results = model.results else {
            // This window has not scanned. The helper may have, and it fills the list too.
            if let monitor = model.monitor, monitor.enabled {
                guard monitor.health.fullPass != nil else {
                    return (String(localized: "No Findings Yet", comment: "Worth Reviewing, empty while automatic scanning has not yet read every file once."), "tray",
                            String(localized: "Findings show up here as Loose Keys checks your files.",
                                   comment: "Worth Reviewing, empty while automatic scanning has not yet read every file once."))
                }
                let checked = String(localized: "Loose Keys checked your files and found nothing to review.",
                                     comment: "Worth Reviewing, empty after automatic scanning read the files. A sentence saying some places could not be checked may follow.")
                let unread = (monitor.health.unread ?? 0) > 0
                return (String(localized: "No Findings", comment: "Worth Reviewing, empty after automatic scanning read the files: it found nothing to review."), "tray",
                        unread ? checked + " " + NotCheckedText.some : checked)
            }
            return model.monitor?.health.lastScan == nil
                ? (String(localized: "No Scan Yet", comment: "A list's heading when it is empty because nothing has been scanned yet."), "exclamationmark.triangle",
                   String(localized: "Scan this Mac to look for saved passwords, keys and tokens.",
                          comment: "Worth Reviewing, empty because nothing has been scanned yet."))
                : (String(localized: "Nothing to Review", comment: "Worth Reviewing, empty: no finding needs the person's attention. Never a claim that the Mac is safe."), "tray",
                   String(localized: "Past automatic scans found nothing to review. Use Scan Now to look again.",
                          comment: "Worth Reviewing, empty while automatic scanning is off, after it once ran."))
        }
        if results.review > 0 {
            return (FailureTitle.showFindings, "exclamationmark.triangle",
                    String(localized: "The last scan found \(results.review) findings, but they aren't in this list. Scan again, or save the report to see them.",
                           comment: "Worth Reviewing, empty although the last scan counted this many findings."))
        }
        // A scan is "partial" whenever it could not read something, which
        // includes the folders macOS protects, so most scans are.
        return results.status == "complete"
            ? (String(localized: "Nothing to Review", comment: "Worth Reviewing, empty: no finding needs the person's attention. Never a claim that the Mac is safe."), "checkmark.circle",
               String(localized: "The last scan found nothing to review. That doesn't mean this Mac is safe.",
                      comment: "Worth Reviewing, empty after a scan that read every place it was asked to."))
            : (String(localized: "Nothing Found", comment: "Worth Reviewing, empty after a scan that could not read some places."), "eye.slash",
               String(localized: "The last scan found nothing to review, but some places couldn't be checked.",
                      comment: "Worth Reviewing, empty after a scan that could not read some places."))
    }

    /// What an empty Stored Sign-ins says. "No Stored Sign-ins" only once a
    /// scan has looked for each, and never while the last scan counted some
    /// the list doesn't hold.
    private var storedEmpty: (title: String, symbol: String, text: String) {
        switch model.storedEmpty {
        case .allSetAside:
            return (String(localized: "No Sign-ins Waiting", comment: "Stored Sign-ins' heading when every stored sign-in is set aside."), "tray",
                    String(localized: "You set aside every stored sign-in.", comment: "Stored Sign-ins, empty because every stored sign-in is set aside."))
        case .notListed(let found):
            return (FailureTitle.showFindings, "exclamationmark.triangle",
                    String(localized: "The last scan found \(found) sign-ins, but they aren't in this list. Scan again, or save the report to see them.",
                           comment: "Stored Sign-ins, empty although the last scan counted this many stored sign-ins."))
        case .notLookedYet:
            let automatic = model.monitor?.enabled == true
            return (String(localized: "No Sign-ins Yet", comment: "Stored Sign-ins' heading before a scan has looked for stored sign-ins."), "key",
                    automatic
                        ? String(localized: "Sign-ins your apps have saved show up here as Loose Keys checks your files.",
                                 comment: "Stored Sign-ins, empty while automatic scanning has not yet read every file once.")
                        : String(localized: "After a scan, sign-ins your apps have saved appear here. Apps normally keep them, but malware can copy them.",
                                 comment: "Stored Sign-ins, empty before a scan has looked for stored sign-ins, with automatic scanning off."))
        case .none:
            let none = String(localized: "No Stored Sign-ins", comment: "Stored Sign-ins' heading when a scan looked and found none.")
            return model.somePlacesNotChecked ? (none, "key", NotCheckedText.some) : (none, "key", "")
        }
    }
}

/// What the last scans could not read, in a popover from the Overview. It
/// opens only when there is something to list, so it never says nothing was
/// skipped for a scan that has not run.
struct PlacesNotChecked: View {
    @EnvironmentObject private var model: AppModel

    /// One heading's places, from the last scan and automatic scanning together.
    private struct Place: Identifiable {
        let label: String
        let help: String
        var paths: [String]
        /// The most places either scan counted under this heading.
        var count: Int
        var id: String { label }
        var more: Int { max(0, count - paths.count) }
    }

    /// Each place once, under its heading. Which scan missed it changes
    /// nothing a person does, so it is not said. The headings keep the last
    /// scan's order, then automatic scanning's.
    private var places: [Place] {
        var merged: [Place] = []
        let automatic = model.hasAutomaticCoverage ? model.automaticCoverage?.unreadGaps ?? [] : []
        for gap in (model.results?.gaps ?? []) + automatic {
            if let at = merged.firstIndex(where: { $0.label == gap.label }) {
                merged[at].paths += gap.paths.filter { !merged[at].paths.contains($0) }
                merged[at].count = max(merged[at].count, gap.count)
            } else {
                merged.append(Place(label: gap.label, help: gap.help, paths: gap.paths, count: gap.count))
            }
        }
        return merged
    }

    /// When each list was made: the last scan's, and automatic scanning's last full pass.
    private var when: String {
        var parts: [String] = []
        if let results = model.results, !results.gaps.isEmpty {
            parts.append(String(localized: "Last scan: \(localTime(results.generatedAt))",
                                comment: "Places Not Checked, under its title: when the last scan ran. %@ is a date and time."))
        }
        if model.hasAutomaticCoverage, let date = model.automaticCoverage?.fullPass {
            parts.append(String(localized: "Last automatic scan: \(localTime(date))",
                                comment: "Places Not Checked, under its title: when automatic scanning last read every file. %@ is a date and time."))
        }
        return parts.joined(separator: " · ")
    }

    var body: some View {
        Form {
            Section {
                Text("These places couldn't be read, so the scan may have missed something in them.")
                if !when.isEmpty {
                    Text(when).foregroundStyle(.secondary)
                }
                if let error = model.automaticCoverageError {
                    Text("Couldn't update these details, so they may be out of date.")
                    Text(error).foregroundStyle(.secondary)
                    Button("Try Again") { Task { await model.refreshAutomaticCoverage() } }
                }
                if model.hasAutomaticCoverage {
                    if model.automaticCoverage == nil && model.automaticCoverageError == nil {
                        ProgressView("Loading Details…")
                    } else if let health = model.automaticCoverage {
                        if health.unreadGaps == nil {
                            Text("Details will appear after the next full automatic scan.")
                        } else if health.unreadTruncated {
                            Text("This list is full, so it doesn't show every place Loose Keys couldn't check.")
                        }
                    }
                }
            }
            ForEach(places) { place in
                Section {
                    ForEach(place.paths, id: \.self) { path in
                        Text(path)
                            .font(.callout.monospaced())
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .textSelection(.enabled)
                    }
                    if place.more > 0 {
                        Text(String(localized: "and \(place.more) more",
                                    comment: "Places Not Checked, below the places listed under one heading: how many more there are. Export has them all."))
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    Text(EngineText.shown(place.label))
                } footer: {
                    if !place.help.isEmpty {
                        Text(EngineText.shown(place.help))
                    }
                }
            }
        }
        .formStyle(.grouped)
        .frame(width: 440, height: 380)
        .task { await model.refreshAutomaticCoverage() }
    }
}
