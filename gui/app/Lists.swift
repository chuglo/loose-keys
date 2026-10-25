// The lists the sidebar opens: what to review, what is stored, what was not checked.
import SwiftUI

struct ReviewTable: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        if let error = model.reviewProblem {
            // Never "nothing to review" for a list that could not be read, saved or got.
            ContentUnavailableView {
                Label("Review List Unavailable", systemImage: "exclamationmark.triangle")
            } description: {
                // The engine keeps its own failure until the app is opened
                // again, when it reads the list afresh. A request of this
                // window's that failed clears with the next one that works,
                // and the advice still holds. Only a window that has a scan's
                // results has a report to save.
                Text(verbatim: model.results == nil
                     ? String(localized: "\(error) Quit and reopen the app to try again.",
                              comment: "Worth Reviewing, when the list of findings could not be read or saved and this window has not scanned. %@ is the reason, one or more sentences from the engine or macOS.")
                     : String(localized: "\(error) Save the report to see the last scan's findings, and quit and reopen the app to try again.",
                              comment: "Worth Reviewing, when the list of findings could not be read or saved after a scan. %@ is the reason, one or more sentences from the engine or macOS."))
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
                Text(empty.text)
            }
        } else {
            Table(model.reviewRows, selection: $model.selectedReview, sortOrder: $model.reviewSort) {
                TableColumn("Finding", value: \.shownTitle) { (item: ReviewItem) in
                    // Most rows are open, and Set Aside lists only set-aside
                    // ones, so only a fixed row says what it is.
                    if item.status == "fixed" {
                        HStack(spacing: 8) {
                            Text(item.shownTitle).lineLimit(1)
                            Text(item.statusText).fixedSize()
                        }
                        .foregroundStyle(.secondary)
                    } else {
                        Text(item.shownTitle).lineLimit(1)
                    }
                }
                .width(min: 180, ideal: 320)
                TableColumn("Where", value: \.path) { (item: ReviewItem) in
                    PathText(path: item.path)
                }
                .width(min: 130, ideal: 190)
                // The first click puts the highest risk at the top.
                TableColumn("Risk", sortUsing: KeyPathComparator(\ReviewItem.riskLevel, order: .reverse)) { (item: ReviewItem) in
                    RiskLabel(severity: item.severity)
                }
                .width(min: 92, ideal: 96, max: 120)
            }
            .contextMenu(forSelectionType: ReviewItem.ID.self) { ids in
                // Not for a file whose name the app does not act on.
                if let id = ids.first, model.reviewEntry(id)?.actionable != false {
                    Button("Show in Finder") { model.showInFinder(id, review: true) }
                    Button("Copy Path") { model.copyPath(id, review: true) }
                }
            } primaryAction: { ids in
                if let id = ids.first, model.reviewEntry(id)?.actionable != false {
                    model.showInFinder(id, review: true)
                }
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
                    String(localized: "Findings you set aside appear here, with your reason and an option to return them to review.",
                           comment: "The Set Aside page, empty."))
        }
        if model.setAsideCount > 0 {
            // Not Checked lists only a scan's gaps, so without one this says
            // what background checks have read instead.
            let rest: String
            if model.results != nil {
                rest = String(localized: "Not Checked lists any places the scan could not read.",
                              comment: "Worth Reviewing, empty because every finding is set aside: the sentence after the one saying so. Not Checked is the page's name.")
            } else if let monitor = model.monitor, monitor.enabled, monitor.health.fullPass == nil {
                rest = String(localized: "New findings show up here as Loose Keys checks your files.",
                              comment: "Worth Reviewing, empty because every finding is set aside, while automatic scanning has not yet read every file once.")
            } else if let monitor = model.monitor, monitor.enabled, let unread = monitor.health.unread, unread > 0 {
                rest = String(localized: "\(unread) places could not be read. Scan this Mac to see which.",
                              comment: "Worth Reviewing, empty because every finding is set aside, after automatic scanning could not read some places.")
            } else {
                rest = String(localized: "Scan this Mac to check it now.",
                              comment: "Worth Reviewing, empty because every finding is set aside: the sentence after the one saying so.")
            }
            // Two whole sentences, the second chosen above.
            return (String(localized: "No Items Waiting for Review", comment: "Worth Reviewing's heading when every finding is set aside."), "tray",
                    String(localized: "Your set-aside findings are in Set Aside and are still counted.",
                           comment: "Worth Reviewing, empty because every finding is set aside. Set Aside is the page's name. Another sentence follows.")
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
                if let unread = monitor.health.unread, unread > 0 {
                    return (String(localized: "No Findings", comment: "Worth Reviewing, empty after automatic scanning read the files: it found nothing to review."), "tray",
                            String(localized: "Nothing to review, but \(unread) places could not be read.",
                                   comment: "Worth Reviewing, empty after automatic scanning could not read some places."))
                }
                return (String(localized: "No Findings", comment: "Worth Reviewing, empty after automatic scanning read the files: it found nothing to review."), "tray",
                        String(localized: "Loose Keys checked your files and found nothing to review.",
                               comment: "Worth Reviewing, empty after automatic scanning read every file."))
            }
            return model.monitor?.health.lastScan == nil
                ? (String(localized: "No Scan Yet", comment: "A list's heading when it is empty because nothing has been scanned yet."), "exclamationmark.triangle",
                   String(localized: "Scan this Mac to look for saved passwords, keys and tokens.",
                          comment: "Worth Reviewing, empty because nothing has been scanned yet."))
                : (String(localized: "Nothing to Review", comment: "Worth Reviewing, empty: no finding needs the person's attention. Never a claim that the Mac is safe."), "tray",
                   String(localized: "Earlier automatic scans found nothing that needs your attention. Scan this Mac to check it now.",
                          comment: "Worth Reviewing, empty while automatic scanning is off, after it once ran."))
        }
        if results.review > 0 {
            return (String(localized: "Findings Not Listed", comment: "Worth Reviewing, empty although the last scan found something."), "exclamationmark.triangle",
                    String(localized: "The last scan found \(results.review) findings, but they are not in this list. Scan again, or save the report to see them.",
                           comment: "Worth Reviewing, empty although the last scan counted this many findings."))
        }
        // A scan is "partial" whenever it could not read something, which
        // includes the folders macOS protects, so most scans are.
        return results.status == "complete"
            ? (String(localized: "Nothing to Review", comment: "Worth Reviewing, empty: no finding needs the person's attention. Never a claim that the Mac is safe."), "checkmark.circle",
               String(localized: "The last scan found nothing that needs your attention. That is not proof this Mac is safe.",
                      comment: "Worth Reviewing, empty after a scan that read every place it was asked to."))
            : (String(localized: "Nothing Found in What Was Checked", comment: "Worth Reviewing, empty after a scan that could not read some places."), "eye.slash",
               String(localized: "The last scan could not check everything, and found nothing that needs your attention in what it read. Not Checked lists what it missed.",
                      comment: "Worth Reviewing, empty after a scan that could not read some places. Not Checked is the page's name."))
    }
}

struct StoredTable: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        if model.results == nil {
            ContentUnavailableView {
                Label("No Scan Yet", systemImage: "key")
            } description: {
                Text("Stored sign-ins are listed after a scan. They are normal, but malware can copy them.")
            }
        } else {
            Table(model.storedRows, selection: $model.selectedStored, sortOrder: $model.storedSort) {
                TableColumn("Sign-in", value: \.shownTitle) { (row: StoredRow) in
                    Text(row.shownTitle).lineLimit(1)
                }
                .width(min: 180, ideal: 300)
                TableColumn("Where", value: \.file.path) { (row: StoredRow) in
                    PathText(path: row.file.path)
                }
                .width(min: 140, ideal: 240)
            }
            .contextMenu(forSelectionType: StoredRow.ID.self) { ids in
                // Not for a file whose name the app does not act on.
                if let id = ids.first, model.storedRows.first(where: { $0.id == id })?.file.actionable != false {
                    Button("Show in Finder") { model.showInFinder(id, review: false) }
                    Button("Copy Path") { model.copyPath(id, review: false) }
                }
            }
        }
    }
}

struct GapsView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        let gaps = model.results?.gaps ?? []
        // A folder left out at the person's request is not a gap in the
        // scan, and it was not checked either.
        let skipped = model.review?.skipped ?? []
        // A list that could not be read says nothing about what was left out.
        let unread = model.reviewProblem != nil
        if gaps.isEmpty && skipped.isEmpty && !unread {
            ContentUnavailableView {
                Label(model.results == nil ? "No Scan Yet" : "Everything Was Checked", systemImage: "eye.slash")
            } description: {
                Text(model.results == nil
                     ? "Places macOS or the scan could not read are listed here after a scan."
                     : "The last scan read every place it was asked to.")
            }
        } else {
            Form {
                Section {
                    Text(!gaps.isEmpty
                         ? "These places could not be checked, so anything in them was not found. The scan is incomplete because of them."
                         : model.results == nil
                         ? "Places macOS or the scan could not read are listed here after a scan."
                         : "The last scan read every place it was asked to, except the folders you left out.")
                        .foregroundStyle(.secondary)
                    if unread {
                        Text("The folders you left out could not be read, so they are not listed here.")
                    }
                }
                ForEach(gaps) { gap in
                    Section {
                        ForEach(gap.paths, id: \.self) { path in
                            Text(path).font(.callout.monospaced()).textSelection(.enabled)
                        }
                        if gap.more > 0 {
                            Text(String(localized: "and \(gap.more) more. Save the report for the full list.",
                                        comment: "Not Checked, below the places listed under one heading: how many more there are."))
                                .foregroundStyle(.secondary)
                        }
                    } header: {
                        Text(verbatim: "\(EngineText.shown(gap.label)) (\(gap.count))")
                    } footer: {
                        if !gap.help.isEmpty {
                            Text(EngineText.shown(gap.help))
                        }
                    }
                }
                if !skipped.isEmpty {
                    Section {
                        ForEach(Array(skipped.enumerated()), id: \.offset) { index, folder in
                            LabeledContent {
                                Button("Include Again") { model.checkFolderAgain(index, shown: folder) }
                            } label: {
                                Label(folder, systemImage: "folder.badge.minus")
                            }
                        }
                    } header: {
                        Text("Not Checked at Your Request")
                    } footer: {
                        Text("These folders are not read, so anything in them is not found.")
                    }
                }
            }
            .formStyle(.grouped)
        }
    }
}
