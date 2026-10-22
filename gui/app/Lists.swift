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
                Text(verbatim: "The app could not read or save its list of findings, so what a scan found is not shown here. \(error) "
                     + (model.results == nil
                        ? "Quit the app and open it again to have the list read again."
                        : "Save the report to see what the last scan found. Quit the app and open it again to have the list read again, then scan again, because the list may not have what that scan found."))
            }
        } else if model.review == nil {
            // The first answer has not come. The engine waits for the list
            // while the helper is saving what a background check found.
            ContentUnavailableView {
                Label("Reading the List", systemImage: "hourglass")
            } description: {
                Text("This takes longer while a background check is saving what it found.")
            }
        } else if model.reviewPaneItems.isEmpty {
            let empty = self.empty
            ContentUnavailableView {
                Label(empty.title, systemImage: empty.symbol)
            } description: {
                Text(empty.text)
            }
        } else if model.pane == .setAside {
            // Every row here is set aside, so there is no Status column. A
            // column added by an `if` needs macOS 14.4, so this is a table
            // of its own.
            actions(Table(model.reviewRows, selection: $model.selectedReview, sortOrder: $model.reviewSort) {
                columns
            })
        } else {
            actions(Table(model.reviewRows, selection: $model.selectedReview, sortOrder: $model.reviewSort) {
                columns
                TableColumn("Status", value: \.statusRank) { (item: ReviewItem) in
                    Text(item.statusText)
                        .foregroundStyle(item.status == "open" ? Color.primary : Color.secondary)
                }
                .width(min: 86, ideal: 92, max: 130)
            })
        }
    }

    @TableColumnBuilder<ReviewItem, KeyPathComparator<ReviewItem>>
    private var columns: some TableColumnContent<ReviewItem, KeyPathComparator<ReviewItem>> {
        TableColumn("Finding", value: \.title) { (item: ReviewItem) in
            Text(item.title).lineLimit(1)
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

    private func actions(_ table: some View) -> some View {
        table.contextMenu(forSelectionType: ReviewItem.ID.self) { ids in
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

extension ReviewTable {
    /// What an empty list says. "Nothing to Review" with a tick is only for
    /// a scan that read every place it was asked to and found nothing.
    fileprivate var empty: (title: String, symbol: String, text: String) {
        if model.pane == .setAside {
            return ("No Items Set Aside", "archivebox",
                    "Findings you set aside appear here, with your reason and an option to return them to review.")
        }
        if model.setAsideCount > 0 {
            // Not Checked lists only a scan's gaps, so without one this says
            // what background checks have read instead.
            let rest: String
            if model.results != nil {
                rest = "Not Checked lists any places the scan could not read."
            } else if let monitor = model.monitor, monitor.enabled, monitor.health.fullPass == nil {
                rest = "Background checks list new findings here as they read your files."
            } else if let monitor = model.monitor, monitor.enabled, let unread = monitor.health.unread, unread > 0 {
                rest = "Background checks could not read \(plural(unread, "place", "places")). Scan this Mac to see which."
            } else {
                rest = "Scan this Mac to check it now."
            }
            return ("No Items Waiting for Review", "tray",
                    "Your set-aside findings are in Set Aside and are still counted. " + rest)
        }
        guard let results = model.results else {
            // This window has not scanned. The helper may have, and it fills the list too.
            if let monitor = model.monitor, monitor.enabled {
                guard monitor.health.fullPass != nil else {
                    return ("No Findings Yet", "tray",
                            "Background checks list findings here as they read your files.")
                }
                if let unread = monitor.health.unread, unread > 0 {
                    return ("No Findings", "tray",
                            "Background checks found nothing to review, but could not read \(plural(unread, "place", "places")).")
                }
                return ("No Findings", "tray",
                        "Background checks read your files and found nothing to review.")
            }
            return model.monitor?.health.lastScan == nil
                ? ("No Scan Yet", "exclamationmark.triangle",
                   "Scan this Mac to look for saved passwords, keys and tokens.")
                : ("Nothing to Review", "tray",
                   "Background checks have found nothing that needs your attention. Scan this Mac to check it now.")
        }
        if results.review > 0 {
            return ("Findings Not Listed", "exclamationmark.triangle",
                    "The last scan found \(plural(results.review, "finding", "findings")), but they are not in this list. Scan again, or save the report to see them.")
        }
        // A scan is "partial" whenever it could not read something, which
        // includes the folders macOS protects, so most scans are.
        return results.status == "complete"
            ? ("Nothing to Review", "checkmark.circle",
               "The last scan found nothing that needs your attention. That is not proof this Mac is safe.")
            : ("Nothing Found in What Was Checked", "eye.slash",
               "The last scan could not check everything, and found nothing that needs your attention in what it read. Not Checked lists what it missed.")
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
                TableColumn("Sign-in", value: \.group.title) { (row: StoredRow) in
                    Text(row.group.title).lineLimit(1)
                }
                .width(min: 180, ideal: 300)
                TableColumn("Where", value: \.file.path) { (row: StoredRow) in
                    PathText(path: row.file.path)
                }
                .width(min: 140, ideal: 240)
                TableColumn("About", value: \.about) { (row: StoredRow) in
                    Text(row.file.subject ?? "").foregroundStyle(.secondary).lineLimit(1)
                }
                .width(min: 80, ideal: 150)
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
                            Text("and \(gap.more) more. Save the report for the full list.")
                                .foregroundStyle(.secondary)
                        }
                    } header: {
                        Text("\(gap.label) (\(gap.count))")
                    } footer: {
                        Text(gap.help)
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
                        Text("These folders are not read, so anything in them is not found. They are listed in every report. A folder you include again is read from the next scan on.")
                    }
                }
            }
            .formStyle(.grouped)
        }
    }
}
