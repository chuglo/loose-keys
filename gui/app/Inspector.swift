// The inspector: what the selected finding is, why it matters and what to do.
import SwiftUI

struct Inspector: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        if model.pane == .review, let item = model.currentReview {
            ReviewInspector(item: item)
        } else if model.pane == .stored, let row = model.currentStored {
            StoredInspector(row: row)
        } else {
            ContentUnavailableView {
                Label("No Selection", systemImage: "sidebar.trailing")
            } description: {
                Text(model.pane == .review || model.pane == .stored
                     ? "Select an item to see what it is and what you can do."
                     : "Details of a selected finding appear here.")
            }
        }
    }
}

private struct ReviewInspector: View {
    @EnvironmentObject private var model: AppModel
    let item: ReviewItem

    var body: some View {
        Form {
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Text(item.title).font(.headline)
                    HStack(spacing: 10) {
                        RiskLabel(severity: item.severity)
                        Text(item.statusText).foregroundStyle(.secondary)
                    }
                    .font(.subheadline)
                    // What it concerns, or failing that a count the rule gives, as
                    // for a browser's saved logins.
                    if let about = item.subject ?? item.detail {
                        Text(about).font(.subheadline).foregroundStyle(.secondary)
                    }
                }
                if item.status == "set-aside" {
                    Text("Set aside by you: \(reason?.label ?? "Set aside"). It is still on this Mac and is still counted.")
                        .foregroundStyle(.secondary)
                    if let returns = reason?.returns {
                        Text(returns).foregroundStyle(.secondary)
                    }
                }
                if item.status == "fixed" {
                    Text("This file was checked again and no longer matches. That does not prove the credential was revoked, or that no other copy exists.")
                        .foregroundStyle(.secondary)
                }
            }

            Section("Where") {
                if item.actionable == false {
                    Text(item.path + (item.line.map { ", line \($0)" } ?? ""))
                        .font(.callout.monospaced())
                        .textSelection(.enabled)
                    Text(unusualName).foregroundStyle(.secondary)
                } else {
                    FileRow(path: item.path, line: item.line, index: item.id, review: true)
                }
                if let places = item.places, places.count > 1 {
                    DisclosureGroup("The same credential is in \(plural(places.count, "place", "places"))") {
                        ForEach(places) { place in
                            Text(place.path + (place.fixed ? " (fixed here)" : place.setAside == true ? " (set aside here)" : ""))
                                .font(.callout.monospaced())
                                .textSelection(.enabled)
                        }
                    }
                }
            }

            Section {
                Text(item.nextStep ?? "Confirm why this file is stored here before you change it.")
                StepList(steps: item.steps ?? [])
                if let link = item.link {
                    Button("Open the Page to Revoke It") { model.openLink(link) }
                }
            } header: {
                Text("What to Do")
            } footer: {
                Text("If this belongs to work or you are unsure, ask IT before changing it. This app does not change files or revoke credentials.")
            }

            Section {
                decisions
            } header: {
                Text("Or Decide")
            } footer: {
                Text("An item you set aside is still found and still counted. It only stops asking for attention.")
            }

            // What to do comes first. The reasons and the record stay one press away.
            Section {
                Button(model.inspectorWhy ? "Hide Why It Is Here" : "Show Why It Is Here") {
                    model.inspectorWhy.toggle()
                }
                if model.inspectorWhy {
                    Text(item.explanation)
                    if let reason = item.reason { Text(reason) }
                }
                Button(model.inspectorDetails ? "Hide Details" : "Show Details") {
                    model.inspectorDetails.toggle()
                }
                if model.inspectorDetails {
                    LabeledContent("Rule", value: item.rule)
                    if let seen = item.firstSeen { LabeledContent("First Seen", value: localTime(seen)) }
                    if let fixed = item.resolvedAt { LabeledContent("Fixed", value: localTime(fixed)) }
                }
            }
        }
        .formStyle(.grouped)
    }

    private var reason: SetAsideReason? {
        SetAsideReason.all.first { $0.id == item.setAside }
    }

    /// A folder is left out by itself or along with a folder above it.
    private func folderSkipped(_ folder: String) -> Bool {
        (model.review?.skipped ?? []).contains { folder == $0 || folder.hasPrefix($0 + "/") }
    }

    @ViewBuilder private var decisions: some View {
        if item.status == "set-aside" {
            Button("Show This Again") { model.decide(item, reason: nil) }
        } else if item.status != "fixed" {
            Button(item.deferred ? "Return to Review" : "Remind Me in a Week") { model.remindLater(item) }
            Menu("Set Aside…") {
                ForEach(SetAsideReason.all) { reason in
                    Button(reason.label) { model.decide(item, reason: reason.id) }
                }
            }
            if let folder = item.folder {
                if folderSkipped(folder) {
                    // A folder's name is whatever its maker chose, so it is shown as plain text.
                    Text(verbatim: "\(folder) is no longer checked. Not Checked lists it, and can include it again.")
                        .foregroundStyle(.secondary)
                } else {
                    Button {
                        model.stopCheckingFolder(item)
                    } label: {
                        Text(verbatim: "Stop Checking \(folder)")
                    }
                }
            }
        } else {
            Text("Nothing to decide. It is fixed here.").foregroundStyle(.secondary)
        }
    }
}

private struct StoredInspector: View {
    @EnvironmentObject private var model: AppModel
    let row: StoredRow

    var body: some View {
        Form {
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Text(row.group.title).font(.headline)
                    if let subject = row.file.subject {
                        Text(subject).font(.subheadline).foregroundStyle(.secondary)
                    }
                }
            }
            Section("Where") {
                if row.file.actionable {
                    FileRow(path: row.file.path, line: row.file.line, index: row.file.index, review: false)
                } else {
                    Text(row.file.path).font(.callout.monospaced()).textSelection(.enabled)
                    Text(unusualName).foregroundStyle(.secondary)
                }
            }
            Section("What It Is") {
                Text(row.group.explanation)
                if let reason = row.group.reason { Text(reason) }
            }
            if row.group.nextStep != nil || !row.group.steps.isEmpty {
                Section("What You Can Do") {
                    if let next = row.group.nextStep { Text(next) }
                    StepList(steps: row.group.steps)
                    if let link = row.group.link {
                        Button("Open the Page to Manage It") { model.openLink(link) }
                    }
                }
            }
        }
        .formStyle(.grouped)
    }
}

/// A file's path, with the two things a person does with it.
/// Said in place of Show in Finder and Copy Path, which the engine would refuse.
private let unusualName = "This name has unusual characters, so the app does not act on it."

private struct FileRow: View {
    @EnvironmentObject private var model: AppModel
    let path: String
    let line: Int?
    let index: Int
    let review: Bool

    var body: some View {
        Text(path + (line.map { ", line \($0)" } ?? ""))
            .font(.callout.monospaced())
            .textSelection(.enabled)
        HStack {
            Button("Show in Finder") { model.showInFinder(index, review: review) }
            Button("Copy Path") { model.copyPath(index, review: review) }
        }
    }
}

private struct StepList: View {
    let steps: [String]

    var body: some View {
        ForEach(Array(steps.enumerated()), id: \.offset) { number, step in
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text("\(number + 1).").foregroundStyle(.secondary).monospacedDigit()
                Text(step)
            }
        }
    }
}
