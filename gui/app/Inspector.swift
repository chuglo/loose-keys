// The inspector: what the selected finding is, why it matters and what to do.
import SwiftUI

struct Inspector: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        if model.pane == .review || model.pane == .setAside, let item = model.currentReview {
            ReviewInspector(item: item)
        } else if (model.pane == .review || model.pane == .setAside), model.currentReviews.count > 1 {
            Form {
                Section {
                    Text(String(localized: "\(model.currentReviews.count) items selected",
                                comment: "Inspector heading when several findings are selected."))
                    if model.pane == .setAside {
                        Button("Move to Worth Reviewing") { model.decideSelection(reason: nil) }
                    } else if model.currentReviews.contains(where: { $0.status != "fixed" }) {
                        Menu("Set Aside…") {
                            ForEach(SetAsideReason.all) { reason in
                                Button(reason.label) { model.decideSelection(reason: reason.id) }
                            }
                        }
                    } else {
                        Text("It is fixed here, so there is nothing to set aside.")
                    }
                }
                .disabled(model.decidingSelection)
            }
            .formStyle(.grouped)
        } else if model.pane == .stored, let row = model.currentStored {
            StoredInspector(row: row)
        } else {
            ContentUnavailableView {
                Label("No Selection", systemImage: "sidebar.trailing")
            } description: {
                Text(model.pane == .review || model.pane == .setAside || model.pane == .stored
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
                    Text(item.shownTitle).font(.headline)
                    HStack(spacing: 10) {
                        RiskLabel(severity: item.severity)
                        if item.status != "set-aside" {
                            Text(item.statusText).foregroundStyle(.secondary)
                        }
                    }
                    .font(.subheadline)
                    // What it concerns, or failing that a count the rule gives, as
                    // for a browser's saved logins.
                    if let about = item.shownAbout {
                        Text(about).font(.subheadline).foregroundStyle(.secondary)
                    }
                }
                if item.status == "fixed" {
                    Text("This file was checked again and no longer matches. That does not prove the credential was revoked, or that no other copy exists.")
                        .foregroundStyle(.secondary)
                }
                // At the top, so it is in view without scrolling past what to do.
                if item.status == "open" {
                    decisions.disabled(model.decidingSelection)
                }
            }

            if item.status == "set-aside" {
                Section {
                    let summary = reason?.summary ?? String(localized: "Set aside by you",
                                                            comment: "Inspector, Set Aside section, for a finding set aside for a reason this version of the app does not know.")
                    if let at = item.setAsideAt {
                        LabeledContent(summary, value: localDay(at))
                    } else {
                        Text(summary)
                    }
                    Button("Move to Worth Reviewing") { model.decide(item, reason: nil) }
                        .disabled(model.decidingSelection)
                } header: {
                    Text("Set Aside")
                }
            }

            Section("Where") {
                if item.actionable == false {
                    Text(pathAndLine(item.path, item.line))
                        .font(.callout.monospaced())
                        .textSelection(.enabled)
                    Text(unusualName).foregroundStyle(.secondary)
                } else {
                    FileRow(path: item.path, line: item.line, index: item.id, review: true)
                }
                if let places = item.places, places.count > 1 {
                    DisclosureGroup(String(localized: "The same credential is in \(places.count) places",
                                           comment: "Inspector, the heading over the list of files one credential was found in.")) {
                        ForEach(places) { place in
                            // A path is whatever the file's maker chose, so it is shown as plain text.
                            Text(place.fixed
                                 ? String(localized: "\(place.path) (fixed here)",
                                          comment: "Inspector, one of the files the same credential is in: this file no longer has it. %@ is the file's path, shown as it is.")
                                 : place.setAside == true
                                 ? String(localized: "\(place.path) (set aside here)",
                                          comment: "Inspector, one of the files the same credential is in: the person set the credential aside in this file. %@ is the file's path, shown as it is.")
                                 : place.path)
                                .font(.callout.monospaced())
                                .textSelection(.enabled)
                        }
                    }
                }
            }

            if item.status != "set-aside" {
                Section {
                    Text(item.nextStep.map(EngineText.shown)
                         ?? String(localized: "Confirm why this file is stored here before you change it.",
                                   comment: "Inspector, under What to Do, for a finding whose rule gives no next step."))
                    StepList(steps: item.steps ?? [])
                    if let link = item.link {
                        Button("Open the Page to Revoke It") { model.openLink(link) }
                    }
                } header: {
                    Text("What to Do")
                } footer: {
                    Text("If this belongs to work or you are unsure, ask IT before changing it. This app does not change files or revoke credentials.")
                }
            }

            if item.status != "set-aside" {
                if item.status != "fixed", let folder = item.folder {
                    Section("Folder") {
                        if folderSkipped(folder) {
                            // A folder's name is whatever its maker chose, so it is shown as plain text.
                            Text(verbatim: String(localized: "\(folder) is no longer checked. Not Checked lists it, and can include it again.",
                                                  comment: "Inspector, Folder section. %@ is a folder's path, shown as it is. Not Checked is the page's name."))
                                .foregroundStyle(.secondary)
                        } else {
                            Button {
                                model.stopCheckingFolder(item)
                            } label: {
                                Text(verbatim: String(localized: "Stop Checking \(folder)",
                                                      comment: "Inspector, Folder section: a button that leaves a folder out of scans. %@ is the folder's path, shown as it is."))
                            }
                        }
                    }
                }
            }

            // What to do comes first. The reasons and the record stay one press away.
            Section {
                Button(model.inspectorWhy ? "Hide Why It Is Here" : "Show Why It Is Here") {
                    model.inspectorWhy.toggle()
                }
                if model.inspectorWhy {
                    Text(EngineText.shown(item.explanation))
                    if let reason = item.reason { Text(EngineText.shown(reason)) }
                }
                Button(model.inspectorDetails ? "Hide Details" : "Show Details") {
                    model.inspectorDetails.toggle()
                }
                if model.inspectorDetails {
                    if item.status == "set-aside", let returns = reason?.returns {
                        Text(returns).font(.callout).foregroundStyle(.secondary)
                    }
                    LabeledContent("Rule", value: item.rule)
                    if let seen = item.firstSeen { LabeledContent("First Seen", value: localTime(seen)) }
                    if let fixed = item.resolvedAt {
                        LabeledContent(String(localized: "date.fixed", defaultValue: "Fixed",
                                              comment: "Inspector, under Show Details: the label beside the date and time the finding was found to be fixed."),
                                       value: localTime(fixed))
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    private var reason: SetAsideReason? {
        (SetAsideReason.all + [SetAsideReason.legacy]).first { $0.id == item.setAside }
    }

    /// A folder is left out by itself or along with a folder above it.
    private func folderSkipped(_ folder: String) -> Bool {
        (model.review?.skipped ?? []).contains { folder == $0 || folder.hasPrefix($0 + "/") }
    }

    private var decisions: some View {
        Menu {
            ForEach(SetAsideReason.all) { reason in
                Button(reason.label) { model.decide(item, reason: reason.id) }
            }
        } label: {
            HStack(spacing: 6) {
                Text("Set Aside…")
                Image(systemName: "chevron.down").imageScale(.small)
            }
        }
        .menuIndicator(.hidden)
        .menuStyle(.button)
        .buttonStyle(.bordered)
        .fixedSize()
    }
}

private struct StoredInspector: View {
    @EnvironmentObject private var model: AppModel
    let row: StoredRow

    var body: some View {
        Form {
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Text(row.shownTitle).font(.headline)
                    if let subject = row.file.subject {
                        Text(EngineText.about(subject)).font(.subheadline).foregroundStyle(.secondary)
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
                Text(EngineText.shown(row.group.explanation))
                if let reason = row.group.reason { Text(EngineText.shown(reason)) }
            }
            if row.group.nextStep != nil || !row.group.steps.isEmpty {
                Section("What You Can Do") {
                    if let next = row.group.nextStep { Text(EngineText.shown(next)) }
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
private let unusualName = String(localized: "This name has unusual characters, so the app does not act on it.",
                                 comment: "Inspector, under a file's path, in place of Show in Finder and Copy Path.")

/// A file's path, and the line in it when the rule gives one. The path is
/// whatever the file's maker chose: it is shown as it is, as plain text.
private func pathAndLine(_ path: String, _ line: Int?) -> String {
    guard let line else { return path }
    return String(localized: "\(path), line \(line)", comment: "Inspector: a file's path and a line number in it. %@ is the path, shown as it is.")
}

private struct FileRow: View {
    @EnvironmentObject private var model: AppModel
    let path: String
    let line: Int?
    let index: Int
    let review: Bool

    var body: some View {
        Text(pathAndLine(path, line))
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
                Text(verbatim: "\(number + 1).").foregroundStyle(.secondary).monospacedDigit()
                Text(EngineText.shown(step))
            }
        }
    }
}
