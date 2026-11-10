// The inspector: what the selected finding is, why it matters and what to do.
import SwiftUI

struct Inspector: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        if model.hasInspector, let item = model.currentReview {
            ReviewInspector(item: item)
        } else if model.hasInspector, model.currentReviews.count > 1 {
            Form {
                Section {
                    Text(String(localized: "\(model.currentReviews.count) items selected",
                                comment: "Inspector heading when several findings are selected."))
                    if model.pane == .setAside {
                        // Each moves only the chosen items of its kind.
                        if model.currentReviews.contains(where: { !$0.isStored }) {
                            Button("Move to Worth Reviewing") { model.decideSelection(reason: nil, stored: false) }
                        }
                        if model.currentReviews.contains(where: \.isStored) {
                            Button("Move to Stored Sign-ins") { model.decideSelection(reason: nil, stored: true) }
                        }
                    } else if model.currentReviews.contains(where: { $0.status != "fixed" }) {
                        Menu("Set Aside…") {
                            ForEach(model.setAsideReasons) { reason in
                                Button(reason.label) { model.decideSelection(reason: reason.id) }
                            }
                        }
                    } else {
                        Text("These are fixed, so there's nothing to set aside.")
                    }
                }
                .disabled(model.decidingSelection)
            }
            .formStyle(.grouped)
        } else {
            ContentUnavailableView {
                Label("No Selection", systemImage: "sidebar.trailing")
            } description: {
                Text("Select an item to see what it is and what you can do.")
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
                    // Stored Sign-ins has no Risk column, and lists only what is open.
                    if !item.isStored {
                        HStack(spacing: 10) {
                            RiskLabel(severity: item.severity)
                            if item.status != "set-aside" {
                                Text(item.statusText).foregroundStyle(.secondary)
                            }
                        }
                        .font(.subheadline)
                    }
                    // What it concerns, or failing that a count the rule gives, as
                    // for a browser's saved logins.
                    if let about = item.shownAbout {
                        Text(about).font(.subheadline).foregroundStyle(.secondary)
                    }
                }
                if item.status == "fixed" {
                    Text("Loose Keys no longer finds this in the file. That doesn't mean the credential was revoked, or that no other copy exists.")
                        .foregroundStyle(.secondary)
                }
                // At the top, so it is in view without scrolling past what to do.
                if item.status == "open" {
                    decisions.disabled(model.decidingSelection)
                }
            }

            if item.status == "set-aside" {
                Section {
                    let summary = reason?.summary ?? String(localized: "You set this aside",
                                                            comment: "Inspector, Set Aside section, for a finding set aside for a reason this version of the app does not know.")
                    if let at = item.setAsideAt {
                        LabeledContent(summary, value: localDay(at))
                    } else {
                        Text(summary)
                    }
                    Button(item.isStored ? "Move to Stored Sign-ins" : "Move to Worth Reviewing") { model.decide(item, reason: nil) }
                        .disabled(model.decidingSelection)
                } header: {
                    Text("Set Aside")
                }
            }

            Section("Where") {
                if !item.actionable {
                    Text(pathAndLine(item.path, item.line))
                        .font(.callout.monospaced())
                        .textSelection(.enabled)
                    Text(unusualName).foregroundStyle(.secondary)
                } else {
                    FileRow(path: item.path, line: item.line, id: item.id)
                }
                let locations = item.locations
                if locations.count > 1 {
                    Text(String(localized: "The same credential is in \(locations.count) places",
                                comment: "Inspector, the heading over the list of files one credential was found in."))
                    Button(model.inspectorCopies ? "Hide Copies" : "Show Copies") {
                        model.inspectorCopies.toggle()
                    }
                    if model.inspectorCopies {
                        ForEach(item.otherLocations) { place in
                            // A path is whatever the file's maker chose, so it is shown as plain text.
                            Text(place.fixed
                                 ? String(localized: "\(place.path) (fixed here)",
                                          comment: "Inspector, one of the files the same credential is in: this file no longer has it. %@ is the file's path, shown as it is.")
                                 : place.setAside
                                 ? String(localized: "\(place.path) (set aside here)",
                                          comment: "Inspector, one of the files the same credential is in: the person set the credential aside in this file. %@ is the file's path, shown as it is.")
                                 : place.path)
                                .font(.callout.monospaced())
                                .textSelection(.enabled)
                            if place.actionable {
                                FileActions(id: place.id)
                            } else {
                                Text(unusualName).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }

            if item.isStored {
                storedAdvice
            } else if item.status != "set-aside" {
                Section {
                    Text(item.nextStep.map(EngineText.shown)
                         ?? String(localized: "Find out why this file is here before you change it.",
                                   comment: "Inspector, under What to Do, for a finding whose rule gives no next step."))
                    StepList(steps: item.steps)
                    if let link = item.link {
                        Button("Open the Page to Revoke It") { model.openLink(link) }
                    }
                } header: {
                    Text("What to Do")
                } footer: {
                    Text("If this is for work, or you aren't sure, ask IT before changing it.")
                }
            }

            if item.status != "set-aside", !item.isStored {
                if item.status != "fixed", let folder = item.folder {
                    Section {
                        if folderSkipped(folder) {
                            // A folder's name is whatever its maker chose, so it is shown as plain text.
                            Text(verbatim: String(localized: "Scans will skip \(folder). You can include it again in Settings.",
                                                  comment: "Inspector, Folder section. %@ is a folder's path, shown as it is. Settings is the app's Settings window, where Places to Check lists the folder."))
                                .foregroundStyle(.secondary)
                        } else {
                            Button {
                                model.stopCheckingFolder(item)
                            } label: {
                                Text(verbatim: String(localized: "Stop Checking \(folder)",
                                                      comment: "Inspector, Folder section: a button that leaves a folder out of scans. %@ is the folder's path, shown as it is."))
                            }
                        }
                    } header: {
                        Text("Folder")
                    } footer: {
                        Text(FolderScopeText.exceptions)
                    }
                }
            }

            // What to do comes first. The reasons and the record stay one press away.
            Section {
                // A stored sign-in's explanation is under What It Is.
                if !item.isStored {
                    Button(model.inspectorWhy ? "Hide Explanation" : "Show Explanation") {
                        model.inspectorWhy.toggle()
                    }
                    if model.inspectorWhy {
                        Text(EngineText.shown(item.explanation))
                        if let reason = item.reason { Text(EngineText.shown(reason)) }
                    }
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
        let known = item.isStored ? [SetAsideReason.storedKept, SetAsideReason.storedExpected]
            : SetAsideReason.all + [SetAsideReason.legacy, SetAsideReason.expected]
        return known.first { $0.id == item.setAside }
    }

    /// What a stored sign-in is, and what can be done about it. Apps keep
    /// these files on purpose, so this says how to manage the sign-in, not
    /// how to revoke it.
    @ViewBuilder private var storedAdvice: some View {
        Section("What It Is") {
            Text(EngineText.shown(item.explanation))
            if let reason = item.reason { Text(EngineText.shown(reason)) }
        }
        if item.status != "set-aside", item.nextStep != nil || !item.steps.isEmpty || item.link != nil {
            Section("What You Can Do") {
                if let next = item.nextStep { Text(EngineText.shown(next)) }
                StepList(steps: item.steps)
                if let link = item.link {
                    Button("Open the Page to Manage It") { model.openLink(link) }
                }
            }
        }
    }

    /// A folder is left out by itself or along with a folder above it.
    private func folderSkipped(_ folder: String) -> Bool {
        (model.review?.skipped ?? []).contains { folder == $0 || folder.hasPrefix($0 + "/") }
    }

    private var decisions: some View {
        Menu {
            ForEach(item.isStored ? [SetAsideReason.storedKept] : SetAsideReason.all) { reason in
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

/// Said in place of Show in Finder and Copy Path, which the engine would refuse.
private let unusualName = String(localized: "This name has unusual characters, so Loose Keys won't open or copy it.",
                                 comment: "Inspector, under a file's path, in place of Show in Finder and Copy Path.")

/// A file's path, and the line in it when the rule gives one. The path is
/// whatever the file's maker chose: it is shown as it is, as plain text.
private func pathAndLine(_ path: String, _ line: Int?) -> String {
    guard let line else { return path }
    return String(localized: "\(path), line \(line)", comment: "Inspector: a file's path and a line number in it. %@ is the path, shown as it is.")
}

/// A file's path, with the two things a person does with it.
private struct FileRow: View {
    let path: String
    let line: Int?
    let id: ReviewItem.ID

    var body: some View {
        Text(pathAndLine(path, line))
            .font(.callout.monospaced())
            .textSelection(.enabled)
        FileActions(id: id)
    }
}

private struct FileActions: View {
    @EnvironmentObject private var model: AppModel
    let id: ReviewItem.ID

    var body: some View {
        HStack {
            Button("Show in Finder") { model.showInFinder(id) }
                .accessibilityIdentifier("show-file-review-\(id)")
            Button("Copy Path") { model.copyPath(id) }
                .accessibilityIdentifier("copy-path-review-\(id)")
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
