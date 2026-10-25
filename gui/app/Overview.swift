// The first page: start ongoing checks, follow the helper, and review findings.
import SwiftUI

struct OverviewView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Form {
            if model.preparingAccess {
                Section("Preparing Folder Access") {
                    ProgressView()
                    Text("Answer the macOS prompts for Desktop, Documents and Downloads.")
                    Button("Cancel Preparation") { model.cancelAccessPreparation() }
                }
            } else if model.showsWelcome {
                welcome
            } else {
                background

                if model.phase == .scanning {
                    scanning
                } else if let results = model.results {
                    summary(results)
                } else {
                    Section {
                        LabeledContent {
                            Button("Scan Now") { model.startScan() }
                                .disabled(model.places?.home == nil)
                        } label: {
                            Text("One-Time Scan")
                            Text("Check now for a detailed report, including places that could not be read.")
                        }
                    }
                }
            }
            // The first page's question stands alone. Folders added by dropping
            // them on it are listed, so that they can be removed.
            if !model.showsWelcome || model.places?.extra.isEmpty == false {
                folders
            }
        }
        .formStyle(.grouped)
        .dropDestination(for: URL.self) { folders, _ in
            model.addFolders(folders)
            return !folders.isEmpty
        }
    }

    /// The first page before anything is known to list: one question.
    @ViewBuilder private var welcome: some View {
        Section {
            VStack(spacing: 0) {
                Image(systemName: "key.fill")
                    .font(.system(size: 52))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(.tint)
                    .accessibilityHidden(true)
                    .padding(.bottom, 20)
                Text("Find Passwords and Keys Left in Files")
                    .font(.title.weight(.semibold))
                    .multilineTextAlignment(.center)
                    .padding(.bottom, 8)
                Text("Loose Keys checks your files for supported passwords, keys, tokens and other sign-in material, and says how to remove each exposure.")
                    .font(.title3)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 460)
                    .padding(.bottom, 28)
                // One width for both buttons, so they read as a pair of choices.
                VStack(spacing: 10) {
                    Button { model.setMonitoring(enabled: true, paused: false) } label: {
                        Text("Scan Automatically").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.monitorFailure != nil || model.phase == .scanning || model.places?.home == nil)
                    Button { model.startScan() } label: {
                        Text("Scan Now").frame(maxWidth: .infinity)
                    }
                    .disabled(model.places?.home == nil)
                }
                .controlSize(.large)
                .frame(width: 260)
                Text("macOS may ask for folder access. You can deny it and continue.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 460)
                    .padding(.top, 12)
                if let places = model.places, places.home == nil {
                    Label(cannotScan(places.homeError), systemImage: "exclamationmark.triangle")
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.top, 12)
                }
                Label {
                    Text("Scan Automatically checks your files whenever they change, even when the app is closed.")
                        .fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "lock.shield")
                }
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 460)
                .padding(.top, 24)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 36)
        }
    }

    @ViewBuilder private var scanning: some View {
        Section {
            VStack(alignment: .leading, spacing: 8) {
                ProgressView().progressViewStyle(.linear)
                Text(progressText).foregroundStyle(.secondary)
                if let started = model.started {
                    Text(started, style: .timer).monospacedDigit().foregroundStyle(.secondary)
                }
            }
            .padding(.vertical, 4)
            Button("Stop Scan") { model.cancelScan() }
        } header: {
            Text("Scanning")
        } footer: {
            Text("A scan stops by itself after 30 seconds, once the file it is reading is finished. What it did not reach is listed under Not Checked.")
        }
    }

    /// Why there is no home folder to scan. The engine's reason, when it
    /// gives one, is shown in the window's language.
    private func cannotScan(_ reason: String?) -> String {
        guard let reason else {
            return String(localized: "Cannot scan: the home folder was not found.", comment: "Overview, when there is no home folder to scan.")
        }
        return String(localized: "Cannot scan: \(EngineText.shown(reason)).",
                      comment: "Overview, when there is no home folder to scan. %@ is the engine's reason, such as that HOME is not set to an absolute path.")
    }

    /// Two sentences: what the scan is doing, then how far it has got.
    private var progressText: String {
        guard let progress = model.progress else {
            return String(localized: "Starting…", comment: "Overview, while a scan starts and before it says how far it has got.")
        }
        let phase = progress.phase == "targeted-checks"
            ? String(localized: "Checking known sign-in locations.", comment: "Overview, while a scan reads the places where apps are known to keep sign-ins. A sentence of progress follows.")
            : progress.phase == "finished"
            ? String(localized: "Preparing results.", comment: "Overview, while a scan that has read everything prepares its results. A sentence of progress follows.")
            : String(localized: "Looking through folders.", comment: "Overview, while a scan looks through folders. A sentence of progress follows.")
        let counts = String(localized: "\(progress.entries) items looked at, \(progress.findings) found.",
                            comment: "Overview, while a scan runs: how many files and folders it has looked at, and how many findings it has found.")
        return phase + " " + counts
    }

    @ViewBuilder private func summary(_ results: ScanResults) -> some View {
        Section {
            // The same number the list shows: one credential in several files is one item.
            countRow("Worth Reviewing", model.reviewCount, "exclamationmark.triangle", .review)
            countRow("Stored Sign-ins", results.stored, "key", .stored)
            countRow("Not Checked", results.notChecked, "eye.slash", .gaps)
        } header: {
            Text(results.status == "complete" ? "Last Scan: Complete" : "Last Scan: Incomplete")
        } footer: {
            VStack(alignment: .leading, spacing: 4) {
                Text(results.status == "complete"
                     ? "Scanned \(localTime(results.generatedAt))."
                     : "Scanned \(localTime(results.generatedAt)). Some places could not be checked; see Not Checked.")
                // What the counts cover, which Places to Check may no longer be.
                Text(verbatim: String(localized: "Included: \(results.roots.joined(separator: ", ")).",
                                      comment: "Overview, under the last scan's counts. %@ is the list of folders the scan covered, separated by commas, shown as they are."))
                let skipped = model.review?.skipped?.count ?? 0
                if skipped > 0 {
                    Text(String(localized: "\(skipped) folders are left out at your request; see Not Checked.",
                                comment: "Overview, under the last scan's counts: how many folders the person chose to stop checking. Not Checked is the page's name."))
                }
                if model.reviewProblem != nil {
                    Text("The review list could not be read or saved, so Worth Reviewing shows the scan's own count.")
                }
                if let note = model.findingsNote {
                    Text(note)
                }
            }
        }
    }

    private func countRow(_ title: LocalizedStringKey, _ count: Int, _ symbol: String, _ pane: Pane) -> some View {
        Button {
            model.pane = pane
        } label: {
            HStack {
                Label(title, systemImage: symbol)
                Spacer()
                Text(verbatim: "\(count)").monospacedDigit().foregroundStyle(.secondary)
                Image(systemName: "chevron.right").font(.footnote.weight(.semibold)).foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(Text(title))
        .accessibilityValue(Text(verbatim: "\(count)"))
    }

    @ViewBuilder private var folders: some View {
        Section {
            if let places = model.places {
                if let home = places.home {
                    LabeledContent {
                        Text("Always included").foregroundStyle(.secondary)
                    } label: {
                        Label(home, systemImage: "house")
                    }
                } else {
                    Label(cannotScan(places.homeError), systemImage: "exclamationmark.triangle")
                }
                ForEach(Array(places.extra.enumerated()), id: \.offset) { index, folder in
                    LabeledContent {
                        Button("Remove") { model.removeFolder(index, shown: folder) }
                    } label: {
                        Label(folder, systemImage: "folder")
                    }
                }
            }
            Button("Add Folder or Drive…") { model.addFolder() }
        } header: {
            Text("Places to Check")
        } footer: {
            Text("Automatic scanning does not include added folders and drives. Use Scan Now to check them.")
        }
    }

    /// Each row is a title, what it means beneath, and its control at the
    /// side, as in System Settings, so that no button stands alone.
    @ViewBuilder private var background: some View {
        Section {
            if let monitor = model.monitor, !monitor.enabled {
                LabeledContent {
                    Button("Turn On") { model.setMonitoring(enabled: true, paused: false) }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.monitorFailure != nil || model.phase == .scanning || model.places?.home == nil)
                } label: {
                    Text("Automatic Scanning")
                    Text("Checks your files whenever they change, even when the app is closed.")
                }
            } else {
                LabeledContent {
                    if let monitor = model.monitor {
                        HStack {
                            Button(model.overviewCheckDetails ? "Hide Details" : "Show Details") {
                                model.overviewCheckDetails.toggle()
                            }
                            Button(monitor.paused ? "Resume" : "Pause") {
                                model.setMonitoring(enabled: true, paused: !monitor.paused)
                            }
                            .disabled(model.monitorFailure != nil || model.phase == .scanning)
                        }
                    }
                } label: {
                    Text("Automatic Scanning")
                    Text(model.backgroundState.text)
                    if let monitor = model.monitor {
                        if model.backgroundState == .active, monitor.health.fullPass == nil {
                            Text("Checking existing files…")
                        }
                        if let unread = monitor.health.unread, unread > 0 {
                            Text(String(localized: "\(unread) places could not be read. Run a scan to see which.",
                                        comment: "Overview and Settings, under the state of automatic scanning: how many places the helper's last full pass could not read."))
                        }
                        if monitor.login == 3 {
                            Text("Approve the helper in System Settings > General > Login Items.")
                        } else if monitor.login != 2 || monitor.health.running == false {
                            Text("Open Settings to restart the helper.")
                        }
                    }
                }
                if let monitor = model.monitor {
                    if model.overviewCheckDetails {
                        BackgroundCheckDetails(health: monitor.health)
                    }
                    if model.review?.permission != "allowed" {
                        LabeledContent {
                            if model.canAskForNotifications {
                                Button("Allow Notifications…") { model.enableNotifications() }
                                    .disabled(model.awaitingPermission)
                            } else if model.review?.permission == "denied" {
                                Button("Open System Settings") { model.openNotificationSettings() }
                            }
                        } label: {
                            Text("Notifications")
                            switch model.review?.permission {
                            case "denied":
                                Text("Off for Loose Keys. Turn them on in System Settings to hear about new findings when the app is closed.")
                            case "request failed":
                                Text("macOS could not ask. Try again.")
                            default:
                                Text("Hear about new findings when the app is closed. Alerts never name a file or credential.")
                            }
                        }
                    }
                }
            }
            if let error = model.monitor.flatMap({ $0.error ?? $0.health.error }) {
                Label(EngineText.shown(error), systemImage: "exclamationmark.triangle").foregroundStyle(.red)
            }
            if let problem = model.reviewProblem {
                Label(String(localized: "Review List Unavailable: \(problem)",
                             comment: "Overview, when the list of findings could not be read or saved. %@ is the reason, one or more sentences from the engine or macOS."),
                      systemImage: "exclamationmark.triangle")
            } else if model.review != nil, model.results == nil || model.phase == .scanning {
                // After a scan, the scan's own section has this row.
                countRow("Worth Reviewing", model.reviewCount, "exclamationmark.triangle", .review)
            }
        } footer: {
            HStack(alignment: .firstTextBaseline) {
                Text("Files are only read, never changed.")
                Spacer()
                SettingsLink { Text("Settings…") }
            }
        }
    }
}
