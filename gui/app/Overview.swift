// The first page: start ongoing checks, follow the helper, and review findings.
import SwiftUI

struct OverviewView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Form {
            if model.preparingAccess {
                Section("Preparing Folder Access") {
                    ProgressView()
                    Text("macOS may ask to access Desktop, Documents and Downloads so Loose Keys can check them for exposed credentials. Denied folders will appear under Not Checked after checking finishes.")
                    Text("Answer any open macOS prompt to continue. Other protected locations may ask later.")
                        .foregroundStyle(.secondary)
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

            if !model.showsWelcome {
                scope
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
                Text("Loose Keys checks your home folder for supported passwords, keys, tokens and other sign-in material, and says how to remove each exposure.")
                    .font(.title3)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 460)
                    .padding(.bottom, 28)
                // One width for both buttons, so they read as a pair of choices.
                VStack(spacing: 10) {
                    Button { model.setMonitoring(enabled: true, paused: false) } label: {
                        Text("Enable Background Checks").frame(maxWidth: .infinity)
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
                Text("Before checking starts, macOS may ask for folder access. You can deny access and continue; those folders will be listed as not checked.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 460)
                    .padding(.top, 12)
                if let places = model.places, places.home == nil {
                    Label("Cannot scan: \(places.homeError ?? "the home folder was not found").", systemImage: "exclamationmark.triangle")
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.top, 12)
                }
                Label {
                    Text("Background checks start at login and keep running after you quit. They store paths and keyed fingerprints, never secret values. Nothing leaves this Mac.")
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

    @ViewBuilder private var scope: some View {
        Section {
            Button(model.overviewScope ? "Hide What a Scan Checks" : "Show What a Scan Checks") {
                model.overviewScope.toggle()
            }
            if model.overviewScope {
                Text("Supported passwords, keys, tokens and other sign-in material in your home folder, and in folders you add for one-time scans.")
                    .foregroundStyle(.secondary)
                checked("Passwords", "Export files left on disk, and passwords saved in browsers.", "lock.doc")
                checked("Keys and Tokens", "Private keys without a passphrase, and service tokens in a known format near the start of a file.", "key")
                checked("Developer and AI Tools", "Cloud, package and AI tool sign-ins, and secrets in settings files.", "terminal")
                Text("A scan checks files. It does not check browser cookies or the Keychain. You can also run a one-time scan from the command line.")
                    .font(.callout).foregroundStyle(.secondary)
                if let results = model.results {
                    LabeledContent("Always Skipped") {
                        Text(results.excluded.joined(separator: ", "))
                            .font(.callout.monospaced())
                            .textSelection(.enabled)
                    }
                    Text(results.limitations).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                }
                Button(model.overviewRules ? "Hide Every Rule" : "Show Every Rule") {
                    model.overviewRules.toggle()
                }
                if model.overviewRules {
                    Text(model.rules.isEmpty ? "Loading…" : model.rules)
                        .font(.callout.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                Text("Version \(model.results?.toolVersion ?? model.version ?? appVersion).")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    private var appVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""
    }

    private func checked(_ title: String, _ text: String, _ symbol: String) -> some View {
        Label {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(text).font(.callout).foregroundStyle(.secondary)
            }
        } icon: {
            Image(systemName: symbol).foregroundStyle(.secondary)
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

    private var progressText: String {
        guard let progress = model.progress else { return "Starting…" }
        let phase = progress.phase == "targeted-checks" ? "Checking known sign-in locations"
            : progress.phase == "finished" ? "Preparing results" : "Looking through folders"
        return "\(phase). \(plural(progress.entries, "item", "items")) looked at, \(progress.findings) found."
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
                Text(verbatim: "Included: \(results.roots.joined(separator: ", ")).")
                let skipped = model.review?.skipped?.count ?? 0
                if skipped > 0 {
                    Text("\(plural(skipped, "folder is", "folders are")) left out at your request; see Not Checked.")
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

    private func countRow(_ title: String, _ count: Int, _ symbol: String, _ pane: Pane) -> some View {
        Button {
            model.pane = pane
        } label: {
            HStack {
                Label(title, systemImage: symbol)
                Spacer()
                Text("\(count)").monospacedDigit().foregroundStyle(.secondary)
                Image(systemName: "chevron.right").font(.footnote.weight(.semibold)).foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(title)
        .accessibilityValue("\(count)")
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
                    Label("Cannot scan: \(places.homeError ?? "the home folder was not found").", systemImage: "exclamationmark.triangle")
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
            Text("Background checks watch your home folder. Added folders and drives are included only in one-time scans.")
        }
    }

    /// Each row is a title, what it means beneath, and its control at the
    /// side, as in System Settings, so that no button stands alone.
    @ViewBuilder private var background: some View {
        Section {
            if let monitor = model.monitor, !monitor.enabled {
                LabeledContent {
                    Button("Enable Background Checks") { model.setMonitoring(enabled: true, paused: false) }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.monitorFailure != nil || model.phase == .scanning || model.places?.home == nil)
                } label: {
                    Text("Background Checks")
                    Text("Allow a helper to check files at low priority, start at login and keep running after you quit this app. It stores paths and keyed fingerprints locally, never secret values.")
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
                    Text("Background Checks")
                    Text(model.backgroundState)
                    if let monitor = model.monitor {
                        if model.backgroundState == "Active", monitor.health.fullPass == nil {
                            Text("Checking existing files…")
                        }
                        if let unread = monitor.health.unread, unread > 0 {
                            Text("\(plural(unread, "place was", "places were")) not read during background checks. Run a one-time scan for details.")
                        }
                        if monitor.login == 3 {
                            Text("Approve the helper in System Settings > General > Login Items.")
                        } else if monitor.login != 2 || monitor.health.running == false {
                            Text("Open Settings to start the helper. If it is registered but not running, use Stop Helper, then Start Helper.")
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
                Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.red)
            }
            if let problem = model.reviewProblem {
                Label("Review List Unavailable: \(problem)", systemImage: "exclamationmark.triangle")
            } else if model.review != nil, model.results == nil || model.phase == .scanning {
                // After a scan, the scan's own section has this row.
                countRow("Worth Reviewing", model.reviewCount, "exclamationmark.triangle", .review)
            }
        } footer: {
            HStack(alignment: .firstTextBaseline) {
                Text("Nothing leaves this Mac. Files are only read, never changed.")
                Spacer()
                SettingsLink { Text("Settings…") }
            }
        }
    }
}
