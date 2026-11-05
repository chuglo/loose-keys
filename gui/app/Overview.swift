// The first page: what needs attention, the next step, and automatic scanning.
import SwiftUI

struct OverviewView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        if model.showsWelcome && !model.preparingAccess {
            welcome
        } else {
            Form {
                if let update = model.availableUpdate, let newer = update.newer {
                    Section {
                        LabeledContent {
                            Button("Download") { model.openURL(Releases.page) }
                                .buttonStyle(.borderedProminent)
                        } label: {
                            Text(String(localized: "Loose Keys \(newer) Is Available",
                                        comment: "Overview and the alert after Check for Updates…: a newer version is out. %@ is its version number, such as 0.7.0."))
                            Text(String(localized: "You're using version \(update.current).",
                                        comment: "Overview and the alert after Check for Updates…: the version this app is. %@ is a version number, such as 0.6.0."))
                        }
                    }
                }
                // The answer heads the page, above the counts it comes from.
                Section {
                    results
                } header: {
                    header
                } footer: {
                    resultsFooter
                }
                if !model.preparingAccess && model.phase != .scanning {
                    automatic
                }
            }
            .formStyle(.grouped)
        }
    }

    /// The first page before anything is known to list: one question.
    private var welcome: some View {
        GeometryReader { space in
            ScrollView {
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
                    Text("Loose Keys shows you where they are and how to clean them up.")
                        .font(.title3)
                        .multilineTextAlignment(.center)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: 500)
                        .padding(.bottom, 32)
                    // Each choice says what it does directly beneath it.
                    HStack(alignment: .top, spacing: 16) {
                        choice(caption: String(localized: "Checks whenever your files change.",
                                               comment: "First page, under the Scan Automatically button.")) {
                            Button { model.setMonitoring(enabled: true, paused: false) } label: {
                                Text("Scan Automatically").frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(model.monitorFailure != nil || model.phase == .scanning || model.places?.home == nil)
                        }
                        choice(caption: String(localized: "Checks once, right now.",
                                               comment: "First page, under the Scan Now button.")) {
                            Button { model.startScan() } label: {
                                Text("Scan Now").frame(maxWidth: .infinity)
                            }
                            .disabled(model.places?.home == nil)
                        }
                    }
                    .controlSize(.large)
                    Text("macOS may ask for access to some folders. You can say no and still scan.")
                        .font(.callout)
                        .multilineTextAlignment(.center)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: 440)
                        .padding(.top, 28)
                    if let places = model.places, places.home == nil {
                        Label(Self.cannotScan(places.homeError), systemImage: "exclamationmark.triangle")
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(.top, 12)
                    }
                }
                .padding(.horizontal, 32)
                .padding(.vertical, 40)
                .frame(maxWidth: .infinity, minHeight: space.size.height)
            }
        }
    }

    private func choice<Control: View>(caption: String, @ViewBuilder control: () -> Control) -> some View {
        VStack(spacing: 8) {
            control()
            Text(caption)
                .font(.callout)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(width: 210)
    }

    // MARK: The answer

    /// What needs attention: one title, one line and at most one button. It
    /// never says nothing was found for a list that could not be read.
    @ViewBuilder private var header: some View {
        if model.preparingAccess {
            headerRow(.progress, String(localized: "Preparing Folder Access"),
                      String(localized: "Answer the macOS prompts for Desktop, Documents and Downloads.")) {
                Button("Cancel Preparation") { model.cancelAccessPreparation() }
            }
        } else if model.phase == .scanning {
            headerRow(.progress, String(localized: "Scanning…", comment: "Window subtitle while a scan runs."), progressText) {
                Button("Stop Scan") { model.cancelScan() }
            }
        } else if let problem = model.reviewProblem {
            if let results = model.results {
                // The count is the scan's own when the list cannot be used.
                let line = String(localized: "Loose Keys could not open its saved list, so the Worth Reviewing count is from the last scan.")
                if results.review > 0 {
                    headerRow(.attention, itemsTitle(results.review), line) { reviewButton }
                } else {
                    headerRow(.quiet, String(localized: "Nothing Worth Reviewing",
                                             comment: "Overview title when Worth Reviewing has no item that needs a decision."), line) {}
                }
            } else {
                headerRow(.attention, String(localized: "Cannot Open Worth Reviewing"), problem) {}
            }
        } else if model.review != nil {
            let count = model.reviewCount
            let scanned = model.results.map {
                String(localized: "Last scanned \(localTime($0.generatedAt)).",
                       comment: "Overview, under the number of items worth reviewing. %@ is when the last scan ran, a date and time.")
            }
            if count > 0 {
                headerRow(.attention, itemsTitle(count), scanned ?? String(localized: "From earlier scans.",
                                                                           comment: "Overview, under the number of items worth reviewing, when there has been no scan since the app opened.")) {
                    reviewButton
                }
            } else {
                headerRow(.quiet, emptyTitle, scanned) {}
            }
        } else {
            // The list has not come yet: no title says what it holds.
            ProgressView().controlSize(.small).padding(.vertical, 8)
        }
    }

    /// An empty list that was read. Before anything has been checked it is
    /// not yet an answer, as Worth Reviewing says too. Never "clean": the
    /// counts below say what could not be checked.
    private var emptyTitle: String {
        if model.nothingChecked {
            return String(localized: "No Scan Yet", comment: "A list's heading when it is empty because nothing has been scanned yet.")
        }
        if model.results == nil, let monitor = model.monitor, monitor.enabled, monitor.health.fullPass == nil {
            return String(localized: "No Findings Yet", comment: "Worth Reviewing, empty while automatic scanning has not yet read every file once.")
        }
        return String(localized: "Nothing Worth Reviewing",
                      comment: "Overview title when Worth Reviewing has no item that needs a decision.")
    }

    private enum HeaderSymbol { case progress, attention, quiet }

    private func headerRow<Action: View>(_ symbol: HeaderSymbol, _ title: String, _ line: String?,
                                         @ViewBuilder action: () -> Action) -> some View {
        HStack(spacing: 14) {
            Group {
                switch symbol {
                case .progress:
                    ProgressView()
                case .attention:
                    Image(systemName: "exclamationmark.triangle.fill")
                        .symbolRenderingMode(.palette)
                        .foregroundStyle(.white, .orange)
                case .quiet:
                    Image(systemName: "tray")
                        .foregroundStyle(.secondary)
                }
            }
            .font(.system(size: 34))
            .frame(width: 46)
            .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.title2.weight(.semibold))
                    .foregroundStyle(.primary)
                if let line {
                    Text(line)
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 12)
            action().controlSize(.large)
        }
        .textCase(nil)
        .padding(.top, 6)
        .padding(.bottom, 14)
    }

    private var reviewButton: some View {
        Button("Review Items") { model.pane = .review }
            .buttonStyle(.borderedProminent)
    }

    private func itemsTitle(_ count: Int) -> String {
        String(localized: "\(count) Items Worth Reviewing",
               comment: "Overview title: how many items in Worth Reviewing need a decision. A plural rule.")
    }

    /// How far the scan has got.
    private var progressText: String {
        guard let progress = model.progress else {
            return String(localized: "Starting…", comment: "Overview, while a scan starts and before it says how far it has got.")
        }
        return String(localized: "\(progress.entries) items looked at, \(progress.findings) found.",
                      comment: "Overview, while a scan runs: how many files and folders it has looked at, and how many findings it has found.")
    }

    // MARK: The counts

    @ViewBuilder private var results: some View {
        if !model.preparingAccess && model.phase != .scanning {
            if let places = model.places, places.home == nil {
                Label(Self.cannotScan(places.homeError), systemImage: "exclamationmark.triangle")
            }
            if let results = model.results {
                countRow("Stored Sign-ins", results.stored, "key", .stored)
                countRow("Not Checked", results.notChecked, "eye.slash", .gaps)
            } else {
                LabeledContent {
                    Button("Scan Now") { model.startScan() }
                        .disabled(model.places?.home == nil)
                } label: {
                    Text("Stored sign-ins and places not checked appear after a scan.")
                }
            }
        }
    }

    @ViewBuilder private var resultsFooter: some View {
        if model.results != nil && !model.preparingAccess && model.phase != .scanning {
            VStack(alignment: .leading, spacing: 4) {
                Text("Save the report to keep these details after you quit.")
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

    // MARK: Automatic scanning

    /// The switch Settings has, with the same words beneath it. Pause,
    /// notifications that are off and check timing are in Settings.
    @ViewBuilder private var automatic: some View {
        Section {
            if let monitor = model.monitor {
                Toggle(isOn: Binding(
                    get: { monitor.enabled },
                    set: { model.setMonitoring(enabled: $0, paused: false) })) {
                    Text("Scan Automatically")
                    Text(monitor.enabled ? model.backgroundState.text
                         : String(localized: "Checks your files whenever they change, even when the app is closed.",
                                  comment: "Under the Scan Automatically switch while it is off, and under Automatic Scanning in Overview: what turning it on does."))
                    if monitor.enabled {
                        if model.backgroundState == .active, monitor.health.fullPass == nil {
                            Text("Checking existing files…")
                        }
                        if monitor.login == 3 {
                            Text("Approve Loose Keys in System Settings > General > Login Items.")
                        } else if monitor.login != 2 || monitor.health.running == false {
                            Text("Open Settings to restart the helper.")
                        }
                    }
                    if let unread = monitor.health.unread, unread > 0 {
                        Text(monitor.health.unreadTruncated == true
                             ? String(localized: "At least \(unread) places could not be read.",
                                      comment: "The automatic scan saved only a bounded list of unread places; this is a lower bound.")
                             : String(localized: "\(unread) places could not be read.",
                                      comment: "Overview and Settings, under the state of automatic scanning: how many places the helper's last full pass could not read."))
                    }
                }
                .disabled(model.monitorFailure != nil || (!monitor.enabled && model.places?.home == nil))
                if let unread = monitor.health.unread, unread > 0 {
                    Button("Show Places Not Checked") { model.showUnreadPlaces() }
                }
                // Asked once. After an answer, the switch is in System Settings.
                if monitor.enabled, model.canAskForNotifications {
                    LabeledContent {
                        Button("Allow Notifications…") { model.enableNotifications() }
                            .disabled(model.awaitingPermission)
                    } label: {
                        Text("Notifications")
                        Text(model.review?.permission == "request failed"
                             ? String(localized: "macOS could not show the request. Try again.",
                                      comment: "The state of notifications: macOS could not ask the person whether to allow them.")
                             : String(localized: "Get notified about new findings while the app is closed. Notifications never name a file or credential."))
                    }
                }
                if let error = monitor.error ?? monitor.health.error {
                    Label(EngineText.shown(error), systemImage: "exclamationmark.triangle").foregroundStyle(.red)
                }
            } else {
                LabeledContent("Scan Automatically", value: model.backgroundState.text)
            }
        } footer: {
            HStack {
                Spacer()
                SettingsLink { Text("Settings…") }
            }
        }
    }

    /// Why there is no home folder to scan. The engine's reason, when it
    /// gives one, is shown in the window's language.
    static func cannotScan(_ reason: String?) -> String {
        guard let reason else {
            return String(localized: "Cannot scan: Loose Keys could not find the home folder.", comment: "Overview, when there is no home folder to scan.")
        }
        return String(localized: "Cannot scan: \(EngineText.shown(reason)).",
                      comment: "Overview, when there is no home folder to scan. %@ is the engine's reason, such as that HOME is not set to an absolute path.")
    }
}
