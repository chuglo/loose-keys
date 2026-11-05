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
                // The answer heads the page. Under it, only what the person
                // can act on: a folder to allow again, or why no scan can run.
                // What a scan found is in the sidebar.
                Section {
                    blocked
                    unscannable
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

    /// The first page before anything is known to list: one button, Scan Now.
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
                    // One step: an answer first. Scan Automatically is offered
                    // on the Overview, under what the scan found.
                    Button { model.startScan() } label: {
                        Text("Scan Now").frame(width: 210)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(model.places?.home == nil)
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
            // When the findings were last looked for: this window's scan, else
            // the helper's last check. "From earlier scans." only when neither.
            let scanned = model.results.map {
                String(localized: "Last scanned \(localTime($0.generatedAt)).",
                       comment: "Overview, under the number of items worth reviewing. %@ is when the last scan ran, a date and time.")
            } ?? model.lastChecked
            if model.helperFirstPass {
                // The helper's first pass takes minutes: say it is still going.
                if count > 0 {
                    headerRow(.attention, itemsTitle(count), String(localized: "Still checking your files…",
                                                                    comment: "Overview, under the number of items worth reviewing, while automatic scanning reads every file for the first time.")) {
                        reviewButton
                    }
                } else {
                    headerRow(.progress, String(localized: "Checking Your Files…",
                                                comment: "Overview title while automatic scanning reads every file for the first time and has found nothing yet."),
                              String(localized: "Findings appear here as they turn up.",
                                     comment: "Overview, under Checking Your Files…")) {}
                }
            } else if count > 0 {
                headerRow(.attention, itemsTitle(count), scanned ?? String(localized: "From earlier scans.",
                                                                           comment: "Overview, under the number of items worth reviewing, when nothing has been checked since the app opened.")) {
                    reviewButton
                }
            } else {
                // An empty list never reads as clean when a place went unread.
                let unread = model.nothingChecked || !model.somePlacesNotChecked ? nil : NotCheckedText.some
                let line = [scanned, unread].compactMap { $0 }.joined(separator: " ")
                headerRow(.quiet, emptyTitle, line.isEmpty ? nil : line) {}
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

    // MARK: Under the answer

    @ViewBuilder private var unscannable: some View {
        if !model.preparingAccess && model.phase != .scanning, let places = model.places, places.home == nil {
            Label(Self.cannotScan(places.homeError), systemImage: "exclamationmark.triangle")
        }
    }

    /// Each folder macOS kept from the last scan, with the place to allow it.
    @ViewBuilder private var blocked: some View {
        ForEach(model.blockedFolders, id: \.self) { folder in
            LabeledContent {
                Button("Open System Settings") { model.openFilesAndFoldersSettings() }
            } label: {
                Text(String(localized: "\(Self.folderName(folder)) Wasn't Checked",
                            comment: "Overview: macOS didn't let the last scan read this folder. %@ is the folder's name: Desktop, Documents or Downloads, as Finder shows it."))
                Text("Allow access in System Settings, then scan again.")
            }
        }
    }

    /// The name Finder shows for one of the folders macOS asks about.
    static func folderName(_ folder: String) -> String {
        switch folder {
        case "Desktop":
            return String(localized: "Desktop", comment: "The Desktop folder's name, as Finder shows it.")
        case "Documents":
            return String(localized: "Documents", comment: "The Documents folder's name, as Finder shows it.")
        case "Downloads":
            return String(localized: "Downloads", comment: "The Downloads folder's name, as Finder shows it.")
        default:
            return folder
        }
    }

    @ViewBuilder private var resultsFooter: some View {
        // That a manual scan's details last only until quitting is said on
        // Stored Sign-ins, where they are missed, not here.
        if !model.preparingAccess && model.phase != .scanning && (model.findingsNote != nil || model.somePlacesNotChecked) {
            VStack(alignment: .leading, spacing: 4) {
                if let note = model.findingsNote {
                    Text(note)
                }
                // The one way to the list. It has no count: nearly every Mac
                // has places macOS keeps private.
                if model.somePlacesNotChecked {
                    Button("Show Places Not Checked") { model.showingPlaces = true }
                        .buttonStyle(.link)
                        .popover(isPresented: $model.showingPlaces, arrowEdge: .bottom) {
                            PlacesNotChecked().environmentObject(model)
                        }
                }
            }
        }
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
                        } else if model.backgroundState == .helperNotRunning {
                            Text("Open Settings to restart the helper.")
                        }
                    }
                }
                .disabled(model.monitorFailure != nil || (!monitor.enabled && model.places?.home == nil))
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
