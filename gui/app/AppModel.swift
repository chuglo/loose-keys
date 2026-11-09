// Everything the window shows, and every action it can take.
import AppKit
import ServiceManagement
import SwiftUI
import UniformTypeIdentifiers

enum Pane: String, Hashable {
    case overview, review, stored, setAside
}

enum Phase {
    case ready, scanning, done
}

/// What the menu bar icon shows. No count: the menu has it. `full` is a
/// list that left findings out, whatever is open on it.
enum MenuBarMark {
    case unknown, open, plain, problem, full
}

/// What automatic scanning is doing, as Overview, Settings and the menu bar
/// say it. Logic and tests compare the case, never its words.
enum BackgroundState {
    case unavailable, off, needsApproval, starting, helperNotRunning, waitingForHelper, paused, needsAttention, active

    var text: String {
        switch self {
        case .starting:
            return String(localized: "background.starting", defaultValue: "Starting…",
                          comment: "The state of automatic scanning (a singular noun), in Overview, Settings and the menu bar: just turned on, while its helper starts.")
        case .unavailable:
            return String(localized: "background.unavailable", defaultValue: "Unavailable",
                          comment: "The state of automatic scanning (a singular noun), in Overview, Settings and the menu bar: the window could not get its status.")
        case .off:
            return String(localized: "background.off", defaultValue: "Off",
                          comment: "The state of automatic scanning (a singular noun), in Overview, Settings and the menu bar: turned off.")
        case .needsApproval:
            return String(localized: "Needs macOS Approval",
                          comment: "The state of automatic scanning (a singular noun), in Overview, Settings and the menu bar: its helper waits for the person to approve it in System Settings.")
        case .helperNotRunning:
            return String(localized: "Helper Not Running",
                          comment: "The state of automatic scanning, in Overview, Settings and the menu bar: the helper program that runs it is not running.")
        case .waitingForHelper:
            return String(localized: "Waiting for Helper Status",
                          comment: "The state of automatic scanning, in Overview, Settings and the menu bar: the helper is registered, and has not yet said whether it runs.")
        case .paused:
            return String(localized: "background.paused", defaultValue: "Paused",
                          comment: "The state of automatic scanning (a singular noun), in Overview, Settings and the menu bar: the person paused it.")
        case .needsAttention:
            return String(localized: "Needs Attention",
                          comment: "The state of automatic scanning (a singular noun), in Overview, Settings and the menu bar: the helper reported a problem, shown below it.")
        case .active:
            return String(localized: "background.active", defaultValue: "Active",
                          comment: "The state of automatic scanning (a singular noun), in Overview, Settings and the menu bar: on and running.")
        }
    }
}

/// The order in which the window asked for the folders it shows. Engine calls
/// run off the main thread and their answers come back in any order, so an
/// answer is used only when no later request's has been: neither an older
/// list nor an older failure then replaces what a newer answer showed.
struct RequestOrder {
    private var asked = 0
    private var used = 0

    mutating func next() -> Int {
        asked += 1
        return asked
    }

    /// Whether no answer to a later request has been used.
    func isNewest(_ request: Int) -> Bool {
        request > used
    }

    /// Whether to use the answer to this request. Once it is, the answer to
    /// an earlier request is not.
    mutating func use(_ request: Int) -> Bool {
        guard isNewest(request) else { return false }
        used = request
        return true
    }
}

/// Where the person took an action, so that what goes wrong with it is shown
/// there.
enum ActionOrigin {
    /// The main window.
    case window
    case settings
    /// The menu bar icon, which has no window of its own.
    case menuBar
}

/// What Check for Updates… found, for its alert.
enum UpdateResult: Equatable {
    case newer(ReleaseCheck)
    case upToDate(ReleaseCheck)
    /// Why the check failed, in the window's language.
    case failed(String)
}

/// Reads of one thing the window shows and the helper can change: the review
/// list, background status, or saved automatic coverage. Only one of each
/// is out at a time, so
/// answers are shown in the order the engine read them. A number for each
/// request was not enough: of two calls out together, the one asked for later
/// could read first, and what the other then read, the newest, was put aside.
@MainActor
final class ReadTurns {
    private var asked = 0
    /// How many requests had been made when the read now out, or the last one, began.
    private var began = 0
    private var answered = 0
    /// The newest request that asked for a failure to be shown in an alert.
    private var alertAsked = 0
    /// The newest request a read has shown an answer for: what it read, or
    /// why it failed. A failure left to the read that follows shows none.
    private var shown = 0
    private var reading: Task<Void, Never>?

    /// Whether a request has been made since the read now out began. Its
    /// answer is then not the last word: another read follows it.
    var askedAgain: Bool { asked > began }

    /// Returns once a read that began after this request has been shown.
    /// Requests made while a read is out share the one read that follows it.
    /// The read is told whether a failure is shown in an alert: whether any
    /// request it answers for asked, including one whose failed read left
    /// its answer to this one. It returns false when it leaves its answer to
    /// the read that follows.
    func run(alert: Bool = false, _ read: @escaping @MainActor (_ alert: Bool) async -> Bool) async {
        // The counts keep their order only on the main actor. Checked in
        // builds without optimization, such as the model check.
        MainActor.assertIsolated("ReadTurns runs on the main actor")
        asked += 1
        let mine = asked
        if alert { alertAsked = mine }
        while answered < mine {
            if reading == nil {
                began = asked
                let covers = began
                let alerts = alertAsked > shown
                reading = Task {
                    if await read(alerts) { self.shown = covers }
                    self.answered = covers
                    self.reading = nil
                }
            }
            await reading?.value
        }
    }
}

@MainActor
final class AppModel: ObservableObject {
    let engine: Engine
    private let sleep: @MainActor (UInt64) async throws -> Void

    @Published var pane: Pane? = .overview {
        didSet {
            if pane != oldValue { paneChanged = Date() }
            if Self.list(pane) != Self.list(oldValue) { dropHiddenSelection() }
        }
    }
    private var paneChanged = Date.distantPast
    /// Whether this page has been showing for a moment. Leaving a list closes
    /// the inspector, and the window reports that close a little later, by
    /// which time the page may be a list again.
    var paneSettled: Bool { Date().timeIntervalSince(paneChanged) > 1 }
    private var inspectorPressed = Date.distantPast
    /// The toolbar's Inspector button. The window reports the end of a hide a
    /// little later as well, and by then the button may have been pressed
    /// again.
    func toggleInspector() {
        inspectorShown.toggle()
        inspectorPressed = Date()
    }
    var inspectorSettled: Bool { Date().timeIntervalSince(inspectorPressed) > 1 }
    @Published var places: ScanPlaces?
    /// Why the folders shown may not be the ones saved: the window couldn't
    /// get the list, or the engine couldn't read its saved state. In the
    /// window's language.
    @Published var placesProblem: String?
    @Published var results: ScanResults?
    @Published var review: ReviewList?
    /// Why the last request for the review list failed, if it did. `review`
    /// is then an older list, or none.
    @Published var reviewUnread: String?
    @Published var monitor: MonitorStatus?
    /// Why the last request for the status of background checks failed, if
    /// it did. `monitor` is then none.
    @Published var monitorUnread: String?
    @Published var inspectorWhy = false
    @Published var inspectorDetails = false
    @Published var inspectorCopies = false
    /// The sidebar as the person left it. The first page hides it until there
    /// is something to list, unless the person has opened it or used it since.
    @Published var columns = NavigationSplitViewVisibility.automatic
    @Published var sidebarAsked = false
    @Published var phase = Phase.ready
    @Published var preparingAccess = false
    private var accessCancelled = false
    @Published var progress: ScanProgress?
    @Published var started: Date?
    @Published var selectedReviews: Set<ReviewItem.ID> = [] {
        didSet {
            if selectedReviews != oldValue, pane == .review || pane == .setAside || pane == .stored {
                showInspectorForSelection(!selectedReviews.isEmpty)
            }
        }
    }
    /// Single-item callers and the inspector never pick an arbitrary member.
    var selectedReview: ReviewItem.ID? {
        get { selectedReviews.count == 1 ? selectedReviews.first : nil }
        set { selectedReviews = newValue.map { [$0] } ?? [] }
    }
    @Published private(set) var decidingSelection = false
    /// The column headings each list is sorted by, the last one clicked first.
    /// Status is where the review list starts: open first, then by risk.
    /// Stored Sign-ins has its own, since it has neither column.
    @Published var reviewSort = [KeyPathComparator(\ReviewItem.statusRank)]
    @Published var storedSort: [KeyPathComparator<ReviewItem>] = []
    @Published var search = "" {
        didSet { dropHiddenSelection() }
    }
    @Published var inspectorShown = false

    /// Keep space for the list until a selection needs details. Like the
    /// toolbar, this can outrun the window's report of an earlier close.
    private func showInspectorForSelection(_ shown: Bool) {
        inspectorShown = shown
        inspectorPressed = Date()
    }
    /// A problem to show in an alert on the main window.
    @Published var failure: Failure?
    /// What went wrong with an action taken in Settings, for an alert there.
    @Published var settingsFailure: Failure?
    /// Whether Settings is open, as Settings itself says.
    var settingsOpen = false
    /// A short confirmation, shown under the window title.
    @Published var notice: String?
    private var decisionTurn = 0
    @Published var awaitingPermission = false
    /// macOS answered no to the request the person just made with Set Up
    /// Notifications…, until it says anything else.
    @Published var notificationsTurnedDown = false
    private var placesOrder = RequestOrder()
    private let reviewReads = ReadTurns()
    private let monitorReads = ReadTurns()
    private let coverageReads = ReadTurns()
    @Published var automaticCoverage: AutomaticCoverage?
    @Published var automaticCoverageError: String?
    /// The Overview's list of places not checked, in a popover.
    @Published var showingPlaces = false
    private var backgroundUpdates: Task<Void, Never>?
    /// How often `backgroundUpdates` reads, if it runs.
    private var pollInterval: UInt64?
    private var active = false
    private var quitting = false
    /// Show in Menu Bar, as the engine last said or as the person last set
    /// it. A failed read leaves it as it was: the app is never left running
    /// with no icon and no window.
    @Published private(set) var menuBarOn = false {
        didSet {
            // Out of the menu bar with no window open, the app has nothing
            // left to show: it quits, as when its last window closes.
            if oldValue, !menuBarOn, let app = NSApp, !Self.windowOpen(in: app.windows) {
                app.terminate(nil)
            }
        }
    }
    /// macOS opened the app at login, in the menu bar and with no window.
    /// Over once the person opens the window, Settings or a menu.
    var quietLaunch = false {
        didSet { if quietLaunch { menuBarOn = true } }
    }
    /// Opens the main window, captured from a view that can.
    var openMainWindow: () -> Void = {
        for window in NSApp?.windows ?? [] where window.canBecomeMain { window.makeKeyAndOrderFront(nil) }
    }
    #if PREVIEW || SNAPSHOTS
    /// Opens the Settings window, for the picture-taking code.
    var openSettings: () -> Void = {}
    #endif

    init(engine: Engine, releases: ReleaseSource = NoReleases(), now: @escaping @MainActor () -> Date = { Date() },
         sleep: @escaping @MainActor (UInt64) async throws -> Void = {
        try await Task.sleep(nanoseconds: $0)
    }) {
        self.sleep = sleep
        self.engine = engine
        self.releases = releases
        self.now = now
    }

    // MARK: Checking for a newer version

    private let releases: ReleaseSource
    /// The wall clock, which runs on while the Mac sleeps, unlike `sleep`'s.
    private let now: @MainActor () -> Date
    /// A newer release than this one, for Overview, from the last check that
    /// could tell.
    @Published private(set) var availableUpdate: ReleaseCheck?
    /// Check for Updates… is running.
    @Published private(set) var checkingUpdates = false
    /// What Check for Updates… found, until its alert is closed.
    @Published var updateResult: UpdateResult?
    /// Off in the picture-taking build, whose pictures show no question.
    var asksAboutUpdates = true
    /// The first-open question was answered in this launch, even if saving
    /// the answer failed: then it is asked again at a later launch.
    private var updatesAnswered = false
    /// The automatic checks: one now, then one a day.
    private var updateChecks: Task<Void, Never>?
    /// What the last status read that worked said: whether the question was
    /// answered, and whether the helper has finished a full pass. A read that
    /// fails for a moment then neither asks nor takes the question away.
    @Published private var updateQuestionAnswered: Bool?
    @Published private var helperPassDone = false

    /// Whether to ask if the app may check for updates: never asked, and the
    /// answer can be saved. Not while the app is only in the menu bar, and
    /// not at first start: only once a scan has an answer, this window's or
    /// the helper's first full pass, and none is running.
    var shouldAskAboutUpdates: Bool {
        guard asksAboutUpdates, !updatesAnswered, !quietLaunch, updateQuestionAnswered == false,
              monitorFailure == nil, results != nil || helperPassDone,
              phase != .scanning, !preparingAccess else { return false }
        return true
    }

    func answerUpdateQuestion(_ on: Bool) {
        updatesAnswered = true
        setUpdateCheck(on)
    }

    func setUpdateCheck(_ on: Bool, from origin: ActionOrigin = .window) {
        Task {
            do {
                try await engine.send("set_update_check", ["enabled": on])
            } catch {
                report(error.localizedDescription, title: FailureTitle.updateChecks, from: origin)
            }
            await refreshMonitor()
        }
    }

    /// Check for Updates…: one check, whatever the setting, with an alert.
    /// The alert is on the main window, which comes up with it: the command
    /// is in the app menu also while only Settings is open, and the window
    /// can be closed while the check runs.
    func checkForUpdates() {
        guard !checkingUpdates else { return }
        checkingUpdates = true
        Task {
            do {
                let release = try await latestRelease()
                if release.newer != nil {
                    availableUpdate = release
                    updateResult = .newer(release)
                } else {
                    availableUpdate = nil
                    updateResult = .upToDate(release)
                }
            } catch {
                updateResult = .failed(error.localizedDescription)
            }
            checkingUpdates = false
            showWindow(review: false)
        }
    }

    /// GitHub's reply, as the engine reads it.
    private func latestRelease() async throws -> ReleaseCheck {
        let data = try await releases.latest()
        guard let body = String(data: data, encoding: .utf8) else {
            throw EngineError(message: String(localized: "Loose Keys couldn't read GitHub's response. Try again later.",
                                              comment: "In an alert after Check for Updates…: GitHub's reply was too long or came from somewhere else."))
        }
        return try await engine.request("check_release", ["body": body])
    }

    /// Starts or stops the automatic checks as the saved answer says. Turned
    /// off, they also take their notice away. A check that fails shows
    /// nothing and waits for the next day.
    private func followUpdateSetting(_ on: Bool) {
        guard on, !quitting else {
            if let checks = updateChecks {
                checks.cancel()
                updateChecks = nil
                availableUpdate = nil
            }
            return
        }
        guard updateChecks == nil else { return }
        // `sleep` stops while the Mac sleeps, so a day of it can be several
        // days. The checks look every hour and go by the wall clock.
        updateChecks = Task {
            var due = now()
            while !Task.isCancelled {
                if now() >= due {
                    due = now().addingTimeInterval(Releases.interval)
                    if let release = try? await latestRelease(), !Task.isCancelled {
                        availableUpdate = release.newer == nil ? nil : release
                    }
                }
                do { try await sleep(Releases.look) } catch { return }
            }
        }
    }

    /// Opens a page outside the app. The window check records it instead, so
    /// that a press there opens nothing on the Mac running the check.
    var openURL: (URL) -> Void = { _ = NSWorkspace.shared.open($0) }

    // MARK: What the lists show

    /// The list a page shows: Set Aside, Stored Sign-ins, or Worth Reviewing
    /// for every other page, where the Filter field opens it.
    private static func list(_ pane: Pane?) -> Pane {
        pane == .setAside || pane == .stored ? pane ?? .review : .review
    }

    /// Decisions change which page lists an item, never the findings held or
    /// exported. Set Aside lists both kinds.
    var reviewPaneItems: [ReviewItem] {
        (review?.items ?? []).filter { item in
            switch Self.list(pane) {
            case .setAside: return item.status == "set-aside"
            case .stored: return item.isStored && item.status == "open"
            default: return !item.isStored && item.status != "set-aside"
            }
        }
    }

    /// Whether the Filter field's text is in these texts, taken together:
    /// what a row shows, then the engine's English. Case and accents are
    /// ignored, because a word is often typed without its accents.
    private func leaves(_ wanted: String, _ texts: [String?]) -> Bool {
        wanted.isEmpty || texts.compactMap { $0 }.joined(separator: " ")
            .range(of: wanted, options: [.caseInsensitive, .diacriticInsensitive]) != nil
    }

    /// The findings the filter leaves, not yet in order. Enough to find one
    /// of them, which the filter does for each character typed.
    private var reviewShown: [ReviewItem] {
        let wanted = search.trimmingCharacters(in: .whitespaces)
        return reviewPaneItems.filter {
            leaves(wanted, [$0.shownTitle, $0.path, $0.subject.map(EngineText.about), $0.detail.map(EngineText.about),
                            $0.title, $0.subject, $0.detail])
                || ($0.places ?? []).contains { leaves(wanted, [$0.path]) }
        }
    }

    /// Secondary paths that explain why this group matches the Filter field.
    func matchingReviewPaths(_ item: ReviewItem) -> [String] {
        let wanted = search.trimmingCharacters(in: .whitespaces)
        guard !wanted.isEmpty else { return [] }
        return Set((item.places ?? []).filter {
            $0.path != item.path && leaves(wanted, [$0.path])
        }.map(\.path)).sorted()
    }

    var reviewRows: [ReviewItem] {
        // Until a heading is clicked, and for rows the clicked headings rank
        // the same, sign-ins with one title are together.
        guard pane != .stored else {
            return arranged(reviewShown, by: storedSort) { ($0.shownTitle, $0.id) < ($1.shownTitle, $1.id) }
        }
        return arranged(reviewShown, by: reviewSort) { ($0.order, $0.id) < ($1.order, $1.id) }
    }

    /// Filtered rows out of the usable list, never a scan or error count.
    var filterSummary: String? {
        guard !search.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        let shown: Int
        let total: Int
        switch pane {
        case .review, .setAside, .stored:
            guard review != nil, reviewProblem == nil else { return nil }
            shown = reviewShown.count
            total = reviewPaneItems.count
        default:
            return nil
        }
        guard total > 0 else { return nil }
        return String(localized: "Showing \(shown) of \(total) items",
                      comment: "Filtered list: the number of matching rows followed by the total rows on this page, including fixed findings.")
    }

    var filterHasNoMatches: Bool {
        guard filterSummary != nil else { return false }
        return reviewShown.isEmpty
    }

    var openCount: Int {
        review?.counts?.open ?? (review?.items.filter { !$0.isStored && $0.status == "open" }.count ?? 0)
    }

    /// The number beside Stored Sign-ins. When the list cannot be used it is
    /// the last scan's own count, as for Worth Reviewing.
    var storedCount: Int {
        guard reviewProblem == nil else { return results?.stored ?? 0 }
        return review?.counts?.stored ?? (review?.items.filter { $0.isStored && $0.status == "open" }.count ?? 0)
    }

    /// Why Stored Sign-ins is empty, when it is and its list can be used.
    enum StoredEmpty: Equatable {
        case allSetAside
        /// The last scan found this many, and the list doesn't hold them.
        case notListed(Int)
        /// No scan has looked for every stored sign-in since they were saved.
        case notLookedYet
        case none
    }

    /// A scan this session that counted sign-ins comes before whether one
    /// was recorded as looking: an older helper saves the list without them.
    /// Those saved and since no longer found account for the scan's count.
    var storedEmpty: StoredEmpty {
        if setAside(stored: true) > 0 { return .allSetAside }
        if let found = results?.stored, found > review?.counts?.storedGone ?? 0 { return .notListed(found) }
        if review?.storedChecked != true { return .notLookedYet }
        return .none
    }

    /// Both kinds. No count while the list cannot be used: a scan knows
    /// nothing of decisions, so it has no Set Aside count to fall back on.
    var setAsideCount: Int {
        setAside(stored: false) + setAside(stored: true)
    }

    /// Of one kind: what is worth reviewing, or stored sign-ins.
    func setAside(stored: Bool) -> Int {
        guard reviewProblem == nil else { return 0 }
        let counted = stored ? review?.counts?.storedSetAside : review?.counts?.setAside
        return counted ?? (review?.items.filter { $0.isStored == stored && $0.status == "set-aside" }.count ?? 0)
    }

    /// Why Worth Reviewing cannot show what was found, when it cannot: the
    /// engine could not read or save the list, or this window could not get
    /// it. Whatever list the window holds is then not shown or counted. The
    /// reason is in the window's language.
    var reviewProblem: String? {
        reviewUnread ?? review?.error.map(EngineText.shown)
    }

    /// The number beside Worth Reviewing. When the list cannot be used it is
    /// the last scan's own count, so that a failure never reads as nothing
    /// found.
    var reviewCount: Int {
        reviewProblem == nil ? openCount : (results?.review ?? 0)
    }

    /// Says that the list is full, when that is why it is shorter than the
    /// scan's count. A list is also shorter because it has one item for a
    /// credential however many rules or files found it; that needs nothing
    /// done, so the Overview leaves it out. A full list left findings out for
    /// lack of room, and only the saved report has them all.
    var findingsNote: String? {
        guard let found = results?.review, let review, reviewProblem == nil, review.full == true else { return nil }
        let listed = review.items.filter { !$0.isStored && $0.status != "fixed" }.count
        guard found > listed else { return nil }
        return String(localized: "The scan found \(found) findings, but the list is full at \(listed) items. Save the report to see them all.",
                      comment: "Overview, under the last scan's counts, when the Worth Reviewing list is full. The first number counts findings, the second the list's items.")
    }

    var currentReviews: [ReviewItem] {
        guard reviewProblem == nil else { return [] }
        return reviewRows.filter { selectedReviews.contains($0.id) }
    }

    /// Capture displayed revisions before starting. Stop on the first refusal;
    /// earlier saves remain saved and the ordered refresh shows that progress.
    /// `stored` keeps to one kind, for a Set Aside selection of both.
    func decideSelection(reason: String?, stored: Bool? = nil) {
        guard !decidingSelection else { return }
        let items = currentReviews.filter { $0.status != "fixed" && (stored == nil || $0.isStored == stored) }
        guard !items.isEmpty else { return }
        decisionTurn += 1
        decidingSelection = true
        Task {
            defer { decidingSelection = false }
            var problem: String?
            do {
                for item in items {
                    try await engine.send("decide_review", drawn(item).merging(["reason": reason ?? NSNull()]) { $1 })
                }
            } catch { problem = error.localizedDescription }
            await refreshReview()
            if let problem { failure = Failure(title: FailureTitle.saveChoice, reason: problem) }
        }
    }

    var currentReview: ReviewItem? {
        // A list that cannot be used is not shown, so none of its items is the
        // current one. After a failed read or save the engine would refuse a
        // decision on any of them.
        guard reviewProblem == nil else { return nil }
        return reviewShown.first { $0.id == selectedReview }
    }

    /// The entry with this id, or the one a copy with this id belongs to. A
    /// credential in several files is one entry, named by a copy that still
    /// needs a decision, so a decision or a fix can change the entry's id.
    func reviewEntry(_ id: ReviewItem.ID) -> ReviewItem? {
        let items = review?.items ?? []
        return items.first { $0.id == id } ?? items.first { $0.places?.contains { $0.id == id } == true }
    }

    /// A row the filter hides is no longer selected. Done as the filter
    /// changes, before the table is next drawn, so that the table is not left
    /// to change the selection in the middle of updating its rows.
    private func dropHiddenSelection() {
        // Against what the filter leaves, not the current finding: no finding
        // is current while the list cannot be used, and the choice is kept then.
        selectedReviews.formIntersection(reviewShown.map(\.id))
    }

    var menuBarMark: MenuBarMark {
        if reviewProblem != nil { return .problem }
        guard let review else { return .unknown }
        if review.full == true { return .full }
        return openCount > 0 ? .open : .plain
    }

    /// The menu's first line: fixed words and a count, never a path or a name.
    var menuBarLine: String {
        switch menuBarMark {
        case .plain where nothingChecked:
            return backgroundState == .active
                ? String(localized: "Checking your files…",
                         comment: "The menu bar menu's first line while automatic scanning reads every file for the first time, as the Overview's heading says it.")
                : String(localized: "No scan this session",
                         comment: "The menu bar menu's first line when the list is empty and nothing has been checked since the app opened: no scan, and no check by the helper.")
        case .open, .plain:
            return String(localized: "\(openCount) loose keys to review",
                          comment: "The menu bar menu's first line: how many findings in Worth Reviewing need the person's attention. A loose key is a credential left in a plain file.")
        case .full:
            return String(localized: "\(openCount) loose keys to review, list full",
                          comment: "The menu bar menu's first line: how many findings need attention, when the list is full and left some out.")
        case .problem:
            return String(localized: "Couldn't open Worth Reviewing",
                          comment: "The menu bar menu's first line when the list could not be read. Worth Reviewing is the list's name in the sidebar.")
        case .unknown:
            return String(localized: "Loading Worth Reviewing…",
                          comment: "The menu bar menu's first line while the list is being read. Worth Reviewing is the list's name in the sidebar.")
        }
    }

    /// Unless automatic scanning is known to be running, the state Settings shows for it.
    var menuBarCheckLine: String? {
        backgroundState == .active ? nil
            : String(localized: "Automatic scanning: \(backgroundState.text)",
                     comment: "The menu bar menu's second line: the state of automatic scanning, as Settings shows it.")
    }

    /// Nothing looks cleaner than it is: everything set aside or skipped is counted.
    var reviewSummary: String {
        guard reviewProblem == nil, let counts = review?.counts else { return "" }
        var parts = [String(localized: "\(counts.open) to review",
                            comment: "Part of the Worth Reviewing subtitle, joined to the others by commas: how many findings still need the person's attention.")]
        if counts.setAside > 0 {
            parts.append(String(localized: "\(counts.setAside) set aside",
                                comment: "Part of the Worth Reviewing subtitle, joined to the others by commas: how many findings the person set aside."))
        }
        if counts.fixed > 0 {
            parts.append(String(localized: "\(counts.fixed) fixed",
                                comment: "Part of the Worth Reviewing subtitle, joined to the others by commas: how many findings are no longer in their files."))
        }
        if review?.full == true {
            parts.append(String(localized: "list full, so some findings are missing",
                                comment: "Last part of the Worth Reviewing subtitle, after the counts and a comma: the list had no room for some findings."))
        }
        return parts.joined(separator: ", ")
    }

    // MARK: Starting up, and events

    /// Called before launch finishes, so a notification click that opened the
    /// app is delivered to an engine that is already listening.
    func start(reviewRoute: Bool) {
        engine.start(reviewRoute: reviewRoute) { [weak self] name, payload in
            Task { @MainActor in self?.handle(name, payload) }
        }
        if reviewRoute { pane = .review }
        // The list first, so the first review list drawn already has it.
        Task {
            await syncExpected()
            await refresh()
        }
    }

    /// The organization's expected findings, from a managed preference only:
    /// a value macOS does not mark as forced may come from a file in the
    /// home folder, and is not read. Nothing forced means nothing is listed,
    /// and the engine drops what it had. An entry that is not a dictionary
    /// with string rule and path is left out; the rest are sent.
    func syncExpected() async {
        #if !PREVIEW
        let key = "ExpectedFindings" as CFString
        let domain = "dev.loosekeys.desktop" as CFString
        var entries: [[String: String]] = []
        if CFPreferencesAppValueIsForced(key, domain),
           let listed = CFPreferencesCopyAppValue(key, domain) as? [Any] {
            entries = listed.compactMap { entry in
                guard let entry = entry as? [String: Any],
                      let rule = entry["rule"] as? String,
                      let path = entry["path"] as? String else { return nil }
                return ["rule": rule, "path": path]
            }
        }
        try? await engine.send("set_expected", ["entries": entries])
        #endif
    }

    /// The helper may have found something while the window was in the background.
    func becameActive() {
        Task { await syncExpected() }
        // Notifications may have been allowed or blocked in System Settings
        // meanwhile. While macOS is asking, its answer is on the way.
        if !active, !awaitingPermission {
            Task { try? await engine.send("refresh_notifications") }
        }
        active = true
        updatePolling()
    }

    func becameInactive() {
        active = false
        updatePolling()
    }

    /// Every 5 seconds while the app is in front, every 30 behind it when
    /// the menu bar shows the list, and otherwise not at all. A loop is
    /// replaced only when its interval changes.
    private func updatePolling() {
        let interval: UInt64? = quitting ? nil
            : active ? 5_000_000_000
            : menuBarOn ? 30_000_000_000 : nil
        guard interval != pollInterval else { return }
        backgroundUpdates?.cancel()
        backgroundUpdates = nil
        pollInterval = interval
        guard let interval else { return }
        backgroundUpdates = Task {
            while !Task.isCancelled {
                if phase != .scanning {
                    await refreshReview(reportFailure: false)
                    guard !Task.isCancelled else { return }
                    await refreshMonitor()
                }
                // Await each pair before sleeping: a busy store never builds
                // up a queue of polling tasks. These calls read state only.
                do { try await sleep(interval) }
                catch { return }
            }
        }
    }

    func refresh() async {
        await refreshPlaces(reportFailure: true)
        await refreshReview()
        await refreshMonitor()
    }

    /// The folders scans include, as the engine reads them after this was
    /// asked. Read at launch, when Settings opens, and before a scan when
    /// they couldn't be read.
    func refreshPlaces(reportFailure: Bool = false) async {
        let request = placesOrder.next()
        do {
            let answer: ScanPlaces = try await engine.request("places")
            guard placesOrder.use(request) else { return }
            places = answer
            placesProblem = answer.error.map(EngineText.shown)
        } catch {
            // The folders already shown stay, and so may a change still on its
            // way: a list that could not be got is not an empty one.
            guard placesOrder.use(request) else { return }
            placesProblem = error.localizedDescription
            if reportFailure { failure = Failure(title: FailureTitle.readPlaces, reason: error.localizedDescription) }
        }
    }

    /// The list as the engine reads it after this was asked. Only these reads
    /// take turns: a scan, Stop and every other command go to the engine at once.
    /// A read shared with a request that asked for an alert shows its failure in one.
    func refreshReview(reportFailure: Bool = true) async {
        await reviewReads.run(alert: reportFailure) { [self] alert in
            do {
                let answer: ReviewList = try await engine.request("pending_review")
                review = answer
                reviewUnread = nil
                // The chosen row may be back under another copy's id. It stays chosen.
                selectedReviews = Set(selectedReviews.map { reviewEntry($0)?.id ?? $0 })
                if reviewProblem == nil { dropHiddenSelection() }
            } catch {
                // The read that follows a request made since answers for this
                // one. Until it does, the last list read stays as it was.
                guard !reviewReads.askedAgain else { return false }
                reviewUnread = error.localizedDescription
                // Automatic refresh failures stay visible in the list without
                // reopening a modal alert every five seconds.
                if alert {
                    let title = pane == .stored ? FailureTitle.openStored : FailureTitle.openReview
                    failure = Failure(title: title, reason: error.localizedDescription)
                }
            }
            return true
        }
    }

    func refreshMonitor() async {
        await monitorReads.run { [self] _ in
            do {
                let answer: MonitorStatus = try await engine.request("monitor_status")
                monitor = answer
                monitorUnread = nil
                menuBarOn = answer.menuBar
                followUpdateSetting(answer.updateCheck == true)
                updateQuestionAnswered = answer.updateCheck != nil
                if answer.health.fullPass != nil { helperPassDone = true }
                if showingPlaces,
                   automaticCoverage == nil || automaticCoverageError != nil
                    || automaticCoverage?.fullPass != answer.health.fullPass {
                    await refreshAutomaticCoverage()
                }
            } catch {
                guard !monitorReads.askedAgain else { return false }
                // None when the request failed: the window then says the checks are
                // unavailable, and why, not what an older status said of them.
                monitor = nil
                monitorUnread = error.localizedDescription
            }
            updatePolling()
            // The engine keeps the last scan this process ran, for a window opened after it.
            if results == nil, phase == .ready, let held = monitor?.results {
                results = held
            }
            return true
        }
    }

    func refreshAutomaticCoverage() async {
        await coverageReads.run { [self] _ in
            do {
                automaticCoverage = try await engine.request("automatic_coverage")
                automaticCoverageError = nil
            } catch {
                guard !coverageReads.askedAgain else { return false }
                automaticCoverageError = error.localizedDescription
            }
            return true
        }
    }

    private func handle(_ name: String, _ payload: Data) {
        switch name {
        case "scan-progress":
            if phase == .scanning { progress = try? decodeEngine(ScanProgress.self, from: payload) }
        case "open-review":
            // A notification was clicked: bring the window forward on what it was about.
            showWindow(review: true)
            Task {
                await refreshReview()
                selectedReview = review?.items.filter { !$0.isStored && $0.status == "open" }
                    .max { ($0.revision ?? 0) < ($1.revision ?? 0) }?.id
            }
        case "review-ready":
            Task { await refreshReview() }
        case "monitor-status":
            Task { await refreshMonitor(); await refreshReview() }
        case "notification-permission":
            let asked = awaitingPermission
            awaitingPermission = false
            Task {
                await refreshReview()
                // Asked about them, macOS said no, which it also says to a
                // prompt that was missed: the Overview keeps saying so, with
                // the way to turn them on.
                if asked, review?.permission == "denied" { notificationsTurnedDown = true }
                await refreshMonitor()
            }
        default:
            break
        }
    }

    /// Whether a window the person can come back to is open: a minimized
    /// one too. `closing` is one about to go.
    static func windowOpen(in windows: [NSWindow], except closing: Int? = nil) -> Bool {
        windows.contains { window in
            window.windowNumber != closing && (window.isVisible || window.isMiniaturized)
                && window.styleMask.contains(.titled)
        }
    }

    /// In front with a Dock icon, for a window the person asked for.
    func comeForward() {
        quietLaunch = false
        // None in the model check, which runs no app.
        guard let app = NSApp else { return }
        app.setActivationPolicy(.regular)
        app.activate(ignoringOtherApps: true)
    }

    /// The window in front, with a Dock icon while it is open.
    func showWindow(review: Bool) {
        comeForward()
        for window in NSApp?.windows ?? [] where window.isMiniaturized { window.deminiaturize(nil) }
        openMainWindow()
        if review { pane = .review }
    }

    var hasAutomaticCoverage: Bool {
        if let coverage = automaticCoverage,
           coverage.fullPass != nil || coverage.unread > 0 { return true }
        guard let health = monitor?.health else { return false }
        return health.fullPass != nil || (health.unread ?? 0) > 0
    }

    /// Some place the last manual scan or automatic full pass could not read.
    /// No count is shown for it: nearly every Mac has places macOS keeps private.
    var somePlacesNotChecked: Bool {
        (results?.notChecked ?? 0) > 0 || (monitor?.health.unread ?? 0) > 0
    }

    /// Folders macOS did not let the last scan read, which the person can allow.
    var blockedFolders: [String] {
        guard !preparingAccess, phase != .scanning else { return [] }
        return results?.blocked ?? []
    }

    /// Show a short confirmation under the window title, then give the subtitle back.
    private func confirm(_ text: String) {
        notice = text
        Task {
            try? await Task.sleep(nanoseconds: 4_000_000_000)
            if notice == text { notice = nil }
        }
    }

    /// Run an action, and show what went wrong if it fails.
    private func attempt(_ title: String, from origin: ActionOrigin = .window, _ work: @escaping () async throws -> Void) {
        Task {
            do { try await work() } catch { report(error.localizedDescription, title: title, from: origin) }
        }
    }

    /// Shows what went wrong in the window the person acted in, and in no
    /// other. Settings shows its own while it is open. Otherwise the main
    /// window does, and comes up for it unless the action was taken there:
    /// Settings may have closed while the engine answered, and the menu bar
    /// has no window.
    private func report(_ reason: String, title: String, from origin: ActionOrigin) {
        let problem = Failure(title: title, reason: reason)
        switch origin {
        case .window:
            failure = problem
        case .settings where settingsOpen:
            settingsFailure = problem
        case .settings, .menuBar:
            failure = problem
            showWindow(review: false)
        }
    }

    /// A change to the review list, which is then asked for again whether or
    /// not the change was made. The engine sends no event when a save fails,
    /// and after one the list is one it can no longer read or save. The page
    /// is brought up to date before the failure is reported over it.
    private func change(_ title: String, from origin: ActionOrigin = .window, _ work: @escaping () async throws -> Void,
                        after saved: (() -> Void)? = nil) {
        Task {
            var problem: String?
            do { try await work() } catch { problem = error.localizedDescription }
            await refreshReview()
            if let problem { report(problem, title: title, from: origin) }
            else if reviewProblem == nil { saved?() }
        }
    }

    // MARK: Scanning

    /// The caller reserves preparation synchronously, before creating its
    /// task, so repeated presses cannot start overlapping permission requests.
    private func prepareAccess() async throws -> Bool {
        defer { preparingAccess = false }
        for index in 0..<3 {
            guard !accessCancelled else { return false }
            try await engine.send("prepare_access", ["index": index])
        }
        return !accessCancelled
    }

    func cancelAccessPreparation() {
        // macOS owns any open permission alert. Finish that request, then
        // stop without requesting another folder, a scan or helper consent.
        accessCancelled = true
    }

    /// Scan Now can be pressed: no scan or folder access preparation runs,
    /// and the folders, if they could be read, include a home folder.
    /// Folders that couldn't be read are read again first.
    var canStartScan: Bool {
        phase != .scanning && !preparingAccess && (places == nil || places?.home != nil)
    }

    func startScan() {
        guard canStartScan else { return }
        preparingAccess = true
        accessCancelled = false
        phase = .scanning
        progress = nil
        started = nil
        notice = nil
        pane = .overview
        Task {
            do {
                if places == nil { await refreshPlaces(reportFailure: true) }
                guard places?.home != nil else {
                    preparingAccess = false
                    phase = results == nil ? .ready : .done
                    return
                }
                guard try await prepareAccess() else {
                    phase = results == nil ? .ready : .done
                    return
                }
                started = Date()
                results = try await engine.request("start_scan")
                await refreshReview()
                phase = .done
                if let error = reviewProblem {
                    failure = Failure(title: FailureTitle.showFindings,
                                      reason: String(localized: "The scan finished. \(error) Save the report to see what it found.",
                                                     comment: "In an alert after a scan, under Couldn't Show the Findings. %@ is the reason, one or more sentences from the engine or macOS."))
                }
            } catch {
                phase = results == nil ? .ready : .done
                failure = Failure(title: FailureTitle.scan, reason: error.localizedDescription)
            }
            started = nil
        }
    }

    func cancelScan() {
        if preparingAccess {
            cancelAccessPreparation()
            return
        }
        attempt(FailureTitle.stopScan) { try await self.engine.send("cancel_scan") }
    }

    // MARK: Folders

    func addFolder(from origin: ActionOrigin = .window) {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.prompt = String(localized: "Add", comment: "The button of the panel that chooses a folder or drive to include in scans.")
        panel.message = String(localized: "Choose a folder or drive to include in scans.",
                               comment: "At the top of the panel that chooses a folder or drive to include in scans.")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        attempt(FailureTitle.addFolder, from: origin) {
            let places = try await self.changePlaces("type_place", ["text": url.path])
            if let error = places.error { self.report(EngineText.shown(error), title: FailureTitle.addFolder, from: origin) }
        }
    }

    /// Folders dropped on Settings. The first one refused ends the batch, and says why.
    func addFolders(_ folders: [URL], from origin: ActionOrigin = .window) {
        attempt(FailureTitle.addFolder, from: origin) {
            for folder in folders {
                // The panel offers only folders. A drop can carry a file or a web link.
                guard folder.isFileURL,
                      (try? folder.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true else {
                    self.report(String(localized: "Only folders and drives can be added.",
                                       comment: "In an alert: something other than a folder or drive was dropped on the window."),
                                title: FailureTitle.addFolder, from: origin)
                    break
                }
                let places = try await self.changePlaces("type_place", ["text": folder.path])
                if let error = places.error {
                    self.report(EngineText.shown(error), title: FailureTitle.addFolder, from: origin)
                    break
                }
            }
        }
    }

    /// A folder is named by its place in the list and by what is shown there.
    /// The engine acts only while the two agree, so a second press that lands
    /// after the list has moved up does nothing to the folder now in that place.
    func removeFolder(_ index: Int, shown: String, from origin: ActionOrigin = .window) {
        attempt(FailureTitle.removeFolder, from: origin) {
            let places = try await self.changePlaces("remove_place", ["index": index, "shown": shown])
            if let error = places.error { self.report(EngineText.shown(error), title: FailureTitle.removeFolder, from: origin) }
        }
    }

    /// A change to the folders, answered with the list after it. The list is
    /// shown unless a later request's answer already is. A refusal is always
    /// the caller's to report.
    private func changePlaces(_ command: String, _ args: [String: Any]) async throws -> ScanPlaces {
        let request = placesOrder.next()
        let answer: ScanPlaces = try await engine.request(command, args)
        if placesOrder.use(request) {
            places = answer
            // A change that was saved read the saved state. A refusal says
            // nothing of it, and is the caller's to report.
            if answer.error == nil { placesProblem = nil }
        }
        return answer
    }

    func checkFolderAgain(_ index: Int, shown: String, from origin: ActionOrigin = .window) {
        change(FailureTitle.includeFolder, from: origin) { try await self.engine.send("unskip_folder", ["index": index, "shown": shown]) }
    }

    // MARK: One finding

    /// The path of the item or copy with this id, from either list.
    private func path(_ id: ReviewItem.ID) async throws -> String {
        try await engine.request("item_path", ["index": id, "review": true])
    }

    /// Text for this Mac's clipboard only. Paths and summaries name files and
    /// accounts, so they are not offered to the person's other devices.
    private func copy(_ text: String) {
        NSPasteboard.general.prepareForNewContents(with: .currentHostOnly)
        NSPasteboard.general.setString(text, forType: .string)
    }

    /// A path as it is safe to paste after a command. Whoever made a file
    /// chose its name, and a shell acts on spaces, semicolons and the like.
    func quotedIfNeeded(_ path: String) -> String {
        let plain = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._+@%,:=-")
        if path.unicodeScalars.allSatisfy(plain.contains) { return path }
        return "'" + path.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    func showInFinder(_ id: ReviewItem.ID) {
        attempt(FailureTitle.showInFinder) {
            let path = try await self.path(id)
            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
        }
    }

    func copyPath(_ id: ReviewItem.ID) {
        attempt(FailureTitle.copyPath) {
            let path = try await self.path(id)
            let text = self.quotedIfNeeded(path)
            self.copy(text)
            self.confirm(text == path
                         ? String(localized: "Path copied", comment: "Shown for a moment under the window title after Copy Path.")
                         : String(localized: "Path copied, in quotes for Terminal",
                                  comment: "Shown for a moment under the window title after Copy Path, when the path was put in quotes so that it can be pasted after a command in the Terminal app."))
        }
    }

    /// System Settings at Notifications, at this app's entry where macOS goes
    /// that far: the only place notifications that are off can be turned on.
    func openNotificationSettings() {
        var link = "x-apple.systempreferences:com.apple.Notifications-Settings.extension"
        if let id = Bundle.main.bundleIdentifier { link += "?id=\(id)" }
        if let url = URL(string: link) { openURL(url) }
    }

    /// System Settings at Login Items, where the helper and the app are
    /// allowed to start. The checks record a press instead.
    var openLoginItems: () -> Void = { SMAppService.openSystemSettingsLoginItems() }

    /// System Settings at Privacy & Security, Files & Folders, where a folder
    /// denied at the prompt can be allowed again (unverified on macOS 26 and later).
    func openFilesAndFoldersSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_FilesAndFolders") {
            openURL(url)
        }
    }

    /// The engine accepts only pages listed in its rules, and hands back the one to open.
    func openLink(_ link: String) {
        attempt(FailureTitle.openPage) {
            let checked: String = try await self.engine.request("open_link", ["url": link])
            if let url = URL(string: checked) { self.openURL(url) }
        }
    }

    /// What names the row a press was made on: its id, and the revision it
    /// was drawn with. The engine acts only while the two still agree, so a
    /// press on a row whose value has since changed decides nothing about
    /// the new one. The list is then asked for again, and the refusal shown.
    private func drawn(_ item: ReviewItem) -> [String: Any] {
        ["id": item.id, "revision": item.revision ?? NSNull()]
    }

    /// Set an item aside for a reason, or return it to review with nil.
    func decide(_ item: ReviewItem, reason: String?) {
        guard !decidingSelection else { return }
        decisionTurn += 1
        let turn = decisionTurn
        let from = pane
        let since = paneChanged
        change(FailureTitle.saveChoice, {
            try await self.engine.send("decide_review", self.drawn(item).merging(["reason": reason ?? NSNull()]) { $1 })
        }, after: { [self] in
            // Follow the finding only if the person chose nothing since: the
            // refresh has dropped its row from Set Aside, so a selection left
            // is one made after the press, and so is a page change.
            guard turn == decisionTurn, reason == nil,
                  from == .setAside, pane == from, paneChanged == since, selectedReviews.isEmpty,
                  let entry = reviewEntry(item.id), entry.status != "set-aside" else { return }
            pane = entry.isStored ? .stored : .review
            selectedReview = reviewShown.first { $0.id == entry.id }?.id
        })
    }

    func stopCheckingFolder(_ item: ReviewItem) {
        change(FailureTitle.skipFolder) { try await self.engine.send("skip_folder", ["id": item.id]) }
    }

    // MARK: Saving and copying results

    func save(feedback: Bool) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = feedback ? "loose-keys-counts.json" : "loose-keys-report.json"
        panel.message = feedback
            ? String(localized: "Counts only. No paths or file names.",
                     comment: "At the top of the save panel for Save Counts Only…: what the saved file holds.")
            : String(localized: "Every finding and file path. Review before sharing.",
                     comment: "At the top of the save panel for Save Report…: what the saved file holds.")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        attempt(FailureTitle.saveReport) {
            try await self.write(feedback: feedback, to: url)
            self.confirm(String(localized: "Saved \(url.lastPathComponent)",
                                comment: "Shown for a moment under the window title after a save. %@ is the name of the file the person chose."))
        }
    }

    /// The engine never writes over a file. A report the person chose to
    /// replace goes to the Trash, where it can be recovered, but only once the
    /// new one has been written beside it under a name of its own. A report
    /// that cannot be written then costs the earlier one nothing.
    func write(feedback: Bool, to url: URL) async throws {
        let files = FileManager.default
        guard files.fileExists(atPath: url.path) else {
            return try await engine.send("save_report", ["path": url.path, "feedback": feedback])
        }
        let name = url.deletingPathExtension().lastPathComponent + "-" + UUID().uuidString.prefix(8)
        let fresh = url.deletingLastPathComponent().appendingPathComponent(name).appendingPathExtension(url.pathExtension)
        try await engine.send("save_report", ["path": fresh.path, "feedback": feedback])
        do {
            try files.trashItem(at: url, resultingItemURL: nil)
        } catch {
            throw EngineError(message: String(localized: "Loose Keys couldn't move the old report to the Trash, so it saved the new one next to it as \(fresh.lastPathComponent). \(error.localizedDescription)",
                                              comment: "In an alert when the report the person chose to replace could not be moved to the Trash. The first %@ is the new file's name, the second is the reason macOS gave."))
        }
        do {
            try files.moveItem(at: fresh, to: url)
        } catch {
            throw EngineError(message: String(localized: "The old report is in the Trash, but Loose Keys couldn't give the new one its name. It's saved as \(fresh.lastPathComponent). \(error.localizedDescription)",
                                              comment: "In an alert when the report the person chose to replace went to the Trash, but the new report couldn't be renamed to the name the person chose. The first %@ is the new file's name, the second is the reason macOS gave."))
        }
    }

    func copySummary() {
        attempt(FailureTitle.copySummary) {
            let text: String = try await self.engine.request("summary_text")
            self.copy(text)
            self.confirm(String(localized: "Summary copied", comment: "Shown for a moment under the window title after Copy Summary."))
        }
    }

    /// Whether asking for notifications can work: macOS has no answer yet, or
    /// a request failed before it had one. Blocked is changed only in System
    /// Settings, and an unknown permission may not be askable.
    var canAskForNotifications: Bool {
        ["not requested", "request failed"].contains(review?.permission ?? "")
    }

    /// Whether the Overview still shows the turned-down request: only while
    /// macOS says notifications are off. Off by the person's own hand later,
    /// in System Settings, they are not asked about again.
    var showsTurnedDownNotifications: Bool {
        notificationsTurnedDown && review?.permission == "denied"
    }

    // MARK: Background checks

    var backgroundState: BackgroundState {
        guard let monitor, monitorFailure == nil else { return .unavailable }
        if !monitor.enabled { return .off }
        if monitor.login == 3 { return .needsApproval }
        if helperStarting { return .starting }
        if monitor.login != 2 || monitor.health.running == false { return .helperNotRunning }
        guard monitor.health.running == true else { return .waitingForHelper }
        if monitor.paused { return .paused }
        if monitor.health.error != nil { return .needsAttention }
        return .active
    }

    /// When the person turned automatic scanning on in this launch.
    private var turnedOn: Date?

    /// The helper takes a few seconds to start after automatic scanning is
    /// turned on. Until it runs, or for 15 seconds, it is starting, not stopped.
    var helperStarting: Bool {
        guard let turnedOn, let monitor, monitor.enabled, monitor.health.running != true else { return false }
        return now().timeIntervalSince(turnedOn) < 15
    }

    /// The helper is reading every file for the first time and this window
    /// has not scanned: its findings arrive as it goes.
    var helperFirstPass: Bool {
        guard results == nil, let monitor, monitor.enabled, !monitor.paused, monitor.health.fullPass == nil else { return false }
        return [.starting, .waitingForHelper, .active].contains(backgroundState)
    }

    /// When the helper last checked a file, for a list this window has not scanned.
    var lastChecked: String? {
        monitor?.health.lastScan.map {
            String(localized: "Last checked \(localTime($0)).",
                   comment: "Overview, under the answer, when the findings come from automatic scanning. %@ is when it last checked a file, a date and time.")
        }
    }

    /// Nothing has been checked that a count could come from: nothing worth
    /// reviewing is listed, there is no scan this session, and the helper, whose state has
    /// been read, has recorded no check. An empty list then means not yet
    /// looked, not none found. Saved stored sign-ins leave this as it was
    /// before they were saved.
    var nothingChecked: Bool {
        guard let monitor, let review, reviewProblem == nil else { return false }
        return !review.items.contains { !$0.isStored } && results == nil && phase != .scanning && monitor.health.lastScan == nil
    }

    /// The first page offers one step, Scan Now, before anything is known.
    /// Only when every answer it depends on has come and none of them
    /// has anything to show. A state not yet known, or a failure, is the full
    /// page, which says what it is.
    var showsWelcome: Bool {
        guard let monitor, monitor.error == nil, monitor.health.error == nil, !monitor.enabled, monitor.health.lastScan == nil,
              let review, reviewProblem == nil, !review.items.contains(where: { !$0.isStored }),
              results == nil, phase != .scanning else { return false }
        return true
    }

    /// Why background checks cannot be changed: the app's private state could
    /// not be read or saved. The engine puts its notice that the review list
    /// is full in the same field, and that is no failure. The checks still
    /// run then, and consent to them can still be withdrawn.
    var monitorFailure: String? {
        guard let error = monitor?.error else { return nil }
        return review?.full == true && review?.error == nil ? nil : error
    }

    func setMonitoring(enabled: Bool, paused: Bool, from origin: ActionOrigin = .window) {
        guard !preparingAccess else { return }
        let needsAccess = enabled && monitor?.enabled != true
        if needsAccess {
            guard phase != .scanning, places?.home != nil else { return }
            preparingAccess = true
            accessCancelled = false
            pane = .overview
        }
        attempt(FailureTitle.automaticScanning, from: origin) {
            if needsAccess, try await !self.prepareAccess() { return }
            try await self.engine.send("set_monitoring", ["enabled": enabled, "paused": paused])
            if needsAccess { self.turnedOn = self.now() }
            await self.refreshMonitor()
            await self.refreshMonitorSoon()
        }
    }

    /// The helper takes a moment to start or stop after macOS is asked, and
    /// tells this window nothing when it has.
    private func refreshMonitorSoon() async {
        try? await sleep(2_000_000_000)
        await refreshMonitor()
    }

    /// A registered helper that is not running is stopped, then started:
    /// macOS starts it again only for a new registration. One that is not
    /// registered is only started. Stopping waits until macOS has finished.
    /// A button in Settings only.
    func restartHelper() {
        let registered = monitor?.login == 2
        attempt(FailureTitle.restartHelper, from: .settings) {
            var result = 1
            if registered {
                result = try await self.engine.request("set_login_startup", ["enabled": false])
            }
            if result != 4 {
                result = try await self.engine.request("set_login_startup", ["enabled": true])
            }
            await self.refreshMonitor()
            await self.refreshMonitorSoon()
            if result == 4 {
                self.report(String(localized: "Check that Loose Keys is turned on under Allow in the Background in System Settings.",
                                   comment: "In an alert after Restart Helper, under Couldn't Restart the Helper. Allow in the Background is the name of a list in System Settings' Login Items pane; use macOS's own names."),
                            title: FailureTitle.restartHelper, from: .settings)
            }
        }
    }

    func setMenuBar(_ on: Bool, from origin: ActionOrigin = .window) {
        Task {
            do {
                try await engine.send("set_menu_bar", ["enabled": on])
                menuBarOn = on
                updatePolling()
            } catch {
                report(error.localizedDescription, title: FailureTitle.menuBar, from: origin)
            }
            await refreshMonitor()
        }
    }

    func enableNotifications(from origin: ActionOrigin = .window) {
        guard !awaitingPermission else { return }
        awaitingPermission = true
        Task {
            do {
                try await engine.send("enable_notifications")
            } catch {
                awaitingPermission = false
                report(error.localizedDescription, title: FailureTitle.askNotifications, from: origin)
            }
        }
    }

    /// A button in Settings only.
    func retryNotifications() {
        attempt(FailureTitle.sendNotification, from: .settings) {
            try await self.engine.send("retry_notifications")
            await self.refreshMonitor()
        }
    }

    func prepareToQuit() {
        accessCancelled = true
        quitting = true
        updatePolling()
        followUpdateSetting(false)
        _ = try? engine.call("prepare_quit", [:])
    }
}
