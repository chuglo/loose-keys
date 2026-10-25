// Everything the window shows, and every action it can take.
import AppKit
import SwiftUI
import UniformTypeIdentifiers

enum Pane: String, Hashable {
    case overview, review, stored, gaps, setAside
}

enum Phase {
    case ready, scanning, done
}

/// What the menu bar icon shows. No count: the menu has it. `full` is a
/// list that left findings out, whatever is open on it.
enum MenuBarMark {
    case unknown, open, plain, problem, full
}

/// A stored sign-in from the last scan, with its rule's advice.
struct StoredRow: Identifiable {
    let file: FindingFile
    let group: FindingGroup
    /// Where the engine listed it among the sign-ins: a rule at a time.
    let place: Int
    var id: Int { file.index }
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

/// Reads of one thing the window shows and the helper can change: the review
/// list, or the status of background checks. Only one is out at a time, so
/// answers are shown in the order the engine read them. A number for each
/// request was not enough: of two calls out together, the one asked for later
/// could read first, and what the other then read, the newest, was put aside.
@MainActor
final class ReadTurns {
    private var asked = 0
    /// How many requests had been made when the read now out, or the last one, began.
    private var began = 0
    private var answered = 0
    private var reading: Task<Void, Never>?

    /// Whether a request has been made since the read now out began. Its
    /// answer is then not the last word: another read follows it.
    var askedAgain: Bool { asked > began }

    /// Returns once a read that began after this request has been shown.
    /// Requests made while a read is out share the one read that follows it.
    func run(_ read: @escaping @MainActor () async -> Void) async {
        asked += 1
        let mine = asked
        while answered < mine {
            if reading == nil {
                began = asked
                let covers = began
                reading = Task {
                    await read()
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
            if (pane == .setAside) != (oldValue == .setAside) { dropHiddenSelection() }
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
    @Published var results: ScanResults?
    @Published var review: ReviewList?
    /// Why the last request for the review list failed, if it did. `review`
    /// is then an older list, or none.
    @Published var reviewUnread: String?
    @Published var monitor: MonitorStatus?
    @Published var overviewCheckDetails = false
    @Published var inspectorWhy = false
    @Published var inspectorDetails = false
    /// The sidebar as the person left it. The first page hides it until there
    /// is something to list, unless the person has opened it or used it since.
    @Published var columns = NavigationSplitViewVisibility.automatic
    @Published var sidebarAsked = false
    @Published var phase = Phase.ready
    @Published var preparingAccess = false
    private var accessCancelled = false
    @Published var progress: ScanProgress?
    @Published var started: Date?
    @Published var selectedReview: ReviewItem.ID?
    @Published var selectedStored: StoredRow.ID?
    /// The column headings each list is sorted by, the last one clicked first.
    /// Status is where the review list starts: open first, then by risk.
    @Published var reviewSort = [KeyPathComparator(\ReviewItem.statusRank)]
    @Published var storedSort: [KeyPathComparator<StoredRow>] = []
    @Published var search = "" {
        didSet {
            dropHiddenSelection()
            // The Filter field is on every page and filters the finding lists.
            // Typed into anywhere else, it opens the first of them.
            if !search.isEmpty, pane != .review, pane != .setAside, pane != .stored { pane = .review }
        }
    }
    @Published var inspectorShown = true
    /// A problem to show in an alert.
    @Published var failure: String?
    /// A short confirmation, shown under the window title.
    @Published var notice: String?
    private var decisionTurn = 0
    @Published var awaitingPermission = false
    @Published var askingConsent = false
    private var placesOrder = RequestOrder()
    private let reviewReads = ReadTurns()
    private let monitorReads = ReadTurns()
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
        for window in NSApp.windows where window.canBecomeMain { window.makeKeyAndOrderFront(nil) }
    }
    #if PREVIEW || SNAPSHOTS
    /// Opens the Settings window, for the picture-taking code.
    var openSettings: () -> Void = {}
    #endif

    init(engine: Engine, sleep: @escaping @MainActor (UInt64) async throws -> Void = {
        try await Task.sleep(nanoseconds: $0)
    }) {
        self.sleep = sleep
        self.engine = engine
    }

    /// Opens a page outside the app. The window check records it instead, so
    /// that a press there opens nothing on the Mac running the check.
    var openURL: (URL) -> Void = { _ = NSWorkspace.shared.open($0) }

    // MARK: What the lists show

    /// Decisions change which page lists an item, never the findings held or exported.
    var reviewPaneItems: [ReviewItem] {
        (review?.items ?? []).filter { ($0.status == "set-aside") == (pane == .setAside) }
    }

    /// The findings the filter leaves, not yet in order. Enough to find one
    /// of them, which the filter does for each character typed.
    private var reviewShown: [ReviewItem] {
        let wanted = search.trimmingCharacters(in: .whitespaces).lowercased()
        return reviewPaneItems
            .filter { wanted.isEmpty || "\($0.title) \($0.path) \($0.subject ?? "") \($0.detail ?? "")".lowercased().contains(wanted) }
    }

    var reviewRows: [ReviewItem] {
        arranged(reviewShown, by: reviewSort) { ($0.order, $0.id) < ($1.order, $1.id) }
    }

    /// The stored sign-ins the filter leaves, as the engine listed them.
    /// Enough to find one of them or to count them.
    var storedShown: [StoredRow] {
        let wanted = search.trimmingCharacters(in: .whitespaces).lowercased()
        return (results?.groups ?? [])
            .filter { $0.kind == "inventory" }
            .flatMap { group in group.items.map { (file: $0, group: group) } }
            .enumerated()
            .map { StoredRow(file: $0.element.file, group: $0.element.group, place: $0.offset) }
            .filter { wanted.isEmpty || "\($0.group.title) \($0.file.path) \($0.file.subject ?? "")".lowercased().contains(wanted) }
    }

    var storedRows: [StoredRow] {
        // Until a heading is clicked, and for rows the clicked headings rank
        // the same, the order the engine listed them in: each rule's together.
        arranged(storedShown, by: storedSort) { $0.place < $1.place }
    }

    var openCount: Int {
        review?.counts?.open ?? (review?.items.filter { $0.status == "open" }.count ?? 0)
    }

    /// No count while the list cannot be used: a scan knows nothing of
    /// decisions, so it has no Set Aside count to fall back on.
    var setAsideCount: Int {
        guard reviewProblem == nil else { return 0 }
        return review?.counts?.setAside ?? (review?.items.filter { $0.status == "set-aside" }.count ?? 0)
    }

    /// Why Worth Reviewing cannot show what was found, when it cannot: the
    /// engine could not read or save the list, or this window could not get
    /// it. Whatever list the window holds is then not shown or counted.
    var reviewProblem: String? {
        reviewUnread ?? review?.error
    }

    /// The number beside Worth Reviewing. When the list cannot be used it is
    /// the last scan's own count, so that a failure never reads as nothing
    /// found.
    var reviewCount: Int {
        reviewProblem == nil ? openCount : (results?.review ?? 0)
    }

    /// Says why the list is shorter than the count in the saved report and the
    /// copied summary, when it is. Both numbers are right: those count each
    /// finding, and the list has one item for a credential however many rules
    /// or files found it. A full list is shorter for a worse reason as well:
    /// findings it had no room for. The window cannot tell how much of the
    /// difference is which, so it gives both, the worse one first.
    var findingsNote: String? {
        guard let found = results?.review, let review, reviewProblem == nil else { return nil }
        let listed = review.items.filter { $0.status != "fixed" }.count
        guard found > listed else { return nil }
        let counts = "The saved report and the copied summary count \(plural(found, "finding", "findings")). The list has \(plural(listed, "item", "items"))"
        let grouping = "a credential found by more than one rule, or in more than one file, is one item"
        if review.full == true {
            return "\(counts) and is full, so findings it has no room for are left out: save the report to see them all. Also, \(grouping)."
        }
        return "\(counts), because \(grouping)."
    }

    var currentReview: ReviewItem? {
        // A list that cannot be used is not shown, so none of its items is the
        // current one. After a failed read or save the engine would refuse a
        // decision on any of them.
        guard reviewProblem == nil else { return nil }
        return reviewShown.first { $0.id == selectedReview }
    }

    var currentStored: StoredRow? {
        storedShown.first { $0.id == selectedStored }
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
        if let chosen = selectedReview, !reviewShown.contains(where: { $0.id == chosen }) { selectedReview = nil }
        if selectedStored != nil, currentStored == nil { selectedStored = nil }
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
        case .open, .plain: return "\(plural(openCount, "loose key", "loose keys")) to review"
        case .full: return "\(plural(openCount, "loose key", "loose keys")) to review, list full"
        case .problem: return "Worth Reviewing could not be read"
        case .unknown: return "Reading Worth Reviewing…"
        }
    }

    /// Unless automatic scanning is known to be running, the state Settings shows for it.
    var menuBarCheckLine: String? {
        backgroundState == "Active" ? nil : "Automatic scanning: \(backgroundState)"
    }

    /// Nothing looks cleaner than it is: everything set aside or skipped is counted.
    var reviewSummary: String {
        guard reviewProblem == nil, let counts = review?.counts else { return "" }
        var parts = ["\(counts.open) to review"]
        if counts.setAside > 0 { parts.append("\(counts.setAside) set aside") }
        if counts.fixed > 0 { parts.append("\(counts.fixed) fixed") }
        if review?.full == true { parts.append("list full, so some findings were left out") }
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
        Task { await refresh() }
    }

    /// The helper may have found something while the window was in the background.
    func becameActive() {
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
        let request = placesOrder.next()
        do {
            let answer: ScanPlaces = try await engine.request("places")
            if placesOrder.use(request) { places = answer }
        } catch {
            // The folders already shown stay, and so may a change still on its
            // way: a list that could not be got is not an empty one.
            if placesOrder.isNewest(request) { failure = error.localizedDescription }
        }
        await refreshReview()
        await refreshMonitor()
    }

    /// The list as the engine reads it after this was asked. Only these reads
    /// take turns: a scan, Stop and every other command go to the engine at once.
    func refreshReview(reportFailure: Bool = true) async {
        await reviewReads.run { [self] in
            do {
                let answer: ReviewList = try await engine.request("pending_review")
                review = answer
                reviewUnread = nil
                // The chosen row may be back under another copy's id. It stays chosen.
                if let chosen = selectedReview, let entry = reviewEntry(chosen), entry.id != chosen {
                    selectedReview = entry.id
                }
                if reviewProblem == nil { dropHiddenSelection() }
            } catch {
                // The read that follows a request made since answers for this
                // one. Until it does, the last list read stays as it was.
                guard !reviewReads.askedAgain else { return }
                reviewUnread = error.localizedDescription
                // Automatic refresh failures stay visible in the list without
                // reopening a modal alert every five seconds.
                if reportFailure { failure = error.localizedDescription }
            }
        }
    }

    func refreshMonitor() async {
        await monitorReads.run { [self] in
            let answer: MonitorStatus? = try? await engine.request("monitor_status")
            guard answer != nil || !monitorReads.askedAgain else { return }
            // None when the request failed: the window then says the checks are
            // unavailable, not what an older status said of them.
            monitor = answer
            if let answer { menuBarOn = answer.menuBar }
            updatePolling()
            // The engine keeps the last scan this process ran, for a window opened after it.
            if results == nil, phase == .ready, let held = monitor?.results {
                results = held
            }
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
                selectedReview = review?.items.filter { $0.status == "open" }
                    .max { ($0.revision ?? 0) < ($1.revision ?? 0) }?.id
            }
        case "review-ready":
            Task { await refreshReview() }
        case "monitor-status":
            Task { await refreshMonitor(); await refreshReview() }
        case "notification-permission":
            awaitingPermission = false
            Task { await refreshReview(); await refreshMonitor() }
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
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// The window in front, with a Dock icon while it is open.
    func showWindow(review: Bool) {
        comeForward()
        for window in NSApp.windows where window.isMiniaturized { window.deminiaturize(nil) }
        openMainWindow()
        if review { pane = .review }
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
    private func attempt(_ work: @escaping () async throws -> Void) {
        Task {
            do { try await work() } catch { failure = error.localizedDescription }
        }
    }

    /// A change to the review list, which is then asked for again whether or
    /// not the change was made. The engine sends no event when a save fails,
    /// and after one the list is one it can no longer read or save. The page
    /// is brought up to date before the failure is reported over it.
    private func change(_ work: @escaping () async throws -> Void, after saved: (() -> Void)? = nil) {
        Task {
            var problem: String?
            do { try await work() } catch { problem = error.localizedDescription }
            await refreshReview()
            if let problem { failure = problem }
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

    func startScan() {
        guard phase != .scanning, !preparingAccess, places?.home != nil else { return }
        preparingAccess = true
        accessCancelled = false
        phase = .scanning
        progress = nil
        started = nil
        notice = nil
        pane = .overview
        Task {
            do {
                guard try await prepareAccess() else {
                    phase = results == nil ? .ready : .done
                    return
                }
                started = Date()
                results = try await engine.request("start_scan")
                // A stored sign-in is known by its place in the results, which are new.
                selectedStored = nil
                await refreshReview()
                phase = .done
                if let error = reviewProblem {
                    failure = "The scan finished, but its findings could not be listed. \(error) Save the report to see them."
                }
            } catch {
                phase = results == nil ? .ready : .done
                failure = error.localizedDescription
            }
            started = nil
        }
    }

    func cancelScan() {
        if preparingAccess {
            cancelAccessPreparation()
            return
        }
        attempt { try await self.engine.send("cancel_scan") }
    }

    // MARK: Folders

    func addFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.prompt = "Add"
        panel.message = "Choose a folder or drive to include in scans."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        attempt {
            let places = try await self.changePlaces("type_place", ["text": url.path])
            self.failure = places.error
        }
    }

    /// Folders dropped on the window. The first one refused ends the batch, and says why.
    func addFolders(_ folders: [URL]) {
        attempt {
            for folder in folders {
                // The panel offers only folders. A drop can carry a file or a web link.
                guard folder.isFileURL,
                      (try? folder.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true else {
                    self.failure = "Only folders and drives can be added."
                    break
                }
                let places = try await self.changePlaces("type_place", ["text": folder.path])
                if let error = places.error {
                    self.failure = error
                    break
                }
            }
        }
    }

    /// A folder is named by its place in the list and by what is shown there.
    /// The engine acts only while the two agree, so a second press that lands
    /// after the list has moved up does nothing to the folder now in that place.
    func removeFolder(_ index: Int, shown: String) {
        attempt { _ = try await self.changePlaces("remove_place", ["index": index, "shown": shown]) }
    }

    /// A change to the folders, answered with the list after it. The list is
    /// shown unless a later request's answer already is. A refusal is always
    /// the caller's to report.
    private func changePlaces(_ command: String, _ args: [String: Any]) async throws -> ScanPlaces {
        let request = placesOrder.next()
        let answer: ScanPlaces = try await engine.request(command, args)
        if placesOrder.use(request) { places = answer }
        return answer
    }

    func checkFolderAgain(_ index: Int, shown: String) {
        change { try await self.engine.send("unskip_folder", ["index": index, "shown": shown]) }
    }

    // MARK: One finding

    private func path(_ index: Int, review: Bool) async throws -> String {
        // A stored sign-in is named by its place in the last results, and a
        // scan replaces those before this window has them.
        if !review, phase == .scanning {
            throw EngineError(message: "Wait for the scan to finish, then try again.")
        }
        return try await engine.request("item_path", ["index": index, "review": review])
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

    func showInFinder(_ index: Int, review: Bool) {
        attempt {
            let path = try await self.path(index, review: review)
            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
        }
    }

    func copyPath(_ index: Int, review: Bool) {
        attempt {
            let path = try await self.path(index, review: review)
            let text = self.quotedIfNeeded(path)
            self.copy(text)
            self.confirm(text == path ? "Path copied" : "Path copied, in quotes for Terminal")
        }
    }

    /// System Settings at Notifications, at this app's entry where macOS goes
    /// that far: the only place notifications that are off can be turned on.
    func openNotificationSettings() {
        var link = "x-apple.systempreferences:com.apple.Notifications-Settings.extension"
        if let id = Bundle.main.bundleIdentifier { link += "?id=\(id)" }
        if let url = URL(string: link) { openURL(url) }
    }

    /// The engine accepts only pages listed in its rules, and hands back the one to open.
    func openLink(_ link: String) {
        attempt {
            let checked: String = try await self.engine.request("open_link", ["url": link])
            if let url = URL(string: checked) { NSWorkspace.shared.open(url) }
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
        decisionTurn += 1
        let turn = decisionTurn
        let from = pane
        let since = paneChanged
        change({
            try await self.engine.send("decide_review", self.drawn(item).merging(["reason": reason ?? NSNull()]) { $1 })
        }, after: { [self] in
            // Follow the finding only if the person chose nothing since: the
            // refresh has dropped its row from Set Aside, so a selection left
            // is one made after the press, and so is a page change.
            guard turn == decisionTurn, reason == nil,
                  from == .setAside, pane == from, paneChanged == since, selectedReview == nil,
                  let entry = reviewEntry(item.id), entry.status != "set-aside" else { return }
            pane = .review
            selectedReview = reviewShown.first { $0.id == entry.id }?.id
        })
    }

    func stopCheckingFolder(_ item: ReviewItem) {
        change { try await self.engine.send("skip_folder", ["id": item.id]) }
    }

    // MARK: Saving and copying results

    func save(feedback: Bool) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = feedback ? "loose-keys-counts.json" : "loose-keys-report.json"
        panel.message = feedback
            ? "Counts only. No paths or file names."
            : "Every finding and file path. Review before sharing."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        attempt {
            try await self.write(feedback: feedback, to: url)
            self.confirm("Saved \(url.lastPathComponent)")
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
            try files.moveItem(at: fresh, to: url)
        } catch {
            throw EngineError(message: "The new report is saved as \(fresh.lastPathComponent), beside the one you chose to replace. \(error.localizedDescription)")
        }
    }

    func copySummary() {
        attempt {
            let text: String = try await self.engine.request("summary_text")
            self.copy(text)
            self.confirm("Summary copied")
        }
    }

    /// Whether asking for notifications can work: macOS has no answer yet, or
    /// a request failed before it had one. Blocked is changed only in System
    /// Settings, and an unknown permission may not be askable.
    var canAskForNotifications: Bool {
        ["not requested", "request failed"].contains(review?.permission ?? "")
    }

    // MARK: Background checks

    var backgroundState: String {
        guard let monitor, monitorFailure == nil else { return "Unavailable" }
        if !monitor.enabled { return "Off" }
        if monitor.login == 3 { return "Needs macOS Approval" }
        if monitor.login != 2 || monitor.health.running == false { return "Helper Not Running" }
        guard monitor.health.running == true else { return "Waiting for Helper Status" }
        if monitor.paused { return "Paused" }
        if monitor.health.error != nil { return "Needs Attention" }
        return "Active"
    }

    /// The first page asks one question: check in the background, or scan
    /// once. Only when every answer it depends on has come and none of them
    /// has anything to show. A state not yet known, or a failure, is the full
    /// page, which says what it is.
    var showsWelcome: Bool {
        guard let monitor, monitor.error == nil, monitor.health.error == nil, !monitor.enabled, monitor.health.lastScan == nil,
              let review, reviewProblem == nil, review.items.isEmpty,
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

    func setMonitoring(enabled: Bool, paused: Bool) {
        guard !preparingAccess else { return }
        let needsAccess = enabled && monitor?.enabled != true
        if needsAccess {
            guard phase != .scanning, places?.home != nil else { return }
            preparingAccess = true
            accessCancelled = false
            pane = .overview
        }
        attempt {
            if needsAccess, try await !self.prepareAccess() { return }
            try await self.engine.send("set_monitoring", ["enabled": enabled, "paused": paused])
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
    func restartHelper() {
        let registered = monitor?.login == 2
        attempt {
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
                self.failure = "macOS could not restart the background helper. Check System Settings > General > Login Items."
            }
        }
    }

    func setMenuBar(_ on: Bool) {
        Task {
            do {
                try await engine.send("set_menu_bar", ["enabled": on])
                menuBarOn = on
                updatePolling()
            } catch {
                failure = error.localizedDescription
            }
            await refreshMonitor()
        }
    }

    func enableNotifications() {
        guard !awaitingPermission else { return }
        awaitingPermission = true
        Task {
            do {
                try await engine.send("enable_notifications")
            } catch {
                awaitingPermission = false
                failure = "Could not request notification permission: \(error.localizedDescription)"
            }
        }
    }

    func retryNotifications() {
        attempt {
            try await self.engine.send("retry_notifications")
            await self.refreshMonitor()
        }
    }

    func prepareToQuit() {
        accessCancelled = true
        quitting = true
        updatePolling()
        _ = try? engine.call("prepare_quit", [:])
    }
}
