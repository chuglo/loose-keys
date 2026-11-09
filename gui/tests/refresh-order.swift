// Separate test driver for the window's model. Never linked into the app
// bundle. gui/tests/check-model.sh builds it with the real AppModel, Models and
// Engine sources and the stand-in engine below: no window, no scanner, and
// nothing in a home folder is read. The stand-in answers each command when
// the test says, so answers can be made to arrive in any order. It also
// counts how many calls of one command it held at once: the review list and
// the status of background checks are each read one call at a time. The last
// cases look the engine's text up in made-up tables, two of them written to a
// folder under TMPDIR and removed after.
import Foundation

/// One command the model sent, held until the test answers it.
final class HeldCall: @unchecked Sendable {
    let command: String
    let args: [String: Any]
    let gate = DispatchSemaphore(value: 0)
    var answer: Result<String, EngineError> = .success("null")
    init(_ command: String, _ args: [String: Any]) {
        self.command = command
        self.args = args
    }
}

final class HeldEngine: Engine, @unchecked Sendable {
    private let lock = NSLock()
    private var calls: [HeldCall] = []
    private var unanswered: [String: Int] = [:]
    private var most: [String: Int] = [:]
    private var events: ((String, Data) -> Void)?

    func start(reviewRoute: Bool, onEvent: @escaping (String, Data) -> Void) {
        lock.lock()
        events = onEvent
        lock.unlock()
    }

    /// Sends an event to the model, as the engine does.
    func fire(_ name: String) {
        lock.lock()
        let events = events
        lock.unlock()
        events?(name, Data("null".utf8))
    }

    func call(_ command: String, _ args: [String: Any]) throws -> Data {
        let held = HeldCall(command, args)
        lock.lock()
        calls.append(held)
        unanswered[command, default: 0] += 1
        most[command] = max(most[command] ?? 0, unanswered[command] ?? 0)
        lock.unlock()
        let answered = held.gate.wait(timeout: .now() + 10) == .success
        lock.lock()
        unanswered[command, default: 0] -= 1
        lock.unlock()
        guard answered else {
            throw EngineError(message: "The test never answered \(command).")
        }
        return Data(try held.answer.get().utf8)
    }

    /// The calls of one command, in the order they reached the engine.
    func held(_ command: String) -> [HeldCall] {
        lock.lock()
        defer { lock.unlock() }
        return calls.filter { $0.command == command }
    }

    /// The most calls of one command the engine held at the same time.
    func mostAtOnce(_ command: String) -> Int {
        lock.lock()
        defer { lock.unlock() }
        return most[command] ?? 0
    }
}

var failures = 0

func check(_ holds: Bool, _ what: String) {
    if holds { return }
    failures += 1
    fputs("FAIL: \(what)\n", stderr)
}

/// Waits for what another thread or task does, with a deadline that names it.
@MainActor func eventually(_ what: String, _ done: () -> Bool) async {
    let deadline = Date().addingTimeInterval(10)
    while !done() {
        guard Date() < deadline else {
            fputs("FAIL: timeout: \(what)\n", stderr)
            exit(1)
        }
        try? await Task.sleep(nanoseconds: 1_000_000)
    }
}

/// Test-controlled wakeups. Cancellation is checked both before suspension and
/// after a wakeup, as Task.sleep does. No wall-clock interval needs to pass.
@MainActor final class HeldSleep {
    private var waiting: [(UInt64, CheckedContinuation<Void, Never>)] = []
    private(set) var cancelled = 0
    var isWaiting: Bool { !waiting.isEmpty }

    func sleep(_ nanoseconds: UInt64) async throws {
        do {
            try Task.checkCancellation()
            await withCheckedContinuation { waiting.append((nanoseconds, $0)) }
            try Task.checkCancellation()
        } catch {
            cancelled += 1
            throw error
        }
    }

    func wake(after nanoseconds: UInt64) async {
        await eventually("the model waits for its next timer") { !self.waiting.isEmpty }
        let (requested, continuation) = waiting.removeFirst()
        check(requested == nanoseconds, "the model requests its production timer interval")
        continuation.resume()
    }
}

/// GitHub's latest-release reply, held until the test gives it.
final class HeldReleases: ReleaseSource, @unchecked Sendable {
    private let lock = NSLock()
    private var waiting: [CheckedContinuation<Data, Error>] = []
    private var asked = 0

    func latest() async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            asked += 1
            waiting.append(continuation)
            lock.unlock()
        }
    }

    /// How many times GitHub has been asked.
    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return asked
    }

    /// Answers the oldest request still held.
    func answer(_ result: Result<Data, Error>) {
        lock.lock()
        let continuation = waiting.removeFirst()
        lock.unlock()
        continuation.resume(with: result)
    }
}

/// The wall clock, moved by the test: a day can pass while the Mac sleeps
/// and no timer fires.
@MainActor final class FakeNow {
    var date = Date(timeIntervalSince1970: 1_800_000_000)
}

typealias Asked = (call: HeldCall, done: Task<Void, Never>)

/// How many requests the test has put to the model.
@MainActor final class Made {
    var count = 0
}

@MainActor struct Bench {
    let engine = HeldEngine()
    let model: AppModel
    private let made = Made()

    init(clock: HeldSleep? = nil, releases: ReleaseSource = NoReleases(), now: FakeNow? = nil) {
        let time: @MainActor () -> Date = now.map { fake in { fake.date } } ?? { Date() }
        if let clock { model = AppModel(engine: engine, releases: releases, now: time, sleep: clock.sleep) }
        else { model = AppModel(engine: engine, releases: releases, now: time) }
    }

    /// Starts work that sends `command` and waits until the engine holds the
    /// call. Asked one at a time, calls are held in the order they were asked.
    func ask(_ command: String, _ work: @escaping @MainActor (AppModel) async -> Void) async -> Asked {
        let before = engine.held(command).count
        let model = model
        let done = Task { await work(model) }
        await eventually("\(command) reaches the engine") { engine.held(command).count == before + 1 }
        return (engine.held(command)[before], done)
    }

    /// Starts work and waits until the model has been asked, not until a
    /// call reaches the engine: a request made while the same thing is being
    /// read sends nothing until that read has answered.
    func request(_ work: @escaping @MainActor (AppModel) async -> Void) async -> Task<Void, Never> {
        let (model, made, before) = (model, made, made.count)
        let done = Task {
            made.count += 1
            await work(model)
        }
        await eventually("the model is asked") { made.count == before + 1 }
        return done
    }

    /// Whether the engine goes on holding this many calls of `command` and
    /// no more, for long enough that a call the model had sent beside them
    /// would have arrived.
    func holdsOnly(_ count: Int, _ command: String) async -> Bool {
        for _ in 0..<50 {
            guard engine.held(command).count == count else { return false }
            try? await Task.sleep(nanoseconds: 1_000_000)
        }
        return engine.held(command).count == count
    }

    /// The next call of `command` that work already started sends by itself.
    func next(_ command: String, after before: Int = 0) async -> HeldCall {
        await eventually("\(command) reaches the engine") { engine.held(command).count == before + 1 }
        return engine.held(command)[before]
    }

    func answer(_ call: HeldCall, _ result: Result<String, EngineError>) {
        call.answer = result
        call.gate.signal()
    }

    /// Answers a call and waits for the work that sent it to finish with it.
    func answer(_ asked: Asked, _ result: Result<String, EngineError>) async {
        answer(asked.call, result)
        await asked.done.value
    }

    /// Answers the two requests `refresh` makes after the one for the folders.
    func finishRefresh(_ asked: Asked, round: Int = 0) async {
        answer(await next("pending_review", after: round), .success(reviewList(1)))
        answer(await next("monitor_status", after: round), .success(monitorStatus(enabled: false)))
        await asked.done.value
    }
}

func json(_ value: Any) -> String {
    String(decoding: (try? JSONSerialization.data(withJSONObject: value)) ?? Data(), as: UTF8.self)
}

/// A review list with this many open findings, each drawn at `revision`.
func reviewList(_ open: Int, revision: Int = 1) -> String {
    let items: [[String: Any]] = (0..<open).map {
        ["id": $0 + 1, "rule": "fixture-rule", "path": "~/fixture-\($0 + 1).txt",
         "title": "Synthetic finding", "explanation": "Review fixture",
         "severity": "high", "state": "open", "revision": revision]
    }
    return json(["items": items,
                 "counts": ["open": open, "set_aside": 0, "kept": 0, "fixed": 0],
                 "skipped": [String](), "full": false])
}

func reviewStates(_ states: [String], revision: Int = 1, full: Bool = false) -> String {
    let items: [[String: Any]] = states.enumerated().map { index, state in
        ["id": index + 1, "rule": "fixture-rule", "path": "~/fixture-\(index + 1).txt",
         "title": "Synthetic finding \(index + 1)", "explanation": "Review fixture",
         "severity": "high", "state": state,
         "set_aside": state == "set-aside" ? "not-a-credential" : NSNull(), "revision": revision]
    }
    return json(["items": items,
                 "counts": ["open": states.filter { $0 == "open" }.count,
                            "set_aside": states.filter { $0 == "set-aside" }.count,
                            "kept": 0, "fixed": states.filter { $0 == "fixed" }.count],
                 "skipped": [String](), "full": full])
}

/// A list of findings worth reviewing and stored sign-ins, as the engine
/// sends both: each entry's state, and whether it is a stored sign-in. Ids
/// count from 1, and the revision rises with them.
func kindsList(_ entries: [(state: String, stored: Bool)], full: Bool = false, storedFull: Bool = false,
               storedChecked: Bool = true, storedGone: Int = 0) -> String {
    let items: [[String: Any]] = entries.enumerated().map { index, entry in
        ["id": index + 1, "kind": entry.stored ? "inventory" : "review", "rule": "fixture-rule",
         "path": "~/fixture-\(index + 1).txt", "title": entry.stored ? "Synthetic sign-in \(index + 1)" : "Synthetic finding \(index + 1)",
         "explanation": "Review fixture", "severity": entry.stored ? "low" : "high", "state": entry.state,
         "set_aside": entry.state == "set-aside" ? (entry.stored ? "kept" : "not-a-credential") : NSNull(),
         "revision": index + 1]
    }
    let count = { (state: String, stored: Bool) in entries.filter { $0.state == state && $0.stored == stored }.count }
    return json(["items": items,
                 "counts": ["open": count("open", false), "set_aside": count("set-aside", false), "kept": 0,
                            "fixed": count("fixed", false), "stored": count("open", true),
                            "stored_set_aside": count("set-aside", true), "stored_gone": storedGone],
                 "skipped": [String](), "full": full, "stored_full": storedFull, "stored_checked": storedChecked])
}

@MainActor func multipleReviewSelection() async {
    let bench = Bench()
    bench.model.pane = .review
    let read = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(read, .success(reviewStates(["open", "open", "fixed"])))
    bench.model.selectedReviews = [1, 2, 3]
    check(bench.model.currentReview == nil && bench.model.currentReviews.count == 3,
          "multiple selection never inspects an arbitrary item")
    bench.model.search = "fixture-2"
    check(bench.model.selectedReviews == [2], "filtering retains only visible selections")
    bench.model.search = ""
    bench.model.selectedReviews = [1, 2, 3]
    let first = await bench.ask("decide_review") { $0.decideSelection(reason: "testing") }
    check(first.call.args["id"] as? Int == 1 && first.call.args["revision"] as? Int == 1,
          "batch sends the first displayed id and revision")
    bench.model.decideSelection(reason: "kept")
    check(await bench.holdsOnly(1, "decide_review"), "repeated presses cannot overlap a batch")
    // A later selection must not change the captured targets.
    bench.model.selectedReview = 3
    await bench.answer(first, .success("null"))
    let second = await bench.next("decide_review", after: 1)
    check(second.args["id"] as? Int == 2 && second.args["revision"] as? Int == 1
          && second.args["reason"] as? String == "testing", "batch keeps the drawn targets and reason")
    bench.answer(second, .success("null"))
    bench.answer(await bench.next("pending_review", after: 1), .success(reviewStates(["set-aside", "set-aside", "fixed"])))
    await eventually("batch refresh finishes") { !bench.model.decidingSelection }
    check(bench.model.selectedReviews == [3] && bench.engine.held("decide_review").count == 2,
          "fixed items are skipped and a later visible selection survives")

    bench.model.pane = .setAside
    bench.model.selectedReviews = [1, 2]
    let failed = await bench.ask("decide_review") { $0.decideSelection(reason: nil) }
    await bench.answer(failed, .failure(EngineError(message: "The finding changed.")))
    bench.answer(await bench.next("pending_review", after: 2), .success(reviewStates(["set-aside", "set-aside", "fixed"], revision: 2)))
    await eventually("failed batch refresh finishes") { !bench.model.decidingSelection }
    check(bench.model.failure != nil && bench.engine.held("decide_review").count == 3,
          "a refusal is shown after refreshing and stops the remaining decisions")
    check(bench.model.selectedReviews == [1, 2], "failed decisions retain visible selections")
}

@MainActor func setAsideLeavesReview() async {
    let bench = Bench()
    bench.model.pane = .review
    let read = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(read, .success(reviewStates(["open", "open"])))
    guard let item = bench.model.reviewRows.last else { return check(false, "a finding is available") }
    bench.model.selectedReview = item.id
    let decision = await bench.ask("decide_review") { $0.decide(item, reason: "not-a-credential") }
    check(bench.model.reviewRows.count == 2, "a pending decision keeps the finding visible")
    await bench.answer(decision, .success("null"))
    bench.answer(await bench.next("pending_review", after: 1), .success(reviewStates(["open", "set-aside"])))
    await eventually("the saved decision is read") { bench.model.review?.counts?.setAside == 1 }
    check(bench.model.reviewRows.map(\.id) == [1], "set-aside findings leave Worth Reviewing")
    check(bench.model.selectedReview == nil && bench.model.currentReview == nil,
          "the moved finding is no longer selected or inspected in Worth Reviewing")
    check(bench.model.pane == .review, "setting aside keeps the person in Worth Reviewing")
    check(bench.model.review?.items.count == 2 && bench.model.reviewCount == 1,
          "the decision changes the attention count without dropping the finding")
    bench.model.pane = .setAside
    check(bench.model.reviewRows.map(\.id) == [2] && bench.model.setAsideCount == 1,
          "the separate Set Aside page lists the decided finding")
    bench.model.selectedReview = item.id
    bench.model.search = "finding 2"
    check(bench.model.pane == .setAside && bench.model.currentReview?.id == item.id,
          "filtering Set Aside keeps the page and the matching selection")
    bench.model.search = "no match"
    check(bench.model.selectedReview == nil, "filtering out a set-aside finding clears its selection")
    bench.model.search = ""
    bench.model.selectedReview = item.id
    guard let aside = bench.model.currentReview else { return check(false, "a set-aside finding can be inspected") }
    let returned = await bench.ask("decide_review") { $0.decide(aside, reason: nil) }
    check(returned.call.args["id"] as? Int == item.id && returned.call.args["revision"] as? Int == item.revision
          && returned.call.args["reason"] is NSNull, "Move to Worth Reviewing uses the drawn id and revision")
    await bench.answer(returned, .success("null"))
    bench.answer(await bench.next("pending_review", after: 2), .success(reviewStates(["open", "open"])))
    await eventually("the returned finding is shown in Worth Reviewing") {
        bench.model.setAsideCount == 0 && bench.model.pane == .review
    }
    check(bench.model.pane == .review && bench.model.currentReview?.id == item.id,
          "Move to Worth Reviewing follows the finding to its review row")
    check(bench.model.reviewRows.count == 2, "returning restores the review queue")
}

/// Lets main-actor work that is already queued, such as what a saved
/// decision does after its refresh, run before a check that it did nothing.
@MainActor func drainMainActor() async {
    for _ in 0..<100 { await Task.yield() }
}

@MainActor func setAsideMoveYieldsToLaterChoice() async {
    let bench = Bench()
    bench.model.pane = .setAside
    let read = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(read, .success(reviewStates(["set-aside", "set-aside"])))
    bench.model.selectedReview = 1
    guard let first = bench.model.currentReview else { return check(false, "a set-aside finding is selected") }
    let moved = await bench.ask("decide_review") { $0.decide(first, reason: nil) }
    bench.model.selectedReview = 2
    await bench.answer(moved, .success("null"))
    bench.answer(await bench.next("pending_review", after: 1), .success(reviewStates(["open", "set-aside"])))
    await eventually("the first move is read") { bench.model.setAsideCount == 1 }
    await drainMainActor()
    check(bench.model.pane == .setAside && bench.model.currentReview?.id == 2,
          "a row chosen while a move is saved stays chosen on Set Aside")
    guard let second = bench.model.currentReview else { return check(false, "the second finding is selected") }
    let again = await bench.ask("decide_review") { $0.decide(second, reason: nil) }
    bench.model.pane = .review
    bench.model.pane = .setAside
    await bench.answer(again, .success("null"))
    bench.answer(await bench.next("pending_review", after: 2), .success(reviewStates(["open", "open"])))
    await eventually("the second move is read") { bench.model.setAsideCount == 0 }
    await drainMainActor()
    check(bench.model.pane == .setAside,
          "leaving Set Aside and coming back while a move is saved keeps the person there")
}

@MainActor func setAsideFailuresAndChanges() async {
    let bench = Bench()
    bench.model.pane = .review
    let read = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(read, .success(reviewStates(["open"], revision: 7)))
    guard let item = bench.model.reviewRows.first else { return check(false, "a finding is available") }
    let failed = await bench.ask("decide_review") { $0.decide(item, reason: "not-a-credential") }
    await bench.answer(failed, refused)
    bench.answer(await bench.next("pending_review", after: 1), .success(reviewStates(["open"], revision: 7)))
    await eventually("a refused decision is reported") { bench.model.failure != nil }
    check(bench.model.reviewRows.count == 1, "a failed decision keeps the row in review")
    bench.model.failure = nil
    let saved = await bench.ask("decide_review") { $0.decide(item, reason: "not-a-credential") }
    await bench.answer(saved, .success("null"))
    bench.answer(await bench.next("pending_review", after: 2), .success(reviewStates(["set-aside"], revision: 7)))
    await eventually("the saved decision is read") { bench.model.setAsideCount == 1 }
    check(bench.model.reviewPaneItems.isEmpty && bench.model.review?.items.count == 1,
          "an entirely set-aside list has an empty review queue, not missing findings")
    bench.model.pane = .setAside
    bench.model.selectedReview = item.id
    guard let drawn = bench.model.currentReview else { return check(false, "a set-aside finding is selected") }
    // The value changes after the inspector was drawn. Move to Worth Reviewing must
    // retain that revision so the engine can refuse to act on the new value.
    let changed = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(changed, .success(reviewStates(["open"], revision: 9)))
    let returned = await bench.ask("decide_review") { $0.decide(drawn, reason: nil) }
    check(returned.call.args["id"] as? Int == 1 && returned.call.args["revision"] as? Int == 7,
          "Move to Worth Reviewing names the drawn value, never a later value with the same id")
    await bench.answer(returned, refused)
    bench.answer(await bench.next("pending_review", after: 4), .success(reviewStates(["open"], revision: 9)))
    await eventually("the stale Move to Worth Reviewing refusal is reported") { bench.model.failure != nil }
    check(bench.model.pane == .setAside && bench.model.currentReview == nil
          && bench.model.reviewEntry(1)?.revision == 9,
          "a stale Move to Worth Reviewing preserves the new finding and does not navigate as if saved")
    bench.model.failure = nil
    bench.model.pane = .setAside
    let aside = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(aside, .success(reviewStates(["set-aside"], revision: 9)))
    bench.model.selectedReview = 1
    let reopened = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(reopened, .success(reviewStates(["open"], revision: 10)))
    check(bench.model.reviewRows.isEmpty && bench.model.selectedReview == nil && bench.model.currentReview == nil,
          "a finding reopened by a scan leaves Set Aside and clears its inspector")
    // Held again before the failed read, so the checks below hold only
    // because a list that cannot be used is neither counted nor inspected.
    let asideAgain = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(asideAgain, .success(reviewStates(["set-aside"], revision: 10)))
    bench.model.selectedReview = 1
    check(bench.model.setAsideCount == 1 && bench.model.currentReview?.id == 1,
          "a finding set aside again is listed and inspected")
    bench.model.results = try? decodeEngine(ScanResults.self, from: Data(scanResults(review: 5).utf8))
    let unread = await bench.ask("pending_review") { await $0.refreshReview(reportFailure: false) }
    await bench.answer(unread, refused)
    // A scan knows nothing of decisions, so its count is not a Set Aside count.
    check(bench.model.reviewProblem != nil && bench.model.setAsideCount == 0 && bench.model.currentReview == nil,
          "an unavailable Set Aside list shows no count and never claims an empty result")
}

func monitorStatus(enabled: Bool, paused: Bool = false, menuBar: Bool = false, running: Bool? = nil,
                   updateCheck: Bool? = nil, error: String? = nil, fullPass: String? = nil) -> String {
    var health: [String: Any] = [:]
    if let running { health["running"] = running }
    if let fullPass { health["full_pass"] = fullPass }
    return json(["enabled": enabled, "paused": paused, "scanning": false, "login": enabled ? 2 : 1,
                 "menu_bar": menuBar, "app_login": menuBar && enabled ? 2 : 1,
                 "update_check": updateCheck.map { $0 as Any } ?? NSNull(), "error": error.map { $0 as Any } ?? NSNull(),
                 "health": health, "pending_delivery": false, "attempts": 0])
}

func places(_ extra: [String], error: String? = nil) -> String {
    json(["home": "~", "extra": extra, "error": error.map { $0 as Any } ?? NSNull()])
}

/// What a scan that found this many review findings answers.
func scanResults(review: Int, stored: Int = 0) -> String {
    json(["status": "partial", "tool_version": "0.0.0-test", "generated_at": "2026-10-13T00:00:00Z",
          "review": review, "stored": stored, "not_checked": 0, "groups": [Any](), "gaps": [Any](),
          "roots": ["~"], "excluded": [String](), "limitations": ""])
}

let refused = Result<String, EngineError>.failure(EngineError(message: "That action stopped unexpectedly."))

// MARK: The review list
//
// These four cases once put two requests for the list at the engine together
// and answered the later one first. The window now reads the list one call at
// a time, so that order cannot happen: a request made during a read is sent
// only when that read has answered. Each case keeps what it said of the list
// shown at the end, and reaches it in the one order left.

@MainActor func reviewOlderListBeforeNewer() async {
    let bench = Bench()
    let older = await bench.ask("pending_review") { await $0.refreshReview() }
    let newer = await bench.request { await $0.refreshReview() }
    check(await bench.holdsOnly(1, "pending_review"),
          "review: a request made during a read of the list is not sent beside it")
    await bench.answer(older, .success(reviewList(0)))
    bench.answer(await bench.next("pending_review", after: 1), .success(reviewList(1)))
    await newer.value
    check(bench.model.openCount == 1 && bench.model.reviewRows.count == 1,
          "review: an older, empty list does not replace the newer one")
    check(bench.model.reviewProblem == nil, "review: no problem is reported for it")
    check(bench.engine.mostAtOnce("pending_review") == 1, "review: the older list cannot arrive after the newer")
}

@MainActor func reviewOlderFailureBeforeNewer() async {
    let bench = Bench()
    let older = await bench.ask("pending_review") { await $0.refreshReview() }
    let newer = await bench.request { await $0.refreshReview() }
    await bench.answer(older, refused)
    check(bench.model.reviewProblem == nil && bench.model.failure == nil,
          "review: a read that fails while a later request waits reports nothing: the next read answers")
    bench.answer(await bench.next("pending_review", after: 1), .success(reviewList(2)))
    await newer.value
    check(bench.model.reviewProblem == nil && bench.model.failure == nil,
          "review: an older request that failed reports nothing over the newer list")
    check(bench.model.reviewCount == 2 && bench.model.reviewRows.count == 2,
          "review: the newer list is shown and counted after it")
}

@MainActor func reviewNewestFailure() async {
    let bench = Bench()
    bench.model.results = try? decodeEngine(ScanResults.self, from: Data(scanResults(review: 3).utf8))
    let older = await bench.ask("pending_review") { await $0.refreshReview() }
    let newest = await bench.request { await $0.refreshReview() }
    await bench.answer(older, .success(reviewList(1)))
    bench.model.selectedReview = 1
    check(bench.model.currentReview?.id == 1, "review: an older list is shown until a newer answer comes")
    bench.answer(await bench.next("pending_review", after: 1), refused)
    await newest.value
    check(bench.model.reviewProblem != nil && bench.model.failure != nil,
          "review: the newest request's failure is reported")
    check(bench.model.reviewCount == 3, "review: the count is then the scan's own, never none")
    check(bench.model.currentReview == nil, "review: no finding of the list that cannot be used is current")
}

@MainActor func reviewOlderListBeforeNewestFailure() async {
    let bench = Bench()
    bench.model.results = try? decodeEngine(ScanResults.self, from: Data(scanResults(review: 3).utf8))
    let older = await bench.ask("pending_review") { await $0.refreshReview() }
    let newest = await bench.request { await $0.refreshReview() }
    await bench.answer(older, .success(reviewList(0)))
    bench.answer(await bench.next("pending_review", after: 1), refused)
    await newest.value
    check(bench.model.reviewProblem != nil,
          "review: an older, empty list does not hide the newest failure")
    check(bench.model.reviewCount == 3, "review: the count stays the scan's own after it")
    check(bench.engine.mostAtOnce("pending_review") == 1, "review: the older list cannot arrive after the failure")
}

@MainActor func reviewOneReadAtATime() async {
    let bench = Bench()
    let first = await bench.ask("pending_review") { await $0.refreshReview() }
    let second = await bench.request { await $0.refreshReview() }
    let third = await bench.request { await $0.refreshReview() }
    check(await bench.holdsOnly(1, "pending_review"),
          "review: requests made during a read of the list wait for it")
    // What the first call read is from before the later two were made.
    await bench.answer(first, .success(reviewList(0)))
    bench.answer(await bench.next("pending_review", after: 1), .success(reviewList(2)))
    await second.value
    await third.value
    check(bench.model.openCount == 2 && bench.model.reviewRows.count == 2,
          "review: the list read after the last request is the one shown")
    check(bench.engine.held("pending_review").count == 2,
          "review: the requests made during one read share the next one")
    check(bench.engine.mostAtOnce("pending_review") == 1, "review: the list is never read twice at once")
}

@MainActor func reviewChangeDuringRead() async {
    let bench = Bench()
    let first = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(first, .success(reviewList(2)))
    guard let row = bench.model.reviewRows.first else { return check(false, "review: the list is shown") }
    let reading = await bench.ask("pending_review") { await $0.refreshReview() }
    let decision = await bench.ask("decide_review") { $0.decide(row, reason: "kept") }
    bench.answer(decision.call, .success("null"))
    check(await bench.holdsOnly(2, "pending_review"),
          "review: the list is not asked for again beside a read that began before the change")
    // That read may have been made before the change was.
    await bench.answer(reading, .success(reviewList(2)))
    bench.answer(await bench.next("pending_review", after: 2), .success(reviewList(1)))
    await eventually("the list read after the change is shown") { bench.model.openCount == 1 }
    check(bench.model.reviewRows.count == 1 && bench.model.reviewProblem == nil && bench.model.failure == nil,
          "review: the list read after a change is the one shown")
    check(bench.engine.mostAtOnce("pending_review") == 1, "review: a change does not read the list beside another read")
}

@MainActor func reviewFailureThenNextRead() async {
    let bench = Bench()
    bench.model.results = try? decodeEngine(ScanResults.self, from: Data(scanResults(review: 5).utf8))
    let first = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(first, .success(reviewList(2)))
    let failing = await bench.ask("pending_review") { await $0.refreshReview() }
    let after = await bench.request { await $0.refreshReview() }
    await bench.answer(failing, refused)
    check(bench.model.reviewProblem == nil && bench.model.failure == nil
          && bench.model.reviewCount == 2 && bench.model.reviewRows.count == 2,
          "review: the last list read stays shown while the read after a failed one is made")
    bench.answer(await bench.next("pending_review", after: 2), .success(reviewList(3)))
    await after.value
    check(bench.model.reviewCount == 3 && bench.model.reviewRows.count == 3 && bench.model.reviewProblem == nil,
          "review: the list read after a failed read is the one shown")
    let last = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(last, refused)
    check(bench.model.reviewProblem != nil && bench.model.failure != nil,
          "review: a failed read that no later request follows is reported")
    check(bench.model.reviewCount == 5 && bench.model.review?.items.count == 3,
          "review: the count is then the scan's own and the last list read is kept, never an empty one")
    check(bench.engine.mostAtOnce("pending_review") == 1, "review: a failed read is not retried beside another read")
}

/// Requests that share a read share whether its failure is shown in an
/// alert: shown if any of them asked for one, and not otherwise.
@MainActor func reviewFailureAlertsForAnyRequest() async {
    let bench = Bench()
    // A refresh's read fails while a poll waits: the poll's read answers for both.
    let refresh = await bench.ask("pending_review") { await $0.refreshReview() }
    let poll = await bench.request { await $0.refreshReview(reportFailure: false) }
    await bench.answer(refresh, refused)
    bench.answer(await bench.next("pending_review", after: 1), refused)
    await poll.value
    check(bench.model.reviewProblem != nil && bench.model.failure?.title == FailureTitle.openReview,
          "review: a refresh's failure, answered by a poll's read, is still shown in an alert")
    bench.model.failure = nil
    // A refresh's read that works answers for it: the poll after it alerts nothing.
    let shown = await bench.ask("pending_review") { await $0.refreshReview() }
    let later = await bench.request { await $0.refreshReview(reportFailure: false) }
    await bench.answer(shown, .success(reviewList(1)))
    bench.answer(await bench.next("pending_review", after: 3), refused)
    await later.value
    check(bench.model.reviewProblem != nil && bench.model.failure == nil,
          "review: a poll's failure after a refresh that worked opens no alert")
}

/// A press names the row by its id and the revision it was drawn with. The
/// engine refuses a press without the revision it holds for that row.
@MainActor func reviewPressNamesTheRowDrawn() async {
    let bench = Bench()
    let first = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(first, .success(reviewList(1, revision: 7)))
    guard let drawn = bench.model.reviewRows.first else { return check(false, "review: the list is shown") }
    let decision = await bench.ask("decide_review") { $0.decide(drawn, reason: "kept") }
    check(decision.call.args["id"] as? Int == 1 && decision.call.args["revision"] as? Int == 7,
          "review: a decision is sent with the row's id and the revision it was drawn with")
    check(decision.call.args["reason"] as? String == "kept", "review: a decision is sent with its reason")
    bench.answer(decision.call, .success("null"))
    // The value at that place has been replaced: same id, a later revision.
    bench.answer(await bench.next("pending_review", after: 1), .success(reviewList(1, revision: 9)))
    await eventually("the list read after the decision is shown") { bench.model.reviewRows.first?.revision == 9 }
    guard let redrawn = bench.model.reviewRows.first else { return check(false, "review: the list is shown again") }
    let undone = await bench.ask("decide_review") { $0.decide(redrawn, reason: nil) }
    check(undone.call.args["id"] as? Int == 1 && undone.call.args["revision"] as? Int == 9,
          "review: a press is sent with the revision the row was last drawn with, not an earlier one")
    check(undone.call.args["reason"] is NSNull, "review: returning a row to review is sent with no reason")
    bench.answer(undone.call, .success("null"))
    bench.answer(await bench.next("pending_review", after: 2), .success(reviewList(1, revision: 9)))
}

// MARK: Background checks
//
// As for the review list: the status is read one call at a time, so an older
// status cannot arrive after a newer one.

@MainActor func monitorOlderStatusBeforeNewer() async {
    let bench = Bench()
    let older = await bench.ask("monitor_status") { await $0.refreshMonitor() }
    let newer = await bench.request { await $0.refreshMonitor() }
    check(await bench.holdsOnly(1, "monitor_status"),
          "monitor: a request made during a read of the status is not sent beside it")
    await bench.answer(older, .success(monitorStatus(enabled: true)))
    bench.answer(await bench.next("monitor_status", after: 1), .success(monitorStatus(enabled: false)))
    await newer.value
    check(bench.model.monitor?.enabled == false,
          "monitor: an older status does not turn consent back on in the window")
    check(bench.engine.held("monitor_status").count == 2 && bench.engine.mostAtOnce("monitor_status") == 1,
          "monitor: the older status cannot arrive after the newer")
}

@MainActor func monitorOlderFailureBeforeNewer() async {
    let bench = Bench()
    let first = await bench.ask("monitor_status") { await $0.refreshMonitor() }
    await bench.answer(first, .success(monitorStatus(enabled: false)))
    let older = await bench.ask("monitor_status") { await $0.refreshMonitor() }
    let newer = await bench.request { await $0.refreshMonitor() }
    await bench.answer(older, refused)
    check(bench.model.monitor?.enabled == false,
          "monitor: the last status read stays shown while the read after a failed one is made")
    bench.answer(await bench.next("monitor_status", after: 2), .success(monitorStatus(enabled: true)))
    await newer.value
    check(bench.model.monitor?.enabled == true,
          "monitor: an older request that failed does not take the newer status away")
}

@MainActor func monitorNewestFailure() async {
    let bench = Bench()
    let older = await bench.ask("monitor_status") { await $0.refreshMonitor() }
    let newest = await bench.request { await $0.refreshMonitor() }
    await bench.answer(older, .success(monitorStatus(enabled: true)))
    check(bench.model.monitor?.enabled == true, "monitor: an older status is shown until a newer answer comes")
    bench.answer(await bench.next("monitor_status", after: 1), refused)
    await newest.value
    check(bench.model.monitor == nil, "monitor: after the newest request fails the status is unavailable, not the older one")
}

@MainActor func monitorFailureKeepsReason() async {
    let bench = Bench()
    await status(bench, refused)
    check(bench.model.monitor == nil && bench.model.monitorUnread == "That action stopped unexpectedly.",
          "monitor: a status the engine refused is unavailable, with the engine's reason")
    await status(bench, .success(monitorStatus(enabled: false)))
    check(bench.model.monitor != nil && bench.model.monitorUnread == nil, "monitor: a status read that works clears the reason")
    // An answer the window can't decode is a failure too, with a reason.
    await status(bench, .success("{}"))
    check(bench.model.monitor == nil && !(bench.model.monitorUnread ?? "").isEmpty,
          "monitor: a status that couldn't be decoded is unavailable, with a reason")
}

// MARK: Places to check

@MainActor func placesOlderListAfterRemoval() async {
    let bench = Bench()
    let read = await bench.ask("places") { await $0.refresh() }
    let removal = await bench.ask("remove_place") { $0.removeFolder(0, shown: "/Volumes/Fixture") }
    bench.answer(removal.call, .success(places([])))
    await eventually("the folders after the removal are shown") { bench.model.places != nil }
    bench.answer(read.call, .success(places(["/Volumes/Fixture"])))
    await bench.finishRefresh(read)
    check(bench.model.places?.extra == [],
          "places: a list asked for before a folder was removed does not put the folder back")
}

@MainActor func placesOlderFailureAfterNewer() async {
    let bench = Bench()
    let read = await bench.ask("places") { await $0.refresh() }
    let removal = await bench.ask("remove_place") { $0.removeFolder(0, shown: "/Volumes/Fixture") }
    bench.answer(removal.call, .success(places(["/Volumes/Other"])))
    await eventually("the folders after the removal are shown") { bench.model.places != nil }
    bench.answer(read.call, refused)
    await bench.finishRefresh(read)
    check(bench.model.places?.extra == ["/Volumes/Other"] && bench.model.failure == nil,
          "places: an older request that fails late does not take the newer list away")
}

@MainActor func placesRemovalRefusal() async {
    for problem in ["Wait for the scan to finish.", "Could not save the review list."] {
        let bench = Bench()
        let first = await bench.ask("places") { await $0.refresh() }
        bench.answer(first.call, .success(places(["/Volumes/Fixture"])))
        await bench.finishRefresh(first)
        let removal = await bench.ask("remove_place") { $0.removeFolder(0, shown: "/Volumes/Fixture") }
        bench.answer(removal.call, .success(places(["/Volumes/Fixture"], error: problem)))
        await eventually("the refused removal's response is applied") { bench.model.places?.error == problem }
        check(bench.model.failure?.reason == EngineText.shown(problem),
              "places: a refusal inside a successful removal response is reported")
        check(bench.model.places?.home == "~" && bench.model.places?.extra == ["/Volumes/Fixture"],
              "places: a refused removal keeps the usable folder list")
    }
}

@MainActor func placesNewestFailure() async {
    let bench = Bench()
    let first = await bench.ask("places") { await $0.refresh() }
    bench.answer(first.call, .success(places(["/Volumes/Fixture"])))
    await bench.finishRefresh(first)
    let second = await bench.ask("places") { await $0.refresh() }
    bench.answer(second.call, refused)
    await bench.finishRefresh(second, round: 1)
    check(bench.model.places?.home == "~" && bench.model.places?.extra == ["/Volumes/Fixture"],
          "places: a request that fails leaves the folders shown, not an empty list")
    check(bench.model.failure != nil, "places: the newest request's failure is reported")
}

/// A list of folders that couldn't be read at launch is read again when the
/// person presses Scan Now, rather than the press doing nothing.
@MainActor func placesReadAgainBeforeScan() async {
    let bench = Bench()
    let first = await bench.ask("places") { await $0.refresh() }
    bench.answer(first.call, refused)
    // The review list's failure comes after, in the same refresh.
    bench.answer(await bench.next("pending_review"), refused)
    bench.answer(await bench.next("monitor_status"), .success(monitorStatus(enabled: false)))
    await first.done.value
    check(bench.model.places == nil, "places: a list that couldn't be read is not an empty one")
    bench.model.startScan()
    bench.answer(await bench.next("places", after: 1), refused)
    await eventually("the failed read ends the scan") { !bench.model.preparingAccess && bench.model.phase == .ready }
    check(bench.model.failure?.title == FailureTitle.readPlaces && bench.engine.held("prepare_access").isEmpty,
          "places: Scan Now says the folders still couldn't be read, and asks for no folder access")
    bench.model.failure = nil
    bench.model.startScan()
    bench.answer(await bench.next("places", after: 2), .success(places([])))
    let access = await bench.next("prepare_access")
    check(bench.model.places?.home == "~", "places: Scan Now reads the folders again, then scans")
    bench.model.cancelAccessPreparation()
    bench.answer(access, .success("null"))
    await eventually("the cancelled preparation ends") { !bench.model.preparingAccess }
}

// MARK: A scan in progress

@MainActor func folderAccessBeforeWork() async {
    for background in [false, true] {
        let clock = HeldSleep()
        let now = FakeNow()
        let bench = Bench(clock: clock, now: now)
        bench.model.places = try? decodeEngine(ScanPlaces.self, from: Data(places([]).utf8))
        if background { bench.model.setMonitoring(enabled: true, paused: false) }
        else { bench.model.startScan() }
        for index in 0..<3 {
            let access = await bench.next("prepare_access", after: index)
            check(access.args["index"] as? Int == index, "access: folders are requested in order")
            bench.model.startScan()
            bench.model.setMonitoring(enabled: true, paused: false)
            check(await bench.holdsOnly(0, "start_scan") && bench.engine.held("set_monitoring").isEmpty,
                  "access: repeated actions cannot start work while access is pending")
            bench.answer(access, .success("null"))
        }
        if background {
            let enabled = await bench.next("set_monitoring")
            check(enabled.args["enabled"] as? Bool == true, "access: enabling follows preparation")
            bench.answer(enabled, .success("null"))
            bench.answer(await bench.next("monitor_status"), .success(monitorStatus(enabled: true)))
            await clock.wake(after: 2_000_000_000)
            bench.answer(await bench.next("monitor_status", after: 1), .success(monitorStatus(enabled: true)))
            // The helper takes a few seconds to start: starting, not stopped.
            bench.model.monitor = try? decodeEngine(MonitorStatus.self, from: Data(monitorStatus(enabled: true, running: false).utf8))
            check(bench.model.backgroundState == .starting,
                  "background status: just turned on, a helper not yet running is starting")
            now.date += 16
            check(bench.model.backgroundState == .helperNotRunning,
                  "background status: still not running 15 seconds after turning on, the helper is stopped")
        } else {
            bench.answer(await bench.next("start_scan"), .success(scanResults(review: 0)))
            bench.answer(await bench.next("pending_review"), .success(reviewList(0)))
            await eventually("prepared scan finishes") { bench.model.phase == .done }
        }
    }
}

@MainActor func folderAccessCancellationAndFailure() async {
    for background in [false, true] {
        for fails in [false, true] {
            let bench = Bench()
            bench.model.places = try? decodeEngine(ScanPlaces.self, from: Data(places([]).utf8))
            if background { bench.model.setMonitoring(enabled: true, paused: false) }
            else { bench.model.startScan() }
            let access = await bench.next("prepare_access")
            if fails {
                bench.answer(access, .failure(EngineError(message: "Synthetic access command failure")))
            } else {
                bench.model.cancelAccessPreparation()
                bench.answer(access, .success("null"))
            }
            await eventually("access preparation ends") { !bench.model.preparingAccess }
            check(await bench.holdsOnly(1, "prepare_access"), "access: cancellation or failure stops subsequent requests")
            check(bench.engine.held("start_scan").isEmpty && bench.engine.held("set_monitoring").isEmpty,
                  "access: cancellation or failure cannot start a scan or grant background consent")
            check(bench.model.phase == .ready && (bench.model.failure != nil) == fails,
                  "access: cancellation restores the page and command failure is visible")
        }
    }
}

@MainActor func scanDoesNotHoldRefreshes() async {
    let bench = Bench()
    bench.model.places = try? decodeEngine(ScanPlaces.self, from: Data(places([]).utf8))
    bench.model.startScan()
    for index in 0..<3 {
        bench.answer(await bench.next("prepare_access", after: index), .success("null"))
    }
    let scan = await bench.next("start_scan")
    let older = await bench.ask("pending_review") { await $0.refreshReview() }
    let newer = await bench.request { await $0.refreshReview() }
    // Only reads of the same thing take turns. The status and a press on
    // Stop reach the engine while the scan and a read of the list are out.
    let status = await bench.ask("monitor_status") { await $0.refreshMonitor() }
    let stop = await bench.ask("cancel_scan") { $0.cancelScan() }
    check(bench.engine.held("pending_review").count == 1 && bench.model.phase == .scanning,
          "scan: the status and Stop are sent while the scan and a read of the list are still out")
    bench.answer(stop.call, .success("null"))
    await bench.answer(status, .success(monitorStatus(enabled: false)))
    await bench.answer(older, .success(reviewList(0)))
    bench.answer(await bench.next("pending_review", after: 1), .success(reviewList(1)))
    await newer.value
    check(bench.model.phase == .scanning && bench.model.openCount == 1,
          "scan: the list is refreshed, in order, while a scan is still running")
    bench.answer(scan, .success(scanResults(review: 2)))
    bench.answer(await bench.next("pending_review", after: 2), .success(reviewList(2)))
    await eventually("the scan finishes") { bench.model.phase == .done }
    check(bench.model.openCount == 2 && bench.model.failure == nil,
          "scan: the list asked for when the scan ends is the one shown")
}

/// The helper writes in a separate process and sends no event to this window.
@MainActor func foregroundFollowsHelper() async {
    let clock = HeldSleep()
    let bench = Bench(clock: clock)
    bench.model.becameActive()
    bench.model.becameActive()
    bench.answer(await bench.next("pending_review"), .success(reviewList(0)))
    bench.answer(await bench.next("monitor_status"), .success(monitorStatus(enabled: true)))
    // No activation, scan or injected engine event accompanies the new finding.
    await clock.wake(after: 5_000_000_000)
    bench.answer(await bench.next("pending_review", after: 1), .success(reviewList(1)))
    bench.answer(await bench.next("monitor_status", after: 1), .success(monitorStatus(enabled: true)))
    await eventually("a helper finding appears while the window stays active") { bench.model.openCount == 1 }
    check(bench.engine.held("start_scan").isEmpty, "following the helper never starts a scan")
    await clock.wake(after: 5_000_000_000)
    bench.answer(await bench.next("pending_review", after: 2), refused)
    let status = await bench.next("monitor_status", after: 2)
    check(bench.model.reviewProblem != nil && bench.model.failure == nil,
          "automatic read failure is visible without a repeating modal alert")
    bench.model.becameInactive()
    bench.answer(status, refused)
    await eventually("failed status becomes unavailable") { bench.model.monitor == nil }
    await eventually("the late status answer reaches the cancelled timer") { clock.cancelled == 1 }
    check(await bench.holdsOnly(3, "pending_review"),
          "leaving the foreground cancels periodic reads, including one finishing after cancellation")
    check(bench.engine.mostAtOnce("pending_review") == 1,
          "repeated activation does not start parallel polling loops")
    bench.model.becameActive()
    bench.answer(await bench.next("pending_review", after: 3), .success(reviewList(1)))
    bench.answer(await bench.next("monitor_status", after: 3), .success(monitorStatus(enabled: true)))
    // wake() waits until the timer is suspended; cancel before releasing it.
    await eventually("the restarted polling loop reaches its timer") { clock.isWaiting }
    bench.model.becameInactive()
    await clock.wake(after: 5_000_000_000)
    await eventually("the sleeping timer observes cancellation") { clock.cancelled == 2 }
    check(await bench.holdsOnly(4, "pending_review"), "a cancelled sleeping timer cannot start another read")
}

/// A change made in System Settings reaches the window only when it asks.
@MainActor func activationRereadsNotificationPermission() async {
    let bench = Bench()
    bench.model.becameActive()
    bench.answer(await bench.next("refresh_notifications"), .success("null"))
    bench.model.becameInactive()
    bench.model.awaitingPermission = true
    bench.model.becameActive()
    check(await bench.holdsOnly(1, "refresh_notifications"),
          "notifications: no second read while macOS is asking")
    bench.model.becameInactive()
}

@MainActor func backgroundStatusIsHonest() async {
    let model = AppModel(engine: HeldEngine())
    check(model.backgroundState == .unavailable, "missing status is unavailable")
    for (enabled, paused, login, running, expected) in [
        (false, false, 1, false, BackgroundState.off),
        (true, false, 3, false, .needsApproval),
        (true, false, 2, false, .helperNotRunning),
        (true, true, 2, false, .helperNotRunning),
        (true, true, 2, true, .paused),
        (true, false, 2, true, .active),
    ] {
        let value = json(["enabled": enabled, "paused": paused, "scanning": false, "login": login,
                          "menu_bar": false, "app_login": 1, "health": ["running": running], "pending_delivery": false, "attempts": 0])
        model.monitor = try? decodeEngine(MonitorStatus.self, from: Data(value.utf8))
        check(model.backgroundState == expected, "background status: \(expected.text)")
    }
    model.monitor = try? decodeEngine(MonitorStatus.self, from: Data(monitorStatus(enabled: true).utf8))
    check(model.backgroundState == .waitingForHelper, "registration alone is not a running helper")
    // The words each state shows. This check runs in English, so they are the source text.
    for (state, word) in [(BackgroundState.unavailable, "Unavailable"), (.off, "Off"), (.needsApproval, "Needs macOS Approval"), (.starting, "Starting…"),
                          (.helperNotRunning, "Helper Not Running"), (.waitingForHelper, "Waiting for Helper Status"),
                          (.paused, "Paused"), (.needsAttention, "Needs Attention"), (.active, "Active")] {
        check(state.text == word, "background status words: \(word), not \(state.text)")
    }
}

// MARK: Engine text
//
// The check runs in English, where the window shows the engine's text as it
// came. These cases look it up in a made-up table instead, so that what they
// check does not depend on the shipped translation.

// MARK: Checking for updates

/// A status read, answered.
@MainActor func status(_ bench: Bench, _ answer: Result<String, EngineError>) async {
    let read = await bench.ask("monitor_status") { await $0.refreshMonitor() }
    await bench.answer(read, answer)
}

@MainActor func updatesAskOnlyWhenStateUsable() async {
    let bench = Bench()
    check(!bench.model.shouldAskAboutUpdates, "updates: nothing is asked before the saved state has been read")
    await status(bench, refused)
    check(!bench.model.shouldAskAboutUpdates, "updates: nothing is asked when the status could not be read")
    await status(bench, .success(monitorStatus(enabled: false, error: "The review list is unavailable.")))
    check(!bench.model.shouldAskAboutUpdates,
          "updates: nothing is asked while the saved state cannot be used, since the answer could not be kept")
    await status(bench, .success(monitorStatus(enabled: false)))
    check(!bench.model.shouldAskAboutUpdates, "updates: not asked at first start, before any scan has an answer")
    let checked = "2026-10-13T00:00:00Z"
    await status(bench, .success(monitorStatus(enabled: true, running: true, fullPass: checked)))
    check(bench.model.shouldAskAboutUpdates,
          "updates: asked once the saved state says it never was and the helper's first full pass has an answer")
    await status(bench, refused)
    check(bench.model.shouldAskAboutUpdates, "updates: a status read that fails for a moment does not take the question away")
    await status(bench, .success(monitorStatus(enabled: false, updateCheck: true, fullPass: checked)))
    check(!bench.model.shouldAskAboutUpdates, "updates: not asked again once answered yes")
    await status(bench, .success(monitorStatus(enabled: false, fullPass: checked)))
    bench.model.answerUpdateQuestion(false)
    check(!bench.model.shouldAskAboutUpdates, "updates: an answer closes the question at once, before it is saved")
    let saved = await bench.next("set_update_check")
    check(saved.args["enabled"] as? Bool == false, "updates: Don't Check saves no")
    bench.answer(saved, .success("null"))
    bench.answer(await bench.next("monitor_status", after: 7), .success(monitorStatus(enabled: false, updateCheck: false)))
    await eventually("the status after the answer is read") { bench.model.monitor?.updateCheck == false }

    let quiet = Bench()
    await status(quiet, .success(monitorStatus(enabled: false)))
    quiet.model.quietLaunch = true
    check(!quiet.model.shouldAskAboutUpdates, "updates: nothing is asked while the app is only in the menu bar")
}

@MainActor func updatesCheckAtStartAndDaily() async {
    let clock = HeldSleep()
    let releases = HeldReleases()
    let now = FakeNow()
    let bench = Bench(clock: clock, releases: releases, now: now)
    await status(bench, .success(monitorStatus(enabled: false, updateCheck: true)))
    await eventually("the first check asks GitHub") { releases.count == 1 }
    let reply = #"{"tag_name":"v0.7.0","draft":false,"prerelease":false}"#
    releases.answer(.success(Data(reply.utf8)))
    let judged = await bench.next("check_release")
    check(judged.args["body"] as? String == reply, "updates: the engine is given GitHub's reply as it came")
    bench.answer(judged, .success(#"{"newer":"0.7.0","current":"0.6.0"}"#))
    await eventually("the newer version is shown") { bench.model.availableUpdate?.newer == "0.7.0" }
    check(bench.model.availableUpdate?.current == "0.6.0", "updates: the notice says which version this is")
    check(bench.model.updateResult == nil, "updates: an automatic check opens no alert")
    now.date += 3_600
    await clock.wake(after: 3_600_000_000_000)
    await eventually("the checks look again an hour later") { clock.isWaiting }
    check(releases.count == 1, "updates: an hour after a check, GitHub is not asked again")
    // The Mac slept through the day: a day passed with only one more look.
    now.date += 86_400
    await clock.wake(after: 3_600_000_000_000)
    await eventually("a look a day after the last check asks GitHub") { releases.count == 2 }
    releases.answer(.success(Data(reply.utf8)))
    bench.answer(await bench.next("check_release", after: 1), .success(#"{"newer":null,"current":"0.7.0"}"#))
    await eventually("a check that finds nothing newer takes the notice away") { bench.model.availableUpdate == nil }
    await status(bench, .success(monitorStatus(enabled: false, updateCheck: true)))
    check(releases.count == 2, "updates: a later status read starts no second loop of checks")
}

@MainActor func updatesDailyLoopSurvivesFailure() async {
    let clock = HeldSleep()
    let releases = HeldReleases()
    let now = FakeNow()
    let bench = Bench(clock: clock, releases: releases, now: now)
    await status(bench, .success(monitorStatus(enabled: false, updateCheck: true)))
    await eventually("the first check asks GitHub") { releases.count == 1 }
    releases.answer(.failure(URLError(.notConnectedToInternet)))
    now.date += 3_600
    await clock.wake(after: 3_600_000_000_000)
    check(bench.model.availableUpdate == nil && bench.model.failure == nil && bench.model.updateResult == nil,
          "updates: an automatic check that fails shows nothing")
    await eventually("the checks look again an hour later") { clock.isWaiting }
    check(releases.count == 1, "updates: a failed check waits for the next day")
    now.date += 86_400
    await clock.wake(after: 3_600_000_000_000)
    await eventually("the check after a failed one asks GitHub") { releases.count == 2 }
}

@MainActor func updatesLateResultAfterTurningOff() async {
    let clock = HeldSleep()
    let releases = HeldReleases()
    let bench = Bench(clock: clock, releases: releases)
    await status(bench, .success(monitorStatus(enabled: false, updateCheck: true)))
    await eventually("the first check asks GitHub") { releases.count == 1 }
    releases.answer(.success(Data(#"{"tag_name":"v0.7.0"}"#.utf8)))
    let judged = await bench.next("check_release")
    await status(bench, .success(monitorStatus(enabled: false, updateCheck: false)))
    bench.answer(judged, .success(#"{"newer":"0.7.0","current":"0.6.0"}"#))
    await drainMainActor()
    check(bench.model.availableUpdate == nil, "updates: a check that ends after checks were turned off shows nothing")
    check(!clock.isWaiting, "updates: checks turned off do not wait for the next day")
}

@MainActor func updatesFailures() async {
    let releases = HeldReleases()
    let bench = Bench(releases: releases)
    bench.model.checkForUpdates()
    await eventually("Check for Updates asks GitHub") { releases.count == 1 }
    check(bench.model.checkingUpdates, "updates: Check for Updates… is busy while it runs")
    bench.model.checkForUpdates()
    releases.answer(.failure(URLError(.notConnectedToInternet)))
    await eventually("the failed check is shown") { bench.model.updateResult != nil }
    check(releases.count == 1, "updates: Check for Updates… while one runs asks GitHub once")
    check(bench.model.updateResult == .failed(URLError(.notConnectedToInternet).localizedDescription),
          "updates: a check that could not reach GitHub says why")
    check(!bench.model.checkingUpdates, "updates: Check for Updates… can be chosen again after a failure")

    bench.model.updateResult = nil
    bench.model.checkForUpdates()
    await eventually("the second check asks GitHub") { releases.count == 2 }
    releases.answer(.success(Data([0xff, 0xfe])))
    await eventually("the unreadable reply is shown") { bench.model.updateResult != nil }
    check(bench.model.updateResult == .failed("Loose Keys couldn't read GitHub's response. Try again later.")
          && bench.engine.held("check_release").isEmpty,
          "updates: a reply that is not text is refused before the engine is given it")

    bench.model.updateResult = nil
    bench.model.checkForUpdates()
    await eventually("the third check asks GitHub") { releases.count == 3 }
    releases.answer(.success(Data("{}".utf8)))
    bench.answer(await bench.next("check_release"), refused)
    await eventually("the refused reply is shown") { bench.model.updateResult != nil }
    check(bench.model.updateResult == .failed("That action stopped unexpectedly."),
          "updates: a reply the engine refuses says why")

    let latest = ReleaseCheck(newer: nil, current: "0.6.0")
    bench.model.updateResult = nil
    bench.model.checkForUpdates()
    await eventually("the fourth check asks GitHub") { releases.count == 4 }
    releases.answer(.success(Data("{}".utf8)))
    bench.answer(await bench.next("check_release", after: 1), .success(#"{"newer":null,"current":"0.6.0"}"#))
    await eventually("the result is shown") { bench.model.updateResult != nil }
    check(bench.model.updateResult == .upToDate(latest) && bench.model.availableUpdate == nil,
          "updates: Check for Updates… says when this is the latest version")

    let newer = ReleaseCheck(newer: "0.7.0", current: "0.6.0")
    bench.model.updateResult = nil
    bench.model.checkForUpdates()
    await eventually("the fifth check asks GitHub") { releases.count == 5 }
    releases.answer(.success(Data("{}".utf8)))
    bench.answer(await bench.next("check_release", after: 2), .success(#"{"newer":"0.7.0","current":"0.6.0"}"#))
    await eventually("the result is shown") { bench.model.updateResult != nil }
    check(bench.model.updateResult == .newer(newer) && bench.model.availableUpdate == newer,
          "updates: Check for Updates… that finds a newer version also puts it on Overview")
    await status(bench, .success(monitorStatus(enabled: false, updateCheck: false)))
    check(bench.model.availableUpdate == newer,
          "updates: with automatic checks off, a version found by Check for Updates… stays on Overview")

    bench.model.updateResult = nil
    bench.model.checkForUpdates()
    await eventually("the sixth check asks GitHub") { releases.count == 6 }
    releases.answer(.success(Data("{}".utf8)))
    bench.answer(await bench.next("check_release", after: 3), .success(#"{"newer":null,"current":"0.7.0"}"#))
    await eventually("the result is shown") { bench.model.updateResult != nil }
    check(bench.model.availableUpdate == nil,
          "updates: Check for Updates… that finds nothing newer takes the Overview notice away")
}

/// The alert is on the main window, and Check for Updates… is in the app
/// menu also while only Settings is open, or the window can be closed while
/// the check runs. Each result brings the window up, on the page it was on.
@MainActor func updatesResultOpensTheWindow() async {
    let releases = HeldReleases()
    let bench = Bench(releases: releases)
    let opened = Made()
    bench.model.openMainWindow = { opened.count += 1 }
    bench.model.pane = .stored
    bench.model.checkForUpdates()
    await eventually("Check for Updates asks GitHub") { releases.count == 1 }
    releases.answer(.failure(URLError(.notConnectedToInternet)))
    await eventually("the failed check ends") { !bench.model.checkingUpdates }
    check(opened.count == 1 && bench.model.pane == .stored,
          "updates: a failed Check for Updates… brings the main window up, on the page it was on")

    bench.model.updateResult = nil
    bench.model.checkForUpdates()
    await eventually("the second check asks GitHub") { releases.count == 2 }
    releases.answer(.success(Data("{}".utf8)))
    bench.answer(await bench.next("check_release"), .success(#"{"newer":null,"current":"0.6.0"}"#))
    await eventually("the second check ends") { !bench.model.checkingUpdates }
    check(opened.count == 2 && bench.model.pane == .stored,
          "updates: what Check for Updates… found brings the main window up, on the page it was on")
}

@MainActor func updatesSettingFailure() async {
    let bench = Bench()
    await status(bench, .success(monitorStatus(enabled: false)))
    bench.model.answerUpdateQuestion(true)
    bench.answer(await bench.next("set_update_check"), refused)
    bench.answer(await bench.next("monitor_status", after: 1), .success(monitorStatus(enabled: false)))
    await eventually("the refusal is shown") { bench.model.failure != nil }
    check(!bench.model.shouldAskAboutUpdates, "updates: a refused answer is not asked for again in this launch")
}

let madeUpEngineText: [String: String] = [
    "Saved password": "Contraseña guardada",
    "Cloud key": "Llave de la nube",
    "could not resolve selected path": "no se pudo resolver la ruta elegida",
    "7": "siete",
    "profile default": "perfil predeterminado",
    "profile %@": "perfil %@",
    "%lld saved logins": "%lld inicios guardados",
    "Could not read %@": "No se pudo leer %@",
    "Could not read %@ (shared file)": "No se pudo leer %@ (archivo compartido)",
    "Cannot add the folder: %@": "No se puede añadir la carpeta: %@",
    "on %@ on": "en %@ en",
    "%@ and %@": "%@ y %@",
    "%@ folders": "carpetas",
]

func expect(_ shown: String, _ wanted: String, _ what: String) {
    check(shown == wanted, "engine text: \(what): showed \"\(shown)\", not \"\(wanted)\"")
}

func engineTextMatches() {
    let table = EngineText.Table(madeUpEngineText)
    expect(table.shown("Saved password"), "Contraseña guardada", "an exact key")
    expect(table.shown("Something else"), "Something else", "a string the table lacks is shown as it came")
    expect(table.about("profile default"), "perfil predeterminado", "an exact key comes before a template")
    expect(table.about("profile work"), "perfil work", "a %@ template")
    expect(table.about("profile "), "profile ", "a %@ never stands for nothing")
    expect(table.about("12 saved logins"), "12 inicios guardados", "a %lld template")
    expect(table.about("twelve saved logins"), "twelve saved logins", "a %lld stands for digits only")
    expect(table.about("\u{0661}\u{0662} saved logins"), "\u{0661}\u{0662} saved logins", "a %lld stands for ASCII digits only")
    expect(table.about(" saved logins"), " saved logins", "a %lld never stands for nothing")
    expect(table.shown("on x on"), "en x en", "fixed text on both sides of a %@")
    expect(table.shown("on on"), "on on", "the text in a %@ never overlaps the fixed text")
    expect(table.shown("Could not read x (shared file)"), "No se pudo leer x (archivo compartido)",
           "the template with the longest fixed text")
    let nested = "Cannot add the folder: could not resolve selected path"
    expect(table.shown(nested), "No se puede añadir la carpeta: no se pudo resolver la ruta elegida",
           "shown looks up the text in a %@")
    expect(table.about(nested), "No se puede añadir la carpeta: could not resolve selected path",
           "about keeps the text in a %@")
    expect(table.shown("profile Saved password"), "perfil Contraseña guardada", "shown looks up a %@'s text exactly")
    expect(table.about("profile Saved password"), "perfil Saved password", "about keeps a name a file gave")
    // The engine nests its text two deep, as in "Could not save: export
    // directory: permission-denied.", so shown looks two levels down, no more.
    expect(table.shown("Cannot add the folder: Could not read could not resolve selected path"),
           "No se puede añadir la carpeta: No se pudo leer no se pudo resolver la ruta elegida",
           "shown looks up the text in a %@ two levels deep")
    expect(table.shown("Cannot add the folder: Could not read Could not read could not resolve selected path"),
           "No se puede añadir la carpeta: No se pudo leer No se pudo leer could not resolve selected path",
           "shown looks up the text in a %@ two levels deep only")
    expect(table.shown("7 saved logins"), "7 inicios guardados", "the digits in a %lld are kept")
    expect(table.about("profile %@ %lld"), "perfil %@ %lld", "the text in a %@ is put in as it is, never as a format")
    expect(table.shown("a and b"), "a and b", "a key with two placeholders is left out")
    expect(table.shown("3 folders"), "3 folders", "a translation without its key's placeholder is left out")
}

/// Which localization's table the window uses, from tables written to a
/// folder under TMPDIR named for this process and removed after.
func engineTextTableChoice() {
    let folder = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("model-check-\(getpid())-engine-text")
    try? FileManager.default.removeItem(at: folder)
    defer { try? FileManager.default.removeItem(at: folder) }
    func write(_ entries: [String: String], _ bundle: String, _ language: String) -> Bool {
        let lproj = folder.appendingPathComponent(bundle).appendingPathComponent("\(language).lproj")
        guard (try? FileManager.default.createDirectory(at: lproj, withIntermediateDirectories: true)) != nil,
              let data = try? PropertyListSerialization.data(fromPropertyList: entries, format: .binary, options: 0)
        else { return false }
        return (try? data.write(to: lproj.appendingPathComponent("Engine.strings"), options: .withoutOverwriting)) != nil
    }
    guard write(["Saved password": "Contraseña guardada"], "both", "es"),
          write(["Saved password": "Clave guardada"], "both", "es-419"),
          write(["Saved password": "Contraseña guardada"], "spain", "es"),
          let both = Bundle(url: folder.appendingPathComponent("both")),
          let spain = Bundle(url: folder.appendingPathComponent("spain"))
    else { return check(false, "engine text: the made-up tables are written under TMPDIR") }
    func shown(_ bundle: Bundle, _ languages: [String]) -> String {
        EngineText.Table.load(from: bundle, languages: languages).shown("Saved password")
    }
    expect(shown(both, ["es-419", "es"]), "Clave guardada", "the first language's table")
    expect(shown(both, ["es"]), "Contraseña guardada", "the one language's table")
    expect(shown(spain, ["es-419", "es"]), "Contraseña guardada", "a language with no table gives way to the next")
    expect(shown(both, ["en", "es"]), "Saved password", "English first uses no table")
    expect(shown(both, ["en-GB", "es"]), "Saved password", "a regional English first uses no table")
    expect(shown(both, []), "Saved password", "no language uses no table")
}

/// The Filter field matches what a row shows, without regard to case or
/// accents, and the engine's English; a title heading sorts by the title shown.
@MainActor func engineTextFilterAndSort() async {
    let english = EngineText.table
    EngineText.table = EngineText.Table(madeUpEngineText)
    defer { EngineText.table = english }
    let model = AppModel(engine: HeldEngine())
    let items: [[String: Any]] = [
        ["id": 1, "rule": "fixture-rule", "path": "~/fixture-1.txt", "title": "Saved password",
         "explanation": "Review fixture", "severity": "high", "deferred": false, "state": "open", "subject": "profile work"],
        ["id": 2, "rule": "fixture-rule", "path": "~/fixture-2.txt", "title": "Cloud key",
         "explanation": "Review fixture", "severity": "high", "deferred": false, "state": "open"],
    ]
    model.review = try? decodeEngine(ReviewList.self, from: Data(json(["items": items]).utf8))
    for (typed, wanted, what) in [
        ("contrasena", [1], "a shown title typed without its accents"),
        ("CONTRASEÑA GUARDADA", [1], "a shown title in other case"),
        ("saved password", [1], "the engine's English title"),
        ("perfil work", [1], "what the row is about, as shown"),
        ("profile work", [1], "what the row is about, as the engine gave it"),
        ("fixture-2", [2], "the path"),
    ] {
        model.search = typed
        let ids = model.reviewRows.map(\.id)
        check(ids == wanted, "filter: \(what) leaves findings \(wanted), not \(ids)")
    }
    model.search = ""
    model.reviewSort = [KeyPathComparator(\ReviewItem.shownTitle)]
    check(model.reviewRows.map(\.id) == [1, 2], "sort: the Finding heading sorts by the title shown")
    model.reviewSort = [KeyPathComparator(\ReviewItem.shownTitle, order: .reverse)]
    check(model.reviewRows.map(\.id) == [2, 1], "sort: the Finding heading sorts by the title shown, in reverse")
    var stored = items
    stored[0]["kind"] = "inventory"
    stored[1]["kind"] = "inventory"
    stored[1]["title"] = "Saved password"
    stored[1]["subject"] = NSNull()
    model.review = try? decodeEngine(ReviewList.self, from: Data(json(["items": stored]).utf8))
    model.pane = .stored
    for (typed, wanted, what) in [
        ("contrasena", 2, "a shown title typed without its accents"),
        ("saved password", 2, "the engine's English title"),
        ("perfil work", 1, "what the row is about, as shown"),
        ("profile work", 1, "what the row is about, as the engine gave it"),
        ("llave", 0, "another title"),
    ] {
        model.search = typed
        check(model.reviewRows.count == wanted, "filter: \(what) leaves \(wanted) stored sign-ins, not \(model.reviewRows.count)")
    }
    model.search = ""
}

@MainActor func filterResultCounts() async {
    let model = AppModel(engine: HeldEngine())
    model.pane = .review
    model.search = "fixture"
    check(model.filterSummary == nil, "filter count: no empty-results claim before the list arrives")
    model.review = try? decodeEngine(ReviewList.self, from: Data(reviewStates(["open", "fixed", "set-aside"]).utf8))
    check(model.filterSummary == "Showing 2 of 2 items", "filter count: review includes fixed rows, not set-aside rows")
    model.search = "fixture-2"
    check(model.filterSummary == "Showing 1 of 2 items", "filter count: partial match distinguishes shown and total rows")
    check(!model.filterHasNoMatches, "filter message: partial matches keep the table")
    model.search = "not present"
    check(model.filterSummary == "Showing 0 of 2 items", "filter count: no matches is distinct from an empty source list")
    check(model.filterHasNoMatches, "filter message: review offers no-match guidance")
    model.reviewUnread = "Could not read the review list."
    check(model.filterSummary == nil, "filter count: a failed read is not a zero-match result")
    check(!model.filterHasNoMatches, "filter message: no-match guidance cannot hide a read failure")
    model.reviewUnread = nil
    model.pane = .setAside
    model.search = "fixture-3"
    check(model.filterSummary == "Showing 1 of 1 item", "filter count: Set Aside has its own total and singular form")
    model.search = "not present"
    check(model.filterHasNoMatches, "filter message: Set Aside offers no-match guidance")
    model.search = " \t "
    check(model.filterSummary == nil, "filter count: whitespace does not advertise an active filter")
    model.pane = .stored
    model.search = "fixture-3"
    check(model.filterSummary == nil, "filter count: Stored Sign-ins with none listed shows no count")
    model.review = try? decodeEngine(ReviewList.self, from: Data(kindsList([("open", false), ("open", true), ("open", true),
                                                                             ("set-aside", true)]).utf8))
    check(model.filterSummary == "Showing 1 of 2 items", "filter count: stored sign-ins show the filtered and full totals")
    model.search = "not present"
    check(model.filterSummary == "Showing 0 of 2 items", "filter count: stored sign-ins report no matches explicitly")
    check(model.filterHasNoMatches, "filter message: stored sign-ins offer no-match guidance")
    model.search = ""
    check(model.filterSummary == nil && model.reviewRows.count == 2,
          "filter count: clearing restores all stored sign-ins")
    check(!model.filterHasNoMatches, "filter message: clearing dismisses no-match guidance")
}

func initialWindowFitsScreen() {
    for screen in [CGSize(width: 1024, height: 700), CGSize(width: 1280, height: 680), CGSize(width: 1920, height: 1000)] {
        let size = initialWindowSize(in: screen)
        check(size.width + 40 <= screen.width && size.height + 80 <= screen.height,
              "window: initial content leaves space for frame, toolbar and screen edges")
        check(size.width >= 760 && size.height >= 480,
              "window: initial content meets the supported minimum")
    }
    check(initialWindowSize(in: CGSize(width: 1920, height: 1000)) == CGSize(width: 1180, height: 720),
          "window: a large screen keeps the preferred content size")
}

@MainActor func compactInspectorSelection() async {
    let model = AppModel(engine: HeldEngine())
    model.pane = .review
    model.review = try? decodeEngine(ReviewList.self, from: Data(reviewList(2).utf8))
    check(model.review?.items.first?.copyHint == nil, "single row: no copy hint without a grouped places list")
    check(!model.inspectorShown, "inspector: an unselected list starts compact")
    model.selectedReview = 1
    check(model.inspectorShown, "inspector: choosing a finding opens its details")
    model.toggleInspector()
    model.selectedReviews = [1]
    check(!model.inspectorShown, "inspector: an unchanged selection keeps a manual hide")
    model.selectedReview = 2
    check(model.inspectorShown, "inspector: choosing another finding reopens details")
    model.search = "no matching finding"
    check(!model.inspectorShown, "inspector: filtering away the selection closes empty details")
    model.toggleInspector()
    check(model.inspectorShown, "inspector: the toolbar can explicitly show empty details")
    model.review = try? decodeEngine(ReviewList.self, from: Data(kindsList([("open", false), ("open", true)]).utf8))
    model.search = ""
    model.pane = .stored
    model.selectedReview = 2
    check(model.inspectorShown && model.currentReview?.id == 2, "inspector: choosing a stored sign-in opens details")
    model.selectedReviews = []
    check(!model.inspectorShown, "inspector: clearing the stored selection closes empty details")
}

/// A grouped finding keeps its representative identity even when another
/// copy (including a fixed or set-aside copy) is the reason it matches.
@MainActor func groupedPathFiltering() async {
    let model = AppModel(engine: HeldEngine())
    for state in ["open", "set-aside", "fixed"] {
        let item: [String: Any] = [
            "id": 41, "revision": 7, "rule": "fixture-rule", "path": "~/.config/example/hosts.yml",
            "title": "Synthetic grouped finding", "explanation": "Review fixture",
            "severity": "high", "state": state,
            "places": [
                ["id": 41, "path": "~/.config/example/hosts.yml", "fixed": false],
                ["id": 42, "path": "~/Projects/payments-api/.env", "fixed": false],
                ["id": 43, "path": "~/Projects/retired/.env", "fixed": true],
                ["id": 44, "path": "~/Projects/kept/.env", "fixed": false, "set_aside": true],
            ],
        ]
        model.search = ""
        model.review = try? decodeEngine(ReviewList.self, from: Data(json(["items": [item]]).utf8))
        check(model.review?.items.first?.copyHint == "4 copies",
              "grouped row: the copy hint counts listed open, fixed and set-aside copies")
        model.pane = state == "set-aside" ? .setAside : .review
        for (query, path) in [("PAYMENTS-API", "~/Projects/payments-api/.env"),
                              ("retired", "~/Projects/retired/.env"), ("kept", "~/Projects/kept/.env")] {
            model.search = ""
            model.selectedReview = 41
            model.search = query
            check(model.reviewRows.map(\.id) == [41], "grouped filter: \(state) matches a secondary path (\(query))")
            check(model.reviewRows.first.map { model.matchingReviewPaths($0) } == [path],
                  "grouped filter: the row explains the matching secondary path")
            check(model.currentReview?.id == 41 && model.currentReview?.revision == 7
                  && model.currentReview?.path == "~/.config/example/hosts.yml",
                  "grouped filter: matching a copy keeps the selected representative and revision")
        }
        model.search = ".env"
        check(model.reviewRows.first.map { model.matchingReviewPaths($0).count } == 3,
              "grouped filter: context includes every matching secondary path")
        for query in ["", "Synthetic grouped", "hosts.yml"] {
            model.search = query
            check(model.reviewRows.first.map { model.matchingReviewPaths($0) } == [],
                  "grouped filter: no redundant path context for an empty, title or representative match")
        }
        model.search = "no matching copy"
        check(model.reviewRows.isEmpty && model.selectedReviews.isEmpty,
              "grouped filter: a missing path clears the hidden selection")
    }
}

/// Two rules can find the same credential on the same line of one file. The
/// engine lists both places, but it is one copy, in one file.
@MainActor func groupedCopiesInOneFile() async {
    let model = AppModel(engine: HeldEngine())
    let item = { (places: [[String: Any]]) -> [String: Any] in
        ["id": 51, "revision": 3, "rule": "fixture-rule", "path": "~/.example-credentials", "line": 1,
         "title": "Synthetic grouped finding", "explanation": "Review fixture", "severity": "high",
         "state": "open", "places": places]
    }
    let sameFile: [[String: Any]] = [
        ["id": 51, "path": "~/.example-credentials", "line": 1, "fixed": false],
        ["id": 52, "path": "~/.example-credentials", "line": 1, "fixed": false],
    ]
    model.review = try? decodeEngine(ReviewList.self, from: Data(json(["items": [item(sameFile)]]).utf8))
    check(model.review?.items.first?.copyHint == nil,
          "grouped copies: two rules in one file are not two copies")
    let twoFiles: [[String: Any]] = sameFile + [
        ["id": 53, "path": "~/Projects/shop/.env", "line": 4, "fixed": true],
        ["id": 54, "path": "~/Projects/shop/.env", "line": 4, "fixed": false, "set_aside": true],
    ]
    model.review = try? decodeEngine(ReviewList.self, from: Data(json(["items": [item(twoFiles)]]).utf8))
    check(model.review?.items.first?.copyHint == "2 copies",
          "grouped copies: the hint counts files, fixed and set-aside copies included")
    let others = model.review?.items.first?.otherLocations ?? []
    check(others.map(\.path) == ["~/Projects/shop/.env"],
          "grouped copies: the inspector lists each other file once, not the finding's own file again")
    check(others.first?.id == 54 && others.first?.fixed == false && others.first?.setAside == true,
          "grouped copies: a file still holding the credential is not shown as fixed")
}

// MARK: Stored sign-ins
//
// They come in the same list as what is worth reviewing, told apart by kind,
// and are saved: a window opened after the scan that found them lists them.

/// What a relaunched window shows, with no scan of its own: each page lists
/// its kind, and nothing stored counts toward what is worth reviewing.
@MainActor func storedSignInsFromTheSavedList() async {
    let bench = Bench()
    let model = bench.model
    model.pane = .stored
    let read = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(read, .success(kindsList([("open", false), ("set-aside", false), ("open", true),
                                                 ("set-aside", true), ("open", true)])))
    check(model.results == nil && model.reviewRows.map(\.id) == [3, 5],
          "stored: Stored Sign-ins lists the saved sign-ins still to look at, with no scan this session (\(model.reviewRows.map(\.id)))")
    check(model.storedCount == 2, "stored: the badge counts the saved sign-ins (\(model.storedCount))")
    model.pane = .review
    check(model.reviewRows.map(\.id) == [1] && model.reviewCount == 1 && model.openCount == 1,
          "stored: Worth Reviewing and its count leave stored sign-ins out")
    check(model.reviewSummary == "1 to review, 1 set aside", "stored: Worth Reviewing's subtitle leaves stored sign-ins out (\(model.reviewSummary))")
    check(model.menuBarLine == "1 loose key to review", "stored: the menu bar counts no stored sign-in")
    model.pane = .setAside
    check(Set(model.reviewRows.map(\.id)) == [2, 4] && model.setAsideCount == 2,
          "stored: Set Aside lists both kinds, and its count sums them")
    // Stored Sign-ins has no Risk column, so a risk heading pressed on
    // another list does not order it.
    model.reviewSort = [KeyPathComparator(\ReviewItem.riskLevel)]
    model.pane = .stored
    check(model.reviewRows.map(\.id) == [3, 5], "stored: a sort chosen on Worth Reviewing does not order Stored Sign-ins")
    model.storedSort = [KeyPathComparator(\ReviewItem.shownTitle, order: .reverse)]
    check(model.reviewRows.map(\.id) == [5, 3], "stored: the Sign-in heading orders Stored Sign-ins")
    // A full Worth Reviewing is shorter than the scan's count by what it left
    // out, which stored sign-ins on the list do not make up.
    model.review = try? decodeEngine(ReviewList.self, from: Data(kindsList([("open", false), ("open", true), ("open", true)], full: true).utf8))
    model.results = try? decodeEngine(ScanResults.self, from: Data(scanResults(review: 2, stored: 2).utf8))
    check(model.findingsNote == "The scan found 2 findings, but the list is full at 1 item. Save the report to see them all.",
          "stored: the Overview's full-list note counts no stored sign-in as listed (\(model.findingsNote ?? "none"))")
}

/// A list that cannot be read is never an empty one: the badge is the last
/// scan's count, and the last list read stays for when it can be used again.
@MainActor func storedListThatCannotBeRead() async {
    let bench = Bench()
    let model = bench.model
    model.pane = .stored
    let read = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(read, .success(kindsList([("open", true), ("open", true)])))
    model.results = try? decodeEngine(ScanResults.self, from: Data(scanResults(review: 0, stored: 5).utf8))
    let failed = await bench.ask("pending_review") { await $0.refreshReview(reportFailure: false) }
    await bench.answer(failed, refused)
    check(model.reviewProblem != nil && model.storedCount == 5 && model.setAsideCount == 0,
          "stored: with the list unreadable, the badge is the scan's own count (\(model.storedCount))")
    check(model.review?.items.filter(\.isStored).count == 2 && model.currentReviews.isEmpty && model.filterSummary == nil,
          "stored: a failed read keeps the last list but offers none of it")
    let back = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(back, .success(kindsList([("open", true), ("open", true)])))
    check(model.reviewProblem == nil && model.storedCount == 2 && model.reviewRows.count == 2,
          "stored: the list is used again once it can be read")
}

/// An empty Stored Sign-ins says why. A scan this session that counted
/// sign-ins the list doesn't hold is a list that couldn't be filled, even
/// before any scan was recorded as looking for them, as when an older helper
/// saved the list without them. Sign-ins saved and since no longer found
/// empty it without any failure.
@MainActor func storedEmptyStates() async {
    let bench = Bench()
    let model = bench.model
    model.pane = .stored
    let read = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(read, .success(kindsList([("open", false)], storedChecked: false)))
    check(model.storedEmpty == .notLookedYet, "stored: with no scan, an empty list is one not looked at yet (\(model.storedEmpty))")
    model.results = try? decodeEngine(ScanResults.self, from: Data(scanResults(review: 1, stored: 5).utf8))
    check(model.storedEmpty == .notListed(5),
          "stored: a scan's sign-ins missing from a list never looked at are not 'none yet' (\(model.storedEmpty))")
    model.results = try? decodeEngine(ScanResults.self, from: Data(scanResults(review: 1, stored: 1).utf8))
    model.review = try? decodeEngine(ReviewList.self, from: Data(kindsList([("open", false)], storedGone: 1).utf8))
    check(model.storedEmpty == .none,
          "stored: a list emptied because the scan's sign-ins are gone says there are none (\(model.storedEmpty))")
    model.review = try? decodeEngine(ReviewList.self, from: Data(kindsList([("open", false)]).utf8))
    check(model.storedEmpty == .notListed(1), "stored: a list that holds none of the scan's sign-ins says so (\(model.storedEmpty))")
    model.review = try? decodeEngine(ReviewList.self, from: Data(kindsList([("set-aside", true)], storedGone: 1).utf8))
    check(model.storedEmpty == .allSetAside, "stored: every sign-in set aside is said first (\(model.storedEmpty))")
}

/// Saved stored sign-ins are no scan of this session: with nothing worth
/// reviewing and no check recorded, the Overview and the menu bar still say
/// nothing has been checked, as Worth Reviewing does.
@MainActor func storedOnlyIsNotAScan() async {
    let bench = Bench()
    let model = bench.model
    model.monitor = try? decodeEngine(MonitorStatus.self, from: Data(monitorStatus(enabled: false).utf8))
    model.review = try? decodeEngine(ReviewList.self, from: Data(kindsList([("open", true), ("set-aside", true)]).utf8))
    check(model.results == nil && model.nothingChecked && model.showsWelcome,
          "stored: saved sign-ins alone leave the Overview as before any scan")
    check(model.menuBarLine == "No scan this session", "stored: saved sign-ins alone leave the menu bar as before any scan (\(model.menuBarLine))")
}

/// A read that fails on Stored Sign-ins is named as that page names it.
@MainActor func storedReadFailureTitle() async {
    let bench = Bench()
    let model = bench.model
    model.pane = .stored
    let failed = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(failed, refused)
    check(model.failure?.title == FailureTitle.openStored,
          "stored: a failed read on Stored Sign-ins has the page's own title (\(model.failure?.title ?? "none"))")
}

/// Moving a stored sign-in back from Set Aside opens Stored Sign-ins on it,
/// and a mixed selection moves only the kind asked for.
@MainActor func storedMoveBackFollowsTheItem() async {
    let bench = Bench()
    let model = bench.model
    model.pane = .setAside
    let read = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(read, .success(kindsList([("set-aside", false), ("set-aside", true)])))
    model.selectedReview = 2
    guard let item = model.currentReview else { return check(false, "stored: a set-aside sign-in is selected") }
    let moved = await bench.ask("decide_review") { $0.decide(item, reason: nil) }
    check(moved.call.args["id"] as? Int == 2 && moved.call.args["reason"] is NSNull,
          "stored: Move to Stored Sign-ins names the sign-in")
    await bench.answer(moved, .success("null"))
    bench.answer(await bench.next("pending_review", after: 1), .success(kindsList([("set-aside", false), ("open", true)])))
    await eventually("the returned sign-in is shown") { model.pane == .stored }
    check(model.currentReview?.id == 2, "stored: moving a sign-in back opens Stored Sign-ins with it selected")

    model.pane = .setAside
    let both = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(both, .success(kindsList([("set-aside", false), ("set-aside", true)])))
    model.selectedReviews = [1, 2]
    let only = await bench.ask("decide_review") { $0.decideSelection(reason: nil, stored: true) }
    check(only.call.args["id"] as? Int == 2, "stored: Move to Stored Sign-ins on a mixed selection moves the sign-in")
    await bench.answer(only, .success("null"))
    bench.answer(await bench.next("pending_review", after: 3), .success(kindsList([("set-aside", false), ("open", true)])))
    await eventually("the mixed move finishes") { !model.decidingSelection }
    check(bench.engine.held("decide_review").count == 2, "stored: a mixed move leaves the other kind where it is")
}

/// A notification is only ever about something worth reviewing.
@MainActor func openReviewSkipsStoredSignIns() async {
    let bench = Bench()
    let model = bench.model
    model.start(reviewRoute: false)
    bench.answer(await bench.next("places"), .success(places([])))
    bench.answer(await bench.next("pending_review"), .success(reviewList(0)))
    bench.answer(await bench.next("monitor_status"), .success(monitorStatus(enabled: true)))
    bench.engine.fire("open-review")
    // The stored sign-in is the newest item, and open.
    bench.answer(await bench.next("pending_review", after: 1), .success(kindsList([("open", false), ("open", true)])))
    await eventually("the notification's finding is chosen") { model.selectedReview != nil }
    check(model.pane == .review && model.selectedReview == 1,
          "stored: a notification click never chooses a stored sign-in (\(model.selectedReview.map(String.init) ?? "none"))")
}

func helperStatus(login: Int, running: Bool, paused: Bool = false) -> String {
    json(["enabled": true, "paused": paused, "scanning": false, "login": login,
          "menu_bar": false, "app_login": 1, "health": ["running": running], "pending_delivery": false, "attempts": 0])
}

/// Restart Helper stops a registered helper, then starts it, and only starts
/// one that is not registered. After a stop that failed it starts nothing and
/// says so.
@MainActor func restartHelperOrder() async {
    for (login, stopAnswer, sent) in [(2, "1", [false, true]), (1, "", [true]), (2, "4", [false])] {
        let clock = HeldSleep()
        let bench = Bench(clock: clock)
        let model = bench.model
        model.monitor = try? decodeEngine(MonitorStatus.self, from: Data(helperStatus(login: login, running: false).utf8))
        model.restartHelper()
        for (index, enabled) in sent.enumerated() {
            let call = await bench.next("set_login_startup", after: index)
            check(call.args["enabled"] as? Bool == enabled,
                  "restart from login \(login): request \(index + 1) is a \(enabled ? "start" : "stop")")
            bench.answer(call, .success(enabled ? "2" : stopAnswer))
        }
        bench.answer(await bench.next("monitor_status"), .success(helperStatus(login: 2, running: true)))
        await clock.wake(after: 2_000_000_000)
        bench.answer(await bench.next("monitor_status", after: 1), .success(helperStatus(login: 2, running: true, paused: true)))
        await eventually("the restart's last status read is applied") { model.monitor?.paused == true }
        check(bench.engine.held("set_login_startup").count == sent.count,
              "restart from login \(login): \(sent.count) registration requests, no more")
        if stopAnswer == "4" {
            await eventually("a failed stop is reported") { model.failure != nil }
        } else {
            check(model.failure == nil, "restart from login \(login): nothing is reported when it works")
        }
    }
}

/// With Show in Menu Bar on, the icon follows the helper while the window is
/// in the background, more slowly, and still one read at a time.
@MainActor func menuBarFollowsHelperInBackground() async {
    let clock = HeldSleep()
    let bench = Bench(clock: clock)
    bench.model.becameActive()
    bench.answer(await bench.next("pending_review"), .success(reviewList(0)))
    bench.answer(await bench.next("monitor_status"), .success(monitorStatus(enabled: true, menuBar: true)))
    await eventually("the menu bar setting is read") { bench.model.menuBarOn }
    await eventually("the foreground loop reaches its timer") { clock.isWaiting }
    bench.model.becameInactive()
    bench.answer(await bench.next("pending_review", after: 1), .success(reviewList(0)))
    bench.answer(await bench.next("monitor_status", after: 1), .success(monitorStatus(enabled: true, menuBar: true)))
    await clock.wake(after: 5_000_000_000)
    await eventually("the foreground timer is cancelled") { clock.cancelled == 1 }
    await clock.wake(after: 30_000_000_000)
    bench.answer(await bench.next("pending_review", after: 2), .success(reviewList(1)))
    bench.answer(await bench.next("monitor_status", after: 2), refused)
    await eventually("a helper finding reaches the menu bar while the window is in the background") {
        bench.model.openCount == 1 && bench.model.monitor == nil
    }
    check(bench.model.menuBarOn, "a status that could not be read does not take the icon away")
    check(bench.model.menuBarMark == .open, "an open item marks the icon")
    await eventually("the background loop reaches its timer") { clock.isWaiting }

    // Coming forward and going back, again and again, never reads twice at once.
    bench.model.becameActive()
    let out = await bench.next("pending_review", after: 3)
    bench.model.becameInactive()
    bench.model.becameActive()
    bench.model.becameInactive()
    check(await bench.holdsOnly(4, "pending_review"), "menu bar: a read that is out is not joined by another")
    bench.answer(out, .success(reviewList(1)))
    bench.answer(await bench.next("pending_review", after: 4), .success(reviewList(1)))
    bench.answer(await bench.next("monitor_status", after: 3), .success(monitorStatus(enabled: true, menuBar: true)))
    await clock.wake(after: 30_000_000_000)
    await eventually("the replaced background timer is cancelled") { clock.cancelled == 2 }
    await eventually("the last loop reaches its timer") { clock.isWaiting }
    check(bench.engine.mostAtOnce("pending_review") == 1 && bench.engine.mostAtOnce("monitor_status") == 1,
          "menu bar: switching between foreground and background never reads twice at once")

    // Turned off, the background reads stop.
    let off = await bench.ask("set_menu_bar") { $0.setMenuBar(false) }
    check(off.call.args["enabled"] as? Bool == false, "menu bar: the switch sends the setting")
    bench.answer(off.call, .success("null"))
    bench.answer(await bench.next("monitor_status", after: 4), .success(monitorStatus(enabled: true)))
    await eventually("the setting is off") { !bench.model.menuBarOn }
    await clock.wake(after: 30_000_000_000)
    await eventually("the background timer is cancelled") { clock.cancelled == 3 }
    check(await bench.holdsOnly(5, "pending_review"), "menu bar off: no reads while the window is in the background")
}

@MainActor func menuBarSettingFailures() async {
    let bench = Bench()
    let on = await bench.ask("set_menu_bar") { $0.setMenuBar(true) }
    bench.answer(on.call, refused)
    // Before the status read after it answers, so that no read can put it back.
    let after = await bench.next("monitor_status")
    check(bench.model.failure != nil && !bench.model.menuBarOn,
          "a refused switch is reported and keeps the setting as the engine has it")
    bench.answer(after, refused)
    // Sent only once the read before it has finished.
    let again = await bench.ask("monitor_status") { await $0.refreshMonitor() }
    await bench.answer(again, refused)
    check(!bench.model.menuBarOn, "a refused switch is not turned on by a failed read")
    bench.model.failure = nil
    bench.model.quietLaunch = true
    check(bench.model.menuBarOn, "opened at login, the app is in the menu bar before any read")
    let failed = await bench.ask("monitor_status") { await $0.refreshMonitor() }
    await bench.answer(failed, refused)
    check(bench.model.menuBarOn, "a failed read never leaves the app with no icon and no window")
}

/// What went wrong with an action taken in Settings is shown in Settings
/// while it is open, and not in the main window as well. Once Settings has
/// closed, and for the menu bar icon, which has no window, it is shown in
/// the main window, which comes up for it. From the main window it is shown
/// there, with Settings open or not.
@MainActor func failuresShownWhereAsked() async {
    let bench = Bench()
    let model = bench.model
    let opened = Made()
    model.openMainWindow = { opened.count += 1 }
    model.settingsOpen = true
    model.setMenuBar(true, from: .settings)
    bench.answer(await bench.next("set_menu_bar"), refused)
    bench.answer(await bench.next("monitor_status"), refused)
    await eventually("the refused switch is reported") { model.settingsFailure != nil || model.failure != nil }
    check(model.settingsFailure != nil && model.failure == nil && opened.count == 0,
          "failures: a switch refused in Settings is shown in Settings alone")
    model.settingsFailure = nil

    model.retryNotifications()
    bench.answer(await bench.next("retry_notifications"), refused)
    await eventually("the refused Try Again is reported") { model.settingsFailure != nil || model.failure != nil }
    check(model.settingsFailure != nil && model.failure == nil && opened.count == 0,
          "failures: Try Again refused in Settings is shown in Settings alone")
    model.settingsFailure = nil

    // Settings closes while the engine is still answering.
    model.setUpdateCheck(true, from: .settings)
    let late = await bench.next("set_update_check")
    model.settingsOpen = false
    bench.answer(late, refused)
    bench.answer(await bench.next("monitor_status", after: 1), refused)
    await eventually("the late refusal is reported") { model.settingsFailure != nil || model.failure != nil }
    check(model.failure != nil && model.settingsFailure == nil && opened.count == 1,
          "failures: a refusal that comes once Settings has closed is shown in the main window, which comes up")
    model.failure = nil

    model.setMenuBar(false, from: .menuBar)
    bench.answer(await bench.next("set_menu_bar", after: 1), refused)
    bench.answer(await bench.next("monitor_status", after: 2), refused)
    await eventually("the refused icon removal is reported") { model.settingsFailure != nil || model.failure != nil }
    check(model.failure != nil && model.settingsFailure == nil && opened.count == 2,
          "failures: taking the icon out of the menu bar, refused, is shown in the main window, which comes up")
    model.failure = nil

    model.settingsOpen = true
    model.enableNotifications()
    bench.answer(await bench.next("enable_notifications"), refused)
    await eventually("the refused request is reported") { model.settingsFailure != nil || model.failure != nil }
    check(model.failure != nil && model.settingsFailure == nil && opened.count == 2,
          "failures: a refusal in the main window is shown there alone, with Settings open as well")
}

/// Quitting stops the background reads, and none starts after.
@MainActor func quittingStopsMenuBarReads() async {
    let clock = HeldSleep()
    let bench = Bench(clock: clock)
    let status = await bench.ask("monitor_status") { await $0.refreshMonitor() }
    await bench.answer(status, .success(monitorStatus(enabled: true, menuBar: true)))
    bench.answer(await bench.next("pending_review"), .success(reviewList(0)))
    bench.answer(await bench.next("monitor_status", after: 1), .success(monitorStatus(enabled: true, menuBar: true)))
    await eventually("the background loop reaches its timer") { clock.isWaiting }
    let engine = bench.engine
    // prepare_quit is sent on the main actor and waits for its answer.
    DispatchQueue.global().async {
        let deadline = Date().addingTimeInterval(10)
        while engine.held("prepare_quit").isEmpty, Date() < deadline { usleep(1000) }
        engine.held("prepare_quit").first?.gate.signal()
    }
    bench.model.prepareToQuit()
    check(engine.held("prepare_quit").count == 1, "quitting tells the engine")
    await clock.wake(after: 30_000_000_000)
    await eventually("the background timer is cancelled on quit") { clock.cancelled == 1 }
    let late = await bench.ask("monitor_status") { await $0.refreshMonitor() }
    await bench.answer(late, .success(monitorStatus(enabled: true, menuBar: true)))
    check(await bench.holdsOnly(1, "pending_review") && !clock.isWaiting,
          "after quitting, no read or timer starts again")
}

@MainActor func menuBarSaysOnlyWhatTheListSays() async {
    let bench = Bench()
    let model = bench.model
    check(model.menuBarMark == .unknown && model.menuBarLine == "Loading Worth Reviewing…",
          "menu bar: before the list is read it says so")
    let failed = await bench.ask("pending_review") { await $0.refreshReview(reportFailure: false) }
    await bench.answer(failed, refused)
    check(model.menuBarMark == .problem && model.menuBarLine == "Couldn't open Worth Reviewing",
          "menu bar: a list that could not be read is a problem, not nothing")
    let one = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(one, .success(reviewList(1)))
    check(model.menuBarLine == "1 loose key to review", "menu bar: one open item is one loose key")
    let two = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(two, .success(reviewList(2)))
    check(model.menuBarMark == .open && model.menuBarLine == "2 loose keys to review", "menu bar: open items are counted")
    let lost = await bench.ask("pending_review") { await $0.refreshReview(reportFailure: false) }
    await bench.answer(lost, refused)
    check(model.menuBarMark == .problem && !model.menuBarLine.contains("2"),
          "menu bar: a failure after a good read does not show the old count")
    let decided = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(decided, .success(reviewStates(["set-aside", "fixed"])))
    check(model.menuBarMark == .plain && model.menuBarLine == "0 loose keys to review",
          "menu bar: everything set aside or fixed is a count of none, never a claim of safety")
    // A full list left findings out: it is not a list with nothing open.
    let crowded = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(crowded, .success(reviewStates(["set-aside"], full: true)))
    check(model.menuBarMark == .full && model.menuBarLine == "0 loose keys to review, list full",
          "menu bar: a full list with nothing open says it is full")
    let crowdedOpen = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(crowdedOpen, .success(reviewStates(["open", "open"], full: true)))
    check(model.menuBarMark == .full && model.menuBarLine == "2 loose keys to review, list full",
          "menu bar: a full list with items open counts them and says it is full")
    // Checks that are not known to be running say so, as Settings does.
    model.monitor = nil
    check(model.menuBarCheckLine == "Automatic scanning: Unavailable", "menu bar: a status not read is not running checks")
    for (status, line) in [(monitorStatus(enabled: false), "Automatic scanning: Off"),
                           (monitorStatus(enabled: true, paused: true, running: true), "Automatic scanning: Paused"),
                           (monitorStatus(enabled: true, running: false), "Automatic scanning: Helper Not Running"),
                           (monitorStatus(enabled: true), "Automatic scanning: Waiting for Helper Status")] {
        model.monitor = try? decodeEngine(MonitorStatus.self, from: Data(status.utf8))
        check(model.menuBarCheckLine == line, "menu bar: \(line)")
    }
    model.monitor = try? decodeEngine(MonitorStatus.self, from: Data(monitorStatus(enabled: true, running: true).utf8))
    check(model.menuBarCheckLine == nil, "menu bar: running checks need no line")

    // Whatever the items hold, the menu says a fixed phrase and a count.
    let pieces = ["synthetic", "planted", "menu"]
    let path = "~/" + pieces.joined(separator: "-") + ".txt"
    let subject = pieces.reversed().joined(separator: "_")
    let planted = json(["items": [["id": 1, "rule": "fixture-rule", "path": path, "title": "Synthetic finding",
                                    "explanation": "Review fixture", "severity": "high", "state": "open",
                                    "subject": subject, "detail": subject, "revision": 1]],
                        "counts": ["open": 1, "set_aside": 0, "kept": 0, "fixed": 0],
                        "skipped": [path], "full": false])
    let read = await bench.ask("pending_review") { await $0.refreshReview() }
    await bench.answer(read, .success(planted))
    check(model.openCount == 1, "menu bar: the planted item is read")
    for status in [monitorStatus(enabled: false), monitorStatus(enabled: true, paused: true, running: true)] {
        model.monitor = try? decodeEngine(MonitorStatus.self, from: Data(status.utf8))
        let shown = model.menuBarLine + (model.menuBarCheckLine ?? "")
        check(!([path, subject] + pieces).contains { shown.contains($0) },
              "menu bar: no path, subject or piece of either is shown")
    }
}

/// An empty list before anything was checked is not a count of none: the
/// menu says no scan has run, or that the helper is still on its first pass.
@MainActor func menuBarBeforeAnyCheck() async {
    let model = AppModel(engine: HeldEngine())
    model.review = try? decodeEngine(ReviewList.self, from: Data(reviewList(0).utf8))
    model.monitor = try? decodeEngine(MonitorStatus.self, from: Data(monitorStatus(enabled: false).utf8))
    check(model.menuBarMark == .plain && model.menuBarLine == "No scan this session",
          "menu bar: an empty list with no scan and no helper check is not a count")
    model.monitor = try? decodeEngine(MonitorStatus.self, from: Data(monitorStatus(enabled: true, running: true).utf8))
    check(model.menuBarLine == "Checking existing files…",
          "menu bar: the helper's first pass is checking, not a count")
    let checked = json(["enabled": true, "paused": false, "scanning": false, "login": 2, "menu_bar": true,
                        "app_login": 2, "health": ["running": true, "last_scan": "2026-11-03T05:39:00Z"],
                        "pending_delivery": false, "attempts": 0])
    model.monitor = try? decodeEngine(MonitorStatus.self, from: Data(checked.utf8))
    check(model.menuBarLine == "0 loose keys to review", "menu bar: after a helper check, the empty list is counted")
    model.monitor = nil
    check(model.menuBarLine == "0 loose keys to review", "menu bar: an unread helper status changes nothing")
}

@MainActor func automaticCoverageReads() async {
    let bench = Bench()
    let old = #"{"full_pass":"2026-10-20T12:00:00Z","unread":1,"unread_gaps":[{"label":"Could not be read","help":"","count":1,"paths":["~/old"],"more":0}],"unread_truncated":false}"#
    let newer = old.replacingOccurrences(of: "~/old", with: "~/new")
        .replacingOccurrences(of: "2026-10-20", with: "2026-10-21")
    let first = await bench.ask("automatic_coverage") { await $0.refreshAutomaticCoverage() }
    await bench.answer(first, .success(old))
    let failing = await bench.ask("automatic_coverage") { await $0.refreshAutomaticCoverage() }
    let queued = await bench.request { await $0.refreshAutomaticCoverage() }
    await bench.answer(failing, refused)
    check(bench.model.automaticCoverage?.unreadGaps?.first?.paths == ["~/old"]
          && bench.model.automaticCoverageError == nil,
          "coverage: a superseded failure preserves the saved list while the next read is pending")
    bench.answer(await bench.next("automatic_coverage", after: 2), .success(newer))
    await queued.value
    check(bench.model.automaticCoverage?.unreadGaps?.first?.paths == ["~/new"],
          "coverage: the last read supplies paths and completion time together")
    let last = await bench.ask("automatic_coverage") { await $0.refreshAutomaticCoverage() }
    await bench.answer(last, refused)
    check(bench.model.automaticCoverage?.unreadGaps?.first?.paths == ["~/new"]
          && bench.model.automaticCoverageError != nil,
          "coverage: a final failure is visible and retains the previous details")
    check(bench.engine.mostAtOnce("automatic_coverage") == 1,
          "coverage: reads do not overlap")
    check(bench.engine.held("start_scan").isEmpty && bench.engine.held("prepare_access").isEmpty,
          "coverage: reading details neither scans nor prompts for file access")
}

@main enum RefreshOrder {
    @MainActor static func main() async {
        let cases: [(String, @MainActor () async -> Void)] = [
            ("automatic coverage: ordered reads and failures", automaticCoverageReads),
            ("multiple review selection", multipleReviewSelection),
            ("set aside leaves the review queue", setAsideLeavesReview),
            ("set aside failures and changed values", setAsideFailuresAndChanges),
            ("set aside: a later choice outranks a saved move", setAsideMoveYieldsToLaterChoice),
            ("folder access precedes scans and background consent", folderAccessBeforeWork),
            ("folder access cancellation and failure", folderAccessCancellationAndFailure),
            ("review list: older list, then newer", reviewOlderListBeforeNewer),
            ("review list: older failure, then newer list", reviewOlderFailureBeforeNewer),
            ("review list: newest failure after older list", reviewNewestFailure),
            ("review list: older list, then newest failure", reviewOlderListBeforeNewestFailure),
            ("review list: one read at a time", reviewOneReadAtATime),
            ("review list: a change during a read", reviewChangeDuringRead),
            ("review list: a failed read, then the next", reviewFailureThenNextRead),
            ("review list: a press names the row drawn", reviewPressNamesTheRowDrawn),
            ("review list: a shared read alerts if any request asked", reviewFailureAlertsForAnyRequest),
            ("background checks: older status, then newer", monitorOlderStatusBeforeNewer),
            ("background checks: older failure, then newer status", monitorOlderFailureBeforeNewer),
            ("background checks: newest failure after older status", monitorNewestFailure),
            ("background checks: a failed status read keeps its reason", monitorFailureKeepsReason),
            ("places: older list after a removal", placesOlderListAfterRemoval),
            ("places: older failure after newer list", placesOlderFailureAfterNewer),
            ("places: removal refusal preserves folders and reports why", placesRemovalRefusal),
            ("places: newest failure after older list", placesNewestFailure),
            ("places: read again before a scan", placesReadAgainBeforeScan),
            ("scan: refreshes while a scan runs", scanDoesNotHoldRefreshes),
            ("background checks: foreground follows the helper", foregroundFollowsHelper),
            ("background checks: honest helper status", backgroundStatusIsHonest),
            ("background checks: Restart Helper stops, then starts", restartHelperOrder),
            ("notifications: coming forward re-reads permission", activationRereadsNotificationPermission),
            ("menu bar: follows the helper in the background", menuBarFollowsHelperInBackground),
            ("menu bar: a refused switch or failed read keeps the icon", menuBarSettingFailures),
            ("failures: shown in the window the person acted in", failuresShownWhereAsked),
            ("menu bar: quitting stops its reads", quittingStopsMenuBarReads),
            ("menu bar: says only what the list says", menuBarSaysOnlyWhatTheListSays),
            ("menu bar: no count before anything is checked", menuBarBeforeAnyCheck),
            ("updates: asked only when the answer can be kept", updatesAskOnlyWhenStateUsable),
            ("updates: checked at start and every day", updatesCheckAtStartAndDaily),
            ("updates: a failed check waits for the next day", updatesDailyLoopSurvivesFailure),
            ("updates: a late result after turning checks off", updatesLateResultAfterTurningOff),
            ("updates: Check for Updates… results and failures", updatesFailures),
            ("updates: Check for Updates… brings up the window for its result", updatesResultOpensTheWindow),
            ("updates: a refused save", updatesSettingFailure),
            ("engine text: exact keys and templates", engineTextMatches),
            ("engine text: the table for the window's language", engineTextTableChoice),
            ("filter: usable-list counts", filterResultCounts),
            ("window: initial size fits visible screen", initialWindowFitsScreen),
            ("inspector: compact until a selection", compactInspectorSelection),
            ("grouped copies: filter every path", groupedPathFiltering),
            ("grouped copies: one file is one copy", groupedCopiesInOneFile),
            ("stored: listed from the saved list", storedSignInsFromTheSavedList),
            ("stored: a list that cannot be read", storedListThatCannotBeRead),
            ("stored: why the list is empty", storedEmptyStates),
            ("stored: saved sign-ins alone are no scan", storedOnlyIsNotAScan),
            ("stored: a failed read has the page's title", storedReadFailureTitle),
            ("stored: moving back follows the item", storedMoveBackFollowsTheItem),
            ("stored: a notification never chooses one", openReviewSkipsStoredSignIns),
            ("engine text: filter and sort by what is shown", engineTextFilterAndSort),
        ]
        for (name, run) in cases {
            let before = failures
            await run()
            if failures == before { print("PASS: \(name)") }
        }
        exit(failures == 0 ? 0 : 1)
    }
}
