// Separate test driver for the window's model. Never linked into the app
// bundle. gui/tests/check-model.sh builds it with the real AppModel, Models and
// Engine sources and the stand-in engine below: no window, no scanner, and
// nothing in a home folder is read. The stand-in answers each command when
// the test says, so answers can be made to arrive in any order. It also
// counts how many calls of one command it held at once: the review list and
// the status of background checks are each read one call at a time.
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

    func start(reviewRoute: Bool, onEvent: @escaping (String, Data) -> Void) {}

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

typealias Asked = (call: HeldCall, done: Task<Void, Never>)

/// How many requests the test has put to the model.
@MainActor final class Made {
    var count = 0
}

@MainActor struct Bench {
    let engine = HeldEngine()
    let model: AppModel
    private let made = Made()

    init(clock: HeldSleep? = nil) {
        if let clock { model = AppModel(engine: engine, sleep: clock.sleep) }
        else { model = AppModel(engine: engine) }
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

func reviewStates(_ states: [String], revision: Int = 1) -> String {
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
                 "skipped": [String](), "full": false])
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

func monitorStatus(enabled: Bool) -> String {
    json(["enabled": enabled, "paused": false, "scanning": false, "login": enabled ? 2 : 1,
          "health": [String: Any](), "pending_delivery": false, "attempts": 0])
}

func places(_ extra: [String]) -> String {
    json(["home": "~", "extra": extra])
}

/// What a scan that found this many review findings answers.
func scanResults(review: Int) -> String {
    json(["status": "partial", "tool_version": "0.0.0-test", "generated_at": "2026-10-13T00:00:00Z",
          "review": review, "stored": 0, "not_checked": 0, "groups": [Any](), "gaps": [Any](),
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

// MARK: A scan in progress

@MainActor func folderAccessBeforeWork() async {
    for background in [false, true] {
        let clock = HeldSleep()
        let bench = Bench(clock: clock)
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
    check(model.backgroundState == "Unavailable", "missing status is unavailable")
    for (enabled, paused, login, running, expected) in [
        (false, false, 1, false, "Off"),
        (true, false, 3, false, "Needs macOS Approval"),
        (true, false, 2, false, "Helper Not Running"),
        (true, true, 2, false, "Helper Not Running"),
        (true, true, 2, true, "Paused"),
        (true, false, 2, true, "Active"),
    ] {
        let value = json(["enabled": enabled, "paused": paused, "scanning": false, "login": login,
                          "health": ["running": running], "pending_delivery": false, "attempts": 0])
        model.monitor = try? decodeEngine(MonitorStatus.self, from: Data(value.utf8))
        check(model.backgroundState == expected, "background status: \(expected)")
    }
    model.monitor = try? decodeEngine(MonitorStatus.self, from: Data(monitorStatus(enabled: true).utf8))
    check(model.backgroundState == "Waiting for Helper Status", "registration alone is not a running helper")
}

@main enum RefreshOrder {
    @MainActor static func main() async {
        let cases: [(String, @MainActor () async -> Void)] = [
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
            ("background checks: older status, then newer", monitorOlderStatusBeforeNewer),
            ("background checks: older failure, then newer status", monitorOlderFailureBeforeNewer),
            ("background checks: newest failure after older status", monitorNewestFailure),
            ("places: older list after a removal", placesOlderListAfterRemoval),
            ("places: older failure after newer list", placesOlderFailureAfterNewer),
            ("places: newest failure after older list", placesNewestFailure),
            ("scan: refreshes while a scan runs", scanDoesNotHoldRefreshes),
            ("background checks: foreground follows the helper", foregroundFollowsHelper),
            ("background checks: honest helper status", backgroundStatusIsHonest),
            ("notifications: coming forward re-reads permission", activationRereadsNotificationPermission),
        ]
        for (name, run) in cases {
            let before = failures
            await run()
            if failures == before { print("PASS: \(name)") }
        }
        exit(failures == 0 ? 0 : 1)
    }
}
