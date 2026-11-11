// Development only, never shipped. Built with -D PREVIEW: the window on sample
// data. Built with -D SNAPSHOTS: the real engine. Either way, with
// SNAPSHOT_DIR set it saves a picture of each page and quits.
#if PREVIEW || SNAPSHOTS
import AppKit
import ApplicationServices
import SwiftUI
#endif

#if PREVIEW
final class SampleEngine: Engine {
    /// Set by the checks: the review list then answers as the engine does once
    /// a save of it has failed, with the items it still holds and the reason.
    static var storeFailed = false
    /// Set by the checks: the request for the review list then fails.
    static var refused = false
    /// Set by the checks: the request for the status of background checks then fails.
    static var statusRefused = false
    static let statusRefusal = "Synthetic status read failure."
    /// Set by the checks: the folders answer as the engine does when it
    /// couldn't read its saved state.
    static var placesFailed = false
    /// Set by the checks: there is no home folder to scan, as when HOME is unusable.
    static var noHome = false
    /// Set by the checks: saving a decision then fails, and from then on the
    /// review list answers as it does once a save has failed.
    static var saveFails = false
    /// Set by the checks: nothing needs a decision. The review list is then
    /// empty, and a scan finds no review finding in what it could read.
    static var nothingFound = false
    /// Set by the checks: every finding is set aside, so Worth Reviewing
    /// has nothing to list.
    static var allSetAside = false
    /// Set by the checks: a report cannot be saved.
    static var reportFails = false
    /// Set by the checks: macOS denied the scan access to Documents.
    static var documentsBlocked = false
    /// What the window last asked to have done to a folder, for the checks.
    static var folderRequest: [String: Any] = [:]
    /// The folders scans skip. skip_folder adds one, and the checks put it back.
    static var skipped = ["~/Movies/Raw"]
    /// The folder of the sample's password export, which Stop Checking skips.
    static let exportFolder = "~/Downloads"
    /// A file action must name the selected copy, not the group's lead.
    static var pathRequest: [String: Any] = [:]
    /// Set by the checks: the review list is then full. The engine says so in
    /// the list, and in the field where it reports a storage failure.
    static var listFull = false
    static let fullNotice = "The review list is full, so new findings are not being added."
    /// The copies of the sample's token in two files that were set aside as
    /// kept. decide_review changes it, and the checks put it back.
    static var kept: Set<Int> = []
    /// Decisions on the sample's single-location findings.
    static var decisions: [Int: String] = [6: "kept"]
    /// The stored sign-ins set aside as kept. decide_review changes it, and
    /// the checks put it back.
    static var storedKept: Set<Int> = []
    /// Whether a scan has looked for stored sign-ins since they were saved.
    static var storedChecked = true
    /// The ids of the sample's stored sign-ins, in the order of the scan's.
    static let storedIds = 20...24
    /// When every sample decision was made.
    static let setAsideAt = "2026-10-24T18:00:00Z"
    /// Consent to background checks, with the helper running while it is
    /// given. set_monitoring changes it, and the checks put it back.
    static var monitoring = false
    static var paused = false
    /// Set by the checks: the helper is registered but not running. As with
    /// macOS, only a start after a stop runs it again.
    static var helperStopped = false
    static var helperUnregistered = false
    /// Set by the checks: macOS waits for the person to let the helper run.
    static var helperNeedsApproval = false
    /// How long a sample scan takes; the checks lengthen it to stop one.
    static var scanSeconds = 0.3
    static var cancelRequests = 0
    /// What the window asked of the helper's registration, in order.
    static var loginRequests: [Bool] = []
    /// Show in Menu Bar. set_menu_bar changes it, and the checks put it back.
    static var menuBar = true
    /// Set by the checks: set_menu_bar is then refused, and the setting kept.
    static var menuBarRefused = false
    static let menuBarRefusal = "Could not save the setting."
    /// May the window check for updates: nil until asked. Answered no, so
    /// that the question is shown only by the checks that ask for it.
    static var updateCheck: Bool? = false
    /// The version check_release calls newer, if any.
    static var newer: String?
    /// The sample reply cannot be got, as when GitHub is out of reach.
    static var releaseFails = false
    /// The app's own Login Items status, when the checks set one.
    static var appLogin: Int?
    static var completedPass = false
    /// When the helper last checked a file, if the checks set it.
    static var lastCheck: String?
    /// An error the helper kept from before checks were turned off.
    static var helperError = false
    static var notificationRequests = 0
    /// A notification the helper hasn't sent yet, and how often it has tried.
    /// retry_notifications sends it.
    static var pendingDelivery = false
    static var attempts = 0
    static var retryRequests = 0
    /// The person's answer to macOS's request is no.
    static var declinesNotifications = false
    static var permission = "denied"
    /// Places the helper's last full pass did not read. Set by the checks.
    static var unread = 0
    static var scanRequests = 0
    static var coverageFails = false
    static var coverageMissing = false
    /// The window check holds preparation while it presses Cancel.
    static var accessGate: DispatchSemaphore?

    private var onEvent: ((String, Data) -> Void)?

    func start(reviewRoute: Bool, onEvent: @escaping (String, Data) -> Void) {
        self.onEvent = onEvent
    }

    /// The checks change this engine's state on the main thread while the
    /// window calls it from others, at times two at once. Unguarded, that
    /// crashed the window check. So the state is read and written on the main
    /// thread only, and only the waits stay off it, so that the checks can
    /// act while one goes on.
    func call(_ command: String, _ args: [String: Any]) throws -> Data {
        switch command {
        case "prepare_access":
            if let gate = Self.onMain({ Self.accessGate }), gate.wait(timeout: .now() + 10) != .success {
                throw EngineError(message: "The window check never released folder access.")
            }
            return Data("null".utf8)
        case "start_scan":
            Thread.sleep(forTimeInterval: Self.onMain { Self.scanRequests += 1; return Self.scanSeconds })
        default:
            break
        }
        return try Self.onMain { try respond(command, args) }
    }

    /// On the main thread, waiting for it, or at once when already there.
    private static func onMain<T>(_ work: () throws -> T) rethrows -> T {
        if Thread.isMainThread { return try work() }
        return try DispatchQueue.main.sync(execute: work)
    }

    /// The answer to a call, on the main thread.
    private func respond(_ command: String, _ args: [String: Any]) throws -> Data {
        switch command {
        case "places" where Self.placesFailed:
            return Data(#"{"home":"~","home_error":null,"extra":[],"error":"Could not read the saved state."}"#.utf8)
        case "places" where Self.noHome:
            return Data(#"{"home":null,"home_error":"HOME is not set to an absolute path","extra":[],"error":null}"#.utf8)
        case "places": return Data(#"{"home":"~","home_error":null,"extra":["/Volumes/Backup"],"error":null}"#.utf8)
        case "skip_folder":
            Self.folderRequest = args
            if args["id"] as? Int == 3, !Self.skipped.contains(Self.exportFolder) { Self.skipped.append(Self.exportFolder) }
            return Data("null".utf8)
        case "remove_place", "unskip_folder":
            // The sample keeps its folders. The checks look at what was asked.
            Self.folderRequest = args
            return command == "remove_place" ? try respond("places", [:]) : Data("null".utf8)
        case "save_report" where Self.reportFails:
            throw EngineError(message: "Could not save: the disk is full.")
        case "pending_review" where Self.refused:
            throw EngineError(message: "That action stopped unexpectedly.")
        case "pending_review" where Self.nothingFound:
            return Data(#"{"items":[],"counts":{"open":0,"set_aside":0,"fixed":0,"stored":0,"stored_set_aside":0,"stored_gone":0},"skipped":[],"error":null,"full":false,"stored_full":false,"stored_checked":\#(Self.storedChecked),"route":false,"permission":"denied"}"#.utf8)
        case "pending_review" where Self.allSetAside: return Data(Self.everythingSetAside.utf8)
        case "pending_review": return Data(Self.review.utf8)
        case "decide_review" where Self.saveFails:
            Self.storeFailed = true
            throw EngineError(message: "Could not save the review list.")
        case "decide_review" where !(args["revision"] is Int):
            // As the engine: a press says which drawing of the row it was made on.
            throw EngineError(message: "The request has no usable \"revision\".")
        case "decide_review" where Self.storedIds.contains(args["id"] as? Int ?? 0):
            // As the engine: a stored sign-in takes only Keeping It Here on Purpose.
            switch args["reason"] as? String {
            case "kept": Self.storedKept.insert(args["id"] as? Int ?? 0)
            case nil: Self.storedKept.remove(args["id"] as? Int ?? 0)
            default: throw EngineError(message: "That reason doesn't apply to a stored sign-in.")
            }
            return Data("null".utf8)
        case "decide_review":
            // "Kept" covers one place, so it can leave another copy to decide.
            if let id = args["id"] as? Int {
                if id == 4 || id == 9 {
                    if args["reason"] as? String == "kept" { Self.kept.insert(id) } else { Self.kept.remove(id) }
                } else {
                    Self.decisions[id] = args["reason"] as? String
                }
            }
            return Data("null".utf8)
        case "set_menu_bar" where Self.menuBarRefused:
            throw EngineError(message: Self.menuBarRefusal)
        case "set_menu_bar":
            Self.menuBar = args["enabled"] as? Bool ?? false
            return Data("null".utf8)
        case "set_update_check":
            Self.updateCheck = args["enabled"] as? Bool ?? false
            return Data("null".utf8)
        case "check_release":
            let newer = Self.newer.map { "\"\($0)\"" } ?? "null"
            return Data(#"{"newer":\#(newer),"current":"0.2.0"}"#.utf8)
        case "set_monitoring":
            Self.monitoring = args["enabled"] as? Bool ?? false
            Self.paused = args["paused"] as? Bool ?? false
            return Data("null".utf8)
        case "set_login_startup":
            let on = args["enabled"] as? Bool ?? false
            Self.loginRequests.append(on)
            if on, Self.helperUnregistered { Self.helperStopped = false }
            Self.helperUnregistered = !on
            return Data((on ? "2" : "1").utf8)
        case "enable_notifications":
            Self.notificationRequests += 1
            // As if the person chose Allow. Once blocked, macOS answers without asking.
            if Self.permission == "not requested" { Self.permission = Self.declinesNotifications ? "denied" : "allowed" }
            onEvent?("notification-permission", Data("null".utf8))
            return Data("null".utf8)
        case "refresh_notifications":
            onEvent?("notification-permission", Data("null".utf8))
            return Data("null".utf8)
        case "retry_notifications":
            Self.retryRequests += 1
            Self.pendingDelivery = false
            Self.attempts = 0
            return Data("null".utf8)
        case "monitor_status" where Self.statusRefused: throw EngineError(message: Self.statusRefusal)
        case "monitor_status": return Data(Self.monitor.utf8)
        case "automatic_coverage":
            if Self.coverageFails { throw EngineError(message: "Synthetic coverage read failure.") }
            return Data(Self.automaticCoverage.utf8)
        case "start_scan":
            // The sample scan could not read everything: its status is "partial".
            var answer = Self.results
            if Self.nothingFound { answer = answer.replacingOccurrences(of: #""review":8"#, with: #""review":0"#) }
            if Self.documentsBlocked { answer = answer.replacingOccurrences(of: #""blocked":[]"#, with: #""blocked":["Documents"]"#) }
            return Data(answer.utf8)
        case "item_path":
            Self.pathRequest = args
            return Data(#""sample""#.utf8)
        case "summary_text": return Data(#""sample""#.utf8)
        // As the engine, which hands back the page to open once its rules list it.
        case "open_link": return try JSONSerialization.data(withJSONObject: args["url"] as? String ?? "", options: .fragmentsAllowed)
        case "cancel_scan":
            Self.cancelRequests += 1
            return Data("null".utf8)
        default: return Data("null".utf8)
        }
    }

    private static func item(_ id: Int, _ title: String, _ path: String, _ severity: String, _ state: String,
                             subject: String? = nil, detail: String? = nil, aside: String? = nil, places: String? = nil,
                             link: String? = nil, folder: String? = nil, actionable: Bool = true) -> String {
        let aside = decisions[id] ?? aside
        let state = aside == nil ? state : "set-aside"
        let quoted = { (text: String?) in text.map { "\"\($0)\"" } ?? "null" }
        let copies = places ?? #"[{"id":\#(id),"path":"\#(path)","line":null,"fixed":false,"set_aside":\#(aside != nil),"actionable":\#(actionable)}]"#
        return """
        {"id":\(id),"kind":"review","revision":\(id),"rule":"sample.rule","path":"\(path)","line":null,"title":"\(title)",
         "explanation":"This file starts with 12 or more words from the list wallets use for recovery phrases. Loose Keys did not check whether they make a valid phrase or a wallet with funds.",
         "reason":"A recovery phrase is the wallet. Anyone who copies these words can take everything in it, with no password, and stealers collect small text files from Desktop, Documents and Downloads.",
         "next_step":"Treat the phrase as exposed if this Mac could have had malware. Otherwise move it off the Mac now.",
         "severity":"\(severity)","steps":["Write the phrase on paper, or stamp it in metal, and store it somewhere safe away from the computer.","Delete this file and empty the Trash. Check Notes, Photos and cloud folders for other copies, including screenshots.","If this Mac may have been infected, create a new wallet with a new phrase and move the funds to it."],
         "link":\(quoted(link)),"subject":\(quoted(subject)),"detail":\(quoted(detail)),"first_seen":"2026-10-\(10 + id % 9)T21:40:00Z","resolved_at":null,
         "resolved":\(state == "fixed"),"state":"\(state)","set_aside":\(quoted(aside)),"set_aside_at":\(quoted(aside.map { _ in setAsideAt })),
         "places":\(copies),"folder":\(quoted(folder)),"actionable":\(actionable)}
        """
    }

    /// One token in two files. The engine lists it as one entry, named by the
    /// first copy that still needs a decision.
    private static var tokenInTwoFiles: String {
        let copies = [(id: 4, path: "~/Projects/shop/.env"),
                      (id: 9, path: "~/.claude/projects/shop/earlier-session.jsonl")]
        let lead = copies.first { !kept.contains($0.id) } ?? copies[0]
        let decided = copies.allSatisfy { kept.contains($0.id) }
        let places = copies.map {
            #"{"id":\#($0.id),"path":"\#($0.path)","line":null,"fixed":false,"set_aside":\#(kept.contains($0.id)),"actionable":true}"#
        }
        return item(lead.id, "Service token stored in a file", lead.path, "high", decided ? "set-aside" : "open",
                    subject: "GitHub personal access token", aside: decided ? "kept" : nil,
                    places: "[\(places.joined(separator: ","))]")
    }

    private static var everythingSetAside: String {
        """
        {"items":[\(item(6, "Possible npm token stored in a config file", "~/.npmrc", "medium", "open", aside: "kept"))],
         "counts":{"open":0,"set_aside":1,"fixed":0,"stored":0,"stored_set_aside":0,"stored_gone":0},"skipped":[],"error":null,"full":\(listFull),
         "stored_full":false,"stored_checked":\(storedChecked),"route":false,"permission":"\(permission)"}
        """
    }

    /// A second copy of one sample sign-in, under its own id.
    static let storedCopy = "~/backup/gh/hosts.yml"

    /// A stored sign-in, as the engine lists it after what is worth reviewing:
    /// one of the scan's sign-ins below, with its rule's advice.
    private static func storedItem(_ id: Int, _ path: String, subject: String?, aiTool: Bool, copy: (id: Int, path: String)? = nil) -> String {
        let quoted = { (text: String?) in text.map { "\"\($0)\"" } ?? "null" }
        let aside = storedKept.contains(id)
        let copies = [(id: id, path: path)] + (copy.map { [$0] } ?? [])
        let places = copies.map {
            #"{"id":\#($0.id),"path":"\#($0.path)","line":null,"fixed":false,"set_aside":\#(aside),"actionable":true}"#
        }
        let advice = aiTool
            ? #""title":"Sign-in stored by an AI tool","explanation":"This tool keeps you signed in with a token in this file. That is how it is meant to work.","reason":"Any program running as you can read it, and stealers look for it by name.","next_step":"Sign out of the tool when you stop using it.","steps":["Sign out in the tool, which removes this file.","Sign in again when you next need it."],"link":"\#(managePage)""#
            : #""title":"Sign-in stored by a command-line tool","explanation":"A command-line tool keeps its sign-in in this file.","reason":null,"next_step":null,"steps":[],"link":null"#
        return """
        {"id":\(id),"kind":"inventory","revision":\(id),"rule":"sample.stored","path":"\(path)","line":null,\(advice),
         "severity":"medium","subject":\(quoted(subject)),"detail":null,"first_seen":"2026-10-0\(id % 9 + 1)T21:40:00Z","resolved_at":null,
         "resolved":false,"state":"\(aside ? "set-aside" : "open")","set_aside":\(aside ? #""kept""# : "null"),"set_aside_at":\(quoted(aside ? setAsideAt : nil)),
         "places":[\(places.joined(separator: ","))],"folder":null,"actionable":true}
        """
    }

    /// The scan's five sign-ins, saved.
    private static var storedItems: String {
        [storedItem(20, "~/.codex/auth.json", subject: "Codex", aiTool: true),
         storedItem(21, "~/.claude/.credentials.json", subject: "Claude Code", aiTool: true),
         storedItem(22, "~/.gemini/oauth_creds.json", subject: nil, aiTool: true),
         storedItem(23, "~/.config/gh/hosts.yml", subject: "github.com", aiTool: false, copy: (25, storedCopy)),
         storedItem(24, "~/.config/glab-cli/config.yml", subject: nil, aiTool: false)].joined(separator: ",\n")
    }

    /// The pages the sample's rules name, which open_link hands back.
    static let revokePage = "https://example.com/revoke"
    static let managePage = "https://example.com/manage"

    private static var skippedList: String {
        "[" + skipped.map { "\"\($0)\"" }.joined(separator: ",") + "]"
    }

    private static var review: String {
        let error = storeFailed ? #""Could not save the review list.""# : "null"
        let tokenAside = kept.contains(4) && kept.contains(9) ? 1 : 0
        let asideCount = decisions.count + tokenAside
        return """
        {"items":[
        \(item(7, "Possible wallet recovery phrase in a file", "~/Desktop/wallet backup.txt", "high", "open")),
        \(item(1, "Private key with no passphrase", "~/.ssh/id_ed25519", "high", "open")),
        \(item(2, "AWS access keys stored in a file", "~/.aws/credentials", "high", "open", subject: "profile default", link: revokePage)),
        \(item(3, "Possible password export file", "~/Downloads/passwords.csv", "high", "open", folder: exportFolder)),
        \(tokenInTwoFiles),
        \(item(5, "Passwords saved in a browser", "~/Library/Application Support/Google/Chrome/Default/Login Data", "medium", "open", detail: "214 saved logins")),
        \(item(6, "Possible npm token stored in a config file", "~/.npmrc", "medium", "open")),
        \(item(8, "Service token in an AI agent's records", "~/.claude/projects/caf\\\\u{e9}/session.jsonl", "high", "fixed", subject: "Tailscale API key", actionable: false)),
        \(storedItems)
        ],"counts":{"open":\(7 - asideCount),"set_aside":\(asideCount),"fixed":1,"stored":\(storedIds.count - storedKept.count),"stored_set_aside":\(storedKept.count),"stored_gone":0},
         "skipped":\(skippedList),"error":\(error),"full":\(listFull),"stored_full":false,"stored_checked":\(storedChecked),"route":false,"permission":"\(permission)"}
        """
    }

    /// A scan counts each finding. For the list above that is 8: the token in
    /// two files is two, and the item set aside is still found.
    private static let results = """
    {"status":"partial","generated_at":"2026-10-10T21:40:00Z",
     "review":8,"stored":5,"not_checked":123,
     "gaps":[{"label":"No Access","help":"macOS privacy protection or file permissions don't let Loose Keys read these. Nearly every Mac has some.","count":123,"paths":["~/Library/Mail","~/Library/Messages","~/Library/Safari","~/Library/Cookies","~/Library/Group Containers/group.com.apple.notes"]}],
     "blocked":[]}
    """

    private static var automaticCoverage: String {
        let fullPass = completedPass ? #""2026-10-14T12:00:00Z""# : "null"
        let gaps = unread > 0 ? #"[{"label":"No Access","help":"macOS privacy protection or file permissions don't let Loose Keys read these. Nearly every Mac has some.","count":1,"paths":["~/Library/Mail"]},{"label":"Couldn't Be Read","help":"If an app such as a browser is using any of these, quit the app, then scan again.","count":3,"paths":["~/Library/SyntheticUnread","~/Library/SyntheticUnread2","~/Library/SyntheticUnread3"]}]"# : "[]"
        return """
        {"full_pass":\(fullPass),"unread":\(unread),"unread_gaps":\(coverageMissing ? "null" : gaps),"unread_truncated":false}
        """
    }

    private static var monitor: String {
        let error = listFull ? "\"\(fullNotice)\"" : "null"
        let fullPass = completedPass ? #""2026-10-14T12:00:00Z""# : "null"
        let helperFailed = helperError ? #""Could not watch the home folder for changes.""# : "null"
        let lastScan = lastCheck.map { "\"\($0)\"" } ?? "null"
        return """
        {"enabled":\(monitoring),"paused":\(paused),"login":\(helperNeedsApproval ? 3 : monitoring && !helperUnregistered ? 2 : 1),
         "menu_bar":\(menuBar),"app_login":\(appLogin ?? (menuBar && monitoring ? 2 : 1)),
         "update_check":\(updateCheck.map { String($0) } ?? "null"),
         "health":{"running":\(monitoring && !helperStopped && !helperUnregistered && !helperNeedsApproval),"last_scan":\(lastScan),"full_pass":\(fullPass),"left":\(completedPass ? 0 : 4),"unread":\(unread),"error":\(helperFailed)},
         "error":\(error),"pending_delivery":\(pendingDelivery),"attempts":\(attempts),"results":null}
        """
    }
}

/// The sample's GitHub, which is never asked: a fixed reply, or a failure.
final class SampleReleases: ReleaseSource, @unchecked Sendable {
    /// How many times the window asked for the latest release.
    static var requests = 0

    func latest() async throws -> Data {
        Self.requests += 1
        if SampleEngine.releaseFails { throw URLError(.notConnectedToInternet) }
        return Data(#"{"tag_name":"v9.9.9","draft":false,"prerelease":false}"#.utf8)
    }
}

#endif

#if PREVIEW || SNAPSHOTS
/// Pictures of each page, taken from the window as macOS composes it.
@MainActor
enum Snapshots {
    static func runIfAsked() {
        let environment = ProcessInfo.processInfo.environment
        guard let folder = environment["SNAPSHOT_DIR"], let model = AppDelegate.model else { return }
        // The pictures show the pages, not the question about updates.
        model.asksAboutUpdates = false
        if let look = environment["SNAPSHOT_LOOK"] {
            NSApp.appearance = NSAppearance(named: look == "light" ? .aqua : .darkAqua)
        }
        Task { @MainActor in
            @MainActor func shot(_ name: String) async {
                try? await Task.sleep(nanoseconds: 900_000_000)
                capture(to: "\(folder)/\(name).png")
            }
            await shot("1-start")
            model.startScan()
            for _ in 0..<600 where model.phase == .scanning {
                try? await Task.sleep(nanoseconds: 100_000_000)
            }
            await shot("2-overview")
            model.pane = .review
            model.selectedReview = model.reviewRows.first?.id
            await shot("3-review")
            model.pane = .setAside
            model.selectedReview = model.reviewRows.first?.id
            await shot("3-set-aside")
            model.pane = .stored
            model.selectedReview = model.reviewRows.first?.id
            await shot("4-stored")
            model.pane = .overview
            model.showingPlaces = true
            await shot("5-places-not-checked")
            model.showingPlaces = false
            #if compiler(>=6.0)
            model.openSettings()
            await shot("6-settings")
            #endif
            if environment["SNAPSHOT_ACTIONS"] != nil {
                await actions(model, into: "\(folder)/actions.txt")
            }
            NSApp.terminate(nil)
        }
    }

    /// Each decision a person can make, sent through the engine and read back.
    /// Nothing here opens a panel, Finder or a link, or touches the clipboard.
    private static func actions(_ model: AppModel, into path: String) async {
        var lines: [String] = []
        func settle() async { try? await Task.sleep(nanoseconds: 400_000_000) }
        // An item in several files can come back under another copy's id.
        func state(_ id: Int) -> String { model.reviewEntry(id)?.status ?? "missing" }
        if let item = model.reviewRows.first(where: { $0.status == "open" }) {
            let id = item.id
            model.decide(item, reason: "kept")
            await settle()
            lines.append("set aside: \(state(id))")
            if let now = model.reviewEntry(id) { model.decide(now, reason: nil) }
            await settle()
            lines.append("shown again: \(state(id))")
            let place: String? = try? await model.engine.request("item_path", ["index": id])
            lines.append("path is absolute: \(place?.hasPrefix("/") ?? false)")
        }
        let summary: String? = try? await model.engine.request("summary_text")
        lines.append("summary characters: \(summary?.count ?? 0)")
        for feedback in [false, true] {
            let file = "\((path as NSString).deletingLastPathComponent)/saved-\(feedback ? "counts" : "report").json"
            do {
                try await model.engine.send("save_report", ["path": file, "feedback": feedback])
                lines.append("saved \(feedback ? "counts" : "report"): \(FileManager.default.fileExists(atPath: file))")
            } catch {
                lines.append("save failed: \(error.localizedDescription)")
            }
        }
        if let failure = model.failure { lines.append("alert: \(failure.title): \(failure.reason)") }
        try? lines.joined(separator: "\n").write(toFile: path, atomically: true, encoding: .utf8)
    }

    /// A process may read back its own windows without screen recording access.
    private static func capture(to path: String) {
        typealias Capture = @convention(c) (CGRect, UInt32, UInt32, UInt32) -> Unmanaged<CGImage>?
        // The newest window is the one just opened: Settings, when it is showing.
        let front = NSApp.windows.filter { $0.isVisible && $0.frame.width > 200 }
            .max { $0.windowNumber < $1.windowNumber }
        guard let window = front,
              let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "CGWindowListCreateImage"),
              let image = unsafeBitCast(symbol, to: Capture.self)(.null, 1 << 3, UInt32(window.windowNumber), 1)?
                .takeRetainedValue() else { return }
        let picture = NSBitmapImageRep(cgImage: image)
        try? picture.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
    }
}
#endif

#if PREVIEW || SNAPSHOTS
/// Uses the window and writes down what did not work. gui/tests/check-window.sh runs
/// it, with CHECK_REPORT naming the file to write. Rows are chosen, headings
/// and buttons pressed, and names read through the interface assistive software
/// uses, which an app may use on itself without being given access and without
/// coming to the front. No page is changed in code, so a control that ignores
/// the person fails here. What it cannot show: where a pointer lands, and
/// typing. The Filter field does not take text this way, so the filter is set
/// in code.
@MainActor
enum Checks {
    private static var lines: [String] = []
    private static var failed = false
    private static var log = ""
    private static var complaints = 0

    static func runIfAsked() {
        guard let report = ProcessInfo.processInfo.environment["CHECK_REPORT"],
              let model = AppDelegate.model else { return }
        // What AppKit logs is part of the result.
        log = report + ".log"
        freopen(log, "w", stderr)
        setvbuf(stderr, nil, _IONBF, 0)
        Task { @MainActor in
            await settle()
            // With the screen locked or its saver on, macOS puts a shield
            // over every window and shows assistive software none of them.
            // Every step that uses the window then fails, and none of those
            // failures says anything about the window. So ask for the window
            // once, and if AppKit logs that it is shielded, say that and stop.
            _ = windows()
            await settle()
            if shielded() {
                let why = "STOP the screen is locked or its saver is on. macOS then shows assistive software no window, so no step was run and nothing was learned about the window. Wake the screen and run the check again."
                try? (why + "\n").write(toFile: report, atomically: true, encoding: .utf8)
                exit(2)
            }
            await run(model)
            try? (lines.joined(separator: "\n") + "\n").write(toFile: report, atomically: true, encoding: .utf8)
            exit(failed ? 1 : 0)
        }
    }

    /// Whether AppKit has logged that it gives assistive software nothing of
    /// this app's windows because a shield is over them.
    private static func shielded() -> Bool {
        let logged = (try? String(contentsOfFile: log, encoding: .utf8)) ?? ""
        return logged.contains("Not vending elements because")
    }

    private static func expect(_ passed: Bool, _ what: String) {
        lines.append("\(passed ? "ok  " : "FAIL") \(what)")
        if !passed { failed = true }
    }

    /// Lets the window catch up, and notes what AppKit logged during the step
    /// named. A note is not a failure: the warning comes from the system's own
    /// table when its rows move or return (a sort with a row selected, a
    /// filter cleared), and nothing in this app is in its path. It is printed
    /// so that a new place it appears is seen.
    private static func settle(after step: String? = nil) async {
        try? await Task.sleep(nanoseconds: 400_000_000)
        guard let step else { return }
        checkComplaints(after: step)
    }

    private static func checkComplaints(after step: String) {
        let logged = (try? String(contentsOfFile: log, encoding: .utf8)) ?? ""
        let count = logged.components(separatedBy: "reentrant operation").count - 1
        if count > complaints {
            lines.append("note \(step): AppKit logged that a table was changed while it was updating")
        }
        complaints = count
    }

    /// Waits, six seconds at most, for what the window should come to show.
    /// A busy Mac draws late, and one look after a fixed pause then misses it.
    private static func eventually(_ shown: () -> Bool) async -> Bool {
        let deadline = ProcessInfo.processInfo.systemUptime + 6
        while !shown() && ProcessInfo.processInfo.systemUptime < deadline {
            try? await Task.sleep(nanoseconds: 20_000_000)
        }
        return shown()
    }

    // MARK: The window as assistive software is told about it

    private static func value(_ element: AXUIElement, _ attribute: String) -> CFTypeRef? {
        var value: CFTypeRef?
        return AXUIElementCopyAttributeValue(element, attribute as CFString, &value) == .success ? value : nil
    }

    private static func children(_ element: AXUIElement) -> [AXUIElement] {
        value(element, kAXChildrenAttribute) as? [AXUIElement] ?? []
    }

    private static func role(_ element: AXUIElement) -> String {
        value(element, kAXRoleAttribute) as? String ?? ""
    }

    private static func names(_ element: AXUIElement) -> [String] {
        [kAXDescriptionAttribute, kAXTitleAttribute].compactMap { value(element, $0) as? String }.filter { !$0.isEmpty }
    }

    private static func everything(in root: AXUIElement? = nil) -> [AXUIElement] {
        var found: [AXUIElement] = []
        func look(_ element: AXUIElement, _ depth: Int) {
            found.append(element)
            guard depth < 30, found.count < 5000 else { return }
            children(element).forEach { look($0, depth + 1) }
        }
        if let root {
            look(root, 0)
        } else {
            windows().forEach { look($0, 0) }
        }
        return found
    }

    private static func windows() -> [AXUIElement] {
        value(AXUIElementCreateApplication(getpid()), kAXWindowsAttribute) as? [AXUIElement] ?? []
    }

    private static func tables() -> [AXUIElement] {
        everything().filter { [kAXOutlineRole, kAXTableRole].contains(role($0)) }
    }

    private static func rows(_ table: AXUIElement) -> [AXUIElement] {
        children(table).filter { role($0) == kAXRowRole }
    }

    /// The sidebar's rows a person can choose. Its section headings are rows too.
    private static func sidebarRows() -> [AXUIElement] {
        guard let sidebar = tables().first else { return [] }
        return rows(sidebar).filter { row in !everything(in: row).contains { role($0) == "AXHeading" } }
    }

    /// The list of findings or sign-ins: the table with more than one column.
    private static func list() -> AXUIElement? {
        tables().first { table in children(table).filter { role($0) == kAXColumnRole }.count > 1 }
    }

    private static func button(_ name: String, in root: AXUIElement? = nil) -> AXUIElement? {
        everything(in: root).first { role($0) == kAXButtonRole && names($0).contains(name) }
    }

    /// A button drawn as a link. Assistive software may be told it is a link,
    /// or a button whose name is only in its text.
    private static func linkButton(_ name: String, in root: AXUIElement? = nil) -> AXUIElement? {
        everything(in: root).first { element in
            var actions: CFArray?
            guard [kAXButtonRole, "AXLink"].contains(role(element)),
                  AXUIElementCopyActionNames(element, &actions) == .success,
                  (actions as? [String])?.contains(kAXPressAction) == true else { return false }
            return names(element).contains(name) || written(in: element).contains(name)
        }
    }

    /// A toolbar button, where the page may have a button of the same name.
    private static func toolbarButton(_ name: String) -> AXUIElement? {
        everything().first { role($0) == kAXToolbarRole }.flatMap { button(name, in: $0) }
    }

    /// This app's icons in the menu bar, as assistive software is told about them.
    private static func menuBarItems() -> [AXUIElement] {
        guard let extras = value(AXUIElementCreateApplication(getpid()), kAXExtrasMenuBarAttribute),
              CFGetTypeID(extras) == AXUIElementGetTypeID() else { return [] }
        return children(extras as! AXUIElement)
    }

    /// Whether closing the last window would quit the app, asked as AppKit asks.
    private static func quitsWithLastWindow() -> Bool? {
        NSApp.delegate?.applicationShouldTerminateAfterLastWindowClosed?(NSApp)
    }

    /// Links the window opened, recorded instead of opened.
    private static var opened: [URL] = []
    /// Presses that would have opened Login Items in System Settings.
    private static var loginItemsOpened = 0

    /// The last button of this name, for a window that has more than one.
    private static func lastButton(_ name: String, in root: AXUIElement? = nil) -> AXUIElement? {
        everything(in: root).last { role($0) == kAXButtonRole && names($0).contains(name) }
    }

    /// Whether an item in one of the app's menus can be chosen.
    private static func menuEnabled(_ title: String) -> Bool? {
        appMenuItem(title).flatMap { value($0, kAXEnabledAttribute) as? Bool }
    }

    /// An item in one of the app's menus, as assistive software is told about it.
    private static func appMenuItem(_ title: String) -> AXUIElement? {
        appMenuItems(title).first
    }

    /// Every item of that name in the app's menus.
    private static func appMenuItems(_ title: String) -> [AXUIElement] {
        guard let bar = value(AXUIElementCreateApplication(getpid()), kAXMenuBarAttribute),
              CFGetTypeID(bar) == AXUIElementGetTypeID() else { return [] }
        return everything(in: (bar as! AXUIElement)).filter { role($0) == kAXMenuItemRole && names($0).contains(title) }
    }

    #if PREVIEW
    /// The update question, the Overview notice, the switch in Settings and
    /// Check for Updates…, with the sample's reply: nothing here goes online.
    /// Runs with Settings open and the review list full, so Overview shows
    /// its full page.
    private static func updates(_ model: AppModel) async {
        model.pane = .overview
        SampleEngine.newer = "9.9.9"
        SampleEngine.updateCheck = nil
        await model.refreshMonitor()
        expect(await eventually { written().contains("Check for Updates Automatically?") },
               "the first time, the app asks whether it may check for updates")
        expect(!everything().contains { role($0) == kAXSheetRole },
               "the update question is a row on the Overview, not an alert")
        await press(button("Don't Check"), "declining update checks",
                    until: { SampleEngine.updateCheck == false && !written().contains("Check for Updates Automatically?") })
        expect(SampleReleases.requests == 0, "declining update checks asks the sample's GitHub nothing")
        // One answer per launch, so the question is asked again as at a later launch.
        SampleEngine.updateCheck = nil
        model.updatesAnswered = false
        await model.refreshMonitor()
        expect(await eventually { written().contains("Check for Updates Automatically?") },
               "unanswered at a later launch, the app asks again")
        await press(button("Check Automatically"), "allowing update checks",
                    until: { SampleEngine.updateCheck == true && SampleReleases.requests == 1 })
        expect(await eventually { written().contains("Loose Keys 9.9.9 Is Available") && button("Download") != nil },
               "a newer version found by the automatic check is on Overview, with Download")
        await press(button("Download"), "pressing Download on Overview",
                    until: { opened.last == Releases.page })
        await press(toggle("Check for Updates Automatically"), "turning update checks off in Settings",
                    until: { SampleEngine.updateCheck == false && !written().contains("Loose Keys 9.9.9 Is Available") })
        SampleEngine.releaseFails = true
        await press(appMenuItem("Check for Updates…"), "choosing Check for Updates… with GitHub out of reach",
                    until: { written().contains("Couldn't Check for Updates") })
        await press(button("OK"), "closing the failed check", until: { model.updateResult == nil })
        SampleEngine.releaseFails = false
        await press(appMenuItem("Check for Updates…"), "choosing Check for Updates… with a newer version out",
                    until: { written().contains("Loose Keys 9.9.9 Is Available") && button("Not Now") != nil })
        await press(button("Not Now"), "putting the newer version off", until: { model.updateResult == nil })
        // The Overview has a Download too, so the alert's is pressed in its sheet.
        func alertSheet() -> AXUIElement? { everything().first { role($0) == kAXSheetRole } }
        await press(appMenuItem("Check for Updates…"), "choosing Check for Updates… with a newer version out, to download it",
                    until: { alertSheet().flatMap { button("Download", in: $0) } != nil })
        opened.removeAll()
        await press(alertSheet().flatMap { button("Download", in: $0) }, "pressing Download in the update alert",
                    until: { model.updateResult == nil && opened == [Releases.page] })
        SampleEngine.newer = nil
        await press(appMenuItem("Check for Updates…"), "choosing Check for Updates… with no newer version",
                    until: { written().contains("You're up to date.") })
        await press(button("OK"), "closing the up-to-date check",
                    until: { model.updateResult == nil && !written().contains("Loose Keys 9.9.9 Is Available") })
        expect(SampleReleases.requests == 5, "each check asks the sample's GitHub once (\(SampleReleases.requests) asked)")
        SampleEngine.updateCheck = false
        await model.refreshMonitor()
    }
    #endif

    /// A switch, known by the text beside it.
    private static func toggle(_ name: String, in root: AXUIElement? = nil) -> AXUIElement? {
        everything(in: root).first { element in
            guard role(element) == kAXCheckBoxRole, let title = value(element, kAXTitleUIElementAttribute),
                  CFGetTypeID(title) == AXUIElementGetTypeID() else { return false }
            return value(title as! AXUIElement, kAXValueAttribute) as? String == name
        }
    }

    /// The text in the window, or in one part of it, as assistive software reads it.
    private static func written(in root: AXUIElement? = nil) -> [String] {
        everything(in: root).compactMap { value($0, kAXValueAttribute) as? String }
    }

    private static func choose(_ row: AXUIElement, _ step: String) async {
        begin(step)
        AXUIElementSetAttributeValue(row, kAXSelectedAttribute as CFString, kCFBooleanTrue)
        await settle(after: step)
    }

    private static func press(_ element: AXUIElement?, _ step: String, until shown: (() -> Bool)? = nil) async {
        begin(step)
        if let element { AXUIElementPerformAction(element, kAXPressAction as CFString) }
        if let shown {
            expect(await eventually(shown), step)
            checkComplaints(after: step)
        } else {
            await settle(after: step)
        }
    }

    /// If the window stops, the last step named in its output is the one that stopped it.
    private static func begin(_ step: String) {
        fputs("step: \(step)\n", stderr)
    }

    // MARK: The checks

    private static func run(_ model: AppModel) async {
        if let window = NSApp.windows.first(where: { $0.isVisible && $0.canBecomeMain }), let screen = window.screen {
            expect(screen.visibleFrame.insetBy(dx: -1, dy: -1).contains(window.frame),
                   "the initial window fits within the screen's usable frame")
        } else {
            expect(false, "the initial window has a screen")
        }
        // The sidebar. Every row is chosen, last to first so that each choice
        // has to change the page, and between them they must open every page.
        var rowOf: [Pane: Int] = [:]
        for index in (0..<sidebarRows().count).reversed() {
            let before = model.pane
            await choose(sidebarRows()[index], "choosing sidebar row \(index + 1)")
            if let pane = model.pane, pane != before { rowOf[pane] = index }
        }
        expect(rowOf.count == 4, "choosing each sidebar row opens its page (\(rowOf.count) of 4 opened)")
        func open(_ pane: Pane) async {
            let rows = sidebarRows()
            if let index = rowOf[pane], index < rows.count { await choose(rows[index], "opening \(pane.rawValue)") }
        }

        #if PREVIEW
        // Stored sign-ins are saved, so the list has them before this window scans.
        await open(.stored)
        expect(await eventually {
            guard model.results == nil, let table = list() else { return false }
            return rows(table).count == SampleEngine.storedIds.count && model.storedCount == SampleEngine.storedIds.count
                && written().contains("auth.json")
        }, "before a scan, Stored Sign-ins lists the saved sign-ins, and its badge counts them")
        // The Overview's answer comes from the saved list.
        await open(.overview)
        expect(await eventually {
            let text = written()
            return text.contains("6 Loose Keys Worth Reviewing") && text.contains("From earlier scans.")
                && button("Review Items") != nil && linkButton("Show Places Not Checked") == nil
        }, "before a scan, the Overview answers from saved findings")
        // Before any scan this window has no report to save, so a list that
        // cannot be read must not send the person to save one.
        SampleEngine.storeFailed = true
        await model.refreshReview()
        await open(.review)
        let early = written()
        expect(model.results == nil && early.contains("Couldn't Open Worth Reviewing")
               && !early.contains { $0.contains("Save the report") },
               "before a scan, a review list that cannot be read does not tell the person to save a report")
        SampleEngine.storeFailed = false
        // Nor is an empty list "nothing to review" when nothing has been scanned.
        SampleEngine.nothingFound = true
        await model.refreshReview()
        await settle(after: "an empty review list before any scan")
        let unscanned = written()
        expect(model.results == nil && unscanned.contains("No Scan Yet") && !unscanned.contains("Nothing to Review"),
               "before any scan, an empty review list says there has been no scan, not that there is nothing to review")
        // Stored Sign-ins says "none" only once a scan has looked for them.
        SampleEngine.storedChecked = false
        await model.refreshReview()
        await open(.stored)
        expect(await eventually {
            written().contains("No Sign-ins Yet")
                && written().contains("After a scan, sign-ins your apps have saved appear here. Apps normally keep them, but malware can copy them.")
        } && !written().contains("No Stored Sign-ins"),
               "before a scan has looked for them, an empty Stored Sign-ins says there are none yet, not none")
        SampleEngine.monitoring = true
        await model.refreshMonitor()
        expect(await eventually {
            written().contains("No Sign-ins Yet")
                && written().contains("Sign-ins your apps have saved show up here as Loose Keys checks your files.")
        }, "with automatic scanning on, an empty Stored Sign-ins says sign-ins show up as it checks")
        SampleEngine.monitoring = false
        await model.refreshMonitor()
        SampleEngine.storedChecked = true
        await model.refreshReview()
        expect(await eventually { written().contains("No Stored Sign-ins") } && !written().contains("No Sign-ins Yet"),
               "once a scan has looked for them, an empty Stored Sign-ins says there are none")
        await open(.review)
        // With background checks on, "Yet" lasts only until their first full
        // pass, and a pass that could not read everything says so.
        SampleEngine.monitoring = true
        await model.refreshMonitor()
        expect(await eventually { written().contains("No Findings Yet") },
               "before the first full pass, an empty review list says background checks are still reading")
        // The Overview says the first pass is still going, not that nothing was scanned.
        await open(.overview)
        expect(await eventually {
            written().contains("Checking Your Files…") && written().contains("Findings appear here as they turn up.")
        } && !written().contains("No Scan Yet"),
               "during the first full pass with nothing found yet, the Overview says it is checking")
        await open(.review)
        SampleEngine.completedPass = true
        await model.refreshMonitor()
        expect(await eventually { written().contains("No Findings") && written().contains("Loose Keys checked your files and found nothing to review.") },
               "after a full pass that read everything, an empty review list says background checks found nothing")
        SampleEngine.unread = 3
        await model.refreshMonitor()
        expect(await eventually {
            written().contains("No Findings")
                && written().contains("Loose Keys checked your files and found nothing to review. \(NotCheckedText.some)")
        } && !written().contains { $0.contains("3 places") },
               "after a full pass that could not read everything, an empty review list says so, with no count")
        SampleEngine.monitoring = false
        SampleEngine.completedPass = false
        SampleEngine.unread = 0
        await model.refreshMonitor()
        // With nothing listed, nothing scanned and background checks off, the
        // first page offers one step, and the sidebar waits. The checks have
        // used the sidebar already, so this starts as a window just opened.
        model.pane = .overview
        model.sidebarAsked = false
        let welcomed = await eventually { written().contains("Find Passwords and Keys Left in Files") }
        // The page's own buttons: the toolbar has a Scan Now too.
        let toolbarParts = everything().first { role($0) == kAXToolbarRole }.map { everything(in: $0) } ?? []
        func enabled(_ name: String) -> Bool {
            let onPage = everything().first { element in
                role(element) == kAXButtonRole && names(element).contains(name) && !toolbarParts.contains { CFEqual($0, element) }
            }
            return onPage.flatMap { value($0, kAXEnabledAttribute) as? Bool } == true
        }
        expect(welcomed && enabled("Scan Now") && toggle("Scan Automatically") == nil && sidebarRows().isEmpty,
               "with nothing to list, the first page offers Scan Now alone and hides the sidebar")
        expect(await eventually { !everything().contains { role($0) == kAXToolbarRole } },
               "the first page hides the toolbar, with its Scan Now, Export and Filter")
        // Folders are listed in Settings; automatic scanning is offered after an answer.
        expect(button("Remove") == nil && !everything().contains { role($0) == kAXCheckBoxRole }
               && !written().contains("Checks your files whenever they change, even when the app is closed."),
               "the first page has no folder list or second choice")
        // With the toolbar hidden, the View menu has the sidebar, once.
        expect(appMenuItems("Show Sidebar").count == 1, "the View menu has one Show Sidebar (\(appMenuItems("Show Sidebar").count) found)")
        await press(appMenuItem("Show Sidebar"), "opening the sidebar from the first page with View > Show Sidebar")
        expect(await eventually { sidebarRows().count == 4 } && model.pane == .overview && model.showsWelcome,
               "the sidebar can be opened from the first page, and stays open there")
        model.sidebarAsked = false
        expect(await eventually { sidebarRows().isEmpty }, "the first page hides the sidebar again in a window just opened")
        // The first page's Scan Now starts by preparing folder access. Stopped
        // there with the toolbar's Stop Scan, it neither scans nor leaves
        // the first page.
        let scanGate = DispatchSemaphore(value: 0)
        SampleEngine.accessGate = scanGate
        let scansBefore = SampleEngine.scanRequests
        let firstScanNow = everything().first { role($0) == kAXButtonRole && names($0).contains("Scan Now") }
        await press(firstScanNow, "pressing the first page's Scan Now",
                    until: { model.preparingAccess && model.phase == .scanning && toolbarButton("Stop Scan") != nil })
        expect(button("Cancel Preparation") == nil && everything().filter { role($0) == kAXButtonRole && names($0).contains("Stop Scan") }.count == 1,
               "while folder access is prepared for a scan, the toolbar's Stop Scan is the one way to stop it")
        await press(toolbarButton("Stop Scan"), "stopping the scan with the toolbar's Stop Scan while folder access is prepared")
        SampleEngine.accessGate = nil
        scanGate.signal()
        expect(await eventually { !model.preparingAccess && model.phase == .ready && model.showsWelcome }
                   && model.results == nil && SampleEngine.scanRequests == scansBefore,
               "Stop Scan during folder access ends it without a scan, back on the first page")
        model.sidebarAsked = false
        expect(await eventually { sidebarRows().isEmpty }, "the first page hides the sidebar again after the stopped scan")
        // Turned on elsewhere, as from the menu bar or an earlier launch.
        SampleEngine.monitoring = true
        await model.refreshMonitor()
        expect(await eventually { sidebarRows().count == 4 && !model.showsWelcome },
               "background checks turned on leave the first page for the Overview and bring the sidebar back")
        expect(await eventually { toolbarButton("Scan Now") != nil },
               "leaving the first page brings the toolbar back")
        await press(appMenuItem("Hide Sidebar"), "hiding the sidebar with View > Hide Sidebar",
                    until: { sidebarRows().isEmpty && appMenuItem("Show Sidebar") != nil })
        await press(appMenuItem("Show Sidebar"), "showing the sidebar again with View > Show Sidebar",
                    until: { sidebarRows().count == 4 })
        SampleEngine.monitoring = false
        await model.refreshMonitor()
        expect(await eventually { model.showsWelcome } && sidebarRows().count == 4,
               "turning background checks off again brings the first page back but keeps the sidebar")
        SampleEngine.helperError = true
        await model.refreshMonitor()
        expect(await eventually { !model.showsWelcome && written().contains("Could not watch the home folder for changes.") },
               "an error the helper kept is shown on the full Overview, not hidden behind the first page")
        SampleEngine.helperError = false
        await model.refreshMonitor()
        model.pane = .review
        // Before the engine's first answer, which waits while the helper is
        // using the list, the page says neither.
        model.review = nil
        let reading = await eventually { written().contains("Reading the List") }
        expect(reading && !written().contains("No Scan Yet"),
               "before the engine's first answer, the review page says the list is being read")
        SampleEngine.nothingFound = false
        await model.refreshReview()
        await open(.overview)
        expect(model.results == nil && button("Add Folder or Drive…") == nil,
               "before a scan, Overview has no folder controls")
        // With every finding set aside and no scan in this window, Worth
        // Reviewing says where they went. It does not say places went
        // unchecked: before a scan, nothing says so.
        SampleEngine.allSetAside = true
        await model.refreshReview()
        await open(.review)
        let emptied = await eventually {
            (written() + everything().flatMap(names)).contains { $0.contains("You set aside everything the scan found") }
        }
        expect(model.results == nil && emptied
               && !(written() + everything().flatMap(names)).contains { $0.contains(NotCheckedText.some) },
               "before a scan, an empty Worth Reviewing with set-aside findings does not say places went unchecked")
        SampleEngine.allSetAside = false
        await model.refreshReview()
        await open(.overview)
        // The Overview's switch is the one Settings has, under the same name.
        func switchedOn(_ name: String) -> Bool? {
            toggle(name).flatMap { value($0, kAXValueAttribute) as? Int }.map { $0 == 1 }
        }
        expect(!SampleEngine.monitoring && switchedOn("Scan Automatically") == false
               && written().contains("Checks your files whenever they change, even when the app is closed."),
               "Overview offers automatic scanning, off and explained, without enabling it before consent")
        let accessGate = DispatchSemaphore(value: 0)
        SampleEngine.accessGate = accessGate
        await press(toggle("Scan Automatically"), "preparing folder access", until: { button("Cancel Preparation") != nil })
        // A form heading can reach assistive software as a name, not a value.
        expect(await eventually {
            let text = written()
            return (text + everything().flatMap(names)).contains("Preparing Folder Access")
                && text.contains("Answer the macOS prompts for Desktop, Documents and Downloads.")
                && button("Cancel Preparation") != nil
        }, "folder access explains the system prompts before starting checks")
        expect(!written().contains("Preparing folder access…"),
               "the Overview says it prepares folder access once, in its heading, not in the window's subtitle as well")
        expect(await eventually { menuEnabled("Scan Now") == false },
               "while folder access is prepared for automatic scanning, File > Scan Now can't be chosen")
        await press(button("Cancel Preparation"), "cancelling folder access preparation")
        SampleEngine.accessGate = nil
        accessGate.signal()
        expect(await eventually { !model.preparingAccess && switchedOn("Scan Automatically") == false },
               "cancelling preparation returns to the switch, still off")
        expect(!SampleEngine.monitoring && model.results == nil,
               "cancelled preparation neither enables the helper nor scans")
        await press(toggle("Scan Automatically"), "enabling background checks from Overview", until: { SampleEngine.monitoring && written().contains(BackgroundState.active.text) })
        expect(await eventually { SampleEngine.monitoring && written().contains(BackgroundState.active.text) && switchedOn("Scan Automatically") == true },
               "background setup starts the helper without a one-time scan")
        expect(model.results == nil && SampleEngine.notificationRequests == 0,
               "background consent neither runs a manual scan nor asks for notification permission")
        // Check timing, Pause and notifications that are off are in Settings.
        expect(!written().contains("Last Check") && button("Show Details") == nil && toggle("Pause Scanning") == nil,
               "the switch says only its state, and the Overview leaves check timing and Pause to Settings")
        // Findings that turn up during the first pass are not "from earlier scans".
        expect(written().contains("Still checking your files…") && !written().contains("From earlier scans."),
               "during the first full pass, the Overview's answer says checking goes on")
        // Just turned on, a helper that is not running yet is starting, not stopped.
        SampleEngine.helperStopped = true
        await model.refreshMonitor()
        expect(await eventually { written().contains(BackgroundState.starting.text) }
               && !written().contains(BackgroundState.helperNotRunning.text)
               && !written().contains("Open Settings to restart the helper."),
               "right after automatic scanning is turned on, the helper is starting, not reported as stopped")
        SampleEngine.helperStopped = false
        await model.refreshMonitor()
        SampleEngine.completedPass = true
        SampleEngine.lastCheck = "2026-10-14T12:30:00Z"
        await model.refreshMonitor()
        expect(await eventually { written().contains(BackgroundState.active.text) && !written().contains("Still checking your files…") },
               "completed initial checking leaves a simple active status")
        // After the helper's pass, the answer says when it last checked.
        let checkedAt = "Last checked \(localTime("2026-10-14T12:30:00Z"))."
        expect(await eventually { written().contains(checkedAt) } && !written().contains("From earlier scans."),
               "after the helper's full pass, the Overview says when it last checked, not that findings are from earlier scans")
        SampleEngine.permission = "not requested"
        await model.refreshReview()
        await settle()
        await press(button("Set Up Notifications…"), "requesting notifications from Overview")
        expect(await eventually { SampleEngine.notificationRequests == 1 && !model.awaitingPermission },
               "Overview requests notifications only on a separate press, and stops waiting once macOS answers")
        SampleEngine.permission = "denied"
        await model.refreshReview()
        await settle()
        model.openURL = { Checks.opened.append($0) }
        expect(await eventually { button("Set Up Notifications…") == nil && button("Open System Settings") == nil
                   && !written().contains("Notifications") },
               "once macOS has an answer, the Overview stops asking about notifications")
        // Asked about them, macOS said no: the Overview says they are off,
        // with the way to turn them on, and opens nothing by itself.
        SampleEngine.permission = "not requested"
        SampleEngine.declinesNotifications = true
        await model.refreshReview()
        await settle()
        Checks.opened.removeAll()
        await press(button("Set Up Notifications…"), "asking for notifications that macOS then turns down")
        expect(await eventually { written().contains("Off in System Settings") && button("Open System Settings") != nil }
                   && Checks.opened.isEmpty,
               "notifications turned down after Set Up Notifications… stay on the Overview as off, with Open System Settings")
        await press(button("Open System Settings"), "opening System Settings for notifications turned down")
        expect(Checks.opened.contains { $0.absoluteString.hasPrefix("x-apple.systempreferences:com.apple.Notifications-Settings") },
               "Open System Settings beside notifications that are off opens Loose Keys' notifications")
        SampleEngine.declinesNotifications = false
        await press(button("Review Items"), "opening background findings before a manual scan")
        expect(model.pane == .review && model.results == nil, "background findings can be reviewed without a manual scan")
        SampleEngine.monitoring = false
        SampleEngine.completedPass = false
        SampleEngine.lastCheck = nil
        await model.refreshMonitor()
        await open(.overview)
        #endif

        #if PREVIEW
        SampleEngine.scanSeconds = 3
        // Past folder access, where Stop Scan cancels the preparation instead.
        await press(toolbarButton("Scan Now"), "pressing Scan Now to stop it",
                    until: { model.phase == .scanning && !model.preparingAccess && toolbarButton("Stop Scan") != nil })
        expect(await eventually { menuEnabled("Stop Scan") == true }, "while a scan runs, File > Stop Scan can be chosen")
        expect(everything().filter { role($0) == kAXButtonRole && names($0).contains("Stop Scan") }.count == 1,
               "while a scan runs, Stop Scan is in the toolbar and not repeated on the Overview")
        let scanningTexts = everything().filter { role($0) == kAXStaticTextRole && value($0, kAXValueAttribute) as? String == "Scanning…" }.count
        let scanningNamed = everything().filter { names($0).contains("Scanning…") }.count
        expect(scanningTexts + scanningNamed == 1,
               "the Overview says a scan runs once, not in the window's subtitle as well (\(scanningTexts) texts, \(scanningNamed) names)")
        await press(appMenuItem("Stop Scan"), "choosing Stop Scan in the File menu",
                    until: { SampleEngine.cancelRequests == 1 })
        // The sample scan ends on its own whatever was asked.
        for _ in 0..<100 where model.phase == .scanning { await settle() }
        SampleEngine.scanSeconds = 0.3
        #endif
        await press(toolbarButton("Scan Now"), "pressing Scan Now")
        for _ in 0..<100 where model.phase != .done { await settle() }
        expect(model.phase == .done && model.results != nil, "pressing Scan Now runs a scan and shows its results")
        await open(.overview)
        let scanned = "Last scanned \(localTime(model.results?.generatedAt))."
        expect(await eventually { written().contains(scanned) }, "after a scan, the Overview's answer says when the scan ran")
        // Save Report… and Save Counts Only… open a save panel, which would
        // stop the check, so they are only seen to be offered.
        expect(await eventually { menuEnabled("Save Report…") == true && menuEnabled("Save Counts Only…") == true },
               "after a scan, the File menu offers Save Report… and Save Counts Only…")
        await press(appMenuItem("Copy Summary"), "choosing Copy Summary in the File menu",
                    until: { model.notice == "Summary copied" })
        #if PREVIEW
        // With results from a scan, a second scan still disables what exports them.
        SampleEngine.scanSeconds = 3
        await press(toolbarButton("Scan Now"), "pressing Scan Now with results to export",
                    until: { model.phase == .scanning && !model.preparingAccess && model.results != nil })
        expect(await eventually { menuEnabled("Save Report…") == false && menuEnabled("Save Counts Only…") == false
                   && menuEnabled("Copy Summary") == false },
               "while a scan runs, the File menu's export commands can't be chosen, as the toolbar's Export can't")
        let cancelsBefore = SampleEngine.cancelRequests
        await press(toolbarButton("Stop Scan"), "pressing the toolbar's Stop Scan",
                    until: { SampleEngine.cancelRequests == cancelsBefore + 1 })
        for _ in 0..<100 where model.phase == .scanning { await settle() }
        SampleEngine.scanSeconds = 0.3
        #endif
        // That the report lasts only until quitting is in docs/usage.md, not the window.
        expect(!written().contains { $0.contains("Save the report") },
               "after a manual scan, Overview has no note about saving the report")
        // Where the link is not found, say what assistive software was told it is.
        let linkRoles = everything().filter { element in
            names(element).contains("Show Places Not Checked") || value(element, kAXValueAttribute) as? String == "Show Places Not Checked"
        }.map(role)
        // What a scan found is in the sidebar, which has the same names and
        // counts. Looked for until the page has drawn the scan's end: one
        // look as the scan ended missed the link in two guest runs.
        expect(await eventually {
            button("Stored Sign-ins") == nil
                && (linkButton("Show Places Not Checked") != nil) == model.somePlacesNotChecked
                && button("Add Folder or Drive…") == nil
        }, "after a scan, Overview repeats no sidebar count, with folder controls left to Settings (the link's roles: \(linkRoles))")

        #if PREVIEW
        // The one way to what the scan could not read, without a count.
        await press(linkButton("Show Places Not Checked"), "opening the places not checked",
                    until: { model.showingPlaces && written().contains("~/Library/Mail") })
        // A section's heading may reach assistive software as a name, not a value.
        let listed = written() + everything().flatMap(names)
        let missing = ["No Access", "and 118 more"].filter { !listed.contains($0) }
        expect(missing.isEmpty && !listed.contains { $0.contains("(123)") },
               "the places not checked are listed under a title-case heading, with no count beside it (missing: \(missing))")
        model.showingPlaces = false
        await settle(after: "closing the places not checked")
        // A folder macOS kept from the scan is named, with the place to allow it.
        SampleEngine.documentsBlocked = true
        await press(toolbarButton("Scan Now"), "pressing Scan Now with Documents blocked")
        for _ in 0..<100 where model.phase == .scanning || model.blockedFolders.isEmpty { await settle() }
        expect(await eventually {
            written().contains("Documents Wasn't Checked") && written().contains("Allow access in System Settings, then scan again.")
        }, "a folder macOS kept from the scan is named on the Overview, with what to do")
        await press(button("Open System Settings"), "pressing Open System Settings for Documents",
                    until: { opened.last?.absoluteString.hasSuffix("Privacy_FilesAndFolders") == true })
        SampleEngine.documentsBlocked = false
        await press(toolbarButton("Scan Now"), "pressing Scan Now with Documents readable")
        for _ in 0..<100 where model.phase == .scanning || !model.blockedFolders.isEmpty { await settle() }
        expect(await eventually { !written().contains("Documents Wasn't Checked") },
               "once a scan reads Documents, the Overview no longer asks for access to it")
        #endif

        #if PREVIEW
        await open(.review)
        model.search = "earlier-session"
        expect(await eventually {
            guard let table = list(), rows(table).count == 1 else { return false }
            let text = written(in: rows(table)[0])
            return model.reviewRows.first?.id == 4
                && text.contains("Matches: ~/.claude/projects/shop/earlier-session.jsonl")
                && text.contains(".env")
                && text.contains("2 copies")
        }, "filtering a secondary copy keeps the representative row and explains the matching path")
        await open(.stored)
        model.search = "backup"
        expect(await eventually {
            guard let table = list(), rows(table).count == 1 else { return false }
            let text = written(in: rows(table)[0])
            return model.reviewRows.first?.id == 23 && text.contains("Matches: \(SampleEngine.storedCopy)")
        }, "on Stored Sign-ins, filtering a secondary copy explains the matching path")
        model.search = ""
        await settle(after: "clearing the grouped-copy filter")
        for pane in [Pane.review, .setAside, .stored] {
            await open(pane)
            model.search = "no matching fixture"
            expect(await eventually {
                written().contains("No Matches") && model.filterSummary.map { written().contains($0) } == true
                    && button("Clear Filter") != nil
            }, "a nonmatching filter explains its zero count and offers Clear Filter on \(pane.rawValue)")
            await press(button("Clear Filter"), "clearing a nonmatching filter")
            expect(await eventually {
                model.search.isEmpty && !written().contains("No Matches") && list().map { !rows($0).isEmpty } == true
            }, "Clear Filter restores the \(pane.rawValue) rows")
        }
        #endif

        // Both lists share one Filter field; a second one in the toolbar stops the app.
        for pane in [Pane.review, .stored, .review, .stored, .setAside, .overview, .stored] {
            await open(pane)
        }
        expect(model.pane == .stored, "moving between the lists and the other pages leaves the app running")

        // Pages changed faster than the inspector closes and opens, as with
        // the arrow keys in the sidebar. The window finishing a close it was
        // asked for on leaving a list is not the person hiding the inspector.
        // Explicitly open an empty inspector: this tests the person's choice,
        // not the initial compact layout.
        expect(!model.inspectorShown && !written().contains("No Selection"),
               "without a selection the lists leave room for their rows")
        await press(button("Inspector"), "explicitly opening the empty inspector")
        var kept = true
        for _ in 0..<5 {
            for _ in 0..<6 {
                model.pane = .overview
                try? await Task.sleep(nanoseconds: 150_000_000)
                model.pane = .stored
                try? await Task.sleep(nanoseconds: 150_000_000)
            }
            await settle()
            await settle()
            kept = kept && model.inspectorShown
            // Later steps need the inspector, whatever this one found.
            model.inspectorShown = true
            await settle()
        }
        expect(kept, "changing pages quickly leaves the inspector shown on the lists")
        // Faster still, as with the arrow keys in the sidebar. An inspector
        // closed by the page change while still opening made AppKit throw,
        // and the toolbar and inspector stopped responding.
        for _ in 0..<60 {
            model.pane = .overview
            try? await Task.sleep(nanoseconds: 80_000_000)
            model.pane = .stored
            try? await Task.sleep(nanoseconds: 80_000_000)
        }
        await settle()
        await settle()
        model.inspectorShown = true
        await settle()
        let thrown = ((try? String(contentsOfFile: log, encoding: .utf8)) ?? "").contains("Unable to install constraint")
        expect(!thrown, "changing between the Overview and a list faster than the inspector opens makes AppKit throw nothing")

        let toolbar = everything().first { role($0) == kAXToolbarRole }
        // A menu in the toolbar is a menu button to assistive software on
        // this Mac's macOS 26, and a pop-up button on macOS 14.
        let menus = everything(in: toolbar)
            .filter { [kAXMenuButtonRole, kAXPopUpButtonRole].contains(role($0)) }.map(names)
        expect(toolbar != nil && menus.count == 1 && menus[0].contains("Export") && !menus[0].contains("Share"),
               "assistive software is told the export button is called Export (it is told \(menus))")

        await settle()
        let shown = model.inspectorShown
        await press(button("Inspector"), "pressing Inspector")
        let hidden = model.inspectorShown
        await press(button("Inspector"), "pressing Inspector again")
        await settle()
        await settle()
        expect(shown && !hidden && model.inspectorShown,
               "the Inspector button hides the inspector and shows it again (shown \(shown), then \(hidden), then \(model.inspectorShown))")
        // Pressed again before the window has finished hiding it. The window
        // reports the end of the hide some 0.3 to 0.5 seconds after the first
        // press (measured on macOS 14), which is after the second.
        model.inspectorShown = true
        await settle()
        await settle()
        await settle()
        begin("pressing Inspector twice quickly")
        if let inspector = button("Inspector") {
            AXUIElementPerformAction(inspector, kAXPressAction as CFString)
            try? await Task.sleep(nanoseconds: 100_000_000)
            AXUIElementPerformAction(inspector, kAXPressAction as CFString)
        }
        for _ in 0..<5 { await settle() }
        expect(model.inspectorShown, "the Inspector button pressed twice quickly leaves the inspector shown")
        // Later steps need the inspector, whatever this one found.
        model.inspectorShown = true
        await settle()

        await open(.review)
        if let list = list(), rows(list).count == model.reviewRows.count, model.reviewRows.count > 2 {
            let chosen = model.reviewRows[1].id
            await choose(rows(list)[1], "choosing a finding")
            expect(model.selectedReview == chosen, "choosing a finding selects it")
            expect(button("Copy Path") != nil, "the inspector shows the chosen finding")
            await press(appMenuItem("Hide Inspector"), "choosing Hide Inspector in the View menu",
                        until: { !model.inspectorShown })
            expect(await eventually { appMenuItem("Show Inspector") != nil },
                   "with the inspector hidden, the View menu's item says Show Inspector")
            await press(appMenuItem("Show Inspector"), "choosing Show Inspector in the View menu",
                        until: { model.inspectorShown && button("Copy Path") != nil })
            expect(await eventually { menuEnabled("Show in Finder") == true && menuEnabled("Copy Path") == true },
                   "the Item menu offers Show in Finder and Copy Path for the chosen finding")
            // The control for the Set Aside check below: the heading is visible here.
            expect((written() + everything().flatMap(names)).contains { $0.contains("What to Do") },
                   "an open finding's inspector shows What to Do")
            let why = EngineText.shown(model.reviewRows[1].explanation)
            expect(!written().contains(why), "why a finding is here starts folded, below what to do")
            await press(button("Show Explanation"), "unfolding why the finding is here")
            expect(await eventually { written().contains(why) }, "the inspector unfolds why the finding is here")
            await press(button("Hide Explanation"), "folding why the finding is here")
            expect(await eventually { !written().contains(why) }, "the inspector folds why the finding is here again")
            let folded = !written().contains("Rule")
            await press(button("Show Details"), "unfolding the finding's details")
            expect(await eventually { folded && written().contains("Rule") },
                   "the finding's details start folded and unfold")
            await press(button("Hide Details"), "folding the finding's details")
            expect(await eventually { !written().contains("Rule") }, "the inspector folds the finding's details again")
            let keys: [PartialKeyPath<ReviewItem>] = [\.shownTitle, \.path, \.riskLevel, \.firstSeenOrder]
            await headings(list, keys, sort: { model.reviewSort }, rows: { model.reviewRows })
            expect(model.selectedReview == chosen, "sorting keeps the chosen finding selected")
            begin("selecting several findings")
            let selected = Array(rows(list).prefix(2))
            let selectionResult = AXUIElementSetAttributeValue(list, kAXSelectedRowsAttribute as CFString, selected as CFArray)
            await settle(after: "selecting several findings")
            expect(selectionResult == .success && model.selectedReviews.count == 2,
                   "the table accepts multiple selected rows")
            expect(model.currentReview == nil && button("Copy Path") == nil,
                   "multiple selection does not offer an arbitrary file action")
            expect(await eventually { menuEnabled("Show in Finder") == false && menuEnabled("Copy Path") == false },
                   "with several findings chosen, the Item menu offers no file action")
            expect(await eventually { written().contains("2 items selected") },
                   "the inspector shows the selected count")
            model.search = "no finding has this text"
            await settle(after: "filtering out the selected finding")
            expect(model.selectedReview == nil && model.currentReview == nil, "a finding the filter hides is no longer selected")
            model.search = ""
            await settle(after: "clearing the filter")
            #if PREVIEW
            // A browser's saved logins are one finding with a count, which the
            // engine sends apart from the subject.
            if let counted = model.reviewRows.firstIndex(where: { $0.detail != nil }), counted < rows(list).count {
                await choose(rows(list)[counted], "choosing a finding that has a count")
                let shown = await eventually { written().contains("214 saved logins") }
                model.search = "saved logins"
                await settle(after: "filtering by a finding's count")
                expect(shown && model.reviewRows.count == 1,
                       "the inspector shows a finding's count of saved logins, and the filter finds it by that count (shown \(shown), \(model.reviewRows.count) of 1 rows)")
                model.search = ""
                model.selectedReview = nil
                await settle(after: "clearing the filter and the choice")
            } else {
                expect(false, "the sample list has a finding with a count")
            }
            // What to Do opens the page the rule names, recorded instead of opened.
            if let linked = model.reviewRows.firstIndex(where: { $0.link != nil }), linked < rows(list).count {
                await choose(rows(list)[linked], "choosing a finding whose rule names a page to revoke it")
                await press(button("Open the Page to Revoke It"), "pressing Open the Page to Revoke It",
                            until: { opened.last?.absoluteString == SampleEngine.revokePage })
                model.selectedReview = nil
                await settle(after: "clearing the choice")
            } else {
                expect(false, "the sample list has a finding whose rule names a page")
            }
            // A finding in a folder scans can skip offers Stop Checking, which
            // names the finding; once skipped, the inspector says so.
            if let inFolder = model.reviewRows.firstIndex(where: { $0.folder != nil && $0.status == "open" }),
               inFolder < rows(list).count, let folder = model.reviewRows[inFolder].folder {
                let id = model.reviewRows[inFolder].id
                await choose(rows(list)[inFolder], "choosing a finding in a folder scans can skip")
                SampleEngine.folderRequest = [:]
                await press(button("Stop Checking \(folder)"), "pressing Stop Checking in the inspector",
                            until: { SampleEngine.folderRequest["id"] as? Int == id
                                && written().contains("Scans will skip \(folder). You can include it again in Settings.") })
                SampleEngine.skipped = ["~/Movies/Raw"]
                await model.refreshReview()
                model.selectedReview = nil
                await settle(after: "including the folder again and clearing the choice")
            } else {
                expect(false, "the sample list has an open finding in a folder scans can skip")
            }
            // The app acts only on plain names. For a file with another kind
            // of name it says so, and offers no button that could only fail.
            if let odd = model.reviewRows.firstIndex(where: { $0.path.contains("u{e9}") }), odd < rows(list).count {
                await choose(rows(list)[odd], "choosing a finding whose name the app does not act on")
                let told = await eventually { written().contains { $0.contains("unusual characters") } }
                expect(told && button("Copy Path") == nil && button("Show in Finder") == nil,
                       "a finding whose name the app does not act on says so, and has no Show in Finder or Copy Path")
                model.selectedReview = nil
                await settle(after: "clearing the choice")
            } else {
                expect(false, "the sample list has a finding whose name the app does not act on")
            }
            // There is no Status column: only a row that is not open says
            // what it is, beside the finding's name.
            if let fixed = model.reviewRows.firstIndex(where: { $0.status == "fixed" }),
               let open = model.reviewRows.firstIndex(where: { $0.status == "open" }),
               max(fixed, open) < rows(list).count {
                expect(written(in: rows(list)[fixed]).contains("Fixed") && !written(in: rows(list)[open]).contains("Open"),
                       "a fixed finding says Fixed beside its name, and an open one says nothing more")
            } else {
                expect(false, "the sample list has a fixed finding and an open one")
            }
            #endif
        } else {
            expect(false, "the review list is a table with a row for each finding")
        }

        #if PREVIEW
        await open(.setAside)
        if let table = list(), let row = rows(table).first {
            expect(headingButtons(table).count == 4 && !headingButtons(table).flatMap(names).contains("Status"),
                   "Set Aside omits the redundant Status column")
            await choose(row, "choosing a set-aside finding")
            expect(model.reviewRows.map(\.id) == [6] && model.currentReview?.id == 6,
                   "Set Aside has its own table and inspector")
            if let hide = button("Hide Details") {
                await press(hide, "collapsing the finding details")
            }
            // Form headings can be AX titles; grouped text can be one value.
            expect(await eventually {
                let text = (written() + everything().flatMap(names)).joined(separator: "\n")
                guard let keptReason = SetAsideReason.all.first(where: { $0.id == "kept" }) else { return false }
                // The sidebar row and the window title say "Set Aside" too,
                // so the heading is looked for everywhere but there.
                let toolbar = everything().first { role($0) == kAXToolbarRole }
                let chrome = Set(windows().map(CFHash)
                    + [tables().first, toolbar].compactMap { $0 }.flatMap { everything(in: $0) }.map(CFHash))
                let heading = everything().contains { element in
                    !chrome.contains(CFHash(element))
                        && (names(element) + [value(element, kAXValueAttribute) as? String].compactMap { $0 }).contains("Set Aside")
                }
                return heading && text.contains(keptReason.summary) && !text.contains(keptReason.returns)
            }, "the decision card shows the saved reason with its explanation collapsed")
            expect(await eventually { (written() + everything().flatMap(names)).contains(localDay(SampleEngine.setAsideAt)) },
                   "the decision card shows the day the finding was set aside")
            await press(button("Show Details"), "revealing the decision explanation in Details")
            expect(await eventually {
                let text = (written() + everything().flatMap(names)).joined(separator: "\n")
                guard let keptReason = SetAsideReason.all.first(where: { $0.id == "kept" }) else { return false }
                return text.contains(keptReason.returns)
            }, "Details reveals the complete decision scope and return conditions")
            await press(button("Hide Details"), "hiding the decision explanation")
            expect(await eventually {
                let text = (written() + everything().flatMap(names)).joined(separator: "\n")
                guard let keptReason = SetAsideReason.all.first(where: { $0.id == "kept" }) else { return false }
                return !text.contains(keptReason.returns)
            }, "hiding Details collapses the decision explanation again")
            // Form headings can be AX titles, so titles are searched too.
            expect(!(written() + everything().flatMap(names)).contains { $0.contains("What to Do") },
                   "a set-aside finding leads with the decision instead of remediation")
            model.search = "npm"
            await settle(after: "filtering Set Aside")
            expect(model.pane == .setAside && model.reviewRows.map(\.id) == [6], "filtering Set Aside stays on that page")
            model.search = ""
            await press(button("Move to Worth Reviewing"), "returning a set-aside finding to review")
            expect(await eventually { model.pane == .review && model.currentReview?.id == 6 },
                   "Move to Worth Reviewing opens Worth Reviewing with the returned finding selected")
            if model.currentReview != nil {
                // The Item menu's Set Aside has the inspector's reasons.
                let reason = SetAsideReason.all.first { $0.id == "not-a-credential" }?.label ?? ""
                await press(appMenuItem(reason), "setting the finding aside with the Item menu")
                expect(await eventually { model.setAsideCount == 1 && !model.reviewRows.contains { $0.id == 6 } },
                       "saving a decision moves the finding to Set Aside")
                expect(model.pane == .review && !model.reviewRows.contains { $0.id == 6 }
                       && model.currentReview == nil && button("Copy Path") == nil,
                       "setting aside removes the row and its inspector while keeping the review page open")
                await open(.setAside)
                if let table = list(), let row = rows(table).first {
                    await choose(row, "selecting the newly set-aside finding")
                }
                await press(appMenuItem("Move to Worth Reviewing"), "returning the finding from Set Aside with the Item menu")
                expect(await eventually { model.pane == .review && model.reviewRows.contains { $0.id == 6 } && model.setAsideCount == 0 },
                       "Move to Worth Reviewing restores the finding to Worth Reviewing")
            }
            await open(.setAside)
            expect(await eventually { written().contains("No Items Set Aside") },
                   "the Set Aside page explains an empty list")
            for reason in SetAsideReason.all + [SetAsideReason.legacy, SetAsideReason.expected] {
                await open(.review)
                guard let item = model.reviewRows.first(where: { $0.id == 6 }) else {
                    expect(false, "the finding is available for each decision reason")
                    break
                }
                model.decide(item, reason: reason.id)
                expect(await eventually { model.setAsideCount == 1 }, "saving the reason: \(reason.label)")
                await open(.setAside)
                if let table = list(), let row = rows(table).first {
                    await choose(row, "inspecting the saved reason")
                }
                expect(await eventually { (written() + everything().flatMap(names)).joined(separator: "\n").contains(reason.summary) },
                       "the inspector shows the chosen reason: \(reason.label)")
                await press(button("Move to Worth Reviewing"), "returning the finding for the next choice")
                expect(await eventually { model.pane == .review && model.setAsideCount == 0 },
                       "each decision can be returned to review")
            }
            await open(.review)
            let batch = Set(model.reviewRows.filter { $0.status == "open" }.prefix(2).map(\.id))
            model.selectedReviews = batch
            await settle(after: "selecting findings to set aside together")
            expect(batch.count == 2 && everything().flatMap(names).contains("Set Aside…"),
                   "multiple findings offer Set Aside")
            // Menus are chosen through the model, as in the single-item checks.
            model.decideSelection(reason: "testing")
            expect(await eventually { !model.decidingSelection && batch.allSatisfy { model.reviewEntry($0)?.status == "set-aside" } },
                   "Set Aside applies to each selected finding")
            await open(.setAside)
            model.selectedReviews = batch
            await settle(after: "selecting findings to return together")
            await press(button("Move to Worth Reviewing"), "returning several findings to review")
            expect(await eventually { !model.decidingSelection && batch.allSatisfy { model.reviewEntry($0)?.status == "open" } },
                   "Move to Worth Reviewing returns each selected finding")
            SampleEngine.decisions = [6: "kept"]
            await model.refreshReview()
            await open(.review)
            expect(!model.reviewRows.contains { $0.id == 6 }, "an existing decision stays out of Worth Reviewing after refresh")
            model.selectedReview = nil
        } else {
            expect(false, "Set Aside has the sample's decided finding")
        }
        #endif

        await open(.stored)
        if let list = list(), rows(list).count == model.reviewRows.count, model.reviewRows.count > 1 {
            // With no heading pressed, sign-ins are in the order of their
            // titles, each rule's together. The rows are read from the window.
            let drawn = zip(rows(list), model.reviewRows).allSatisfy { row, item in
                written(in: row).contains((item.path as NSString).lastPathComponent)
            }
            expect(model.storedSort.isEmpty && model.reviewRows.allSatisfy(\.isStored) && drawn
                   && headingButtons(list).flatMap(names) == ["Sign-in", "Where"],
                   "Stored Sign-ins lists only stored sign-ins, under Sign-in and Where (shown \(model.reviewRows.map(\.id)))")
            #if PREVIEW
            // Rows a pressed heading ranks the same keep that order: the
            // sample's sign-ins of one rule share a title.
            await press(headingButtons(list).first { names($0).contains("Sign-in") }, "pressing the Sign-in heading")
            let shown = model.reviewRows
            let level = zip(shown, shown.dropFirst()).filter { pair in
                model.storedSort.allSatisfy { $0.compare(pair.0, pair.1) == .orderedSame }
            }
            expect(!model.storedSort.isEmpty && !level.isEmpty && level.allSatisfy { $0.id < $1.id },
                   "sign-ins a pressed heading ranks the same stay in their first order (shown \(shown.map(\.id)))")
            model.storedSort = []
            await settle(after: "putting the sign-ins back in their first order")
            #endif
            let keys: [PartialKeyPath<ReviewItem>] = [\.shownTitle, \.path]
            await headings(list, keys, sort: { model.storedSort }, rows: { model.reviewRows })
            model.storedSort = []
            await settle(after: "putting the sign-ins back in their first order")
            let at = model.reviewRows.firstIndex { $0.link != nil } ?? 0
            let chosen = model.reviewRows[at].id
            await choose(rows(list)[at], "choosing a stored sign-in")
            expect(model.selectedReview == chosen, "choosing a stored sign-in selects it")
            #if PREVIEW
            await press(button("Open the Page to Manage It"), "pressing Open the Page to Manage It",
                        until: { opened.last?.absoluteString == SampleEngine.managePage })
            // The file actions name the sign-in by its id, as for a finding.
            SampleEngine.pathRequest = [:]
            await press(button("Copy Path"), "copying a stored sign-in's path",
                        until: { SampleEngine.pathRequest["index"] as? Int == chosen && SampleEngine.pathRequest.count == 1 })
            expect(await eventually { menuEnabled("Show in Finder") == true && menuEnabled("Copy Path") == true },
                   "the Item menu offers Show in Finder and Copy Path for the chosen sign-in")
            // Only Keeping It Here on Purpose: the Item menu has no other reason here.
            let kept = SetAsideReason.storedKept.label
            expect(await eventually {
                (written() + everything().flatMap(names)).contains("Set Aside…")
                    && appMenuItem(kept) != nil && appMenuItem(SetAsideReason.all[0].label) == nil
            } && model.setAsideReasons.map(\.id) == ["kept"],
                   "a stored sign-in can be set aside only as Keeping It Here on Purpose")
            #endif
            model.search = "no sign-in has this text"
            await settle(after: "filtering out the selected sign-in")
            expect(model.selectedReview == nil && model.currentReview == nil, "a sign-in the filter hides is no longer selected")
            #if PREVIEW
            model.search = "Claude Code"
            await settle(after: "filtering by what the inspector shows under a sign-in's title")
            expect(model.reviewRows.count == 1, "the filter finds a sign-in by what the inspector shows under its title (\(model.reviewRows.count) of 1 rows)")
            #endif
            model.search = ""
            await settle(after: "clearing the filter")
            #if PREVIEW
            await storedSetAside(model, chosen: chosen, open: open)
            #endif
        } else {
            expect(false, "the stored list is a table with a row for each sign-in")
        }

        // The Filter field is on the lists it filters and not on the Overview.
        // Taken out and put back as the page changes, it must not stop the app.
        let filterShown = { everything().contains { value($0, kAXSubroleAttribute) as? String == kAXSearchFieldSubrole } }
        for round in 1...5 {
            await open(.overview)
            expect(await eventually { !filterShown() }, "the Overview has no Filter field (round \(round))")
            for pane in [Pane.review, .setAside, .stored] {
                await open(pane)
                expect(await eventually { filterShown() }, "the Filter field is in the toolbar on \(pane.rawValue) (round \(round))")
            }
        }

        // A file's name is whatever its maker chose. Copied for pasting after a command, it is quoted.
        expect(model.quotedIfNeeded("/Users/me/.aws/credentials") == "/Users/me/.aws/credentials"
               && model.quotedIfNeeded("/tmp/x -rf /Users/me") == "'/tmp/x -rf /Users/me'"
               && model.quotedIfNeeded("/tmp/it's;here") == "'/tmp/it'\\''s;here'",
               "a copied path with characters a shell acts on is in quotes")

        #if PREVIEW
        // A review list that cannot be read must never read as nothing found.
        SampleEngine.storeFailed = true
        await model.refreshReview()
        await open(.review)
        let texts = everything().compactMap { value($0, kAXValueAttribute) as? String }
        expect(texts.contains("Couldn't Open Worth Reviewing") && !texts.contains("Nothing to Review")
               && model.reviewCount == model.results?.review,
               "a review list that cannot be read says so, and the count beside it is the scan's own")
        // The engine keeps the failure until the app is opened again, and
        // after a scan the report has what the list does not show.
        let advice = texts.first { $0.contains("reopen the app") } ?? ""
        expect(advice.contains("reopen the app") && advice.contains("Save the report"),
               "a review list that cannot be read says that quitting the app and opening it again reads it again, and that the report has the findings")
        await open(.stored)
        expect(await eventually { written().contains("Couldn't Open Stored Sign-ins") }
               && !written().contains("No Stored Sign-ins") && list() == nil && model.storedCount == model.results?.stored,
               "Stored Sign-ins that cannot be read says so, and the count beside it is the scan's own")
        await open(.setAside)
        expect(await eventually { written().contains("Couldn't Open Set Aside") }
               && !written().contains("Couldn't Open Worth Reviewing") && list() == nil,
               "Set Aside that cannot be read names Set Aside as the list that couldn't be opened")
        await open(.review)
        SampleEngine.storeFailed = false
        await model.refreshReview()
        await settle(after: "the review list returning")

        // A finding chosen before the list failed has buttons that can now only fail.
        if let table = list(), let at = model.reviewRows.firstIndex(where: \.actionable), at < rows(table).count {
            await choose(rows(table)[at], "choosing a finding before the list fails")
            let shown = await eventually { button("Copy Path") != nil }
            SampleEngine.storeFailed = true
            await model.refreshReview()
            await settle(after: "the review list failing with a finding chosen")
            let gone = await eventually { button("Copy Path") == nil }
            expect(shown && gone,
                   "the inspector lets go of a finding when the review list can no longer be read or saved")
            SampleEngine.storeFailed = false
            await model.refreshReview()
            model.selectedReview = nil
            await settle(after: "the review list returning with no finding chosen")
        } else {
            expect(false, "the review list is shown again once it can be read")
        }

        // The save of a decision can be what fails. The engine sends no event
        // then, so the model has to ask for the list again by itself. Checked
        // on a model that is in no window, so that no alert is put on screen.
        let deciding = AppModel(engine: model.engine)
        await deciding.refreshReview()
        if let item = deciding.reviewRows.first {
            deciding.selectedReview = item.id
            SampleEngine.saveFails = true
            deciding.decide(item, reason: "kept")
            for _ in 0..<25 where deciding.failure == nil { await settle() }
            expect(deciding.failure != nil && deciding.reviewProblem != nil && deciding.currentReview == nil,
                   "when a decision cannot be saved, the review list is asked for again and is then unavailable, with no finding current")
            // The choice is kept in case the list comes back, and a filter
            // that still shows the chosen finding does not drop it.
            deciding.search = String(item.title.prefix(4))
            expect(deciding.selectedReview == item.id,
                   "a filter that still shows the chosen finding keeps it chosen while the review list cannot be used")
            SampleEngine.saveFails = false
            SampleEngine.storeFailed = false
        } else {
            expect(false, "the review list has a finding to decide")
        }

        // A report the person chose to replace is not lost when the new one
        // cannot be written.
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("window-check-report-\(getpid())")
        let old = folder.appendingPathComponent("report.json")
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        try? Data("the earlier report".utf8).write(to: old)
        SampleEngine.reportFails = true
        let unsaved = AppModel(engine: model.engine)
        var failed = false
        do { try await unsaved.write(feedback: false, to: old) } catch { failed = true }
        expect(failed && (try? String(contentsOf: old, encoding: .utf8)) == "the earlier report",
               "a report that cannot be written leaves the one it was to replace where it was")
        SampleEngine.reportFails = false
        // The sample engine writes no file, so the old report goes to the
        // Trash and the new one, which isn't there, can't take its name.
        try? Data("the earlier report".utf8).write(to: old)
        var moveFailure = ""
        do { try await unsaved.write(feedback: false, to: old) } catch { moveFailure = error.localizedDescription }
        let trashed = !FileManager.default.fileExists(atPath: old.path)
        expect(trashed && moveFailure.contains("is in the Trash") && moveFailure.contains("report-"),
               "when the old report went to the Trash but the new one couldn't take its name, the alert says so (trashed: \(trashed), it said: \(moveFailure))")
        try? FileManager.default.removeItem(at: folder)

        // The request for the list can fail as well. What the window holds
        // is then an older list, or none, and neither is what was found.
        SampleEngine.refused = true
        await model.refreshReview()
        // The alert that reports the failure is not what is checked here. It
        // is closed with OK, as a person closes it: cleared in code while it
        // was still opening, it stopped the check inside AppKit.
        _ = await eventually { button("OK") != nil }
        await press(button("OK"), "closing the alert about the review list",
                    until: { model.failure == nil })
        await settle(after: "the request for the review list failing")
        let refused = written()
        expect(refused.contains("Couldn't Open Worth Reviewing") && !refused.contains("Nothing to Review")
               && list() == nil && model.reviewSummary.isEmpty,
               "a review list the window could not get says so, and shows no older list or count in its place")
        // The Overview's answer is then the scan's own count, never "nothing".
        await open(.overview)
        let fromScan = model.results?.review ?? 0
        expect(await eventually {
            let text = written()
            return fromScan > 1 && text.contains("\(fromScan) Loose Keys Worth Reviewing")
                && text.contains("Loose Keys couldn't open its saved list, so the Worth Reviewing count is from the last scan.")
                && !text.contains("Nothing Worth Reviewing")
        }, "with the review list unreadable, the Overview answers with the scan's own count and says why")
        await open(.review)
        // The same from the start: a window that never got the list, then a scan.
        let fresh = AppModel(engine: model.engine)
        await fresh.refresh()
        fresh.startScan()
        for _ in 0..<100 where fresh.phase != .done { await settle() }
        expect(fresh.review == nil && fresh.results != nil && fresh.reviewCount == fresh.results?.review,
               "after a scan, the count beside a review list the window never got is the scan's own (it is \(fresh.reviewCount))")
        // Its status read started reads every 30 seconds, as for the menu
        // bar. It is in no window, so they stop as they do when the app quits.
        fresh.prepareToQuit()
        SampleEngine.refused = false
        await model.refreshReview()
        await settle(after: "the review list being got again")

        // One credential in two files is one row, named by a copy that still
        // needs a decision. Keeping the first copy leaves the second to
        // decide, and the row takes its id. It is the same row, still open.
        if let table = list(), let at = model.reviewRows.firstIndex(where: { $0.places.count > 1 }),
           at < rows(table).count {
            let first = model.reviewRows[at]
            await choose(rows(table)[at], "choosing a credential that is in two files")
            if let copy = first.places.first(where: { $0.id != first.id }) {
                func copyButton() -> AXUIElement? {
                    everything().first { value($0, kAXIdentifierAttribute) as? String == "copy-path-review-\(copy.id)" }
                }
                await press(button("Show Copies"), "opening the grouped-copy list")
                let available = await eventually { copyButton() != nil }
                expect(available, "a secondary grouped copy has its own Copy Path control")
                if available {
                    SampleEngine.pathRequest = [:]
                    await press(copyButton(), "copying the secondary file's path")
                    expect(await eventually { SampleEngine.pathRequest["index"] as? Int == copy.id
                        && SampleEngine.pathRequest.count == 1 },
                           "a grouped-copy file action sends that copy's existing id to item_path")
                    await press(button("Hide Copies"), "closing the grouped-copy list",
                                until: { copyButton() == nil && button("Show Copies") != nil })
                }
            } else {
                expect(false, "the grouped credential has a secondary copy to act on")
            }
            model.decide(first, reason: "kept")
            for _ in 0..<25 where model.review?.items.contains(where: { $0.id == first.id }) == true { await settle() }
            await settle(after: "keeping the first copy of a credential in two files")
            let entry = model.review?.items.first { $0.places.contains { $0.id == first.id } }
            let row = model.reviewRows.firstIndex { $0.id == entry?.id }
            let drawn = await eventually {
                let marked = rows(table).map { value($0, kAXSelectedAttribute) as? Bool ?? false }
                return row.map { $0 < marked.count && marked[$0] } == true && button("Copy Path") != nil
            }
            let followed = entry != nil && entry?.id != first.id && model.selectedReview == entry?.id && drawn
            let seen = "the row took the id \(entry.map { "\($0.id)" } ?? "of no entry"), and the id chosen was \(model.selectedReview.map { "\($0)" } ?? "none")"
            // When the first copy needs a decision again, it names the row once more.
            SampleEngine.kept = []
            await model.refreshReview()
            await settle(after: "the first copy needing a decision again")
            let back = await eventually { button("Copy Path") != nil }
            expect(followed && model.selectedReview == first.id && back,
                   "a credential in two files stays chosen when a decision on one copy changes which copy names its row (\(seen))")
            model.selectedReview = nil
            await settle(after: "choosing no finding")
        } else {
            expect(false, "the sample's credential in two files is one row in the review list")
        }

        // The engine reports a full review list in the field where it
        // reports a storage failure. The background checks still run then,
        // and consent to them can still be withdrawn.
        SampleEngine.listFull = true
        SampleEngine.monitoring = true
        SampleEngine.unread = 3
        await model.refreshReview()
        await model.refreshMonitor()
        await open(.overview)
        let state = written()
        expect(state.contains(BackgroundState.active.text) && !state.contains(BackgroundState.unavailable.text),
               "with the review list full, the Overview says background checks are on, not unavailable")
        let before = windows()
        await press(button("Settings…"), "pressing Settings…")
        // The Overview has a switch of the same name, so wait for the window.
        for _ in 0..<10 where windows().count <= before.count { await settle() }
        let settingsWindow = windows().first { window in !before.contains { CFEqual($0, window) } }
        let consent = settingsWindow.flatMap { toggle("Scan Automatically", in: $0) }
        expect(consent != nil && written(in: settingsWindow).contains("Active"),
               "Settings shows the state of automatic scanning under its switch")
        expect(written(in: settingsWindow).contains(SampleEngine.fullNotice),
               "Settings says the review list is full, beside automatic scanning")
        expect(!written(in: settingsWindow).contains { $0.contains("3 places") }
               && linkButton("Show Places Not Checked", in: settingsWindow) == nil,
               "Settings neither counts the places the helper's last full pass did not read nor links to them")
        expect(await eventually { written(in: settingsWindow).contains("Last Check") && written(in: settingsWindow).contains("Last Full Scan") },
               "Settings shows check timing while automatic scanning is on")
        expect(written(in: settingsWindow).contains("Always included") && button("Add Folder or Drive…", in: settingsWindow) != nil,
               "Settings lists the places to check, with Add Folder or Drive…")
        SampleEngine.folderRequest = [:]
        await press(button("Remove", in: settingsWindow), "pressing Remove beside an added folder in Settings")
        for _ in 0..<10 where SampleEngine.folderRequest.isEmpty { await settle() }
        let removing = SampleEngine.folderRequest
        expect(removing["index"] as? Int == 0 && removing["shown"] as? String == "/Volumes/Backup",
               "Remove in Settings says which folder it was shown for (it sent \(removing["shown"] ?? "nothing"))")
        // A folder left out with Stop Checking is listed apart from the places
        // to check, and named by its place and by what is shown, as Remove is.
        // A section's heading may reach assistive software as a name, not a value.
        let placesText = written(in: settingsWindow) + everything(in: settingsWindow).flatMap(names)
        expect(placesText.contains("~/Movies/Raw") && placesText.contains("Skipped Folders")
               && placesText.contains(FolderScopeText.exceptions),
               "Settings lists a skipped folder under Skipped Folders, with what full scans still read in it")
        SampleEngine.folderRequest = [:]
        await press(button("Include Again", in: settingsWindow), "pressing Include Again beside a skipped folder in Settings")
        for _ in 0..<10 where SampleEngine.folderRequest.isEmpty { await settle() }
        let including = SampleEngine.folderRequest
        expect(including["index"] as? Int == 0 && including["shown"] as? String == "~/Movies/Raw",
               "Include Again says which folder it was shown for (it sent \(including["shown"] ?? "nothing"))")
        // A review list that cannot be read says nothing about what is skipped.
        SampleEngine.storeFailed = true
        await model.refreshReview()
        expect(await eventually { written(in: settingsWindow).contains("Couldn't read the list of folders you skipped.") }
               && button("Include Again", in: settingsWindow) == nil,
               "with the review list unreadable, Settings says the skipped folders could not be listed")
        SampleEngine.storeFailed = false
        await model.refreshReview()
        // The added folders are in the saved state too, which can be unreadable.
        SampleEngine.placesFailed = true
        await model.refreshPlaces()
        expect(await eventually { written(in: settingsWindow).contains("Couldn't read the list of folders you added.") }
               && button("Remove", in: settingsWindow) == nil,
               "with the saved state unreadable, Settings says the added folders could not be listed")
        SampleEngine.placesFailed = false
        await model.refreshPlaces()
        expect(await eventually { !written(in: settingsWindow).contains("Couldn't read the list of folders you added.")
                   && button("Remove", in: settingsWindow) != nil },
               "once the saved state can be read, Settings lists the added folders again")
        // The helper's unread places open from the Overview, the one way to them.
        let scansBeforeDetails = SampleEngine.scanRequests
        await press(linkButton("Show Places Not Checked"), "opening unread places from the Overview",
                    until: { model.showingPlaces && written().contains("~/Library/SyntheticUnread") })
        // A section's heading may reach assistive software as a name, not a value.
        let automaticListed = written() + everything().flatMap(names)
        expect(automaticListed.contains("Couldn't Be Read") && !automaticListed.contains { $0.contains("(3)") },
               "the automatic scan's places are listed under a title-case heading, with no count beside it")
        // A place both scans missed is listed once, under one heading, with no
        // word on which scan missed which.
        expect(written().filter { $0 == "~/Library/Mail" }.count == 1
                   && !written().contains { $0.contains("Last Manual Scan") || $0.contains("Last Automatic Scan") },
               "places both scans missed are listed once, in one list")
        expect(SampleEngine.scanRequests == scansBeforeDetails,
               "opening unread places does not run a scan")
        SampleEngine.coverageFails = true
        await model.refreshAutomaticCoverage()
        expect(await eventually { written().contains("Synthetic coverage read failure.") && written().contains("~/Library/SyntheticUnread") },
               "a failed coverage read keeps the saved paths and explains the failure")
        SampleEngine.coverageFails = false
        await press(button("Try Again"), "retrying the automatic coverage read",
                    until: { model.automaticCoverageError == nil })
        SampleEngine.coverageMissing = true
        await model.refreshAutomaticCoverage()
        expect(await eventually { written().contains("Details will appear after the next full automatic scan.") },
               "older automatic results explain their missing details instead of claiming nothing was missed")
        SampleEngine.coverageMissing = false
        await model.refreshAutomaticCoverage()
        model.showingPlaces = false
        await settle(after: "closing the places not checked")
        // Return focus to Settings for its remaining controls.
        await press(button("Settings…"), "returning to Settings")
        // Once they are off, macOS answers a request without asking: the
        // switch is in System Settings.
        expect(settingsWindow != nil && button("Set Up Notifications…", in: settingsWindow) == nil
                   && button("Open System Settings", in: settingsWindow) != nil,
               "Settings offers System Settings, not a request, for notifications that are off")
        // Neither while the answer is not known yet: asking might not be possible.
        SampleEngine.permission = "checking"
        await model.refreshReview()
        await settle()
        expect(button("Set Up Notifications…", in: settingsWindow) == nil
                   && button("Open System Settings", in: settingsWindow) == nil,
               "Settings offers neither before macOS has said whether it can ask")
        // Not asked yet, Settings asks macOS itself, and then says what it answered.
        SampleEngine.permission = "not requested"
        await model.refreshReview()
        let requestsBefore = SampleEngine.notificationRequests
        expect(await eventually { button("Set Up Notifications…", in: settingsWindow) != nil },
               "Settings offers Set Up Notifications… before macOS has been asked")
        await press(button("Set Up Notifications…", in: settingsWindow), "pressing Set Up Notifications… in Settings",
                    until: { SampleEngine.notificationRequests == requestsBefore + 1
                        && button("Set Up Notifications…", in: settingsWindow) == nil
                        && written(in: settingsWindow).contains("Allowed") })
        // A notification the helper couldn't send after three tries can be sent from here.
        SampleEngine.pendingDelivery = true
        SampleEngine.attempts = 3
        await model.refreshMonitor()
        expect(await eventually { written(in: settingsWindow).contains("Pending Notification") && button("Try Again", in: settingsWindow) != nil },
               "Settings shows a notification not sent after three tries, with Try Again")
        await press(button("Try Again", in: settingsWindow), "pressing Try Again beside Pending Notification",
                    until: { SampleEngine.retryRequests == 1 && !written(in: settingsWindow).contains("Pending Notification") })
        SampleEngine.permission = "denied"
        await model.refreshReview()
        await settle()
        // The helper has a row only when it needs something done.
        expect(button("Restart Helper", in: settingsWindow) == nil,
               "Settings offers no helper control while the helper runs")
        SampleEngine.helperStopped = true
        await model.refreshMonitor()
        expect(await eventually { button("Restart Helper", in: settingsWindow) != nil && written(in: settingsWindow).contains("Not running") },
               "Settings offers Restart Helper for a helper that is registered but not running")
        SampleEngine.loginRequests = []
        await press(button("Restart Helper", in: settingsWindow), "restarting the helper from Settings",
                    until: { SampleEngine.loginRequests == [false, true] && button("Restart Helper", in: settingsWindow) == nil })
        // Approval is given in System Settings, which a button opens.
        model.openLoginItems = { Checks.loginItemsOpened += 1 }
        SampleEngine.helperNeedsApproval = true
        await model.refreshMonitor()
        let mainWindow = windows().first { window in settingsWindow.map { !CFEqual($0, window) } ?? true }
        expect(await eventually { written(in: settingsWindow).contains(LoginItemsText.approveHelper)
                   && written(in: mainWindow).contains(LoginItemsText.approveHelper) },
               "Settings and the Overview say where to approve a helper macOS is waiting on")
        let linksBefore = opened.count
        await press(button("Open System Settings", in: settingsWindow), "opening Login Items from Settings",
                    until: { Checks.loginItemsOpened == 1 && opened.count == linksBefore })
        SampleEngine.helperNeedsApproval = false
        await model.refreshMonitor()
        expect(await eventually { !written(in: settingsWindow).contains(LoginItemsText.approveHelper) },
               "Settings drops the approval line once the helper may run")
        await press(toggle("Pause Scanning"), "pausing from Settings",
                    until: { SampleEngine.paused && written(in: settingsWindow).contains("Paused") })
        await press(toggle("Pause Scanning"), "resuming from Settings",
                    until: { !SampleEngine.paused && written(in: settingsWindow).contains("Active") })
        // Show in Menu Bar is saved by the engine and on until turned off.
        // While on, an icon is in this Mac's menu bar.
        expect(await eventually { model.menuBarOn && menuBarItems().count == 1 }, "Show in Menu Bar is on by default, with one icon in the menu bar")
        expect(quitsWithLastWindow() == false, "with Show in Menu Bar on, closing the last window leaves the app running")
        // Settings says when the app is not in Login Items, so not opened at login.
        SampleEngine.appLogin = 3
        await model.refreshMonitor()
        expect(await eventually { written().contains("Turn on Loose Keys in Login Items to show the icon at login.") },
               "Settings says when Login Items needs the person's approval for the app")
        // Notifications, also off in this run, have a button of the same name above it.
        await press(lastButton("Open System Settings", in: settingsWindow), "opening Login Items for the app's own entry",
                    until: { Checks.loginItemsOpened == 2 })
        SampleEngine.appLogin = 1
        await model.refreshMonitor()
        expect(await eventually { written().contains("Shown only while the app is open, because Loose Keys isn't in Login Items.") },
               "Settings says when the app is not in Login Items")
        SampleEngine.appLogin = nil
        await model.refreshMonitor()
        expect(await eventually { !written().contains { $0.contains("Login Items") } },
               "Settings says nothing of Login Items while the app is in them")
        // The engine refuses the switch while private state cannot be used.
        SampleEngine.storeFailed = true
        await model.refreshReview()
        await model.refreshMonitor()
        expect(await eventually { toggle("Show in Menu Bar").flatMap { value($0, kAXEnabledAttribute) as? Bool } == false },
               "with private state unavailable, the Show in Menu Bar switch is disabled")
        SampleEngine.storeFailed = false
        await model.refreshReview()
        await model.refreshMonitor()
        // The switch shows what was saved at once, so a second press undoes the first.
        func menuBarSwitch() -> Int? { toggle("Show in Menu Bar").flatMap { value($0, kAXValueAttribute) as? Int } }
        await press(toggle("Show in Menu Bar"), "turning Show in Menu Bar off",
                    until: { !SampleEngine.menuBar && !model.menuBarOn && menuBarSwitch() == 0 })
        expect(await eventually { menuBarItems().isEmpty }, "with Show in Menu Bar off, the icon leaves the menu bar")
        expect(quitsWithLastWindow() == true, "with Show in Menu Bar off, closing the last window quits the app")
        await press(toggle("Show in Menu Bar"), "turning Show in Menu Bar back on",
                    until: { SampleEngine.menuBar && model.menuBarOn && menuBarSwitch() == 1 })
        expect(await eventually { menuBarItems().count == 1 }, "with Show in Menu Bar on again, the icon is back")
        // A refusal is shown in Settings, where the switch was pressed, and
        // not in the main window as well.
        let refusal = SampleEngine.menuBarRefusal
        SampleEngine.menuBarRefused = true
        await press(toggle("Show in Menu Bar"), "turning Show in Menu Bar off when the engine refuses",
                    until: { settingsWindow != nil && written(in: settingsWindow).contains(refusal) && button("OK", in: settingsWindow) != nil })
        expect(model.failure == nil && !before.contains { written(in: $0).contains(refusal) },
               "a switch refused in Settings is not shown in the main window as well")
        expect(written(in: settingsWindow).contains(FailureTitle.menuBar) && !written(in: settingsWindow).contains("Loose Keys"),
               "the refusal's title says what failed, not the app's name")
        SampleEngine.menuBarRefused = false
        await press(button("OK", in: settingsWindow), "closing the refusal in Settings",
                    until: { model.settingsFailure == nil && !written().contains(refusal) && model.menuBarOn && menuBarSwitch() == 1 })
        let told = consent.flatMap { value($0, kAXEnabledAttribute) as? Bool }
        await press(consent, "turning background checks off with the review list full")
        for _ in 0..<10 where SampleEngine.monitoring { await settle() }
        expect(!SampleEngine.monitoring,
               "with the review list full, the switch for background checks still turns them off (assistive software is told the switch is \(told == true ? "enabled" : told == false ? "disabled" : "not there"))")
        let settings = windows().first { window in !before.contains { CFEqual($0, window) } }
        expect(await eventually { toggle("Pause Scanning") == nil && button("Open System Settings", in: settings) == nil },
               "with automatic scanning off, Settings shows neither Pause Scanning nor notifications")
        // With no home folder to watch, turning it on could do nothing, so
        // neither switch can be pressed.
        func switchEnabled(in window: AXUIElement?) -> Bool? {
            toggle("Scan Automatically", in: window).flatMap { value($0, kAXEnabledAttribute) as? Bool }
        }
        SampleEngine.noHome = true
        await model.refreshPlaces()
        expect(await eventually { switchEnabled(in: settings) == false && switchEnabled(in: mainWindow) == false },
               "with no home folder, Scan Automatically can't be turned on in Settings or on the Overview")
        SampleEngine.noHome = false
        await model.refreshPlaces()
        expect(await eventually { switchEnabled(in: settings) == true && switchEnabled(in: mainWindow) == true },
               "once there is a home folder, Scan Automatically can be turned on in Settings and on the Overview")
        SampleEngine.statusRefused = true
        await model.refreshMonitor()
        expect(await eventually { written(in: settings).contains("Automatic scanning isn't available.")
                   && written(in: settings).contains(SampleEngine.statusRefusal) },
               "a status of background checks that couldn't be read says why in Settings")
        SampleEngine.statusRefused = false
        await model.refreshMonitor()
        expect(await eventually { toggle("Show in Menu Bar", in: settings) != nil }, "Settings shows its switches again once the status can be read")
        await updates(model)
        if let settings, let close = value(settings, kAXCloseButtonAttribute), CFGetTypeID(close) == AXUIElementGetTypeID() {
            await press((close as! AXUIElement), "closing Settings")
        }
        // A refusal that comes once Settings has closed is shown in the main
        // window instead of waiting for Settings to open again.
        expect(await eventually { !model.settingsOpen }, "the model knows that Settings has closed")
        SampleEngine.menuBarRefused = true
        model.setMenuBar(false, from: .settings)
        expect(await eventually { model.failure != nil && model.settingsFailure == nil && written().contains(refusal) },
               "a refusal from Settings that comes once it has closed is shown in the main window")
        SampleEngine.menuBarRefused = false
        await press(button("OK"), "closing the refusal in the main window",
                    until: { model.failure == nil && !written().contains(refusal) })
        SampleEngine.listFull = false
        SampleEngine.monitoring = false
        SampleEngine.unread = 0
        await model.refreshReview()
        await model.refreshMonitor()
        await open(.review)

        // The menu bar icon is marked from the same list as the window, and
        // assistive software is told the mark. Its menu is not reachable from here.
        let labels = [MenuBarMark.unknown, .open, .plain, .problem, .full].map(MenuBarIcon.label)
        expect(Set(labels).count == labels.count, "each menu bar mark has its own label for assistive software")
        model.setMenuBar(true)
        expect(await eventually { model.menuBarOn && menuBarItems().count == 1 }, "the menu bar icon is shown again")
        func marked(_ mark: MenuBarMark) async -> Bool {
            await eventually { menuBarItems().first.map(names)?.contains(MenuBarIcon.label(mark)) == true }
        }
        SampleEngine.refused = true
        await model.refreshReview(reportFailure: false)
        let problemMarked = await marked(.problem)
        expect(model.menuBarMark == .problem && model.menuBarLine == "Couldn't open Worth Reviewing" && problemMarked,
               "with the review list refused, the menu bar shows a problem, not a count")
        SampleEngine.refused = false
        SampleEngine.storeFailed = true
        await model.refreshReview()
        expect(model.menuBarMark == .problem, "with the review list not saved, the menu bar shows a problem")
        SampleEngine.storeFailed = false
        SampleEngine.allSetAside = true
        await model.refreshReview()
        let plainMarked = await marked(.plain)
        expect(model.menuBarMark == .plain && model.menuBarLine == "0 loose keys worth reviewing" && plainMarked,
               "with everything set aside, the menu bar counts none to review")
        SampleEngine.listFull = true
        await model.refreshReview()
        let fullMarked = await marked(.full)
        expect(model.menuBarMark == .full && model.menuBarLine == "0 loose keys worth reviewing, list full" && fullMarked,
               "with everything set aside and the list full, the menu bar says the list is full")
        SampleEngine.listFull = false
        SampleEngine.allSetAside = false
        await model.refreshReview()
        let openMarked = await marked(.open)
        expect(model.openCount > 0 && model.menuBarMark == .open && model.menuBarLine == "\(model.openCount) loose \(model.openCount == 1 ? "key" : "keys") worth reviewing" && openMarked,
               "with items open, the menu bar is marked and the menu counts them")
        // A minimized window is one to come back to: with it, turning the
        // menu bar off or closing another window neither quits nor hides the app.
        let spare = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 320, height: 200),
                             styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        spare.isReleasedWhenClosed = false
        spare.orderFront(nil)
        spare.miniaturize(nil)
        let minimized = await eventually { spare.isMiniaturized }
        expect(minimized && AppModel.windowOpen(in: [spare]),
               "a minimized window counts as open (AppKit calls it \(spare.isVisible ? "visible" : "not visible"))")
        spare.close()
        model.setMenuBar(false)
        expect(await eventually { !model.menuBarOn && menuBarItems().isEmpty }, "the menu bar icon is taken away again")
        await settle(after: "the review list read again")

        // A list shorter than the scan's count because one credential is one
        // item needs nothing done, so the Overview says nothing of it. A full
        // list is shorter for a worse reason, findings left out for lack of
        // room, and the Overview says so.
        await open(.overview)
        let grouped = model.findingsNote
        SampleEngine.listFull = true
        await model.refreshReview()
        await model.refreshMonitor()
        await settle(after: "the review list becoming full")
        let crowded = model.findingsNote ?? ""
        expect(grouped == nil && crowded.contains("full") && written().contains(crowded),
               "the Overview says nothing of grouped findings, and says that the review list is full when it is")
        expect(!written().contains(SampleEngine.fullNotice),
               "the Overview says the review list is full once, not in the engine's notice as well")
        SampleEngine.listFull = false
        await model.refreshReview()
        await model.refreshMonitor()
        await open(.review)

        // A scan that could not check everything and found nothing is not
        // "nothing to review" with a tick: the page says what it did not check.
        SampleEngine.nothingFound = true
        await press(toolbarButton("Scan Now"), "pressing Scan Now with nothing to find")
        for _ in 0..<50 where model.results?.review != 0 || model.phase == .scanning { await settle() }
        await open(.review)
        let bare = written()
        expect(model.results?.status == "partial" && model.results?.review == 0 && model.review?.items.isEmpty == true
               && !bare.contains("Nothing to Review") && bare.contains("Nothing Found")
               && bare.contains("The last scan found nothing to review, but some places couldn't be checked."),
               "a scan that could not check everything and found nothing says so, and does not say there is nothing to review")
        // The Overview's answer says it too, beside the link to the places.
        await open(.overview)
        let answer = "Last scanned \(localTime(model.results?.generatedAt))."
        expect(await eventually { written().contains("Nothing Worth Reviewing") && written().contains(answer) }
               && linkButton("Show Places Not Checked") != nil && !written().contains { $0.contains(NotCheckedText.some) },
               "an empty Overview after a scan that could not read everything says so once, with Show Places Not Checked")
        SampleEngine.nothingFound = false
        await press(toolbarButton("Scan Now"), "pressing Scan Now to bring the sample findings back")
        for _ in 0..<50 where model.results?.review == 0 || model.phase == .scanning { await settle() }
        #endif
    }

    #if PREVIEW
    /// Setting a stored sign-in aside and moving it back, through the window.
    private static func storedSetAside(_ model: AppModel, chosen: ReviewItem.ID, open: (Pane) async -> Void) async {
        guard let stored = list(), let at = model.reviewRows.firstIndex(where: { $0.id == chosen }), at < rows(stored).count else {
            return expect(false, "the chosen sign-in is still listed")
        }
        await choose(rows(stored)[at], "choosing the sign-in to set aside")
        let before = (stored: model.storedCount, aside: model.setAsideCount)
        await press(appMenuItem(SetAsideReason.storedKept.label), "setting a stored sign-in aside with the Item menu",
                    until: { model.storedCount == before.stored - 1 && model.setAsideCount == before.aside + 1
                        && !model.reviewRows.contains { $0.id == chosen } })
        // The engine refuses any other reason. Checked on a model that is in
        // no window, so that no alert is put on screen.
        let refusing = AppModel(engine: model.engine)
        refusing.pane = .stored
        await refusing.refreshReview()
        if let item = refusing.reviewRows.first {
            refusing.decide(item, reason: "testing")
            for _ in 0..<25 where refusing.failure == nil { await settle() }
            expect(refusing.failure?.reason == "That reason doesn't apply to a stored sign-in."
                   && refusing.reviewEntry(item.id)?.status == "open",
                   "a reason other than Keeping It Here on Purpose is refused for a stored sign-in, and it stays listed")
        } else {
            expect(false, "Stored Sign-ins has another sign-in to decide")
        }
        func setAsideRows() async -> (table: AXUIElement, sign: Int, finding: Int)? {
            await open(.setAside)
            guard let table = list(), let sign = model.reviewRows.firstIndex(where: { $0.id == chosen }),
                  let finding = model.reviewRows.firstIndex(where: { !$0.isStored }), max(sign, finding) < rows(table).count else {
                expect(false, "Set Aside lists the set-aside sign-in beside a finding")
                return nil
            }
            return (table, sign, finding)
        }
        guard let first = await setAsideRows() else { return }
        await choose(rows(first.table)[first.sign], "choosing the set-aside sign-in")
        expect(await eventually { menuEnabled("Move to Worth Reviewing") == false && menuEnabled("Move to Stored Sign-ins") == true },
               "with only a sign-in chosen on Set Aside, the Item menu moves it to Stored Sign-ins only")
        let returns = SetAsideReason.storedKept.returns
        if button("Show Details") != nil { await press(button("Show Details"), "showing the set-aside sign-in's details") }
        expect(await eventually { (written() + everything().flatMap(names)).joined(separator: "\n").contains(returns) },
               "a set-aside sign-in's details say when it comes back to Stored Sign-ins")
        await press(button("Hide Details"), "hiding the set-aside sign-in's details")
        await press(button("Move to Stored Sign-ins"), "moving the sign-in back to Stored Sign-ins",
                    until: { model.pane == .stored && model.currentReview?.id == chosen
                        && model.storedCount == before.stored && model.setAsideCount == before.aside })
        // Set aside again from the Item menu, then chosen with a finding: each
        // kind has its own way back. Just after the page changes the Item
        // menu doesn't have the item yet, so it is pressed once offered.
        expect(await eventually { menuEnabled(SetAsideReason.storedKept.label) == true },
               "after Move to Stored Sign-ins, the Item menu offers Keeping It Here on Purpose for the sign-in")
        await press(appMenuItem(SetAsideReason.storedKept.label), "setting the sign-in aside again with the Item menu",
                    until: { model.storedCount == before.stored - 1 && model.setAsideCount == before.aside + 1 })
        guard let both = await setAsideRows() else { return }
        begin("choosing a finding and a sign-in on Set Aside")
        AXUIElementSetAttributeValue(both.table, kAXSelectedRowsAttribute as CFString,
                                     [rows(both.table)[both.sign], rows(both.table)[both.finding]] as CFArray)
        await settle(after: "choosing a finding and a sign-in on Set Aside")
        expect(await eventually {
            model.selectedReviews.count == 2 && button("Move to Worth Reviewing") != nil && button("Move to Stored Sign-ins") != nil
                && menuEnabled("Move to Worth Reviewing") == true && menuEnabled("Move to Stored Sign-ins") == true
        }, "with a finding and a sign-in chosen on Set Aside, each is offered its own way back")
        await press(button("Move to Stored Sign-ins"), "moving only the sign-in of the two back",
                    until: { !model.decidingSelection && model.storedCount == before.stored && model.setAsideCount == before.aside })
        expect(model.pane == .setAside && model.reviewRows.contains { !$0.isStored },
               "Move to Stored Sign-ins leaves the finding chosen with it in Set Aside")
        model.selectedReview = nil
        await settle(after: "choosing no sign-in")
    }
    #endif

    /// The buttons at the head of a list's columns.
    private static func headingButtons(_ list: AXUIElement) -> [AXUIElement] {
        guard let header = value(list, kAXHeaderAttribute), CFGetTypeID(header) == AXUIElementGetTypeID() else { return [] }
        return children(header as! AXUIElement).filter { role($0) == kAXButtonRole }
    }

    /// Each heading is pressed twice. The list must then be sorted by that
    /// column, first one way and then the other.
    private static func headings<Row>(_ list: AXUIElement, _ keys: [PartialKeyPath<Row>],
                                      sort: () -> [KeyPathComparator<Row>], rows: () -> [Row]) async {
        func buttons() -> [AXUIElement] { headingButtons(list) }
        guard buttons().count == keys.count else {
            expect(false, "the list has \(keys.count) column headings (it has \(buttons().count))")
            return
        }
        for (column, key) in keys.enumerated() {
            let title = names(buttons()[column]).first ?? "column \(column + 1)"
            var ways: [SortOrder] = []
            var fault = ""
            for _ in 0..<2 {
                await press(buttons()[column], "pressing the \(title) heading")
                guard let first = sort().first, first.keyPath == key else {
                    fault = "pressing it did not make it the column sorted by"
                    break
                }
                ways.append(first.order)
                let shown = rows()
                if !zip(shown, shown.dropFirst()).allSatisfy({ first.compare($0, $1) != .orderedDescending }) {
                    fault = "the rows are not in that order"
                }
            }
            if fault.isEmpty, ways.count == 2, ways[0] == ways[1] { fault = "pressing it again did not reverse the order" }
            expect(fault.isEmpty, "the \(title) heading sorts the list, and pressing it again reverses it"
                   + (fault.isEmpty ? "" : " (\(fault))"))
        }
    }
}
#endif
