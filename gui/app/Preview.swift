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
    /// What the window last asked to have done to a folder, for the checks.
    static var folderRequest: [String: Any] = [:]
    /// Set by the checks: the review list is then full. The engine says so in
    /// the list, and in the field where it reports a storage failure.
    static var listFull = false
    /// The copies of the sample's token in two files that were set aside as
    /// kept. decide_review changes it, and the checks put it back.
    static var kept: Set<Int> = []
    /// Decisions on the sample's single-location findings.
    static var decisions: [Int: String] = [6: "kept"]
    /// Consent to background checks, with the helper running while it is
    /// given. set_monitoring changes it, and the checks put it back.
    static var monitoring = false
    static var paused = false
    /// Set by the checks: the helper is registered but not running. As with
    /// macOS, only a start after a stop runs it again.
    static var helperStopped = false
    static var helperUnregistered = false
    /// What the window asked of the helper's registration, in order.
    static var loginRequests: [Bool] = []
    /// Show in Menu Bar. set_menu_bar changes it, and the checks put it back.
    static var menuBar = true
    /// The app's own Login Items status, when the checks set one.
    static var appLogin: Int?
    static var completedPass = false
    /// An error the helper kept from before checks were turned off.
    static var helperError = false
    static var notificationRequests = 0
    static var permission = "denied"
    /// Places the helper's last full pass did not read. Set by the checks.
    static var unread = 0
    /// The window check holds preparation while it presses Cancel.
    static var accessGate: DispatchSemaphore?

    private var onEvent: ((String, Data) -> Void)?

    func start(reviewRoute: Bool, onEvent: @escaping (String, Data) -> Void) {
        self.onEvent = onEvent
    }

    func call(_ command: String, _ args: [String: Any]) throws -> Data {
        switch command {
        case "prepare_access":
            if let gate = Self.accessGate, gate.wait(timeout: .now() + 10) != .success {
                throw EngineError(message: "The window check never released folder access.")
            }
            return Data("null".utf8)
        case "places": return Data(#"{"home":"~","home_error":null,"extra":["/Volumes/Backup"],"error":null}"#.utf8)
        case "remove_place", "unskip_folder":
            // The sample keeps its folders. The checks look at what was asked.
            Self.folderRequest = args
            return command == "remove_place" ? try call("places", [:]) : Data("null".utf8)
        case "version": return Data(#""0.2.0-beta.1""#.utf8)
        case "save_report" where Self.reportFails:
            throw EngineError(message: "Could not save: the disk is full.")
        case "pending_review" where Self.refused:
            throw EngineError(message: "That action stopped unexpectedly.")
        case "pending_review" where Self.nothingFound:
            return Data(#"{"items":[],"counts":{"open":0,"set_aside":0,"kept":0,"fixed":0},"skipped":[],"error":null,"full":false,"route":false,"permission":"denied"}"#.utf8)
        case "pending_review" where Self.allSetAside: return Data(Self.everythingSetAside.utf8)
        case "pending_review": return Data(Self.review.utf8)
        case "decide_review" where Self.saveFails:
            Self.storeFailed = true
            throw EngineError(message: "Cannot save local review storage.")
        case "decide_review" where !(args["revision"] is Int):
            // As the engine: a press says which drawing of the row it was made on.
            throw EngineError(message: "The request has no usable \"revision\".")
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
        case "set_menu_bar":
            Self.menuBar = args["enabled"] as? Bool ?? false
            return Data("null".utf8)
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
            if Self.permission == "not requested" { Self.permission = "allowed" }
            onEvent?("notification-permission", Data("null".utf8))
            return Data("null".utf8)
        case "refresh_notifications":
            onEvent?("notification-permission", Data("null".utf8))
            return Data("null".utf8)
        case "monitor_status": return Data(Self.monitor.utf8)
        case "start_scan":
            Thread.sleep(forTimeInterval: 0.3)
            // The sample scan could not read everything: its status is "partial".
            return Data((Self.nothingFound ? Self.results.replacingOccurrences(of: #""review":8"#, with: #""review":0"#) : Self.results).utf8)
        case "rules_text": return Data(#""key.ssh.private\n   Private key with no passphrase\n   Looks in: any file in the scanned folders, ~/.ssh/*\ndev.aws.inline-credentials\n   AWS access keys stored in a file\n   Looks in: ~/.aws/credentials, ~/.aws/config""#.utf8)
        case "summary_text", "item_path", "open_link": return Data(#""sample""#.utf8)
        default: return Data("null".utf8)
        }
    }

    private static func item(_ id: Int, _ title: String, _ path: String, _ severity: String, _ state: String,
                             subject: String? = nil, detail: String? = nil, aside: String? = nil, places: String? = nil,
                             actionable: Bool = true) -> String {
        let aside = decisions[id] ?? aside
        let state = aside == nil ? state : "set-aside"
        let quoted = { (text: String?) in text.map { "\"\($0)\"" } ?? "null" }
        let copies = places ?? #"[{"id":\#(id),"path":"\#(path)","line":null,"fixed":false}]"#
        return """
        {"id":\(id),"revision":\(id),"rule":"sample.rule","path":"\(path)","line":null,"title":"\(title)",
         "explanation":"This file starts with a run of 12 or more words from the standard list wallets use for recovery phrases. Whether they form a valid phrase, or a wallet with funds, was not checked.",
         "reason":"A recovery phrase is the wallet. Anyone who copies these words can take everything in it, with no password, and stealers collect small text files from Desktop, Documents and Downloads.",
         "next_step":"Treat the phrase as exposed if this Mac could have had malware. Otherwise move it off the Mac now.",
         "severity":"\(severity)","steps":["Write the phrase on paper, or stamp it in metal, and store it somewhere safe away from the computer.","Delete this file and empty the Trash. Check Notes, Photos and cloud folders for other copies, including screenshots.","If this Mac may have been infected, create a new wallet with a new phrase and move the funds to it."],
         "link":null,"subject":\(quoted(subject)),"detail":\(quoted(detail)),"first_seen":"2026-10-10T21:40:00Z","resolved_at":null,
         "resolved":\(state == "fixed"),"state":"\(state)","set_aside":\(quoted(aside)),
         "places":\(copies),"folder":null,"actionable":\(actionable)}
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
            #"{"id":\#($0.id),"path":"\#($0.path)","line":null,"fixed":false,"set_aside":\#(kept.contains($0.id))}"#
        }
        return item(lead.id, "Service token stored in a file", lead.path, "high", decided ? "set-aside" : "open",
                    subject: "GitHub personal access token", aside: decided ? "kept" : nil,
                    places: "[\(places.joined(separator: ","))]")
    }

    private static var everythingSetAside: String {
        """
        {"items":[\(item(6, "Possible npm inline credential", "~/.npmrc", "medium", "open", aside: "kept"))],
         "counts":{"open":0,"set_aside":1,"kept":1,"fixed":0},"skipped":[],"error":null,"full":\(listFull),"route":false,"permission":"\(permission)"}
        """
    }

    private static var review: String {
        let error = storeFailed ? #""Cannot save local review storage.""# : "null"
        let tokenAside = kept.contains(4) && kept.contains(9) ? 1 : 0
        let asideCount = decisions.count + tokenAside
        let keptCount = decisions.values.filter { $0 == "kept" }.count + tokenAside
        return """
        {"items":[
        \(item(7, "Possible wallet recovery phrase in a file", "~/Desktop/wallet backup.txt", "high", "open")),
        \(item(1, "Private key with no passphrase", "~/.ssh/id_ed25519", "high", "open")),
        \(item(2, "AWS access keys stored in a file", "~/.aws/credentials", "high", "open", subject: "profile default")),
        \(item(3, "Possible password export file", "~/Downloads/passwords.csv", "high", "open")),
        \(tokenInTwoFiles),
        \(item(5, "Passwords saved in a browser", "~/Library/Application Support/Google/Chrome/Default/Login Data", "medium", "open", detail: "214 saved logins")),
        \(item(6, "Possible npm inline credential", "~/.npmrc", "medium", "open")),
        \(item(8, "Service token in an AI agent's records", "~/.claude/projects/caf\\\\u{e9}/session.jsonl", "high", "fixed", subject: "Tailscale API key", actionable: false))
        ],"counts":{"open":\(7 - asideCount),"set_aside":\(asideCount),"kept":\(keptCount),"fixed":1},"skipped":["~/Movies/Raw"],"error":\(error),"full":\(listFull),"route":false,"permission":"\(permission)"}
        """
    }

    /// A scan counts each finding. For the list above that is 8: the token in
    /// two files is two, and the item set aside is still found. Sign-ins are
    /// listed a rule at a time, as the engine lists them, so their indexes
    /// are out of order: 4 comes before 2 and 3.
    private static let results = """
    {"status":"partial","context":"user","tool_version":"0.2.0-beta.1","generated_at":"2026-10-10T21:40:00Z",
     "review":8,"stored":5,"not_checked":123,
     "groups":[
      {"kind":"inventory","severity":"medium","title":"Sign-in stored by an AI tool","explanation":"This tool keeps you signed in with a token in this file. That is how it is meant to work.","reason":"Any program running as you can read it, and stealers look for it by name.","next_step":"Sign out of the tool when you stop using it.","steps":["Sign out in the tool, which removes this file.","Sign in again when you next need it."],"link":null,
       "items":[{"index":0,"path":"~/.codex/auth.json","line":null,"subject":"Codex","actionable":true},{"index":1,"path":"~/.claude/.credentials.json","line":null,"subject":"Claude Code","actionable":true},{"index":4,"path":"~/.gemini/oauth_creds.json","line":null,"subject":null,"actionable":true}]},
      {"kind":"inventory","severity":"medium","title":"Sign-in stored by a command-line tool","explanation":"A command-line tool keeps its sign-in in this file.","reason":null,"next_step":null,"steps":[],"link":null,
       "items":[{"index":2,"path":"~/.config/gh/hosts.yml","line":null,"subject":"github.com","actionable":true},{"index":3,"path":"~/.config/glab-cli/config.yml","line":null,"subject":null,"actionable":true}]}],
     "gaps":[{"label":"Access denied by macOS","help":"macOS protects these folders, so the app could not look inside them. The results do not cover them.","count":123,"paths":["~/Library/Mail","~/Library/Messages","~/Library/Safari","~/Library/Cookies","~/Library/Group Containers/group.com.apple.notes"],"more":118}],
     "roots":["~","/Volumes/Backup"],"excluded":["node_modules",".git","target","Caches",".Trash"],
     "limitations":"Discovery reads the first 4 KiB of regular files. Not checked: browser cookies and sessions, Safari, Notes and Keychain items. No findings is not a clean bill of health."}
    """

    private static var monitor: String {
        let error = listFull ? #""The review list is full, so new findings are not being added.""# : "null"
        let fullPass = completedPass ? #""2026-10-14T12:00:00Z""# : "null"
        let helperFailed = helperError ? #""Could not watch the home folder for changes.""# : "null"
        return """
        {"enabled":\(monitoring),"paused":\(paused),"scanning":false,"login":\(monitoring && !helperUnregistered ? 2 : 1),
         "menu_bar":\(menuBar),"app_login":\(appLogin ?? (menuBar && monitoring ? 2 : 1)),
         "health":{"running":\(monitoring && !helperStopped && !helperUnregistered),"last_scan":null,"coverage":"partial","full_pass":\(fullPass),"left":\(completedPass ? 0 : 4),"unread":\(unread),"changes":0,"error":\(helperFailed)},
         "error":\(error),"pending_delivery":false,"attempts":0,"results":null}
        """
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
            model.selectedStored = model.storedRows.first?.id
            await shot("4-stored")
            model.pane = .gaps
            await shot("5-not-checked")
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
            let place: String? = try? await model.engine.request("item_path", ["index": id, "review": true])
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
        if let failure = model.failure { lines.append("alert: \(failure)") }
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

    /// A switch, known by the text beside it.
    private static func toggle(_ name: String) -> AXUIElement? {
        everything().first { element in
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
        // The sidebar. Every row is chosen, last to first so that each choice
        // has to change the page, and between them they must open every page.
        var rowOf: [Pane: Int] = [:]
        for index in (0..<sidebarRows().count).reversed() {
            let before = model.pane
            await choose(sidebarRows()[index], "choosing sidebar row \(index + 1)")
            if let pane = model.pane, pane != before { rowOf[pane] = index }
        }
        expect(rowOf.count == 5, "choosing each sidebar row opens its page (\(rowOf.count) of 5 opened)")
        func open(_ pane: Pane) async {
            let rows = sidebarRows()
            if let index = rowOf[pane], index < rows.count { await choose(rows[index], "opening \(pane.rawValue)") }
        }

        #if PREVIEW
        // Before any scan this window has no report to save, so a list that
        // cannot be read must not send the person to save one.
        SampleEngine.storeFailed = true
        await model.refreshReview()
        await open(.review)
        let early = written()
        expect(model.results == nil && early.contains("Review List Unavailable")
               && !early.contains { $0.contains("Save the report") },
               "before a scan, a review list that cannot be read does not tell the person to save a report")
        await open(.gaps)
        let blind = written()
        expect(blind.contains("The folders you left out could not be read, so they are not listed here.") && !blind.contains("Everything Was Checked"),
               "with the review list unreadable, Not Checked says the folders left out could not be listed")
        await open(.review)
        SampleEngine.storeFailed = false
        // Nor is an empty list "nothing to review" when nothing has been scanned.
        SampleEngine.nothingFound = true
        await model.refreshReview()
        await settle(after: "an empty review list before any scan")
        let unscanned = written()
        expect(model.results == nil && unscanned.contains("No Scan Yet") && !unscanned.contains("Nothing to Review"),
               "before any scan, an empty review list says there has been no scan, not that there is nothing to review")
        // With background checks on, "Yet" lasts only until their first full
        // pass, and a pass that could not read everything says so.
        SampleEngine.monitoring = true
        await model.refreshMonitor()
        expect(await eventually { written().contains("No Findings Yet") },
               "before the first full pass, an empty review list says background checks are still reading")
        SampleEngine.completedPass = true
        await model.refreshMonitor()
        expect(await eventually { written().contains("No Findings") && written().contains("Loose Keys checked your files and found nothing to review.") },
               "after a full pass that read everything, an empty review list says background checks found nothing")
        SampleEngine.unread = 3
        await model.refreshMonitor()
        expect(await eventually { written().contains("No Findings") && written().contains { $0.contains("3 places could not be read") } },
               "after a full pass that could not read everything, an empty review list says how many places it missed")
        SampleEngine.monitoring = false
        SampleEngine.completedPass = false
        SampleEngine.unread = 0
        await model.refreshMonitor()
        // With nothing listed, nothing scanned and background checks off, the
        // first page asks one question, and the sidebar waits. The checks have
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
        expect(welcomed && enabled("Scan Automatically") && enabled("Scan Now") && sidebarRows().isEmpty,
               "with nothing to list, the first page asks one question and hides the sidebar")
        // Only the folder already added is listed below it, so that it can be removed.
        expect(button("Show What a Scan Checks") == nil && button("Remove") != nil,
               "the first page has no scan reference section, and still lists an added folder")
        await press(button("Show Sidebar") ?? button("Toggle Sidebar"), "opening the sidebar from the first page")
        expect(await eventually { sidebarRows().count == 5 } && model.pane == .overview && model.showsWelcome,
               "the sidebar can be opened from the first page, and stays open there")
        model.sidebarAsked = false
        expect(await eventually { sidebarRows().isEmpty }, "the first page hides the sidebar again in a window just opened")
        await press(button("Scan Automatically"), "enabling background checks from the first page")
        expect(await eventually { SampleEngine.monitoring && sidebarRows().count == 5 && !model.showsWelcome },
               "enabling background checks from the first page starts them and brings the sidebar back")
        SampleEngine.monitoring = false
        await model.refreshMonitor()
        expect(await eventually { model.showsWelcome } && sidebarRows().count == 5,
               "turning background checks off again brings the question back but keeps the sidebar")
        SampleEngine.helperError = true
        await model.refreshMonitor()
        expect(await eventually { !model.showsWelcome && written().contains("Could not watch the home folder for changes.") },
               "an error the helper kept is shown on the full Overview, not hidden behind the first page's question")
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
        expect(model.results == nil && button("Show What a Scan Checks") == nil
               && button("Show Every Rule") == nil && button("Add Folder or Drive…") != nil,
               "before a scan, Overview has folder controls without the scan reference section")
        // With every finding set aside and no scan in this window, Worth
        // Reviewing says where they went. It does not point to Not Checked,
        // which lists what a scan could not read and so, before one, nothing.
        SampleEngine.allSetAside = true
        await model.refreshReview()
        await open(.review)
        let emptied = await eventually {
            (written() + everything().flatMap(names)).contains { $0.contains("Your set-aside findings are in Set Aside") }
        }
        expect(model.results == nil && emptied
               && !(written() + everything().flatMap(names)).contains { $0.contains("Not Checked lists") },
               "before a scan, an empty Worth Reviewing with set-aside findings does not point to Not Checked")
        SampleEngine.allSetAside = false
        await model.refreshReview()
        // Before any scan, Not Checked is still where a folder left out is included again.
        await open(.gaps)
        let unscannedGaps = written()
        expect(model.results == nil && button("Include Again") != nil && unscannedGaps.contains { $0.hasPrefix("These folders are not read") }
               && !unscannedGaps.contains("No Scan Yet"),
               "before any scan, Not Checked lists the folders left out with Include Again")
        await open(.overview)
        expect(!SampleEngine.monitoring && button("Turn On") != nil,
               "Overview offers background setup without enabling it before consent")
        let accessGate = DispatchSemaphore(value: 0)
        SampleEngine.accessGate = accessGate
        await press(button("Turn On"), "preparing folder access", until: { button("Cancel Preparation") != nil && written().contains("Preparing folder access…") })
        // A Form section heading is not exposed as AXValue. Check the
        // accessible status and explanation, as well as the usable control.
        expect(await eventually {
            let text = written()
            return text.contains("Preparing folder access…")
                && text.contains("Answer the macOS prompts for Desktop, Documents and Downloads.")
                && button("Cancel Preparation") != nil
        }, "folder access explains the system prompts before starting checks")
        await press(button("Cancel Preparation"), "cancelling folder access preparation")
        SampleEngine.accessGate = nil
        accessGate.signal()
        expect(await eventually { !model.preparingAccess && button("Turn On") != nil },
               "cancelling preparation returns to the start choices")
        expect(!SampleEngine.monitoring && model.results == nil,
               "cancelled preparation neither enables the helper nor scans")
        await press(button("Turn On"), "enabling background checks from Overview", until: { SampleEngine.monitoring && written().contains("Active") })
        expect(await eventually { SampleEngine.monitoring && written().contains("Active") },
               "background setup starts the helper without a one-time scan")
        expect(model.results == nil && SampleEngine.notificationRequests == 0,
               "background consent neither runs a manual scan nor asks for notification permission")
        expect(written().contains("Checking existing files…") && !written().contains("Last Recorded Check"),
               "initial checking is visible while diagnostic timestamps start collapsed")
        await press(button("Show Details"), "expanding Overview check details", until: { written().contains("Last Recorded Check") && written().contains("Last Completed Full Scan") })
        expect(await eventually { written().contains("Last Recorded Check") && written().contains("Last Completed Full Scan") && written().contains { $0.contains("4 folders left") } },
               "Overview check details reveal both diagnostic timestamps")
        await press(button("Hide Details"), "collapsing Overview check details", until: { !written().contains("Last Recorded Check") })
        expect(await eventually { !written().contains("Last Recorded Check") }, "Overview check details collapse")
        SampleEngine.completedPass = true
        await model.refreshMonitor()
        expect(await eventually { written().contains("Active") && !written().contains("Checking existing files…") },
               "completed initial checking leaves a simple active status")
        SampleEngine.permission = "not requested"
        await model.refreshReview()
        await settle()
        await press(button("Allow Notifications…"), "requesting notifications from Overview")
        expect(await eventually { SampleEngine.notificationRequests == 1 && !model.awaitingPermission },
               "Overview requests notifications only on a separate press, and stops waiting once macOS answers")
        SampleEngine.permission = "denied"
        await model.refreshReview()
        await settle()
        model.openURL = { Checks.opened.append($0) }
        await press(button("Open System Settings"), "opening notification settings from Overview")
        expect(opened.last?.absoluteString.hasPrefix("x-apple.systempreferences:com.apple.Notifications-Settings.extension") == true
                   && button("Allow Notifications…") == nil,
               "with notifications off, Overview offers System Settings, not a request macOS would ignore")
        await press(button("Pause"), "pausing background checks from Overview")
        expect(await eventually { SampleEngine.paused && written().contains("Paused") }, "Overview pauses background checks")
        await press(button("Resume"), "resuming background checks from Overview")
        expect(await eventually { !SampleEngine.paused && written().contains("Active") }, "Overview resumes background checks")
        await press(button("Worth Reviewing"), "opening background findings before a manual scan")
        expect(model.pane == .review && model.results == nil, "background findings can be reviewed without a manual scan")
        SampleEngine.monitoring = false
        SampleEngine.completedPass = false
        await model.refreshMonitor()
        await open(.overview)
        #endif

        await press(toolbarButton("Scan Now"), "pressing Scan Now")
        for _ in 0..<100 where model.phase != .done { await settle() }
        expect(model.phase == .done && model.results != nil, "pressing Scan Now runs a scan and shows its results")
        await open(.overview)
        let roots = model.results?.roots.joined(separator: ", ") ?? ""
        expect(!roots.isEmpty && written().contains("Included: \(roots)."), "the Overview says which places the last scan included")
        expect(button("Show What a Scan Checks") == nil && button("Show Every Rule") == nil
               && button("Worth Reviewing") != nil && button("Not Checked") != nil
               && button("Add Folder or Drive…") != nil,
               "after a scan, Overview keeps results and folder controls without the scan reference section")

        // Both lists share one Filter field; a second one in the toolbar stops the app.
        for pane in [Pane.review, .stored, .review, .stored, .gaps, .overview, .stored] {
            await open(pane)
        }
        expect(model.pane == .stored, "moving between the lists and the other pages leaves the app running")

        // Pages changed faster than the inspector closes and opens, as with
        // the arrow keys in the sidebar. The window finishing a close it was
        // asked for on leaving a list is not the person hiding the inspector.
        var kept = true
        for _ in 0..<5 {
            for _ in 0..<6 {
                model.pane = .gaps
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
            // The control for the Set Aside check below: the heading is visible here.
            expect((written() + everything().flatMap(names)).contains { $0.contains("What to Do") },
                   "an open finding's inspector shows What to Do")
            let why = model.reviewRows[1].explanation
            expect(!written().contains(why), "why a finding is here starts folded, below what to do")
            await press(button("Show Why It Is Here"), "unfolding why the finding is here")
            expect(await eventually { written().contains(why) }, "the inspector unfolds why the finding is here")
            await press(button("Hide Why It Is Here"), "folding why the finding is here")
            expect(await eventually { !written().contains(why) }, "the inspector folds why the finding is here again")
            let folded = !written().contains("Rule")
            await press(button("Show Details"), "unfolding the finding's details")
            expect(await eventually { folded && written().contains("Rule") },
                   "the finding's details start folded and unfold")
            await press(button("Hide Details"), "folding the finding's details")
            expect(await eventually { !written().contains("Rule") }, "the inspector folds the finding's details again")
            let keys: [PartialKeyPath<ReviewItem>] = [\.title, \.path, \.riskLevel]
            await headings(list, keys, sort: { model.reviewSort }, rows: { model.reviewRows })
            expect(model.selectedReview == chosen, "sorting keeps the chosen finding selected")
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
            expect(headingButtons(table).count == 3 && !headingButtons(table).flatMap(names).contains("Status"),
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
            if let item = model.currentReview {
                // As with the existing kept-copy check, choosing a menu reason
                // is done in the model; Move to Worth Reviewing is pressed below.
                model.decide(item, reason: "not-a-credential")
                expect(await eventually { model.setAsideCount == 1 && !model.reviewRows.contains { $0.id == 6 } },
                       "saving a decision moves the finding to Set Aside")
                expect(model.pane == .review && !model.reviewRows.contains { $0.id == 6 }
                       && model.currentReview == nil && button("Copy Path") == nil,
                       "setting aside removes the row and its inspector while keeping the review page open")
                expect(button("Undo") == nil, "setting aside does not show a temporary Undo button")
                await open(.setAside)
                if let table = list(), let row = rows(table).first {
                    await choose(row, "selecting the newly set-aside finding")
                }
                await press(button("Move to Worth Reviewing"), "returning the finding from Set Aside")
                expect(await eventually { model.pane == .review && model.reviewRows.contains { $0.id == 6 } && model.setAsideCount == 0 },
                       "Move to Worth Reviewing restores the finding to Worth Reviewing")
            }
            await open(.setAside)
            expect(await eventually { written().contains("No Items Set Aside") },
                   "the Set Aside page explains an empty list")
            for reason in SetAsideReason.all + [SetAsideReason.legacy] {
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
        if let list = list(), rows(list).count == model.storedRows.count, model.storedRows.count > 1 {
            // With no heading pressed the sign-ins are in the order the scan
            // listed them, each rule's together. The first few are also read
            // from the window.
            let listed = (model.results?.groups ?? []).filter { $0.kind == "inventory" }.flatMap(\.items)
            let drawn = zip(rows(list), listed).prefix(5).allSatisfy { row, file in
                written(in: row).contains((file.path as NSString).lastPathComponent)
            }
            expect(model.storedSort.isEmpty && model.storedRows.map(\.id) == listed.map(\.index) && drawn,
                   "until a heading is pressed, the stored sign-ins are in the order the scan listed them (listed \(listed.map(\.index)), shown \(model.storedRows.map(\.id)))")
            #if PREVIEW
            // Rows a pressed heading ranks the same keep that order: the
            // sample's sign-ins of one rule share a title.
            await press(headingButtons(list).first { names($0).contains("Sign-in") }, "pressing the Sign-in heading")
            let place = Dictionary(uniqueKeysWithValues: listed.enumerated().map { ($0.element.index, $0.offset) })
            let shown = model.storedRows
            let level = zip(shown, shown.dropFirst()).filter { pair in
                model.storedSort.allSatisfy { $0.compare(pair.0, pair.1) == .orderedSame }
            }
            expect(!model.storedSort.isEmpty && !level.isEmpty
                   && level.allSatisfy { (place[$0.id] ?? 0) < (place[$1.id] ?? 0) },
                   "sign-ins a pressed heading ranks the same stay in the order the scan listed them (shown \(shown.map(\.id)))")
            model.storedSort = []
            await settle(after: "putting the sign-ins back in the scan's order")
            #endif
            let chosen = model.storedRows[1].id
            await choose(rows(list)[1], "choosing a stored sign-in")
            expect(model.selectedStored == chosen, "choosing a stored sign-in selects it")
            let keys: [PartialKeyPath<StoredRow>] = [\.group.title, \.file.path]
            await headings(list, keys, sort: { model.storedSort }, rows: { model.storedRows })
            model.search = "no sign-in has this text"
            await settle(after: "filtering out the selected sign-in")
            expect(model.selectedStored == nil && model.currentStored == nil, "a sign-in the filter hides is no longer selected")
            #if PREVIEW
            model.search = "Claude Code"
            await settle(after: "filtering by what the inspector shows under a sign-in's title")
            expect(model.storedRows.count == 1, "the filter finds a sign-in by what the inspector shows under its title (\(model.storedRows.count) of 1 rows)")
            #endif
            model.search = ""
            await settle(after: "clearing the filter")
        } else {
            expect(false, "the stored list is a table with a row for each sign-in")
        }

        // The Filter field is on every page. Used on one it does not filter, it opens the first list.
        await open(.gaps)
        expect(everything().contains { role($0) == kAXTextFieldRole },
               "the Filter field is in the toolbar on a page without a list")
        model.search = "token"
        await settle(after: "filtering from a page without a list")
        expect(model.pane == .review, "a filter set on a page without a list opens Worth Reviewing")
        model.search = ""
        await settle(after: "clearing the filter")

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
        expect(texts.contains("Review List Unavailable") && !texts.contains("Nothing to Review")
               && model.reviewCount == model.results?.review,
               "a review list that cannot be read says so, and the count beside it is the scan's own")
        // The engine keeps the failure until the app is opened again, and
        // after a scan the report has what the list does not show.
        let advice = texts.first { $0.contains("reopen the app") } ?? ""
        expect(advice.contains("reopen the app") && advice.contains("Save the report"),
               "a review list that cannot be read says that quitting the app and opening it again reads it again, and that the report has the findings")
        SampleEngine.storeFailed = false
        await model.refreshReview()
        await settle(after: "the review list returning")

        // A finding chosen before the list failed has buttons that can now only fail.
        if let table = list(), let at = model.reviewRows.firstIndex(where: { $0.actionable != false }), at < rows(table).count {
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

        // A folder's button names it by its place in a list, and the list can
        // have moved up by the time a second press lands. So the request also
        // says which folder the button was drawn for.
        await open(.overview)
        SampleEngine.folderRequest = [:]
        await press(button("Remove"), "pressing Remove beside an added folder")
        for _ in 0..<10 where SampleEngine.folderRequest.isEmpty { await settle() }
        let removing = SampleEngine.folderRequest
        await open(.gaps)
        SampleEngine.folderRequest = [:]
        await press(button("Include Again"), "pressing Include Again beside a folder left out")
        for _ in 0..<10 where SampleEngine.folderRequest.isEmpty { await settle() }
        let including = SampleEngine.folderRequest
        expect(removing["index"] as? Int == 0 && removing["shown"] as? String == "/Volumes/Backup"
               && including["index"] as? Int == 0 && including["shown"] as? String == "~/Movies/Raw",
               "Remove and Include Again say which folder they were shown for (they sent \(removing["shown"] ?? "nothing") and \(including["shown"] ?? "nothing"))")
        await open(.review)

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
        try? FileManager.default.removeItem(at: folder)

        // The request for the list can fail as well. What the window holds
        // is then an older list, or none, and neither is what was found.
        SampleEngine.refused = true
        await model.refreshReview()
        // The alert that reports the failure is not what is checked here.
        model.failure = nil
        await settle(after: "the request for the review list failing")
        let refused = written()
        expect(refused.contains("Review List Unavailable") && !refused.contains("Nothing to Review")
               && list() == nil && model.reviewSummary.isEmpty,
               "a review list the window could not get says so, and shows no older list or count in its place")
        // The same from the start: a window that never got the list, then a scan.
        let fresh = AppModel(engine: model.engine)
        await fresh.refresh()
        fresh.startScan()
        for _ in 0..<100 where fresh.phase != .done { await settle() }
        expect(fresh.review == nil && fresh.results != nil && fresh.reviewCount == fresh.results?.review,
               "after a scan, the count beside a review list the window never got is the scan's own (it is \(fresh.reviewCount))")
        SampleEngine.refused = false
        await model.refreshReview()
        await settle(after: "the review list being got again")

        // One credential in two files is one row, named by a copy that still
        // needs a decision. Keeping the first copy leaves the second to
        // decide, and the row takes its id. It is the same row, still open.
        if let table = list(), let at = model.reviewRows.firstIndex(where: { ($0.places?.count ?? 0) > 1 }),
           at < rows(table).count {
            let first = model.reviewRows[at]
            await choose(rows(table)[at], "choosing a credential that is in two files")
            model.decide(first, reason: "kept")
            for _ in 0..<25 where model.review?.items.contains(where: { $0.id == first.id }) == true { await settle() }
            await settle(after: "keeping the first copy of a credential in two files")
            let entry = model.review?.items.first { $0.places?.contains { $0.id == first.id } == true }
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
        expect(state.contains("Active") && !state.contains("Unavailable"),
               "with the review list full, the Overview says background checks are on, not unavailable")
        let before = windows()
        await press(button("Settings…"), "pressing Settings…")
        for _ in 0..<10 where toggle("Scan Automatically") == nil { await settle() }
        let consent = toggle("Scan Automatically")
        let settingsWindow = windows().first { window in !before.contains { CFEqual($0, window) } }
        expect(consent != nil && written(in: settingsWindow).contains("Active"),
               "Settings shows the state of automatic scanning under its switch")
        expect(written(in: settingsWindow).contains { $0.contains("3 places could not be read") },
               "Settings says how many places the helper's last full pass did not read")
        expect(!written(in: settingsWindow).contains("Last Recorded Check") && button("Show Check Details", in: settingsWindow) == nil,
               "Settings leaves check timing to the Overview")
        // Once they are off, macOS answers a request without asking: the
        // switch is in System Settings.
        expect(settingsWindow != nil && button("Allow Notifications…", in: settingsWindow) == nil
                   && button("Open System Settings", in: settingsWindow) != nil,
               "Settings offers System Settings, not a request, for notifications that are off")
        // Neither while the answer is not known yet: asking might not be possible.
        SampleEngine.permission = "checking"
        await model.refreshReview()
        await settle()
        expect(button("Allow Notifications…", in: settingsWindow) == nil
                   && button("Open System Settings", in: settingsWindow) == nil,
               "Settings offers neither before macOS has said whether it can ask")
        SampleEngine.permission = "denied"
        await model.refreshReview()
        await settle()
        // The helper has a row only when it needs something done.
        expect(button("Restart Helper", in: settingsWindow) == nil && button("Stop Helper", in: settingsWindow) == nil,
               "Settings offers no helper control while the helper runs")
        SampleEngine.helperStopped = true
        await model.refreshMonitor()
        expect(await eventually { button("Restart Helper", in: settingsWindow) != nil && written(in: settingsWindow).contains("Not running") },
               "Settings offers Restart Helper for a helper that is registered but not running")
        SampleEngine.loginRequests = []
        await press(button("Restart Helper", in: settingsWindow), "restarting the helper from Settings",
                    until: { SampleEngine.loginRequests == [false, true] && button("Restart Helper", in: settingsWindow) == nil })
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
        expect(await eventually { written().contains("Allow Loose Keys in Login Items to show it at login.") },
               "Settings says when Login Items needs the person's approval for the app")
        SampleEngine.appLogin = 1
        await model.refreshMonitor()
        expect(await eventually { written().contains("Not in Login Items: shown only while the app is open.") },
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
        let told = consent.flatMap { value($0, kAXEnabledAttribute) as? Bool }
        await press(consent, "turning background checks off with the review list full")
        for _ in 0..<10 where SampleEngine.monitoring { await settle() }
        expect(!SampleEngine.monitoring,
               "with the review list full, the switch for background checks still turns them off (assistive software is told the switch is \(told == true ? "enabled" : told == false ? "disabled" : "not there"))")
        let settings = windows().first { window in !before.contains { CFEqual($0, window) } }
        expect(await eventually { toggle("Pause Scanning") == nil && button("Open System Settings", in: settings) == nil },
               "with automatic scanning off, Settings shows neither Pause Scanning nor notifications")
        if let settings, let close = value(settings, kAXCloseButtonAttribute), CFGetTypeID(close) == AXUIElementGetTypeID() {
            await press((close as! AXUIElement), "closing Settings")
        }
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
        expect(model.menuBarMark == .problem && model.menuBarLine == "Worth Reviewing could not be read" && problemMarked,
               "with the review list refused, the menu bar shows a problem, not a count")
        SampleEngine.refused = false
        SampleEngine.storeFailed = true
        await model.refreshReview()
        expect(model.menuBarMark == .problem, "with the review list not saved, the menu bar shows a problem")
        SampleEngine.storeFailed = false
        SampleEngine.allSetAside = true
        await model.refreshReview()
        let plainMarked = await marked(.plain)
        expect(model.menuBarMark == .plain && model.menuBarLine == "0 loose keys to review" && plainMarked,
               "with everything set aside, the menu bar counts none to review")
        SampleEngine.listFull = true
        await model.refreshReview()
        let fullMarked = await marked(.full)
        expect(model.menuBarMark == .full && model.menuBarLine == "0 loose keys to review, list full" && fullMarked,
               "with everything set aside and the list full, the menu bar says the list is full")
        SampleEngine.listFull = false
        SampleEngine.allSetAside = false
        await model.refreshReview()
        let openMarked = await marked(.open)
        expect(model.openCount > 0 && model.menuBarMark == .open && model.menuBarLine == plural(model.openCount, "loose key", "loose keys") + " to review" && openMarked,
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

        // The Overview explains a list shorter than the scan's count: one
        // credential is one item. A full list is shorter for a worse reason,
        // findings left out for lack of room, and must not be explained away.
        await open(.overview)
        let grouped = model.findingsNote ?? ""
        SampleEngine.listFull = true
        await model.refreshReview()
        await model.refreshMonitor()
        await settle(after: "the review list becoming full")
        let crowded = model.findingsNote ?? ""
        expect(!grouped.isEmpty && !grouped.contains("full") && crowded.contains("full") && written().contains(crowded),
               "the Overview says that the review list is full where it explains why the list is shorter than the scan's count")
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
               && !bare.contains("Nothing to Review") && bare.contains("Nothing Found in What Was Checked"),
               "a scan that could not check everything and found nothing says so, and does not say there is nothing to review")
        SampleEngine.nothingFound = false
        await press(toolbarButton("Scan Now"), "pressing Scan Now to bring the sample findings back")
        for _ in 0..<50 where model.results?.review == 0 || model.phase == .scanning { await settle() }
        #endif
    }

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
