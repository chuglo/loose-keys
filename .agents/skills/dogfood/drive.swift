// Drives the Loose Keys window in a disposable guest through Accessibility,
// one command per run, so a session can use the app as a person would and
// read what it shows. Guest only. Never linked into the app bundle.
import AppKit
import ApplicationServices

let usage = """
usage: drive <command>
  tree                      every element of the app's windows, with its role and text
  texts                     the text of the app's windows, one line each
  menu <item>               choose a menu bar item, such as "Scan Now"
  press <name> [nth]        press a button, checkbox or menu item named <name>
  page <name>               open a sidebar page, such as "Worth Reviewing"
  rows                      the open list's rows as JSON
  select <n> [<n> ...]      select rows of the open list by number, from 0; "all" selects every row
  toggle <label>            press the switch beside the text <label>, such as "Scan Automatically"
  filter [text]             type into the Filter field; with no text, clear it
  setaside <reason>         choose Set Aside… and then <reason> for the selected rows
  detail                    the text beside the list: the inspector of the selection
  dump <file>               every row of the open list with its inspector, as JSON
  wait <text> [seconds]     wait until the window shows <text>
  scan [seconds]            choose Scan Now, answer macOS's folder requests with Allow, and time the scan
  prompts [button]          macOS's own dialogs and notifications; with <button>, press it
"""

struct Failure: Error { let message: String }
func fail(_ message: String) throws -> Never { throw Failure(message: message) }

func attribute(_ element: AXUIElement, _ name: String) -> CFTypeRef? {
    var result: CFTypeRef?
    return AXUIElementCopyAttributeValue(element, name as CFString, &result) == .success ? result : nil
}
func role(_ element: AXUIElement) -> String { attribute(element, kAXRoleAttribute) as? String ?? "" }
func children(_ element: AXUIElement) -> [AXUIElement] { attribute(element, kAXChildrenAttribute) as? [AXUIElement] ?? [] }
func texts(_ element: AXUIElement) -> [String] {
    [kAXTitleAttribute, kAXDescriptionAttribute, kAXValueAttribute]
        .compactMap { attribute(element, $0) as? String }.filter { !$0.isEmpty }
}
func descendants(_ root: AXUIElement, limit: Int = 60000) -> [AXUIElement] {
    var result: [AXUIElement] = []
    func visit(_ element: AXUIElement, _ depth: Int) {
        guard depth < 40, result.count < limit else { return }
        result.append(element)
        for child in children(element) { visit(child, depth + 1) }
    }
    visit(root, 0)
    return result
}
func allTexts(_ root: AXUIElement) -> [String] {
    var seen: [String] = []
    for text in descendants(root).flatMap({ texts($0) }) where seen.last != text { seen.append(text) }
    return seen
}
func waitFor(_ what: String, seconds: Double = 20, _ condition: () -> Bool) throws {
    let deadline = Date().addingTimeInterval(seconds)
    repeat {
        if condition() { return }
        Thread.sleep(forTimeInterval: 0.2)
    } while Date() < deadline
    try fail("timeout: \(what)")
}

func looseKeys() throws -> AXUIElement {
    guard AXIsProcessTrusted() else { try fail("Accessibility is not granted to this driver") }
    guard let running = NSRunningApplication.runningApplications(withBundleIdentifier: "dev.loosekeys.desktop")
        .first(where: { $0.executableURL?.lastPathComponent == "loose-keys-gui" && $0.activationPolicy != .prohibited })
    else { try fail("Loose Keys is not running") }
    let app = AXUIElementCreateApplication(running.processIdentifier)
    AXUIElementSetMessagingTimeout(app, 5)
    return app
}
func windows(_ app: AXUIElement) -> [AXUIElement] { attribute(app, kAXWindowsAttribute) as? [AXUIElement] ?? [] }
func windowElements(_ app: AXUIElement) -> [AXUIElement] { windows(app).flatMap { descendants($0) } }

/// The rows of the list the page shows: the table with the most columns,
/// which the sidebar, with one, never is.
func listRows(_ app: AXUIElement) -> (table: AXUIElement, rows: [AXUIElement])? {
    let tables = windowElements(app).filter { [kAXTableRole, kAXOutlineRole].contains(role($0)) }
    let columns = { (table: AXUIElement) in (attribute(table, kAXColumnsAttribute) as? [AXUIElement] ?? []).count }
    guard let table = tables.max(by: { columns($0) < columns($1) }), columns(table) > 1 else { return nil }
    return (table, attribute(table, kAXRowsAttribute) as? [AXUIElement] ?? [])
}
/// The window's elements outside its tables: headings, the inspector and
/// its buttons. A long list has thousands of elements, and each one read is
/// a call to the app, so what follows the selection is read without them.
func besideLists(_ app: AXUIElement) -> [AXUIElement] {
    var out: [AXUIElement] = []
    func visit(_ element: AXUIElement, _ depth: Int) {
        guard depth < 40, ![kAXTableRole, kAXOutlineRole, kAXToolbarRole].contains(role(element)) else { return }
        out.append(element)
        for child in children(element) { visit(child, depth + 1) }
    }
    for window in windows(app) { visit(window, 0) }
    return out
}
/// What the window says outside its tables.
func detail(_ app: AXUIElement) -> [String] {
    var out: [String] = []
    for text in besideLists(app).flatMap({ texts($0) }) where out.last != text { out.append(text) }
    return out
}
func named(_ app: AXUIElement, _ name: String, in roles: [String]) -> [AXUIElement] {
    let menus = (attribute(app, kAXMenuBarAttribute).map { descendants($0 as! AXUIElement) }) ?? []
    return (windowElements(app) + menus).filter { roles.contains(role($0)) && texts($0).contains(name) }
}
func json(_ value: Any) -> String {
    let data = try! JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .withoutEscapingSlashes])
    return String(decoding: data, as: UTF8.self)
}

/// macOS's own dialogs and notification banners, which belong to other
/// processes: each one's text and its buttons.
func systemPrompts() -> [(texts: [String], buttons: [AXUIElement])] {
    let owners = ["UserNotificationCenter", "NotificationCenter", "CoreServicesUIAgent", "universalAccessAuthWarn", "SecurityAgent"]
    var found: [(texts: [String], buttons: [AXUIElement])] = []
    // The list of running programs is brought up to date by the run loop,
    // and macOS starts the program that asks only when it has a question.
    RunLoop.current.run(until: Date().addingTimeInterval(0.05))
    for running in NSWorkspace.shared.runningApplications {
        guard let name = running.executableURL?.lastPathComponent, owners.contains(name) else { continue }
        let app = AXUIElementCreateApplication(running.processIdentifier)
        AXUIElementSetMessagingTimeout(app, 2)
        for window in windows(app) {
            let all = descendants(window, limit: 2000)
            let shown = allTexts(window)
            if !shown.isEmpty { found.append((["[" + name + "]"] + shown, all.filter { role($0) == kAXButtonRole })) }
        }
    }
    return found
}
func actionNames(_ element: AXUIElement) -> [String] {
    var names: CFArray?
    return AXUIElementCopyActionNames(element, &names) == .success ? names as? [String] ?? [] : []
}
/// A notification banner offers its buttons as actions of the banner, named
/// "Name:Allow ...", until the pointer is over it.
func bannerAction(_ button: String, about: String?) -> Bool {
    for running in NSWorkspace.shared.runningApplications where running.executableURL?.lastPathComponent == "NotificationCenter" {
        let app = AXUIElementCreateApplication(running.processIdentifier)
        for element in windows(app).flatMap({ descendants($0, limit: 2000) }) {
            if let about, !allTexts(element).contains(where: { $0.contains(about) }) { continue }
            for action in actionNames(element) where action.contains("Name:\(button)\n") || action == button {
                if AXUIElementPerformAction(element, action as CFString) == .success { return true }
            }
        }
    }
    return false
}
/// Press a button of one of those dialogs. With `about`, only of a dialog
/// that names it, so a request made for another program is left alone.
func pressPrompt(_ button: String, about: String? = nil) -> Bool {
    for prompt in systemPrompts() {
        if let about, !prompt.texts.contains(where: { $0.contains(about) }) { continue }
        if let match = prompt.buttons.first(where: { texts($0).contains(button) }) {
            return AXUIElementPerformAction(match, kAXPressAction as CFString) == .success
        }
    }
    return bannerAction(button, about: about)
}

func press(_ element: AXUIElement, _ what: String) throws {
    guard AXUIElementPerformAction(element, kAXPressAction as CFString) == .success else { try fail("could not press \(what)") }
}

func showPrompts(pressing button: String?) {
    for prompt in systemPrompts() { print(prompt.texts.joined(separator: " | ")) }
    for running in NSWorkspace.shared.runningApplications where running.executableURL?.lastPathComponent == "NotificationCenter" {
        let center = AXUIElementCreateApplication(running.processIdentifier)
        for element in windows(center).flatMap({ descendants($0, limit: 2000) }) {
            let offered = actionNames(element).filter { $0.hasPrefix("Name:") }.map { $0.split(separator: "\n").first.map(String.init) ?? $0 }
            if !offered.isEmpty { print("  banner \(texts(element).first ?? "") offers: " + offered.joined(separator: ", ")) }
        }
    }
    if let button { print(pressPrompt(button) ? "pressed \(button)" : "no prompt has \(button)") }
}

func showTree(_ app: AXUIElement) {
    func show(_ element: AXUIElement, _ depth: Int) {
        guard depth < 40 else { return }
        print(String(repeating: "  ", count: depth) + role(element) + " " + texts(element).map { "\"\($0)\"" }.joined(separator: " "))
        for child in children(element) { show(child, depth + 1) }
    }
    for window in windows(app) { show(window, 0) }
}

func pressControl(_ app: AXUIElement, _ name: String, nth: Int) throws {
    let roles = [kAXButtonRole, kAXCheckBoxRole, kAXMenuButtonRole, kAXPopUpButtonRole, kAXMenuItemRole, kAXRadioButtonRole, "AXLink", "AXSwitch"]
    let matches = named(app, name, in: roles)
    guard nth < matches.count else { try fail("no control named \(name) (found \(matches.count))") }
    try press(matches[nth], name)
}

func openPage(_ app: AXUIElement, _ name: String) throws {
    if let show = named(app, "Show Sidebar", in: [kAXButtonRole]).first { try press(show, "Show Sidebar") }
    var row: AXUIElement?
    try waitFor("sidebar row \(name)") {
        row = windowElements(app).first { role($0) == kAXRowRole && descendants($0).flatMap { texts($0) }.contains(name) }
        return row != nil
    }
    guard AXUIElementSetAttributeValue(row!, kAXSelectedAttribute as CFString, kCFBooleanTrue) == .success else { try fail("could not open \(name)") }
}

func selectRows(_ app: AXUIElement, _ numbers: [String]) throws {
    guard let list = listRows(app) else { try fail("the page shows no list") }
    let picked = numbers == ["all"] ? list.rows : try numbers.map { (text: String) -> AXUIElement in
        guard let n = Int(text), n < list.rows.count else { try fail("no row \(text) of \(list.rows.count)") }
        return list.rows[n]
    }
    guard AXUIElementSetAttributeValue(list.table, kAXSelectedRowsAttribute as CFString, picked as CFArray) == .success else {
        try fail("could not select the rows")
    }
}

func toggle(_ app: AXUIElement, beside label: String) throws {
    // A switch has no name of its own: its label is a text beside it.
    let holder = besideLists(app).first { element in
        let inside = children(element)
        return inside.contains { texts($0).contains(label) } && inside.contains { role($0) == kAXCheckBoxRole }
    }
    guard let box = holder.flatMap({ children($0).first { role($0) == kAXCheckBoxRole } }) else { try fail("no switch beside \(label)") }
    try press(box, "the switch")
}

func filter(_ app: AXUIElement, _ text: String) throws {
    guard let field = windowElements(app).first(where: {
        role($0) == kAXTextFieldRole && attribute($0, kAXSubroleAttribute) as? String == "AXSearchField"
    }) else { try fail("the window has no Filter field") }
    guard AXUIElementSetAttributeValue(field, kAXValueAttribute as CFString, text as CFString) == .success else {
        try fail("could not type into the Filter field")
    }
    _ = AXUIElementPerformAction(field, kAXConfirmAction as CFString)
}

func setAside(_ app: AXUIElement, reason: String) throws {
    let menus = [kAXMenuButtonRole, kAXPopUpButtonRole]
    guard let menu = besideLists(app).first(where: {
        menus.contains(role($0)) && descendants($0).flatMap { texts($0) }.contains { $0.hasPrefix("Set Aside") }
    }) else { try fail("the selection has no Set Aside… menu") }
    try press(menu, "Set Aside…")
    var item: AXUIElement?
    try waitFor("the reason \(reason)", seconds: 5) {
        item = (descendants(menu) + descendants(app, limit: 400)).first { role($0) == kAXMenuItemRole && texts($0).contains(reason) }
        return item != nil
    }
    try press(item!, reason)
}

/// Every row of the open list as its inspector's text, written to `file`.
func dump(_ app: AXUIElement, to file: String) throws {
    var out: [[String]] = []
    var before: [String] = []
    // An empty page shows a heading in place of its list.
    let list = listRows(app)
    for row in list?.rows ?? [] {
        _ = AXUIElementSetAttributeValue(list!.table, kAXSelectedRowsAttribute as CFString, [row] as CFArray)
        // The inspector follows the selection. Rows off the screen have no
        // text of their own, so the inspector is what says what a row is.
        var shown: [String] = []
        try? waitFor("the inspector to change", seconds: 3) {
            shown = detail(app)
            return shown != before && shown.contains("Where")
        }
        if let copies = besideLists(app).first(where: { role($0) == kAXButtonRole && texts($0).contains("Show Copies") }),
           AXUIElementPerformAction(copies, kAXPressAction as CFString) == .success {
            try? waitFor("the copies", seconds: 3) { detail(app).contains("Hide Copies") }
            shown = detail(app)
        }
        before = shown
        out.append(shown)
    }
    try json(out).write(toFile: file, atomically: true, encoding: .utf8)
    print("\(out.count) rows -> \(file)")
}

/// Choose Scan Now, answer macOS's requests that name Loose Keys with Allow,
/// and say how long the scan took.
func scan(_ app: AXUIElement, limit: Double) throws {
    guard let item = named(app, "Scan Now", in: [kAXMenuItemRole]).first else { try fail("no menu item Scan Now") }
    try press(item, "Scan Now")
    let started = Date()
    var answered = 0
    let enabled = { (name: String) in named(app, name, in: [kAXMenuItemRole]).first.map { attribute($0, kAXEnabledAttribute) as? Bool == true } ?? false }
    func answer() {
        for prompt in systemPrompts() where prompt.texts.contains(where: { $0.contains("Loose Keys") })
            && prompt.buttons.contains(where: { texts($0).contains("Allow") }) {
            print("macOS asked: " + prompt.texts.joined(separator: " | "))
            if pressPrompt("Allow", about: "Loose Keys") { answered += 1 }
        }
    }
    try waitFor("the scan to start", seconds: 15) {
        answer()
        return enabled("Stop Scan") || !enabled("Scan Now")
    }
    try waitFor("the scan to finish", seconds: limit) {
        answer()
        return enabled("Scan Now") && !enabled("Stop Scan")
    }
    print(String(format: "scan finished in %.1f seconds; %d macOS requests answered with Allow", Date().timeIntervalSince(started), answered))
}

func run(_ args: [String]) throws {
    guard let command = args.first else { print(usage); return }
    let rest = Array(args.dropFirst())
    if command == "prompts" { return showPrompts(pressing: rest.first) }
    let app = try looseKeys()
    let takesArgument = ["menu", "press", "page", "toggle", "setaside", "dump", "wait"]
    guard !takesArgument.contains(command) || !rest.isEmpty else { try fail(usage) }
    switch command {
    case "tree": showTree(app)
    case "texts": for window in windows(app) { allTexts(window).forEach { print($0) } }
    case "menu":
        guard let item = named(app, rest[0], in: [kAXMenuItemRole]).first else { try fail("no menu item \(rest[0])") }
        try press(item, rest[0])
    case "press": try pressControl(app, rest[0], nth: rest.count > 1 ? Int(rest[1]) ?? 0 : 0)
    case "page": try openPage(app, rest[0])
    case "rows": print(json((listRows(app)?.rows ?? []).map { allTexts($0) }))
    case "select": try selectRows(app, rest)
    case "toggle": try toggle(app, beside: rest[0])
    case "filter": try filter(app, rest.first ?? "")
    case "setaside": try setAside(app, reason: rest[0])
    case "detail": detail(app).forEach { print($0) }
    case "dump": try dump(app, to: rest[0])
    case "wait":
        try waitFor(rest[0], seconds: rest.count > 1 ? Double(rest[1]) ?? 20 : 20) {
            windowElements(app).flatMap { texts($0) }.contains { $0.contains(rest[0]) }
        }
    case "scan": try scan(app, limit: rest.first.flatMap(Double.init) ?? 180)
    default: print(usage)
    }
}

do { try run(Array(CommandLine.arguments.dropFirst())) } catch {
    fputs("FAIL: \((error as? Failure)?.message ?? "\(error)")\n", stderr)
    exit(1)
}
