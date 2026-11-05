// Guest-only regression against the real bundle; never linked into the app.
import AppKit
import ApplicationServices

struct CheckError: Error { let message: String }
var runDeadline = Date().addingTimeInterval(80)
func fail(_ message: String) throws -> Never { throw CheckError(message: message) }
func attribute(_ element: AXUIElement, _ name: String) -> CFTypeRef? {
    guard Date() < runDeadline else { return nil }
    var value: CFTypeRef?
    return AXUIElementCopyAttributeValue(element, name as CFString, &value) == .success ? value : nil
}
func descendants(_ root: AXUIElement) -> [AXUIElement] {
    var result: [AXUIElement] = []
    func visit(_ element: AXUIElement, _ depth: Int) {
        guard depth < 30, result.count < 5000, Date() < runDeadline else { return }
        result.append(element)
        for child in attribute(element, kAXChildrenAttribute) as? [AXUIElement] ?? [] { visit(child, depth + 1) }
    }
    visit(root, 0)
    return result
}
func texts(_ element: AXUIElement) -> [String] {
    [kAXTitleAttribute, kAXDescriptionAttribute, kAXValueAttribute].compactMap { attribute(element, $0) as? String }
}
func wait(_ name: String, _ condition: () throws -> Bool) throws {
    let deadline = min(Date().addingTimeInterval(20), runDeadline)
    repeat {
        if try condition() { return }
        Thread.sleep(forTimeInterval: 0.1)
    } while Date() < deadline
    try fail("timeout: \(name)")
}
func key(_ code: CGKeyCode, flags: CGEventFlags) {
    for down in [true, false] {
        let event = CGEvent(keyboardEventSource: nil, virtualKey: code, keyDown: down)
        event?.flags = flags
        event?.post(tap: .cghidEventTap)
        Thread.sleep(forTimeInterval: 0.1)
    }
    Thread.sleep(forTimeInterval: 0.3)
}
let args = CommandLine.arguments
let files = FileManager.default
guard args.count == 3, ProcessInfo.processInfo.environment["LOOSE_KEYS_APP_CHECK"] == "synthetic-home" else {
    fputs("FAIL: use the guarded guest check script\n", stderr)
    exit(2)
}
let work = URL(fileURLWithPath: args[2])
let home = work.appendingPathComponent("home")
var child: Process?
var outcome: Int32 = 0
var questionWorded = true
func unanswered() throws {
    let state = home.appendingPathComponent("Library/Application Support/dev.loosekeys.desktop/state.json")
    if files.fileExists(atPath: state.path) {
        guard let json = try JSONSerialization.jsonObject(with: Data(contentsOf: state)) as? [String: Any],
              json["update_check"] == nil || json["update_check"] is NSNull else {
            try fail("quitting answered update consent")
        }
    }
}
func launch(_ name: String) throws -> (Process, AXUIElement) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: args[1] + "/Contents/MacOS/loose-keys-gui")
    var environment = ProcessInfo.processInfo.environment
    environment["HOME"] = home.path
    process.environment = environment
    let logURL = work.appendingPathComponent(name + ".log")
    files.createFile(atPath: logURL.path, contents: nil)
    let log = try FileHandle(forWritingTo: logURL)
    defer { try? log.close() }
    process.standardOutput = log
    process.standardError = log
    try process.run()
    child = process
    let app = AXUIElementCreateApplication(process.processIdentifier)
    AXUIElementSetMessagingTimeout(app, 2)
    try wait("unanswered update question") {
        guard process.isRunning else { try fail("app exited before update question") }
        return descendants(app).flatMap { texts($0) }.contains("Check for Updates Automatically?")
    }
    // One line says what the check does; what GitHub sees is in the usage guide.
    let message = descendants(app).flatMap { texts($0) }.joined(separator: "\n")
    questionWorded = questionWorded && message.contains("Loose Keys can check GitHub for a new version once a day.")
        && !message.contains("IP address")
    try unanswered()
    return (process, app)
}
do {
    guard AXIsProcessTrusted() else { try fail("Accessibility is not granted to the driver responsible client") }
    try files.createDirectory(at: home, withIntermediateDirectories: false)
    // Reuse the same synthetic HOME: every successful quit must leave the
    // question unanswered, so the next launch must ask it again.
    for method in ["native", "menu", "keyboard"] {
        let (process, app) = try launch(method)
        print("PASS: unanswered update question before \(method) quit")
        switch method {
        case "native":
            guard NSRunningApplication(processIdentifier: process.processIdentifier)?.terminate() == true else {
                try fail("native termination request refused")
            }
        case "menu":
            guard let bar = attribute(app, kAXMenuBarAttribute),
                  let item = descendants(bar as! AXUIElement).first(where: {
                      attribute($0, kAXRoleAttribute) as? String == kAXMenuItemRole && texts($0).contains("Quit Loose Keys")
                  }), attribute(item, kAXEnabledAttribute) as? Bool == true else { try fail("Quit menu item absent or disabled") }
            // Termination can invalidate the AX element before its reply.
            _ = AXUIElementPerformAction(item, kAXPressAction as CFString)
        default:
            NSRunningApplication(processIdentifier: process.processIdentifier)?.activate(options: [])
            Thread.sleep(forTimeInterval: 0.3)
            key(12, flags: .maskCommand)
        }
        try wait("unanswered update consent permits \(method) quit") { !process.isRunning }
        guard process.terminationStatus == 0 else { try fail("app did not exit normally") }
        try unanswered()
        print("PASS: \(method) quit exits normally without answering update consent")
    }
    guard questionWorded else {
        try fail("update consent must say in one line that Loose Keys checks GitHub once a day")
    }
    print("PASS: update consent says in one line that Loose Keys checks GitHub once a day")
} catch {
    fputs("FAIL: \((error as? CheckError)?.message ?? "test setup or file operation failed")\n", stderr)
    outcome = 1
}
if let process = child, process.isRunning {
    runDeadline = Date().addingTimeInterval(20)
    kill(process.processIdentifier, SIGKILL)
    do { try wait("owned app cleanup") { !process.isRunning } }
    catch { fputs("FAIL: owned app cleanup\n", stderr); outcome = 1 }
}
do {
    if files.fileExists(atPath: home.path) { try files.removeItem(at: home) }
    print("PASS: owned process stopped and synthetic home removed")
} catch { fputs("FAIL: synthetic home cleanup\n", stderr); outcome = 1 }
exit(outcome)
