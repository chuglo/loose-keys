// Separate test driver. Never linked into the app bundle.
import AppKit
import ApplicationServices

struct CheckError: Error { let message: String }
var runDeadline = Date().addingTimeInterval(80)
func fail(_ message: String) throws -> Never { throw CheckError(message: message) }
func attribute(_ element: AXUIElement, _ name: String) -> CFTypeRef? {
    guard Date() < runDeadline else { return nil }
    var result: CFTypeRef?
    return AXUIElementCopyAttributeValue(element, name as CFString, &result) == .success ? result : nil
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
    [kAXTitleAttribute, kAXDescriptionAttribute, kAXValueAttribute, kAXHelpAttribute]
        .compactMap { attribute(element, $0) as? String }
}
func wait(_ name: String, _ condition: () throws -> Bool) throws {
    let deadline = min(Date().addingTimeInterval(20), runDeadline)
    repeat {
        if try condition() { return }
        Thread.sleep(forTimeInterval: 0.1)
    } while Date() < deadline
    try fail("timeout: \(name)")
}
func press(_ element: AXUIElement?, _ name: String) throws {
    guard let element else { try fail("missing control: \(name)") }
    guard AXUIElementPerformAction(element, kAXPressAction as CFString) == .success else {
        try fail("AX press: \(name)")
    }
}

let files = FileManager.default
let args = CommandLine.arguments
guard args.count == 3, ProcessInfo.processInfo.environment["CREDHYG_APP_CHECK"] == "synthetic-home" else {
    fputs("FAIL: driver requires the guarded check script in an approved test guest\n", stderr)
    exit(2)
}
let home = URL(fileURLWithPath: args[2]).appendingPathComponent("home")
let report = files.homeDirectoryForCurrentUser.appendingPathComponent("Documents")
    .appendingPathComponent("credhyg-bundle-check-" + UUID().uuidString + ".json")
let process = Process()
var launched = false
var outcome = 0
var secrets: [String] = []
func leaks(_ text: String) -> Bool {
    secrets.contains { text.contains($0) || text.contains(String($0.prefix(10))) || text.contains(String($0.suffix(10))) }
}
do {
    guard AXIsProcessTrusted() else { try fail("Accessibility is not granted to the driver responsible client") }
    guard files.fileExists(atPath: args[1] + "/Contents/MacOS/loose-keys-gui") else {
        try fail("built app bundle is absent")
    }
    try files.createDirectory(at: home.appendingPathComponent(".ssh"), withIntermediateDirectories: true)
    try files.createDirectory(at: home.appendingPathComponent(".aws"), withIntermediateDirectories: true)
    let keyBody = UUID().uuidString
    let access = "AK" + "IA" + String(UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(16))
    let secret = UUID().uuidString.replacingOccurrences(of: "-", with: "") +
        String(UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(8))
    secrets = [keyBody, access, secret]
    let key = "-----BEGIN RSA " + "PRIVATE KEY-----\n" + keyBody + "\n-----END RSA " + "PRIVATE KEY-----\n"
    try key.write(to: home.appendingPathComponent(".ssh/id_bundle_check"), atomically: false, encoding: .utf8)
    if ProcessInfo.processInfo.environment["CREDHYG_APP_CHECK_OMIT_AWS"] != "1" {
        try "[bundle-check]\naws_access_key_id = \(access)\naws_secret_access_key = \(secret)\n"
            .write(to: home.appendingPathComponent(".aws/credentials"), atomically: false, encoding: .utf8)
    }
    process.executableURL = URL(fileURLWithPath: args[1] + "/Contents/MacOS/loose-keys-gui")
    var environment = ProcessInfo.processInfo.environment
    environment["HOME"] = home.path
    process.environment = environment
    // App logs can contain paths. Keep them in the owner-only test work folder.
    files.createFile(atPath: args[2] + "/app.log", contents: nil)
    let log = try FileHandle(forWritingTo: URL(fileURLWithPath: args[2] + "/app.log"))
    defer { try? log.close() }
    process.standardOutput = log
    process.standardError = log
    try process.run()
    launched = true
    let app = AXUIElementCreateApplication(process.processIdentifier)
    AXUIElementSetMessagingTimeout(app, 2)
    func alive() throws {
        guard process.isRunning else { try fail("app exited before check completed") }
    }
    func windowElements() -> [AXUIElement] {
        (attribute(app, kAXWindowsAttribute) as? [AXUIElement] ?? []).flatMap { descendants($0) }
    }
    func checkLeaks() throws {
        let exposed = windowElements().flatMap { texts($0) }.joined(separator: "\n")
        guard !leaks(exposed) else { try fail("planted secret exposed through Accessibility") }
    }
    func menuItem(_ name: String) -> AXUIElement? {
        guard let bar = attribute(app, kAXMenuBarAttribute) else { return nil }
        return descendants(bar as! AXUIElement).first { texts($0).contains(name) }
    }
    func button(_ name: String) -> AXUIElement? {
        windowElements().first {
            attribute($0, kAXRoleAttribute) as? String == kAXButtonRole && texts($0).contains(name)
        }
    }
    try wait("app window") { try alive(); return !windowElements().isEmpty }
    print("PASS: built bundle launched and window is accessible")
    try wait("home ready for scan") {
        windowElements().contains { attribute($0, kAXRoleAttribute) as? String == kAXButtonRole &&
            texts($0).contains("Scan") && attribute($0, kAXEnabledAttribute) as? Bool == true }
    }
    try wait("Scan Now menu item") { menuItem("Scan Now") != nil }
    try press(menuItem("Scan Now"), "Scan Now")
    try wait("scan completion") {
        try alive()
        try checkLeaks()
        return menuItem("Save Report…").map { attribute($0, kAXEnabledAttribute) as? Bool == true } ?? false
    }
    print("PASS: scan through app interface completed with app alive")
    guard let row = windowElements().first(where: {
        attribute($0, kAXRoleAttribute) as? String == kAXRowRole &&
            descendants($0).flatMap { texts($0) }.contains("Worth Reviewing")
    }) else { try fail("Worth Reviewing sidebar row is absent") }
    guard AXUIElementSetAttributeValue(row, kAXSelectedAttribute as CFString, kCFBooleanTrue) == .success else {
        try fail("cannot select Worth Reviewing")
    }
    let expected = [("Possible private key", "~/.ssh/id_bundle_check", "key.ssh.private"),
                    ("AWS access keys stored in a file", "~/.aws/credentials", "dev.aws.inline-credentials")]
    try wait("specific fixture findings in window") {
        try alive()
        try checkLeaks()
        let rows = windowElements().filter { attribute($0, kAXRoleAttribute) as? String == kAXRowRole }
        return expected.allSatisfy { title, path, _ in
            rows.contains { row in
                let exposed = descendants(row).flatMap { texts($0) }
                return exposed.contains(title) && exposed.contains((path as NSString).lastPathComponent) &&
                    exposed.contains((path as NSString).deletingLastPathComponent)
            }
        }
    }
    print("PASS: window shows private-key and AWS fixture titles and paths; no planted values, prefixes or suffixes")
    for (title, path, _) in expected {
        guard let finding = windowElements().first(where: {
            attribute($0, kAXRoleAttribute) as? String == kAXRowRole && descendants($0).flatMap { texts($0) }.contains(title)
        }), AXUIElementSetAttributeValue(finding, kAXSelectedAttribute as CFString, kCFBooleanTrue) == .success else {
            try fail("cannot select fixture finding")
        }
        try wait("fixture inspector") {
            try alive()
            try checkLeaks()
            return windowElements().flatMap { texts($0) }.contains { $0.hasPrefix(path) }
        }
    }
    print("PASS: fixture inspectors expose no planted values, prefixes or suffixes")
    // The last selected item is AWS. Exercise persisted decisions through the
    // real window, then leave it deferred while exporting: a label must not
    // remove a finding from the report.
    try wait("reminder decision") { button("Remind Me in a Week") != nil }
    try press(button("Remind Me in a Week"), "Remind Me in a Week")
    try wait("deferred decision saved") {
        try alive()
        try checkLeaks()
        return button("Return to Review") != nil
    }
    try press(button("Return to Review"), "Return to Review")
    try wait("decision restored") { button("Remind Me in a Week") != nil }
    try press(button("Remind Me in a Week"), "Remind Me in a Week")
    try wait("deferred again") { button("Return to Review") != nil }
    print("PASS: real review decisions defer, restore and defer the AWS item")
    try press(menuItem("Save Report…"), "Save Report")
    try wait("save panel name field") {
        windowElements().contains { attribute($0, kAXRoleAttribute) as? String == kAXTextFieldRole &&
            (attribute($0, kAXValueAttribute) as? String ?? "").contains("loose-keys-report") }
    }
    guard let field = windowElements().first(where: { attribute($0, kAXRoleAttribute) as? String == kAXTextFieldRole &&
        (attribute($0, kAXValueAttribute) as? String ?? "").contains("loose-keys-report") }) else {
        try fail("save panel name field disappeared")
    }
    guard AXUIElementSetAttributeValue(field, kAXValueAttribute as CFString, report.lastPathComponent as CFString) == .success else {
        try fail("cannot set report destination")
    }
    guard let destination = windowElements().first(where: {
        attribute($0, kAXRoleAttribute) as? String == kAXPopUpButtonRole && texts($0).contains("Where:")
    }), attribute(destination, kAXValueAttribute) as? String == "Documents" else {
        try fail("save panel destination must be Documents in the test guest")
    }
    guard let save = windowElements().first(where: { attribute($0, kAXRoleAttribute) as? String == kAXButtonRole && texts($0).contains("Save") }) else {
        try fail("save panel Save button is absent")
    }
    try press(save, "save panel Save")
    try wait("exported report") { try alive(); return files.fileExists(atPath: report.path) }
    let data = try Data(contentsOf: report)
    let text = String(decoding: data, as: UTF8.self)
    guard !leaks(text) else { try fail("export contains planted secret") }
    let mode = try files.attributesOfItem(atPath: report.path)[.posixPermissions] as? NSNumber
    guard let mode, mode.intValue & 0o077 == 0 else { try fail("export is not owner-only") }
    guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          json["schema"] as? String == "loose-keys/report/1",
          let findings = json["findings"] as? [[String: Any]] else { try fail("export is not report version 1") }
    for (_, path, rule) in expected {
        guard findings.contains(where: { $0["path"] as? String == path && $0["rule"] as? String == rule }) else {
            try fail("export missing \(rule) at \(path)")
        }
    }
    try checkLeaks()
    try data.write(to: URL(fileURLWithPath: args[2]).appendingPathComponent("report.json"), options: .withoutOverwriting)
    print("PASS: app exported owner-only report with specific fixture rules and paths; no planted values, prefixes or suffixes")
    // Remove only the fixture this driver created, then rescan through the UI.
    // A previously deferred item must still be rechecked and marked fixed.
    try files.removeItem(at: home.appendingPathComponent(".aws/credentials"))
    try press(menuItem("Scan Now"), "Scan Now after fixture removal")
    // Every scan opens Overview. Return to the list before asserting its rows.
    try wait("rescan opened overview") {
        windowElements().contains {
            attribute($0, kAXRoleAttribute) as? String == kAXRowRole &&
                descendants($0).flatMap { texts($0) }.contains("Worth Reviewing") &&
                attribute($0, kAXSelectedAttribute) as? Bool == false
        }
    }
    try wait("rescan completion") {
        try alive()
        try checkLeaks()
        return menuItem("Save Report…").map { attribute($0, kAXEnabledAttribute) as? Bool == true } ?? false
    }
    guard let reviewRow = windowElements().first(where: {
        attribute($0, kAXRoleAttribute) as? String == kAXRowRole &&
            descendants($0).flatMap { texts($0) }.contains("Worth Reviewing")
    }), AXUIElementSetAttributeValue(reviewRow, kAXSelectedAttribute as CFString, kCFBooleanTrue) == .success else {
        try fail("cannot return to Worth Reviewing after rescan")
    }
    var rescanEvidence = "no rows observed"
    do {
        try wait("removed AWS fixture marked fixed") {
            try alive()
            try checkLeaks()
            let rows = windowElements().filter { attribute($0, kAXRoleAttribute) as? String == kAXRowRole }
            let awsFixed = rows.contains {
                let exposed = descendants($0).flatMap { texts($0) }
                return exposed.contains("AWS access keys stored in a file") && exposed.contains("Fixed")
            }
            let keyStillOpen = rows.contains {
                let exposed = descendants($0).flatMap { texts($0) }
                return exposed.contains("Possible private key") && !exposed.contains("Fixed")
            }
            let visible = windowElements().flatMap { texts($0) }
            let awsPresent = rows.contains { descendants($0).flatMap { texts($0) }.contains("AWS access keys stored in a file") }
            let inspectorFixed = visible.contains("Nothing to decide. It is fixed here.")
            rescanEvidence = "AWS row=\(awsPresent), row fixed=\(awsFixed), key open=\(keyStillOpen), inspector fixed=\(inspectorFixed)"
            return awsFixed && keyStillOpen
        }
    } catch {
        let message = (error as? CheckError)?.message ?? "rescan failed"
        try fail(message + " (" + rescanEvidence + ")")
    }
    print("PASS: rescan marks the removed deferred fixture fixed and leaves the private key unresolved")
} catch {
    let message = (error as? CheckError)?.message ?? "test setup or file operation failed"
    fputs("FAIL: \(message)\n", stderr)
    outcome = 1
}
if launched {
    // Each AX call has its own timeout. Cleanup gets a separate total deadline.
    runDeadline = Date().addingTimeInterval(20)
    let app = AXUIElementCreateApplication(process.processIdentifier)
    AXUIElementSetMessagingTimeout(app, 2)
    let windows = attribute(app, kAXWindowsAttribute) as? [AXUIElement] ?? []
    if let cancel = windows.flatMap({ descendants($0) }).first(where: {
        attribute($0, kAXRoleAttribute) as? String == kAXButtonRole && texts($0).contains("Cancel")
    }) { try? press(cancel, "cancel save panel") }
    if let running = NSRunningApplication(processIdentifier: process.processIdentifier) { running.terminate() }
    do { try wait("app quit") { !process.isRunning } }
    catch {
        process.terminate()
        if process.isRunning { kill(process.processIdentifier, SIGKILL) }
        fputs("FAIL: app did not quit within deadline\n", stderr)
        outcome = 1
    }
}
if files.fileExists(atPath: args[2] + "/app.log") {
    do {
        let log = try String(contentsOfFile: args[2] + "/app.log", encoding: .utf8)
        if leaks(log) { fputs("FAIL: app log contains planted secret\n", stderr); outcome = 1 }
        else if launched { print("PASS: app quit; log exposes no planted values, prefixes or suffixes") }
    } catch { fputs("FAIL: cannot check app log\n", stderr); outcome = 1 }
}
if files.fileExists(atPath: home.path) {
    do { try files.removeItem(at: home) }
    catch { fputs("FAIL: synthetic home cleanup failed\n", stderr); outcome = 1 }
}
if files.fileExists(atPath: report.path) {
    do { try files.removeItem(at: report) }
    catch { fputs("FAIL: guest report cleanup failed\n", stderr); outcome = 1 }
}
if outcome == 0 { print("PASS: synthetic home and temporary Documents export removed") }
exit(Int32(outcome))
