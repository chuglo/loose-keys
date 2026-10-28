// Installs a configuration profile through System Settings, as a person does
// after downloading one, and checks that macOS reports the app's settings in it
// as managed. Guest only: it installs a profile for the whole Mac and types the
// guest's administrator password. Never linked into the app.
import AppKit
import ApplicationServices

let domain = "dev.loosekeys.desktop"

func stop(_ message: String, _ status: Int32 = 1) -> Never {
    print(message)
    exit(status)
}
func attribute(_ element: AXUIElement, _ name: String) -> CFTypeRef? {
    var result: CFTypeRef?
    return AXUIElementCopyAttributeValue(element, name as CFString, &result) == .success ? result : nil
}
func role(_ element: AXUIElement) -> String { attribute(element, kAXRoleAttribute) as? String ?? "" }
func texts(_ element: AXUIElement) -> [String] {
    [kAXTitleAttribute, kAXDescriptionAttribute, kAXValueAttribute].compactMap { attribute(element, $0) as? String }
}
func descendants(_ root: AXUIElement, _ depth: Int = 0) -> [AXUIElement] {
    guard depth < 40 else { return [] }
    return [root] + (attribute(root, kAXChildrenAttribute) as? [AXUIElement] ?? []).flatMap { descendants($0, depth + 1) }
}
func elements(_ app: NSRunningApplication) -> [AXUIElement] {
    let element = AXUIElementCreateApplication(app.processIdentifier)
    AXUIElementSetMessagingTimeout(element, 2)
    return (attribute(element, kAXWindowsAttribute) as? [AXUIElement] ?? []).flatMap { descendants($0) }
}
func running(_ bundle: String) -> [NSRunningApplication] {
    NSRunningApplication.runningApplications(withBundleIdentifier: bundle)
}
func button(_ bundle: String, _ title: String) -> AXUIElement? {
    running(bundle).flatMap { elements($0) }.first { role($0) == kAXButtonRole && texts($0).contains(title) }
}
/// Waits up to `seconds` for `found` to return a value. It runs the run loop
/// meanwhile: NSWorkspace learns of newly started apps, such as SecurityAgent,
/// only through it.
func waitFor<T>(_ what: String, _ seconds: Double = 30, _ found: () -> T?) -> T {
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline {
        if let value = found() { return value }
        RunLoop.current.run(until: Date().addingTimeInterval(0.25))
    }
    stop("FAIL: timeout: \(what)")
}
func press(_ bundle: String, _ title: String) {
    let control = waitFor("\(title) button") { button(bundle, title) }
    guard AXUIElementPerformAction(control, kAXPressAction as CFString) == .success else { stop("FAIL: could not press \(title)") }
    print("pressed \(title)")
}
func open(_ target: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
    process.arguments = [target]
    do { try process.run() } catch { stop("FAIL: could not run open") }
    process.waitUntilExit()
    guard process.terminationStatus == 0 else { stop("FAIL: open exited \(process.terminationStatus)") }
}
/// Points across the middle of an element, left to right.
func points(_ element: AXUIElement) -> [CGPoint] {
    guard let position = attribute(element, kAXPositionAttribute), let size = attribute(element, kAXSizeAttribute) else { return [] }
    var origin = CGPoint.zero, extent = CGSize.zero
    AXValueGetValue(position as! AXValue, .cgPoint, &origin)
    AXValueGetValue(size as! AXValue, .cgSize, &extent)
    return [0.1, 0.3, 0.5, 0.7, 0.9].map { CGPoint(x: origin.x + extent.width * $0, y: origin.y + extent.height / 2) }
}
/// The process that owns the frontmost window at a point, among app windows
/// and alerts. The Dock's (20) and the menu bar's levels hold transparent
/// full-screen windows that do not take clicks.
func owner(at point: CGPoint) -> pid_t? {
    let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
    for window in windows where (0..<20).contains(window[kCGWindowLayer as String] as? Int ?? -1) {
        guard let bounds = window[kCGWindowBounds as String] as? NSDictionary,
              let rect = CGRect(dictionaryRepresentation: bounds), rect.contains(point),
              (window[kCGWindowAlpha as String] as? Double ?? 1) > 0 else { continue }
        return window[kCGWindowOwnerPID as String] as? pid_t
    }
    return nil
}
func doubleClick(_ point: CGPoint) {
    for count in 1...2 {
        for type in [CGEventType.leftMouseDown, .leftMouseUp] {
            let event = CGEvent(mouseEventSource: nil, mouseType: type, mouseCursorPosition: point, mouseButton: .left)!
            event.setIntegerValueField(.mouseEventClickState, value: Int64(count))
            event.post(tap: .cghidEventTap)
            usleep(40_000)
        }
    }
}

// Guards: an approved disposable guest, never the host or root.
var size = 0
sysctlbyname("hw.model", nil, &size, nil, 0)
var model = [CChar](repeating: 0, count: size)
sysctlbyname("hw.model", &model, &size, nil, 0)
guard ProcessInfo.processInfo.environment["LOOSE_KEYS_PROFILE_CHECK"] == "disposable-guest",
      String(cString: model).hasPrefix("VirtualMac"), getuid() != 0 else {
    stop("BLOCKED: approved disposable guest required", 2)
}
guard AXIsProcessTrusted() else { stop("BLOCKED: guest driver needs Accessibility", 2) }
let args = CommandLine.arguments
guard args.count == 2, let password = ProcessInfo.processInfo.environment["LOOSE_KEYS_GUEST_PASSWORD"] else {
    stop("Usage: LOOSE_KEYS_GUEST_PASSWORD=… install-profile <file.mobileconfig>", 2)
}

// What the profile should change: the keys of its payloads for the app.
guard let data = FileManager.default.contents(atPath: args[1]),
      let profile = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
      let name = profile["PayloadDisplayName"] as? String,
      let payloads = profile["PayloadContent"] as? [[String: Any]] else {
    stop("FAIL: not an unsigned configuration profile with a PayloadDisplayName and PayloadContent", 2)
}
let keys = Set(payloads.filter { $0["PayloadType"] as? String == domain }
    .flatMap { $0.keys.filter { !$0.hasPrefix("Payload") } }).sorted()
guard !keys.isEmpty else { stop("FAIL: the profile sets nothing for \(domain)", 2) }
let before = keys.filter { CFPreferencesAppValueIsForced($0 as CFString, domain as CFString) }
guard before.isEmpty else { stop("FAIL: already managed before install: \(before.joined(separator: ", "))", 2) }

// Download it, as a browser does, and open Device Management.
open(args[1])
// macOS says "Profile Downloaded" in an alert that can cover the list.
press("com.apple.UserNotificationCenter", "OK")
open("x-apple.systempreferences:com.apple.Profiles-Settings.extension")
let settings = waitFor("System Settings") { running("com.apple.systempreferences").first }
settings.activate()
let row = waitFor("\(name) under Downloaded") {
    elements(settings).first { role($0) == kAXStaticTextRole && texts($0).contains(name) }
}
// The row opens only on a double-click. Move the window to the left edge, away
// from alerts in the middle of the screen, and click only where it is on top.
if let window = (attribute(AXUIElementCreateApplication(settings.processIdentifier), kAXWindowsAttribute) as? [AXUIElement])?.first {
    var corner = CGPoint(x: 0, y: 30)
    AXUIElementSetAttributeValue(window, kAXPositionAttribute as CFString, AXValueCreate(.cgPoint, &corner)!)
}
let point = waitFor("\(name) on screen and uncovered", 15) { () -> CGPoint? in
    settings.activate()
    return points(row).first { owner(at: $0) == settings.processIdentifier }
}
doubleClick(point)
press("com.apple.systempreferences", "Install…")
press("com.apple.systempreferences", "Install")

// macOS asks for the administrator password unless it was given in the last
// few minutes. Its prompt is SecurityAgent's; the second field is the password.
func managed() -> Bool { keys.allSatisfy { CFPreferencesAppValueIsForced($0 as CFString, domain as CFString) } }
func prompt() -> [AXUIElement] {
    NSWorkspace.shared.runningApplications.filter { $0.bundleIdentifier == "com.apple.SecurityAgent" }.flatMap { elements($0) }
}
let field = waitFor("password prompt or managed settings") { () -> AXUIElement?? in
    if managed() { return .some(nil) }
    let fields = prompt().filter { role($0) == kAXTextFieldRole }
    guard fields.count >= 2 else { return nil }
    return .some(fields.first { attribute($0, kAXSubroleAttribute) as? String == kAXSecureTextFieldSubrole } ?? fields[1])
}
if let field {
    guard AXUIElementSetAttributeValue(field, kAXValueAttribute as CFString, password as CFString) == .success,
          let ok = prompt().first(where: { role($0) == kAXButtonRole && texts($0).contains("OK") }),
          AXUIElementPerformAction(ok, kAXPressAction as CFString) == .success else {
        stop("FAIL: could not answer the password prompt")
    }
    print("answered the password prompt")
}

// macOS reports every key in the payload as managed, and the profile as installed.
for key in keys {
    _ = waitFor("\(key) managed", 30) { CFPreferencesAppValueIsForced(key as CFString, domain as CFString) ? true : nil }
    print("PASS: \(key) is managed")
}
_ = waitFor("\(name) listed as installed", 15) { () -> Bool? in
    elements(settings).contains { texts($0).contains("Profile not installed. Double-click to review.") } ? nil : true
}
settings.terminate()
print("PASS: installed \(name)")
