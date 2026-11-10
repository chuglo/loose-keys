// Minimal Settings driver for helper integration tests. Never linked into the app.
import AppKit
import ApplicationServices

func stop(_ message: String, _ status: Int32 = 1) -> Never {
    print(message)
    exit(status)
}
let args = CommandLine.arguments
let environment = ProcessInfo.processInfo.environment
// Independent guard: this executable must also refuse the physical host.
let model = Process()
let output = Pipe()
model.executableURL = URL(fileURLWithPath: "/usr/sbin/sysctl")
model.arguments = ["-n", "hw.model"]
model.standardOutput = output
try model.run()
model.waitUntilExit()
let hardware = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
guard environment["LOOSE_KEYS_HELPER_CHECK"] == "disposable-guest",
      hardware.hasPrefix("VirtualMac"), getuid() != 0 else {
    stop("BLOCKED: approved disposable guest required", 2)
}
guard AXIsProcessTrusted() else { stop("BLOCKED: guest driver needs Accessibility", 2) }
if args.count == 2 && args[1] == "preflight" { print("PASS: Accessibility"); exit(0) }
guard args.count == 3, let pid = Int32(args[1]),
      ["enable", "disable", "restart"].contains(args[2]) else {
    stop("BLOCKED: expected app PID and helper action", 2)
}
let deadline = ProcessInfo.processInfo.systemUptime + 20
// A just-spawned process need not have published its AppKit identity yet.
// Spend the same action deadline waiting for identity before touching any UI.
var identified: NSRunningApplication?
repeat {
    if let candidate = NSRunningApplication(processIdentifier: pid),
       let identifier = candidate.bundleIdentifier {
        guard identifier == "dev.loosekeys.desktop" else {
            stop("BLOCKED: unexpected app identity", 2)
        }
        identified = candidate
        break
    }
    Thread.sleep(forTimeInterval: 0.1)
} while ProcessInfo.processInfo.systemUptime < deadline
guard let running = identified else { stop("FAIL: app identity unavailable before deadline") }
let action = args[2]
let app = AXUIElementCreateApplication(pid)
AXUIElementSetMessagingTimeout(app, 2)
func attribute(_ element: AXUIElement, _ name: String) -> CFTypeRef? {
    var value: CFTypeRef?
    return AXUIElementCopyAttributeValue(element, name as CFString, &value) == .success ? value : nil
}
func descendants(_ root: AXUIElement) -> [AXUIElement] {
    var result: [AXUIElement] = []
    func visit(_ element: AXUIElement, _ depth: Int) {
        guard depth < 24, result.count < 3000,
              ProcessInfo.processInfo.systemUptime < deadline else { return }
        result.append(element)
        for child in attribute(element, kAXChildrenAttribute) as? [AXUIElement] ?? [] {
            visit(child, depth + 1)
        }
    }
    visit(root, 0)
    return result
}
func named(_ element: AXUIElement, _ name: String) -> Bool {
    if [kAXTitleAttribute, kAXDescriptionAttribute].contains(where: { attribute(element, $0) as? String == name }) {
        return true
    }
    if let title = attribute(element, kAXTitleUIElementAttribute) {
        return attribute(title as! AXUIElement, kAXValueAttribute) as? String == name
    }
    return false
}
func windows() -> [AXUIElement] {
    (attribute(app, kAXWindowsAttribute) as? [AXUIElement] ?? []).flatMap { descendants($0) }
}
// The app probes these folders before enabling checks. Decline only its
// exact English folder prompts, through the guest UI; the helper fixture is
// in .aws and needs none of these grants. Never dump system dialog contents.
func declineFolderAccess() {
    let requests = ["Loose Keys", "tart-guest-agent"].flatMap { client in
        ["Desktop", "Documents", "Downloads"].map {
            "\"\(client)\" would like to access files in your \($0) folder."
        }
    }
    for owner in NSWorkspace.shared.runningApplications {
        guard ProcessInfo.processInfo.systemUptime < deadline else { return }
        guard owner.bundleIdentifier == "com.apple.UserNotificationCenter" else { continue }
        let systemApp = AXUIElementCreateApplication(owner.processIdentifier)
        AXUIElementSetMessagingTimeout(systemApp, 0.2)
        for window in attribute(systemApp, kAXWindowsAttribute) as? [AXUIElement] ?? [] {
            let elements = descendants(window)
            let request = elements.contains { element in
                [kAXValueAttribute, kAXTitleAttribute, kAXDescriptionAttribute].contains { key in
                    guard let text = attribute(element, key) as? String else { return false }
                    let normalized = text.replacingOccurrences(of: "“", with: "\"")
                        .replacingOccurrences(of: "”", with: "\"")
                    return requests.contains(normalized)
                }
            }
            guard request else { continue }
            let buttons = elements.filter {
                attribute($0, kAXRoleAttribute) as? String == kAXButtonRole &&
                (named($0, "Don’t Allow") || named($0, "Don't Allow")) &&
                attribute($0, kAXEnabledAttribute) as? Bool == true
            }
            guard buttons.count == 1 else { continue }
            press(buttons[0], "decline folder access")
            print("NOTE: declined a protected-folder request in the guest")
        }
    }
}
func wait(_ message: String, _ condition: () -> Bool) {
    repeat {
        declineFolderAccess()
        if condition() { return }
        // NSWorkspace updates runningApplications only when the main run
        // loop runs. The system prompt's app can launch after this driver.
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.1))
    } while ProcessInfo.processInfo.systemUptime < deadline
    stop("FAIL: " + message)
}
func press(_ element: AXUIElement, _ name: String) {
    let result = AXUIElementPerformAction(element, kAXPressAction as CFString)
    guard result == .success else {
        stop("FAIL: Settings action refused: \(name), AX \(result.rawValue), enabled \(attribute(element, kAXEnabledAttribute) as? Bool ?? false)")
    }
}
func enabled(_ element: AXUIElement, _ name: String, _ role: String) -> Bool {
    named(element, name) && attribute(element, kAXEnabledAttribute) as? Bool == true &&
        attribute(element, kAXRoleAttribute) as? String == role
}
/// A control in Settings, the one window with Add Folder or Drive…. The
/// Overview has a Scan Automatically switch under the same name.
func control(_ name: String, _ role: String) -> AXUIElement? {
    let settings = (attribute(app, kAXWindowsAttribute) as? [AXUIElement] ?? []).map { descendants($0) }
        .filter { $0.contains { enabled($0, "Add Folder or Drive…", kAXButtonRole) } }
    guard settings.count == 1 else { return nil }
    let matches = settings[0].filter { enabled($0, name, role) }
    return matches.count == 1 ? matches[0] : nil
}
func consentSwitch() -> AXUIElement? { control("Scan Automatically", kAXCheckBoxRole) }
running.activate(options: [.activateIgnoringOtherApps])
wait("Settings menu unavailable") {
    if consentSwitch() != nil { return true }
    guard let bar = attribute(app, kAXMenuBarAttribute) else { return false }
    let menu = descendants(bar as! AXUIElement).filter { named($0, "Settings…") }
    if menu.count == 1 { press(menu[0], "Settings"); return true }
    return false
}
wait("background toggle unavailable") { consentSwitch() != nil }
if action == "enable" || action == "disable" {
    let toggle = consentSwitch()!
    let desired = action == "enable" ? 1 : 0
    guard let current = attribute(toggle, kAXValueAttribute) as? Int else {
        stop("FAIL: background toggle value unavailable")
    }
    if current != desired {
        press(toggle, "background toggle")
    }
    wait("background setting did not change") {
        guard let toggle = consentSwitch() else { return false }
        return attribute(toggle, kAXValueAttribute) as? Int == desired
    }
} else {
    // Settings offers the button only while the helper is not running, and
    // takes it away once the helper runs again.
    wait("Restart Helper unavailable") { control("Restart Helper", kAXButtonRole) != nil }
    press(control("Restart Helper", kAXButtonRole)!, "Restart Helper")
    wait("helper did not restart") { control("Restart Helper", kAXButtonRole) == nil }
}
if windows().contains(where: { element in
    (attribute(element, kAXValueAttribute) as? String ?? "").contains("Allow in the Background")
}) { stop("BLOCKED: approve helper in guest Login Items before rerunning", 2) }
print("PASS: helper Settings action " + action)
