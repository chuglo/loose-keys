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
guard environment["CREDHYG_HELPER_CHECK"] == "disposable-guest",
      hardware.hasPrefix("VirtualMac"), getuid() != 0 else {
    stop("BLOCKED: approved disposable guest required", 2)
}
guard AXIsProcessTrusted() else { stop("BLOCKED: guest driver needs Accessibility", 2) }
if args.count == 2 && args[1] == "preflight" { print("PASS: Accessibility"); exit(0) }
guard args.count == 3, let pid = Int32(args[1]),
      ["enable", "enable-overview", "disable", "stop", "start"].contains(args[2]) else {
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
func wait(_ message: String, _ condition: () -> Bool) {
    repeat {
        if condition() { return }
        Thread.sleep(forTimeInterval: 0.1)
    } while ProcessInfo.processInfo.systemUptime < deadline
    stop("FAIL: " + message)
}
func press(_ element: AXUIElement, _ name: String) {
    let result = AXUIElementPerformAction(element, kAXPressAction as CFString)
    // macOS 26 can dismiss the consent sheet and apply Allow, then return
    // attributeUnsupported for its now-gone control. Do not press it twice.
    // The unchanged wait below must prove the toggle became enabled, and the
    // Rust runner separately requires real registration and a completed pass.
    if name == "Allow" && result == .attributeUnsupported {
        print("NOTE: Allow returned AX -25205; checking outcome")
        return
    }
    guard result == .success else {
        stop("FAIL: Settings action refused: \(name), AX \(result.rawValue), enabled \(attribute(element, kAXEnabledAttribute) as? Bool ?? false)")
    }
}
func control(_ name: String) -> AXUIElement? {
    let matches = windows().filter { named($0, name) &&
        attribute($0, kAXEnabledAttribute) as? Bool == true &&
        [kAXCheckBoxRole, kAXButtonRole].contains(attribute($0, kAXRoleAttribute) as? String ?? "") }
    return matches.count == 1 ? matches[0] : nil
}
running.activate(options: [.activateIgnoringOtherApps])
if action == "enable-overview" {
    wait("Overview background consent unavailable") { control("Enable Background Checks") != nil }
    press(control("Enable Background Checks")!, "Enable Background Checks")
}
wait("Settings menu unavailable") {
    if control("Check in the Background") != nil { return true }
    guard let bar = attribute(app, kAXMenuBarAttribute) else { return false }
    let menu = descendants(bar as! AXUIElement).filter { named($0, "Settings…") }
    if menu.count == 1 { press(menu[0], "Settings"); return true }
    return false
}
wait("background toggle unavailable") { control("Check in the Background") != nil }
if action == "enable-overview" {
    // Observe consent through Settings without enabling it there: the first
    // page's action must have done the work. The runner checks the real agent.
    wait("Overview background consent was not saved") {
        guard let toggle = control("Check in the Background") else { return false }
        return attribute(toggle, kAXValueAttribute) as? Int == 1
    }
} else if action == "enable" || action == "disable" {
    let toggle = control("Check in the Background")!
    let desired = action == "enable" ? 1 : 0
    guard let current = attribute(toggle, kAXValueAttribute) as? Int else {
        stop("FAIL: background toggle value unavailable")
    }
    if current != desired {
        press(toggle, "background toggle")
        if desired == 1 {
            wait("background consent unavailable") { control("Allow") != nil }
            press(control("Allow")!, "Allow")
        }
    }
    wait("background setting did not change") {
        guard let toggle = control("Check in the Background") else { return false }
        return attribute(toggle, kAXValueAttribute) as? Int == desired
    }
} else {
    let name = action == "stop" ? "Stop Helper" : "Start Helper"
    wait("helper lifecycle button unavailable") { control(name) != nil }
    press(control(name)!, name)
    let opposite = action == "stop" ? "Start Helper" : "Stop Helper"
    wait("helper registration did not change") { control(opposite) != nil }
}
if windows().contains(where: { element in
    (attribute(element, kAXValueAttribute) as? String ?? "").contains("Needs approval in System Settings")
}) { stop("BLOCKED: approve helper in guest Login Items before rerunning", 2) }
print("PASS: helper Settings action " + action)
