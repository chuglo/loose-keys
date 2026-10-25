// Settings: automatic scanning, its helper, notifications and the menu bar.
import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Form {
            if let monitor = model.monitor {
                scanning(monitor)
                menuBar(monitor)
            } else {
                Section {
                    Text("Automatic scanning is not available.").foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .frame(width: 520)
        .fixedSize(horizontal: false, vertical: true)
        .confirmationDialog("Allow Automatic Scanning?", isPresented: $model.askingConsent) {
            Button("Allow") { model.setMonitoring(enabled: true, paused: false) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Loose Keys will check your files whenever they change, even when the app is closed.")
        }
    }

    /// The switch with its state beneath it. The rest shows only while the
    /// switch is on: the helper when it needs something done, Pause, and
    /// notifications, which only the helper sends. Check timing is on the
    /// Overview.
    @ViewBuilder private func scanning(_ monitor: MonitorStatus) -> some View {
        Section {
            Toggle(isOn: Binding(
                get: { monitor.enabled },
                set: { on in
                    if on { model.askingConsent = true } else { model.setMonitoring(enabled: false, paused: false) }
                })) {
                Text("Scan Automatically")
                Text(monitor.enabled ? model.backgroundState : "Checks your files whenever they change, even when the app is closed.")
                // The helper keeps the number and not the places: a scan lists them.
                if let unread = monitor.health.unread, unread > 0 {
                    Text("\(plural(unread, "place", "places")) could not be read. Run a scan to see which.")
                }
            }
            .disabled(model.monitorFailure != nil || model.phase == .scanning || model.preparingAccess)
            if monitor.enabled, let helper = helperProblem(monitor) {
                LabeledContent {
                    if helper.restarts {
                        Button("Restart Helper") { model.restartHelper() }
                    }
                } label: {
                    Text("Helper")
                    Text(helper.text)
                }
            }
            if let error = monitor.error ?? monitor.health.error {
                Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.red)
            }
            if monitor.enabled {
                // Neither switch can be used during a scan, so that a setting
                // is never changed under one that is running.
                Toggle("Pause Scanning", isOn: Binding(
                    get: { monitor.paused },
                    set: { model.setMonitoring(enabled: true, paused: $0) }))
                    .disabled(model.phase == .scanning)
                notifications(monitor)
            }
        } footer: {
            if monitor.enabled {
                Text("Notifications never show file names or credentials.")
            }
        }
    }

    /// What the helper needs, if it is not simply running. macOS reports a
    /// registered helper as enabled even when it will not start.
    private func helperProblem(_ monitor: MonitorStatus) -> (text: String, restarts: Bool)? {
        switch monitor.login {
        case 0: return ("Needs macOS 13 or later", false)
        case 2: return monitor.health.running == false ? ("Not running", true) : nil
        case 3: return ("Needs approval in System Settings > General > Login Items", false)
        case 4: return ("macOS could not start it", true)
        default: return ("Not started", true)
        }
    }

    @ViewBuilder private func notifications(_ monitor: MonitorStatus) -> some View {
        let permission = model.review?.permission ?? "checking"
        LabeledContent {
            // Once macOS has an answer it no longer asks: the switch is in
            // System Settings, either way.
            if model.canAskForNotifications {
                Button("Allow Notifications…") { model.enableNotifications() }
                    .disabled(model.awaitingPermission)
            } else if permission == "denied" || permission == "allowed" {
                Button("Open System Settings") { model.openNotificationSettings() }
            }
        } label: {
            Text("Notifications")
            Text(model.awaitingPermission ? "Waiting for your answer…" : permissionText(permission))
        }
        if monitor.pendingDelivery {
            LabeledContent {
                if monitor.attempts >= 3 {
                    Button("Try Again") { model.retryNotifications() }
                }
            } label: {
                Text("Pending Notification")
                Text("Not sent yet. The finding is in Worth Reviewing.")
            }
        }
    }

    @ViewBuilder private func menuBar(_ monitor: MonitorStatus) -> some View {
        Section {
            // What was last saved, which the next status read only confirms.
            Toggle("Show in Menu Bar", isOn: Binding(
                get: { model.menuBarOn },
                set: { model.setMenuBar($0) }))
                .disabled(model.monitorFailure != nil)
            if monitor.enabled, monitor.menuBar {
                if monitor.appLogin == 3 {
                    Text("Allow Loose Keys in Login Items to show it at login.").foregroundStyle(.secondary)
                } else if monitor.appLogin == 1 || monitor.appLogin == 4 {
                    Text("Not in Login Items: shown only while the app is open.").foregroundStyle(.secondary)
                }
            }
        }
    }

    private func permissionText(_ permission: String) -> String {
        switch permission {
        case "allowed": return "Allowed"
        case "denied": return "Off in System Settings"
        case "unavailable outside an app bundle": return "Open the app from its bundle to allow"
        case "request failed": return "macOS could not ask. Try again."
        case "checking": return "Checking…"
        default: return "Not asked yet"
        }
    }
}

/// Diagnostic timing is separate from the status and coverage warnings.
struct BackgroundCheckDetails: View {
    let health: HelperHealth

    var body: some View {
        LabeledContent("Last Recorded Check", value: health.lastScan.map { localTime($0) } ?? "No check recorded yet")
        LabeledContent("Last Completed Full Scan", value: health.fullPass.map { localTime($0) } ?? "Not completed yet")
        if let left = health.left, left > 0 {
            Text("At least \(plural(left, "folder", "folders")) left in the current full scan.")
                .foregroundStyle(.secondary)
        }
    }
}
