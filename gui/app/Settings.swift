// Settings: background checks, their helper, notifications and the menu bar.
import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Form {
            if let monitor = model.monitor {
                checks(monitor)
                helper(monitor)
                notifications(monitor)
                menuBar(monitor)
            } else {
                Section {
                    Text("Background checks are not available.").foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .frame(width: 520)
        .fixedSize(horizontal: false, vertical: true)
        .confirmationDialog("Allow Background Checks?", isPresented: $model.askingConsent) {
            Button("Allow") { model.setMonitoring(enabled: true, paused: false) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("A helper checks your home folder as files change, starting at login.")
        }
    }

    @ViewBuilder private func checks(_ monitor: MonitorStatus) -> some View {
        Section {
            Toggle("Check in the Background", isOn: Binding(
                get: { monitor.enabled },
                set: { on in
                    if on { model.askingConsent = true } else { model.setMonitoring(enabled: false, paused: false) }
                }))
                .disabled(model.monitorFailure != nil || model.phase == .scanning || model.preparingAccess)
            if monitor.enabled {
                // Neither switch can be used during a scan, so that a setting
                // is never changed under one that is running.
                Toggle("Pause Checks", isOn: Binding(
                    get: { monitor.paused },
                    set: { model.setMonitoring(enabled: true, paused: $0) }))
                    .disabled(model.phase == .scanning)
            }
            if let error = monitor.error ?? monitor.health.error {
                Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.red)
            }
            LabeledContent {
                Button(model.settingsCheckDetails ? "Hide Check Details" : "Show Check Details") {
                    model.settingsCheckDetails.toggle()
                }
            } label: {
                Text("Status")
                Text(model.backgroundState)
                // The helper keeps the number and not the places: a scan lists them.
                if let unread = monitor.health.unread, unread > 0 {
                    Text("\(plural(unread, "place was", "places were")) not read during background checks. Run a scan to see what was not checked.")
                }
            }
            if model.settingsCheckDetails {
                BackgroundCheckDetails(health: monitor.health)
            }
        } header: {
            Text("Background Checks")
        }
    }

    @ViewBuilder private func helper(_ monitor: MonitorStatus) -> some View {
        Section {
            LabeledContent {
                if monitor.login == 2 || monitor.login == 3 {
                    Button("Stop Helper") { model.setHelper(running: false) }
                } else if monitor.login != 0, monitor.enabled {
                    Button("Start Helper") { model.setHelper(running: true) }
                }
            } label: {
                Text("Status")
                Text(helperText(monitor))
            }
        } header: {
            Text("Helper")
        } footer: {
            Text("macOS starts the helper at login and restarts it if it stops unexpectedly.")
        }
    }

    /// macOS reports a registered helper as enabled even when it will not start.
    private func helperText(_ monitor: MonitorStatus) -> String {
        switch monitor.login {
        case 0: return "Needs macOS 13 or later"
        case 2: return monitor.health.running == false ? "Registered, but not running" : "Running"
        case 3: return "Needs approval in System Settings > General > Login Items"
        case 4: return monitor.enabled ? "Could not be registered" : "Not started"
        default: return "Not started"
        }
    }

    @ViewBuilder private func notifications(_ monitor: MonitorStatus) -> some View {
        let permission = model.review?.permission ?? "checking"
        Section {
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
                Text("Status")
                Text(model.awaitingPermission ? "Waiting for your answer…" : permissionText(permission))
            }
            if monitor.enabled, monitor.pendingDelivery {
                LabeledContent {
                    if monitor.attempts >= 3 {
                        Button("Try Again") { model.retryNotifications() }
                    }
                } label: {
                    Text("Pending Notification")
                    Text("A finding is waiting to be notified. It is listed under Worth Reviewing.")
                }
            }
        } header: {
            Text("Notifications")
        } footer: {
            Text("A notification says only that something needs review. It never names a file or a credential.")
        }
    }

    @ViewBuilder private func menuBar(_ monitor: MonitorStatus) -> some View {
        Section {
            Toggle("Show in Menu Bar", isOn: Binding(
                get: { monitor.menuBar },
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
