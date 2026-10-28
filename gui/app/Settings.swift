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
                Text(monitor.enabled ? model.backgroundState.text
                     : String(localized: "Checks your files whenever they change, even when the app is closed.",
                              comment: "Under the Scan Automatically switch while it is off, and under Automatic Scanning in Overview: what turning it on does."))
                // The count and its details are from the same completed pass.
                if let unread = monitor.health.unread, unread > 0 {
                    Text(monitor.health.unreadTruncated == true
                         ? String(localized: "At least \(unread) places could not be read.",
                                  comment: "The automatic scan saved only a bounded list of unread places; this is a lower bound.")
                         : String(localized: "\(unread) places could not be read.",
                                comment: "Overview and Settings, under the state of automatic scanning: how many places the helper's last full pass could not read."))
                }
            }
            .disabled(model.monitorFailure != nil || model.phase == .scanning || model.preparingAccess)
            if let unread = monitor.health.unread, unread > 0 {
                Button("Show Unread Places") { model.showUnreadPlaces() }
            }
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
                Label(EngineText.shown(error), systemImage: "exclamationmark.triangle").foregroundStyle(.red)
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
        case 0:
            return (String(localized: "Needs macOS 13 or later", comment: "Settings, beside Helper: the state of the helper (a singular noun)."), false)
        case 2:
            return monitor.health.running == false
                ? (String(localized: "Not running", comment: "Settings, beside Helper: the state of the helper (a singular noun). It is registered with macOS, but not running."), true)
                : nil
        case 3:
            return (String(localized: "Needs approval in System Settings > General > Login Items",
                           comment: "Settings, beside Helper: the state of the helper (a singular noun). Use the names macOS gives System Settings and its Login Items pane."), false)
        case 4:
            return (String(localized: "macOS could not start it", comment: "Settings, beside Helper: macOS refused to start the helper (a singular noun)."), true)
        default:
            return (String(localized: "Not started", comment: "Settings, beside Helper: the state of the helper (a singular noun). It is not registered with macOS."), true)
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
            Text(model.awaitingPermission
                 ? String(localized: "Waiting for your answer…", comment: "Settings, the state of notifications while macOS asks the person whether to allow them.")
                 : permissionText(permission))
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
        case "allowed":
            return String(localized: "notifications.allowed", defaultValue: "Allowed",
                          comment: "Settings, the state of notifications (a plural noun): macOS allows them.")
        case "denied":
            return String(localized: "Off in System Settings",
                          comment: "Settings, the state of notifications (a plural noun): turned off for this app in System Settings.")
        case "unavailable outside an app bundle":
            return String(localized: "Open the app from its bundle to allow",
                          comment: "Settings, the state of notifications: macOS allows them only to an app opened from its bundle.")
        case "request failed":
            return String(localized: "macOS could not ask. Try again.",
                          comment: "The state of notifications: macOS could not ask the person whether to allow them.")
        case "checking":
            return String(localized: "Checking…", comment: "Settings, the state of notifications while the app asks macOS whether they are allowed.")
        default:
            return String(localized: "Not asked yet", comment: "Settings, the state of notifications (a plural noun): the person has not been asked whether to allow them.")
        }
    }
}

/// Diagnostic timing is separate from the status and coverage warnings.
struct BackgroundCheckDetails: View {
    let health: HelperHealth

    var body: some View {
        LabeledContent("Last Recorded Check", value: health.lastScan.map { localTime($0) }
                       ?? String(localized: "No check recorded yet", comment: "Check details, beside Last Recorded Check: the helper has recorded no check."))
        LabeledContent("Last Completed Full Scan", value: health.fullPass.map { localTime($0) }
                       ?? String(localized: "Not completed yet", comment: "Check details, beside Last Completed Full Scan: no full scan by the helper has finished."))
        if let left = health.left, left > 0 {
            Text(String(localized: "At least \(left) folders left in the current full scan.",
                        comment: "Check details: how many folders the helper's current full scan has still to read, at the least."))
                .foregroundStyle(.secondary)
        }
    }
}
