// What an alert says when an action fails: what failed, then why.
import Foundation

/// The alert's title names the action that failed; its message is the reason.
struct Failure: Equatable {
    let title: String
    let reason: String
}

/// The titles of those alerts, one for each action.
enum FailureTitle {
    static var scan: String {
        String(localized: "Couldn't Scan", comment: "The title of an alert: a scan could not start or finish.")
    }
    static var stopScan: String {
        String(localized: "Couldn't Stop the Scan", comment: "The title of an alert: Stop Scan failed.")
    }
    static var showFindings: String {
        String(localized: "Couldn't Show the Findings", comment: "The title of an alert: a scan finished, but its findings could not be listed.")
    }
    static var openReview: String {
        String(localized: "Couldn't Open Worth Reviewing", comment: "The title of an alert: the list of findings could not be read. Worth Reviewing is the list's name in the sidebar.")
    }
    static var saveChoice: String {
        String(localized: "Couldn't Save Your Choice", comment: "The title of an alert: Set Aside or Move to Worth Reviewing failed.")
    }
    static var readPlaces: String {
        String(localized: "Couldn't Read the Places to Check", comment: "The title of an alert: the folders scans include could not be read. Places to Check is a heading in Settings.")
    }
    static var addFolder: String {
        String(localized: "Couldn't Add the Folder", comment: "The title of an alert: Add Folder or Drive… or a drop on Settings failed.")
    }
    static var removeFolder: String {
        String(localized: "Couldn't Remove the Folder", comment: "The title of an alert: Remove beside a folder in Settings failed.")
    }
    static var skipFolder: String {
        String(localized: "Couldn't Stop Checking the Folder", comment: "The title of an alert: Stop Checking a folder failed.")
    }
    static var includeFolder: String {
        String(localized: "Couldn't Include the Folder Again", comment: "The title of an alert: Include Again beside a skipped folder failed.")
    }
    static var showInFinder: String {
        String(localized: "Couldn't Show the File in Finder", comment: "The title of an alert: Show in Finder failed.")
    }
    static var copyPath: String {
        String(localized: "Couldn't Copy the Path", comment: "The title of an alert: Copy Path failed.")
    }
    static var openPage: String {
        String(localized: "Couldn't Open the Page", comment: "The title of an alert: a button that opens a vendor's web page failed.")
    }
    static var saveReport: String {
        String(localized: "Couldn't Save the Report", comment: "The title of an alert: Save Report… or Save Counts Only… failed.")
    }
    static var copySummary: String {
        String(localized: "Couldn't Copy the Summary", comment: "The title of an alert: Copy Summary failed.")
    }
    static var automaticScanning: String {
        String(localized: "Couldn't Change Automatic Scanning", comment: "The title of an alert: turning Scan Automatically or Pause Scanning on or off failed.")
    }
    static var restartHelper: String {
        String(localized: "Couldn't Restart the Helper", comment: "The title of an alert: Restart Helper failed.")
    }
    static var menuBar: String {
        String(localized: "Couldn't Change Show in Menu Bar", comment: "The title of an alert: turning Show in Menu Bar on or off failed. Show in Menu Bar is the switch's name in Settings.")
    }
    static var updateChecks: String {
        String(localized: "Couldn't Change Update Checks", comment: "The title of an alert: turning Check for Updates Automatically on or off failed.")
    }
    static var askNotifications: String {
        String(localized: "Couldn't Ask About Notifications", comment: "The title of an alert: Allow Notifications… could not show macOS's request.")
    }
    static var sendNotification: String {
        String(localized: "Couldn't Send the Notification", comment: "The title of an alert: Try Again beside a pending notification failed.")
    }
}
