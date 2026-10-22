// What the engine sends, as it sends it. Field names follow the engine's JSON
// (snake case there, camel case here).
import Foundation

struct ScanResults: Decodable {
    let status: String
    let toolVersion: String
    let generatedAt: String
    let review: Int
    let stored: Int
    let notChecked: Int
    let groups: [FindingGroup]
    let gaps: [Gap]
    let roots: [String]
    let excluded: [String]
    let limitations: String
}

/// One rule's findings from a scan, with the rule's advice.
struct FindingGroup: Decodable {
    let kind: String
    let severity: String
    let title: String
    let explanation: String
    let reason: String?
    let nextStep: String?
    let steps: [String]
    let link: String?
    let items: [FindingFile]
}

struct FindingFile: Decodable {
    /// How the engine names this file; the app never sends a path back.
    let index: Int
    let path: String
    let line: Int?
    let subject: String?
    let actionable: Bool
}

struct Gap: Decodable, Identifiable {
    let label: String
    let help: String
    let count: Int
    let paths: [String]
    let more: Int
    var id: String { label }
}

struct ReviewList: Decodable {
    let items: [ReviewItem]
    let counts: ReviewCounts?
    let skipped: [String]?
    /// Why the list could not be read or saved. It is then not what was found.
    let error: String?
    /// A finding was left out for lack of room, and no scan the person ran to
    /// its end has since found room on the list.
    let full: Bool?
    let permission: String?
}

struct ReviewCounts: Decodable {
    let open: Int
    let setAside: Int
    let kept: Int
    let fixed: Int
}

/// A finding worth reviewing, kept between scans with what the person decided.
struct ReviewItem: Decodable, Identifiable {
    let id: Int
    let rule: String
    let path: String
    let line: Int?
    let title: String
    let explanation: String
    let reason: String?
    let nextStep: String?
    let severity: String
    let steps: [String]?
    let link: String?
    let subject: String?
    let detail: String?
    let firstSeen: String?
    let resolvedAt: String?
    let resolved: Bool?
    /// Rises each time the item is new again; the newest is the one a notification is about.
    let revision: Int?
    /// "open", "set-aside" or "fixed".
    let state: String?
    let setAside: String?
    let places: [ReviewPlace]?
    let folder: String?
    /// Whether the app will act on this file. It acts only on plain names.
    let actionable: Bool?
}

struct ReviewPlace: Decodable, Identifiable {
    let id: Int
    let path: String
    let line: Int?
    let fixed: Bool
    /// Still there, and set aside by a decision that covers this place.
    let setAside: Bool?
}

struct MonitorStatus: Decodable {
    let enabled: Bool
    let paused: Bool
    let scanning: Bool
    /// The helper's registration with macOS: 0 unavailable, 1 not registered,
    /// 2 registered, 3 needs approval, 4 failed.
    let login: Int
    let health: HelperHealth
    let error: String?
    let pendingDelivery: Bool
    let attempts: Int
    let results: ScanResults?
}

struct HelperHealth: Decodable {
    let running: Bool?
    let lastScan: String?
    let coverage: String?
    let fullPass: String?
    let left: Int?
    /// Places the helper's last full pass did not read.
    let unread: Int?
    let changes: Int?
    let error: String?
}

struct ScanPlaces: Decodable {
    let home: String?
    let homeError: String?
    let extra: [String]
    let error: String?
}

struct ScanProgress: Decodable {
    let phase: String
    let entries: Int
    let findings: Int
    let notChecked: Int
}

/// Why a person sets an item aside, and what brings it back.
struct SetAsideReason: Identifiable {
    let id: String
    let label: String
    let summary: String
    let returns: String

    static let all = [
        SetAsideReason(id: "not-a-credential", label: "Not a Password or Key",
                       summary: "Not a password or key",
                       returns: "Applies to all copies of the flagged text. If that text changes and is flagged again, it will appear in Worth Reviewing."),
        SetAsideReason(id: "testing", label: "Used Only for Testing",
                       summary: "Used only for testing",
                       returns: "Applies to all copies of this password or key. If it is replaced, the new one will appear in Worth Reviewing."),
        SetAsideReason(id: "no-longer-works", label: "No Longer Works",
                       summary: "No longer works",
                       returns: "Applies to all copies of this password or key. If it is replaced, the new one will appear in Worth Reviewing."),
        SetAsideReason(id: "kept", label: "Keeping It Here Intentionally",
                       summary: "Keeping it here intentionally",
                       returns: "Applies only to this location. Returns to review if the file becomes readable by others, a different kind of credential appears here, or after six months."),
    ]

    // Older decisions did not distinguish these reasons. Display that choice
    // without offering it again or guessing which reason the person meant.
    static let legacy = SetAsideReason(
        id: "test-or-revoked", label: "Testing or No Longer Working (Previous Choice)",
        summary: "Testing or no longer working (previous choice)",
        returns: "Applies to all copies of this password or key. If it is replaced, the new one will appear in Worth Reviewing.")

}

extension ReviewItem {
    var status: String { state ?? (resolved == true ? "fixed" : "open") }

    var statusText: String {
        switch status {
        case "fixed": return "Fixed"
        case "set-aside": return "Set Aside"
        default: return "Open"
        }
    }

    /// The list's first order: open, then set aside, then fixed.
    var statusRank: Int {
        switch status {
        case "set-aside": return 2
        case "fixed": return 3
        default: return 0
        }
    }

    /// What the Risk heading sorts by: a higher number is a higher risk.
    var riskLevel: Int {
        switch severity {
        case "medium": return 1
        case "low": return 0
        default: return 2
        }
    }

    /// Open first, then by risk, so what needs attention is at the top.
    var order: Int {
        statusRank * 10 + (2 - riskLevel)
    }
}

/// Rows in the order the clicked headings ask for. `tie` settles rows they rank the same.
func arranged<Row>(_ rows: [Row], by headings: [KeyPathComparator<Row>], tie: (Row, Row) -> Bool) -> [Row] {
    rows.sorted { first, second in
        for heading in headings {
            let result = heading.compare(first, second)
            if result != .orderedSame { return result == .orderedAscending }
        }
        return tie(first, second)
    }
}

func riskText(_ severity: String) -> String {
    ["high": "High", "medium": "Medium", "low": "Low"][severity] ?? severity.capitalized
}

/// The engine's UTC timestamp, in the person's own format.
func localTime(_ timestamp: String?) -> String {
    guard let timestamp, let date = ISO8601DateFormatter().date(from: timestamp) else { return timestamp ?? "" }
    return date.formatted(date: .abbreviated, time: .shortened)
}

func plural(_ count: Int, _ one: String, _ many: String) -> String {
    "\(count) \(count == 1 ? one : many)"
}
