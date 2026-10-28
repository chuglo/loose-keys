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
    /// Show in Menu Bar, and the app itself in Login Items, with the same
    /// codes as `login`.
    let menuBar: Bool
    let appLogin: Int
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
    let unreadTruncated: Bool?
    let changes: Int?
    let error: String?
}

struct AutomaticCoverage: Decodable {
    let fullPass: String?
    let unread: Int
    let unreadGaps: [Gap]?
    let unreadTruncated: Bool
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

/// What the engine and scanner say, in the window's language. The engine and
/// the saved review list keep English; the window looks each string up in
/// Engine.strings for the localization the app runs in. A string the table
/// does not have is shown as it came.
///
/// A key with one placeholder is a template: %@ stands for any text, %lld for
/// digits. What the placeholder stands for is never used as a format: `about`
/// puts it in as it came, and `shown` looks it up first.
enum EngineText {
    private struct Template {
        let before: [UInt8]
        let after: [UInt8]
        /// The placeholder is %lld, which stands for digits only.
        let digits: Bool
        let shownBefore: String
        let shownAfter: String
    }

    /// One localization's Engine.strings, ready to look strings up in.
    struct Table {
        private var exact: [String: String] = [:]
        /// The longest fixed text first, so that the most particular key is the one used.
        private var templates: [Template] = []

        /// No table: every string is shown as it came.
        init() {}

        /// The entries of an Engine.strings. A key with more than one
        /// placeholder, or whose translation does not have that placeholder
        /// exactly once, is left out.
        init(_ entries: [String: Any]) {
            var keyed: [(key: String, template: Template)] = []
            for case let (key, value as String) in entries {
                let placeholders = [("%@", false), ("%lld", true)].filter { key.contains($0.0) }
                guard let (placeholder, digits) = placeholders.first else {
                    exact[key] = value
                    continue
                }
                // One placeholder, in the key and in its translation, and some fixed text beside it.
                let parts = key.components(separatedBy: placeholder)
                let shown = value.components(separatedBy: placeholder)
                guard placeholders.count == 1, parts.count == 2, shown.count == 2, !(parts[0] + parts[1]).isEmpty else { continue }
                keyed.append((key, Template(before: Array(parts[0].utf8), after: Array(parts[1].utf8), digits: digits,
                                            shownBefore: shown[0], shownAfter: shown[1])))
            }
            templates = keyed.sorted { first, second in
                let lengths = (first.template.before.count + first.template.after.count,
                               second.template.before.count + second.template.after.count)
                return lengths.0 != lengths.1 ? lengths.0 > lengths.1 : first.key < second.key
            }.map(\.template)
        }

        /// The Engine.strings of the first of these localizations whose table
        /// can be read, or none once English comes: the engine's text is
        /// English already.
        static func load(from bundle: Bundle, languages: [String]) -> Table {
            for language in languages {
                if language == "en" || language.hasPrefix("en-") || language.hasPrefix("en_") { return Table() }
                guard let url = bundle.url(forResource: "Engine", withExtension: "strings", subdirectory: nil, localization: language),
                      let entries = NSDictionary(contentsOf: url) as? [String: Any] else { continue }
                return Table(entries)
            }
            return Table()
        }

        /// The template the text fits, and the text in its placeholder's place:
        /// not empty, and never part of the fixed text before or after it.
        private func fit(_ text: String) -> (template: Template, middle: String)? {
            guard !templates.isEmpty else { return nil }
            let bytes = Array(text.utf8)
            for template in templates {
                guard bytes.count > template.before.count + template.after.count,
                      bytes.starts(with: template.before), bytes.suffix(template.after.count).elementsEqual(template.after) else { continue }
                let middle = bytes[template.before.count..<(bytes.count - template.after.count)]
                if template.digits, !middle.allSatisfy({ (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) }) { continue }
                return (template, String(decoding: middle, as: UTF8.self))
            }
            return nil
        }

        /// As `EngineText.shown`, in this table.
        func shown(_ english: String) -> String {
            // The engine nests its text at most two deep inside its own, as in
            // "Could not save: export directory: permission-denied.".
            shown(english, levels: 2)
        }

        private func shown(_ english: String, levels: Int) -> String {
            if let exact = exact[english] { return exact }
            guard let (template, middle) = fit(english) else { return english }
            let put = levels > 0 && !template.digits ? shown(middle, levels: levels - 1) : middle
            return template.shownBefore + put + template.shownAfter
        }

        /// As `EngineText.about`, in this table.
        func about(_ english: String) -> String {
            if let exact = exact[english] { return exact }
            guard let (template, middle) = fit(english) else { return english }
            return template.shownBefore + middle + template.shownAfter
        }
    }

    /// The table for the localization the app runs in, read from its bundle
    /// the first time engine text is shown. Only the model check
    /// (gui/tests/refresh-order.swift) puts another in its place.
    static var table = Table.load(from: Bundle.main, languages: Bundle.main.preferredLocalizations)

    /// Prose and error text: a rule's title, explanation and steps, a gap's
    /// label and help, an engine error. Text in a %@ is engine text as well,
    /// such as the reason a folder could not be added, and is looked up in
    /// turn, two levels deep.
    static func shown(_ english: String) -> String {
        table.shown(english)
    }

    /// What a finding is about: a subject or a detail. The text in a
    /// placeholder's place, such as a profile's name, can come from a file,
    /// so it is kept exactly as it came.
    static func about(_ english: String) -> String {
        table.about(english)
    }
}

/// Why a person sets an item aside, and what brings it back.
struct SetAsideReason: Identifiable {
    let id: String
    /// The menu item.
    let label: String
    /// The reason on its own, as the inspector's Set Aside section shows it.
    let summary: String
    let returns: String

    static let all = [
        SetAsideReason(id: "not-a-credential",
                       label: String(localized: "Not a Password or Key",
                                     comment: "Menu item under Set Aside…: why the person sets the finding aside. What was found is not a password or key."),
                       summary: String(localized: "Not a password or key",
                                       comment: "Inspector, Set Aside section: the reason the person gave for setting the finding aside."),
                       returns: String(localized: "Applies to all copies of the flagged text. If that text changes and is flagged again, it will appear in Worth Reviewing.",
                                       comment: "Inspector details for a finding set aside as not a password or key: what the choice covers and when the finding comes back.")),
        SetAsideReason(id: "testing",
                       label: String(localized: "Used Only for Testing",
                                     comment: "Menu item under Set Aside…: why the person sets the finding aside. The password or key found is only used for testing."),
                       summary: String(localized: "Used only for testing",
                                       comment: "Inspector, Set Aside section: the reason the person gave for setting the finding aside (the password or key)."),
                       returns: String(localized: "Applies to all copies of this password or key. If it is replaced, the new one will appear in Worth Reviewing.",
                                       comment: "Inspector details for a finding set aside as a test credential, or as one that no longer works: what the choice covers and when it comes back.")),
        SetAsideReason(id: "no-longer-works",
                       label: String(localized: "No Longer Works",
                                     comment: "Menu item under Set Aside…: why the person sets the finding aside. The password or key found no longer works."),
                       summary: String(localized: "No longer works",
                                       comment: "Inspector, Set Aside section: the reason the person gave for setting the finding aside (the password or key)."),
                       returns: String(localized: "Applies to all copies of this password or key. If it is replaced, the new one will appear in Worth Reviewing.",
                                       comment: "Inspector details for a finding set aside as a test credential, or as one that no longer works: what the choice covers and when it comes back.")),
        SetAsideReason(id: "kept",
                       label: String(localized: "Keeping It Here Intentionally",
                                     comment: "Menu item under Set Aside…: why the person sets the finding aside. The credential is real and stays in this file on purpose."),
                       summary: String(localized: "Keeping it here intentionally",
                                       comment: "Inspector, Set Aside section: the reason the person gave for setting the finding aside (the person keeps the credential here)."),
                       returns: String(localized: "Applies only to this location. Returns to review if the file becomes readable by others, a different kind of credential appears here, or after six months.",
                                       comment: "Inspector details for a credential the person keeps here on purpose: what the choice covers and when it comes back.")),
    ]

    // Older decisions did not distinguish these reasons. Display that choice
    // without offering it again or guessing which reason the person meant.
    static let legacy = SetAsideReason(
        id: "test-or-revoked",
        label: String(localized: "Testing or No Longer Working (Previous Choice)",
                      comment: "The reason an older version of the app recorded for a set-aside finding: a test credential, or one that no longer works."),
        summary: String(localized: "Testing or no longer working (previous choice)",
                        comment: "Inspector, Set Aside section: the reason an older version of the app recorded for setting the finding aside."),
        returns: String(localized: "Applies to all copies of this password or key. If it is replaced, the new one will appear in Worth Reviewing.",
                        comment: "Inspector details for a finding set aside as a test credential, or as one that no longer works: what the choice covers and when it comes back."))

}

extension ReviewItem {
    var status: String { state ?? (resolved == true ? "fixed" : "open") }

    var statusText: String {
        switch status {
        case "fixed":
            return String(localized: "status.fixed", defaultValue: "Fixed",
                          comment: "A finding's status: the file was checked again and no longer has it.")
        case "set-aside":
            return String(localized: "status.set-aside", defaultValue: "Set Aside",
                          comment: "A finding's status: the person set it aside.")
        default:
            return String(localized: "status.open", defaultValue: "Open",
                          comment: "A finding's status: it still needs a decision.")
        }
    }

    /// The title as the window shows it, which the Finding heading sorts by.
    var shownTitle: String { EngineText.shown(title) }

    /// What it concerns, or failing that a count the rule gives, as for a
    /// browser's saved logins, as the window shows it.
    var shownAbout: String? { (subject ?? detail).map(EngineText.about) }

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
    switch severity {
    case "high": return String(localized: "High", comment: "A finding's risk, beside its coloured mark in the Risk column and the inspector.")
    case "medium": return String(localized: "Medium", comment: "A finding's risk, beside its coloured mark in the Risk column and the inspector.")
    case "low": return String(localized: "Low", comment: "A finding's risk, beside its coloured mark in the Risk column and the inspector.")
    default: return severity.capitalized
    }
}

/// The engine's UTC timestamp, in the person's own format.
func localTime(_ timestamp: String?) -> String {
    guard let timestamp, let date = ISO8601DateFormatter().date(from: timestamp) else { return timestamp ?? "" }
    return date.formatted(date: .abbreviated, time: .shortened)
}
