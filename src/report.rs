//! Report format v1 (schema/report-1.schema.json) and the plain-text summary.

use serde::Serialize;

#[derive(Serialize, Default)]
pub struct Finding {
    /// Private keyed material digest. Never included in exports.
    #[serde(skip)]
    pub fingerprint: Option<String>,
    pub rule: &'static str,
    pub category: &'static str,
    pub kind: &'static str,
    /// "high", "medium" or "low": how usable the material is if copied.
    pub severity: &'static str,
    pub title: &'static str,
    pub explanation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<&'static str>,
    /// Ordered steps that remove the exposure.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub steps: &'static [&'static str],
    /// Where the issuer revokes or replaces the credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<&'static str>,
    /// The kind of service token, from the scanner's fixed list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<&'static str>,
    /// A count or similar that may change without this being a new finding.
    /// Local only, like `subject`.
    #[serde(skip)]
    pub detail: Option<String>,
    /// Private keyed digest of the secret value alone, the same wherever that
    /// value is stored. Never included in exports.
    #[serde(skip)]
    pub secret: Option<String>,
    /// Whether group/other read mode bits are set on the file.
    #[serde(skip)]
    pub shared: bool,
    /// Where the volume holding the file is mounted, as `fsutil::mounted_at`
    /// counts it, for telling later whether a file that is gone was removed
    /// or went with its drive. Never included in exports.
    #[serde(skip)]
    pub mount: Option<u32>,
    /// What the finding concerns (profile, host, variable or token type), never
    /// a value. Shown on this Mac only: exports leave out account and host names.
    #[serde(skip)]
    pub subject: Option<String>,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

#[derive(Serialize)]
pub struct NotChecked {
    pub path: String,
    pub reason: &'static str,
}

#[derive(Serialize)]
pub struct Coverage {
    pub roots: Vec<String>,
    pub excluded_directories: &'static [&'static str],
    /// Folders the person asked not to be checked. Always listed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub excluded_by_user: Vec<String>,
    pub limitations: &'static str,
}

pub const LIMITATIONS: &str = "Discovery reads the first 4 KiB of regular files regardless of extension for CSV password-export headers, private-key headers, plaintext Bitwarden JSON exports, KeePass databases, Google service-account keys, kubeconfigs, wallet recovery phrases and service tokens in a known issuer format. Later tokens are found only in files read whole (1 MiB max): .env*, *.env, shell files, .git/config, MCP configs, .txt/.rtf notes, .ovpn profiles. Terraform state: named or sensitive values only. AI agent folders (Claude Code, Codex, others) are read in full for tokens, 16 levels deep, up to 256 MiB and 50 tokens per file. Other token formats and secrets with no format are not found. Known locations (see --list-rules) include ~/.ssh, ~/.aws/credentials, ~/.git-credentials, ~/.config/gh/hosts.yml, ~/.npmrc and other developer, cloud and AI tool files; saved-login and saved-card counts in Chromium- and Firefox-family profiles; and the presence of listed wallet extensions, desktop wallet folders and Telegram Desktop's session, reported without being read. Parsers read simple literal fields only, not full YAML/INI, custom locations, references or credential helpers; malformed or oversized candidates produce gaps. Not checked: browser cookies and sessions, Safari, Notes and Keychain items, images, password-manager vaults. No archives or decryption. Links met in discovery, special files, container metadata and Contacts settings are skipped; a link at a known location is followed only inside the home; cloud-only files are not downloaded. Exclusions match path suffixes; a selected root overrides its own. Limits: 64 levels, 10000 entries per directory, 100000 per root, breadth-first, Library, Movies, Music and Pictures last; omitted entries or matches produce gaps. Headers, formats, presence and mode bits do not prove valid credentials or effective access. Nothing is executed or verified online. Deleting files does not revoke credentials. No findings is not a clean bill of health.";

#[derive(Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub tool_version: &'static str,
    pub generated_at: String,
    pub status: &'static str,
    pub context: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<Coverage>,
    pub findings: Vec<Finding>,
    pub not_checked: Vec<NotChecked>,
}

/// Only fixed scanner identifiers and counts cross this sharing boundary.
pub fn to_feedback_json(report: &Report) -> String {
    counts_json(report, None)
}

/// The same counts for a device-management run, with the name the caller
/// gave for this Mac and the time of the scan. Neither is added otherwise.
pub fn to_device_counts_json(report: &Report, device_id: &str) -> String {
    counts_json(report, Some(device_id))
}

fn counts_json(report: &Report, device_id: Option<&str>) -> String {
    use std::collections::BTreeMap;
    /// One risk level's findings worth reviewing. Open is all of them for
    /// now: this command keeps no record of what anyone has set aside.
    #[derive(Default, Serialize)]
    struct Level<'a> {
        open: usize,
        open_by_rule: BTreeMap<&'a str, usize>,
    }
    #[derive(Default, Serialize)]
    struct Review<'a> {
        high: Level<'a>,
        medium: Level<'a>,
        low: Level<'a>,
    }
    #[derive(Serialize)]
    struct Counts<'a> {
        schema: &'static str,
        tool_version: &'a str,
        platform: &'static str,
        architecture: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        device_id: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        generated_at: Option<&'a str>,
        status: &'a str,
        context: &'a str,
        requested_roots: usize,
        /// Folders left unread at the person's request. How many, not which.
        excluded_by_user: usize,
        findings_by_rule: BTreeMap<&'a str, usize>,
        findings_by_severity: BTreeMap<&'a str, usize>,
        findings_by_token_type: BTreeMap<&'a str, usize>,
        /// What `--fail-on-open` counts: stored sign-in material is left out.
        review: Review<'a>,
        not_checked_by_reason: BTreeMap<&'a str, usize>,
    }
    let mut counts = Counts {
        schema: match device_id {
            Some(_) => "loose-keys/device-counts/1",
            None => "loose-keys/feedback/1",
        },
        tool_version: report.tool_version,
        platform: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        device_id,
        generated_at: device_id.map(|_| report.generated_at.as_str()),
        status: report.status,
        context: report.context,
        requested_roots: report.coverage.as_ref().map_or(0, |c| c.roots.len()),
        excluded_by_user: (report.coverage.as_ref()).map_or(0, |c| c.excluded_by_user.len()),
        findings_by_rule: Default::default(),
        findings_by_severity: Default::default(),
        findings_by_token_type: Default::default(),
        review: Default::default(),
        not_checked_by_reason: Default::default(),
    };
    for finding in &report.findings {
        *counts.findings_by_rule.entry(finding.rule).or_default() += 1;
        *counts
            .findings_by_severity
            .entry(finding.severity)
            .or_default() += 1;
        if let Some(token_type) = finding.token_type {
            *counts.findings_by_token_type.entry(token_type).or_default() += 1;
        }
        if finding.kind == "review" {
            let level = match finding.severity {
                "high" => &mut counts.review.high,
                "medium" => &mut counts.review.medium,
                _ => &mut counts.review.low,
            };
            level.open += 1;
            *level.open_by_rule.entry(finding.rule).or_default() += 1;
        }
    }
    for gap in &report.not_checked {
        *counts.not_checked_by_reason.entry(gap.reason).or_default() += 1;
    }
    serde_json::to_string_pretty(&counts).expect("counts serialize")
}

/// JSON with every non-ASCII character \u-escaped, so hostile filenames
/// (bidi overrides, escape sequences) can never reach a reader raw. The
/// serializer escapes the control characters below a space; DEL is left to us.
pub fn to_ascii_json(report: &Report) -> String {
    let json = serde_json::to_string_pretty(report).expect("report serializes");
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if c.is_ascii() && c != '\x7f' {
            out.push(c);
        } else {
            let mut buf = [0u16; 2];
            for unit in c.encode_utf16(&mut buf) {
                out.push_str(&format!("\\u{:04x}", unit));
            }
        }
    }
    out
}

/// Render a path for a terminal: printable ASCII as-is, everything else escaped.
pub fn escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            ' '..='~' => out.push(c),
            _ => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
        }
    }
    out
}

const WIDTH: usize = 78;
/// Gap paths shown per reason; the JSON export always has the full list.
const GAPS_SHOWN: usize = 5;

/// Word-wrap fixed scanner text. Never use for paths: they must stay whole.
fn wrap(out: &mut String, first: &str, rest: &str, text: &str) {
    let mut col = 0;
    let mut indent = first;
    for word in text.split_whitespace() {
        if col > indent.len() && col + 1 + word.len() > WIDTH {
            out.push('\n');
            col = 0;
            indent = rest;
        }
        if col == 0 {
            out.push_str(indent);
            col = indent.len();
        } else {
            out.push(' ');
            col += 1;
        }
        out.push_str(word);
        col += word.len();
    }
    if col > 0 {
        out.push('\n');
    }
}

fn gap_label(reason: &str) -> &str {
    match reason {
        "permission-denied" => "Access denied by macOS",
        "unreadable" => "Could not be read",
        "too-large" => "Too large to check",
        "cloud-only-file" => "Cloud-only, not downloaded",
        "scan-limit" => "Scan limit reached",
        "symlink" => "Link leading outside the home folder, not followed",
        other => other,
    }
}

/// Findings of one kind, grouped by rule, reason and advice so each shows once.
pub fn group_findings<'a>(r: &'a Report, kind: &str) -> Vec<Vec<&'a Finding>> {
    let mut groups: Vec<Vec<&Finding>> = Vec::new();
    for f in r.findings.iter().filter(|f| f.kind == kind) {
        match groups
            .iter_mut()
            .find(|g| g[0].rule == f.rule && g[0].reason == f.reason && g[0].link == f.link)
        {
            Some(g) => g.push(f),
            None => groups.push(vec![f]),
        }
    }
    groups
}

/// Gap paths grouped by reason, in first-seen order.
pub fn group_gaps(r: &Report) -> Vec<(&'static str, Vec<&str>)> {
    let mut groups: Vec<(&'static str, Vec<&str>)> = Vec::new();
    for n in &r.not_checked {
        match groups.iter_mut().find(|g| g.0 == n.reason) {
            Some(g) => g.1.push(&n.path),
            None => groups.push((n.reason, vec![&n.path])),
        }
    }
    groups
}

/// One numbered entry per rule: its paths, then its advice once.
fn push_findings(s: &mut String, r: &Report, kind: &str, label: &str) {
    // Token types of one rule differ only in where they are revoked, so they
    // share an entry here and each gets its own "Where" line.
    let mut groups: Vec<Vec<&Finding>> = Vec::new();
    for group in group_findings(r, kind) {
        match groups
            .iter_mut()
            .find(|g| g[0].rule == group[0].rule && g[0].reason == group[0].reason)
        {
            Some(g) => g.extend(group),
            None => groups.push(group),
        }
    }
    if groups.is_empty() {
        return;
    }
    let total: usize = groups.iter().map(Vec::len).sum();
    s.push_str(&format!("\n{} ({})\n", label, total));
    for (i, group) in groups.iter().enumerate() {
        let f = group[0];
        s.push_str(&format!(
            "\n{}. [{}] {}\n",
            i + 1,
            f.severity.to_ascii_uppercase(),
            f.title
        ));
        for g in group {
            let line = g.line.map(|l| format!(" line {}", l)).unwrap_or_default();
            let subject = [&g.subject, &g.detail]
                .into_iter()
                .flatten()
                .map(|s| format!(" ({})", escape(s)))
                .collect::<String>();
            s.push_str(&format!("   \"{}\"{}{}\n", escape(&g.path), line, subject));
        }
        wrap(s, "   ", "   ", f.explanation);
        if let Some(reason) = &f.reason {
            wrap(s, "   Why: ", "        ", reason);
        }
        if let Some(next) = f.next_step {
            wrap(s, "   Next: ", "         ", next);
        }
        for (n, step) in f.steps.iter().enumerate() {
            wrap(s, &format!("     {}. ", n + 1), "        ", step);
        }
        let mut links: Vec<(&str, Vec<&str>)> = Vec::new();
        for g in group {
            let Some(link) = g.link else { continue };
            let types = match links.iter().position(|l| l.0 == link) {
                Some(at) => &mut links[at].1,
                None => {
                    links.push((link, Vec::new()));
                    &mut links.last_mut().unwrap().1
                }
            };
            if let Some(t) = g.token_type.filter(|t| !types.contains(t)) {
                types.push(t);
            }
        }
        let several = links.len() > 1;
        for (link, types) in links {
            if several && !types.is_empty() {
                s.push_str(&format!("   Where: {link} ({})\n", types.join(", ")));
            } else {
                s.push_str(&format!("   Where: {link}\n"));
            }
        }
    }
}

/// Gaps grouped by reason, with a few paths each.
fn push_gaps(s: &mut String, r: &Report) {
    if r.not_checked.is_empty() {
        return;
    }
    s.push_str(&format!("\nNOT CHECKED ({})\n", r.not_checked.len()));
    for (reason, paths) in group_gaps(r) {
        s.push_str(&format!("\n{} ({})\n", gap_label(reason), paths.len()));
        for p in paths.iter().take(GAPS_SHOWN) {
            s.push_str(&format!("   \"{}\"\n", escape(p)));
        }
        if paths.len() > GAPS_SHOWN {
            s.push_str(&format!(
                "   ...and {} more (--export has the full list)\n",
                paths.len() - GAPS_SHOWN
            ));
        }
    }
}

pub fn to_text(r: &Report, limits: bool) -> String {
    let review = r.findings.iter().filter(|f| f.kind == "review").count();
    let mut s = format!(
        "loose-keys {} - scan {}\n{} worth reviewing, {} stored sign-in material, {} not checked\n",
        r.tool_version,
        r.status,
        review,
        r.findings.len() - review,
        r.not_checked.len()
    );
    push_findings(&mut s, r, "review", "WORTH REVIEWING");
    push_findings(&mut s, r, "inventory", "STORED SIGN-IN MATERIAL");
    push_gaps(&mut s, r);
    s.push('\n');
    if let Some(c) = &r.coverage {
        let roots: Vec<String> = c
            .roots
            .iter()
            .map(|p| format!("\"{}\"", escape(p)))
            .collect();
        s.push_str(&format!("Scanned: {}\n", roots.join(", ")));
        wrap(
            &mut s,
            "Skipped folders: ",
            "                 ",
            &c.excluded_directories.join(", "),
        );
        // Never left out: a folder skipped on request is not a clean folder.
        for skipped in &c.excluded_by_user {
            s.push_str(&format!(
                "Not checked at your request: \"{}\"\n",
                escape(skipped)
            ));
        }
    }
    wrap(
        &mut s,
        "Not assessed: ",
        "              ",
        "browser cookies and sessions, Safari, Notes, Keychain items, images.",
    );
    match &r.coverage {
        Some(c) if limits => {
            s.push_str("\nLIMITS\n");
            wrap(&mut s, "", "", c.limitations);
        }
        _ => s.push_str(
            "No findings does not mean safe. Add --limits to see what is not detected.\n",
        ),
    }
    s
}

/// UTC timestamp, second precision, without a date library.
pub fn utc_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_neutralizes_hostile_names() {
        assert_eq!(escape("a\u{1b}]0;x\u{7}b"), "a\\u{1b}]0;x\\u{7}b");
        assert_eq!(escape("x\ny"), "x\\u{a}y");
        assert_eq!(escape("p-\u{202e}vsc.exe"), "p-\\u{202e}vsc.exe");
    }

    #[test]
    fn json_is_ascii_only() {
        let r = Report {
            schema: "loose-keys/report/1",
            tool_version: "0.1.0",
            generated_at: utc_now(),
            status: "complete",
            context: "user",
            coverage: None,
            findings: vec![],
            not_checked: vec![NotChecked {
                path: "~/\u{202e}\u{1F600}\u{1b}".into(),
                reason: "unreadable",
            }],
        };
        let j = to_ascii_json(&r);
        assert!(j.is_ascii());
        assert!(j.contains("\\u202e") && j.contains("\\ud83d\\ude00") && j.contains("\\u001b"));
        let back: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(back["not_checked"][0]["path"], "~/\u{202e}\u{1F600}\u{1b}");
    }

    #[test]
    fn json_has_no_raw_delete_character() {
        let r = Report {
            schema: "loose-keys/report/1",
            tool_version: "0.1.0",
            generated_at: utc_now(),
            status: "partial",
            context: "user",
            coverage: None,
            findings: vec![],
            not_checked: vec![NotChecked {
                path: "~/a\u{7f}b".into(),
                reason: "unreadable",
            }],
        };
        let j = to_ascii_json(&r);
        assert!(!j.contains('\u{7f}') && j.contains("a\\u007fb"));
        let back: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(back["not_checked"][0]["path"], "~/a\u{7f}b");
    }

    #[test]
    fn a_finding_in_the_json_report_has_only_the_fields_of_the_schema() {
        let schema = include_str!("../schema/report-1.schema.json");
        let schema: serde_json::Value = serde_json::from_str(schema).unwrap();
        let named = &schema["properties"]["findings"]["items"]["properties"];
        // Every field set, those kept on this Mac alone included.
        let r = Report {
            schema: "loose-keys/report/1",
            tool_version: "0.1.0",
            generated_at: utc_now(),
            status: "complete",
            context: "user",
            coverage: None,
            findings: vec![Finding {
                fingerprint: Some("synthetic-file-digest".into()),
                rule: "secret.service-token",
                category: "developer-cloud",
                kind: "review",
                severity: "high",
                title: "Synthetic finding",
                explanation: "Synthetic reason.",
                reason: Some("Synthetic why.".into()),
                next_step: Some("Synthetic next step."),
                steps: &["Synthetic step."],
                link: Some("https://fixture.invalid/"),
                token_type: Some("Synthetic token"),
                detail: Some("synthetic-detail".into()),
                secret: Some("synthetic-value-digest".into()),
                shared: true,
                mount: Some(271_828),
                subject: Some("synthetic-subject".into()),
                path: "/Volumes/Backup/notes.txt".into(),
                line: Some(7),
            }],
            not_checked: vec![],
        };
        let json = to_ascii_json(&r);
        let report: serde_json::Value = serde_json::from_str(&json).unwrap();
        let finding = report["findings"][0].as_object().unwrap();
        // Each optional field of the schema is there, so the list is whole.
        assert_eq!(finding.len(), named.as_object().unwrap().len());
        for field in finding.keys() {
            assert!(!named[field].is_null(), "not in the schema: {field}");
        }
        for private in ["digest", "detail", "subject", "271828", "mount", "shared"] {
            assert!(!json.contains(private), "in the report: {private}");
        }
    }

    #[test]
    fn text_groups_by_rule_and_skips_empty_sections() {
        let finding = |path: &str| Finding {
            fingerprint: None,
            rule: "export.password-csv",
            category: "password-export",
            kind: "review",
            severity: "high",
            title: "Possible password export file",
            explanation: "Explained once.",
            next_step: Some("Delete it."),
            steps: &["Open the folder.", "Delete the file."],
            path: path.into(),
            ..Finding::default()
        };
        let gap = |path: &str| NotChecked {
            path: path.into(),
            reason: "permission-denied",
        };
        let r = Report {
            schema: "loose-keys/report/1",
            tool_version: "0.1.0",
            generated_at: utc_now(),
            status: "partial",
            context: "user",
            coverage: None,
            findings: vec![finding("~/a.csv"), finding("~/b\u{1b}.csv")],
            not_checked: (0..7).map(|i| gap(&format!("~/gap{i}"))).collect(),
        };
        let t = to_text(&r, false);
        assert!(t.contains("2 worth reviewing, 0 stored sign-in material, 7 not checked"));
        assert_eq!(t.matches("Explained once.").count(), 1);
        assert!(t.contains(
            "1. [HIGH] Possible password export file\n   \"~/a.csv\"\n   \"~/b\\u{1b}.csv\""
        ));
        assert_eq!(t.matches("     2. Delete the file.").count(), 1);
        assert!(!t.contains("STORED SIGN-IN MATERIAL ("));
        assert!(t.contains("Access denied by macOS (7)") && t.contains("...and 2 more"));
        assert!(!t.contains('\u{1b}'));
    }

    #[test]
    fn text_gives_one_entry_to_a_rule_that_found_several_token_types() {
        let finding = |token_type, link| Finding {
            rule: "secret.agent-record",
            kind: "review",
            severity: "high",
            title: "Service token in an AI agent's records",
            explanation: "Explained once.",
            token_type: Some(token_type),
            link: Some(link),
            path: "~/record.jsonl".into(),
            ..Finding::default()
        };
        let mut r = Report {
            schema: "loose-keys/report/1",
            tool_version: "0.1.0",
            generated_at: utc_now(),
            status: "complete",
            context: "user",
            coverage: None,
            findings: vec![
                finding("Square access token", "https://one.invalid"),
                finding("Tailscale API key", "https://two.invalid"),
                finding("Square app secret", "https://one.invalid"),
            ],
            not_checked: vec![],
        };
        let t = to_text(&r, false);
        assert!(t.contains("WORTH REVIEWING (3)\n\n1. [HIGH]") && !t.contains("\n2. [HIGH]"));
        assert_eq!(t.matches("Explained once.").count(), 1);
        assert!(t.contains(
            "   Where: https://one.invalid (Square access token, Square app secret)\n   Where: https://two.invalid (Tailscale API key)\n"
        ));
        // With one place to go, the types are already on the lines above it.
        r.findings.remove(1);
        assert!(to_text(&r, false).contains("   Where: https://one.invalid\n"));
    }

    #[test]
    fn timestamp_shape() {
        let t = utc_now();
        assert_eq!(t.len(), 20);
        assert!(t.ends_with('Z') && t.as_bytes()[10] == b'T');
    }
}
