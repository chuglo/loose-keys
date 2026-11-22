//! Scan and coverage views for the window. The report format is independent.

use crate::{report, review, scan};
use report::Report;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// The home folders macOS asks about one at a time, before a scan.
pub(super) const ACCESS_FOLDERS: [&str; 3] = ["Desktop", "Documents", "Downloads"];

/// Paths listed per "not checked" reason. Saved reports retain every manual gap.
const GAPS_SHOWN: usize = 20;

/// Whether a refusal the helper saved still stands. One that an older
/// build's pass saved, for a place this build leaves out, would be shown
/// until the next weekly pass. Paths are saved below the home as `~/…`.
fn still_unread(path: &str, reason: &str) -> bool {
    reason != "permission-denied"
        || !path
            .strip_prefix("~/")
            .is_some_and(|rel| scan::not_tried(Path::new(rel)))
}

/// The helper's count of places it couldn't read, less the saved ones that
/// no longer stand.
pub(super) fn unread_count(agent: &review::Agent) -> usize {
    let gone = agent.unread_places.as_ref().map_or(0, |snapshot| {
        snapshot
            .places
            .iter()
            .filter(|(path, reason)| !still_unread(path, reason))
            .count()
    });
    agent.unread.saturating_sub(gone)
}

/// Details are read on demand; frequent status polls carry only counts.
#[derive(Serialize)]
pub(super) struct AutomaticCoverage {
    full_pass: Option<String>,
    unread: usize,
    manual_scan_id: Option<u64>,
    unread_gaps: Option<Vec<GapView>>,
    unread_truncated: bool,
}

pub(super) fn automatic_coverage(
    agent: &review::Agent,
    manual: Option<&ManualReport>,
) -> AutomaticCoverage {
    let report = manual.map(|m| &m.report);
    AutomaticCoverage {
        full_pass: agent.baseline.clone(),
        unread: unread_count(agent),
        manual_scan_id: manual.map(|m| m.id),
        unread_gaps: agent.unread_places.as_ref().map(|snapshot| {
            let mut automatic: Vec<_> = snapshot
                .places
                .iter()
                .filter(|(path, reason)| still_unread(path, reason))
                .map(|(path, reason)| (path.as_str(), reason.as_str()))
                .collect();
            automatic.sort_by_key(|(_, reason)| *reason);
            gap_view(report, automatic.into_iter())
        }),
        unread_truncated: agent.unread_places.as_ref().is_some_and(|p| p.truncated),
    }
}

pub(super) struct ManualReport {
    pub(super) id: u64,
    pub(super) report: Report,
}

impl ManualReport {
    pub(super) fn view(&self) -> ResultsView {
        results_view(&self.report, self.id)
    }
}

#[derive(Serialize)]
pub(super) struct ResultsView {
    scan_id: u64,
    status: &'static str,
    generated_at: String,
    review: usize,
    stored: usize,
    not_checked: usize,
    pub(super) gaps: Vec<GapView>,
    /// Which of the folders `prepare_access` asks for the scan was denied,
    /// as fixed words: the person can allow access to these again.
    blocked: Vec<&'static str>,
}

#[derive(Serialize, Clone)]
pub(super) struct GapView {
    label: String,
    pub(super) help: String,
    count: usize,
    paths: Vec<String>,
}

pub(super) fn results_view(r: &Report, scan_id: u64) -> ResultsView {
    let review = r.findings.iter().filter(|f| f.kind == "review").count();
    let gaps = gap_view(Some(r), std::iter::empty());
    let blocked = ACCESS_FOLDERS
        .into_iter()
        .filter(|folder| {
            r.not_checked
                .iter()
                .any(|gap| gap.reason == "permission-denied" && gap.path == format!("~/{folder}"))
        })
        .collect();
    ResultsView {
        scan_id,
        status: r.status,
        generated_at: r.generated_at.clone(),
        review,
        stored: r.findings.len() - review,
        not_checked: r.not_checked.len(),
        gaps,
        blocked,
    }
}

/// Count distinct retained paths under each reason before choosing which
/// to display. Prefer the manual report's order, then the helper's.
fn gap_view<'a>(
    manual: Option<&'a Report>,
    automatic: impl Iterator<Item = (&'a str, &'a str)>,
) -> Vec<GapView> {
    struct Group<'a> {
        reason: &'a str,
        seen: HashSet<&'a str>,
        paths: Vec<String>,
    }
    let root = manual.is_some_and(|r| r.context == "system");
    let manual = manual
        .into_iter()
        .flat_map(|r| &r.not_checked)
        .map(|gap| (gap.path.as_str(), gap.reason));
    let mut by_reason = HashMap::new();
    let mut groups = Vec::new();
    for (path, reason) in manual.chain(automatic) {
        let at = *by_reason.entry(reason).or_insert_with(|| {
            let at = groups.len();
            groups.push(Group {
                reason,
                seen: HashSet::new(),
                paths: Vec::new(),
            });
            at
        });
        let group = &mut groups[at];
        if group.seen.insert(path) && group.paths.len() < GAPS_SHOWN {
            group.paths.push(report::escape(path));
        }
    }
    groups
        .into_iter()
        .map(|group| {
            let (label, help) = gap_text(group.reason, root);
            GapView {
                label: report::escape(label),
                help: help.to_owned(),
                count: group.seen.len(),
                paths: group.paths,
            }
        })
        .collect()
}

/// `root`: the scan ran as root, where no link is followed.
pub(super) fn gap_text(reason: &str, root: bool) -> (&str, &str) {
    match reason {
        // Labels are headings in the window, so they use title case.
        "permission-denied" => (
            "No Access",
            "macOS privacy protection or file permissions don't let Loose Keys read these. Nearly every Mac has some.",
        ),
        "unreadable" => (
            "Couldn't Be Read",
            "If an app such as a browser is using any of these, quit the app, then scan again.",
        ),
        // The heading says it; the limits are in docs/detection.md.
        "too-large" => ("Too Large to Check", ""),
        "cloud-only-file" => (
            "Stored Only in the Cloud",
            "Download these to this Mac, then scan again.",
        ),
        // The heading and the list's opening line say it; the limits are in
        // docs/detection.md.
        "scan-limit" => ("Only Partly Checked", ""),
        "symlink" if root => (
            "Link Not Followed",
            "These sign-in files are links. Loose Keys follows no links when running as root.",
        ),
        "symlink" => (
            "Link Not Followed",
            "These sign-in files are links to places outside your home folder. \
             Loose Keys does not follow such links.",
        ),
        other => (other, ""),
    }
}
