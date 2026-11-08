//! The scanner: which folders and files it visits, and how it reads them.
//! The rules it applies are in `rules/`. This file has the limits, each kind
//! of scan and what a scan records; the parts of the work are in `scan/`.

mod changes;
mod discovery;
mod known;
mod paths;
mod read;
mod recheck;
mod traversal;

pub use known::read_when_skipped;
pub use paths::{change_at, home, is_root, named_folder, on_disk, selected_root, skipped_folder};
pub use recheck::{recheck, recheck_identities, recheck_values};

use recheck::scope_digest;
use traversal::Traversal;

use crate::fsutil::{presence, through_links, Gap};
use crate::report::{self, Finding, NotChecked, Report};
use crate::rules::{Hit, Rule, Target, RULES};
use std::collections::{HashMap, HashSet};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

type Fingerprint = Box<dyn Fn(&str, &[u8], bool) -> String + Send>;
/// A hit a scan has reported: its rule and path, and its line, subject and
/// where its value sits. Never the value.
type Reported = (
    &'static str,
    PathBuf,
    Option<usize>,
    Option<String>,
    Option<std::ops::Range<usize>>,
);

const HEADER: u64 = 4096;
const CONFIG_MAX: u64 = 1024 * 1024;
/// The largest file read in full as a stream, and the entries listed per tree.
const STREAM_MAX: u64 = 256 * 1024 * 1024;
const TREE_ENTRIES: usize = 50_000;
/// Folder levels read below the root of such a tree.
const TREE_DEPTH: usize = 16;
/// Different tokens listed for one file that is read through.
const RECORD_HITS: usize = 50;
/// Folders inside an AI tool's own folder that hold programs, not records.
const TREE_SKIP: &[&str] = &[
    "extensions",
    "plugins",
    "packages",
    "bin",
    "Cache",
    "Code Cache",
    "GPUCache",
];
pub const EXCLUDED: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".cache",
    "Library/Caches",
    ".bun/install/cache",
    ".npm/_cacache",
    ".cargo/registry",
    ".rustup/toolchains",
    "vendor",
    "Library/Application Support/dev.loosekeys.desktop",
    // Stores macOS keeps for its own apps. No rule reads them, and entering
    // one makes macOS ask the person for their calendar, contacts, reminders
    // or photos in this program's name, and hold the scan until they answer.
    "Library/Calendars",
    "Library/Application Support/AddressBook",
    "Library/Reminders",
    "Library/Photos",
    "Photos Library.photoslibrary",
    // Other apps' data and the TV app's media: listing inside makes macOS ask
    // for "data from other apps" or the media library, seen with SIP on in
    // macOS 26. A known location inside, such as Telegram's App Store copy,
    // is still read. Music/Music is the Music app's library, assumed to be
    // guarded as the TV app's is (unverified).
    "Library/Group Containers",
    "Library/Containers",
    "Movies/TV",
    "Music/Music",
];

/// Settings files macOS guards as it does their app's data: opening the
/// Contacts app's asks for the contacts, the TV app's for the media library.
/// Discovery passes them.
const ASKS: &[&str] = &[
    "Library/Preferences/com.apple.AddressBook.plist",
    "Library/Preferences/com.apple.TV.plist",
];

/// Home folders that discovery reaches last: large, and rarely where a
/// credential file is left. Known locations inside them are checked first.
const LAST: &[&str] = &["Library", "Movies", "Music", "Pictures"];

/// What one background check may spend.
#[derive(Clone, Copy)]
pub struct Limits {
    /// Entries discovery may list. A sweep needs at least the 10,000-entry
    /// limit of one folder here, or a folder that large is never finished.
    pub entries: usize,
    pub time: Duration,
}

/// One thing a full pass made in slices has still to do.
#[derive(Clone, Debug, PartialEq)]
pub enum Step {
    /// The known locations, before anything else, from this one on: an
    /// earlier slice did the ones before it.
    Known(usize),
    /// A folder of an agent's records, to be read in full by this rule:
    /// how deep it is below the root of its tree and, once its subfolders
    /// are listed here too, the last of its files already read.
    Records {
        rule: &'static str,
        dir: PathBuf,
        depth: usize,
        after: Option<PathBuf>,
    },
    /// A folder discovery has not reached, and how deep it is.
    Folder(PathBuf, usize),
    /// A folder discovery was stopped in, how deep it is, and the last of
    /// its entries it finished: the files and subfolders after that one are
    /// still to do.
    Rest {
        dir: PathBuf,
        depth: usize,
        after: PathBuf,
    },
}

/// What is left of a full pass, in the order it will be done.
pub type Pending = Vec<Step>;

/// The paths a change check did not finish, by why: each in the list for what
/// stopped its own check. A path given twice is judged each time, and a
/// folder holding a gap is walked again for each path that reaches it, so the
/// entry budget can stop it there with nothing more to read. A path in none
/// was checked as far as any scan checks it, or what is unread of it was left
/// by an earlier path that is listed. What was not read is also a gap in the
/// report.
#[derive(Debug, Default, PartialEq)]
pub struct Unreached {
    /// A cancel came before the path was reached or while it was checked:
    /// the check can be made again as it was.
    pub cancelled: Vec<PathBuf>,
    /// Not begun, or left unfinished after it was begun, because the paths
    /// before it used up or shared the check's time, the findings one scan
    /// keeps or, for a folder to walk, its entry budget. Checked without them
    /// it may well be finished.
    pub out_of_budget: Vec<PathBuf>,
    /// Begun first, with the whole check to itself, and left unfinished by
    /// one of those three limits. Not by a
    /// limit a full pass reaches at the same place: how deep folders are
    /// read, how many entries of one folder or one tree of records, how many
    /// tokens of one record, or how long one record may take. Nor is a
    /// record that was read to its end after the time was up.
    pub cut_short: Vec<PathBuf>,
}

pub struct Scan {
    cancel: Option<Arc<AtomicBool>>,
    fingerprint: Option<Fingerprint>,
    digests: std::collections::HashMap<(&'static str, PathBuf), String>,
    started: Instant,
    home: PathBuf,
    found: HashSet<Reported>,
    /// Whole-file checks already made, so a file reached twice is read once.
    whole_files_checked: HashSet<(&'static str, PathBuf)>,
    traversal: Traversal,
    /// Real locations of targeted paths; None where a link was not followed.
    links: HashMap<PathBuf, Option<PathBuf>>,
    /// For a check of changes: where links lead from the entries of a known
    /// folder to the file each is read for, by folder and file name, and
    /// whether every entry was looked at. One for each folder and file name
    /// the rules give, holding no more places than the check may list
    /// entries.
    linked_target_cache: HashMap<(PathBuf, &'static str), (Vec<PathBuf>, bool)>,
    /// For a check of changes: the entries listed of a browser's folder,
    /// in each of which rules name a file or a folder, and whether the
    /// check's entries ran out before its end. No more of them for one
    /// browser than the check may list entries.
    profiles: HashMap<PathBuf, (Vec<(PathBuf, bool)>, bool)>,
    /// The last folder reported as holding cloud-only files.
    cloud_dir: Option<PathBuf>,
    /// The folder discovery is checking the files of, open, as it was
    /// listed: its files are opened from it, not walked to from "/" again.
    folder: Option<(PathBuf, std::fs::File)>,
    /// The folders above the last one discovery listed, open, so the next
    /// is not walked to from "/" again either.
    folders: crate::fsutil::Folders,
    /// How long a cancellable scan may run.
    limit: Duration,
    /// How long a cancellable scan may spend reading one record through.
    record_time: Duration,
    /// Folders the person asked not to be checked.
    skip: Vec<PathBuf>,
    /// Times a reader said it did not read because the scan was stopped,
    /// also when the list of gaps was full or already had that row.
    unread: usize,
    /// Something was not read because the scan was stopped or its entry
    /// budget was spent: never for a limit any scan reaches at that place.
    work_unfinished: bool,
    counts: Progress,
    observer: Option<Box<dyn FnMut(Progress) + Send>>,
    last_update: Instant,
    /// Files checked so far and the last redraw, when stderr is a terminal.
    progress: Option<(usize, Instant)>,
    pub findings: Vec<Finding>,
    pub not_checked: Vec<NotChecked>,
    /// Each path and reason in `not_checked`, so a place reached twice, as
    /// from two roots, is listed once for a reason.
    gaps_listed: HashSet<(String, Gap)>,
}

/// Aggregate work only. No file names or secret values cross this boundary.
#[derive(Clone, Copy, Default, serde::Serialize)]
pub struct Progress {
    pub phase: &'static str,
    pub entries: usize,
    pub header_attempts: usize,
    pub config_attempts: usize,
    pub findings: usize,
    pub not_checked: usize,
}

/// Each tree of agent records, with the rule that reads it.
fn trees() -> impl Iterator<Item = (&'static Rule, &'static str)> {
    RULES.iter().flat_map(|rule| {
        rule.targets.iter().filter_map(move |t| match *t {
            Target::Tree(dir) => Some((rule, dir)),
            _ => None,
        })
    })
}

impl Scan {
    #[cfg(test)]
    pub fn run(home: &Path, roots: &[PathBuf]) -> Scan {
        Self::run_observed(home, roots, None, None, None)
    }

    #[cfg(test)]
    fn run_observed(
        home: &Path,
        roots: &[PathBuf],
        observer: Option<Box<dyn FnMut(Progress) + Send>>,
        cancel: Option<Arc<AtomicBool>>,
        fingerprint: Option<Fingerprint>,
    ) -> Scan {
        Self::run_budgeted(home, roots, &[], observer, cancel, fingerprint, 100_000)
    }

    /// `budget` is the number of entries discovery may list under each root.
    fn run_budgeted(
        home: &Path,
        roots: &[PathBuf],
        skip: &[PathBuf],
        observer: Option<Box<dyn FnMut(Progress) + Send>>,
        cancel: Option<Arc<AtomicBool>>,
        fingerprint: Option<Fingerprint>,
        budget: usize,
    ) -> Scan {
        let mut s = Scan::new(home, observer, cancel, fingerprint, budget);
        s.skip = skip.to_vec();
        if s.progress.is_some() {
            eprint!("Scanning... ");
        }
        s.publish(true);
        s.known();
        s.counts.phase = "discovery";
        s.publish(true);
        for root in roots {
            // A selected folder in a skipped one, or that is one, is left out
            // with it: the app takes all of a skipped folder to be unread.
            if s.skipped(root) {
                continue;
            }
            // Limited subtrees can be retried with an independent budget.
            s.traversal.remaining = budget;
            s.discover(root, vec![(root.clone(), 0)]);
        }
        s.finish()
    }

    fn new(
        home: &Path,
        observer: Option<Box<dyn FnMut(Progress) + Send>>,
        cancel: Option<Arc<AtomicBool>>,
        fingerprint: Option<Fingerprint>,
        budget: usize,
    ) -> Scan {
        Scan {
            cancel,
            fingerprint,
            digests: Default::default(),
            started: Instant::now(),
            home: home.to_path_buf(),
            found: HashSet::new(),
            whole_files_checked: HashSet::new(),
            traversal: Traversal::new(budget),
            links: HashMap::new(),
            linked_target_cache: HashMap::new(),
            profiles: HashMap::new(),
            cloud_dir: None,
            folder: None,
            folders: Default::default(),
            limit: Duration::from_secs(30),
            record_time: Duration::from_secs(60),
            skip: Vec::new(),
            unread: 0,
            work_unfinished: false,
            counts: Progress {
                phase: "targeted-checks",
                ..Progress::default()
            },
            observer,
            last_update: Instant::now(),
            progress: std::io::stderr().is_terminal().then(|| (0, Instant::now())),
            findings: Vec::new(),
            not_checked: Vec::new(),
            gaps_listed: HashSet::new(),
        }
    }

    fn finish(mut self) -> Scan {
        let s = &mut self;
        s.counts.phase = "finished";
        s.publish(true);
        if s.progress.is_some() {
            // Erase the status line so the summary starts clean.
            eprint!("\r\x1b[2K");
        }
        let rank = |f: &Finding| {
            (
                f.kind != "review",
                ["high", "medium"]
                    .iter()
                    .position(|s| *s == f.severity)
                    .unwrap_or(2),
            )
        };
        s.findings
            .sort_by(|a, b| (rank(a), &a.path, a.line).cmp(&(rank(b), &b.path, b.line)));
        self
    }

    /// One bounded slice of a full check of the home folder, for the
    /// background agent. `resume` is what an earlier slice returned as still
    /// to do; None starts over, beginning with the known locations. Returns
    /// what was found and what is left. The pass is over when nothing is.
    pub fn sweep(
        home: &Path,
        skip: &[PathBuf],
        resume: Option<Pending>,
        limits: Limits,
        cancel: Arc<AtomicBool>,
        fingerprint: impl Fn(&str, &[u8], bool) -> String + Send + 'static,
    ) -> (Report, Pending) {
        let mut s = Scan::new(
            home,
            None,
            Some(cancel),
            Some(Box::new(fingerprint)),
            limits.entries,
        );
        s.limit = limits.time;
        s.skip = skip.to_vec();
        let mut places = HashMap::new();
        let mut left = Vec::new();
        let mut folders = Vec::new();
        for step in resume.unwrap_or_else(|| vec![Step::Known(0)]) {
            match step {
                // A folder the person has skipped since the step was left.
                // Not the root of an agent's folder: that is a known
                // location, which a scan reads whatever is skipped. (A
                // change check does not: it passes by every skipped path.)
                Step::Records {
                    dir, depth: 1.., ..
                }
                | Step::Folder(dir, _)
                | Step::Rest { dir, .. }
                    if s.skipped(&dir) => {}
                Step::Known(from) => {
                    // A fixed list of small files, so it is given the time a
                    // scan made by hand has. Stopped, it goes on in the next
                    // slice from the file it had reached.
                    s.limit = limits.time.max(Duration::from_secs(30));
                    let reached = s.known_files(from, true);
                    s.limit = limits.time;
                    if let Some(done) = reached {
                        left.push(Step::Known(done));
                        continue;
                    }
                    for (rule, dir) in trees() {
                        let root = s.targeted(&home.join(dir));
                        // One that is not there is not left for later.
                        if let Some(root) = root.filter(|root| s.there(root).is_some()) {
                            left.extend(s.records(rule, root, 0, None));
                        }
                    }
                    folders.push((home.to_path_buf(), 0));
                }
                Step::Records {
                    rule,
                    dir,
                    depth,
                    after,
                } => {
                    if let Some((rule, _)) = trees().find(|(r, _)| r.id == rule) {
                        left.extend(s.records(rule, dir, depth, after));
                    }
                }
                Step::Folder(dir, depth) => folders.push((dir, depth)),
                Step::Rest { dir, depth, after } => {
                    places.insert(dir.clone(), after);
                    folders.push((dir, depth));
                }
            }
        }
        s.traversal.resume(places);
        s.discover(home, folders);
        let mut s = s.finish();
        left.extend(s.traversal.pending_steps());
        (s.into_report(&[home.to_path_buf()]), left)
    }

    /// `tree_from` for a sweep: what it did not finish, as steps.
    fn records(
        &mut self,
        rule: &'static Rule,
        dir: PathBuf,
        depth: usize,
        after: Option<PathBuf>,
    ) -> Vec<Step> {
        let left = self.tree_from(rule, dir, depth, after);
        let step = |(dir, depth, after)| Step::Records {
            rule: rule.id,
            dir,
            depth,
            after,
        };
        left.into_iter().map(step).collect()
    }

    /// Check only these files and folders, as when they have just changed.
    /// A changed folder is walked; a changed known location is checked by its
    /// own rules. Paths outside the home or in a skipped folder are ignored.
    /// In a folder discovery passes over, only known locations and the files
    /// rules name in a repository's `.git` are checked. Returns, beside the
    /// report, the paths it did not finish.
    pub fn changed(
        home: &Path,
        skip: &[PathBuf],
        paths: &[PathBuf],
        limits: Limits,
        cancel: Arc<AtomicBool>,
        fingerprint: impl Fn(&str, &[u8], bool) -> String + Send + 'static,
    ) -> (Report, Unreached) {
        let mut s = Scan::new(
            home,
            None,
            Some(cancel),
            Some(Box::new(fingerprint)),
            limits.entries,
        );
        s.limit = limits.time;
        s.skip = skip.to_vec();
        let unreached = s.changes(paths);
        (s.finish().into_report(&[home.to_path_buf()]), unreached)
    }

    /// Scan home plus `selected` and build the report both front ends show.
    pub fn report(home: &Path, selected: &[PathBuf]) -> Report {
        Self::report_excluding(home, selected, &[])
    }

    /// As `report`, leaving out folders the person asked not to be checked.
    pub fn report_excluding(home: &Path, selected: &[PathBuf], skip: &[PathBuf]) -> Report {
        Self::report_options(home, selected, skip, None, None, None)
    }

    pub fn report_with_progress(
        home: &Path,
        selected: &[PathBuf],
        observer: impl FnMut(Progress) + Send + 'static,
    ) -> Report {
        Self::report_observed(home, selected, Some(Box::new(observer)))
    }

    fn report_observed(
        home: &Path,
        selected: &[PathBuf],
        observer: Option<Box<dyn FnMut(Progress) + Send>>,
    ) -> Report {
        Self::report_options(home, selected, &[], observer, None, None)
    }

    pub fn report_controlled(
        home: &Path,
        selected: &[PathBuf],
        skip: &[PathBuf],
        cancel: Arc<AtomicBool>,
        fingerprint: impl Fn(&str, &[u8], bool) -> String + Send + 'static,
        observer: impl FnMut(Progress) + Send + 'static,
    ) -> Report {
        Self::report_options(
            home,
            selected,
            skip,
            Some(Box::new(observer)),
            Some(cancel),
            Some(Box::new(fingerprint)),
        )
    }

    fn report_options(
        home: &Path,
        selected: &[PathBuf],
        skip: &[PathBuf],
        observer: Option<Box<dyn FnMut(Progress) + Send>>,
        cancel: Option<Arc<AtomicBool>>,
        fingerprint: Option<Fingerprint>,
    ) -> Report {
        let mut roots = vec![home.to_path_buf()];
        for path in selected {
            if !roots.contains(path) {
                roots.push(path.clone());
            }
        }
        let s = Scan::run_budgeted(home, &roots, skip, observer, cancel, fingerprint, 100_000);
        s.into_report(&roots)
    }

    fn into_report(self, roots: &[PathBuf]) -> Report {
        let s = self;
        Report {
            schema: "loose-keys/report/1",
            tool_version: env!("CARGO_PKG_VERSION"),
            generated_at: report::utc_now(),
            status: if s.not_checked.is_empty() {
                "complete"
            } else {
                "partial"
            },
            context: if is_root() { "system" } else { "user" },
            coverage: report::Coverage {
                roots: roots.iter().map(|p| s.rel(p)).collect(),
                excluded_directories: EXCLUDED,
                excluded_by_user: s.skip.iter().map(|p| s.rel(p)).collect(),
                limitations: report::LIMITATIONS,
            },
            findings: s.findings,
            not_checked: s.not_checked,
        }
    }

    pub fn rel(&self, p: &Path) -> String {
        match p.strip_prefix(&self.home) {
            Ok(r) => format!("~/{}", r.to_string_lossy()),
            Err(_) => p.to_string_lossy().into_owned(),
        }
    }

    fn gap(&mut self, p: &Path, reason: Gap) {
        if reason == "scan-limit" {
            self.unread += 1;
        }
        let path = self.rel(p);
        if self.gaps_listed.contains(&(path.clone(), reason)) {
            return;
        }
        if self.cancel.is_some() && self.not_checked.len() >= 4096 - 1 {
            // The last row a report keeps says that more was not checked
            // than the list names, even if the home is listed already: a
            // full list is one of 4,096 rows.
            if self.not_checked.len() == 4096 - 1 {
                let path = self.rel(&self.home);
                let reason = "scan-limit";
                self.not_checked.push(NotChecked { path, reason });
            }
            return;
        }
        self.gaps_listed.insert((path.clone(), reason));
        self.not_checked.push(NotChecked { path, reason });
    }

    /// A place not read because the scan was stopped. Not said of one that
    /// is not there: nothing would have been read of it.
    fn unread(&mut self, p: &Path) {
        let gone =
            std::fs::symlink_metadata(p).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound);
        if !gone {
            self.gap(p, "scan-limit");
            self.work_unfinished = true;
        }
    }

    fn stopped(&self) -> bool {
        self.halted()
            || self
                .cancel
                .as_ref()
                .is_some_and(|_| self.started.elapsed() >= self.limit)
    }

    /// Stopped for a reason other than the time: a cancel, or as many
    /// findings as one scan keeps. A record being read is finished when only
    /// the time is up, and what it holds is kept; this ends it.
    fn halted(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|c| c.load(Ordering::SeqCst) || self.findings.len() >= 4096)
    }

    /// The place to read for a known location. A link is followed only when
    /// it leads somewhere inside the home folder, and never as root, where a
    /// link is something another user could have placed. Otherwise it is a
    /// gap: "symlink", or why a link could not be resolved.
    fn targeted(&mut self, p: &Path) -> Option<PathBuf> {
        if let Some(known) = self.links.get(p) {
            return known.clone();
        }
        let real = match through_links(p, &self.home) {
            None => Some(p.to_path_buf()),
            Some(_) if is_root() => {
                self.gap(p, "symlink");
                None
            }
            Some(Ok(real)) => Some(real),
            Some(Err(g)) => {
                self.gap(p, g);
                None
            }
        };
        self.links.insert(p.to_path_buf(), real.clone());
        real
    }

    /// What is at `p`, a known location whose presence is asked. One whose
    /// presence cannot be told is a gap, not taken to be absent.
    fn there(&mut self, p: &Path) -> Option<std::fs::Metadata> {
        presence(p).unwrap_or_else(|g| {
            self.gap(p, g);
            None
        })
    }

    /// `bytes` is the file's material for its fingerprint, and what `hit.span`
    /// points into unless `source` gives the piece a streamed hit came from.
    /// Returns false when the scan had been stopped and the hit was dropped.
    fn add_from(
        &mut self,
        rule: &Rule,
        p: &Path,
        hit: Hit,
        shared: bool,
        bytes: &[u8],
        source: Option<&[u8]>,
    ) -> bool {
        // A file read through is read once in a scan, and each different
        // value in it is passed on once. So two tokens of one kind on a line,
        // or in a file with no lines, are two findings. Any other hit is
        // known by where its value sits as well: two values of one kind on a
        // line are two findings, and a file reached twice gives each once.
        let key = (
            rule.id,
            p.to_path_buf(),
            hit.line,
            hit.subject.clone(),
            hit.span.clone(),
        );
        if source.is_none() && self.found.contains(&key) {
            return true;
        }
        // A streamed file is read past the time limit, and so are its hits.
        let stop = match source {
            Some(_) => self.halted(),
            None => self.stopped(),
        };
        if stop {
            self.work_unfinished = true;
            // One gap for the file, however many of its hits are dropped.
            let path = self.rel(p);
            let last = self.not_checked.last();
            if !last.is_some_and(|g| g.reason == "scan-limit" && g.path == path) {
                self.gap(p, "scan-limit");
            } else {
                self.unread += 1;
            }
            return false;
        }
        if source.is_none() {
            self.found.insert(key);
        }
        let wording = hit.wording;
        let advice = hit
            .advice
            .or(wording.map(|w| &w.advice))
            .unwrap_or(&rule.advice);
        let rule_reason = wording.map_or(rule.reason, |w| w.reason);
        let (mut kind, mut reason) = (rule.kind, rule_reason.map(String::from));
        let mut severity = rule.severity;
        if hit.low {
            (kind, severity, reason) = ("inventory", "low", None);
        }
        // A test credential is no more worth reviewing for being readable.
        if shared && !hit.low {
            kind = "review";
            let mode_note = "The file's permissions let other users on this Mac read it, unless a folder above it or an access list blocks them.";
            reason = Some(match reason {
                Some(r) => format!("{r} {mode_note}"),
                None => mode_note.to_string(),
            });
        }
        // The value alone, under no rule's name, so the same credential has
        // the same digest in every file and under every rule.
        let value = hit
            .span
            .clone()
            .and_then(|s| source.unwrap_or(bytes).get(s));
        let secret = self
            .fingerprint
            .as_ref()
            .and_then(|f| value.map(|v| f("", v, false)));
        let fingerprint = match (&secret, source) {
            // A streamed file has no bounded material; its secret stands in.
            (Some(secret), Some(_)) => Some(secret.clone()),
            _ => self.fingerprint.as_ref().map(|f| {
                self.digests
                    .entry((rule.id, p.to_path_buf()))
                    .or_insert_with(|| f(rule.id, bytes, shared))
                    .clone()
            }),
        };
        // Asked only where a review list is kept, as the digests are.
        let listed = self.fingerprint.as_ref();
        let mount = listed.and_then(|_| crate::fsutil::mounted_at(p, &self.home));
        let scope = self
            .fingerprint
            .as_ref()
            .and_then(|digest| scope_digest(&hit, source.unwrap_or(bytes), digest.as_ref()));
        self.findings.push(Finding {
            scope,
            fingerprint,
            secret,
            shared,
            mount,
            detail: hit.detail,
            rule: rule.id,
            category: rule.category,
            kind,
            severity,
            title: rule.title,
            explanation: wording.map_or(rule.explanation, |w| w.explanation),
            reason,
            next_step: wording.map_or(rule.next_step, |w| w.next_step),
            steps: advice.steps,
            link: hit.link.or(advice.link),
            token_type: hit.token_type,
            subject: hit.subject,
            path: self.rel(p),
            line: hit.line,
        });
        true
    }

    fn add(&mut self, rule: &Rule, p: &Path, hit: Hit, shared: bool, bytes: &[u8]) {
        self.add_from(rule, p, hit, shared, bytes, None);
    }

    fn skipped(&self, dir: &Path) -> bool {
        self.skip.iter().any(|s| dir.starts_with(s))
    }

    /// Counts only: paths never reach the status line.
    fn tick(&mut self) {
        self.publish(false);
        let Some((files, last)) = &mut self.progress else {
            return;
        };
        *files += 1;
        if last.elapsed() >= Duration::from_millis(100) {
            *last = Instant::now();
            eprint!(
                "\r\x1b[2KScanning... {} header read attempts, {} found, {} not checked",
                files,
                self.findings.len(),
                self.not_checked.len()
            );
            let _ = std::io::stderr().flush();
        }
    }

    fn publish(&mut self, force: bool) {
        if !force && self.last_update.elapsed() < Duration::from_millis(100) {
            return;
        }
        self.last_update = Instant::now();
        self.counts.findings = self.findings.len();
        self.counts.not_checked = self.not_checked.len();
        if let Some(observer) = &mut self.observer {
            observer(self.counts);
        }
    }
}

#[cfg(test)]
mod tests;
