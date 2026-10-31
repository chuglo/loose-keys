//! The scanner: which folders and files it visits, and how it reads them.
//! The rules it applies are in `rules/`.

#[path = "scan/traversal.rs"]
mod traversal;
use traversal::{Traversal, Visit, Walk};

use crate::fsutil::{list_dir, open_regular, read_config, read_head, through_links, Gap};
use crate::report::{self, Finding, NotChecked, Report};
use crate::rules::browser::CHROMIUM;
use crate::rules::{Hit, Matcher, Rule, Target, RULES};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsStr;
use std::hash::{Hash, Hasher};
use std::io::{IsTerminal, Read, Write};
use std::path::{Component, Path, PathBuf};
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
];

/// A settings file of the Contacts app, which macOS guards as it does the
/// contacts: opening it asks the person for them. Discovery passes it.
const ASKS: &str = "Library/Preferences/com.apple.AddressBook.plist";

/// Home folders that discovery reaches last: large, and rarely where a
/// credential file is left. Known locations inside them are checked first.
const LAST: &[&str] = &["Library", "Movies", "Music", "Pictures"];

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// The home folder, which every scan includes.
pub fn home() -> Result<PathBuf, &'static str> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
        .ok_or("HOME is not set to an absolute path")?;
    // A home reached through a link (a relocated or network home) is scanned
    // at its real location, where no path component is a link.
    Ok(std::fs::canonicalize(&home).unwrap_or(home))
}

/// An extra folder to scan: made absolute, and never containing `..`.
pub fn selected_root(path: &OsStr) -> Result<PathBuf, &'static str> {
    let path = std::path::absolute(path).map_err(|_| "could not resolve selected path")?;
    if path.components().any(|c| c == Component::ParentDir) {
        return Err("selected paths must not contain '..'");
    }
    Ok(path)
}

/// Check one file against one rule, outside a scan, to learn whether a review
/// item is still there. None: the file could not be checked, so nothing is
/// known. Some: what is still worth reviewing there, by subject; empty when
/// the file is gone or no longer matches. `mount` is what the finding kept
/// about the volume the file was on, if it kept anything: a file that is not
/// there because its volume is not is one that could not be checked.
pub fn recheck(
    rule: &str,
    path: &Path,
    home: &Path,
    mount: Option<u32>,
) -> Option<Vec<Option<String>>> {
    let found = recheck_values(rule, path, home, mount, &|_, _, _| String::new())?;
    Some(found.into_iter().map(|(subject, _)| subject).collect())
}

/// As `recheck`, with which value each thing still found holds: the digest
/// a scan given `digest` lists that value by, or None where the hit has no
/// single value. Two credentials of one kind at one place are told apart by
/// it, so that one of them being gone is something a fresh read can say. A
/// record read in full gives each different value once, as a scan does.
pub fn recheck_values(
    rule: &str,
    path: &Path,
    home: &Path,
    mount: Option<u32>,
    digest: &dyn Fn(&str, &[u8], bool) -> String,
) -> Option<Vec<(Option<String>, Option<String>)>> {
    let mut still = Vec::new();
    // The value alone, under no rule's name, as `Scan::add_from` asks for it.
    let valued = |hit: Hit, bytes: &[u8]| {
        let value = hit.span.and_then(|s| bytes.get(s));
        (hit.subject, value.map(|v| digest("", v, false)))
    };
    // One id can have a rule for each format its files come in. The rules
    // whose targets are this file, by its name or through a link, are the
    // ones the scan reads it with, and only they are asked. Where none is,
    // as for a file discovery found, every form is tried, and one that
    // cannot read the file means nothing is known.
    let same = || RULES.iter().filter(|r| r.id == rule);
    let reads = |r: &&Rule| {
        let mut targets = r.targets.iter();
        targets.any(|t| names(t, path) || linked(t, path, home))
    };
    // Asked once of each rule: a known folder may be listed to answer it.
    let mut forms: Vec<&Rule> = same().filter(reads).collect();
    if forms.is_empty() {
        forms = same().collect();
    }
    for rule in forms {
        match rule.matcher {
            // Presence is the finding: say what is still there, by its name.
            Matcher::Present => {
                if std::fs::symlink_metadata(path).is_ok() {
                    still.extend(rule.targets.iter().filter_map(|t| match *t {
                        Target::Present(_, what) | Target::Extension(_, what)
                            if names(t, path) || linked(t, path, home) =>
                        {
                            Some((crate::rules::label(what), None))
                        }
                        _ => None,
                    }));
                } else if !crate::fsutil::checked_or_absent(path, mount, home) {
                    return None;
                }
                continue;
            }
            Matcher::Stream(test) => {
                let Some((mut file, len, _)) = open_regular(path).ok()? else {
                    return crate::fsutil::checked_or_absent(path, mount, home).then_some(still);
                };
                if len > STREAM_MAX {
                    return None;
                }
                // Rechecks are rare; reading it in one piece keeps this simple.
                // As long as it was when opened, as the scan reads it.
                let mut bytes = Vec::new();
                (&mut file).take(len).read_to_end(&mut bytes).ok()?;
                // Compared here, where the bytes are: nothing of them is kept.
                let value = |hit: &Hit| hit.span.clone().and_then(|s| bytes.get(s));
                let mut hits: Vec<Hit> = Vec::new();
                for hit in test(&bytes, 1).ok()? {
                    let seen = |h: &Hit| h.subject == hit.subject && value(h) == value(&hit);
                    if !hits.iter().any(seen) {
                        hits.push(hit);
                    }
                }
                still.extend(hits.into_iter().map(|hit| valued(hit, &bytes)));
                continue;
            }
            _ => {}
        }
        let read = match rule.matcher {
            Matcher::Head(_) => read_head(path, HEADER),
            _ => read_config(path, CONFIG_MAX).and_then(|read| match read {
                Some(h) => settled(path, h),
                None => Ok(None),
            }),
        };
        let Some(h) = read.ok()? else {
            // Links and special files are not evidence of removal.
            return crate::fsutil::checked_or_absent(path, mount, home).then_some(still);
        };
        let hits = match rule.matcher {
            Matcher::Head(m) => m(&h.bytes).then(Hit::file).into_iter().collect(),
            Matcher::Whole { test, .. } => test(&h.bytes).ok()?,
            _ => Vec::new(),
        };
        if rule.kind == "review" || h.shared {
            still.extend(hits.into_iter().map(|hit| valued(hit, &h.bytes)));
        }
    }
    Some(still)
}

/// A file read whole, as a rule may count what is in it. An SQLite database
/// is more than its file while a write-ahead log beside it holds anything:
/// rows committed there are in the database and not yet in the file, and
/// SQLite reads a log that is there whatever the file says of itself. It is
/// less than its file while a rollback journal holds anything: pages of a
/// change not yet committed, or never to be, may be in the file already, and
/// SQLite puts back what the journal kept before it reads. So the file is
/// read again once both are seen to hold nothing, and both looked at once
/// more after that. Otherwise the database could not be checked, which is a
/// gap: never a count, and never a count of none. Neither is read. A journal
/// that holds nothing and has a length, as `journal_mode=PERSIST` leaves one
/// after each commit, is therefore a gap too. This is not a snapshot of the
/// database: a change that begins and ends between two looks is not seen.
fn settled(path: &Path, first: crate::fsutil::Head) -> Result<Option<crate::fsutil::Head>, Gap> {
    if !crate::rules::browser::is_sqlite(&first.bytes) {
        return Ok(Some(first));
    }
    let beside = |end: &str| {
        let mut name = path.as_os_str().to_os_string();
        name.push(end);
        PathBuf::from(name)
    };
    let logs = [beside("-wal"), beside("-journal")];
    for log in &logs {
        if !holds_nothing(log)? {
            return Err("unreadable");
        }
    }
    // Read after they were seen empty: a row that a checkpoint moved out of
    // the log before then is in this read, as it may not be in the first,
    // and so is a page that the journal put back.
    let Some(again) = read_config(path, CONFIG_MAX)? else {
        return Ok(None);
    };
    for log in &logs {
        if !holds_nothing(log)? {
            return Err("unreadable");
        }
    }
    Ok(Some(again))
}

/// Whether nothing is kept at `path`: no file of that name, or one of no
/// length. A link or a special file there is neither, and nothing is known.
fn holds_nothing(path: &Path) -> Result<bool, Gap> {
    match open_regular(path)? {
        Some((_, len, _)) => Ok(len == 0),
        None => match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
            _ => Err("unreadable"),
        },
    }
}

/// Whether a target is this path: the place a rule knows, or a name it reads.
fn names(target: &Target, path: &Path) -> bool {
    let name = path.file_name().unwrap_or_default();
    let inside = |dir: &str| path.parent().is_some_and(|p| p.ends_with(dir));
    match *target {
        Target::Discovery => false,
        Target::File(f) | Target::Present(f, _) | Target::Extension(f, _) => path.ends_with(f),
        Target::Dir(d) => inside(d),
        Target::Each(d, f) => {
            name == f
                && path
                    .parent()
                    .and_then(Path::parent)
                    .is_some_and(|p| p.ends_with(d))
        }
        Target::Name(_) => target.names(name),
        Target::Profiles(f) => name == f,
        Target::Tree(d) => path.ancestors().any(|a| a.ends_with(d)),
        Target::Repo(f) => name == f && inside(".git"),
    }
}

/// Whether a target is this path through a link: the known location is a
/// link, or is under one, that leads here.
fn linked(target: &Target, path: &Path, home: &Path) -> bool {
    let through = |at: &Path| match through_links(at, home) {
        Some(Ok(real)) => Some(real),
        _ => None,
    };
    let real = |at: &str| through(&home.join(at));
    // An entry of a known folder that is itself a link, which the scan
    // follows: the entry, or the named file in it.
    let entry = |d: &str, file: Option<&str>| {
        let dir = real(d).unwrap_or_else(|| home.join(d));
        let mut remaining = 10_000;
        list_dir(&dir, false, &mut remaining).is_ok_and(|listing| {
            listing.entries.iter().any(|(p, _)| {
                let at = file.map_or_else(|| p.clone(), |f| p.join(f));
                through(&at).is_some_and(|real| real == path)
            })
        })
    };
    match *target {
        Target::File(f) | Target::Present(f, _) => real(f).is_some_and(|real| real == path),
        Target::Dir(d) => {
            real(d).is_some_and(|real| path.parent() == Some(&real)) || entry(d, None)
        }
        Target::Each(d, f) => {
            real(d).is_some_and(|real| {
                path.file_name() == Some(f.as_ref())
                    && path.parent().and_then(Path::parent) == Some(&real)
            }) || entry(d, Some(f))
        }
        Target::Tree(d) => real(d).is_some_and(|real| path.starts_with(real)),
        _ => false,
    }
}

/// What to check for a change at `p`. Inside a folder that discovery passes
/// over, `Scan::changed` reads only known locations and the files rules name
/// in a repository's `.git`, and checking the outermost such folder reads all
/// of those. So a build that writes thousands of files there is one change of
/// that folder. Any other path is checked as it is.
pub fn change_at(home: &Path, p: &Path) -> PathBuf {
    let Ok(below) = p.strip_prefix(home) else {
        return p.to_path_buf();
    };
    // From `p` upwards, so the last match is the outermost.
    let left_out = below
        .ancestors()
        .filter(|a| EXCLUDED.iter().any(|name| a.ends_with(name)))
        .last();
    left_out.map_or_else(|| p.to_path_buf(), |a| home.join(a))
}

/// A folder the person asks not to be checked: absolute, with no "..", and
/// never the home folder or a folder above it.
pub fn skipped_folder(path: &OsStr, home: &Path) -> Result<PathBuf, &'static str> {
    let path = selected_root(path)?;
    if home.starts_with(&path) {
        return Err("the home folder, or a folder above it, cannot be skipped");
    }
    Ok(path)
}

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
    /// How long a cancellable scan may run.
    limit: Duration,
    /// How long a cancellable scan may spend reading one record through.
    record_time: Duration,
    /// Folders the person asked not to be checked.
    skip: Vec<PathBuf>,
    /// Times a reader said it did not read because the scan was stopped,
    /// also when the list of gaps was full.
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

/// Where to cut a line too long to hold whole: after the last byte near its
/// end that no token format contains and that says nothing about where the
/// next one starts, so that no token is cut in two there. "[" and ";" are
/// not such bytes: a colour code before a token has them. A run with no such
/// byte, as in encoded binary data, is cut short of its end, and a token
/// across that place can be missed.
fn long_line_cut(carry: &[u8]) -> usize {
    let near = carry.len().saturating_sub(4096);
    carry[near..]
        .iter()
        .rposition(|b| b" \t\"'{}]()<>:&%|?#@".contains(b))
        .map_or(carry.len().saturating_sub(512), |at| near + at + 1)
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
        }
    }

    /// Check every known location, before any discovery.
    fn known(&mut self) {
        self.known_files(0, false);
        for (rule, dir) in trees() {
            self.tree(rule, dir);
        }
    }

    /// The known locations that are one file or one folder's worth of files:
    /// all but the trees of agent records, which can take long. `from` is how
    /// many of them an earlier slice of a sweep did. A sweep can `resume`:
    /// once it is stopped, the count of those done is returned, and the rest
    /// is left for its next slice. Any other scan goes through all of them,
    /// each recording that it was not read.
    fn known_files(&mut self, from: usize, resume: bool) -> Option<usize> {
        enum Place {
            Dir(&'static str),
            Target(&'static Rule, Target),
            Extensions,
        }
        let mut dirs = Vec::new();
        for target in RULES.iter().flat_map(|r| r.targets) {
            if let Target::Dir(d) = *target {
                if !dirs.contains(&d) {
                    dirs.push(d);
                }
            }
        }
        let targets = RULES
            .iter()
            .flat_map(|rule| rule.targets.iter().map(move |t| Place::Target(rule, *t)));
        let places = dirs.into_iter().map(Place::Dir).chain(targets);
        for (done, place) in places.chain([Place::Extensions]).enumerate().skip(from) {
            if resume && self.stopped() {
                return Some(done);
            }
            match place {
                Place::Dir(d) => self.dir(d),
                Place::Target(rule, Target::File(f)) => {
                    if let Some(p) = self.targeted(&self.home.join(f)) {
                        self.whole(rule, &p);
                    }
                }
                Place::Target(rule, Target::Each(parent, file)) => self.each(rule, parent, file),
                Place::Target(rule, Target::Profiles(file)) => {
                    for parent in CHROMIUM {
                        // Some browsers keep one profile at the top level.
                        if let Some(p) = self.targeted(&self.home.join(parent).join(file)) {
                            self.whole(rule, &p);
                        }
                        self.each(rule, parent, file);
                    }
                }
                Place::Target(rule, Target::Present(at, what)) => {
                    self.present(rule, &self.home.join(at), what)
                }
                Place::Target(..) => {}
                Place::Extensions => self.extensions(),
            }
            // A place that was being read when the scan stopped is read
            // again by the next slice. Unless it was this slice's first and
            // nothing cancelled it: it had its whole time and a scan's worth
            // of findings to itself, and would hold every later slice too.
            let cancelled = self.cancel.as_ref();
            let cancelled = cancelled.is_some_and(|c| c.load(Ordering::SeqCst));
            if resume && self.stopped() && (cancelled || done > from) {
                return Some(done);
            }
        }
        None
    }

    /// Report a file or folder that is there. Nothing in it is read.
    fn present(&mut self, rule: &Rule, at: &Path, what: &str) {
        if let Some(real) = self.targeted(at) {
            if std::fs::symlink_metadata(&real).is_ok() {
                self.add(rule, &real, Hit::file().about(what), false, &[]);
            }
        }
    }

    /// Report the storage folders of listed browser extensions, by their IDs.
    fn extensions(&mut self) {
        for parent in CHROMIUM {
            let Some(dir) = self.targeted(&self.home.join(parent)) else {
                continue;
            };
            let mut remaining = 10_000;
            let Ok(profiles) = list_dir(&dir, false, &mut remaining) else {
                continue;
            };
            self.counts.entries += 10_000 - remaining;
            self.stores(&dir, profiles.entries, false);
        }
    }

    /// As `extensions`, for the one browser's folder `dir` and these
    /// `profiles` listed of it. A check of what `changed` ends at the
    /// profile it is stopped at: the ones after it are not looked in.
    fn stores(&mut self, dir: &Path, profiles: Vec<(PathBuf, bool)>, changed: bool) {
        let wanted: Vec<(&Rule, &str, &str)> = RULES
            .iter()
            .flat_map(|r| r.targets.iter().map(move |t| (r, t)))
            .filter_map(|(r, t)| match *t {
                Target::Extension(id, what) => Some((r, id, what)),
                _ => None,
            })
            .collect();
        // Some browsers keep one profile at the top level.
        let top = std::iter::once((dir.to_path_buf(), true));
        for (profile, is_dir) in top.chain(profiles) {
            if changed && self.stopped() {
                self.unread_once(dir);
                break;
            }
            for &(rule, id, what) in wanted.iter().filter(|_| is_dir) {
                let store = profile.join("Local Extension Settings").join(id);
                if std::fs::symlink_metadata(&store).is_ok_and(|m| m.is_dir()) {
                    self.add(rule, &store, Hit::file().about(what), false, &[]);
                }
            }
        }
    }

    /// For a check of changes: the entries of the browser's folder `dir`,
    /// in each of which rules name a file or a folder. A check that walks
    /// what changed has the entries it may list and its time to do so, and
    /// this is part of it: the folder is listed once a check, out of those
    /// entries and 10,000 names at most, and not once the check is stopped.
    /// A folder not listed, or not to its end, is a gap, said once. Where
    /// the check's own limits kept it from that, the changed path is also
    /// left unfinished: a profile not looked in may hold what a rule names.
    fn profiles(&mut self, dir: &Path) -> Vec<(PathBuf, bool)> {
        if !self.profiles.contains_key(dir) {
            if self.stopped() {
                self.unread_once(dir);
                return Vec::new();
            }
            let before = self.traversal.remaining;
            let listing = list_dir(dir, false, &mut self.traversal.remaining);
            self.counts.entries += before - self.traversal.remaining;
            let mut entries = Vec::new();
            // Stopped by a limit of this check, not one any scan reaches.
            let mut cut = false;
            match listing {
                Ok(listing) => {
                    if let Some(g) = listing.gap {
                        self.gap(dir, g);
                        // The budget ran out, not the fixed 10,000-entry
                        // limit per folder.
                        cut = g == "scan-limit" && listing.entries.len() < 10_000;
                    }
                    entries = listing.entries;
                }
                Err(g) => self.gap(dir, g),
            }
            self.profiles.insert(dir.to_path_buf(), (entries, cut));
        }
        let (entries, cut) = &self.profiles[dir];
        let (entries, cut) = (entries.clone(), *cut);
        self.work_unfinished |= cut;
        entries
    }

    /// As `each` for a browser's profiles, in a check of changes: the file
    /// named `file` in each entry `profiles` gives of the folder `dir`, as
    /// far as the check is not stopped.
    fn each_profile(&mut self, rule: &Rule, dir: &Path, file: &str) {
        // A profile folder may itself be a link, so every entry is tried.
        for (p, _) in self.profiles(dir) {
            if self.stopped() {
                self.unread_once(dir);
                break;
            }
            if let Some(p) = self.targeted(&p.join(file)) {
                self.whole(rule, &p);
            }
        }
    }

    /// As `unread`, of a folder the rules come to more than once in one
    /// check of changes: it is said once, and each time leaves the changed
    /// path unfinished.
    fn unread_once(&mut self, dir: &Path) {
        let path = self.rel(dir);
        let said = |g: &NotChecked| g.reason == "scan-limit" && g.path == path;
        if self.not_checked.iter().any(said) {
            self.work_unfinished = true;
        } else {
            self.unread(dir);
        }
    }

    /// Whether `p` is where a Chromium-family browser keeps the storage of
    /// the extension `id`: in a profile, or at the top of a browser's folder
    /// when it has one profile there. Any other folder with that name is not.
    /// The browser's folder is as it is named, or where a link puts it.
    fn extension_store(&mut self, p: &Path, id: &str) -> bool {
        let named = |p: &Path, name: &str| p.file_name() == Some(name.as_ref());
        let settings = p.parent().filter(|_| named(p, id));
        let profile = settings
            .filter(|s| named(s, "Local Extension Settings"))
            .and_then(Path::parent);
        profile.is_some_and(|profile| {
            CHROMIUM.iter().any(|browser| {
                let at = self.home.join(browser);
                let real = self.targeted(&at);
                [Some(at), real]
                    .iter()
                    .flatten()
                    .any(|browser| profile == browser || profile.parent() == Some(browser))
            })
        })
    }

    /// The real places at or under the changed path `p` of `file` in the
    /// entries of the known folder `dir` that a link leads to: the entry is
    /// a link, or the file in it is. With no `file`, of the entries
    /// themselves. A change is reported at the real place, and only the
    /// folder says which places those are. It is listed once a check, out
    /// of the entries the check may list and 10,000 names at most, and not
    /// once the check is stopped. Nothing is opened: a link is resolved as
    /// `targeted` resolves it, inside the home folder only and never as
    /// root. A folder that could not be listed is a gap. One the check's
    /// own limits kept from being looked at in full also leaves unfinished
    /// every path asked about: a link not looked at may lead to it.
    fn linked_targets(&mut self, dir: &Path, file: &'static str, p: &Path) -> Vec<PathBuf> {
        let key = (dir.to_path_buf(), file);
        if !self.linked_target_cache.contains_key(&key) {
            let mut real = Vec::new();
            let mut gap = None;
            // Stopped by a limit of this check, not one any scan reaches.
            let mut cut = false;
            if is_root() {
                // No link is followed, so none leads anywhere.
            } else if self.stopped() {
                // Not said of a folder that is not there, as in `unread`.
                let gone = |e: std::io::Error| e.kind() == std::io::ErrorKind::NotFound;
                cut = !std::fs::symlink_metadata(dir).is_err_and(gone);
            } else {
                let before = self.traversal.remaining;
                let listing = list_dir(dir, false, &mut self.traversal.remaining);
                self.counts.entries += before - self.traversal.remaining;
                let entries = match listing {
                    Ok(listing) => {
                        gap = listing.gap;
                        // The budget ran out, not the fixed 10,000-entry
                        // limit per folder.
                        cut = gap == Some("scan-limit") && listing.entries.len() < 10_000;
                        listing.entries
                    }
                    Err(g) => {
                        gap = Some(g);
                        Vec::new()
                    }
                };
                let link = |p: &Path| {
                    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink())
                };
                for (entry, is_dir) in entries {
                    if self.stopped() {
                        cut = true;
                        break;
                    }
                    let at = match file {
                        "" => entry.clone(),
                        file => entry.join(file),
                    };
                    if link(if is_dir { &at } else { &entry }) {
                        if let Some(Ok(to)) = through_links(&at, &self.home) {
                            real.push(to);
                        }
                    }
                }
            }
            // Said once of a folder asked about for two file names.
            for reason in [gap, cut.then_some("scan-limit")].into_iter().flatten() {
                let path = self.rel(dir);
                let said = |g: &NotChecked| g.reason == reason && g.path == path;
                if !self.not_checked.iter().any(said) {
                    // Said of the folder, not by a known place at the
                    // changed path: a stopped check still names that path.
                    let unread = self.unread;
                    self.gap(dir, reason);
                    self.unread = unread;
                }
            }
            self.linked_target_cache.insert(key.clone(), (real, !cut));
        }
        let (real, whole) = &self.linked_target_cache[&key];
        let led = real.iter().filter(|to| to.starts_with(p)).cloned();
        let (led, whole) = (led.collect(), *whole);
        self.work_unfinished |= !whole;
        led
    }

    /// Read every file under a folder in full.
    fn tree(&mut self, rule: &Rule, dir: &'static str) {
        if let Some(root) = self.targeted(&self.home.join(dir)) {
            self.tree_from(rule, root, 0, None);
        }
    }

    /// As `tree`, from a folder `depth` levels below the tree's root. With
    /// `after`, that folder's subfolders are already queued and its files up
    /// to that one already read. Returns the folders not finished when the
    /// scan was stopped, in those three parts, for a later slice of a sweep.
    fn tree_from(
        &mut self,
        rule: &Rule,
        start: PathBuf,
        depth: usize,
        after: Option<PathBuf>,
    ) -> Vec<(PathBuf, usize, Option<PathBuf>)> {
        let mut queue = VecDeque::from([(start, depth, after)]);
        let mut remaining = TREE_ENTRIES;
        // One gap for the tree, at the first folder too deep to read.
        let mut too_deep = false;
        while let Some((dir, depth, after)) = queue.pop_front() {
            if self.stopped() {
                let said = self.unread;
                self.unread(&dir);
                if self.unread == said {
                    // Gone: nothing of it is unread, but the next may be.
                    continue;
                }
                queue.push_front((dir, depth, after));
                break;
            }
            let before = remaining;
            let listing = list_dir(&dir, false, &mut remaining);
            self.counts.entries += before - remaining;
            let entries = match listing {
                Ok(e) => e,
                Err(g) => {
                    self.gap(&dir, g);
                    continue;
                }
            };
            if let Some(g) = entries.gap {
                self.gap(&dir, g);
            }
            // Subfolders first, so a walk stopped among the files has them all.
            let (folders, files): (Vec<_>, Vec<_>) =
                entries.entries.into_iter().partition(|(_, is_dir)| *is_dir);
            for (p, _) in folders.into_iter().filter(|_| after.is_none()) {
                if !self.skipped(&p)
                    && !EXCLUDED.iter().any(|name| p.ends_with(name))
                    && !TREE_SKIP
                        .iter()
                        .any(|name| p.file_name() == Some(name.as_ref()))
                {
                    if depth < TREE_DEPTH {
                        queue.push_back((p, depth + 1, None));
                    } else if !std::mem::replace(&mut too_deep, true) {
                        self.gap(&p, "scan-limit");
                    }
                }
            }
            // Files come sorted, and each is below the folder's own path.
            let mut read = after.unwrap_or_else(|| dir.clone());
            for (p, _) in files {
                if p <= read {
                    continue;
                }
                let stopped = self.stopped();
                if stopped {
                    self.gap(&dir, "scan-limit");
                    self.work_unfinished = true;
                }
                if stopped || !self.stream(rule, &p) {
                    queue.push_front((dir, depth, Some(read)));
                    return queue.into();
                }
                read = p;
            }
        }
        queue.into()
    }

    /// Read one file from start to end in pieces that end at a line break,
    /// reporting each distinct secret once, at its first appearance. A session
    /// record repeats one token many times; two different tokens are two findings.
    /// Returns false when the scan was stopped before the file's end; a file
    /// that could not be read, or need not be, is done with.
    fn stream(&mut self, rule: &Rule, p: &Path) -> bool {
        let Matcher::Stream(test) = rule.matcher else {
            return true;
        };
        if !self.whole_files_checked.insert((rule.id, p.to_path_buf())) {
            return true;
        }
        if self.stopped() {
            self.whole_files_checked.remove(&(rule.id, p.to_path_buf()));
            self.gap(p, "scan-limit");
            self.work_unfinished = true;
            return false;
        }
        self.counts.config_attempts += 1;
        self.publish(false);
        let (file, len, shared) = match open_regular(p) {
            Ok(Some(opened)) => opened,
            Ok(None) => return true,
            Err(g) => {
                self.gap(p, g);
                return true;
            }
        };
        if len > STREAM_MAX {
            self.gap(p, "too-large");
            return true;
        }
        // Read as far as the file went when it was opened. What is added
        // while it is read is a later change, and following a file that
        // keeps growing would be a read with no limit.
        let mut file = file.take(len);
        let mut seen = HashSet::new();
        let (mut carry, mut line) = (Vec::new(), 1);
        let mut buffer = vec![0u8; 1024 * 1024];
        let (mut dropped, mut full) = (false, false);
        let begun = Instant::now();
        loop {
            let Ok(read) = file.read(&mut buffer) else {
                self.gap(p, "unreadable");
                return true;
            };
            // A file that was started is read to its end when only the time
            // is up: cut short, a large record would be cut short by every
            // slice of a sweep and never read. A cancel does stop it.
            if read > 0 && self.halted() {
                self.whole_files_checked.remove(&(rule.id, p.to_path_buf()));
                self.gap(p, "scan-limit");
                self.work_unfinished = true;
                return false;
            }
            // Text can be made slow to check, so one file gets only so long.
            // It is then done with, or it would hold every later slice too.
            if read > 0 && self.cancel.is_some() && begun.elapsed() >= self.record_time {
                self.gap(p, "scan-limit");
                return true;
            }
            carry.extend_from_slice(&buffer[..read]);
            // Test up to the last line break and keep the rest for the next
            // piece. A very long line is cut where no token is, if it can be.
            let cut = match carry.iter().rposition(|b| *b == b'\n') {
                _ if read == 0 => carry.len(),
                Some(end) => end + 1,
                None if carry.len() > 4 * buffer.len() => long_line_cut(&carry),
                None => 0,
            };
            if cut > 0 {
                let piece: Vec<u8> = carry.drain(..cut).collect();
                let hits = self.matcher_hits(p, test(&piece, line));
                for hit in hits {
                    // Only a hash of the bytes is kept, and only for this file.
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    hit.subject.hash(&mut hasher);
                    hit.span
                        .clone()
                        .and_then(|s| piece.get(s))
                        .hash(&mut hasher);
                    let value = hasher.finish();
                    if seen.contains(&value) {
                        continue;
                    }
                    // A record lists this many different tokens. One more
                    // is a limit reached, which is said once for the file.
                    if seen.len() == RECORD_HITS {
                        if !std::mem::replace(&mut full, true) {
                            self.matcher_gap(p, "scan-limit");
                        }
                        continue;
                    }
                    seen.insert(value);
                    dropped |= !self.add_from(rule, p, hit, shared, &[], Some(&piece));
                }
                line += piece.iter().filter(|b| **b == b'\n').count();
            }
            if read == 0 {
                // With a hit dropped, the file is not done with.
                return !dropped;
            }
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
                        let there = |root: &PathBuf| std::fs::symlink_metadata(root).is_ok();
                        if let Some(root) = root.filter(there) {
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

    /// The work of `changed`, for a scan made with its limits.
    fn changes(&mut self, paths: &[PathBuf]) -> Unreached {
        let s = self;
        let home = &s.home.clone();
        let mut unreached = Unreached::default();
        // Whether a path before this one began to use the check's limits.
        let mut shared = false;
        // Judged below the home only: the names above it are not the scan's.
        let excluded = |p: &Path| {
            p.strip_prefix(home).is_ok_and(|below| {
                below
                    .ancestors()
                    .any(|a| EXCLUDED.iter().any(|name| a.ends_with(name)))
            })
        };
        for p in paths {
            if !p.starts_with(home) || s.skipped(p) {
                continue;
            }
            // In an excluded folder, only what a full scan reads there: known
            // locations, and the files rules name in the `.git` of a
            // repository it would reach.
            let git = [Some(p.as_path()), p.parent()]
                .into_iter()
                .flatten()
                .find(|d| d.file_name() == Some(".git".as_ref()))
                .filter(|git| git.parent().is_some_and(|repo| !excluded(repo)));
            if s.stopped() {
                // Said only of what would have been read: in a `.git`, the
                // folder itself or a file a rule names there.
                let named = git.is_some_and(|git| {
                    let repo = RULES.iter().flat_map(|r| r.targets);
                    p == git
                        || repo.into_iter().any(
                            |t| matches!(*t, Target::Repo(f) if p.file_name() == Some(f.as_ref())),
                        )
                });
                // A known location says so itself: stopped, its rules read
                // nothing and record that they did not.
                let said = s.unread;
                s.work_unfinished = false;
                s.known_at(p, false);
                s.known_at(p, true);
                let known = s.unread > said;
                let meta = std::fs::symlink_metadata(p);
                let walked = meta.is_ok_and(|m| m.is_dir() || m.is_file()) && !excluded(p);
                // Not for a record too deep for any scan: that is said, and
                // checking it again would read no more.
                if walked || named || s.work_unfinished {
                    if !known {
                        s.gap(p, "scan-limit");
                    }
                    let cancelled = s.cancel.as_ref().is_some_and(|c| c.load(Ordering::SeqCst));
                    if cancelled {
                        unreached.cancelled.push(p.clone());
                    } else {
                        unreached.out_of_budget.push(p.clone());
                    }
                }
                continue;
            }
            s.work_unfinished = false;
            s.known_at(p, false);
            let meta = std::fs::symlink_metadata(p).ok().filter(|_| !excluded(p));
            // A file's head is read before it is read as a record: a record
            // once begun is read to its end, past the time, and the head
            // would then be left unread. The report keeps a full scan's
            // order, with what the record holds first.
            let file = meta.as_ref().is_some_and(|m| m.is_file());
            if !file {
                s.known_at(p, true);
            }
            let (found, gaps) = (s.findings.len(), s.not_checked.len());
            if let Some(git) = git {
                s.repo(git, (p != git).then(|| p.file_name()).flatten());
            }
            let mut begun = true;
            match meta {
                Some(m) if m.is_dir() => {
                    // With no entries left to list, the walk is not begun;
                    // the known locations above were read.
                    begun = s.work_unfinished || s.traversal.remaining > 0;
                    s.discover(p, vec![(p.clone(), 0)]);
                }
                Some(_) if file && !p.ends_with(ASKS) => s.check_head(p, Target::Discovery),
                _ => {}
            }
            if file {
                let head = (s.findings.len() - found, s.not_checked.len() - gaps);
                s.known_at(p, true);
                s.findings[found..].rotate_left(head.0);
                s.not_checked[gaps..].rotate_left(head.1);
            }
            if s.work_unfinished {
                let cancelled = s.cancel.as_ref().is_some_and(|c| c.load(Ordering::SeqCst));
                if cancelled {
                    unreached.cancelled.push(p.clone());
                } else if begun && !shared {
                    unreached.cut_short.push(p.clone());
                } else {
                    unreached.out_of_budget.push(p.clone());
                }
            }
            shared = true;
        }
        unreached
    }

    /// Run the rules for any known location that is `p`, is inside `p`, or is
    /// a link that leads to `p`: the trees of agent records, or all others.
    fn known_at(&mut self, p: &Path, records: bool) {
        // A folder is checked once, by every rule that names it.
        let mut dirs = Vec::new();
        // The extensions' storage is looked for once, for every rule's.
        let mut extensions = false;
        let named = |file: &str| p.file_name() == Some(file.as_ref());
        // A known folder: as it is named, and where a link puts it, which
        // is where a change in it is reported.
        type Folder = [Option<PathBuf>; 2];
        fn is(path: Option<&Path>, folder: &Folder) -> bool {
            path.is_some_and(|path| folder.iter().flatten().any(|f| f == path))
        }
        // At the changed path or under it.
        let under = |folder: &Folder| folder.iter().flatten().any(|f| f.starts_with(p));
        // A link leads to nothing at a path that is not there or is itself
        // a link, so no folder is looked at for one.
        let leads =
            !records && std::fs::symlink_metadata(p).is_ok_and(|m| !m.file_type().is_symlink());
        let mut browsers: Vec<Folder> = Vec::new();
        for browser in CHROMIUM.iter().filter(|_| !records) {
            let at = self.home.join(browser);
            let real = self.targeted(&at);
            browsers.push([Some(at), real]);
        }
        for rule in RULES {
            for target in rule.targets {
                if matches!(target, Target::Tree(_)) != records {
                    continue;
                }
                match *target {
                    Target::File(f) => {
                        let at = self.home.join(f);
                        let real = self.targeted(&at);
                        let above = |real: &PathBuf| real.starts_with(p);
                        if at.starts_with(p) || real.as_ref().is_some_and(above) {
                            if let Some(real) = real {
                                self.whole(rule, &real);
                            }
                        }
                    }
                    Target::Each(parent, file) => {
                        let at = self.home.join(parent);
                        let real = self.targeted(&at);
                        let folder = [Some(at), real.clone()];
                        // The folder or one above it, an entry of it, or
                        // the file in one.
                        let inside = under(&folder)
                            || is(p.parent(), &folder)
                            || (named(file) && is(p.parent().and_then(Path::parent), &folder));
                        // Or where a link in the folder leads.
                        let led = |s: &mut Scan, real| !s.linked_targets(real, file, p).is_empty();
                        let real = real.as_deref().filter(|_| leads);
                        if inside || real.is_some_and(|real| led(self, real)) {
                            self.each(rule, parent, file);
                        }
                    }
                    Target::Profiles(file) => {
                        for (browser, folder) in CHROMIUM.iter().zip(&browsers) {
                            let top = self.targeted(&self.home.join(browser).join(file));
                            if under(folder) {
                                // The browser's folder or one above it, as
                                // when it is moved into place: all of it.
                                if let Some(top) = top {
                                    self.whole(rule, &top);
                                }
                                if let Some(dir) = &folder[1] {
                                    self.each_profile(rule, dir, file);
                                }
                                continue;
                            }
                            // Only what a scan reads there: the file at the
                            // top, or in a profile. A profile's folder is
                            // one change when it is moved in as a whole;
                            // what changes in it is reported file by file.
                            let mut read = Vec::new();
                            read.extend(top.filter(|top| top.starts_with(p)));
                            if is(p.parent(), folder) {
                                read.extend(self.targeted(&p.join(file)));
                            } else if named(file) && is(p.parent().and_then(Path::parent), folder) {
                                read.extend(self.targeted(p));
                            }
                            // Or where a link in the folder leads.
                            if let Some(real) = folder[1].as_ref().filter(|_| leads) {
                                read.extend(self.linked_targets(real, file, p));
                            }
                            for file in read {
                                self.whole(rule, &file);
                            }
                        }
                    }
                    Target::Present(at, what) => {
                        let at = self.home.join(at);
                        let real = self.targeted(&at);
                        let there = |at: &PathBuf| at.starts_with(p) || p.starts_with(at);
                        if there(&at) || real.as_ref().is_some_and(there) {
                            self.present(rule, &at, what);
                        }
                    }
                    Target::Extension(id, what) => {
                        if browsers.iter().any(under) {
                            // A browser's folder or one above it: every
                            // profile's storage in each such browser, as a
                            // scan looks for it, within this check's limits.
                            if !std::mem::replace(&mut extensions, true) {
                                for folder in browsers.iter().filter(|f| under(f)) {
                                    if let Some(dir) = &folder[1] {
                                        let profiles = self.profiles(dir);
                                        self.stores(dir, profiles, true);
                                    }
                                }
                            }
                            continue;
                        }
                        // The storage itself, or the folder it is in or the
                        // profile that is in: a folder moved into place.
                        let folder =
                            |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir());
                        let settings = "Local Extension Settings";
                        for store in [p.to_path_buf(), p.join(id), p.join(settings).join(id)] {
                            if self.extension_store(&store, id) && folder(p) && folder(&store) {
                                self.add(rule, &store, Hit::file().about(what), false, &[]);
                            }
                        }
                    }
                    Target::Tree(dir) => {
                        let at = self.home.join(dir);
                        // The tree as it is named, or where a link puts it:
                        // a change is reported at the real path.
                        let real = self.targeted(&at);
                        if at.starts_with(p) || real.as_ref().is_some_and(|r| r.starts_with(p)) {
                            self.tree(rule, dir);
                            continue;
                        }
                        let mut roots = [Some(at), real].into_iter().flatten();
                        let root = roots.find(|root| p.starts_with(root));
                        if let Some(at) = root {
                            // Only what `tree` reaches from the root: a file
                            // or a folder of them, not under a folder it skips.
                            let Ok(meta) = std::fs::symlink_metadata(p) else {
                                continue;
                            };
                            let below = p.strip_prefix(&at).unwrap_or(p);
                            let is_dir = meta.is_dir();
                            let folders = if is_dir { Some(below) } else { below.parent() };
                            let depth = folders.map_or(0, |d| d.components().count());
                            let passed = folders.into_iter().flat_map(Path::ancestors).any(|d| {
                                EXCLUDED.iter().any(|name| at.join(d).ends_with(name))
                                    || TREE_SKIP
                                        .iter()
                                        .any(|name| d.file_name() == Some(name.as_ref()))
                            });
                            if passed {
                                continue;
                            }
                            if depth > TREE_DEPTH {
                                self.gap(p, "scan-limit");
                                continue;
                            }
                            if is_dir {
                                self.tree_from(rule, p.to_path_buf(), depth, None);
                            } else if meta.is_file() {
                                self.stream(rule, p);
                            }
                        }
                    }
                    Target::Dir(d) => {
                        if dirs.contains(&d) {
                            continue;
                        }
                        dirs.push(d);
                        let at = self.home.join(d);
                        let real = self.targeted(&at);
                        if at.starts_with(p) || real.as_ref().is_some_and(|r| r.starts_with(p)) {
                            self.dir(d);
                        } else if p.parent() == Some(&at) || p.parent() == real.as_deref() {
                            if let Some(real) = self.targeted(p) {
                                self.check_head(&real, Target::Dir(d));
                            }
                        } else if let Some(real) = real.filter(|_| leads) {
                            // Or where a link in the folder leads.
                            for to in self.linked_targets(&real, "", p) {
                                self.check_head(&to, Target::Dir(d));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
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
            coverage: Some(report::Coverage {
                roots: roots.iter().map(|p| s.rel(p)).collect(),
                excluded_directories: EXCLUDED,
                excluded_by_user: s.skip.iter().map(|p| s.rel(p)).collect(),
                limitations: report::LIMITATIONS,
            }),
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
        if self.cancel.is_some() && self.not_checked.len() >= 4096 {
            return;
        }
        let path = self.rel(p);
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
    /// link is something another user could have placed. Otherwise it is a gap.
    fn targeted(&mut self, p: &Path) -> Option<PathBuf> {
        if let Some(known) = self.links.get(p) {
            return known.clone();
        }
        let real = match through_links(p, &self.home) {
            None => Some(p.to_path_buf()),
            Some(Ok(real)) if !is_root() => Some(real),
            Some(_) => {
                self.gap(p, "symlink");
                None
            }
        };
        self.links.insert(p.to_path_buf(), real.clone());
        real
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
        let advice = hit.advice.unwrap_or(&rule.advice);
        let (mut kind, mut reason) = (rule.kind, rule.reason.map(String::from));
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
        self.findings.push(Finding {
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
            explanation: rule.explanation,
            reason,
            next_step: rule.next_step,
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

    /// Read a file's head, recording a gap if it is in scope but unreadable.
    fn head(&mut self, p: &Path, max: u64) -> Option<crate::fsutil::Head> {
        if self.stopped() {
            self.unread(p);
            return None;
        }
        self.counts.header_attempts += 1;
        self.tick();
        match read_head(p, max) {
            Ok(h) => h,
            // One gap per folder: a synced folder can hold thousands of these.
            Err("cloud-only-file") => {
                let dir = p.parent().unwrap_or(p).to_path_buf();
                if self.cloud_dir.as_ref() != Some(&dir) {
                    self.gap(&dir, "cloud-only-file");
                    self.cloud_dir = Some(dir);
                }
                None
            }
            Err(g) => {
                self.gap(p, g);
                None
            }
        }
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

    /// Walk a root breadth-first from `start`, so the work budget is spent on
    /// shallow folders everywhere before deep ones anywhere. When the budget,
    /// time or a cancel ends the walk, the unvisited folders are kept in
    /// `pending` and each top-level folder holding some gets one gap.
    fn discover(&mut self, root: &Path, start: Vec<(PathBuf, usize)>) {
        let mut walk = Walk::new(start);
        while let Some((dir, depth)) = walk.next() {
            let spent =
                self.traversal.remaining == 0 && !self.traversal.completed.contains_key(&dir);
            if self.stopped() || spent {
                self.work_unfinished = true;
                walk.stop(dir, depth);
                break;
            }
            if depth > 64 {
                self.gap(&dir, "scan-limit");
                continue;
            }
            let visit = match self.traversal.completed.get(&dir) {
                Some(known) => Visit {
                    folders: known.clone(),
                    ..Visit::default()
                },
                // Only a root must still exist when it is reached.
                None => self.visit(&dir, depth == 0),
            };
            self.work_unfinished |= visit.interrupted;
            self.traversal.record(&dir, &visit);
            walk.visited(&dir, depth, visit, |child| {
                depth == 0
                    && root == self.home
                    && LAST
                        .iter()
                        .any(|name| child.file_name() == Some(name.as_ref()))
            });
        }
        let unreached = walk.unfinished();
        let mut tops: Vec<PathBuf> = unreached
            .iter()
            .map(|(dir, _)| {
                match dir
                    .strip_prefix(root)
                    .ok()
                    .and_then(|r| r.components().next())
                {
                    Some(first) => root.join(first),
                    None => root.to_path_buf(),
                }
            })
            .collect();
        tops.sort_unstable();
        tops.dedup();
        for top in tops {
            let path = self.rel(&top);
            if !self
                .not_checked
                .iter()
                .any(|g| g.reason == "scan-limit" && g.path == path)
            {
                self.gap(&top, "scan-limit");
            }
        }
        self.traversal.defer(unreached);
    }

    /// List one folder and check its files. Returns its subfolders. A
    /// `required` folder that is not there is a gap.
    fn visit(&mut self, dir: &Path, required: bool) -> Visit {
        let before = self.traversal.remaining;
        let gaps_before = self.not_checked.len();
        let after = self.traversal.take_checkpoint(dir);
        let mut interrupted = false;
        // Every slice that comes back to this folder lists it again before
        // the first entry left in it, so the listing counts as part of that
        // entry's time.
        let mut listed = Some(self.started.elapsed());
        let listing = list_dir(dir, required, &mut self.traversal.remaining);
        self.counts.entries += before - self.traversal.remaining;
        self.publish(false);
        let entries = match listing {
            Ok(e) => e,
            Err(g) => {
                self.gap(dir, g);
                return Visit::default();
            }
        };
        if let Some(g) = entries.gap {
            self.gap(dir, g);
            // The budget ran out, not the fixed 10,000-entry limit per folder.
            interrupted = g == "scan-limit" && entries.entries.len() < 10_000;
        }
        // A listing the budget cut is some of the entries, in no order: the
        // place reached in it says nothing about the ones it left out.
        let ordered = !interrupted;
        let mut reached = after.clone();
        let mut subfolders = Vec::new();
        let mut entries = entries.entries.into_iter().peekable();
        while let Some((p, is_dir)) = entries.next() {
            // Done by an earlier slice, its subfolders passed on then.
            if after.as_ref().is_some_and(|a| p <= *a) {
                continue;
            }
            if self.stopped() {
                self.gap(dir, "scan-limit");
                interrupted = true;
                break;
            }
            let began = listed.take().unwrap_or_else(|| self.started.elapsed());
            let held = self.findings.len();
            let left = std::mem::replace(&mut self.work_unfinished, false);
            let skipped = is_dir && self.skipped(&p);
            // macOS denies reads of this per-container bookkeeping file; it
            // never holds credentials, so it would only add a gap.
            let denied = ".com.apple.containermanagerd.metadata.plist";
            if is_dir {
                if !skipped && p.file_name() == Some(".git".as_ref()) {
                    self.repo(&p, None);
                }
            } else if p.file_name() != Some(denied.as_ref()) && !p.ends_with(ASKS) {
                self.check_head(&p, Target::Discovery);
            }
            let dropped = std::mem::replace(&mut self.work_unfinished, left);
            self.work_unfinished |= dropped;
            if dropped {
                // The stop came while this entry was checked, and some of
                // it was dropped: a sweep's next slice checks it again.
                // Unless the entry had the slice to itself and would end
                // every later one the same way: it filled the findings one
                // scan keeps from none, or the time was up though it had
                // begun in the first half of it. Then it is done, with the
                // gap it was given. A full list of gaps may not have kept
                // that gap, and then nothing would say what was dropped.
                let cancelled = self.cancel.as_ref();
                let cancelled = cancelled.is_some_and(|c| c.load(Ordering::SeqCst));
                let unsaid = self.not_checked.len() >= 4096;
                let alone = if self.findings.len() >= 4096 {
                    held == 0
                } else {
                    self.started.elapsed() >= self.limit && began < self.limit / 2
                };
                // Only a sweep comes back to the folder. Any other scan
                // meets the stop, if it still holds, at the next entry.
                if self.traversal.resumable() && (cancelled || unsaid || !alone) {
                    // As when the stop is met at the entry after this one.
                    if entries.peek().is_some() {
                        self.gap(dir, "scan-limit");
                    }
                    interrupted = true;
                    break;
                }
            }
            if ordered {
                reached = Some(p.clone());
            }
            if is_dir && !EXCLUDED.iter().any(|name| p.ends_with(name)) && !skipped {
                subfolders.push(p);
            }
        }
        Visit {
            folders: subfolders,
            interrupted,
            last_entry: reached.filter(|_| interrupted),
            complete: self.not_checked.len() == gaps_before && after.is_none(),
        }
    }

    /// Check the files that rules name inside a repository's `.git` folder,
    /// or just `only` when one file there changed. The folder is never walked:
    /// it holds every past version of the project, not what is in use now.
    fn repo(&mut self, git: &Path, only: Option<&OsStr>) {
        for rule in RULES {
            for target in rule.targets {
                if let Target::Repo(file) = *target {
                    if only.is_none_or(|name| name == file) {
                        self.whole(rule, &git.join(file));
                    }
                }
            }
        }
    }

    /// Run every rule with this target against one file.
    fn check_head(&mut self, p: &Path, target: Target) {
        let Some(h) = self.head(p, HEADER) else {
            return;
        };
        let name = p.file_name().unwrap_or_default();
        for rule in RULES {
            // A file a rule names, or one in a folder a rule covers, is read
            // whole, whatever its head holds.
            let named = target == Target::Discovery && rule.targets.iter().any(|t| t.names(name));
            if !named && !rule.targets.contains(&target) {
                continue;
            }
            let all = named || matches!(target, Target::Dir(_));
            match rule.matcher {
                Matcher::Head(m) if m(&h.bytes) => {
                    if self.fingerprint.is_some() {
                        if let Some(full) = self.config(p) {
                            self.add(rule, p, Hit::file(), full.shared, &full.bytes);
                        } else {
                            self.add(rule, p, Hit::file(), h.shared, &h.bytes);
                        }
                    } else {
                        self.add(rule, p, Hit::file(), h.shared, &h.bytes);
                    }
                }
                Matcher::Whole { candidate, .. } if candidate(&h.bytes) => self.whole(rule, p),
                // The head is the whole file: no second read is needed.
                Matcher::Whole { test, .. } if all && (h.bytes.len() as u64) < HEADER => {
                    if self.whole_files_checked.insert((rule.id, p.to_path_buf())) {
                        let hits = self.matcher_hits(p, test(&h.bytes));
                        for hit in hits {
                            self.add(rule, p, hit, h.shared, &h.bytes);
                        }
                    }
                }
                Matcher::Whole { .. } if all => {
                    // Files named only by a pattern are common. One too large
                    // to read whole is passed over, not reported as a gap.
                    let loosely = rule.targets.iter().any(|t| t.names_loosely(name));
                    let large = std::fs::symlink_metadata(p).is_ok_and(|m| m.len() > CONFIG_MAX);
                    if !(loosely && large) {
                        self.whole(rule, p);
                    }
                }
                _ => {}
            }
        }
    }

    /// Read the whole file and record each hit, or a gap.
    fn whole(&mut self, rule: &Rule, p: &Path) {
        let Matcher::Whole { test, .. } = rule.matcher else {
            return;
        };
        if !self.whole_files_checked.insert((rule.id, p.to_path_buf())) {
            return;
        }
        let Some(h) = self.config(p) else {
            if self.stopped() {
                self.whole_files_checked.remove(&(rule.id, p.to_path_buf()));
            }
            return;
        };
        let h = match settled(p, h) {
            Ok(Some(h)) => h,
            Ok(None) => return,
            Err(g) => return self.gap(p, g),
        };
        let hits = self.matcher_hits(p, test(&h.bytes));
        for hit in hits {
            self.add(rule, p, hit, h.shared, &h.bytes);
        }
    }

    /// An incomplete matcher still has findings worth reporting. Its fixed
    /// per-file limit is a gap, not unfinished work to retry in another slice.
    fn matcher_hits(&mut self, path: &Path, result: crate::rules::Hits) -> Vec<Hit> {
        match result {
            Ok(hits) => hits,
            Err(incomplete) => {
                self.matcher_gap(path, incomplete.reason);
                incomplete.hits
            }
        }
    }

    fn matcher_gap(&mut self, path: &Path, reason: Gap) {
        // A streamed file can hit both the matcher's and the record's cap,
        // or reach the cap in several pieces. Report that limit once.
        if reason == "scan-limit" {
            let shown = self.rel(path);
            if self
                .not_checked
                .iter()
                .any(|gap| gap.reason == reason && gap.path == shown)
            {
                return;
            }
        }
        self.gap(path, reason);
    }

    /// Check one named file in each direct subfolder, such as browser profiles.
    fn each(&mut self, rule: &Rule, parent: &'static str, file: &'static str) {
        let Some(dir) = self.targeted(&self.home.join(parent)) else {
            return;
        };
        if self.stopped() {
            return self.unread(&dir);
        }
        let mut remaining = 10_000;
        let listing = list_dir(&dir, false, &mut remaining);
        self.counts.entries += 10_000 - remaining;
        let entries = match listing {
            Ok(e) => e,
            Err(g) => return self.gap(&dir, g),
        };
        if let Some(g) = entries.gap {
            self.gap(&dir, g);
        }
        // A profile folder may itself be a link, so every entry is tried.
        for (p, _) in entries.entries {
            if let Some(p) = self.targeted(&p.join(file)) {
                self.whole(rule, &p);
            }
        }
    }

    fn dir(&mut self, name: &'static str) {
        let Some(dir) = self.targeted(&self.home.join(name)) else {
            return;
        };
        if self.stopped() {
            return self.unread(&dir);
        }
        let mut remaining = 10_000;
        let listing = list_dir(&dir, false, &mut remaining);
        self.counts.entries += 10_000 - remaining;
        let entries = match listing {
            Ok(e) => e,
            Err(g) => return self.gap(&dir, g),
        };
        if let Some(g) = entries.gap {
            self.gap(&dir, g);
        }
        for (p, _) in entries.entries {
            if self.stopped() {
                self.gap(&dir, "scan-limit");
                self.work_unfinished = true;
                break;
            }
            if let Some(p) = self.targeted(&p) {
                self.check_head(&p, Target::Dir(name));
            }
        }
    }

    fn config(&mut self, p: &Path) -> Option<crate::fsutil::Head> {
        if self.stopped() {
            self.unread(p);
            return None;
        }
        self.counts.config_attempts += 1;
        self.publish(false);
        match read_config(p, CONFIG_MAX) {
            Ok(h) => h,
            Err(g) => {
                self.gap(p, g);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::{Arc, Mutex};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new(name: &str) -> Self {
            let path = PathBuf::from(std::env::var_os("TMPDIR").expect("set TMPDIR"))
                .join(format!("credential-progress-{}-{name}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn matcher_limits_retain_hits_and_make_rechecks_unknown() {
        for (name, rule, limit) in [
            (".env", "secret.env-assignment", 100),
            ("passwords.txt", "export.password-note", 20),
            (".mcp.json", "dev.mcp.inline-secret", 100),
            (".pypirc", "dev.pypi.inline-credentials", 100),
            (".rclone.conf", "app.rclone.stored-secret", 100),
            (".config/rclone/rclone.conf", "app.rclone.stored-login", 100),
            (".dbt/profiles.yml", "dev.warehouse.inline-password", 100),
            ("profile.ovpn", "app.openvpn.embedded-key", 100),
            ("terraform.tfstate", "dev.terraform.state-secret", 100),
            (".zsh_history", "secret.service-token", 100),
            (".claude/session.jsonl", "secret.agent-record", 50),
        ] {
            let f = Fixture::new("matcher-limits");
            let path = f.0.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            for count in [limit, limit + 1, 201] {
                let body = match name {
                    ".mcp.json" => {
                        let servers: serde_json::Map<String, serde_json::Value> = (0..count)
                            .map(|i| {
                                (
                                    format!("server{i}"),
                                    serde_json::json!({"env": {"API_TOKEN": "synthetic-value"}}),
                                )
                            })
                            .collect();
                        serde_json::json!({"mcpServers": servers}).to_string()
                    }
                    "terraform.tfstate" => {
                        let outputs: serde_json::Map<String, serde_json::Value> = (0..count)
                            .map(|i| (format!("output{i}"), serde_json::json!({"value": "synthetic-value", "sensitive": true})))
                            .collect();
                        serde_json::json!({"terraform_version": "1.9.0", "outputs": outputs})
                            .to_string()
                    }
                    _ => (0..count)
                        .map(|i| match name {
                            ".env" => format!("SERVICE_{i}_TOKEN=synthetic-value-{i}\n"),
                            "passwords.txt" => {
                                format!("service {i} password: synthetic-value-{i}\n")
                            }
                            ".pypirc" => format!("[pypi-token]\nrepo{i}=synthetic-value-{i}\n"),
                            ".rclone.conf" => {
                                format!("[remote{i}]\ntype=sftp\npass=synthetic-value-{i}\n")
                            }
                            ".config/rclone/rclone.conf" => format!(
                                "[remote{i}]\ntype=drive\ntoken={{\"refresh_token\":\"synthetic-value-{i}\"}}\n"
                            ),
                            ".dbt/profiles.yml" => format!(
                                "private_key: \"-----BEGIN {}-----\\nsynthetic-{i}\\n\"\n",
                                "PRIVATE KEY"
                            ),
                            "profile.ovpn" => format!(
                                "<key>\n-----BEGIN {}-----\nsynthetic-{i}\n</key>\n",
                                "PRIVATE KEY"
                            ),
                            _ => format!("{}abcdeABCDE{i:026}\n", "ghp_"),
                        })
                        .collect(),
                };
                fs::write(&path, body).unwrap();
                let scan = Scan::run(&f.0, std::slice::from_ref(&f.0));
                let hits: Vec<_> = scan
                    .findings
                    .iter()
                    .filter(|hit| hit.rule == rule)
                    .collect();
                assert_eq!(hits.len(), count.min(limit), "{name}: {count}");
                let limited = count > limit;
                let gaps: Vec<_> = scan
                    .not_checked
                    .iter()
                    .filter(|gap| gap.reason == "scan-limit")
                    .collect();
                assert_eq!(gaps.len(), usize::from(limited), "{name}: {count}");
                if limited {
                    assert_eq!(gaps[0].path, format!("~/{name}"));
                }
                // Streamed rechecks can inspect more than the 50 reported
                // values, but must be unknown once their own matcher truncates.
                let recheck_limited = count
                    > if name == ".claude/session.jsonl" {
                        100
                    } else {
                        limit
                    };
                assert_eq!(
                    recheck(rule, &path, &f.0, None).is_none(),
                    recheck_limited,
                    "{name}: {count}"
                );
            }
        }
    }

    #[test]
    fn streamed_match_limits_report_one_gap_across_pieces() {
        let f = Fixture::new("streamed-match-limits");
        fs::create_dir(f.0.join(".claude")).unwrap();
        // Keep tokens beyond the discovery head: otherwise the separate
        // whole-file token rule also reports this >1 MiB file as too large.
        let mut body = "ordinary record\n".repeat(300);
        for start in [0, 200] {
            for i in start..start + 200 {
                body.push_str(&format!("{}abcdeABCDE{i:026}\n", "ghp_"));
            }
            body.push_str(&"ordinary record\n".repeat(80_000));
        }
        fs::write(f.0.join(".claude/session.jsonl"), body).unwrap();
        let scan = Scan::run(&f.0, std::slice::from_ref(&f.0));
        assert_eq!(
            scan.findings
                .iter()
                .filter(|f| f.rule == "secret.agent-record")
                .count(),
            50
        );
        assert_eq!(scan.not_checked.len(), 1);
        assert_eq!(scan.not_checked[0].path, "~/.claude/session.jsonl");
        assert_eq!(scan.not_checked[0].reason, "scan-limit");
    }

    #[test]
    fn terraform_nested_limits_report_unexamined_values() {
        let f = Fixture::new("terraform-nested-limits");
        let path = f.0.join("terraform.tfstate");
        for instances_limit in [false, true] {
            for over in [false, true] {
                let count = if instances_limit { 1000 } else { 100 } + usize::from(over);
                let instances = if instances_limit {
                    let mut instances = vec![serde_json::json!({}); count];
                    instances[count - 1] =
                        serde_json::json!({"attributes": {"password": "synthetic-value"}});
                    instances
                } else {
                    let names: Vec<_> = (0..count)
                        .map(|i| serde_json::json!([{"value": format!("field{i}")}]))
                        .collect();
                    let attributes =
                        serde_json::json!({format!("field{}", count - 1): "synthetic-value"});
                    vec![
                        serde_json::json!({"sensitive_attributes": names, "attributes": attributes}),
                    ]
                };
                let body = serde_json::json!({"terraform_version": "1.9.0", "resources": [{
                    "type": "fixture", "name": "last", "instances": instances
                }]})
                .to_string();
                fs::write(&path, body).unwrap();
                let scan = Scan::run(&f.0, std::slice::from_ref(&f.0));
                assert_eq!(scan.findings.len(), usize::from(!over));
                assert_eq!(scan.not_checked.len(), usize::from(over));
                if over {
                    assert_eq!(scan.not_checked[0].reason, "scan-limit");
                    assert_eq!(scan.not_checked[0].path, "~/terraform.tfstate");
                }
                assert_eq!(
                    recheck("dev.terraform.state-secret", &path, &f.0, None).is_none(),
                    over
                );
            }
        }
    }

    #[test]
    fn completed_overlap_does_not_repeat_header_reads() {
        let f = Fixture::new("overlap");
        let nested = f.0.join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("a.csv"), "url,username,password\n").unwrap();
        fs::write(nested.join("b"), "ordinary synthetic data").unwrap();
        let s = Scan::run(&f.0, &[f.0.clone(), nested]);
        assert_eq!(s.counts.header_attempts, 2);
        assert_eq!(s.counts.entries, 3);
        assert_eq!(s.findings.len(), 1);
        assert!(s.not_checked.is_empty());
        assert!(s.traversal.completed.contains_key(&f.0));
    }

    fn files(dir: &Path, count: usize) {
        fs::create_dir_all(dir).unwrap();
        for i in 0..count {
            fs::write(dir.join(format!("file-{i:02}")), "ordinary synthetic data").unwrap();
        }
    }

    fn paths(s: &Scan) -> Vec<&str> {
        s.findings.iter().map(|f| f.path.as_str()).collect()
    }

    #[test]
    fn a_large_early_folder_does_not_starve_later_ones() {
        let f = Fixture::new("fair");
        // Sorted first and far larger than the budget.
        let mut deep = f.0.join("aaa");
        for level in 0..6 {
            files(&deep, 10);
            deep.push(format!("d{level}"));
        }
        files(&f.0.join("zzz"), 0);
        fs::write(f.0.join("zzz/export.csv"), "url,username,password\n").unwrap();
        let s = Scan::run_budgeted(&f.0, std::slice::from_ref(&f.0), &[], None, None, None, 30);
        assert_eq!(paths(&s), ["~/zzz/export.csv"]);
        // What was left is reported under the large folder only: the folder
        // whose listing was cut short, and one gap for anything still queued.
        assert!(!s.not_checked.is_empty() && s.not_checked.len() <= 2);
        assert!(s
            .not_checked
            .iter()
            .all(|g| g.reason == "scan-limit" && g.path.starts_with("~/aaa")));

        // Selecting the limited folder spends a new budget on what is left.
        let again = Scan::run_budgeted(
            &f.0,
            &[f.0.clone(), f.0.join("aaa")],
            &[],
            None,
            None,
            None,
            30,
        );
        assert!(again.counts.entries > s.counts.entries);
    }

    #[test]
    fn library_and_media_folders_are_reached_after_everything_else() {
        let f = Fixture::new("last");
        files(&f.0.join("Library/App"), 50);
        files(&f.0.join("Pictures"), 50);
        files(&f.0.join("work/a/b/c"), 0);
        fs::write(f.0.join("work/a/b/c/export.csv"), "url,username,password\n").unwrap();
        let s = Scan::run_budgeted(&f.0, std::slice::from_ref(&f.0), &[], None, None, None, 20);
        assert_eq!(paths(&s), ["~/work/a/b/c/export.csv"]);
        let gaps: Vec<_> = s.not_checked.iter().map(|g| g.path.as_str()).collect();
        assert!(
            gaps.contains(&"~/Library") && gaps.contains(&"~/Pictures"),
            "{gaps:?}"
        );

        // A folder named Library elsewhere, or chosen as a root, is not deferred.
        let s = Scan::run_budgeted(&f.0, &[f.0.join("Library")], &[], None, None, None, 100);
        assert_eq!(s.counts.header_attempts, 50);
    }

    fn digest(_: &str, _: &[u8], _: bool) -> String {
        "synthetic-digest".into()
    }

    fn limits(entries: usize) -> Limits {
        Limits {
            entries,
            time: Duration::from_secs(30),
        }
    }

    #[test]
    fn one_credential_has_one_identity_wherever_it_is() {
        let f = Fixture::new("identity");
        let token = format!("gh{}_{}", "p", "0123456789abcdefghijABCDEFGHIJ012345");
        let other = format!("gh{}_{}", "p", "ZYXWVUTSRQzyxwvutsrq9876543210987654");
        fs::create_dir_all(f.0.join(".claude/projects/p")).unwrap();
        fs::write(
            f.0.join(".env"),
            format!("GITHUB_TOKEN={token}\nDB_PASSWORD=synthetic-only-value\n"),
        )
        .unwrap();
        fs::write(f.0.join("notes.md"), format!("use {token}\n")).unwrap();
        fs::write(
            f.0.join(".claude/projects/p/s.jsonl"),
            format!("{{\"out\":\"{token}\"}}\n{{\"out\":\"{other}\"}}\n"),
        )
        .unwrap();
        // A stand-in for the keyed digest: it only has to be a function of its input.
        let digest = |rule: &str, bytes: &[u8], _: bool| {
            format!("{rule}:{}", String::from_utf8_lossy(bytes).len())
        };
        let exact = move |rule: &str, bytes: &[u8], shared: bool| {
            if rule.is_empty() {
                format!("value:{}", String::from_utf8_lossy(bytes))
            } else {
                digest(rule, bytes, shared)
            }
        };
        let r = Scan::report_controlled(
            &f.0,
            &[],
            &[],
            Arc::new(AtomicBool::new(false)),
            exact,
            |_| {},
        );
        let secret_of = |path: &str, line: usize| {
            r.findings
                .iter()
                .find(|x| x.path == path && x.line == Some(line))
                .unwrap_or_else(|| panic!("no finding at {path}:{line}"))
                .secret
                .clone()
        };
        // The same token in a settings file, a note and an agent record.
        let same = Some(format!("value:{token}"));
        assert_eq!(secret_of("~/.env", 1), same);
        assert_eq!(secret_of("~/notes.md", 1), same);
        assert_eq!(secret_of("~/.claude/projects/p/s.jsonl", 1), same);
        // A different token, and a different variable in the same file.
        assert_eq!(
            secret_of("~/.claude/projects/p/s.jsonl", 2),
            Some(format!("value:{other}"))
        );
        assert_eq!(
            secret_of("~/.env", 2),
            Some("value:synthetic-only-value".into())
        );
        // Nothing of it reaches an export.
        let export = crate::report::to_ascii_json(&r);
        assert!(!export.contains("value:gh") && !export.contains(&token));
    }

    /// Two tokens of one type on one line were one finding: the second had
    /// the first one's rule, path, line and subject, and was passed over.
    #[test]
    fn two_tokens_of_one_type_on_a_line_are_two_findings_found_once() {
        let f = Fixture::new("same-line");
        let token = |last: char| format!("gh{}_0123456789abcdefghijABCDEFGHIJ01234{last}", "p");
        let (one, two) = (token('A'), token('B'));
        // In a note discovery reads, and in a file a rule names and discovery
        // then passes again.
        put(&f.0, "notes.txt", format!("{one} {two} {one}\n").as_bytes());
        put(&f.0, ".env", format!("{two} {one}\n").as_bytes());
        // A stand-in for the keyed digest: it only has to tell values apart.
        let digest = |rule: &str, bytes: &[u8], _: bool| format!("{rule}:{:?}", bytes.last());
        let scan = |roots: &[PathBuf]| {
            let digest: Fingerprint = Box::new(digest);
            Scan::run_observed(&f.0, roots, None, None, Some(digest))
        };
        let secrets = |s: &Scan, path: &str| -> Vec<(Option<usize>, Option<String>)> {
            let at = s.findings.iter().filter(|x| x.path == path);
            at.filter(|x| x.rule == "secret.service-token")
                .map(|x| (x.line, x.secret.clone()))
                .collect()
        };
        let (a, b) = (Some(":Some(65)".to_string()), Some(":Some(66)".to_string()));
        // The home folder given twice is read once.
        for roots in [vec![f.0.clone()], vec![f.0.clone(), f.0.clone()]] {
            let s = scan(&roots);
            assert_eq!(
                secrets(&s, "~/notes.txt"),
                [(Some(1), a.clone()), (Some(1), b.clone())]
            );
            assert_eq!(
                secrets(&s, "~/.env"),
                [(Some(1), b.clone()), (Some(1), a.clone())]
            );
        }
    }

    #[test]
    fn a_credential_in_a_url_has_the_identity_of_its_value() {
        let f = Fixture::new("url-identity");
        let token = format!("gh{}_{}", "p", "0123456789abcdefghijABCDEFGHIJ012345");
        fs::create_dir_all(f.0.join("project/.git")).unwrap();
        fs::write(
            f.0.join("project/.git/config"),
            format!(
                "[remote \"origin\"]\n\turl = https://fixture:{token}@git.example.invalid/p.git\n"
            ),
        )
        .unwrap();
        fs::write(
            f.0.join(".git-credentials"),
            format!("https://fixture:{token}@git.example.invalid\nhttps://fixture:synthetic-only@other.example.invalid\n"),
        )
        .unwrap();
        // A stand-in for the keyed digest that shows which bytes it was given.
        let exact = |rule: &str, bytes: &[u8], _: bool| {
            if rule.is_empty() {
                format!("value:{}", String::from_utf8_lossy(bytes))
            } else {
                "file".to_string()
            }
        };
        let r = Scan::report_controlled(
            &f.0,
            &[],
            &[],
            Arc::new(AtomicBool::new(false)),
            exact,
            |_| {},
        );
        // Named, so a failure here does not print the token.
        let secrets = |rule: &str| {
            r.findings
                .iter()
                .filter(|x| x.rule == rule)
                .map(|x| match x.secret.as_deref() {
                    Some(s) if s == format!("value:{token}") => "the token",
                    Some("value:synthetic-only") => "the password",
                    Some(_) => "something else",
                    None => "none",
                })
                .collect::<Vec<_>>()
        };
        // The same token under three rules is one credential.
        assert_eq!(secrets("dev.url.inline-password"), ["the token"]);
        assert_eq!(
            secrets("dev.git.inline-credentials"),
            ["the token", "the password"]
        );
        assert_eq!(secrets("secret.service-token"), ["the token", "the token"]);
    }

    #[test]
    fn a_sweep_in_slices_covers_everything_once() {
        let f = Fixture::new("sweep");
        for name in ["a", "b", "c", "d"] {
            files(&f.0.join(name).join("deep/deeper"), 5);
            fs::write(
                f.0.join(name).join("deep/deeper/export.csv"),
                "url,username,password\n",
            )
            .unwrap();
        }
        fs::write(f.0.join(".npmrc"), "_authToken=synthetic-only\n").unwrap();
        let cancel = || Arc::new(AtomicBool::new(false));
        let (mut found, mut slices) = (Vec::new(), 0);
        let mut resume = None;
        loop {
            let first = resume.is_none();
            let (r, pending) = Scan::sweep(&f.0, &[], resume, limits(8), cancel(), digest);
            // Known locations are checked in the first slice only.
            assert_eq!(
                r.findings.iter().any(|x| x.path == "~/.npmrc"),
                first,
                "slice {slices}"
            );
            found.extend(r.findings.into_iter().map(|x| x.path));
            slices += 1;
            if pending.is_empty() {
                break;
            }
            resume = Some(pending);
            assert!(slices < 50);
        }
        assert!(slices > 2, "the budget must force several slices");
        // A folder cut short by the budget is visited again, so a file in it
        // can be reported by two slices.
        found.sort();
        found.dedup();
        assert_eq!(
            found,
            [
                "~/.npmrc",
                "~/a/deep/deeper/export.csv",
                "~/b/deep/deeper/export.csv",
                "~/c/deep/deeper/export.csv",
                "~/d/deep/deeper/export.csv",
            ]
        );
    }

    #[test]
    fn resumed_sweeps_agree_with_an_uninterrupted_pass() {
        let f = Fixture::new("resume-parity");
        put(&f.0, ".npmrc", b"_authToken=synthetic-only\n");
        for folder in ["a", "b/deep", "c", "Library/fixture"] {
            put(
                &f.0,
                &format!("{folder}/export.csv"),
                b"url,username,password\n",
            );
        }
        let token = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        put(
            &f.0,
            ".claude/projects/fixture/record.jsonl",
            record(&token).as_bytes(),
        );
        let canonical = |findings: Vec<Finding>| -> std::collections::BTreeSet<String> {
            findings
                .into_iter()
                .map(|f| serde_json::to_string(&f).unwrap())
                .collect()
        };
        let (baseline, pending) = Scan::sweep(
            &f.0,
            &[],
            None,
            limits(1000),
            Arc::new(AtomicBool::new(false)),
            digest,
        );
        assert!(pending.is_empty() && baseline.not_checked.is_empty());
        let expected = canonical(baseline.findings);
        assert!(!expected.is_empty());
        for budget in [8, 13, 1000] {
            for interrupt in [false, true] {
                let cancel = Arc::new(AtomicBool::new(false));
                let stop = cancel.clone();
                let first_digest = move |rule: &str, bytes: &[u8], shared: bool| {
                    if interrupt {
                        stop.store(true, Ordering::SeqCst);
                    }
                    digest(rule, bytes, shared)
                };
                let (first, mut pending) =
                    Scan::sweep(&f.0, &[], None, limits(budget), cancel, first_digest);
                let mut found = first.findings;
                let mut gaps = first.not_checked;
                let mut passes = 1;
                while !pending.is_empty() {
                    assert!(passes < 50, "resume failed to finish: {pending:?}");
                    // A Known cursor can stop after a fully checked file,
                    // before establishing whether later locations exist.
                    if !pending.iter().any(|step| matches!(step, Step::Known(_))) {
                        assert!(gaps.iter().any(|g| g.reason == "scan-limit"));
                    }
                    let (next, rest) = Scan::sweep(
                        &f.0,
                        &[],
                        Some(pending),
                        limits(budget),
                        Arc::new(AtomicBool::new(false)),
                        digest,
                    );
                    found.extend(next.findings);
                    gaps = next.not_checked;
                    pending = rest;
                    passes += 1;
                }
                assert_eq!(
                    canonical(found),
                    expected,
                    "budget {budget}, cancel {interrupt}"
                );
                assert!(gaps.is_empty(), "completed pass must not invent gaps");
            }
        }
    }

    /// A record whose token only a full read finds: it is past the first 4 KiB.
    fn record(token: &str) -> String {
        format!(
            "{}{{\"out\":\"{token}\"}}\n",
            "{\"type\":\"filler\"}\n".repeat(400)
        )
    }

    #[test]
    fn a_known_step_cut_short_is_finished_by_a_later_slice() {
        let f = Fixture::new("known-resume");
        let token = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        // Neither is found by discovery: one needs a full read, and the
        // other is in a folder discovery passes over.
        fs::create_dir_all(f.0.join(".codex/sessions")).unwrap();
        fs::write(f.0.join(".codex/sessions/s.jsonl"), record(&token)).unwrap();
        fs::create_dir_all(f.0.join(".cache/huggingface")).unwrap();
        fs::write(f.0.join(".cache/huggingface/token"), &token).unwrap();
        let places = ["~/.cache/huggingface/token", "~/.codex/sessions/s.jsonl"];
        let pass = |first: Limits, cancelled: bool| {
            let cancel = Arc::new(AtomicBool::new(cancelled));
            let (r, mut pending) = Scan::sweep(&f.0, &[], None, first, cancel, digest);
            let mut found: Vec<_> = r.findings.into_iter().map(|x| x.path).collect();
            let mut slices = 1;
            while !pending.is_empty() {
                let cancel = Arc::new(AtomicBool::new(false));
                let (r, left) = Scan::sweep(&f.0, &[], Some(pending), limits(1000), cancel, digest);
                found.extend(r.findings.into_iter().map(|x| x.path));
                pending = left;
                slices += 1;
                assert!(slices < 50);
            }
            found.sort();
            (found, slices)
        };
        // The slice's time is up before the trees are read, as when a large
        // one comes first.
        let none = Limits {
            entries: 1000,
            time: Duration::ZERO,
        };
        let (found, slices) = pass(none, false);
        assert_eq!(found, places, "after {slices} slices");
        // The first slice is cancelled before it reads anything, as when the
        // Mac goes to sleep.
        let (found, slices) = pass(limits(1000), true);
        assert_eq!(found, places, "after {slices} slices");
        assert!(slices > 1);
    }

    #[test]
    fn what_a_record_holds_after_the_slice_s_time_is_up_is_still_reported() {
        // A record that is started is read to its end. Its later tokens must
        // not be dropped on the way, or no slice would ever report them.
        let f = Fixture::new("records-late");
        let first = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        let second = format!("AK{}{}", "IA", "ABCDEFGHIJKLMNOP");
        fs::create_dir_all(f.0.join(".claude/projects/p")).unwrap();
        fs::write(
            f.0.join(".claude/projects/p/s.jsonl"),
            format!("{}{{\"out\":\"{second}\"}}\n", record(&first)),
        )
        .unwrap();
        // The first finding takes longer than the whole slice is given.
        let slow = |_: &str, _: &[u8], _: bool| {
            std::thread::sleep(Duration::from_millis(60));
            "synthetic-digest".to_string()
        };
        let short = Limits {
            entries: 1000,
            time: Duration::from_millis(20),
        };
        let mut types = Vec::new();
        let mut pending = None;
        for slice in 0.. {
            let cancel = Arc::new(AtomicBool::new(false));
            let (r, left) = Scan::sweep(&f.0, &[], pending, short, cancel, slow);
            types.extend(r.findings.into_iter().filter_map(|x| x.token_type));
            if left.is_empty() {
                break;
            }
            pending = Some(left);
            assert!(slice < 50, "the pass did not end");
        }
        types.sort();
        types.dedup();
        assert_eq!(types, ["AWS access key", "Hugging Face token"]);
    }

    #[test]
    fn a_record_with_a_dropped_hit_is_read_again() {
        // The first slice is cancelled while its first finding is recorded,
        // so the second token of the same record is dropped. The record is
        // then not finished, however far it was read.
        let f = Fixture::new("records-dropped");
        let first = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        let second = format!("AK{}{}", "IA", "ABCDEFGHIJKLMNOP");
        fs::create_dir_all(f.0.join(".claude/projects/p")).unwrap();
        fs::write(
            f.0.join(".claude/projects/p/s.jsonl"),
            format!("{}{{\"out\":\"{second}\"}}\n", record(&first)),
        )
        .unwrap();
        let mut types = Vec::new();
        let mut pending = None;
        for slice in 0.. {
            let cancel = Arc::new(AtomicBool::new(false));
            let stop = (slice == 0).then(|| cancel.clone());
            let digest = move |_: &str, _: &[u8], _: bool| {
                if let Some(stop) = &stop {
                    stop.store(true, Ordering::SeqCst);
                }
                "synthetic-digest".to_string()
            };
            let (r, left) = Scan::sweep(&f.0, &[], pending, limits(1000), cancel, digest);
            types.extend(r.findings.into_iter().filter_map(|x| x.token_type));
            if left.is_empty() {
                break;
            }
            pending = Some(left);
            assert!(slice < 50, "the pass did not end");
        }
        types.sort();
        types.dedup();
        assert_eq!(types, ["AWS access key", "Hugging Face token"]);
    }

    #[test]
    fn a_known_file_with_more_findings_than_a_scan_keeps_does_not_hold_the_pass() {
        let f = Fixture::new("known-full");
        let token = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        fs::write(
            f.0.join(".pgpass"),
            "db.example.invalid:5432:shop:shop_user:synthetic-only\n".repeat(5000),
        )
        .unwrap();
        put(&f.0, ".codex/sessions/s.jsonl", record(&token).as_bytes());
        put(&f.0, "docs/export.csv", b"url,username,password\n");
        let mut found = HashSet::new();
        let mut pending = None;
        for slice in 0.. {
            let cancel = Arc::new(AtomicBool::new(false));
            let (r, left) = Scan::sweep(&f.0, &[], pending, limits(1000), cancel, digest);
            found.extend(r.findings.into_iter().map(|x| x.path));
            if left.is_empty() {
                break;
            }
            pending = Some(left);
            assert!(slice < 50, "the pass did not end");
        }
        for path in [
            "~/.pgpass",
            "~/.codex/sessions/s.jsonl",
            "~/docs/export.csv",
        ] {
            assert!(found.contains(path), "{path} was never reported");
        }
    }

    /// Every slice of a pass over `home`, the first made by `first`: the
    /// findings of each, and what each left.
    fn slices(
        home: &Path,
        limits: Limits,
        first: impl FnOnce() -> (Report, Pending),
    ) -> (Vec<Finding>, Vec<Pending>) {
        let (r, mut pending) = first();
        let mut found = r.findings;
        let mut left = vec![pending.clone()];
        while !pending.is_empty() {
            let cancel = Arc::new(AtomicBool::new(false));
            let (r, rest) = Scan::sweep(home, &[], Some(pending), limits, cancel, digest);
            found.extend(r.findings);
            pending = rest;
            left.push(pending.clone());
            assert!(left.len() < 50, "the pass did not end");
        }
        (found, left)
    }

    #[test]
    fn a_folder_stopped_in_its_last_file_is_finished_by_a_later_slice() {
        // The slice is cancelled while the first token of the folder's last
        // file is recorded, so the second is dropped. Nothing came after the
        // file to show that the folder was not finished.
        let f = Fixture::new("folder-last-file");
        let first = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        let second = format!("AK{}{}", "IA", "ABCDEFGHIJKLMNOP");
        put(
            &f.0,
            "proj/.env",
            format!("A={first}\nB={second}\n").as_bytes(),
        );
        let (found, left) = slices(&f.0, limits(1000), || {
            let cancel = Arc::new(AtomicBool::new(false));
            let stop = cancel.clone();
            let digest = move |_: &str, _: &[u8], _: bool| {
                stop.store(true, Ordering::SeqCst);
                "synthetic-digest".to_string()
            };
            Scan::sweep(&f.0, &[], None, limits(1000), cancel, digest)
        });
        let mut types: Vec<_> = found.into_iter().filter_map(|x| x.token_type).collect();
        types.sort();
        types.dedup();
        assert_eq!(types, ["AWS access key", "Hugging Face token"], "{left:?}");
    }

    #[test]
    fn a_slice_stopped_in_a_folder_goes_on_after_the_last_entry_it_finished() {
        let f = Fixture::new("folder-rest");
        let one = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        let two = format!("hf{}{}", "_", "ABCDEFGHIJabcdefghijABCDEFGHIJabcd");
        let three = format!("AK{}{}", "IA", "ABCDEFGHIJKLMNOP");
        put(&f.0, "proj/.env", format!("A={one}\n").as_bytes());
        put(
            &f.0,
            "proj/.env.local",
            format!("A={two}\nB={three}\n").as_bytes(),
        );
        put(&f.0, "proj/sub/.env", format!("A={one}\n").as_bytes());
        put(&f.0, "proj/z-export.csv", b"url,username,password\n");
        let count = |found: &[Finding], path: &str| found.iter().filter(|x| x.path == path).count();
        let whole = slices(&f.0, limits(1000), || {
            let cancel = Arc::new(AtomicBool::new(false));
            Scan::sweep(&f.0, &[], None, limits(1000), cancel, digest)
        });
        assert_eq!(whole.1, [vec![]], "one slice reads it all");
        // Cancelled while the first token of the second file is recorded.
        let (found, left) = slices(&f.0, limits(1000), || {
            let cancel = Arc::new(AtomicBool::new(false));
            let stop = cancel.clone();
            let at = two.clone();
            let digest = move |_: &str, value: &[u8], _: bool| {
                if value == at.as_bytes() {
                    stop.store(true, Ordering::SeqCst);
                }
                "synthetic-digest".to_string()
            };
            Scan::sweep(&f.0, &[], None, limits(1000), cancel, digest)
        });
        // The folder is left with the place reached in it: the first file
        // was finished and the second was not.
        let rest = Step::Rest {
            dir: f.0.join("proj"),
            depth: 1,
            after: f.0.join("proj/.env"),
        };
        assert_eq!(left[0], [rest]);
        assert_eq!(left.len(), 2, "{left:?}");
        // So the first file is not read a second time, the second is read
        // again from its start, and what comes after it once.
        for path in ["~/proj/.env", "~/proj/sub/.env", "~/proj/z-export.csv"] {
            assert_eq!(count(&found, path), count(&whole.0, path), "{path}");
            assert!(count(&found, path) > 0, "{path}");
        }
        let mut types: Vec<_> = found.iter().filter_map(|x| x.token_type).collect();
        types.sort();
        types.dedup();
        assert_eq!(types, ["AWS access key", "Hugging Face token"]);
    }

    #[test]
    fn a_folder_with_more_findings_than_a_scan_keeps_does_not_hold_the_pass() {
        // Read from its start by every slice, it would fill each one before
        // its last files were reached.
        let f = Fixture::new("folder-full");
        let token = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        let lines: String = (0..100).map(|n| format!("K{n}={token}\n")).collect();
        for n in 0..60 {
            put(&f.0, &format!("proj/.env.{n:02}"), lines.as_bytes());
        }
        put(&f.0, "proj/z-export.csv", b"url,username,password\n");
        put(&f.0, "proj/sub/export.csv", b"url,username,password\n");
        let (found, left) = slices(&f.0, limits(1000), || {
            let cancel = Arc::new(AtomicBool::new(false));
            Scan::sweep(&f.0, &[], None, limits(1000), cancel, digest)
        });
        // More than one slice keeps, so it took more than one.
        assert!(found.len() > 4096 && left.len() > 1, "{}", found.len());
        let paths: HashSet<_> = found.iter().map(|x| x.path.as_str()).collect();
        for path in [
            "~/proj/.env.00",
            "~/proj/.env.59",
            "~/proj/z-export.csv",
            "~/proj/sub/export.csv",
        ] {
            assert!(paths.contains(path), "{path} was never reported");
        }
    }

    #[test]
    fn a_file_with_more_findings_than_a_scan_keeps_does_not_hold_the_pass() {
        // Alone in a slice it still fills it, so checking it again would end
        // the same way every time. Wherever it is in its folder.
        let lines: String = (0..5000)
            .map(|n| format!("//registry.example.invalid/:_authToken=synthetic-only-{n}\n"))
            .collect();
        for (name, others) in [
            ("file-full-last", &["proj/-export.csv"][..]),
            ("file-full-only", &[]),
            ("file-full-first", &["proj/z-export.csv"]),
            (
                "file-full-middle",
                &["proj/-export.csv", "proj/z-export.csv"],
            ),
        ] {
            let f = Fixture::new(name);
            put(&f.0, "proj/.npmrc", lines.as_bytes());
            put(&f.0, "zzz/export.csv", b"url,username,password\n");
            for other in others {
                put(&f.0, other, b"url,username,password\n");
            }
            let mut found = HashSet::new();
            let mut gaps = HashSet::new();
            let mut pending = None;
            for slice in 0.. {
                let cancel = Arc::new(AtomicBool::new(false));
                let (r, left) = Scan::sweep(&f.0, &[], pending, limits(1000), cancel, digest);
                found.extend(r.findings.into_iter().map(|x| x.path));
                gaps.extend(r.not_checked.into_iter().map(|g| (g.path, g.reason)));
                if left.is_empty() {
                    break;
                }
                assert!(slice < 8, "{name}: the pass did not end, left {left:?}");
                pending = Some(left);
            }
            for path in others
                .iter()
                .copied()
                .chain(["proj/.npmrc", "zzz/export.csv"])
            {
                assert!(found.contains(&format!("~/{path}")), "{name}: {path}");
            }
            // What the file holds beyond that is said to be unread.
            assert!(gaps.contains(&("~/proj/.npmrc".to_string(), "scan-limit")));
        }
    }

    #[test]
    fn a_file_given_up_for_time_is_checked_again_when_no_gap_could_say_so() {
        // The slice already holds the 4,096 gap rows a report keeps when it
        // comes to a file whose first token takes until the time is up. Its
        // own row cannot be added, so nothing would say what was dropped.
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new("folder-gaps-full");
        for n in 0..4100 {
            put(&f.0, &format!("g/u{n:04}"), b"plain");
            let none = fs::Permissions::from_mode(0o000);
            fs::set_permissions(f.0.join(format!("g/u{n:04}")), none).unwrap();
        }
        let one = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        let two = format!("AK{}{}", "IA", "ABCDEFGHIJKLMNOP");
        put(&f.0, "g/zz.env", format!("A={one}\nB={two}\n").as_bytes());
        put(&f.0, "g/zzz-export.csv", b"url,username,password\n");
        let slice = Limits {
            entries: 100_000,
            time: Duration::from_secs(6),
        };
        let mut types = HashSet::new();
        let mut pending = None;
        for n in 0.. {
            let cancel = Arc::new(AtomicBool::new(false));
            let began = Instant::now();
            let at = one.clone();
            let slow = move |_: &str, value: &[u8], _: bool| {
                // Slow once, in the first slice only.
                while n == 0 && value == at.as_bytes() && began.elapsed() < slice.time {
                    std::thread::sleep(Duration::from_millis(50));
                }
                "synthetic-digest".to_string()
            };
            let (r, left) = Scan::sweep(&f.0, &[], pending, slice, cancel, slow);
            if n == 0 {
                assert_eq!(r.not_checked.len(), 4096, "the gap list is not full");
                assert!(r.not_checked.iter().all(|g| g.path != "~/g/zz.env"));
                assert!(r.findings.iter().any(|x| x.path == "~/g/zz.env"));
            }
            types.extend(r.findings.iter().filter_map(|x| x.token_type));
            if left.is_empty() {
                break;
            }
            assert!(n < 6, "the pass did not end");
            pending = Some(left);
        }
        assert!(
            types.contains("AWS access key"),
            "the second token: {types:?}"
        );
    }

    #[test]
    fn a_scan_stopped_inside_a_file_still_names_the_folder_it_did_not_finish() {
        // The file is not its folder's last entry: the folder's own row
        // says the rest of it is unread, beside the file's and the row of
        // the folder at the top of the walk.
        let f = Fixture::new("folder-row");
        let one = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        let two = format!("AK{}{}", "IA", "ABCDEFGHIJKLMNOP");
        let both = format!("A={one}\nB={two}\n");
        put(&f.0, "proj/sub/deep/.env", both.as_bytes());
        put(
            &f.0,
            "proj/sub/deep/z-export.csv",
            b"url,username,password\n",
        );
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = cancel.clone();
        let stopping = move |_: &str, _: &[u8], _: bool| {
            stop.store(true, Ordering::SeqCst);
            "synthetic-digest".to_string()
        };
        let paths = [f.0.join("proj")];
        let (r, left) = Scan::changed(&f.0, &[], &paths, limits(1000), cancel, stopping);
        assert_eq!(left.cancelled, paths);
        let rows = |gaps: &[NotChecked]| -> Vec<(String, &'static str)> {
            gaps.iter().map(|g| (g.path.clone(), g.reason)).collect()
        };
        let all = |paths: [&str; 4]| paths.map(|p| (p.to_string(), "scan-limit")).to_vec();
        let deep = "~/proj/sub/deep";
        let expected = all([
            "~/proj/sub/deep/.env",
            "~/proj/sub/deep/.env",
            deep,
            "~/proj/sub",
        ]);
        assert_eq!(rows(&r.not_checked), expected);

        // The same when the findings one scan keeps are reached inside a
        // file, in a change check and in a whole scan that can be cancelled.
        let f = Fixture::new("folder-row-full");
        let lines: String = (0..100).map(|n| format!("K{n}={one}\n")).collect();
        for n in 0..42 {
            put(&f.0, &format!("big/p/.env.{n:02}"), lines.as_bytes());
        }
        let expected = all(["~/big/p/.env.40", "~/big/p/.env.40", "~/big/p", "~/big"]);
        let cancel = Arc::new(AtomicBool::new(false));
        let paths = [f.0.clone()];
        let (r, left) = Scan::changed(&f.0, &[], &paths, limits(100_000), cancel, digest);
        assert_eq!(r.findings.len(), 4096);
        assert_eq!(left.cut_short, paths);
        assert_eq!(rows(&r.not_checked), expected);
        let cancel = Arc::new(AtomicBool::new(false));
        let s = Scan::run_budgeted(
            &f.0,
            std::slice::from_ref(&f.0),
            &[],
            None,
            Some(cancel),
            Some(Box::new(digest)),
            100_000,
        );
        assert_eq!(s.findings.len(), 4096);
        assert_eq!(rows(&s.not_checked), expected);
    }

    #[test]
    fn a_stop_in_a_folder_s_last_file_adds_no_row_outside_a_sweep() {
        // Only a sweep comes back to the folder. A change check or a whole
        // scan says what it said before sweeps kept a place: the file's own
        // rows, and none for a folder with nothing else left in it. A row
        // more could push another out of a full list.
        let f = Fixture::new("folder-row-last");
        let one = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        let two = format!("AK{}{}", "IA", "ABCDEFGHIJKLMNOP");
        put(
            &f.0,
            "a/b/c/one.env",
            format!("A={one}\nB={two}\n").as_bytes(),
        );
        let stopping = || {
            let cancel = Arc::new(AtomicBool::new(false));
            let stop = cancel.clone();
            let fingerprint = move |_: &str, _: &[u8], _: bool| {
                stop.store(true, Ordering::SeqCst);
                "synthetic-digest".to_string()
            };
            (cancel, fingerprint)
        };
        let file = ["~/a/b/c/one.env", "~/a/b/c/one.env"];
        let (cancel, fingerprint) = stopping();
        let paths = [f.0.join("a")];
        let (r, left) = Scan::changed(&f.0, &[], &paths, limits(1000), cancel, fingerprint);
        assert_eq!(left.cancelled, paths);
        let rows: Vec<_> = r.not_checked.iter().map(|g| g.path.as_str()).collect();
        assert_eq!(rows, file);
        let (cancel, fingerprint) = stopping();
        let roots = std::slice::from_ref(&f.0);
        let s = Scan::run_observed(&f.0, roots, None, Some(cancel), Some(Box::new(fingerprint)));
        let rows: Vec<_> = s.not_checked.iter().map(|g| g.path.as_str()).collect();
        assert_eq!(rows[..2], file);
        assert!(!rows.contains(&"~/a"), "{rows:?}");
    }

    #[test]
    fn a_file_begun_late_in_every_slice_does_not_hold_the_pass() {
        // A folder whose listing alone takes more than half of a slice's
        // time, and in it a file that outlasts the rest of the slice. Every
        // slice that comes back lists the folder again first, so the file
        // never begins in the first half of one.
        let f = Fixture::new("folder-late");
        for n in 0..9_999 {
            fs::create_dir_all(f.0.join(format!("wide/d{n:05}"))).unwrap();
        }
        let first = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        let second = format!("AK{}{}", "IA", "ABCDEFGHIJKLMNOP");
        put(
            &f.0,
            "wide/zz.env",
            format!("A={first}\nB={second}\n").as_bytes(),
        );
        // How long the folder takes to list here: a slice gets less than
        // twice that.
        let mut listing: Vec<Duration> = (0..9)
            .map(|_| {
                let mut budget = 100_000;
                let began = Instant::now();
                list_dir(&f.0.join("wide"), false, &mut budget).unwrap();
                began.elapsed()
            })
            .collect();
        listing.sort();
        let slice = Limits {
            entries: 100_000,
            time: listing[4] * 17 / 10,
        };
        let mut pending = None;
        let mut unchanged = 0;
        for n in 0.. {
            let cancel = Arc::new(AtomicBool::new(false));
            let began = Instant::now();
            let at = first.clone();
            let slow = move |_: &str, value: &[u8], _: bool| {
                // Recording the file's first token takes until the time is up.
                let late = slice.time + Duration::from_millis(5);
                while value == at.as_bytes() && began.elapsed() < late {
                    std::thread::sleep(Duration::from_millis(1));
                }
                "synthetic-digest".to_string()
            };
            let before = pending.clone();
            let (_, left) = Scan::sweep(&f.0, &[], pending, slice, cancel, slow);
            if left.is_empty() {
                break;
            }
            // The agent gives a pass up after three such slices in a row.
            unchanged = if before.as_ref() == Some(&left) {
                unchanged + 1
            } else {
                0
            };
            assert!(
                n < 400,
                "the pass did not end: the last {unchanged} slices left it as it was, with {} steps",
                left.len()
            );
            pending = Some(left);
        }
    }

    #[test]
    fn only_a_sweep_goes_on_from_the_place_a_stop_left_in_a_folder() {
        // A change check or a whole scan that meets the folder again reads
        // it from its start: the subfolders before the place were handed to
        // nothing. The second walk is not stopped here because the cancel
        // was taken back, which is the only stop that can be.
        let f = Fixture::new("folder-place");
        let token = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        put(
            &f.0,
            "par/a-sub/inner/.env",
            format!("A={token}\n").as_bytes(),
        );
        for file in [
            "par/a-sub/x.csv",
            "par/a-sub/y.csv",
            "par/b.csv",
            "par/c.csv",
        ] {
            put(&f.0, file, b"url,username,password\n");
        }
        let all = [
            "~/par/a-sub/inner/.env",
            "~/par/a-sub/x.csv",
            "~/par/a-sub/y.csv",
            "~/par/b.csv",
            "~/par/c.csv",
        ];
        for (first, second) in [("par", "par"), ("par", ""), ("par/a-sub", "par")] {
            let cancel = Arc::new(AtomicBool::new(false));
            let (stop, done) = (cancel.clone(), AtomicBool::new(false));
            // Cancelled the first time a password export is recorded.
            let stopping = move |rule: &str, _: &[u8], _: bool| {
                if rule == "export.password-csv" && !done.swap(true, Ordering::SeqCst) {
                    stop.store(true, Ordering::SeqCst);
                }
                "synthetic-digest".to_string()
            };
            let fingerprint: Fingerprint = Box::new(stopping);
            let mut s = Scan::new(&f.0, None, Some(cancel.clone()), Some(fingerprint), 100_000);
            let left = s.changes(&[f.0.join(first)]);
            assert_eq!(left.cancelled, [f.0.join(first)], "{first:?}");
            cancel.store(false, Ordering::SeqCst);
            let left = s.changes(&[f.0.join(second)]);
            assert_eq!(left, Unreached::default(), "the second walk was stopped");
            let mut found: Vec<_> = s.findings.iter().map(|x| x.path.as_str()).collect();
            found.sort();
            assert_eq!(found, all, "{first:?} then {second:?}");
        }
    }

    #[test]
    fn a_file_slower_than_a_slice_does_not_hold_the_pass() {
        let f = Fixture::new("folder-slow");
        let first = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        let second = format!("AK{}{}", "IA", "ABCDEFGHIJKLMNOP");
        put(
            &f.0,
            "proj/.env",
            format!("A={first}\nB={second}\n").as_bytes(),
        );
        put(&f.0, "proj/z-export.csv", b"url,username,password\n");
        // Recording the file's first token takes longer than a slice has.
        let short = Limits {
            entries: 1000,
            time: Duration::from_millis(200),
        };
        let mut found = HashSet::new();
        let mut pending = None;
        for slice in 0.. {
            let cancel = Arc::new(AtomicBool::new(false));
            let at = first.clone();
            let slow = move |_: &str, value: &[u8], _: bool| {
                if value == at.as_bytes() {
                    std::thread::sleep(Duration::from_millis(400));
                }
                "synthetic-digest".to_string()
            };
            let (r, left) = Scan::sweep(&f.0, &[], pending, short, cancel, slow);
            found.extend(r.findings.into_iter().map(|x| x.path));
            if left.is_empty() {
                break;
            }
            pending = Some(left);
            assert!(slice < 12, "the pass did not end");
        }
        for path in ["~/proj/.env", "~/proj/z-export.csv"] {
            assert!(found.contains(path), "{path} was never reported");
        }
    }

    #[test]
    fn a_record_is_read_as_long_as_it_was_when_opened() {
        // A file that grows while it is read is not followed to its new end:
        // what is added later is another change, and a read with no end
        // would be a loop over scanned data with no limit.
        let f = Fixture::new("records-growing");
        let first = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        let second = format!("AK{}{}", "IA", "ABCDEFGHIJKLMNOP");
        let path = f.0.join(".claude/projects/p/s.jsonl");
        put(
            &f.0,
            ".claude/projects/p/s.jsonl",
            record(&first).as_bytes(),
        );
        let (grow, added) = (path.clone(), format!("{{\"out\":\"{second}\"}}\n"));
        let digest = move |_: &str, _: &[u8], _: bool| {
            let mut file = fs::OpenOptions::new().append(true).open(&grow).unwrap();
            file.write_all(added.as_bytes()).unwrap();
            "synthetic-digest".to_string()
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let r = Scan::report_controlled(&f.0, &[], &[], cancel, digest, |_| {});
        let types: Vec<_> = r
            .findings
            .iter()
            .filter(|x| x.rule == "secret.agent-record")
            .filter_map(|x| x.token_type)
            .collect();
        assert_eq!(types, ["Hugging Face token"]);
    }

    #[test]
    fn a_record_that_takes_too_long_is_left_with_a_gap_and_not_tried_again() {
        // Text can be made slow to check. One file must not hold a pass.
        let f = Fixture::new("records-slow");
        let token = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        let path = f.0.join(".claude/s.jsonl");
        let body = format!("{}{{\"out\":\"{token}\"}}\n", " ".repeat(3 * 1024 * 1024));
        put(&f.0, ".claude/s.jsonl", body.as_bytes());
        let cancel = Arc::new(AtomicBool::new(false));
        let mut s = Scan::new(&f.0, None, Some(cancel), Some(Box::new(digest)), 1000);
        s.record_time = Duration::ZERO;
        let rule = RULES
            .iter()
            .find(|r| r.id == "secret.agent-record")
            .unwrap();
        // Done with, so that a sweep goes on to the next file.
        assert!(s.stream(rule, &path));
        assert!(s.findings.is_empty());
        let gaps: Vec<_> = s
            .not_checked
            .iter()
            .map(|g| (g.path.as_str(), g.reason))
            .collect();
        assert_eq!(gaps, [("~/.claude/s.jsonl", "scan-limit")]);
        // A scan with nothing to cancel it, as the command line's, has no such limit.
        let mut s = Scan::new(&f.0, None, None, None, 1000);
        s.record_time = Duration::ZERO;
        assert!(s.stream(rule, &path));
        assert_eq!(s.findings.len(), 1);
    }

    #[test]
    fn a_step_in_a_folder_skipped_since_is_dropped() {
        let f = Fixture::new("skip-step");
        let token = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        put(
            &f.0,
            ".claude/projects/client/a.jsonl",
            record(&token).as_bytes(),
        );
        put(&f.0, "work/client/export.csv", b"url,username,password\n");
        let skip = [f.0.join(".claude/projects/client"), f.0.join("work/client")];
        let resume = vec![
            Step::Records {
                rule: "secret.agent-record",
                dir: skip[0].clone(),
                depth: 2,
                after: None,
            },
            Step::Folder(skip[1].clone(), 2),
        ];
        let cancel = Arc::new(AtomicBool::new(false));
        let (r, left) = Scan::sweep(&f.0, &skip, Some(resume), limits(1000), cancel, digest);
        assert!(r.findings.is_empty(), "read in a skipped folder");
        assert!(left.is_empty());
        // The root of an agent's folder is a known location, which a skip
        // does not cover: a slice reads it as a scan made at once does.
        put(&f.0, ".claude/history.jsonl", record(&token).as_bytes());
        let skip = [f.0.join(".claude")];
        let resume = vec![Step::Records {
            rule: "secret.agent-record",
            dir: skip[0].clone(),
            depth: 0,
            after: None,
        }];
        let cancel = Arc::new(AtomicBool::new(false));
        let (r, _) = Scan::sweep(&f.0, &skip, Some(resume), limits(1000), cancel, digest);
        let slice: Vec<_> = r.findings.iter().map(|x| x.path.as_str()).collect();
        let whole = Scan::run_budgeted(
            &f.0,
            std::slice::from_ref(&f.0),
            &skip,
            None,
            None,
            None,
            1000,
        );
        assert_eq!(slice, ["~/.claude/history.jsonl"]);
        let mut at_once = paths(&whole);
        at_once.retain(|path| path.starts_with("~/.claude"));
        assert_eq!(slice, at_once);
    }

    #[test]
    fn a_folder_of_records_is_resumed_at_the_file_it_had_reached() {
        let f = Fixture::new("records-resume");
        let token = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        fs::create_dir_all(f.0.join(".claude/projects/p/sub")).unwrap();
        for name in ["a.jsonl", "b.jsonl", "c.jsonl", "sub/d.jsonl"] {
            fs::write(f.0.join(".claude/projects/p").join(name), record(&token)).unwrap();
        }
        // Each slice is cancelled by its first finding, so it reads one record.
        let mut found = Vec::new();
        let mut pending = None;
        let mut slices = 0;
        loop {
            let cancel = Arc::new(AtomicBool::new(false));
            let stop = cancel.clone();
            let digest = move |_: &str, _: &[u8], _: bool| {
                stop.store(true, Ordering::SeqCst);
                "synthetic-digest".to_string()
            };
            let before = pending.clone();
            let (r, left) = Scan::sweep(&f.0, &[], pending, limits(1000), cancel, digest);
            found.extend(r.findings.into_iter().map(|x| x.path));
            slices += 1;
            if left.is_empty() {
                break;
            }
            // The agent gives up on a pass whose list stops changing.
            assert_ne!(before.as_ref(), Some(&left), "slice {slices} did nothing");
            pending = Some(left);
            assert!(slices < 50);
        }
        // Every record once: none is missed, and none is read by two slices.
        assert_eq!(
            found,
            [
                "~/.claude/projects/p/a.jsonl",
                "~/.claude/projects/p/b.jsonl",
                "~/.claude/projects/p/c.jsonl",
                "~/.claude/projects/p/sub/d.jsonl",
            ]
        );
        assert!(slices >= 4, "{slices} slices");
    }

    fn rules_at<'a>(s: &'a Scan, path: &str) -> Vec<&'a str> {
        let mut rules: Vec<_> = s
            .findings
            .iter()
            .filter(|x| x.path == path)
            .map(|x| x.rule)
            .collect();
        rules.sort_unstable();
        rules.dedup();
        rules
    }

    fn put(home: &Path, rel: &str, body: &[u8]) {
        let p = home.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    #[test]
    fn terraform_state_secrets_past_the_head_are_found() {
        let f = Fixture::new("tfstate");
        let state = format!(
            "{{\"version\":4,\"terraform_version\":\"1.9.0\",\"serial\":1,\"lineage\":\"{}\",\"outputs\":{{}},\"resources\":[{{\"mode\":\"managed\",\"type\":\"aws_db_instance\",\"name\":\"fixture\",\"instances\":[{{\"attributes\":{{\"password\":\"synthetic-only-value\"}},\"sensitive_attributes\":[[{{\"type\":\"get_attr\",\"value\":\"password\"}}]]}}]}}]}}",
            "0".repeat(5000)
        );
        put(&f.0, "infra/terraform.tfstate", state.as_bytes());
        put(&f.0, "infra/terraform.tfstate.backup", state.as_bytes());
        put(
            &f.0,
            "infra/empty/terraform.tfstate",
            b"{\"version\":4,\"terraform_version\":\"1.9.0\",\"resources\":[]}",
        );
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        assert_eq!(
            paths(&s),
            [
                "~/infra/terraform.tfstate",
                "~/infra/terraform.tfstate.backup"
            ]
        );
        assert!(s.not_checked.is_empty());
        // A state file too large to read is said to be unread.
        put(&f.0, "large/prod.tfstate", &vec![b' '; 2 * 1024 * 1024]);
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        let gaps: Vec<_> = s
            .not_checked
            .iter()
            .map(|g| (g.path.as_str(), g.reason))
            .collect();
        assert_eq!(gaps, [("~/large/prod.tfstate", "too-large")]);
    }

    #[test]
    fn mcp_remote_tokens_are_listed() {
        let f = Fixture::new("mcp-remote");
        let tokens = b"{\"access_token\":\"synthetic-only-value-1234\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"synthetic-only-value-5678\"}";
        put(&f.0, ".mcp-auth/mcp-remote-v1/0123abcd_tokens.json", tokens);
        put(
            &f.0,
            ".mcp-auth/mcp-remote-0.1.37/0123abcd_tokens.json",
            tokens,
        );
        // A design-tokens file with a similar name is not a sign-in.
        put(
            &f.0,
            "work/site/color_tokens.json",
            b"{\"color\":{\"primary\":{\"value\":\"#0055ff\"}}}",
        );
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        assert_eq!(
            paths(&s),
            [
                "~/.mcp-auth/mcp-remote-0.1.37/0123abcd_tokens.json",
                "~/.mcp-auth/mcp-remote-v1/0123abcd_tokens.json"
            ]
        );
        assert!(s.findings.iter().all(|x| x.rule == "dev.oauth.token-file"));
        assert!(s.not_checked.is_empty());
    }

    #[test]
    fn a_kubeconfig_outside_dot_kube_is_found() {
        let f = Fixture::new("kube-download");
        put(
            &f.0,
            "Downloads/prod-kubeconfig.yaml",
            b"apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: c3ludGhldGlj\n    server: https://k8s.example.invalid\n  name: fixture\nkind: Config\nusers:\n- name: fixture\n  user:\n    token: synthetic-only-value-abcdef\n",
        );
        // A manifest with a token-named field is not a kubeconfig.
        put(
            &f.0,
            "work/app/deploy.yaml",
            b"apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers: []\n      token: synthetic-only-value-abcdef\n",
        );
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        assert_eq!(paths(&s), ["~/Downloads/prod-kubeconfig.yaml"]);
        assert_eq!(s.findings[0].rule, "dev.kube.inline-credentials");
    }

    #[test]
    fn rclone_remotes_with_stored_secrets_are_found() {
        let f = Fixture::new("rclone");
        put(
            &f.0,
            ".config/rclone/rclone.conf",
            b"[nas]\ntype = sftp\nhost = sftp.example.invalid\nuser = fixture\npass = c3ludGhldGljLW9ubHk\n\n[drive]\ntype = drive\nscope = drive\ntoken = {\"access_token\":\"synthetic-only-value-1234\",\"token_type\":\"Bearer\",\"refresh_token\":\"synthetic-only-value-5678\",\"expiry\":\"2026-01-01T00:00:00Z\"}\n\n[local]\ntype = local\n\n[agent]\ntype = sftp\nhost = sftp.example.invalid\npass = \nkey_file = ~/.ssh/id_ed25519\n",
        );
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        let subjects: Vec<_> = s
            .findings
            .iter()
            .filter(|x| x.path == "~/.config/rclone/rclone.conf")
            .map(|x| x.subject.as_deref().unwrap_or(""))
            .collect();
        assert_eq!(subjects, ["nas", "drive"]);
    }

    #[test]
    fn dotenv_and_history_siblings_are_read_whole() {
        assert!(Target::Name("*.env").names("prod.env".as_ref()));
        assert!(!Target::Name("*.env").names(".env".as_ref()));
        let f = Fixture::new("env-siblings");
        // The secret sits past the first 4 KiB, and has no issuer format.
        let late = format!(
            "{}DATABASE_PASSWORD=synthetic-only-value\n",
            "PORT=8080\n".repeat(500)
        );
        put(&f.0, "work/app/prod.env", late.as_bytes());
        put(&f.0, "work/app/.dev.vars", late.as_bytes());
        put(
            &f.0,
            "work/app/.streamlit/secrets.toml",
            b"db_password = \"synthetic-only-value\"\n",
        );
        put(
            &f.0,
            ".bash_sessions/A1B2.history",
            b"export API_TOKEN=synthetic-only-value\n",
        );
        put(
            &f.0,
            ".histfile",
            b"export API_TOKEN=synthetic-only-value\n",
        );
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        let mut found = paths(&s);
        found.sort_unstable();
        assert_eq!(
            found,
            [
                "~/.bash_sessions/A1B2.history",
                "~/.histfile",
                "~/work/app/.dev.vars",
                "~/work/app/.streamlit/secrets.toml",
                "~/work/app/prod.env",
            ]
        );
        assert!(s.findings.iter().all(|x| x.rule == "secret.env-assignment"));
    }

    #[test]
    fn settings_with_comments_and_continue_yaml_are_read() {
        let f = Fixture::new("jsonc");
        // As Zed creates it: comment lines first, trailing commas allowed.
        put(
            &f.0,
            ".config/zed/settings.json",
            b"// Zed settings\n//\n// For information on how to configure Zed, see the Zed\n// documentation: https://zed.dev/docs/configuring-zed\n{\n  \"ui_font_size\": 16,\n  \"context_servers\": {\n    \"fixture\": {\n      \"command\": \"npx\",\n      \"args\": [\"-y\", \"fixture-server\"],\n      \"env\": {\"FIXTURE_TOKEN\": \"synthetic-only-value\"},\n    },\n  },\n}\n",
        );
        put(
            &f.0,
            ".continue/config.yaml",
            b"name: fixture\nversion: 1.0.0\nmodels:\n  - name: fixture\n    provider: openai\n    model: fixture-model\n    apiKey: synthetic-only-value\n  - name: referenced\n    provider: openai\n    model: fixture-model\n    apiKey: ${{ secrets.FIXTURE_KEY }}\n",
        );
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        assert!(
            s.not_checked.is_empty(),
            "a healthy Zed settings file is a gap"
        );
        assert_eq!(
            rules_at(&s, "~/.config/zed/settings.json"),
            ["dev.mcp.inline-secret"]
        );
        assert_eq!(
            rules_at(&s, "~/.continue/config.yaml"),
            ["dev.mcp.inline-secret"]
        );
        assert_eq!(s.findings.len(), 2);
    }

    #[test]
    fn a_1password_export_is_found_whatever_its_first_member() {
        let f = Fixture::new("1pux");
        // Layout of a real export with attachments: files/ members come
        // first, so export.attributes and export.data are past the head.
        let mut zip = b"PK\x03\x04\x14\x00\x00\x00\x00\x00".to_vec();
        zip.extend_from_slice(&[0; 20]);
        zip.extend_from_slice(b"files/fixture.png");
        zip.extend_from_slice(&[b'x'; 6000]);
        zip.extend_from_slice(b"PK\x03\x04\x14\x00\x00\x00\x08\x00");
        zip.extend_from_slice(&[0; 20]);
        zip.extend_from_slice(b"export.attributes{}");
        put(&f.0, "Downloads/fixture.1pux", &zip);
        // An ordinary archive is not reported.
        let mut other = b"PK\x03\x04\x14\x00\x00\x00\x08\x00".to_vec();
        other.extend_from_slice(&[0; 20]);
        other.extend_from_slice(b"word/document.xml");
        put(&f.0, "Downloads/fixture.docx", &other);
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        assert_eq!(paths(&s), ["~/Downloads/fixture.1pux"]);
    }

    #[test]
    fn newer_cli_sign_ins_are_listed() {
        let f = Fixture::new("cli-logins");
        put(
            &f.0,
            ".expo/state.json",
            b"{\"auth\": {\"sessionSecret\": \"{\\\"id\\\":\\\"synthetic-only-value\\\",\\\"version\\\":1}\", \"userId\": \"fixture\", \"username\": \"fixture\"}}",
        );
        put(
            &f.0,
            ".local/share/uv/credentials/credentials.toml",
            b"[[credential]]\nservice = \"https://pypi.example.invalid/simple\"\nusername = \"fixture\"\nscheme = \"basic\"\npassword = \"synthetic-only-value\"\n",
        );
        put(
            &f.0,
            ".modal.toml",
            b"[default]\ntoken_id = \"ak-fixture\"\ntoken_secret = \"as-synthetic-only-value\"\n",
        );
        put(
            &f.0,
            ".kaggle/kaggle.json",
            b"{\"username\":\"fixture\",\"key\":\"0123456789abcdef0123456789abcdef\"}",
        );
        put(
            &f.0,
            ".aws/login/cache/0123abcd.json",
            b"{\"accessToken\":{\"accessKeyId\":\"fixture\",\"secretAccessKey\":\"synthetic-only-value-1234\",\"sessionToken\":\"synthetic-only-value-5678\",\"accountId\":\"000000000000\",\"expiresAt\":\"2026-01-01T00:00:00Z\"},\"refreshToken\":\"synthetic-only-value-9999\",\"clientId\":\"fixture\",\"dpopKey\":\"fixture\"}",
        );
        // A folder with a name like a known one is not read as that one.
        put(
            &f.0,
            ".expo-staging/state.json",
            b"{\"auth\": null, \"uuid\": \"fixture\"}",
        );
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        let mut found: Vec<_> = s
            .findings
            .iter()
            .map(|x| (x.path.as_str(), x.rule))
            .collect();
        found.sort_unstable();
        assert_eq!(
            found,
            [
                ("~/.aws/login/cache/0123abcd.json", "dev.aws.session-cache"),
                ("~/.expo/state.json", "dev.cli.stored-login"),
                ("~/.kaggle/kaggle.json", "dev.cli.stored-login"),
                (
                    "~/.local/share/uv/credentials/credentials.toml",
                    "dev.cli.stored-login"
                ),
                ("~/.modal.toml", "dev.cli.stored-login"),
            ]
        );
    }

    #[test]
    fn warehouse_passwords_are_found_and_key_paths_are_not() {
        let f = Fixture::new("warehouse");
        put(
            &f.0,
            ".dbt/profiles.yml",
            b"fixture:\n  target: prod\n  outputs:\n    prod:\n      type: redshift\n      host: warehouse.example.invalid\n      user: fixture\n      password: synthetic-only-value\n    dev:\n      type: postgres\n      host: localhost\n      user: fixture\n      password: \"{{ env_var('DBT_PASSWORD') }}\"\n      sslkey: /Users/fixture/certs/client.key\n      sslcert: /Users/fixture/certs/client.crt\n",
        );
        put(
            &f.0,
            ".snowsql/config",
            b"[connections.fixture]\naccountname = fixture\nusername = fixture\npassword = synthetic-only-value\n",
        );
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        let found: Vec<_> = s
            .findings
            .iter()
            .map(|x| (x.path.as_str(), x.line))
            .collect();
        // One hit per file: the literal password, not the env_var reference
        // and not the path to a client key.
        assert_eq!(
            found,
            [
                ("~/.dbt/profiles.yml", Some(8)),
                ("~/.snowsql/config", Some(4))
            ]
        );
    }

    #[test]
    fn changed_paths_are_checked_alone() {
        let f = Fixture::new("changed");
        let cancel = || Arc::new(AtomicBool::new(false));
        files(&f.0.join("old"), 20);
        fs::write(f.0.join("old/export.csv"), "url,username,password\n").unwrap();
        files(&f.0.join("new/inner"), 3);
        fs::write(f.0.join("new/inner/export.csv"), "url,username,password\n").unwrap();
        files(&f.0.join("node_modules/pkg"), 0);
        fs::write(
            f.0.join("node_modules/pkg/export.csv"),
            "url,username,password\n",
        )
        .unwrap();
        fs::write(f.0.join(".npmrc"), "_authToken=synthetic-only\n").unwrap();
        fs::create_dir(f.0.join(".ssh")).unwrap();
        fs::write(
            f.0.join(".ssh/id_fixture"),
            "-----BEGIN RSA PRIVATE KEY-----\nsynthetic\n",
        )
        .unwrap();
        let check = |paths: &[&str]| {
            let paths: Vec<_> = paths.iter().map(|p| f.0.join(p)).collect();
            let r = Scan::changed(&f.0, &[], &paths, limits(1000), cancel(), digest).0;
            let mut found: Vec<_> = r.findings.into_iter().map(|x| x.path).collect();
            found.sort();
            found
        };
        // A file, a folder that was moved in, and a known location.
        assert_eq!(check(&["new/inner/export.csv"]), ["~/new/inner/export.csv"]);
        assert_eq!(check(&["new"]), ["~/new/inner/export.csv"]);
        assert_eq!(check(&[".npmrc"]), ["~/.npmrc"]);
        assert_eq!(check(&[".ssh/id_fixture"]), ["~/.ssh/id_fixture"]);
        assert_eq!(check(&[".ssh"]), ["~/.ssh/id_fixture"]);
        // Nothing else is read: not the unchanged folder, a skipped folder,
        // a deleted file, or anything outside the home.
        assert!(check(&["old/file-00", "node_modules/pkg/export.csv", "gone"]).is_empty());
        let outside = f.0.parent().unwrap().join("elsewhere.csv");
        let r = Scan::changed(&f.0, &[], &[outside], limits(1000), cancel(), digest).0;
        assert!(r.findings.is_empty());

        // A known location that is a link is checked when its real file changes.
        fs::create_dir(f.0.join("dotfiles")).unwrap();
        fs::rename(f.0.join(".npmrc"), f.0.join("dotfiles/npmrc")).unwrap();
        std::os::unix::fs::symlink(f.0.join("dotfiles/npmrc"), f.0.join(".npmrc")).unwrap();
        assert_eq!(check(&["dotfiles/npmrc"]), ["~/dotfiles/npmrc"]);
        assert_eq!(check(&[".npmrc"]), ["~/dotfiles/npmrc"]);
    }

    /// What a full scan finds, and what a check of these changed paths
    /// finds, as rule and place, with what each lists as not checked.
    type Seen = (Vec<(&'static str, String)>, Vec<(String, &'static str)>);
    fn seen(r: Report) -> Seen {
        let mut found: Vec<_> = r.findings.into_iter().map(|x| (x.rule, x.path)).collect();
        found.sort();
        let gaps = r.not_checked.into_iter().map(|g| (g.path, g.reason));
        (found, gaps.collect())
    }
    fn full(home: &Path) -> Seen {
        let cancel = Arc::new(AtomicBool::new(false));
        seen(Scan::report_controlled(
            home,
            &[],
            &[],
            cancel,
            digest,
            |_| {},
        ))
    }
    fn change(home: &Path, skip: &[&str], path: &str) -> Seen {
        let cancel = Arc::new(AtomicBool::new(false));
        let skip: Vec<_> = skip.iter().map(|s| home.join(s)).collect();
        let (r, left) = Scan::changed(
            home,
            &skip,
            &[home.join(path)],
            limits(1000),
            cancel,
            digest,
        );
        assert_eq!(left, Unreached::default(), "{path}");
        seen(r)
    }

    /// A folder of sign-ins was compared with a changed path as it is named
    /// only. Where the folder, or an account in it, is a link, macOS reports
    /// a change at the real place, and the check of that change read nothing:
    /// no finding, no gap, nothing left to do.
    #[test]
    fn a_change_behind_a_linked_folder_of_sign_ins_is_checked_as_a_scan_checks_it() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new("each-changed");
        let signed_in = br#"{"type": "authorized_user", "refresh_token": "synthetic-only-value"}"#;
        let rule = "dev.gcloud.stored-login";
        let known = ".config/gcloud/legacy_credentials";
        // The folder is a link.
        put(&f.0, "actual/account/adc.json", signed_in);
        fs::create_dir_all(f.0.join(".config/gcloud")).unwrap();
        symlink(f.0.join("actual"), f.0.join(known)).unwrap();
        let found = (
            vec![(rule, "~/actual/account/adc.json".to_string())],
            vec![],
        );
        assert_eq!(full(&f.0), found);
        // The file, the account's folder, the folder moved into place, and
        // the location as it is named.
        for path in ["actual/account/adc.json", "actual/account", "actual", known] {
            assert_eq!(change(&f.0, &[], path), found, "{path}");
        }
        // Nothing but what the scan reads there: one named file for each account.
        put(&f.0, "actual/account/deeper/adc.json", signed_in);
        put(&f.0, "actual/account/other.json", signed_in);
        put(&f.0, "beside/account/adc.json", signed_in);
        assert_eq!(full(&f.0), found);
        for path in [
            "actual/account/deeper/adc.json",
            "actual/account/deeper",
            "actual/account/other.json",
            "beside/account/adc.json",
            "beside",
        ] {
            assert_eq!(change(&f.0, &[], path), (vec![], vec![]), "{path}");
        }
        // Nothing is read for a change in a folder the person skipped.
        let skipped = change(&f.0, &["actual"], "actual/account/adc.json");
        assert_eq!(skipped, (vec![], vec![]));

        // One account in the folder is a link.
        fs::remove_file(f.0.join(known)).unwrap();
        fs::remove_dir_all(f.0.join("actual")).unwrap();
        fs::remove_dir_all(f.0.join("beside")).unwrap();
        put(&f.0, "dotfiles/gcloud/acct/adc.json", signed_in);
        fs::create_dir(f.0.join(known)).unwrap();
        symlink(
            f.0.join("dotfiles/gcloud/acct"),
            f.0.join(known).join("acct"),
        )
        .unwrap();
        let found = (
            vec![(rule, "~/dotfiles/gcloud/acct/adc.json".to_string())],
            vec![],
        );
        assert_eq!(full(&f.0), found);
        for path in [
            "dotfiles/gcloud/acct/adc.json",
            "dotfiles/gcloud/acct",
            "dotfiles",
        ] {
            assert_eq!(change(&f.0, &[], path), found, "{path}");
        }
        // It leads into a folder discovery passes over. A check stopped
        // before it got there says the change is still to be checked.
        let passed = "build/node_modules/acct";
        put(&f.0, &format!("{passed}/adc.json"), signed_in);
        fs::remove_file(f.0.join(known).join("acct")).unwrap();
        symlink(f.0.join(passed), f.0.join(known).join("acct")).unwrap();
        let found = (vec![(rule, format!("~/{passed}/adc.json"))], vec![]);
        assert_eq!(full(&f.0), found);
        assert_eq!(change(&f.0, &[], &format!("{passed}/adc.json")), found);
        // And as the agent hands it on: a change of the folder passed over.
        let at = change_at(&f.0, &f.0.join(passed).join("adc.json"));
        assert_eq!(at, f.0.join("build/node_modules"));
        assert_eq!(change(&f.0, &[], "build/node_modules"), found);
        let none = Limits {
            entries: 1000,
            time: Duration::ZERO,
        };
        let changed = [f.0.join(passed).join("adc.json")];
        let cancel = Arc::new(AtomicBool::new(false));
        let (r, left) = Scan::changed(&f.0, &[], &changed, none, cancel, digest);
        assert!(r.findings.is_empty());
        assert_eq!(left.out_of_budget, changed);
        fs::remove_dir_all(f.0.join("build")).unwrap();

        // A link that leads out of the home folder is followed by neither,
        // and both say so.
        let outside = Fixture::new("each-changed-outside");
        put(&outside.0, "account/adc.json", signed_in);
        fs::remove_dir_all(f.0.join(known)).unwrap();
        fs::remove_dir_all(f.0.join("dotfiles")).unwrap();
        symlink(&outside.0, f.0.join(known)).unwrap();
        let gap = (vec![], vec![(format!("~/{known}"), "symlink")]);
        assert_eq!(full(&f.0), gap);
        assert_eq!(change(&f.0, &[], known), gap);
        assert_eq!(change(&f.0, &[], ".config/gcloud"), gap);
    }

    /// The agent hands on a change inside a folder discovery passes over as
    /// a change of the outermost such folder. Checked, that folder reads what
    /// the change itself would: here a known file that is a link into it.
    #[test]
    fn a_change_where_discovery_does_not_go_is_one_of_the_folder_it_passes_over() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new("change-at");
        let home = &f.0;
        let at = |p: &str| change_at(home, &home.join(p));
        assert_eq!(at("proj/target/debug/a.o"), home.join("proj/target"));
        assert_eq!(at("proj/.git/objects/ab/cd"), home.join("proj/.git"));
        assert_eq!(at("proj/.git/config"), home.join("proj/.git"));
        assert_eq!(
            at("app/node_modules/pkg/.git/x"),
            home.join("app/node_modules")
        );
        assert_eq!(at("Library/Caches/app/x"), home.join("Library/Caches"));
        assert_eq!(at("proj/target"), home.join("proj/target"));
        assert_eq!(at("proj/src/main.rs"), home.join("proj/src/main.rs"));
        assert_eq!(
            change_at(home, Path::new("/elsewhere/target/x")),
            PathBuf::from("/elsewhere/target/x")
        );

        let real = "dotfiles/vendor/git/config";
        let url = b"[url \"https://fixture:synthetic-only@git.example.invalid/\"]\n\tinsteadOf = https://git.example.invalid/\n";
        put(home, real, url);
        symlink(home.join(real), home.join(".gitconfig")).unwrap();
        let found = (
            vec![("dev.url.inline-password", format!("~/{real}"))],
            vec![],
        );
        assert_eq!(full(home), found);
        assert_eq!(at(real), home.join("dotfiles/vendor"));
        assert_eq!(change(home, &[], "dotfiles/vendor"), found);
    }

    /// The same for a known folder whose files are each read: one of them
    /// is a link, and the change is at the file it leads to.
    #[test]
    fn a_change_behind_a_linked_file_of_a_known_folder_is_checked_as_a_scan_checks_it() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new("dir-changed");
        let known = ".aws/sso/cache";
        let reads = |r: &&Rule| r.targets.contains(&Target::Dir(known));
        let rule = RULES.iter().find(reads).unwrap();
        let session = rule.samples.iter().find(|sample| sample.1).unwrap().0;
        put(&f.0, "elsewhere/session.json", session);
        fs::create_dir_all(f.0.join(known)).unwrap();
        let link = format!("{known}/session.json");
        symlink(f.0.join("elsewhere/session.json"), f.0.join(&link)).unwrap();
        let found = (
            vec![(rule.id, "~/elsewhere/session.json".to_string())],
            vec![],
        );
        assert_eq!(full(&f.0), found);
        for path in ["elsewhere/session.json", "elsewhere", link.as_str(), known] {
            assert_eq!(change(&f.0, &[], path), found, "{path}");
        }
        // A file beside it that no link leads to is read by neither.
        put(&f.0, "elsewhere/other.json", session);
        assert_eq!(full(&f.0), found);
        assert_eq!(change(&f.0, &[], "elsewhere/other.json"), (vec![], vec![]));
        // A link that leads out of the home folder is followed by neither.
        // The scan says so, and so does a check of the folder it is in; a
        // check of another change has nothing to say of it.
        let outside = Fixture::new("dir-changed-outside");
        put(&outside.0, "session.json", session);
        let out = format!("{known}/outside.json");
        symlink(outside.0.join("session.json"), f.0.join(&out)).unwrap();
        let gap = (found.0.clone(), vec![(format!("~/{out}"), "symlink")]);
        assert_eq!(full(&f.0), gap);
        assert_eq!(change(&f.0, &[], known), gap);
        assert_eq!(change(&f.0, &[], "elsewhere/session.json"), found);
    }

    /// A browser's sign-in database was checked only when a change named the
    /// file itself. A profile moved in as a whole is one change, of its
    /// folder, and its saved passwords and its wallet were not found.
    #[test]
    fn a_changed_browser_profile_folder_is_checked_as_a_scan_checks_it() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new("profile-changed");
        let logins = crate::rules::browser::CHROMIUM_LOGINS.samples[0].0;
        let rule = "browser.chromium.saved-logins";
        let chrome = "Library/Application Support/Google/Chrome";
        let profile = format!("{chrome}/Profile 1");
        let database = format!("{profile}/Login Data");
        put(&f.0, &database, logins);
        let found = (vec![(rule, format!("~/{database}"))], vec![]);
        assert_eq!(full(&f.0), found);
        // The file, its profile, the browser's folder and a folder above it.
        let above = "Library/Application Support/Google";
        for path in [database.as_str(), profile.as_str(), chrome, above] {
            assert_eq!(change(&f.0, &[], path), found, "{path}");
        }
        // Nothing but what the scan reads there: the named file in a
        // profile, not one deeper in it, and not a profile kept elsewhere.
        put(&f.0, &format!("{profile}/Snapshots/Login Data"), logins);
        put(&f.0, "Documents/Profile 1/Login Data", logins);
        assert_eq!(full(&f.0), found);
        for path in [
            format!("{profile}/Snapshots/Login Data"),
            "Documents/Profile 1/Login Data".to_string(),
            "Documents/Profile 1".to_string(),
        ] {
            assert_eq!(change(&f.0, &[], &path), (vec![], vec![]), "{path}");
        }
        assert_eq!(change(&f.0, &[], &profile), found);
        // A file beside the profiles, which a browser writes all the time.
        put(&f.0, &format!("{chrome}/Local State"), b"{}");
        let beside = format!("{chrome}/Local State");
        assert_eq!(change(&f.0, &[], &beside), (vec![], vec![]));
        // A profile kept at the top of the browser's folder, and a wallet
        // extension's storage in a profile.
        let id = "nkbihfbeogaeaoehlefnkodbefgpgknn";
        let store = format!("{profile}/Local Extension Settings/{id}");
        fs::create_dir_all(f.0.join(&store)).unwrap();
        put(&f.0, &format!("{chrome}/Login Data"), logins);
        let wallet = "wallet.extension.vault";
        let found = (
            vec![
                (rule, format!("~/{chrome}/Login Data")),
                (rule, format!("~/{database}")),
                (wallet, format!("~/{store}")),
            ],
            vec![],
        );
        assert_eq!(full(&f.0), found);
        assert_eq!(change(&f.0, &[], chrome), found);
        assert_eq!(change(&f.0, &[], above), found);
        let in_profile = (found.0[1..].to_vec(), vec![]);
        assert_eq!(change(&f.0, &[], &profile), in_profile);
        let settings = format!("{profile}/Local Extension Settings");
        assert_eq!(
            change(&f.0, &[], &settings),
            (found.0[2..].to_vec(), vec![])
        );
        let top = (found.0[..1].to_vec(), vec![]);
        assert_eq!(change(&f.0, &[], &format!("{chrome}/Login Data")), top);

        // The browser's folder is a link, and so is one profile in it.
        fs::remove_dir_all(f.0.join("Library")).unwrap();
        fs::remove_dir_all(f.0.join("Documents")).unwrap();
        put(&f.0, "Moved/Chrome/Profile 1/Login Data", logins);
        put(&f.0, "Sync/profile/Login Data", logins);
        fs::create_dir_all(f.0.join(above)).unwrap();
        symlink(f.0.join("Moved/Chrome"), f.0.join(chrome)).unwrap();
        symlink(f.0.join("Sync/profile"), f.0.join("Moved/Chrome/Profile 2")).unwrap();
        let moved = (rule, "~/Moved/Chrome/Profile 1/Login Data".to_string());
        let synced = (rule, "~/Sync/profile/Login Data".to_string());
        assert_eq!(full(&f.0), (vec![moved.clone(), synced.clone()], vec![]));
        for path in [
            "Moved/Chrome/Profile 1/Login Data",
            "Moved/Chrome/Profile 1",
        ] {
            assert_eq!(change(&f.0, &[], path), (vec![moved.clone()], vec![]));
        }
        for path in ["Sync/profile/Login Data", "Sync/profile", "Sync"] {
            assert_eq!(change(&f.0, &[], path), (vec![synced.clone()], vec![]));
        }
        let both = (vec![moved, synced], vec![]);
        for path in ["Moved/Chrome", "Moved", chrome] {
            assert_eq!(change(&f.0, &[], path), both, "{path}");
        }
    }

    /// A check of these changed paths with these limits, cancelled before it
    /// began or not: the entries it listed, what it found and did not check,
    /// and the paths it did not finish.
    fn checked(
        home: &Path,
        paths: &[&str],
        limits: Limits,
        cancelled: bool,
    ) -> (usize, Seen, Unreached) {
        let cancel = Arc::new(AtomicBool::new(cancelled));
        let mut s = Scan::new(
            home,
            None,
            Some(cancel),
            Some(Box::new(digest)),
            limits.entries,
        );
        s.limit = limits.time;
        let paths: Vec<_> = paths.iter().map(|p| home.join(p)).collect();
        let left = s.changes(&paths);
        let listed = s.counts.entries;
        let report = s.finish().into_report(&[home.to_path_buf()]);
        (listed, seen(report), left)
    }

    /// A home with one known folder, of sessions each read as a file. One of
    /// them is a link to a file kept elsewhere, and a file no rule reads is
    /// in a folder discovery passes over. Returns the rule and the folder.
    fn linked_session(home: &Path) -> (&'static str, &'static str) {
        let known = ".aws/sso/cache";
        let reads = |r: &&Rule| r.targets.contains(&Target::Dir(known));
        let rule = RULES.iter().find(reads).unwrap();
        let session = rule.samples.iter().find(|sample| sample.1).unwrap().0;
        put(home, "elsewhere/session.json", session);
        put(home, &format!("{known}/other.json"), b"{}");
        std::os::unix::fs::symlink(
            home.join("elsewhere/session.json"),
            home.join(known).join("session.json"),
        )
        .unwrap();
        put(home, "build/node_modules/pkg/data.json", b"{}");
        (rule.id, known)
    }

    /// To learn whether a link in a known folder leads to a changed path, a
    /// check listed every known folder, 10,000 names of each, whatever it was
    /// given to spend and also once it had been cancelled.
    #[test]
    fn a_cancelled_change_check_lists_no_known_folder_to_look_for_links() {
        let f = Fixture::new("links-cancelled");
        let (rule, known) = linked_session(&f.0);
        std::os::unix::fs::symlink(f.0.join("elsewhere"), f.0.join("link")).unwrap();
        let paths = [
            "elsewhere/session.json",
            "build/node_modules/pkg/data.json",
            "gone.json",
            "link",
        ];
        // Not stopped, the folder is listed once for all of them.
        let (listed, found, left) = checked(&f.0, &paths, limits(1000), false);
        assert_eq!(listed, 2);
        let session = (rule, "~/elsewhere/session.json".to_string());
        assert_eq!(found, (vec![session], vec![]));
        assert_eq!(left, Unreached::default());
        // Cancelled, nothing is listed and nothing read. The folder is said
        // not to have been looked at, and a path a link in it may lead to is
        // still to be checked: not one that is gone or is itself a link.
        let (listed, found, left) = checked(&f.0, &paths, limits(1000), true);
        assert_eq!(listed, 0, "a folder was listed after the cancel");
        let gaps = [known, paths[0], paths[1]].map(|p| (format!("~/{p}"), "scan-limit"));
        assert_eq!(found, (vec![], gaps.to_vec()));
        assert_eq!(left.cancelled, [f.0.join(paths[0]), f.0.join(paths[1])]);
        assert!(left.out_of_budget.is_empty() && left.cut_short.is_empty());
    }

    #[test]
    fn a_wide_known_folder_is_listed_out_of_the_entries_a_change_check_may_list() {
        let f = Fixture::new("links-budget");
        let (rule, known) = linked_session(&f.0);
        for n in 0..39 {
            put(&f.0, &format!("{known}/plain-{n:02}.json"), b"{}");
        }
        put(&f.0, "notes/readme.txt", b"ordinary synthetic data");
        let paths = ["notes/readme.txt", "elsewhere/session.json"];
        let limited = vec![(format!("~/{known}"), "scan-limit")];
        // With entries enough for it, the folder is listed in full, once.
        let (listed, found, left) = checked(&f.0, &paths, limits(1000), false);
        let session = (rule, "~/elsewhere/session.json".to_string());
        assert_eq!((listed, found), (41, (vec![session], vec![])));
        assert_eq!(left, Unreached::default());
        // With fewer, no more of it than those. A link past them may lead
        // to either path, so the folder is a gap and neither is finished.
        for entries in [5, 0] {
            let (listed, found, left) = checked(&f.0, &paths, limits(entries), false);
            assert_eq!(listed, entries, "more entries listed than the check had");
            assert_eq!(found.1, limited);
            // The first path had the check to itself; the second only what
            // the first left of it, so a check of its own may finish it.
            assert_eq!(left.cut_short, [f.0.join(paths[0])]);
            assert_eq!(left.out_of_budget, [f.0.join(paths[1])]);
            assert!(left.cancelled.is_empty());
        }
        // More names than any scan lists of one folder: said as a scan says
        // it, and nothing a full pass would finish.
        for n in 0..10_000 {
            fs::write(f.0.join(known).join(format!("wide-{n:05}")), "").unwrap();
        }
        let (listed, found, left) = checked(&f.0, &paths[..1], limits(20_000), false);
        assert_eq!((listed, found), (10_000, (vec![], limited)));
        assert_eq!(left, Unreached::default());
    }

    #[test]
    fn a_change_is_not_finished_while_a_link_that_may_lead_to_it_was_not_looked_for() {
        let f = Fixture::new("links-unfinished");
        let (_, known) = linked_session(&f.0);
        std::os::unix::fs::symlink(f.0.join("elsewhere"), f.0.join("link")).unwrap();
        let unrelated = "build/node_modules/pkg/data.json";
        // Out of time before the first path: nothing says where the links in
        // the folder lead, so a path no rule reads may be one they lead to.
        let none = Limits {
            entries: 1000,
            time: Duration::ZERO,
        };
        let paths = [unrelated, "gone.json", "link"];
        let (listed, found, left) = checked(&f.0, &paths, none, false);
        assert_eq!(listed, 0);
        let gaps = [known, unrelated].map(|p| (format!("~/{p}"), "scan-limit"));
        assert_eq!(found, (vec![], gaps.to_vec()));
        assert_eq!(left.out_of_budget, [f.0.join(unrelated)]);
        assert!(left.cancelled.is_empty() && left.cut_short.is_empty());
        // Cancelled while the folder itself was read, before any path asked
        // where its links lead: the same for the paths after it.
        let paths = [known, "elsewhere/session.json", unrelated, "gone.json"].map(|p| f.0.join(p));
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = cancel.clone();
        let digest = move |_: &str, _: &[u8], _: bool| {
            stop.store(true, Ordering::SeqCst);
            "synthetic-digest".to_string()
        };
        let (r, left) = Scan::changed(&f.0, &[], &paths, limits(1000), cancel, digest);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(left.cancelled, paths[..3]);
        assert!(left.out_of_budget.is_empty() && left.cut_short.is_empty());
        // With no known folder there, no link leads anywhere, and a stopped
        // check says so only of what it would have read: not of a path no
        // rule reads.
        let bare = Fixture::new("links-none");
        put(&bare.0, unrelated, b"{}");
        put(&bare.0, "project/.git/config", b"[core]\n\tbare = false\n");
        put(&bare.0, "project/.git/index", b"synthetic");
        for (path, said) in [
            ("project/.git/config", 1),
            ("project/.git", 1),
            ("project/.git/index", 0),
            (unrelated, 0),
        ] {
            let (listed, found, left) = checked(&bare.0, &[path], none, false);
            assert_eq!((listed, found.1.len()), (0, said), "{path}");
            assert_eq!(left.out_of_budget.len(), said, "{path}");
        }
    }

    /// What is found, as rule and place.
    type Found = Vec<(&'static str, String)>;

    /// A home with two browsers. The first has two profiles with saved
    /// sign-ins and a wallet extension's storage in one of them; the other
    /// has the wallet's storage in its one profile. Returns each browser's
    /// folder, what a scan finds in the first, and what it finds in both.
    fn two_browsers(home: &Path) -> ([&'static str; 2], [Found; 2]) {
        let logins = crate::rules::browser::CHROMIUM_LOGINS.samples[0].0;
        let browsers = [
            "Library/Application Support/Google/Chrome",
            "Library/Application Support/Chromium",
        ];
        let store = "Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn";
        let stores = [
            format!("{}/Profile 1/{store}", browsers[0]),
            format!("{}/Default/{store}", browsers[1]),
        ];
        let saved = ["Profile 1", "Profile 2"].map(|p| format!("{}/{p}/Login Data", browsers[0]));
        for database in &saved {
            put(home, database, logins);
        }
        for store in &stores {
            fs::create_dir_all(home.join(store)).unwrap();
        }
        let [first, second] = saved.map(|p| ("browser.chromium.saved-logins", format!("~/{p}")));
        let [wallet, other] = stores.map(|p| ("wallet.extension.vault", format!("~/{p}")));
        let one = vec![first, second, wallet];
        let mut both = one.clone();
        both.push(other);
        both.sort();
        (browsers, [one, both])
    }

    /// For a browser's folder that changed, or a folder above it, a check
    /// listed every browser's folder for the extensions in its profiles,
    /// 10,000 names of each, whatever it was given to spend and also once
    /// it had been stopped, and then looked in every profile listed.
    #[test]
    fn a_stopped_change_check_lists_no_browser_folder_for_its_profiles() {
        let f = Fixture::new("profiles-stopped");
        let ([chrome, other], [found, both]) = two_browsers(&f.0);
        let above = "Library/Application Support";
        assert_eq!(full(&f.0), (both.clone(), vec![]));
        // Not stopped, the changed browser's folder is listed once for
        // every rule that reads its profiles, and then walked: 2 names and
        // 6. The other browser's is listed only for a link that leads to
        // the change, its 1 name for each of the 2 files rules read in a
        // profile, and nothing is looked for in it.
        let (listed, saw, left) = checked(&f.0, &[chrome], limits(1000), false);
        assert_eq!((listed, saw), (10, (found, vec![])));
        assert_eq!(left, Unreached::default());
        // Above them both, what a scan finds in each.
        let (_, saw, left) = checked(&f.0, &[above], limits(1000), false);
        assert_eq!(saw, (both, vec![]));
        assert_eq!(left, Unreached::default());
        // Cancelled, nothing is listed and nothing read. The browser's
        // folder is said not to have been looked at, once, and the change
        // is still to be checked. So is the other's: a link in it may lead
        // to the change.
        let unread = |dir: &str| (format!("~/{dir}"), "scan-limit");
        let stopped = (vec![], vec![unread(chrome), unread(other)]);
        let (listed, saw, left) = checked(&f.0, &[chrome], limits(1000), true);
        assert_eq!(listed, 0, "a folder was listed after the cancel");
        assert_eq!(saw, stopped);
        assert_eq!(left.cancelled, [f.0.join(chrome)]);
        assert!(left.out_of_budget.is_empty() && left.cut_short.is_empty());
        // Out of time, the same of each browser's folder that is there.
        let none = Limits {
            entries: 1000,
            time: Duration::ZERO,
        };
        let (listed, saw, left) = checked(&f.0, &[above], none, false);
        assert_eq!(listed, 0, "a folder was listed after the time was up");
        assert_eq!(saw, stopped);
        assert_eq!(left.out_of_budget, [f.0.join(above)]);
        assert!(left.cancelled.is_empty() && left.cut_short.is_empty());
        // Cancelled while the first thing found is reported: no profile
        // after that one is looked in, and the folder says so, once.
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = cancel.clone();
        let digest = move |_: &str, _: &[u8], _: bool| {
            stop.store(true, Ordering::SeqCst);
            "synthetic-digest".to_string()
        };
        let paths = [f.0.join(chrome)];
        let (r, left) = Scan::changed(&f.0, &[], &paths, limits(1000), cancel, digest);
        let (found, gaps) = seen(r);
        assert_eq!((found.len(), gaps), (1, stopped.1));
        assert_eq!(left.cancelled, paths);
        assert!(left.out_of_budget.is_empty() && left.cut_short.is_empty());
    }

    #[test]
    fn a_browser_folder_is_listed_out_of_the_entries_a_change_check_may_list() {
        let f = Fixture::new("profiles-budget");
        let ([chrome, other], [found, _]) = two_browsers(&f.0);
        let above = "Library/Application Support";
        for n in 0..40 {
            fs::create_dir(f.0.join(chrome).join(format!("Guest {n:02}"))).unwrap();
        }
        let limited = |dir: &str| (format!("~/{dir}"), "scan-limit");
        // With entries enough for it, the folder is listed in full, once
        // for its profiles, and then walked: 42 names and 46. The other 2
        // are the other browser's, looked at for a link that leads here.
        let (listed, saw, left) = checked(&f.0, &[chrome], limits(1000), false);
        assert_eq!((listed, saw), (90, (found, vec![])));
        assert_eq!(left, Unreached::default());
        // With fewer, no more of it than those. A profile past them may
        // hold what a rule names, so the folder is a gap, said once, and
        // the change is not finished. Nor was the other browser's folder
        // looked at for a link that leads here.
        for entries in [5, 0] {
            let (listed, saw, left) = checked(&f.0, &[chrome], limits(entries), false);
            assert_eq!(listed, entries, "more entries listed than the check had");
            assert_eq!(saw.1, [chrome, other].map(limited));
            assert_eq!(left.cut_short, [f.0.join(chrome)]);
            assert!(left.cancelled.is_empty() && left.out_of_budget.is_empty());
        }
        // The same above two browsers: one check's entries for them both.
        let (listed, saw, left) = checked(&f.0, &[above], limits(5), false);
        assert_eq!(listed, 5, "more entries listed than the check had");
        assert_eq!(saw.1, [chrome, other, above].map(limited));
        assert_eq!(left.cut_short, [f.0.join(above)]);
        assert!(left.cancelled.is_empty() && left.out_of_budget.is_empty());
        // More names than any scan lists of one folder: said as a scan says
        // it, by the listing for the profiles and by the walk, and nothing
        // a full pass would finish.
        for n in 0..10_000 {
            fs::write(f.0.join(chrome).join(format!("wide-{n:05}")), "").unwrap();
        }
        let (listed, saw, left) = checked(&f.0, &[chrome], limits(100_000), false);
        assert!((20_000..100_000).contains(&listed), "{listed}");
        assert_eq!(saw.1, [limited(chrome), limited(chrome)]);
        assert_eq!(left, Unreached::default());
    }

    /// The helper is told of every change under the home, also in the stores
    /// macOS keeps for its own apps. Reading one there makes macOS ask the
    /// person for their contacts or photos with nobody at the window.
    #[test]
    fn a_change_in_a_store_macos_guards_is_not_read() {
        let f = Fixture::new("changed-guarded");
        let cancel = || Arc::new(AtomicBool::new(false));
        let stores = [
            "Library/Calendars/a",
            "Library/Application Support/AddressBook/Metadata",
            "Library/Reminders/Container_v1",
            "Library/Photos/Libraries/Syndication.photoslibrary/database",
            "Pictures/Photos Library.photoslibrary/database",
        ];
        for store in stores {
            files(&f.0.join(store), 0);
            fs::write(
                f.0.join(store).join("export.csv"),
                "url,username,password\n",
            )
            .unwrap();
        }
        files(&f.0.join("Library/Preferences"), 0);
        for name in ["com.apple.AddressBook.plist", "com.example.plist"] {
            let settings = f.0.join("Library/Preferences").join(name);
            fs::write(settings, "url,username,password\n").unwrap();
        }
        let check = |path: &str| {
            let changed = [f.0.join(path)];
            let r = Scan::changed(&f.0, &[], &changed, limits(1000), cancel(), digest).0;
            let mut found: Vec<_> = r.findings.into_iter().map(|x| x.path).collect();
            found.sort();
            found
        };
        for store in stores {
            assert!(check(&format!("{store}/export.csv")).is_empty(), "{store}");
            assert!(check(store).is_empty(), "{store}");
        }
        assert!(check("Library/Preferences/com.apple.AddressBook.plist").is_empty());
        // The folders around them are read as before.
        let beside = ["~/Library/Preferences/com.example.plist"];
        assert_eq!(check("Library/Preferences/com.example.plist"), beside);
        assert_eq!(check("Library"), beside);
        assert_eq!(check("Pictures"), [""; 0]);
    }

    #[test]
    fn a_changed_repository_config_is_checked_and_the_rest_of_git_is_not() {
        let f = Fixture::new("repo-changed");
        let cancel = || Arc::new(AtomicBool::new(false));
        let git = f.0.join("project/.git");
        fs::create_dir_all(&git).unwrap();
        fs::write(
            git.join("config"),
            "[remote \"origin\"]\n\turl = https://fixture:synthetic-only@git.example.invalid/p.git\n",
        )
        .unwrap();
        fs::write(git.join("export.csv"), "url,username,password\n").unwrap();
        let check = |skip: &[PathBuf], path: &str| {
            let changed = [f.0.join(path)];
            let r = Scan::changed(&f.0, skip, &changed, limits(1000), cancel(), digest).0;
            r.findings.into_iter().map(|x| x.path).collect::<Vec<_>>()
        };
        // The file itself, its folder, and the repository around it.
        for path in ["project/.git/config", "project/.git", "project"] {
            assert_eq!(check(&[], path), ["~/project/.git/config"], "{path}");
        }
        // Nothing else in the folder is read, and a skipped repository is left alone.
        assert!(check(&[], "project/.git/export.csv").is_empty());
        assert!(check(&[f.0.join("project")], "project/.git/config").is_empty());
        // A repository inside an excluded folder is not reached by a full scan
        // either, so a change there is not checked.
        fs::create_dir_all(f.0.join("node_modules/pkg")).unwrap();
        fs::rename(&git, f.0.join("node_modules/pkg/.git")).unwrap();
        assert!(check(&[], "node_modules/pkg/.git/config").is_empty());
    }

    #[test]
    fn a_change_is_checked_wherever_a_full_scan_reads() {
        let f = Fixture::new("changed-known");
        let cancel = || Arc::new(AtomicBool::new(false));
        // A home whose own path has a name that discovery passes over.
        let home = f.0.join("vendor");
        let token = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        // A token past the first 4 KiB, as in an agent's session record.
        let record = format!(
            "{}{{\"out\":\"{token}\"}}\n",
            "{\"type\":\"filler\"}\n".repeat(400)
        );
        for dir in [
            ".cache/huggingface",
            ".claude/projects/p",
            ".claude/plugins/x",
            "Library/Caches/claude-cli-nodejs/p",
        ] {
            fs::create_dir_all(home.join(dir)).unwrap();
        }
        fs::write(home.join(".npmrc"), "_authToken=synthetic-only\n").unwrap();
        fs::write(home.join(".cache/huggingface/token"), &token).unwrap();
        fs::write(home.join(".claude/projects/p/s.jsonl"), &record).unwrap();
        fs::write(home.join(".claude/plugins/x/s.jsonl"), &record).unwrap();
        fs::write(
            home.join("Library/Caches/claude-cli-nodejs/p/mcp.log"),
            &record,
        )
        .unwrap();
        let check = |path: &str| {
            let changed = [home.join(path)];
            let r = Scan::changed(&home, &[], &changed, limits(1000), cancel(), digest).0;
            let mut found: Vec<_> = r.findings.into_iter().map(|x| x.path).collect();
            found.sort();
            found
        };
        // Known locations, also inside a folder that discovery passes over.
        assert_eq!(check(".npmrc"), ["~/.npmrc"]);
        let cached = ["~/.cache/huggingface/token"];
        assert_eq!(check(".cache/huggingface/token"), cached);
        assert_eq!(check(".cache"), cached);
        let log = ["~/Library/Caches/claude-cli-nodejs/p/mcp.log"];
        assert_eq!(check("Library/Caches/claude-cli-nodejs/p/mcp.log"), log);
        assert_eq!(check("Library/Caches/claude-cli-nodejs/p"), log);
        // A folder of records that was moved in is read in full, like its files.
        let records = ["~/.claude/projects/p/s.jsonl"];
        assert_eq!(check(".claude/projects/p/s.jsonl"), records);
        assert_eq!(check(".claude/projects/p"), records);
        assert_eq!(check(".claude/projects"), records);
        // An agent's folder that is a link is read where it really is, and a
        // change is reported there.
        put(&home, "dotfiles/codex/sessions/s.jsonl", record.as_bytes());
        std::os::unix::fs::symlink(home.join("dotfiles/codex"), home.join(".codex")).unwrap();
        let linked = ["~/dotfiles/codex/sessions/s.jsonl"];
        assert_eq!(check("dotfiles/codex/sessions/s.jsonl"), linked);
        assert_eq!(check("dotfiles/codex/sessions"), linked);
        // Also when the change is reported for a folder above where it is.
        assert_eq!(check("dotfiles"), linked);
        // A known folder that is a link, the same.
        put(
            &home,
            "keys/zsh/a.history",
            b"export API_TOKEN=synthetic-only-value\n",
        );
        std::os::unix::fs::symlink(home.join("keys/zsh"), home.join(".zsh_sessions")).unwrap();
        let history = ["~/keys/zsh/a.history"];
        assert_eq!(check("keys/zsh/a.history"), history);
        assert_eq!(check("keys/zsh"), history);
        assert_eq!(check("keys"), history);
        // What a full scan leaves unread in an agent's folder stays unread.
        assert!(check(".claude/plugins/x/s.jsonl").is_empty());
        assert!(check(".claude/plugins/x").is_empty());
        // A record that is gone is not read, however deep it was.
        let gone = format!(".claude/{}gone.jsonl", "d/".repeat(18));
        let r = Scan::changed(
            &home,
            &[],
            &[home.join(gone)],
            limits(1000),
            cancel(),
            digest,
        )
        .0;
        assert!(r.findings.is_empty() && r.not_checked.is_empty());
        // Out of time, a check says so of what it would have read. This home
        // has a known folder, and the check did not look at where the links
        // in it lead. One may lead to a file no rule names, so that is said
        // of the folder and of such a file too. In a home with no known
        // folder nothing is said of one: see
        // `a_change_is_not_finished_while_a_link_that_may_lead_to_it_was_not_looked_for`.
        put(&home, "project/.git/config", b"[core]\n\tbare = false\n");
        put(&home, "project/.git/index", b"synthetic");
        let none = Limits {
            entries: 1000,
            time: Duration::ZERO,
        };
        let unread = |path: &str| {
            let r = Scan::changed(&home, &[], &[home.join(path)], none, cancel(), digest).0;
            let gaps = r.not_checked.into_iter().map(|g| g.path);
            gaps.collect::<Vec<_>>()
        };
        for path in ["project/.git/config", "project/.git", "project/.git/index"] {
            let said = ["~/keys/zsh".to_string(), format!("~/{path}")];
            assert_eq!(unread(path), said);
        }
        // A wallet extension is its storage folder in a browser profile, not
        // any folder that has the extension's name.
        let id = "nkbihfbeogaeaoehlefnkodbefgpgknn";
        let chrome = "Library/Application Support/Google/Chrome/Default";
        let stored = format!("{chrome}/Local Extension Settings/{id}");
        let program = format!("{chrome}/Extensions/{id}");
        let elsewhere = format!("Downloads/{id}");
        for dir in [&stored, &program, &elsewhere] {
            fs::create_dir_all(home.join(dir)).unwrap();
        }
        assert_eq!(check(&stored), [format!("~/{stored}")]);
        assert!(check(&program).is_empty());
        assert!(check(&elsewhere).is_empty());

        let full = Scan::report_controlled(&home, &[], &[], cancel(), digest, |_| {});
        let mut found: Vec<_> = full.findings.into_iter().map(|x| x.path).collect();
        found.sort();
        assert_eq!(
            found,
            [
                cached[0],
                records[0],
                "~/.npmrc",
                format!("~/{stored}").as_str(),
                log[0],
                linked[0],
                history[0],
            ],
            "the full scan finds the same places"
        );
    }

    #[test]
    fn more_different_tokens_than_a_record_keeps_is_said() {
        // A record lists 50 different tokens. One more is a limit reached,
        // and a limit that is reached is reported, not passed over.
        let f = Fixture::new("records-many");
        let tokens = |count: usize| -> String {
            (0..count)
                .map(|n| format!("{{\"out\":\"gh{}_abcdeABCDE{n:026}\"}}\n", "p"))
                .collect()
        };
        put(
            &f.0,
            ".claude/full/s.jsonl",
            format!("{}{}", record("none"), tokens(50)).as_bytes(),
        );
        put(
            &f.0,
            ".claude/over/s.jsonl",
            format!("{}{}", record("none"), tokens(60)).as_bytes(),
        );
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        let kept = |name: &str| s.findings.iter().filter(|x| x.path.contains(name)).count();
        assert_eq!((kept("full"), kept("over")), (50, 50));
        let gaps: Vec<_> = s
            .not_checked
            .iter()
            .map(|g| (g.path.as_str(), g.reason))
            .collect();
        assert_eq!(gaps, [("~/.claude/over/s.jsonl", "scan-limit")]);
    }

    #[test]
    fn two_tokens_of_one_kind_in_a_record_are_two_findings_wherever_they_sit() {
        let f = Fixture::new("records-same-kind");
        let one = format!("AK{}{}", "IA", "ABCDEFGHIJKLMNOP");
        let two = format!("AK{}{}", "IA", "QRSTUVWXYZ234567");
        // On one line, as a record keeps what a command printed.
        let line = format!("{{\"out\":\"[a]\\nid = {one}\\n[b]\\nid = {two}\\n\"}}\n");
        put(
            &f.0,
            ".claude/projects/p/s.jsonl",
            format!("{}{line}", record("no token here")).as_bytes(),
        );
        // In a file that is not text, where no hit has a line.
        let mut store = vec![0u8; 8192];
        store.extend(format!("\n{one}\n\x00\n{two}\n").bytes());
        put(&f.0, ".claude/projects/p/state.db", &store);
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        let records = |name: &str| {
            s.findings
                .iter()
                .filter(|x| x.rule == "secret.agent-record" && x.path.ends_with(name))
                .count()
        };
        assert_eq!((records("s.jsonl"), records("state.db")), (2, 2));
    }

    #[test]
    fn a_pass_cut_before_the_trees_lists_only_the_ones_that_are_there() {
        let f = Fixture::new("trees-there");
        put(&f.0, ".claude/projects/p/s.jsonl", b"{}\n");
        let none = Limits {
            entries: 1000,
            time: Duration::ZERO,
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let (r, left) = Scan::sweep(&f.0, &[], None, none, cancel, digest);
        let records = left
            .iter()
            .filter(|step| matches!(step, Step::Records { .. }));
        assert_eq!(records.count(), 1, "{left:?}");
        // And nothing is said to be unread in a folder that does not exist.
        let gaps: Vec<_> = r.not_checked.iter().map(|g| g.path.as_str()).collect();
        assert_eq!(gaps, ["~/.claude", "~/"]);
    }

    #[test]
    fn a_long_line_is_not_cut_inside_a_colour_code() {
        // "[1;32m" before a token marks where the token starts. Cut after its
        // "[" or ";", the rest of the code would read as part of a word.
        let f = Fixture::new("long-line-colour");
        let token = format!("gh{}_{}", "p", "0123456789abcdefghijABCDEFGHIJ012345");
        let coloured = format!("\\u001b[1;32m{token}\\");
        let mut line = vec![b'x'; 6 * 1024 * 1024];
        let at = 5 * 1024 * 1024 - 200;
        line[at..at + coloured.len()].copy_from_slice(coloured.as_bytes());
        put(&f.0, ".claude/projects/p/s.json", &line);
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        assert_eq!(s.findings.len(), 1);
    }

    #[test]
    fn a_stopped_change_check_says_which_paths_it_did_not_reach() {
        let f = Fixture::new("changed-unreached");
        put(&f.0, ".npmrc", b"_authToken=synthetic-only\n");
        put(&f.0, "a/export.csv", b"url,username,password\n");
        put(
            &f.0,
            "node_modules/pkg/export.csv",
            b"url,username,password\n",
        );
        // Known places in folders discovery passes over would be read too. A
        // link would not, nor a file in such a folder that no rule knows.
        put(&f.0, ".cache/huggingface/token", b"synthetic");
        put(
            &f.0,
            "Library/Caches/claude-cli-nodejs/p/mcp.log",
            b"synthetic",
        );
        std::os::unix::fs::symlink(f.0.join("a/export.csv"), f.0.join("a/link")).unwrap();
        let paths = [
            ".npmrc",
            "a/export.csv",
            ".cache/huggingface/token",
            "Library/Caches/claude-cli-nodejs/p/mcp.log",
            "node_modules/pkg/export.csv",
            "a/link",
        ]
        .map(|p| f.0.join(p));
        let run = |limits: Limits, stop_at_first_finding: bool| {
            let cancel = Arc::new(AtomicBool::new(false));
            let stop = stop_at_first_finding.then(|| cancel.clone());
            let digest = move |_: &str, _: &[u8], _: bool| {
                if let Some(stop) = &stop {
                    stop.store(true, Ordering::SeqCst);
                }
                "synthetic-digest".to_string()
            };
            Scan::changed(&f.0, &[], &paths, limits, cancel, digest).1
        };
        // Finished: nothing is left over.
        assert_eq!(run(limits(1000), false), Unreached::default());
        // Out of time before the first: all that it would have read.
        let none = Limits {
            entries: 1000,
            time: Duration::ZERO,
        };
        let left = run(none, false);
        assert_eq!(left.out_of_budget, paths[..4]);
        assert!(left.cancelled.is_empty());
        // Cancelled while the first was checked, with other rules still to
        // read it: that one and the ones after it.
        let left = run(limits(1000), true);
        assert_eq!(left.cancelled, paths[..4]);
        assert!(left.out_of_budget.is_empty() && left.cut_short.is_empty());
    }

    #[test]
    fn a_known_folder_cut_short_by_a_cancel_is_read_again() {
        // Terminal's per-window histories: one folder, checked as one place.
        let f = Fixture::new("known-cut");
        for name in ["a.history", "b.history", "c.history"] {
            put(
                &f.0,
                &format!(".zsh_sessions/{name}"),
                b"export API_TOKEN=synthetic-only-value\n",
            );
        }
        let mut found = HashSet::new();
        let mut pending = None;
        for slice in 0.. {
            // The Mac goes to sleep while the first file is being recorded.
            let cancel = Arc::new(AtomicBool::new(false));
            let stop = (slice == 0).then(|| cancel.clone());
            let digest = move |_: &str, _: &[u8], _: bool| {
                if let Some(stop) = &stop {
                    stop.store(true, Ordering::SeqCst);
                }
                "synthetic-digest".to_string()
            };
            let (r, left) = Scan::sweep(&f.0, &[], pending, limits(1000), cancel, digest);
            found.extend(r.findings.into_iter().map(|x| x.path));
            if left.is_empty() {
                break;
            }
            pending = Some(left);
            assert!(slice < 50, "the pass did not end");
        }
        assert_eq!(found.len(), 3, "{found:?}");
    }

    #[test]
    fn a_recheck_of_a_linked_file_tries_every_form_of_its_rule() {
        // A shell file kept elsewhere under a name another form reads.
        let f = Fixture::new("recheck-linked");
        put(
            &f.0,
            "dotfiles/zsh/local.env",
            b"NAME_TOKEN=synthetic-only-value && make deploy\n",
        );
        let real = f.0.join("dotfiles/zsh/local.env");
        std::os::unix::fs::symlink(&real, f.0.join(".zshrc")).unwrap();
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        assert_eq!(paths(&s), ["~/dotfiles/zsh/local.env"]);
        // Still there, so not to be marked fixed.
        let still = recheck("secret.env-assignment", &real, &f.0, None).unwrap();
        assert_eq!(still, [Some("NAME_TOKEN".to_string())]);

        // A settings file kept elsewhere: read as JSON, and not known to be
        // fixed when it stops being JSON with its secret still inside.
        let mcp = "dev.mcp.inline-secret";
        let settings = "{\"context_servers\": {\"fixture\": {\"command\": \"npx\", \"env\": {\"FIXTURE_TOKEN\": \"synthetic-only-value\"}}}}";
        put(&f.0, "dotfiles/zed.json", settings.as_bytes());
        let zed = f.0.join("dotfiles/zed.json");
        fs::create_dir_all(f.0.join(".config/zed")).unwrap();
        std::os::unix::fs::symlink(&zed, f.0.join(".config/zed/settings.json")).unwrap();
        assert_eq!(
            recheck(mcp, &zed, &f.0, None),
            Some(vec![Some("server fixture".to_string())])
        );
        put(
            &f.0,
            "dotfiles/zed.json",
            &settings.as_bytes()[..settings.len() - 1],
        );
        assert_eq!(recheck(mcp, &zed, &f.0, None), None);
        // Continue's YAML behind a linked folder is read as YAML, and is
        // fixed when its key is gone.
        put(
            &f.0,
            "dotfiles/continue/config.yaml",
            b"models:\n  - name: fixture\n    apiKey: synthetic-only-value\n",
        );
        std::os::unix::fs::symlink(f.0.join("dotfiles/continue"), f.0.join(".continue")).unwrap();
        let yaml = f.0.join("dotfiles/continue/config.yaml");
        assert_eq!(
            recheck(mcp, &yaml, &f.0, None),
            Some(vec![Some("apiKey".to_string())])
        );
        put(
            &f.0,
            "dotfiles/continue/config.yaml",
            b"models:\n  - name: fixture\n",
        );
        assert_eq!(recheck(mcp, &yaml, &f.0, None), Some(vec![]));
    }

    #[test]
    fn a_recheck_reads_a_settings_file_as_a_settings_file() {
        // The advice followed: the value is now a reference with a blank in
        // it, which only a shell would take the first word of.
        let f = Fixture::new("recheck-env");
        let env = f.0.join("project/.env");
        put(&f.0, "project/.env", b"DB_PASSWORD=synthetic-only-value\n");
        let rule = "secret.env-assignment";
        assert_eq!(
            recheck(rule, &env, &f.0, None),
            Some(vec![Some("DB_PASSWORD".to_string())])
        );
        put(
            &f.0,
            "project/.env",
            b"DB_PASSWORD=op://Private/Shop DB/password\n",
        );
        assert_eq!(recheck(rule, &env, &f.0, None), Some(vec![]));
    }

    #[test]
    fn a_recheck_reads_a_file_as_the_rule_that_names_it() {
        // Two forms of one kind of finding: JSON settings and Continue's YAML.
        let f = Fixture::new("recheck-forms");
        let rule = "dev.mcp.inline-secret";
        let yaml = f.0.join(".continue/config.yaml");
        put(
            &f.0,
            ".continue/config.yaml",
            b"models:\n  - name: fixture\n    apiKey: synthetic-only-value\n",
        );
        assert_eq!(
            recheck(rule, &yaml, &f.0, None),
            Some(vec![Some("apiKey".to_string())])
        );
        // Fixed: the key is now a reference.
        put(
            &f.0,
            ".continue/config.yaml",
            b"models:\n  - name: fixture\n    apiKey: ${{ secrets.FIXTURE_KEY }}\n",
        );
        assert_eq!(recheck(rule, &yaml, &f.0, None), Some(vec![]));
        // A JSON settings file that cannot be read as JSON is not known to
        // be fixed, though the YAML form could make something of its text.
        put(
            &f.0,
            ".cursor/mcp.json",
            b"{\"mcpServers\": {\"fixture\": {\"env\": {\"FIXTURE_API_KEY\": \"synthetic-only-value\"}}}\n",
        );
        assert_eq!(
            recheck(rule, &f.0.join(".cursor/mcp.json"), &f.0, None),
            None
        );
    }

    #[test]
    fn a_recheck_of_a_record_sees_what_the_scan_saw() {
        let f = Fixture::new("recheck-record");
        let repeated = format!("gh{}_{}", "p", "0123456789abcdefghijABCDEFGHIJ012345");
        let other = format!("AK{}{}", "IA", "ABCDEFGHIJKLMNOP");
        fs::create_dir_all(f.0.join(".claude/projects/p")).unwrap();
        let record = f.0.join(".claude/projects/p/s.jsonl");
        fs::write(
            &record,
            format!(
                "{}{}{{\"out\":\"{other}\"}}\n",
                format!("{{\"out\":\"{repeated}\"}}\n").repeat(120),
                "{\"type\":\"filler\"}\n".repeat(70_000),
            ),
        )
        .unwrap();
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        let mut subjects: Vec<_> = s
            .findings
            .iter()
            .filter(|x| x.rule == "secret.agent-record")
            .map(|x| x.subject.clone())
            .collect();
        subjects.sort();
        assert_eq!(subjects.len(), 2);
        // An item is marked fixed when a recheck no longer names its subject.
        let mut still = recheck("secret.agent-record", &record, &f.0, None).unwrap();
        still.sort();
        still.dedup();
        assert_eq!(still, subjects);
    }

    #[test]
    fn a_token_is_not_cut_in_two_where_a_very_long_line_is_split() {
        // One line of 6 MiB, as a record holding an embedded file has. It is
        // read in pieces of 1 MiB and split once more than 4 MiB are held.
        let f = Fixture::new("long-line");
        let token = format!("gh{}_{}", "p", "0123456789abcdefghijABCDEFGHIJ012345");
        let key = format!("AK{}{}", "IA", "ABCDEFGHIJKLMNOP");
        let mut line = vec![b' '; 6 * 1024 * 1024];
        let held = 5 * 1024 * 1024;
        // One across the place the line used to be split, one across the
        // end of what is held when it is split.
        for (at, value) in [(held - 512 - 10, &token), (held - 8, &key)] {
            line[at..at + value.len()].copy_from_slice(value.as_bytes());
        }
        fs::create_dir_all(f.0.join(".claude/projects/p")).unwrap();
        fs::write(f.0.join(".claude/projects/p/s.json"), line).unwrap();
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        let mut types: Vec<_> = s.findings.iter().filter_map(|x| x.token_type).collect();
        types.sort();
        assert_eq!(types, ["AWS access key", "GitHub personal access token"]);
        assert!(s.not_checked.is_empty());
    }

    #[test]
    fn recheck_reports_what_is_still_there_or_that_nothing_is_known() {
        let f = Fixture::new("recheck");
        let npmrc = f.0.join(".npmrc");
        let two = "//a.example.invalid/:_authToken=synthetic-one\n//b.example.invalid/:_authToken=synthetic-two\n";
        fs::write(&npmrc, two).unwrap();
        let rule = "dev.npm.inline-credentials";
        assert_eq!(
            recheck(rule, &npmrc, &f.0, None).unwrap(),
            [
                Some("a.example.invalid".into()),
                Some("b.example.invalid".into())
            ]
        );
        // One of two tokens removed: the other is still there.
        fs::write(&npmrc, two.lines().next().unwrap()).unwrap();
        assert_eq!(
            recheck(rule, &npmrc, &f.0, None).unwrap(),
            [Some("a.example.invalid".into())]
        );
        // Gone, so nothing is left to review.
        fs::remove_file(&npmrc).unwrap();
        assert_eq!(recheck(rule, &npmrc, &f.0, None), Some(vec![]));
        // A link is not evidence of removal.
        fs::write(f.0.join("real"), two).unwrap();
        std::os::unix::fs::symlink(f.0.join("real"), &npmrc).unwrap();
        assert_eq!(recheck(rule, &npmrc, &f.0, None), None);

        // A protected key is only worth reviewing while others can read it.
        use std::os::unix::fs::PermissionsExt;
        let key = f.0.join("key");
        fs::write(&key, "-----BEGIN ENCRYPTED PRIVATE KEY-----\nsynthetic\n").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            recheck("key.ssh.private", &key, &f.0, None),
            Some(vec![None])
        );
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(recheck("key.ssh.private", &key, &f.0, None), Some(vec![]));
    }

    #[test]
    fn a_recheck_says_which_values_are_still_there() {
        let f = Fixture::new("recheck-values");
        let token = |last: char| format!("gh{}_0123456789abcdefghijABCDEFGHIJ01234{last}", "p");
        let (one, two) = (token('A'), token('B'));
        // A stand-in for the keyed digest: it only has to tell values apart.
        let digest = |rule: &str, bytes: &[u8], _: bool| format!("{rule}:{:?}", bytes.last());
        let subject = Some("GitHub personal access token".to_string());
        let value = |last: u8| (subject.clone(), Some(format!(":Some({last})")));
        // As the scan lists them: by the same digest, each value once.
        let notes = f.0.join("notes.txt");
        fs::write(&notes, format!("{one} {two}\n{one}\n")).unwrap();
        let home = std::slice::from_ref(&f.0);
        let s = Scan::run_observed(&f.0, home, None, None, Some(Box::new(digest)));
        let listed: Vec<_> = s.findings.iter().map(|x| x.secret.clone()).collect();
        let still = |path: &Path, rule| recheck_values(rule, path, &f.0, None, &digest);
        let found = still(&notes, "secret.service-token").unwrap();
        assert_eq!(found, [value(b'A'), value(b'B'), value(b'A')]);
        assert_eq!(
            listed,
            found.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>()
        );
        // One of two on a line is taken out: the other is still there.
        fs::write(&notes, format!("{two}\n")).unwrap();
        assert_eq!(
            still(&notes, "secret.service-token").unwrap(),
            [value(b'B')]
        );
        // A record gives each different value once, however often it repeats.
        let record = f.0.join(".claude/projects/p/s.jsonl");
        let line = |token: &str| format!("{{\"out\":\"{token}\"}}\n");
        put(
            &f.0,
            ".claude/projects/p/s.jsonl",
            format!("{}{}{}", line(&one).repeat(3), line(&two), line(&one)).as_bytes(),
        );
        assert_eq!(
            still(&record, "secret.agent-record").unwrap(),
            [value(b'A'), value(b'B')]
        );
        // A finding with no single value has no digest.
        let export = f.0.join("export.csv");
        fs::write(
            &export,
            "url,username,password\nhttps://fixture.invalid,fixture,synthetic\n",
        )
        .unwrap();
        assert_eq!(
            still(&export, "export.password-csv"),
            Some(vec![(None, None)])
        );
    }

    #[test]
    fn inline_environment_values_are_rechecked_independently() {
        let f = Fixture::new("inline-recheck");
        let path = ".codex/config.toml";
        put(
            &f.0,
            path,
            b"env = { FIRST_PASSWORD = 'synthetic-first-A', SECOND_PASSWORD = 'synthetic-second-B' }\n",
        );
        let digest = |_: &str, bytes: &[u8], _: bool| format!("{:?}", bytes.last());
        let still = || {
            recheck_values(
                "secret.env-assignment",
                &f.0.join(path),
                &f.0,
                None,
                &digest,
            )
            .unwrap()
        };
        assert_eq!(
            still(),
            [
                (
                    Some("FIRST_PASSWORD".to_string()),
                    Some("Some(65)".to_string())
                ),
                (
                    Some("SECOND_PASSWORD".to_string()),
                    Some("Some(66)".to_string())
                ),
            ]
        );
        put(
            &f.0,
            path,
            b"env = { SECOND_PASSWORD = 'synthetic-second-B' }\n",
        );
        assert_eq!(
            still(),
            [(
                Some("SECOND_PASSWORD".to_string()),
                Some("Some(66)".to_string())
            )]
        );
    }

    #[test]
    fn a_service_token_past_the_head_of_a_known_environment_file_is_found() {
        let f = Fixture::new("known-env-token");
        let token = format!("gh{}_{}", "p", "0123456789abcdefghijABCDEFGHIJ012345");
        let content = format!("{}api_token={token}\n", "# ordinary settings\n".repeat(300));
        put(&f.0, ".gradle/gradle.properties", content.as_bytes());
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        assert!(s
            .findings
            .iter()
            .any(|finding| finding.rule == "secret.service-token"
                && finding.path == "~/.gradle/gradle.properties"));
        assert!(s.not_checked.is_empty());
    }

    #[test]
    fn a_recheck_of_a_file_gone_with_its_volume_knows_nothing() {
        let f = Fixture::new("recheck-volume");
        // Not there: a file read whole, a record read through, and a folder
        // that is a finding by being there.
        let gone = [
            ("dev.npm.inline-credentials", ".npmrc"),
            ("secret.agent-record", ".claude/projects/p/s.jsonl"),
            ("wallet.desktop.data", ".electrum/wallets"),
        ];
        // As if they had been found on a volume mounted at this folder.
        // Nothing is mounted at it: it is a folder like any other.
        let unmounted = Some(f.0.components().count() as u32);
        for (rule, at) in gone {
            let path = f.0.join(at);
            // Found on the home folder's own volume, they were removed.
            assert_eq!(recheck(rule, &path, &f.0, Some(0)), Some(vec![]), "{rule}");
            assert_eq!(recheck(rule, &path, &f.0, unmounted), None, "{rule}");
        }
    }

    /// A file of `len` bytes, all zero but for these.
    fn sparse(len: usize, runs: &[(usize, &[u8])]) -> Vec<u8> {
        let mut bytes = vec![0; len];
        for (at, run) in runs {
            bytes[*at..*at + run.len()].copy_from_slice(run);
        }
        bytes
    }

    #[test]
    fn a_database_is_not_counted_while_its_write_ahead_log_holds_anything() {
        let f = Fixture::new("write-ahead");
        let rule = "browser.chromium.saved-logins";
        let at = "Library/Application Support/Google/Chrome/Default/Login Data";
        let (path, log) = (f.0.join(at), f.0.join(format!("{at}-wal")));
        // As SQLite 3.51 wrote them, with pages of 512 bytes. A table with
        // no row was checkpointed into the file, then one row was committed
        // and the connection left open. The row is in the log alone: SQLite
        // counts one login, and the file by itself holds none.
        let file = sparse(
            1024,
            &[
                (0, b"SQLite format 3\x00\x02\x00\x02\x02\x00@  \x00\x00\x00\x02\x00\x00\x00\x02"),
                (43, b"\x01\x00\x00\x00\x04"),
                (59, b"\x01"),
                (95, b"\x02\x00.\x8d\xf8\x0d\x00\x00\x00\x01\x01\xab\x00\x01\xab"),
                (427, b"S\x01\x07\x17\x19\x19\x01\x81\x01tableloginslogins\x02CREATE TABLE logins (origin_url TEXT, password_value BLOB)\x0d"),
                (517, b"\x02"),
            ],
        );
        let wal = sparse(
            568,
            &[
                (0, b"7\x7f\x06\x82\x00-\xe2\x18\x00\x00\x02"),
                (15, b"\x01\xe1\x11\xb4#r\x03s\x16\xf9\x7f\x14\xf4\xc8\xcb\xf0\x0b\x00\x00\x00\x02\x00\x00\x00\x02\xe1\x11\xb4#r\x03s\x16\xc6\xc0\xbd4\xc6\xcd\x83\xc0\x0d\x00\x00\x00\x01\x01\xdb\x00\x01\xdb"),
                (531, b"#\x01\x03;\x1ehttps://fixture.invalidsynthetic"),
            ],
        );
        let seen = || {
            let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
            let found: Vec<_> = s
                .findings
                .iter()
                .map(|x| (x.rule, x.detail.clone()))
                .collect();
            let gaps: Vec<_> = s
                .not_checked
                .iter()
                .map(|g| (g.path.clone(), g.reason))
                .collect();
            (found, gaps)
        };
        let unknown = (vec![], vec![(format!("~/{at}"), "unreadable")]);
        let one = (vec![(rule, Some("1 saved login".to_string()))], vec![]);
        put(&f.0, at, &file);
        fs::write(&log, &wal).unwrap();
        assert_eq!(seen(), unknown);
        assert_eq!(recheck(rule, &path, &f.0, Some(0)), None);
        // Whatever the file itself holds: the log may delete it.
        let mut checkpointed = file.clone();
        checkpointed[512..].copy_from_slice(&wal[56..]);
        fs::write(&path, &checkpointed).unwrap();
        assert_eq!(seen(), unknown);
        assert_eq!(recheck(rule, &path, &f.0, Some(0)), None);
        // A checkpoint that empties the log, as SQLite's left the two: the
        // row is in the file, and the file is all there is.
        fs::write(&log, b"").unwrap();
        assert_eq!(seen(), one);
        assert_eq!(recheck(rule, &path, &f.0, Some(0)), Some(vec![None]));
        // With no log, as after the last connection closed.
        fs::remove_file(&log).unwrap();
        assert_eq!(seen(), one);
        assert_eq!(recheck(rule, &path, &f.0, Some(0)), Some(vec![None]));
        // No row and nothing in a log: no login is saved.
        fs::write(&path, &file).unwrap();
        assert_eq!(seen(), (vec![], vec![]));
        assert_eq!(recheck(rule, &path, &f.0, Some(0)), Some(vec![]));
        // A log that is a link is not one that holds nothing: SQLite would
        // follow it.
        fs::write(f.0.join("elsewhere"), &wal).unwrap();
        std::os::unix::fs::symlink(f.0.join("elsewhere"), &log).unwrap();
        assert_eq!(seen(), unknown);
        assert_eq!(recheck(rule, &path, &f.0, Some(0)), None);
    }

    #[test]
    fn a_database_is_not_counted_while_its_rollback_journal_holds_anything() {
        let f = Fixture::new("rollback-journal");
        let rule = "browser.chromium.saved-logins";
        let at = "Library/Application Support/Google/Chrome/Default/Login Data";
        let (path, journal) = (f.0.join(at), f.0.join(format!("{at}-journal")));
        // As SQLite 3.51 wrote them, with pages of 512 bytes and a rollback
        // journal. Three logins were committed and the connection closed.
        let committed = sparse(
            1536,
            &[
                (0, b"SQLite format 3\x00\x02\x00\x01\x01\x00@  \x00\x00\x00\x05\x00\x00\x00\x03"),
                (43, b"\x02\x00\x00\x00\x04"),
                (59, b"\x01"),
                (95, b"\x05\x00.\x8d\xf8\x0d\x00\x00\x00\x02\x01u\x00\x01\xab\x01u"),
                (373, b"4\x02\x06\x17\x19\x19\x01Etablefillerfiller\x03CREATE TABLE filler (x BLOB)S\x01\x07\x17\x19\x19\x01\x81\x01tableloginslogins\x02CREATE TABLE logins (origin_url TEXT, password_value BLOB)\x0d\x00\x00\x00\x03\x01\xa3\x00\x01\xe1\x01\xc2\x01\xa3"),
                (931, b"\x1d\x03\x03?\x0ehttps://fixture-2.invalid\x00\x1d\x02\x03?\x0ehttps://fixture-1.invalid\x00\x1d\x01\x03?\x0ehttps://fixture-0.invalid\x00\x0d"),
                (1029, b"\x02"),
            ],
        );
        // Then a transaction deleted the three and filled the other table.
        // SQLite, told to keep one page in memory (`cache_spill=1`), wrote
        // changed pages into the file before any commit, and the writer
        // ended without one. The file as that left it: the first page as it
        // was, no row on the page of logins, and five pages of the other
        // table after the three there were.
        let mut spilled = sparse(
            4096,
            &[
                (512, b"\x0d\x00\x00\x00\x00\x02"),
                (1024, b"\x0d\x00\x00\x00\x00\x02"),
            ],
        );
        spilled[..512].copy_from_slice(&committed[..512]);
        for row in 0..5 {
            let page = 1536 + 512 * row;
            spilled[page..page + 10].copy_from_slice(b"\x0d\x00\x00\x00\x01\x00\xce\x00\x00\xce");
            spilled[page + 206..page + 212].copy_from_slice(&[
                0x82,
                b'/',
                row as u8 + 1,
                0x03,
                0x84,
                b'd',
            ]);
        }
        // And the journal: the three pages as they were committed, each
        // after its number and before a checksum, and the header of a part
        // not yet written. SQLite puts them back before it reads, and counts
        // three logins.
        let mut hot = sparse(
            3072,
            &[
                (0, b"\xd9\xd5\x05\xf9 \xa1c\xd7\x00\x00\x00\x03\x82&M\x8b\x00\x00\x00\x03\x00\x00\x02\x00\x00\x00\x02"),
                (2572, b"&\x95\x92`\x00\x00\x00\x03\x00\x00\x02\x00\x00\x00\x02"),
            ],
        );
        for (record, page) in [2, 3, 1].into_iter().enumerate() {
            let (to, from) = (512 + 520 * record, 512 * (page - 1));
            hot[to + 3] = page as u8;
            hot[to + 4..to + 516].copy_from_slice(&committed[from..from + 512]);
            hot[to + 516..to + 520].copy_from_slice(b"\x82&M\x8b");
        }
        let seen = || {
            let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
            let found: Vec<_> = s
                .findings
                .iter()
                .map(|x| (x.rule, x.detail.clone()))
                .collect();
            let gaps: Vec<_> = s
                .not_checked
                .iter()
                .map(|g| (g.path.clone(), g.reason))
                .collect();
            (found, gaps)
        };
        let unknown = (vec![], vec![(format!("~/{at}"), "unreadable")]);
        let three = (vec![(rule, Some("3 saved logins".to_string()))], vec![]);
        put(&f.0, at, &committed);
        assert_eq!(seen(), three);
        assert_eq!(recheck(rule, &path, &f.0, Some(0)), Some(vec![None]));
        // The file holds no login and the database holds three: not a count
        // of none, and not a login that was removed.
        fs::write(&path, &spilled).unwrap();
        fs::write(&journal, &hot).unwrap();
        assert_eq!(seen(), unknown);
        assert_eq!(recheck(rule, &path, &f.0, Some(0)), None);
        // Whatever the file itself holds, as before any page was written
        // into it: the journal is not read, so what it would undo is not
        // known.
        fs::write(&path, &committed).unwrap();
        assert_eq!(seen(), unknown);
        assert_eq!(recheck(rule, &path, &f.0, Some(0)), None);
        // As SQLite leaves the two once it has put the pages back: the file
        // as it was committed, and no journal.
        fs::remove_file(&journal).unwrap();
        assert_eq!(seen(), three);
        assert_eq!(recheck(rule, &path, &f.0, Some(0)), Some(vec![None]));
        // A journal emptied and left there, as `journal_mode=TRUNCATE` does.
        fs::write(&journal, b"").unwrap();
        assert_eq!(seen(), three);
        assert_eq!(recheck(rule, &path, &f.0, Some(0)), Some(vec![None]));
        // One left with its header cleared, as `journal_mode=PERSIST` does
        // after each commit. It undoes nothing, which only its bytes say:
        // such a database is not counted.
        let mut kept = hot.clone();
        kept[..28].fill(0);
        fs::write(&journal, &kept).unwrap();
        assert_eq!(seen(), unknown);
        assert_eq!(recheck(rule, &path, &f.0, Some(0)), None);
        // A journal that is a link is not one that holds nothing.
        fs::remove_file(&journal).unwrap();
        fs::write(f.0.join("elsewhere"), &hot).unwrap();
        std::os::unix::fs::symlink(f.0.join("elsewhere"), &journal).unwrap();
        assert_eq!(seen(), unknown);
        assert_eq!(recheck(rule, &path, &f.0, Some(0)), None);
        // Removing the journal does not repair the inconsistent database size.
        // An empty root page alone cannot establish that logins are gone.
        fs::remove_file(&journal).unwrap();
        fs::write(&path, &spilled).unwrap();
        assert_eq!(seen(), unknown);
        assert_eq!(recheck(rule, &path, &f.0, Some(0)), None);
    }

    #[test]
    fn every_row_count_waits_for_an_empty_log_and_journal() {
        let f = Fixture::new("write-ahead-all");
        // A two-page database with one table and one row in it.
        let database = |table: &str| {
            crate::rules::fixture_body::Body::Sqlite {
                sqlite: table.into(),
                rows: 1,
            }
            .bytes()
            .unwrap()
        };
        let stores = [
            (
                "browser.chromium.saved-logins",
                "Library/Application Support/Google/Chrome/Default/Login Data",
                "logins",
            ),
            (
                "browser.chromium.saved-cards",
                "Library/Application Support/Google/Chrome/Default/Web Data",
                "credit_cards",
            ),
            (
                "dev.gcloud.stored-login",
                ".config/gcloud/credentials.db",
                "credentials",
            ),
        ];
        for (_, at, table) in stores {
            put(&f.0, at, &database(table));
        }
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        let mut found: Vec<_> = s.findings.iter().map(|x| x.rule).collect();
        found.sort_unstable();
        let mut rules = stores.map(|(rule, ..)| rule);
        rules.sort_unstable();
        assert_eq!(found, rules);
        assert!(s.not_checked.is_empty());
        // One frame of a log beside each, then one record of a rollback
        // journal: none of them can be counted, and none is known to be
        // empty.
        for (beside, held) in [("-wal", 32 + 24 + 512), ("-journal", 512 + 4 + 512 + 4)] {
            for (rule, at, _) in stores {
                put(&f.0, &format!("{at}{beside}"), &vec![0x37; held]);
                assert_eq!(recheck(rule, &f.0.join(at), &f.0, Some(0)), None, "{rule}");
            }
            let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
            assert!(s.findings.is_empty(), "{beside}");
            let mut gaps: Vec<_> = s
                .not_checked
                .iter()
                .map(|g| (g.path.clone(), g.reason))
                .collect();
            gaps.sort_unstable();
            let mut unknown = stores.map(|(_, at, _)| (format!("~/{at}"), "unreadable"));
            unknown.sort_unstable();
            assert_eq!(gaps, unknown, "{beside}");
            for (_, at, _) in stores {
                fs::remove_file(f.0.join(format!("{at}{beside}"))).unwrap();
            }
        }
    }

    #[test]
    fn a_finding_for_the_review_list_says_where_its_volume_is_mounted() {
        let f = Fixture::new("mounted");
        put(&f.0, "Documents/export.csv", b"url,username,password\n");
        let roots = std::slice::from_ref(&f.0);
        // Asked only where a review list is kept, as the digests are.
        assert_eq!(Scan::run(&f.0, roots).findings[0].mount, None);
        let listed = Scan::run_observed(&f.0, roots, None, None, Some(Box::new(digest)));
        // 0: on the device the home folder is on.
        assert_eq!(listed.findings[0].mount, Some(0));
    }

    #[test]
    fn cancelled_monitor_has_partial_coverage_and_no_reads() {
        let f = Fixture::new("cancelled");
        fs::write(f.0.join("export.csv"), "url,username,password\n").unwrap();
        let cancel = Arc::new(AtomicBool::new(true));
        let r = Scan::report_controlled(
            &f.0,
            &[],
            &[],
            cancel,
            |_, _, _| "synthetic-digest".into(),
            |_| {},
        );
        assert_eq!(r.status, "partial");
        assert!(r.findings.is_empty());
        assert!(r.not_checked.iter().all(|g| g.reason == "scan-limit"));
    }

    #[test]
    fn monitor_bounds_findings_and_hashes_each_file_once() {
        let f = Fixture::new("monitor-bounds");
        fs::write(
            f.0.join(".npmrc"),
            "_authToken=synthetic-only\n".repeat(5000),
        )
        .unwrap();
        let hashed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = hashed.clone();
        let r = Scan::report_controlled(
            &f.0,
            &[],
            &[],
            Arc::new(AtomicBool::new(false)),
            move |_, _, _| {
                count.fetch_add(1, Ordering::SeqCst);
                "private-synthetic-digest".into()
            },
            |_| {},
        );
        assert_eq!(r.findings.len(), 4096);
        assert_eq!(hashed.load(Ordering::SeqCst), 1);
        assert_eq!(r.status, "partial");
        let export = crate::report::to_ascii_json(&r);
        assert!(!export.contains("private-synthetic-digest"));
        assert!(!export.contains("synthetic-only"));
    }

    #[test]
    fn dropped_hits_are_one_gap_for_their_file() {
        let f = Fixture::new("dropped-hits");
        fs::write(
            f.0.join(".npmrc"),
            "_authToken=synthetic-only\n".repeat(5000),
        )
        .unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let r = Scan::report_controlled(&f.0, &[], &[], cancel, digest, |_| {});
        assert_eq!(r.findings.len(), 4096);
        let gaps = r.not_checked.iter().filter(|g| g.path == "~/.npmrc");
        assert_eq!(gaps.count(), 1);
        assert_eq!(r.not_checked[0].reason, "scan-limit");
    }

    #[test]
    fn a_folder_that_went_away_is_not_a_gap() {
        // Listed in one slice of a sweep and removed before the next.
        let f = Fixture::new("gone");
        let cancel = Arc::new(AtomicBool::new(false));
        let resume = Some(vec![Step::Folder(f.0.join("gone"), 1)]);
        let (r, pending) = Scan::sweep(&f.0, &[], resume, limits(100), cancel, digest);
        assert!(pending.is_empty());
        assert!(r.not_checked.is_empty(), "{}", r.not_checked.len());
    }

    #[test]
    fn limited_overlap_retries_and_retains_the_earlier_gap() {
        let f = Fixture::new("deep");
        let mut deep = f.0.clone();
        for _ in 0..65 {
            deep.push("d");
        }
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("export.csv"), "url,username,password\n").unwrap();
        let s = Scan::run(&f.0, &[f.0.clone(), deep.clone()]);
        assert_eq!(s.findings.len(), 1);
        assert_eq!(s.not_checked.len(), 1);
        assert_eq!(s.not_checked[0].reason, "scan-limit");
        assert_eq!(s.not_checked[0].path, s.rel(&deep));
        assert!(s.traversal.completed.contains_key(&deep));
    }

    #[test]
    fn progress_is_aggregate_and_targeted_checks_precede_discovery() {
        let f = Fixture::new("progress");
        fs::write(f.0.join(".npmrc"), "_authToken=synthetic-only\n").unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let observed = events.clone();
        let r = Scan::report_with_progress(&f.0, &[], move |p| observed.lock().unwrap().push(p));
        let events = events.lock().unwrap();
        assert_eq!(events[0].phase, "targeted-checks");
        let discovery = events.iter().find(|p| p.phase == "discovery").unwrap();
        assert_eq!(discovery.findings, 1);
        assert_eq!(discovery.entries, 0);
        let final_event = events.last().unwrap();
        assert_eq!(final_event.phase, "finished");
        assert_eq!(final_event.entries, 1);
        assert_eq!(final_event.header_attempts, 1);
        // One attempt per targeted config file, present or not.
        let targeted: usize = RULES
            .iter()
            .flat_map(|r| r.targets)
            .map(|t| match t {
                Target::File(_) => 1,
                // Each browser's top-level profile is tried as well.
                Target::Profiles(_) => CHROMIUM.len(),
                _ => 0,
            })
            .sum();
        assert_eq!(final_event.config_attempts, targeted);
        assert_eq!(final_event.findings, r.findings.len());
        assert_eq!(final_event.not_checked, r.not_checked.len());
        for pair in events.windows(2) {
            assert!(pair[0].entries <= pair[1].entries);
            assert!(pair[0].header_attempts <= pair[1].header_attempts);
            assert!(pair[0].config_attempts <= pair[1].config_attempts);
        }
        let json = serde_json::to_string(final_event).unwrap();
        for private in [".npmrc", "synthetic-only", "credential-progress", "~/"] {
            assert!(!json.contains(private));
        }
        assert_eq!(r.status, "complete");
    }
    fn reported(s: &Scan) -> Vec<(&'static str, &str, Option<&str>, &'static str)> {
        s.findings
            .iter()
            .map(|x| (x.rule, x.path.as_str(), x.subject.as_deref(), x.kind))
            .collect()
    }

    #[test]
    fn a_recheck_knows_a_wallet_folder_reached_through_a_link() {
        // Presence is the finding, and the scan reports it where the link leads.
        let f = Fixture::new("present-link");
        fs::create_dir_all(f.0.join("Sync/electrum/wallets")).unwrap();
        std::os::unix::fs::symlink(f.0.join("Sync/electrum"), f.0.join(".electrum")).unwrap();
        let rule = "wallet.desktop.data";
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        assert_eq!(
            reported(&s),
            [(rule, "~/Sync/electrum/wallets", Some("Electrum"), "review")]
        );
        let real = f.0.join("Sync/electrum/wallets");
        // Still there, so not to be marked fixed.
        assert_eq!(
            recheck(rule, &real, &f.0, None),
            Some(vec![Some("Electrum".to_string())])
        );
        // Gone: nothing is left to review.
        fs::remove_dir(&real).unwrap();
        assert_eq!(recheck(rule, &real, &f.0, None), Some(vec![]));
    }

    #[test]
    fn a_change_at_a_linked_wallet_folder_reports_it_again() {
        // A change is reported at the real path, which is not where the
        // rule names the folder.
        let f = Fixture::new("present-link-change");
        fs::create_dir_all(f.0.join("Sync/electrum/wallets")).unwrap();
        std::os::unix::fs::symlink(f.0.join("Sync/electrum"), f.0.join(".electrum")).unwrap();
        let real = f.0.join("Sync/electrum/wallets");
        let cancel = Arc::new(AtomicBool::new(false));
        let (r, _) = Scan::changed(
            &f.0,
            &[],
            std::slice::from_ref(&real),
            limits(1000),
            cancel,
            digest,
        );
        let found: Vec<_> = r
            .findings
            .iter()
            .map(|x| (x.rule, x.path.as_str()))
            .collect();
        assert_eq!(found, [("wallet.desktop.data", "~/Sync/electrum/wallets")]);
    }

    #[test]
    fn a_recheck_reads_a_linked_history_entry_as_the_scan_did() {
        // A file in Terminal's history folder that is a link to a file whose
        // own name a settings rule reads. The scan reads it as a shell file.
        let f = Fixture::new("entry-link");
        put(
            &f.0,
            "dotfiles/prod.env",
            b"PGPASSWORD=synthetic-only-value psql -h db.example.invalid shop\n",
        );
        let real = f.0.join("dotfiles/prod.env");
        fs::create_dir_all(f.0.join(".zsh_sessions")).unwrap();
        std::os::unix::fs::symlink(&real, f.0.join(".zsh_sessions/a.history")).unwrap();
        let rule = "secret.env-assignment";
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        assert_eq!(
            reported(&s),
            [(rule, "~/dotfiles/prod.env", Some("PGPASSWORD"), "review")]
        );
        // Still there, so not to be marked fixed.
        assert_eq!(
            recheck(rule, &real, &f.0, None),
            Some(vec![Some("PGPASSWORD".to_string())])
        );
        // Fixed.
        put(
            &f.0,
            "dotfiles/prod.env",
            b"psql -h db.example.invalid shop\n",
        );
        assert_eq!(recheck(rule, &real, &f.0, None), Some(vec![]));
    }

    #[test]
    fn a_recheck_of_a_linked_gcloud_account_can_say_fixed() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new("each-link");
        let signed_in = br#"{"type": "authorized_user", "refresh_token": "synthetic-only-value"}"#;
        put(&f.0, "dotfiles/gcloud/acct/adc.json", signed_in);
        let real = f.0.join("dotfiles/gcloud/acct/adc.json");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o644)).unwrap();
        fs::create_dir_all(f.0.join(".config/gcloud/legacy_credentials")).unwrap();
        std::os::unix::fs::symlink(
            f.0.join("dotfiles/gcloud/acct"),
            f.0.join(".config/gcloud/legacy_credentials/acct"),
        )
        .unwrap();
        let rule = "dev.gcloud.stored-login";
        let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
        assert_eq!(
            reported(&s),
            [(rule, "~/dotfiles/gcloud/acct/adc.json", None, "review")]
        );
        assert_eq!(recheck(rule, &real, &f.0, None), Some(vec![None]));
        // Signed out: the file is readable JSON with no token in it.
        fs::write(
            &real,
            br#"{"type": "authorized_user", "refresh_token": ""}"#,
        )
        .unwrap();
        assert_eq!(recheck(rule, &real, &f.0, None), Some(vec![]));
    }

    #[test]
    fn a_stopped_change_check_reaches_its_gap_limit_and_still_lists_known_places() {
        let f = Fixture::new("gap-cap");
        let mut paths = Vec::new();
        for n in 0..4096 {
            let rel = format!("build/{n:04}.o");
            put(&f.0, &rel, b"x");
            paths.push(f.0.join(rel));
        }
        // Known places in folders discovery passes over.
        put(&f.0, ".cache/huggingface/token", b"synthetic");
        put(
            &f.0,
            "Library/Caches/claude-cli-nodejs/p/mcp.log",
            b"synthetic",
        );
        let known = [
            f.0.join(".cache/huggingface/token"),
            f.0.join("Library/Caches/claude-cli-nodejs/p/mcp.log"),
        ];
        paths.extend(known.iter().cloned());
        let none = Limits {
            entries: 1000,
            time: Duration::ZERO,
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let (_, left) = Scan::changed(&f.0, &[], &paths, none, cancel, digest);
        assert_eq!(left.out_of_budget.len(), paths.len());
        assert_eq!(left.out_of_budget[4096..], known);
    }

    #[test]
    fn a_path_after_the_one_being_checked_is_unreached_whatever_that_one_touched() {
        let f = Fixture::new("in-progress");
        let token = format!("gh{}_{}", "p", "0123456789abcdefghijABCDEFGHIJ012345");
        put(
            &f.0,
            ".cache/huggingface/token",
            format!("{token}\n").as_bytes(),
        );
        put(
            &f.0,
            ".cache/huggingface/stored_tokens",
            b"[auth]\ntoken=synthetic-only-value-1234\n",
        );
        // The folder, then a file in it: two changes in one batch.
        let paths = [".cache/huggingface", ".cache/huggingface/stored_tokens"].map(|p| f.0.join(p));
        let run = |paths: &[PathBuf], stop_at_first_finding: bool| {
            let cancel = Arc::new(AtomicBool::new(false));
            let stop = stop_at_first_finding.then(|| cancel.clone());
            let digest = move |_: &str, _: &[u8], _: bool| {
                if let Some(stop) = &stop {
                    stop.store(true, Ordering::SeqCst);
                }
                "synthetic-digest".to_string()
            };
            Scan::changed(&f.0, &[], paths, limits(1000), cancel, digest)
        };
        // Not stopped, the second path alone is read and reported.
        let (r, left) = run(&paths[1..], false);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(left, Unreached::default());
        // Cancelled while the first was checked: that one, with a file of
        // its own still to read, and the one after it.
        let (r, left) = run(&paths, true);
        assert_eq!(r.findings.len(), 1, "only the token the cancel came at");
        assert_eq!(left.cancelled, paths);
    }

    #[test]
    fn a_stopped_change_check_says_nothing_of_a_known_place_that_is_not_there() {
        let f = Fixture::new("absent");
        fs::create_dir_all(f.0.join("Documents")).unwrap();
        // Deleted, or never there: not stopped, nothing is read and nothing said.
        let paths =
            [".aws/credentials", ".aws", ".kube", ".bashrc", "absent.txt"].map(|p| f.0.join(p));
        let run = |time: Duration| {
            let cancel = Arc::new(AtomicBool::new(false));
            let limits = Limits {
                entries: 1000,
                time,
            };
            Scan::changed(&f.0, &[], &paths, limits, cancel, digest)
        };
        let (r, left) = run(Duration::from_secs(30));
        assert!(r.not_checked.is_empty() && r.findings.is_empty());
        assert_eq!(left, Unreached::default());
        let (r, left) = run(Duration::ZERO);
        let gaps: Vec<_> = r.not_checked.iter().map(|g| g.path.as_str()).collect();
        assert_eq!((left.out_of_budget, gaps), (vec![], vec![]));
    }

    #[test]
    fn a_record_cut_short_by_a_cancel_is_unreached_when_it_comes_next() {
        let f = Fixture::new("in-progress-record");
        let token = format!("gh{}_{}", "p", "0123456789abcdefghijABCDEFGHIJ012345");
        // A record read in several pieces, with a token in the first.
        let mut record = format!("{{\"out\":\"{token}\"}}\n").into_bytes();
        record.extend(b"{\"out\":\"ordinary synthetic data\"}\n".repeat(100_000));
        put(&f.0, "Library/Caches/claude-cli-nodejs/p/mcp.log", &record);
        // The folder, then the file in it: two changes in one batch.
        let paths = [
            "Library/Caches/claude-cli-nodejs/p",
            "Library/Caches/claude-cli-nodejs/p/mcp.log",
        ]
        .map(|p| f.0.join(p));
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = cancel.clone();
        let digest = move |_: &str, _: &[u8], _: bool| {
            stop.store(true, Ordering::SeqCst);
            "synthetic-digest".to_string()
        };
        let (r, left) = Scan::changed(&f.0, &[], &paths, limits(1000), cancel, digest);
        // Cut short: the rest of the record is a gap.
        let gaps: Vec<_> = r.not_checked.iter().map(|g| g.path.as_str()).collect();
        assert!(
            gaps.contains(&"~/Library/Caches/claude-cli-nodejs/p/mcp.log"),
            "{gaps:?}"
        );
        // So neither the folder nor the record itself, which comes next,
        // was finished.
        assert_eq!(left.cancelled, paths);
    }

    #[test]
    fn a_path_a_cancel_cut_short_is_to_be_checked_again() {
        let f = Fixture::new("cancel-cut");
        let token = format!("gh{}_{}", "p", "0123456789abcdefghijABCDEFGHIJ012345");
        put(
            &f.0,
            ".cache/huggingface/token",
            format!("{token}\n").as_bytes(),
        );
        put(
            &f.0,
            ".cache/huggingface/stored_tokens",
            b"[auth]\ntoken=synthetic-only-value-1234\n",
        );
        put(&f.0, "a/export.csv", b"url,username,password\n");
        let run = |path: &str| {
            let cancel = Arc::new(AtomicBool::new(false));
            let stop = cancel.clone();
            let digest = move |_: &str, _: &[u8], _: bool| {
                stop.store(true, Ordering::SeqCst);
                "synthetic-digest".to_string()
            };
            let paths = [f.0.join(path)];
            let (r, left) = Scan::changed(&f.0, &[], &paths, limits(1000), cancel, digest);
            (r.findings.len(), r.not_checked.len(), left)
        };
        // The only path, with one of its two files read when the cancel came.
        let (found, _, left) = run(".cache/huggingface");
        assert_eq!(found, 1);
        assert_eq!(left.cancelled, [f.0.join(".cache/huggingface")]);
        assert!(left.out_of_budget.is_empty() && left.cut_short.is_empty());
        // A path with nothing more to read when the cancel came is finished.
        assert_eq!(run("a/export.csv"), (1, 0, Unreached::default()));
    }

    /// A digest that takes as long as the whole check is given, once.
    fn slow_once(time: Duration) -> impl Fn(&str, &[u8], bool) -> String + Send + 'static {
        let slept = AtomicBool::new(false);
        move |_: &str, _: &[u8], _: bool| {
            if !slept.swap(true, Ordering::SeqCst) {
                std::thread::sleep(time);
            }
            "synthetic-digest".to_string()
        }
    }

    #[test]
    fn a_path_the_check_s_own_limits_cut_short_is_said_to_be() {
        let f = Fixture::new("cut-short");
        for file in ["work/a.csv", "work/b.csv", "more/c.csv"] {
            put(&f.0, file, b"url,username,password\n");
        }
        // Its time: up while the first file of the first folder is recorded.
        let paths = ["work", "more"].map(|p| f.0.join(p));
        let second = Limits {
            entries: 1000,
            time: Duration::from_secs(1),
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let slow = slow_once(second.time);
        let (r, left) = Scan::changed(&f.0, &[], &paths, second, cancel, slow);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(left.cut_short, paths[..1]);
        assert_eq!(left.out_of_budget, paths[1..]);
        assert!(left.cancelled.is_empty());

        // The findings one scan keeps: a file with more is not read through.
        fs::write(
            f.0.join(".npmrc"),
            "_authToken=synthetic-only\n".repeat(5000),
        )
        .unwrap();
        let paths = [".npmrc", "more/c.csv"].map(|p| f.0.join(p));
        let cancel = Arc::new(AtomicBool::new(false));
        let (r, left) = Scan::changed(&f.0, &[], &paths, limits(1000), cancel, digest);
        assert_eq!(r.findings.len(), 4096);
        assert_eq!(left.cut_short, paths[..1]);
        assert_eq!(left.out_of_budget, paths[1..]);
        assert!(left.cancelled.is_empty());
    }

    #[test]
    fn a_folder_met_with_the_entry_budget_spent_is_out_of_budget() {
        let f = Fixture::new("entries-spent");
        files(&f.0.join("big"), 5);
        put(&f.0, "small/x.csv", b"url,username,password\n");
        put(&f.0, "lone.csv", b"url,username,password\n");
        put(&f.0, ".npmrc", b"_authToken=synthetic-only\n");
        let paths = ["big", "small", "lone.csv", ".npmrc"].map(|p| f.0.join(p));
        let cancel = Arc::new(AtomicBool::new(false));
        let (r, left) = Scan::changed(&f.0, &[], &paths, limits(3), cancel, digest);
        // The folder that spent it was begun; the next was not walked at all.
        assert_eq!(left.cut_short, paths[..1]);
        assert_eq!(left.out_of_budget, paths[1..2]);
        assert!(left.cancelled.is_empty());
        let gaps: Vec<_> = r.not_checked.iter().map(|g| g.path.as_str()).collect();
        assert_eq!(gaps, ["~/big", "~/small"]);
        // A file is read whatever is left of the budget: listing nothing, it
        // spends none.
        let mut found: Vec<_> = r.findings.iter().map(|x| x.path.as_str()).collect();
        found.sort();
        assert_eq!(found, ["~/.npmrc", "~/lone.csv"]);
    }

    #[test]
    fn a_limit_every_scan_reaches_at_the_same_place_cuts_no_change_check_short() {
        // A full pass would stop where these do, so it is no answer to them.
        let f = Fixture::new("shared-limits");
        let check = |path: &str, entries: usize| {
            let cancel = Arc::new(AtomicBool::new(false));
            let paths = [f.0.join(path)];
            let (r, left) = Scan::changed(&f.0, &[], &paths, limits(entries), cancel, digest);
            let limited = r.not_checked.iter().any(|g| g.reason == "scan-limit");
            assert!(limited, "{path}: the limit was not reached");
            assert_eq!(left, Unreached::default(), "{path}");
        };
        // More different tokens than a record keeps.
        let tokens: String = (0..60)
            .map(|n| format!("{{\"out\":\"gh{}_abcdeABCDE{n:026}\"}}\n", "p"))
            .collect();
        put(&f.0, ".claude/over/s.jsonl", tokens.as_bytes());
        check(".claude/over/s.jsonl", 1000);
        check(".claude/over", 1000);
        // Records in a folder deeper than a tree is read.
        let deep = format!(".codex/sessions/{}s.jsonl", "d/".repeat(TREE_DEPTH + 1));
        put(&f.0, &deep, b"{}\n");
        check(".codex/sessions", 1000);
        // A folder deeper than discovery goes.
        put(&f.0, &format!("deep/{}x", "d/".repeat(65)), b"x");
        check("deep", 1000);
        // More entries than are listed of one folder.
        files(&f.0.join("wide"), 100);
        for n in 100..10_001 {
            fs::write(f.0.join(format!("wide/file-{n}")), "").unwrap();
        }
        check("wide", 20_000);
    }

    #[test]
    fn a_record_read_to_its_end_past_the_time_is_not_cut_short() {
        let f = Fixture::new("record-late-change");
        let first = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        let second = format!("AK{}{}", "IA", "ABCDEFGHIJKLMNOP");
        put(
            &f.0,
            ".claude/projects/p/s.jsonl",
            format!("{}{{\"out\":\"{second}\"}}\n", record(&first)).as_bytes(),
        );
        let second = Limits {
            entries: 1000,
            time: Duration::from_secs(1),
        };
        let run = |path: &str| {
            let cancel = Arc::new(AtomicBool::new(false));
            let paths = [f.0.join(path)];
            let slow = slow_once(second.time);
            let (r, left) = Scan::changed(&f.0, &[], &paths, second, cancel, slow);
            (r.findings.len(), left)
        };
        // Its time is up at the first token; the record is read on.
        let record_alone = ".claude/projects/p/s.jsonl";
        assert_eq!(run(record_alone), (2, Unreached::default()));
        // A second record in its folder is then not read: the folder is cut
        // short, where the record by itself was not.
        put(&f.0, ".claude/projects/p/t.jsonl", b"{}\n");
        assert_eq!(run(record_alone), (2, Unreached::default()));
        let (found, left) = run(".claude/projects/p");
        assert_eq!(found, 2);
        assert_eq!(left.cut_short, [f.0.join(".claude/projects/p")]);

        // A record given up for taking too long is done with, in a full pass
        // as here.
        let cancel = Arc::new(AtomicBool::new(false));
        let mut s = Scan::new(&f.0, None, Some(cancel), Some(Box::new(digest)), 1000);
        s.record_time = Duration::ZERO;
        let left = s.changes(&[f.0.join(record_alone)]);
        assert_eq!(s.not_checked.len(), 1);
        assert_eq!(left, Unreached::default());
    }

    #[test]
    fn a_stop_met_at_a_folder_of_records_that_is_gone_still_lists_the_path() {
        // Only the records are read here: discovery passes the folder over.
        let tree = "Library/Caches/claude-cli-nodejs";
        let first = format!("gh{}_{}", "p", "0123456789abcdefghijABCDEFGHIJ012345");
        let second = format!("hf{}{}", "_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        let line = |token: &str| format!("{{\"out\":\"{token}\"}}\n");
        // At the first record's token the next folder goes away, and the
        // check is cancelled or its time is used up. The folder after that
        // one is then as unread as if the first were still there.
        let run = |name: &str, cancelled: bool| {
            let f = Fixture::new(name);
            put(&f.0, &format!("{tree}/a.log"), line(&first).as_bytes());
            put(&f.0, &format!("{tree}/x/old.log"), b"{}\n");
            put(&f.0, &format!("{tree}/y/new.log"), line(&second).as_bytes());
            let x = f.0.join(tree).join("x");
            let cancel = Arc::new(AtomicBool::new(false));
            let flag = cancel.clone();
            let second = Limits {
                entries: 1000,
                time: Duration::from_secs(1),
            };
            let digest = move |_: &str, _: &[u8], _: bool| {
                let _ = fs::remove_dir_all(&x);
                if cancelled {
                    flag.store(true, Ordering::SeqCst);
                } else {
                    std::thread::sleep(second.time);
                }
                "synthetic-digest".to_string()
            };
            let paths = [f.0.join(tree)];
            let (r, left) = Scan::changed(&f.0, &[], &paths, second, cancel, digest);
            let gaps: Vec<_> = r.not_checked.into_iter().map(|g| g.path).collect();
            let listed = |list: &[PathBuf]| list == paths;
            (
                r.findings.len(),
                gaps,
                listed(&left.cancelled),
                listed(&left.cut_short),
            )
        };
        let gap = vec![format!("~/{tree}/y")];
        assert_eq!(run("gone-cancel", true), (1, gap.clone(), true, false));
        assert_eq!(run("gone-time", false), (1, gap, false, true));
    }

    #[test]
    fn what_an_earlier_path_read_in_full_is_not_left_of_a_later_one() {
        let f = Fixture::new("read-before");
        put(&f.0, "par/a/export.csv", b"url,username,password\n");
        put(&f.0, "par/a/note", b"ordinary synthetic data");
        let run = |paths: &[&str], entries: usize| {
            let paths: Vec<_> = paths.iter().map(|p| f.0.join(p)).collect();
            let cancel = Arc::new(AtomicBool::new(false));
            Scan::changed(&f.0, &[], &paths, limits(entries), cancel, digest).1
        };
        // The entry budget is spent exactly, and all was listed.
        for paths in [["par", "par/a"], ["par", "par"], ["par/a", "par"]] {
            assert_eq!(run(&paths, 3), Unreached::default(), "{paths:?}");
        }
        // It runs out in a second subfolder: the first was read by then.
        files(&f.0.join("par/b"), 5);
        let left = run(&["par", "par/a"], 6);
        assert_eq!(left.cut_short, [f.0.join("par")]);
        assert!(left.out_of_budget.is_empty() && left.cancelled.is_empty());

        // A place one rule names twice is reported once, and with that done
        // nothing is left of it when the cancel comes.
        let wallets = "Library/Application Support/Bitcoin/wallets";
        put(&f.0, &format!("{wallets}/keep.dat"), b"synthetic");
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = cancel.clone();
        let stopping = move |_: &str, _: &[u8], _: bool| {
            stop.store(true, Ordering::SeqCst);
            "synthetic-digest".to_string()
        };
        // A file that went away there: only the folder's presence is checked.
        let paths = [f.0.join(wallets).join("gone.dat")];
        let (r, left) = Scan::changed(&f.0, &[], &paths, limits(1000), cancel, stopping);
        assert_eq!((r.findings.len(), r.not_checked.len()), (1, 0));
        assert_eq!(left, Unreached::default());
    }

    #[test]
    fn a_change_check_reports_a_record_s_findings_in_a_full_scan_s_order() {
        // A file an agent keeps, with a token in its head: found as a record
        // and as a file. The first of the two heads the item in the app.
        let f = Fixture::new("record-order");
        let token = format!("gh{}_{}", "p", "0123456789abcdefghijABCDEFGHIJ012345");
        let file = ".claude/shell-snapshots/snapshot.sh";
        put(&f.0, file, format!("export GH_TOKEN={token}\n").as_bytes());
        let full = Scan::run(&f.0, std::slice::from_ref(&f.0));
        let full: Vec<_> = full.findings.iter().map(|x| x.rule).collect();
        assert_eq!(full, ["secret.agent-record", "secret.service-token"]);
        for path in [file, ".claude/shell-snapshots", ".claude", ""] {
            let cancel = Arc::new(AtomicBool::new(false));
            let paths = [f.0.join(path)];
            let (r, left) = Scan::changed(&f.0, &[], &paths, limits(1000), cancel, digest);
            let rules: Vec<_> = r.findings.iter().map(|x| x.rule).collect();
            assert_eq!(rules, full, "{path}");
            assert_eq!(left, Unreached::default());
        }
    }

    #[test]
    fn a_known_folder_two_rules_name_is_read_once_by_a_change_check() {
        let f = Fixture::new("dir-once");
        put(
            &f.0,
            ".zsh_sessions/a.history",
            b"ordinary synthetic data\n",
        );
        let cancel = Arc::new(AtomicBool::new(false));
        let mut s = Scan::new(&f.0, None, Some(cancel), Some(Box::new(digest)), 1000);
        let left = s.changes(&[f.0.join(".zsh_sessions")]);
        assert_eq!(left, Unreached::default());
        // Once as the known folder's file, once as any file.
        assert_eq!(s.counts.header_attempts, 2);
    }

    #[test]
    fn a_record_too_deep_to_be_read_is_not_unreached_when_the_check_is_stopped() {
        let f = Fixture::new("deep-stopped");
        let deep = format!(
            "Library/Caches/claude-cli-nodejs/{}mcp.log",
            "d/".repeat(TREE_DEPTH + 1)
        );
        put(&f.0, &deep, b"{}\n");
        let none = Limits {
            entries: 1000,
            time: Duration::ZERO,
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let paths = [f.0.join(&deep)];
        let (r, left) = Scan::changed(&f.0, &[], &paths, none, cancel, digest);
        // No scan reads it, which the report says; checking it again would
        // read no more.
        assert_eq!(r.not_checked.len(), 1);
        assert_eq!(left, Unreached::default());
    }
}
