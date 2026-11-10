//! Reading one file and running the rules on it: its head, the whole file,
//! or a record read through from start to end.

use super::{
    trees, Scan, CONFIG_MAX, EXCLUDED, HEADER, RECORD_HITS, STREAM_MAX, TREE_DEPTH, TREE_SKIP,
};
use crate::fsutil::{open_regular, read_config, read_config_in, read_head, read_head_in, Gap};
use crate::rules::{Hit, Matcher, Rule, Target, RULES};
use std::collections::HashSet;
use std::ffi::OsStr;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

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
pub(super) fn settled(
    path: &Path,
    first: crate::fsutil::Head,
) -> Result<Option<crate::fsutil::Head>, Gap> {
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

/// How much of a file read through is read at a time.
pub(super) const READ_PIECE: usize = 1024 * 1024;

/// The next piece of a file read through, taken from `carry`, what is held
/// of it: up to its last line break, or all of it once the file has
/// `ended`. A line longer than four reads is cut by `long_line_cut`. None:
/// read more first. A scan and a recheck both cut with this, so that a
/// recheck sees what the scan saw.
pub(super) fn take_piece(carry: &mut Vec<u8>, ended: bool) -> Option<Vec<u8>> {
    let cut = match carry.iter().rposition(|b| *b == b'\n') {
        _ if ended => carry.len(),
        Some(end) => end + 1,
        None if carry.len() > 4 * READ_PIECE => long_line_cut(carry),
        None => 0,
    };
    (cut > 0).then(|| carry.drain(..cut).collect())
}

/// What tells one value in a piece from another: a hash of its subject and
/// its bytes, which are not kept.
pub(super) fn value_key(hit: &Hit, piece: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hit.subject.hash(&mut hasher);
    hit.span
        .clone()
        .and_then(|s| piece.get(s))
        .hash(&mut hasher);
    hasher.finish()
}

/// Where to cut a line too long to hold whole: after the last byte near its
/// end that no token format contains and that says nothing about where the
/// next one starts, so that no token is cut in two there. "[" and ";" are
/// not such bytes: a colour code before a token has them. Nor is ":", which
/// a webhook URL's format begins with. A run with no such byte, as in
/// encoded binary data, is cut short of its end, and a token across that
/// place can be missed.
fn long_line_cut(carry: &[u8]) -> usize {
    let near = carry.len().saturating_sub(4096);
    carry[near..]
        .iter()
        .rposition(|b| b" \t\"'{}]()<>&%|?#@".contains(b))
        .map_or(carry.len().saturating_sub(512), |at| near + at + 1)
}

impl Scan {
    /// Read one file from start to end in pieces that end at a line break,
    /// reporting each distinct secret once, at its first appearance. A session
    /// record repeats one token many times; two different tokens are two findings.
    /// Returns false when the scan was stopped before the file's end; a file
    /// that could not be read, or need not be, is done with.
    pub(super) fn stream(&mut self, rule: &Rule, p: &Path) -> bool {
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
        let mut buffer = vec![0u8; READ_PIECE];
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
            if let Some(piece) = take_piece(&mut carry, read == 0) {
                let hits = self.matcher_hits(p, test(&piece, line));
                for hit in hits {
                    // Only a hash of the bytes is kept, and only for this file.
                    let value = value_key(&hit, &piece);
                    if seen.contains(&value) {
                        continue;
                    }
                    // A record lists this many different tokens. One more
                    // is a limit reached, which is said once for the file.
                    if seen.len() == RECORD_HITS {
                        if !std::mem::replace(&mut full, true) {
                            self.gap(p, "scan-limit");
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

    /// Read a file's head, recording a gap if it is in scope but unreadable.
    fn head(&mut self, p: &Path, max: u64) -> Option<crate::fsutil::Head> {
        if self.stopped() {
            self.unread(p);
            return None;
        }
        self.counts.header_attempts += 1;
        self.tick();
        let read = match self.in_folder(p) {
            Some((dir, name)) => read_head_in(dir, name, max),
            None => read_head(p, max),
        };
        match read {
            Ok(h) => h,
            // One gap per folder: a synced folder can hold thousands of these.
            Err("cloud-only-file") => {
                self.gap(p.parent().unwrap_or(p), "cloud-only-file");
                None
            }
            Err(g) => {
                self.gap(p, g);
                None
            }
        }
    }

    /// The open folder `p` is in, and its name there, when discovery is
    /// checking that folder's files.
    fn in_folder<'a>(&self, p: &'a Path) -> Option<(&std::fs::File, &'a OsStr)> {
        let (dir, handle) = self.folder.as_ref()?;
        (p.parent() == Some(dir)).then_some((handle, p.file_name()?))
    }

    /// Run every rule with this target against one file.
    pub(super) fn check_head(&mut self, p: &Path, target: Target) {
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
                    // Read whole only as the fingerprint's material. The head
                    // matched, so a file too large for that is still checked.
                    let full = (self.fingerprint.is_some() && !self.stopped())
                        .then(|| {
                            self.counts.config_attempts += 1;
                            self.read_whole(p).ok().flatten()
                        })
                        .flatten();
                    match full {
                        Some(full) => self.add(rule, p, Hit::file(), full.shared, &full.bytes),
                        None => self.add(rule, p, Hit::file(), h.shared, &h.bytes),
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
    pub(super) fn whole(&mut self, rule: &Rule, p: &Path) {
        let Matcher::Whole { test, .. } = rule.matcher else {
            return;
        };
        if !self.whole_files_checked.insert((rule.id, p.to_path_buf())) {
            return;
        }
        // A record is read through by its own rule for the same tokens, at
        // any size, and that rule says so itself when it cannot read it.
        let record = rule.id == crate::rules::SERVICE_TOKEN_ID && self.read_as_record(p);
        let Some(h) = self.config(p, record.then_some("too-large")) else {
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
                self.gap(path, incomplete.reason);
                incomplete.hits
            }
        }
    }

    /// Read a whole file, recording a gap if it cannot be, unless for
    /// `quiet`: a reason another rule answers for.
    fn config(&mut self, p: &Path, quiet: Option<Gap>) -> Option<crate::fsutil::Head> {
        if self.stopped() {
            self.unread(p);
            return None;
        }
        self.counts.config_attempts += 1;
        self.publish(false);
        match self.read_whole(p) {
            Ok(h) => h,
            Err(g) => {
                if quiet != Some(g) {
                    self.gap(p, g);
                }
                None
            }
        }
    }

    /// Whether a rule for records reads `p` through: a file in a tree of
    /// records, in no folder that rule passes over, and no deeper than it
    /// reads. The tree is where that rule reads it: by its own name in the
    /// home folder, or where a link it follows leads.
    fn read_as_record(&mut self, p: &Path) -> bool {
        trees().any(|(_, dir)| {
            let Some(root) = self.targeted(&self.home.join(dir)) else {
                return false;
            };
            let Some(parent) = p.parent().filter(|parent| parent.starts_with(&root)) else {
                return false;
            };
            // The folders below the root on the way to the file, each judged
            // as `tree_from` judges it before going in.
            let folders: Vec<&Path> = parent.ancestors().take_while(|a| *a != root).collect();
            folders.len() <= TREE_DEPTH
                && folders.iter().all(|folder| {
                    !self.skipped(folder)
                        && !EXCLUDED.iter().any(|name| folder.ends_with(name))
                        && !TREE_SKIP
                            .iter()
                            .any(|name| folder.file_name() == Some(name.as_ref()))
                })
        })
    }

    /// Read a whole file, from the open folder when it is in it.
    fn read_whole(&self, p: &Path) -> Result<Option<crate::fsutil::Head>, Gap> {
        match self.in_folder(p) {
            Some((dir, name)) => read_config_in(dir, name, CONFIG_MAX),
            None => read_config(p, CONFIG_MAX),
        }
    }
}
