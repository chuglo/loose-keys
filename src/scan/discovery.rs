//! Discovery: the walk through the folders of each root, checking the head
//! of each file and the files rules name in a repository's `.git`.
//! `traversal` keeps the walk's order and budget.

use super::traversal::{Visit, Walk};
use super::{Scan, ASKS, EXCLUDED, LAST, MAX_FINDINGS, MAX_GAPS};
use crate::fsutil::FOLDER_ENTRIES;
use crate::rules::{Target, RULES};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

impl Scan {
    /// Walk a root breadth-first from `start`, so the work budget is spent on
    /// shallow folders everywhere before deep ones anywhere. When the budget,
    /// time or a cancel ends the walk, the unvisited folders are kept in
    /// `pending` and each top-level folder holding some gets one gap.
    pub(super) fn discover(&mut self, root: &Path, start: Vec<(PathBuf, usize)>) {
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
            self.gap(&top, "scan-limit");
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
        let listing = self
            .folders
            .list(dir, required, &mut self.traversal.remaining);
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
            interrupted = g == "scan-limit" && entries.entries.len() < FOLDER_ENTRIES;
        }
        let open = entries.handle.map(|handle| (dir.to_path_buf(), handle));
        let outer = std::mem::replace(&mut self.folder, open);
        // A listing the budget cut is some of the entries, in no order: the
        // place reached in it says nothing about the ones it left out.
        let ordered = !interrupted;
        // A sweep lists it again from its start in its next slice, which
        // passes all its subfolders on then. Passed on here as well, those
        // listed now would be walked twice, with all they hold.
        let pass_on = ordered || !self.traversal.resumable();
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
            } else if p.file_name() != Some(denied.as_ref()) && !ASKS.iter().any(|a| p.ends_with(a))
            {
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
                let unsaid = self.not_checked.len() >= MAX_GAPS;
                let alone = if self.findings.len() >= MAX_FINDINGS {
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
            if pass_on && is_dir && !EXCLUDED.iter().any(|name| p.ends_with(name)) && !skipped {
                subfolders.push(p);
            }
        }
        self.folder = outer;
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
    pub(super) fn repo(&mut self, git: &Path, only: Option<&OsStr>) {
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
}
