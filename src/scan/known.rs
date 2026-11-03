//! The known locations: the files, folders and trees of records that rules
//! name, checked before discovery.

use super::{trees, Scan, EXCLUDED, TREE_DEPTH, TREE_ENTRIES, TREE_SKIP};
use crate::fsutil::{list_dir, through_links};
use crate::rules::browser::CHROMIUM;
use crate::rules::{Hit, Rule, Target, RULES};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

/// Whether a scan reads `rel`, a path below the home folder, with the rule
/// `rule` even inside a folder the person asked not to be checked: as
/// `known_files` and the trees of records read it, that rule's own file, a
/// file directly in a folder it covers or at the top of its tree, or a
/// place whose presence is its finding. Nothing else in such a folder is
/// read. By the place's own name: a known location that is a link is read
/// where the link leads, which this does not follow.
pub fn read_when_skipped(rule: &str, rel: &Path) -> bool {
    let at = |up: usize, place: &str| rel.ancestors().nth(up) == Some(Path::new(place));
    let named = |name: &str| rel.file_name() == Some(name.as_ref());
    let stores = rel.parent().and_then(Path::file_name);
    let mut targets = RULES
        .iter()
        .filter(|r| r.id == rule)
        .flat_map(|r| r.targets);
    targets.any(|target| match *target {
        Target::File(f) | Target::Present(f, _) => at(0, f),
        Target::Dir(d) | Target::Tree(d) => at(1, d),
        Target::Each(d, f) => named(f) && at(2, d),
        // At the top of the browser's folder, or in one of its profiles.
        Target::Profiles(f) => named(f) && CHROMIUM.iter().any(|b| at(1, b) || at(2, b)),
        Target::Extension(id, _) => {
            named(id)
                && stores == Some("Local Extension Settings".as_ref())
                && CHROMIUM.iter().any(|b| at(2, b) || at(3, b))
        }
        Target::Discovery | Target::Name(_) | Target::Repo(_) => false,
    })
}

impl Scan {
    /// Check every known location, before any discovery.
    pub(super) fn known(&mut self) {
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
    pub(super) fn known_files(&mut self, from: usize, resume: bool) -> Option<usize> {
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
    pub(super) fn present(&mut self, rule: &Rule, at: &Path, what: &str) {
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
    pub(super) fn stores(&mut self, dir: &Path, profiles: Vec<(PathBuf, bool)>, changed: bool) {
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
            // A profile folder may itself be a link. An entry that leads to
            // no folder, as a link to a file does, has nothing below it.
            if !is_dir && !self.leads_to_folder(&profile) {
                continue;
            }
            for &(rule, id, what) in &wanted {
                // A link on the way is followed as for any known location.
                let at = profile.join("Local Extension Settings").join(id);
                let Some(store) = self.targeted(&at) else {
                    continue;
                };
                if std::fs::symlink_metadata(&store).is_ok_and(|m| m.is_dir()) {
                    self.add(rule, &store, Hit::file().about(what), false, &[]);
                }
            }
        }
    }

    /// Whether `p`, listed as no folder, is a link to one. Where it leads is
    /// resolved once, as `targeted` resolves it, which then says how far a
    /// look below it may follow it. Of a link out of the home folder, or one
    /// that cannot be resolved, only whether it leads to a folder is asked:
    /// nothing in it is looked at here.
    pub(super) fn leads_to_folder(&self, p: &Path) -> bool {
        let folder = |m: std::io::Result<std::fs::Metadata>| m.is_ok_and(|m| m.is_dir());
        let link = std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink());
        link && match through_links(p, &self.home) {
            // Nothing there.
            None => false,
            Some(Ok(real)) => folder(std::fs::symlink_metadata(real)),
            Some(Err(_)) => folder(std::fs::metadata(p)),
        }
    }

    /// Read every file under a folder in full.
    pub(super) fn tree(&mut self, rule: &Rule, dir: &'static str) {
        if let Some(root) = self.targeted(&self.home.join(dir)) {
            self.tree_from(rule, root, 0, None);
        }
    }

    /// As `tree`, from a folder `depth` levels below the tree's root. With
    /// `after`, that folder's subfolders are already queued and its files up
    /// to that one already read. Returns the folders not finished when the
    /// scan was stopped, in those three parts, for a later slice of a sweep.
    pub(super) fn tree_from(
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

    /// Check one named file in each direct subfolder, such as browser profiles.
    pub(super) fn each(&mut self, rule: &Rule, parent: &'static str, file: &'static str) {
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

    pub(super) fn dir(&mut self, name: &'static str) {
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
}
