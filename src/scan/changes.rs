//! A check of changed paths (`Scan::changed`): each path itself, the known
//! locations it touches, and where the links in a known folder lead.

use super::{is_root, Scan, Unreached, ASKS, EXCLUDED, TREE_DEPTH, TREE_SKIP};
use crate::fsutil::{list_dir, through_links};
use crate::report::NotChecked;
use crate::rules::browser::CHROMIUM;
use crate::rules::{Hit, Rule, Target, RULES};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

impl Scan {
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
    pub(super) fn unread_once(&mut self, dir: &Path) {
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

    /// The work of `changed`, for a scan made with its limits.
    pub(super) fn changes(&mut self, paths: &[PathBuf]) -> Unreached {
        let s = self;
        let home = &s.home.clone();
        let mut unreached = Unreached::default();
        // Whether a path before this one began to use the check's limits.
        let mut shared = false;
        // Judged below the home only: the names above it are not the scan's.
        // Discovery passes over folders by these names, never a file.
        let excluded = |p: &Path, folder: bool| {
            p.strip_prefix(home).is_ok_and(|below| {
                below
                    .ancestors()
                    .skip(usize::from(!folder))
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
                .filter(|git| git.parent().is_some_and(|repo| !excluded(repo, true)));
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
                let walked =
                    meta.is_ok_and(|m| (m.is_dir() || m.is_file()) && !excluded(p, m.is_dir()));
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
            let meta = std::fs::symlink_metadata(p)
                .ok()
                .filter(|m| !excluded(p, m.is_dir()));
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
                        for at in [p.to_path_buf(), p.join(id), p.join(settings).join(id)] {
                            if !self.extension_store(&at, id) {
                                continue;
                            }
                            // A link on the way, the changed path too, is
                            // followed as a scan follows it.
                            if let Some(store) = self.targeted(&at).filter(|s| folder(s)) {
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
}
