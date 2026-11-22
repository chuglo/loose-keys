//! Resumable slices of the automatic full pass.

use super::*;

impl Scan {
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
        let (report, left, _) =
            Self::sweep_with_coverage(home, skip, resume, limits, cancel, fingerprint);
        (report, left)
    }

    /// Also say whether the slice omitted an unread path. Ordinary slice
    /// checkpoints are resumed and do not make the saved list incomplete.
    pub fn sweep_with_coverage(
        home: &Path,
        skip: &[PathBuf],
        resume: Option<Pending>,
        limits: Limits,
        cancel: Arc<AtomicBool>,
        fingerprint: impl Fn(&str, &[u8], bool) -> String + Send + 'static,
    ) -> (Report, Pending, bool) {
        let mut s = Scan::new(
            home,
            None,
            Some(cancel),
            Some(Box::new(fingerprint)),
            limits.entries,
        );
        s.limit = limits.time;
        s.skip = paths::saved_paths(skip, home);
        let mut places = HashMap::new();
        let mut left = Vec::new();
        let mut folders = Vec::new();
        for step in resume.unwrap_or_else(|| vec![Step::Known(0)]) {
            let step = if s.skip.is_empty() {
                step
            } else {
                step.on_disk(home)
            };
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
        let omitted = s.unread_paths_omitted;
        (s.into_report(&[home.to_path_buf()]), left, omitted)
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
}

impl Step {
    /// A saved cursor can still name a renamed parent by its old spelling.
    /// Keep its last entry under the folder we will list in this slice.
    fn on_disk(self, home: &Path) -> Self {
        let cursor = |dir: &Path, after: PathBuf| {
            after
                .file_name()
                .map_or_else(|| after.clone(), |name| dir.join(name))
        };
        match self {
            Self::Known(_) => self,
            Self::Folder(dir, depth) => Self::Folder(saved_path(&dir, home), depth),
            Self::Rest { dir, depth, after } => {
                let dir = saved_path(&dir, home);
                let after = cursor(&dir, after);
                Self::Rest { dir, depth, after }
            }
            Self::Records {
                rule,
                dir,
                depth,
                after,
            } => {
                let dir = saved_path(&dir, home);
                let after = after.map(|p| cursor(&dir, p));
                Self::Records {
                    rule,
                    dir,
                    depth,
                    after,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slice_checkpoint_alone_does_not_truncate_automatic_coverage() {
        let home = std::env::temp_dir().join(format!("slice-gap-{}", std::process::id()));
        let mut scan = Scan::new(&home, None, Some(Arc::new(AtomicBool::new(false))), None, 0);
        for n in 0..MAX_GAPS - 1 {
            scan.list_gap(&home.join(n.to_string()), "unreadable");
        }
        scan.list_gap(&home, "scan-limit");
        assert!(!scan.unread_paths_omitted);
        scan.list_gap(&home.join("0"), "unreadable");
        assert!(!scan.unread_paths_omitted);
        scan.list_gap(&home.join("one more"), "unreadable");
        assert!(scan.unread_paths_omitted);
    }
}
