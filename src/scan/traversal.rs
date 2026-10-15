//! Discovery scheduling and checkpoints. This module neither opens files nor
//! runs rules: the scanner returns a Visit for each directory it checks.
//! It owns the entry budget, reusable listings, resume checkpoints and the
//! breadth-first order. Only resumable sweeps keep entry cursors; an ordinary
//! scan revisits from the start. Matching record trees, time and cancellation,
//! and recording gaps stay with the scanner.
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};

#[derive(Default)]
pub(super) struct Visit {
    pub folders: Vec<PathBuf>,
    pub interrupted: bool,
    pub last_entry: Option<PathBuf>,
    /// A gap-free listing from its beginning can be reused for overlapping roots.
    pub complete: bool,
}

pub(super) struct Traversal {
    pub remaining: usize,
    pub completed: HashMap<PathBuf, Vec<PathBuf>>,
    checkpoints: Option<HashMap<PathBuf, PathBuf>>,
    pending: Vec<(PathBuf, usize)>,
}

impl Traversal {
    pub fn new(entries: usize) -> Self {
        Self {
            remaining: entries,
            completed: HashMap::new(),
            checkpoints: None,
            pending: Vec::new(),
        }
    }

    pub fn resume(&mut self, checkpoints: HashMap<PathBuf, PathBuf>) {
        self.checkpoints = Some(checkpoints);
    }

    pub fn resumable(&self) -> bool {
        self.checkpoints.is_some()
    }

    pub fn take_checkpoint(&mut self, dir: &Path) -> Option<PathBuf> {
        self.checkpoints.as_mut().and_then(|c| c.remove(dir))
    }

    pub fn record(&mut self, dir: &Path, visit: &Visit) {
        if let (Some(checkpoints), Some(last)) = (&mut self.checkpoints, &visit.last_entry) {
            if visit.interrupted {
                checkpoints.insert(dir.to_path_buf(), last.clone());
            }
        }
        if visit.complete && self.completed.len() < 100_000 {
            self.completed
                .insert(dir.to_path_buf(), visit.folders.clone());
        }
    }

    pub fn defer(&mut self, folders: Vec<(PathBuf, usize)>) {
        self.pending.extend(folders);
    }

    pub fn pending_steps(&mut self) -> super::Pending {
        let mut checkpoints = self.checkpoints.take().unwrap_or_default();
        std::mem::take(&mut self.pending)
            .into_iter()
            .map(|(dir, depth)| match checkpoints.remove(&dir) {
                Some(after) => super::Step::Rest { dir, depth, after },
                None => super::Step::Folder(dir, depth),
            })
            .collect()
    }
}

/// Breadth-first ordering, delayed home folders and unfinished work for one root.
/// A partial visit retains its directory as well as the children already listed.
pub(super) struct Walk {
    queue: VecDeque<(PathBuf, usize)>,
    delayed: VecDeque<(PathBuf, usize)>,
    unfinished: Vec<(PathBuf, usize)>,
}

impl Walk {
    pub fn new(folders: Vec<(PathBuf, usize)>) -> Self {
        Self {
            queue: folders.into(),
            delayed: VecDeque::new(),
            unfinished: Vec::new(),
        }
    }

    pub fn next(&mut self) -> Option<(PathBuf, usize)> {
        if self.queue.is_empty() {
            self.queue.append(&mut self.delayed);
        }
        self.queue.pop_front()
    }

    pub fn stop(&mut self, dir: PathBuf, depth: usize) {
        self.unfinished.push((dir, depth));
        self.unfinished
            .extend(self.queue.drain(..).chain(self.delayed.drain(..)));
    }

    pub fn visited(
        &mut self,
        dir: &Path,
        depth: usize,
        visit: Visit,
        delay: impl Fn(&Path) -> bool,
    ) {
        if visit.interrupted {
            self.unfinished.push((dir.to_path_buf(), depth));
        }
        for child in visit.folders {
            let queue = if delay(&child) {
                &mut self.delayed
            } else {
                &mut self.queue
            };
            queue.push_back((child, depth + 1));
        }
    }

    pub fn unfinished(self) -> Vec<(PathBuf, usize)> {
        self.unfinished
    }
}
