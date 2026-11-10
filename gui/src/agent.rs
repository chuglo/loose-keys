//! The background agent: this executable run with `--agent`. It has no
//! window or Dock icon. launchd starts it at login and restarts it if it
//! fails (gui/macos/dev.loosekeys.agent.plist).
//!
//! It checks files when they change, works through the rest of the home
//! folder in short slices until every folder has been seen once, and sends
//! the review notification. The app and the agent share the review store.

use crate::monitor::{Monitor, ScanKind, CADENCE};
use crate::report::Report;
use crate::review::{self, Review, Store};
use crate::scan::{self, Limits, Scan};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::{c_char, CStr, CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Seconds over which file changes are gathered into one batch.
const LATENCY: f64 = 10.0;
/// What checking one batch of changes may spend.
const CHANGES: Limits = Limits {
    entries: 20_000,
    time: Duration::from_secs(10),
};
/// What one slice of a full pass may spend, and the rest between slices.
const SLICE: Limits = Limits {
    entries: 20_000,
    time: Duration::from_secs(5),
};
const SLICE_PAUSE: Duration = Duration::from_secs(30);
/// The wait before a full pass held by Low Power Mode is tried again.
const LOW_POWER_PAUSE: Duration = Duration::from_secs(600);
/// The rechecks of one save run with the store locked, which the app waits
/// for whenever it reads or changes the review list.
const RECHECKS: Duration = Duration::from_secs(10);
/// A full pass is repeated this often, in case a change was ever missed.
const FULL_PASS_EVERY: u64 = 7 * 24 * 3600;
/// A file that keeps changing is checked again after this long, doubling each
/// time up to the tick, so a busy file costs a few reads an hour, not thousands.
const RECHECK_AFTER: Duration = Duration::from_secs(30);
/// Changes held at once. Beyond this, a full pass replaces checking each one.
const INBOX_MAX: usize = 5000;
/// A path whose check was cut short asks for a full pass once in this long.
const PASS_AGAIN: Duration = Duration::from_secs(24 * 3600);
/// While notifications are not allowed, macOS is asked again once in this
/// long, or when the app has changed the shared state.
const PERMISSION_AGAIN: Duration = Duration::from_secs(15 * 60);

/// Whether the weekly full pass is due, the last having ended at
/// `baseline_at`. A time more than a day ahead of the clock was written
/// while the clock was wrong. Counted from it, the next pass would wait
/// until the clock was a week past it, so it counts as long ago.
fn pass_due(baseline_at: u64, now: u64) -> bool {
    now.saturating_sub(baseline_at) > FULL_PASS_EVERY || baseline_at > now.saturating_add(24 * 3600)
}

/// Whether an agent starting with the saved `state` begins with a full
/// pass: on its first run, from `since` 0, when the weekly pass is due, and
/// when one was under way or owed, which leaves folders to check.
fn pass_at_start(state: &review::Agent, since: u64, now: u64) -> bool {
    since == 0 || state.left != 0 || pass_due(state.baseline_at, now)
}

// FSEvents flags: events were dropped or coalesced, so the folder must be
// walked; and the marker that ends replayed history.
const MUST_RESCAN: u32 = 0x1 | 0x2 | 0x4 | 0x8;
const HISTORY_DONE: u32 = 0x10;
/// Dropped because this process did not keep up, not by the kernel, with the
/// event numbers intact: the change history still has every one.
const USER_DROPPED: u32 = 0x2;
const LOST: u32 = 0x4 | 0x8;
/// How often the stream may be opened again for dropped events, in
/// `RESUME_WINDOW`, before a full pass makes up for them instead.
const RESUMES_MAX: usize = 10;
const RESUME_WINDOW: Duration = Duration::from_secs(600);

unsafe extern "C" {
    fn ch_watch_start(
        path: *const c_char,
        since: u64,
        latency: f64,
        change: extern "C" fn(*const c_char, u32),
        batch: extern "C" fn(u64),
    ) -> bool;
    fn ch_watch_resume(since: u64) -> bool;
    fn ch_watch_volume(path: *const c_char, out: *mut c_char) -> bool;
    fn ch_low_power() -> bool;
    fn ch_open_app();
    fn ch_agent_run();
}

struct Agent {
    home: PathBuf,
    state_dir: PathBuf,
    store: Store,
    monitor: Monitor,
    inbox: Mutex<Inbox>,
    /// When the notification being sent was handed to macOS, until its
    /// completion comes back.
    delivering: Mutex<Option<Instant>>,
    /// From the last state read or written: what the next step needs without
    /// reading the store again.
    known: Mutex<Known>,
    /// How long a path that changed again waits for its next check, before
    /// doubling. `RECHECK_AFTER`, except in tests.
    recheck_after: Duration,
    /// `SLICE` and `SLICE_PAUSE`, except in tests.
    slice: Limits,
    slice_pause: Duration,
    /// How long one save may spend rechecking open items. `RECHECKS`,
    /// except in tests.
    rechecks: Duration,
    /// What checking one batch of changes may spend. `CHANGES`, except in
    /// tests.
    changes: Limits,
    /// Whether Low Power Mode is on, which postpones the full pass.
    low_power: fn() -> bool,
    /// `LOW_POWER_PAUSE`, except in tests.
    low_power_pause: Duration,
    /// Open the event stream again from an event, to replay what was
    /// dropped. Ends the agent if it cannot, so launchd starts it again.
    resume_watch: fn(u64),
    /// Ask macOS again whether notifications are allowed.
    refresh: fn(),
    /// When it was last asked, by `deliver`.
    asked: Mutex<Option<Instant>>,
    /// Saves of what a check found that have failed in a row. A full pass
    /// waits longer for each before it makes the slice again.
    unsaved: AtomicU32,
}

#[derive(Default)]
struct Inbox {
    paths: BTreeSet<PathBuf>,
    /// Changes were missed or too many to hold: walk the home again.
    full_pass: bool,
    settings: bool,
    last_event: u64,
    /// Events were dropped: the place to replay the change history from.
    resume: Option<u64>,
    /// Drops reported so far, so that one reported while the stream is
    /// opened again is not taken as handled by that opening.
    drops: u64,
}

#[derive(Default)]
struct Known {
    key: Vec<u8>,
    enabled: bool,
    paused: bool,
    /// Paths of unresolved review items and stored sign-ins.
    open: Vec<PathBuf>,
    unnotified: bool,
    /// Folders the person asked not to be checked.
    skip: Vec<PathBuf>,
    /// When the next notification attempt may be made, if one is owed.
    retry_at: Option<u64>,
    saved_event: u64,
    /// The last number given to a read of the state, and the number of the
    /// state remembered.
    tickets: u64,
    remembered: u64,
}

static AGENT: OnceLock<Agent> = OnceLock::new();

impl Agent {
    /// A number for a read of the state about to be made, or for a change
    /// to it, taken inside the store's update: a later read gets a larger one.
    fn ticket(&self) -> u64 {
        let mut known = self.known.lock().unwrap();
        known.tickets += 1;
        known.tickets
    }

    /// Take in `state`, read under `ticket`.
    fn remember(&self, state: &Review, ticket: u64) {
        let mut known = self.known.lock().unwrap();
        // Read before the state last taken in, it may hold a setting that
        // has changed since.
        if ticket < known.remembered {
            return;
        }
        known.remembered = ticket;
        known.key = state.key.clone();
        known.open = state
            .items
            .iter()
            .chain(&state.stored.items)
            .filter(|i| !i.resolved)
            .filter_map(|i| crate::recheck_path(&i.path, Some(&self.home)))
            .collect();
        let now = crate::now();
        known.unnotified = state.items.iter().any(|i| state.alerting(i, now));
        known.skip = crate::skipped_paths(state, &self.home);
        known.retry_at = (known.unnotified && state.attempts < 3).then_some(state.retry_at);
        known.saved_event = state.agent.event_id;
        let wanted = (state.monitoring && !scan::is_root(), state.paused);
        if (known.enabled, known.paused) != wanted {
            (known.enabled, known.paused) = wanted;
            drop(known);
            // Also cancels work in progress and makes the next check due now.
            self.monitor.configure(wanted.0, wanted.1);
        }
    }

    /// The key a check's digests are made with, and a digest made with it.
    fn fingerprint(
        &self,
    ) -> (
        Vec<u8>,
        impl Fn(&str, &[u8], bool) -> String + Send + 'static,
    ) {
        let key = self.known.lock().unwrap().key.clone();
        let made_with = key.clone();
        let digest = move |rule: &str, bytes: &[u8], shared| {
            crate::material_fingerprint(rule, &key, bytes, shared)
        };
        (made_with, digest)
    }

    /// Save what a check found. `only` limits the recheck of open items to
    /// those at or under the changed paths, and those in a file the check
    /// lists a finding in: it read that file, and what it found there may
    /// stand in place of what was listed. `place` is how far in the change
    /// history every change has now been checked, when that has moved.
    /// `key` is the one the check's digests were made with.
    /// Returns whether it was saved. If not, what was found is on no list,
    /// and the check has to be made again before anything is saved that
    /// says it was made.
    #[must_use]
    fn record(
        &self,
        report: &Report,
        key: &[u8],
        only: Option<&[PathBuf]>,
        place: Option<u64>,
        health: impl FnOnce(&mut review::Agent),
    ) -> bool {
        let mut ticket = 0;
        let saved = self.store.update(|state| {
            ticket = self.ticket();
            // A list replaced while the check ran has another key, and the
            // check's digests would be taken for other values there. Nothing
            // it found is saved; the list is, unchanged, so that its key is
            // known below and the check made again with it.
            if state.key != key {
                return Ok(false);
            }
            // Counted from here: the store is locked from here on.
            let rechecking = Instant::now();
            let found: HashSet<&str> = report.findings.iter().map(|f| f.path.as_str()).collect();
            state.merge(report, |item, want| {
                let path = crate::recheck_path(&item.path, Some(&self.home))?;
                let changed = |only: &[PathBuf]| only.iter().any(|p| path.starts_with(p));
                if only.is_some_and(|only| !changed(only)) && !found.contains(item.path.as_str()) {
                    return None;
                }
                // Out of time, or told to stop: nothing is known of the rest,
                // and they stay as they are until they are next checked.
                // Asked again while one large file is read.
                let stop = || {
                    rechecking.elapsed() >= self.rechecks
                        || self.monitor.cancel.load(Ordering::SeqCst)
                };
                if stop() {
                    return None;
                }
                crate::still_there(item, &self.home, key, want, &stop)
            });
            state.agent.last_check = Some(report.generated_at.clone());
            state.agent.error = None;
            // The last slice of a full pass, which looked for every stored
            // sign-in.
            if only.is_none() {
                state.stored.checked_at = Some(report.generated_at.clone());
            }
            if let Some(place) = place.filter(|place| *place != 0) {
                state.agent.event_id = place;
            }
            health(&mut state.agent);
            Ok(true)
        });
        match saved {
            Ok((state, merged)) => {
                if merged {
                    self.unsaved.store(0, Ordering::SeqCst);
                }
                self.remember(&state, ticket);
                merged
            }
            Err(e) => {
                eprintln!("loose-keys agent: {e}");
                // Only the worker counts, so nothing is lost between the two.
                let failed = self.unsaved.load(Ordering::SeqCst);
                self.unsaved
                    .store(failed.saturating_add(1), Ordering::SeqCst);
                false
            }
        }
    }

    /// Whether a batch of changes needs the store at all. Most do not. A
    /// finding of either kind does, a stored sign-in as well as one worth
    /// reviewing, and so does a change to the file of a listed one.
    fn concerns_review(&self, report: &Report, changed: &[PathBuf]) -> bool {
        report
            .findings
            .iter()
            .any(|f| matches!(f.kind, "review" | "inventory"))
            || self
                .known
                .lock()
                .unwrap()
                .open
                .iter()
                .any(|open| changed.iter().any(|p| open.starts_with(p)))
    }

    fn deliver(&self) {
        if !self.known.lock().unwrap().unnotified {
            return;
        }
        if crate::PERMISSION.load(Ordering::SeqCst) != 3 {
            // What was read at the start may no longer hold: consent starts
            // this helper, and the person is asked about notifications after
            // that, in the app. So with something to send, ask again. The
            // answer comes back through `permission`, which calls for
            // another try when it is yes. Not at every wake: the app saves
            // the shared state when notifications are allowed there, and
            // `batch` then lets this ask at once.
            let mut asked = self.asked.lock().unwrap();
            if asked.is_none_or(|at| at.elapsed() >= PERMISSION_AGAIN) {
                *asked = Some(Instant::now());
                drop(asked);
                (self.refresh)();
            }
            return;
        }
        // The app shows new items itself while it is in front.
        if unsafe { crate::ch_app_active() } {
            return self.monitor.retry_in(Duration::from_secs(60));
        }
        let due = |state: &Review| state.monitoring && !state.paused && state.pending(crate::now());
        if !self.store.read().is_ok_and(|state| due(&state)) || !self.claim_delivery() {
            return;
        }
        let attempt = self.store.update(|state| {
            state.attempted(crate::now());
            Ok(state.revision)
        });
        match attempt {
            // The bridge rechecks permission and the front app before sending.
            Ok((_, revision)) => unsafe { crate::ch_notifications_send(revision) },
            Err(e) => {
                eprintln!("loose-keys agent: {e}");
                *self.delivering.lock().unwrap() = None;
            }
        }
    }

    /// Whether a notification may be handed to macOS now, and if so, mark
    /// one as under way.
    fn claim_delivery(&self) -> bool {
        let mut began = self.delivering.lock().unwrap();
        let now = Instant::now();
        if delivery_under_way(*began, now) {
            return false;
        }
        *began = Some(now);
        true
    }

    /// The completion of a notification handed to macOS. `allowed` is
    /// whether notifications were allowed when it came back.
    fn delivered(&self, revision: u64, success: bool, allowed: bool) {
        let state = if success {
            self.store.update(|state| {
                state.delivered(revision);
                Ok(self.ticket())
            })
        } else if !allowed {
            // Refused because notifications are not allowed, which the
            // bridge reports to `permission` first. No delivery failed, so
            // the attempt is given back: turned on again, they find it owed.
            self.store.update(|state| {
                state.attempts = state.attempts.saturating_sub(1);
                Ok(self.ticket())
            })
        } else {
            let ticket = self.ticket();
            self.store.read().map(|state| (state, ticket))
        };
        *self.delivering.lock().unwrap() = None;
        match state {
            Ok((state, ticket)) => {
                self.remember(&state, ticket);
                if state.attempts < 3 {
                    let delay = state.retry_at.saturating_sub(crate::now()).max(1);
                    self.monitor.retry_in(Duration::from_secs(delay));
                }
            }
            Err(e) => eprintln!("loose-keys agent: {e}"),
        }
    }

    /// One file-change event: hold the path for the worker.
    fn changed(&self, path: PathBuf, flags: u32) {
        if flags & HISTORY_DONE != 0 {
            return;
        }
        let mut inbox = self.inbox.lock().unwrap();
        let enabled = self.known.lock().unwrap().enabled;
        if path.starts_with(&self.state_dir) {
            inbox.settings = true;
        } else if enabled && flags & USER_DROPPED != 0 && flags & LOST == 0 && inbox.last_event != 0
        {
            // Read again from the change history, from the last batch handled
            // in full, instead of walking the whole home.
            let from = inbox.last_event;
            inbox.resume.get_or_insert(from);
            inbox.drops = inbox.drops.wrapping_add(1);
        } else if !enabled
            || (flags & MUST_RESCAN != 0 && !path.starts_with(&self.home))
            || (flags & MUST_RESCAN != 0 && path == self.home)
        {
            // Nothing is read while monitoring is off; catch up when it is on.
            inbox.full_pass = true;
        } else {
            inbox.paths.insert(scan::change_at(&self.home, &path));
            if inbox.paths.len() > INBOX_MAX {
                inbox.paths.clear();
                inbox.full_pass = true;
            }
        }
    }

    /// The end of one batch of events: wake the worker for what was held.
    fn batch(&self, last_event: u64) {
        let settings = {
            let mut inbox = self.inbox.lock().unwrap();
            // Not past events that were dropped: until they are replayed,
            // no saved place may follow them. Nor to 0, which FSEvents gives
            // some events and which would make a restart read from now.
            if inbox.resume.is_none() && last_event != 0 {
                inbox.last_event = last_event;
            }
            std::mem::take(&mut inbox.settings)
        };
        // The app changed the shared state: a setting, a decision or a retry.
        if settings {
            *self.asked.lock().unwrap() = None;
            let ticket = self.ticket();
            match self.store.read() {
                Ok(state) => self.remember(&state, ticket),
                Err(e) => eprintln!("loose-keys agent: {e}"),
            }
        }
        self.monitor.retry_in(Duration::ZERO);
    }
}

extern "C" fn changed(path: *const c_char, flags: u32) {
    let Some(agent) = AGENT.get() else {
        return;
    };
    // SAFETY: FSEvents passes a NUL-terminated path valid for this call.
    let path = PathBuf::from(OsStr::from_bytes(
        unsafe { CStr::from_ptr(path) }.to_bytes(),
    ));
    agent.changed(path, flags);
}

extern "C" fn batch(last_event: u64) {
    if let Some(agent) = AGENT.get() {
        agent.batch(last_event);
    }
}

extern "C" fn permission(value: u8) {
    crate::PERMISSION.store(value, Ordering::SeqCst);
    if let (3, Some(agent)) = (value, AGENT.get()) {
        agent.monitor.retry_in(Duration::from_secs(1));
    }
}

extern "C" fn sleeping(asleep: bool) {
    if let Some(agent) = AGENT.get() {
        agent.monitor.sleep(asleep);
    }
}

extern "C" fn allowed(revision: u64) -> bool {
    AGENT.get().is_some_and(|agent| {
        agent.monitor.active()
            && agent.store.read().is_ok_and(|state| {
                state.monitoring
                    && !state.paused
                    && state
                        .items
                        .iter()
                        .any(|i| state.alerting(i, crate::now()) && i.revision <= revision)
            })
    })
}

extern "C" fn delivered(revision: u64, success: bool) {
    if let Some(agent) = AGENT.get() {
        agent.delivered(
            revision,
            success,
            crate::PERMISSION.load(Ordering::SeqCst) == 3,
        );
    }
}

extern "C" fn open_review() {
    unsafe { ch_open_app() }
}

/// Ask for a full pass. One that is under way is finished first and another
/// follows it: started over, it would lose what it has done, and changes lost
/// again and again would keep any pass from reaching its end.
fn ask_for_pass(full_pass: &mut Option<Option<scan::Pending>>, owed: &mut bool) {
    match full_pass {
        Some(Some(_)) => *owed = true,
        _ => *full_pass = Some(None),
    }
}

/// The place in the change history to save: no change after it is unchecked.
/// A change that is waiting its turn holds it at the place its batch followed,
/// so an agent started again is told of that change again.
fn handled(waiting: &BTreeMap<PathBuf, u64>, event: u64) -> u64 {
    waiting
        .values()
        .fold(event, |place, after| place.min(*after))
}

/// What a check of changes that was stopped leaves to do: the paths to check
/// again as they were, and whether a full pass has to make up for the rest.
/// `asked` is when each path last asked for a pass.
fn unfinished(
    left: scan::Unreached,
    cancelled: bool,
    batch: usize,
    asked: &mut HashMap<PathBuf, Instant>,
    now: Instant,
) -> (BTreeSet<PathBuf>, bool) {
    if cancelled {
        // Sleep, a pause or a changed setting stopped the check. Whatever
        // each path was left at, checked again it may be finished.
        let all = [left.cancelled, left.out_of_budget, left.cut_short];
        return (all.into_iter().flatten().collect(), false);
    }
    // A path the check's own limits cut short would be cut at the same place
    // again. A full pass reads on from where a slice stops. But not a pass
    // for every change of one path: a file holding more findings than one
    // scan keeps is cut at the same place by every check, and by the pass.
    let mut pass = false;
    for path in left.cut_short {
        let lately = |at: &Instant| now.saturating_duration_since(*at) < PASS_AGAIN;
        if !asked.get(&path).is_some_and(lately) {
            asked.insert(path, now);
            pass = true;
        }
    }
    if asked.len() > INBOX_MAX {
        asked.clear();
    }
    // Never the whole batch again: a check that begins nothing would go
    // round for ever.
    let none_begun = !left.out_of_budget.is_empty() && left.out_of_budget.len() >= batch;
    if pass || none_begun {
        return (BTreeSet::new(), true);
    }
    // Not begun, because the paths before them used up the check: with a
    // check to themselves they may well be finished.
    (left.out_of_budget.into_iter().collect(), false)
}

/// How long a full pass waits to make a slice again after its save failed,
/// by how many saves have failed in a row: the rest between slices, doubling
/// up to the tick, so a store that stays unwritable costs a slice a quarter
/// of an hour and not one after another.
fn unsaved_wait(pause: Duration, failed: u32) -> Duration {
    (pause * 2u32.pow(failed.saturating_sub(1).min(5))).min(CADENCE)
}

/// How long a notification handed to macOS holds off the next, if its
/// completion never comes back.
const DELIVERY_WAIT: Duration = Duration::from_secs(120);

/// Whether a notification handed to macOS at `began` is still waiting for
/// its completion.
fn delivery_under_way(began: Option<Instant>, now: Instant) -> bool {
    began.is_some_and(|at| now.saturating_duration_since(at) < DELIVERY_WAIT)
}

/// When to wake for a notification that may be tried again at `at`, in
/// seconds since 1970: in a minute at the soonest, and never for a time the
/// clock cannot hold.
fn notify_wake(at: u64) -> Option<Instant> {
    Instant::now().checked_add(Duration::from_secs(at.saturating_sub(crate::now()).max(60)))
}

/// How many folders a full pass has left, for the window. Each may hold
/// folders not listed yet, so it is the least there can be.
fn folders_left(pending: &scan::Pending) -> usize {
    let folders = pending
        .iter()
        .filter(|step| !matches!(step, scan::Step::Known(_)));
    // The known locations are not a folder. None left means the pass is over.
    folders.count().max(usize::from(!pending.is_empty()))
}

/// The worker's loop. `run` gives it one thread at the lowest scheduling and
/// disk priority.
fn work(agent: &'static Agent, mut full_pass: Option<Option<scan::Pending>>) {
    // When each path was last checked and how often lately, and the paths that
    // changed again too soon to be checked yet, each with the place in the
    // change history that its change came after.
    let mut checked: HashMap<PathBuf, (Instant, u32)> = HashMap::new();
    let mut waiting: BTreeMap<PathBuf, u64> = BTreeMap::new();
    // The place up to which changes have been taken from the inbox.
    let mut taken = agent.inbox.lock().unwrap().last_event;
    let due = |(last, checks): (Instant, u32)| {
        last + (agent.recheck_after * 2u32.pow(checks.saturating_sub(1).min(5))).min(CADENCE)
    };
    let mut next_slice = Instant::now();
    let mut stalled = 0;
    // A pass is owed once the one under way has ended.
    let mut owed = false;
    // When a path whose check was cut short last asked for a full pass.
    let mut asked: HashMap<PathBuf, Instant> = HashMap::new();
    // What the slices of the full pass under way list as not checked, for
    // every reason but "scan-limit": where one slice stops, the next goes on,
    // and a report cannot tell that from a limit no slice gets past.
    let mut unread = review::UnreadPlaces::default();
    // When the event stream was last opened again for dropped events.
    let mut resumes: Vec<Instant> = Vec::new();
    // The paths the last check left to check again, by their place in it.
    let mut carried: HashMap<PathBuf, usize> = HashMap::new();
    while let Some(tick) = agent.monitor.wait() {
        if !agent.monitor.arm(ScanKind::Automatic) {
            continue;
        }
        // Copied, not taken: until the stream is open again, events still
        // coming must not move the place past those that were dropped. And
        // not under the lock, which the stream's callbacks wait for.
        let (resume, drops) = {
            let inbox = agent.inbox.lock().unwrap();
            (inbox.resume, inbox.drops)
        };
        if let Some(since) = resume {
            resumes.retain(|at| at.elapsed() < RESUME_WINDOW);
            if resumes.len() < RESUMES_MAX {
                resumes.push(Instant::now());
                (agent.resume_watch)(since);
            } else {
                // Dropped again and again: a full pass makes up for them.
                ask_for_pass(&mut full_pass, &mut owed);
            }
            // A drop reported meanwhile, by either stream, is replayed by
            // opening it again on the next round.
            let mut inbox = agent.inbox.lock().unwrap();
            if inbox.drops == drops {
                inbox.resume = None;
            }
        }
        let (paths, restart, event) = {
            let mut inbox = agent.inbox.lock().unwrap();
            (
                std::mem::take(&mut inbox.paths),
                std::mem::take(&mut inbox.full_pass),
                inbox.last_event,
            )
        };
        if tick {
            checked.retain(|_, (last, _)| last.elapsed() < CADENCE);
            let ticket = agent.ticket();
            // What is to be notified can change by the clock alone, as when
            // a set-aside reason ends, with nothing read or written to say
            // so. What is known is from before; this is as it is now. A
            // state that cannot be read says nothing of when the last pass
            // was, so it starts none.
            if let Ok(state) = agent.store.read() {
                agent.remember(&state, ticket);
                if full_pass.is_none() && pass_due(state.agent.baseline_at, crate::now()) {
                    full_pass = Some(None);
                }
            }
        }
        if restart {
            ask_for_pass(&mut full_pass, &mut owed);
        }
        let now = Instant::now();
        // A change in this batch came after everything taken before it.
        let mut held = std::mem::take(&mut waiting);
        for p in paths {
            held.entry(p).or_insert(taken);
        }
        taken = event;
        // For each path whose turn it is: the place its change came after,
        // and when it was last checked, should this check not finish it.
        let mut ready = Vec::new();
        let mut turn = HashMap::new();
        for (p, after) in held {
            if checked.get(&p).is_some_and(|c| now < due(*c)) {
                waiting.insert(p, after);
            } else {
                turn.insert(p.clone(), (after, checked.get(&p).copied()));
                ready.push(p);
            }
        }
        // The paths the last check left unfinished go first, in the order
        // they had in it. By name among the paths that changed since, paths
        // that keep changing could keep one from ever being the first a check
        // begins, and so from the full pass that finishes it.
        ready.sort_by_key(|p| carried.get(p).copied().unwrap_or(usize::MAX));
        // A path whose wait is over says only how often it changed lately.
        // Forgetting it loses no change: it is checked at once if it changes
        // again. So only the paths still waiting their turn count here.
        if checked.len() > 4 * INBOX_MAX {
            checked.retain(|_, c| now < due(*c));
        }
        if waiting.len() > INBOX_MAX || checked.len() > 4 * INBOX_MAX {
            waiting.clear();
            checked.clear();
            ask_for_pass(&mut full_pass, &mut owed);
        }
        for p in &ready {
            let checks = checked.get(p).map_or(0, |c| c.1);
            checked.insert(p.clone(), (now, checks + 1));
        }

        let cancel = agent.monitor.cancel.clone();
        // Copied out first: a lock held across a scan would block the agent
        // against itself.
        let skip = agent.known.lock().unwrap().skip.clone();
        if !ready.is_empty() {
            let (key, digest) = agent.fingerprint();
            let (report, left) = Scan::changed(
                &agent.home,
                &skip,
                &ready,
                agent.changes,
                cancel.clone(),
                digest,
            );
            let cancelled = cancel.load(Ordering::SeqCst);
            let (again, pass) = unfinished(left, cancelled, ready.len(), &mut asked, now);
            carried = ready
                .iter()
                .filter(|p| again.contains(*p))
                .cloned()
                .zip(0..)
                .collect();
            if pass {
                ask_for_pass(&mut full_pass, &mut owed);
            }
            // A path to check again waits as if this check had not been made:
            // its turn is the next round, and its change is not yet handled.
            let mut back = 0;
            for p in &again {
                if let Some((after, last)) = turn.get(p) {
                    match last {
                        Some(last) => checked.insert(p.clone(), *last),
                        None => checked.remove(p),
                    };
                    waiting.insert(p.clone(), *after);
                    back += 1;
                }
            }
            let done = (ready.len() - back) as u64;
            if agent.concerns_review(&report, &ready) {
                // A full pass stands for changes that were lost, so the place
                // stays where it was until that pass has ended.
                let place = (full_pass.is_none() && !owed).then(|| handled(&waiting, event));
                if !agent.record(&report, &key, Some(&ready), place, |h| h.changes += done) {
                    // Not saved: every path of the batch waits to be checked
                    // again, its change not yet handled, so no later save
                    // puts the place past it. This check counts as one made,
                    // so the next is after the wait that doubles.
                    for p in &ready {
                        if let Some((after, _)) = turn.get(p) {
                            waiting.entry(p.clone()).or_insert(*after);
                        }
                    }
                }
            }
        }
        if let Some(resume) = full_pass.take() {
            // Wait out low power mode and the pause between slices.
            if (agent.low_power)() {
                full_pass = Some(resume);
                next_slice = Instant::now() + agent.low_power_pause;
            } else if Instant::now() < next_slice {
                full_pass = Some(resume);
            } else {
                // A pass begins with nothing counted against it: one given
                // up before must not give up this one at its first cancel.
                if resume.is_none() {
                    unread = review::UnreadPlaces::default();
                    stalled = 0;
                }
                let before = resume.clone();
                let (key, digest) = agent.fingerprint();
                let (report, pending) = Scan::sweep(
                    &agent.home,
                    &skip,
                    resume,
                    agent.slice,
                    cancel.clone(),
                    digest,
                );
                unread.record(&report);
                let done = pending.is_empty();
                let nothing: &[PathBuf] = &[];
                let place = (done && !owed).then(|| handled(&waiting, event));
                let not_read = unread.places.len();
                let saved = agent.record(&report, &key, (!done).then_some(nothing), place, |h| {
                    // A pass owed after this one has every folder left: at
                    // least one, so that a restart still makes it.
                    h.left = folders_left(&pending).max(usize::from(owed));
                    if done {
                        h.baseline = Some(report.generated_at.clone());
                        h.baseline_at = crate::now();
                        h.unread = not_read;
                        h.unread_places = Some(unread.clone());
                    }
                });
                // A pass that three slices in a row leave as they found it is
                // given up, not retried forever. A first pass, or one a week
                // overdue, is begun again at the next quarter-hourly check.
                // The list says how far a folder of records was read, so a
                // large one is not taken for a slice that did nothing. Nor is
                // a slice that a cancel cut short: sleep, a pause or a
                // changed setting says nothing about the pass.
                if saved && !cancel.load(Ordering::SeqCst) {
                    stalled = if before.as_ref() == Some(&pending) {
                        stalled + 1
                    } else {
                        0
                    };
                }
                if !saved {
                    // Not saved: the pass has not got past this slice, nor
                    // ended with it. The slice is made again from where it
                    // began, after a wait that grows, and says nothing about
                    // whether the pass is getting anywhere.
                    let failed = agent.unsaved.load(Ordering::SeqCst);
                    full_pass = Some(before);
                    next_slice = Instant::now() + unsaved_wait(agent.slice_pause, failed);
                } else if !done && stalled < 3 {
                    full_pass = Some(Some(pending));
                    next_slice = Instant::now() + agent.slice_pause;
                } else if std::mem::take(&mut owed) {
                    full_pass = Some(None);
                    next_slice = Instant::now() + agent.slice_pause;
                }
            }
        } else if tick
            && handled(&waiting, event) != 0
            && handled(&waiting, event) != agent.known.lock().unwrap().saved_event
        {
            // Keep the place in the change history, so a restart replays
            // little. Never 0: saved, it would start the next stream from now.
            let place = handled(&waiting, event);
            let saved = agent.store.update(|state| {
                state.agent.event_id = place;
                Ok(agent.ticket())
            });
            if let Ok((state, ticket)) = saved {
                agent.remember(&state, ticket);
            }
        }
        agent.deliver();
        // Wake for whichever comes first: new changes, a path whose wait is
        // over, or the next slice.
        let allowed = crate::PERMISSION.load(Ordering::SeqCst) == 3;
        let notify = agent.known.lock().unwrap().retry_at.filter(|_| allowed);
        // A path put back with no check behind it is due at once.
        let wake = waiting
            .keys()
            .map(|p| checked.get(p).map_or_else(Instant::now, |c| due(*c)))
            .chain(full_pass.is_some().then_some(next_slice))
            .chain(notify.and_then(notify_wake))
            .min();
        if !agent.inbox.lock().unwrap().paths.is_empty() {
            agent.monitor.retry_in(Duration::ZERO);
        } else if let Some(at) = wake {
            agent
                .monitor
                .retry_in(at.saturating_duration_since(Instant::now()));
        }
    }
}

/// Run as the agent. Exits with success on anything that a restart would not
/// fix, so launchd does not start it again in a loop, and with failure on
/// what one may, such as a home folder not mounted yet: launchd then starts
/// it again, a minute later at the soonest (`ThrottleInterval`).
pub fn run() -> ! {
    fn stop(reason: &str) -> ! {
        eprintln!("loose-keys agent: {reason}");
        std::process::exit(0)
    }
    fn fail(reason: &str) -> ! {
        eprintln!("loose-keys agent: {reason}");
        std::process::exit(1)
    }
    // A panic on any thread ends the agent, so launchd starts it again. A
    // worker that died behind a live process would check nothing and look
    // like monitoring.
    let report = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
        report(panic);
        std::process::abort()
    }));
    if scan::is_root() {
        stop("not available as root");
    }
    let home = scan::home().unwrap_or_else(|e| stop(e));
    let store = Store::open(&home).unwrap_or_else(|e| fail(&e));
    let path = CString::new(home.as_os_str().as_bytes()).unwrap_or_else(|_| stop("bad home"));
    let mut volume = [0 as c_char; 37];
    // SAFETY: a NUL-terminated path and a 37-byte buffer, as the bridge requires.
    let volume = if unsafe { ch_watch_volume(path.as_ptr(), volume.as_mut_ptr()) } {
        unsafe { CStr::from_ptr(volume.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    } else {
        String::new()
    };
    // Event numbers continue only within one volume's change history.
    let mut since = 0;
    let started = store.update(|state| {
        if !volume.is_empty() && state.agent.volume == volume {
            since = state.agent.event_id;
        }
        state.agent = review::Agent {
            pid: std::process::id(),
            started: Some(crate::report::utc_now()),
            volume: volume.clone(),
            event_id: since,
            changes: 0,
            error: None,
            ..state.agent.clone()
        };
        Ok(())
    });
    let (state, ()) = started.unwrap_or_else(|e| fail(&e));
    let full_pass = pass_at_start(&state.agent, since, crate::now()).then_some(None);
    let agent = AGENT.get_or_init(|| Agent {
        state_dir: home.join(review::STATE_DIR),
        home,
        store,
        monitor: Monitor::new(false, false),
        inbox: Mutex::new(Inbox {
            last_event: since,
            ..Inbox::default()
        }),
        delivering: Mutex::new(None),
        known: Mutex::new(Known::default()),
        recheck_after: RECHECK_AFTER,
        slice: SLICE,
        slice_pause: SLICE_PAUSE,
        rechecks: RECHECKS,
        changes: CHANGES,
        // SAFETY: reads one process-wide setting; no preconditions.
        low_power: || unsafe { ch_low_power() },
        low_power_pause: LOW_POWER_PAUSE,
        resume_watch: |since| {
            // SAFETY: takes a number and borrows nothing. The worker calls it,
            // never the stream's own queue, which it waits for.
            if !unsafe { ch_watch_resume(since) } {
                // Exits with failure, unlike `stop`, so launchd starts the
                // agent again, and it replays from its saved place.
                eprintln!("loose-keys agent: could not watch the home folder again");
                std::process::exit(1)
            }
        },
        // SAFETY: takes nothing; the answer comes back through `permission`.
        refresh: || unsafe { crate::ch_notifications_refresh() },
        asked: Mutex::new(None),
        unsaved: AtomicU32::new(0),
    });
    agent.remember(&state, agent.ticket());
    // SAFETY: the callbacks are plain functions that live for the whole process.
    unsafe {
        crate::ch_notifications_init(open_review, permission);
        crate::ch_background_init(sleeping, delivered, allowed);
        if !ch_watch_start(path.as_ptr(), since, LATENCY, changed, batch) {
            let _ = agent.store.update(|state| {
                state.agent.error = Some("Could not watch the home folder for changes.".into());
                Ok(())
            });
            fail("could not watch the home folder");
        }
    }
    std::thread::Builder::new()
        .name("credential-agent".into())
        .spawn(move || {
            // SAFETY: sets this thread's own quality of service; no preconditions.
            unsafe {
                libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_BACKGROUND, 0);
            }
            work(agent, full_pass)
        })
        .unwrap_or_else(|_| fail("could not start the worker"));
    // SAFETY: runs the main run loop; called once, on the main thread.
    unsafe { ch_agent_run() };
    // It is not meant to return. Exiting with success would leave launchd
    // to start nothing, while the window showed checks as on.
    fail("the run loop ended")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};

    /// The worker running on a synthetic home folder, fed changes the way the
    /// file-event callbacks feed them. No event stream, window or notification,
    /// and at ordinary priority: at the agent's own, a busy Mac can hold a
    /// worker back for longer than a test should wait.
    struct Fixture {
        home: PathBuf,
        agent: &'static Agent,
        /// A second handle on the shared state, as the app holds one.
        app: Store,
        worker: std::thread::JoinHandle<()>,
        event: u64,
    }

    impl Fixture {
        fn start(name: &str, files: &[&str], setup: impl FnOnce(&mut Review)) -> Self {
            Self::tuned(name, files, setup, |_| {})
        }

        /// As `start`, with the agent's own limits changed for the test.
        fn tuned(
            name: &str,
            files: &[&str],
            setup: impl FnOnce(&mut Review),
            tune: impl FnOnce(&mut Agent),
        ) -> Self {
            let home = std::env::temp_dir().join(format!(
                "credential-agent-test-{}-{name}",
                std::process::id()
            ));
            std::fs::create_dir(&home).unwrap();
            for file in files {
                export(&home, file);
            }
            let store = Store::open(&home).unwrap();
            let saved = store.update(|state| {
                state.monitoring = true;
                setup(state);
                Ok(())
            });
            let mut agent = Agent {
                state_dir: home.join(review::STATE_DIR),
                home: home.clone(),
                store,
                monitor: Monitor::new(false, false),
                inbox: Mutex::default(),
                delivering: Mutex::new(None),
                known: Mutex::default(),
                recheck_after: Duration::from_secs(2),
                slice: SLICE,
                slice_pause: SLICE_PAUSE,
                rechecks: RECHECKS,
                changes: CHANGES,
                low_power: || false,
                low_power_pause: LOW_POWER_PAUSE,
                resume_watch: |_| {},
                refresh: || {},
                asked: Mutex::new(None),
                unsaved: AtomicU32::new(0),
            };
            tune(&mut agent);
            let agent: &'static Agent = Box::leak(Box::new(agent));
            agent.remember(&saved.unwrap().0, agent.ticket());
            Self {
                app: Store::open(&home).unwrap(),
                // As on a first run: the whole home is still to be walked.
                worker: std::thread::spawn(move || work(agent, Some(None))),
                home,
                agent,
                event: 0,
            }
        }

        /// One batch of file-change events.
        fn changes(&mut self, paths: &[&str]) {
            for path in paths {
                self.agent.changed(self.home.join(path), 0);
            }
            self.event += 1;
            self.agent.batch(self.event);
        }

        /// The app changes the shared state, and the agent is told the state
        /// file changed, which is the only way it learns of it.
        fn app_sets(&mut self, change: impl FnOnce(&mut Review)) {
            let saved = self.app.update(|state| {
                change(state);
                Ok(())
            });
            saved.unwrap();
            self.changes(&[&format!("{}/state.json", review::STATE_DIR)]);
        }

        /// The shared state once `done` holds. A worker that has stopped
        /// fails the test here instead of hanging it.
        fn wait(&self, what: &str, done: impl Fn(&Review) -> bool) -> Review {
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                let state = self.app.read().unwrap();
                if done(&state) {
                    return state;
                }
                assert!(Instant::now() < deadline, "the agent never got to: {what}");
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn first_pass(&self) -> Review {
            self.wait("the first full pass", |s| s.agent.baseline.is_some())
        }

        /// Wait for something that is not in the shared state, as `wait`
        /// waits for what is.
        fn until(&self, what: &str, done: impl Fn() -> bool) {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !done() {
                assert!(Instant::now() < deadline, "the agent never got to: {what}");
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        /// The quarter-hourly check, now: nothing changed and nobody asked.
        fn tick(&self) {
            self.agent.monitor.configure(true, false);
        }

        /// The state folder can or cannot be written to. A save into one
        /// that cannot fails, and reading it goes on.
        fn storage(&self, writable: bool) {
            use std::os::unix::fs::PermissionsExt;
            let mode = if writable { 0o700 } else { 0o500 };
            let permissions = std::fs::Permissions::from_mode(mode);
            std::fs::set_permissions(&self.agent.state_dir, permissions).unwrap();
        }

        fn unsaved(&self) -> u32 {
            self.agent.unsaved.load(Ordering::SeqCst)
        }

        /// Changes were lost, as FSEvents says when it dropped some: the
        /// home folder has to be walked again.
        fn changes_lost(&mut self) {
            self.agent.changed(self.home.clone(), MUST_RESCAN);
            self.event += 1;
            self.agent.batch(self.event);
        }

        /// This process fell behind and FSEvents dropped events for it, as
        /// it says while a build deletes thousands of files.
        fn dropped(&mut self) {
            self.agent.changed(self.home.clone(), 0x1 | USER_DROPPED);
            self.event += 1;
            self.agent.batch(self.event);
        }

        fn stop(self) {
            self.agent.monitor.stop();
            self.worker.join().unwrap();
            std::fs::remove_dir_all(self.home).unwrap();
        }
    }

    /// A synthetic password export, which the scanner reports for review.
    fn export(home: &Path, file: &str) {
        let path = home.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let text = format!("url,username,password\nhttps://fixture.invalid,{file},synthetic\n");
        std::fs::write(path, text).unwrap();
    }

    /// Where the unresolved items are.
    fn open(state: &Review) -> Vec<&str> {
        let mut paths: Vec<&str> = state
            .items
            .iter()
            .filter(|i| !i.resolved)
            .map(|i| i.path.as_str())
            .collect();
        paths.sort();
        paths
    }

    #[test]
    fn an_item_with_an_accented_name_is_fixed_once_its_file_is_gone() {
        let file = "Documents/contrase\u{f1}as.csv";
        let mut f = Fixture::start("accented", &[file], |_| {});
        assert_eq!(open(&f.first_pass()).len(), 1);
        std::fs::remove_file(f.home.join(file)).unwrap();
        f.changes(&[file]);
        f.wait("the item for the deleted file to be fixed", |s| {
            open(s).is_empty()
        });
        f.stop();
    }

    /// A sign-in file a command-line tool keeps, which a scan lists as
    /// stored while only its owner can read it.
    const HUB: &str = ".config/hub";

    fn sign_in(home: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let path = home.join(HUB);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "access_token: synthetic-only-value-1234\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// Whether the stored sign-in is listed, and whether it is still found.
    fn stored(state: &Review) -> Option<bool> {
        let hub = format!("~/{HUB}");
        let item = state.stored.items.iter().find(|i| i.path == hub)?;
        Some(!item.resolved)
    }

    /// A batch that changed only a stored sign-in was not saved: only
    /// findings worth reviewing, and their files, needed the store.
    #[test]
    fn a_batch_with_only_a_stored_sign_in_is_saved() {
        let mut f = Fixture::start("stored-batch", &[], |_| {});
        let state = f.first_pass();
        // The pass that ended looked for every stored sign-in.
        assert!(state.stored.checked_at.is_some());
        sign_in(&f.home);
        f.changes(&[HUB]);
        let state = f.wait("the stored sign-in to be saved", |s| {
            stored(s) == Some(true)
        });
        assert!(state.items.is_empty());
        f.stop();
    }

    #[test]
    fn a_stored_sign_in_found_in_the_background_never_notifies() {
        static ASKED: AtomicUsize = AtomicUsize::new(0);
        let mut f = Fixture::tuned(
            "stored-quiet",
            &[],
            |_| {},
            |agent| {
                agent.refresh = || {
                    ASKED.fetch_add(1, Ordering::SeqCst);
                }
            },
        );
        f.first_pass();
        sign_in(&f.home);
        f.changes(&[HUB]);
        let state = f.wait("the stored sign-in to be saved", |s| {
            stored(s) == Some(true)
        });
        assert!(!f.agent.known.lock().unwrap().unnotified);
        // Nothing to send, so macOS is not even asked whether it may be.
        f.agent.deliver();
        assert_eq!(ASKED.load(Ordering::SeqCst), 0);
        assert_eq!(
            (state.revision, state.notified_revision, state.attempts),
            (0, 0, 0)
        );
        assert!(!state.pending(crate::now()));
        f.stop();
    }

    #[test]
    fn removing_a_sign_in_file_marks_it_gone() {
        let mut f = Fixture::start("stored-removed", &[], |_| {});
        f.first_pass();
        sign_in(&f.home);
        f.changes(&[HUB]);
        f.wait("the stored sign-in to be saved", |s| {
            stored(s) == Some(true)
        });
        std::fs::remove_file(f.home.join(HUB)).unwrap();
        f.changes(&[HUB]);
        f.wait("the removed sign-in to be no longer found", |s| {
            stored(s) == Some(false)
        });
        f.stop();
    }

    /// Two tokens of one type in one file are two items, and which of them
    /// is gone is asked of the file as it is when the check is saved.
    #[test]
    fn a_value_taken_out_of_a_file_is_fixed_and_the_one_beside_it_is_not() {
        let token = |last: char| format!("gh{}_0123456789abcdefghijABCDEFGHIJ01234{last}", "p");
        let (one, two) = (token('A'), token('B'));
        let mut f = Fixture::start("two-values", &[], |_| {});
        f.first_pass();
        let notes = f.home.join("notes.txt");
        std::fs::write(&notes, format!("{one} {two}\n")).unwrap();
        f.changes(&["notes.txt"]);
        let both = f.wait("both tokens to be listed", |s| open(s).len() == 2);
        let secret = |n: usize| both.items[n].secret.clone();
        assert_ne!(secret(0), secret(1));
        std::fs::write(&notes, format!("{two}\n")).unwrap();
        f.changes(&["notes.txt"]);
        let left = f.wait("the token taken out to be fixed", |s| open(s).len() == 1);
        let gone: Vec<_> = left.items.iter().filter(|i| i.resolved).collect();
        assert_eq!((gone.len(), gone[0].line), (1, Some(1)));
        // The one still there is the second on its old line, known by its value.
        let there = left.items.iter().find(|i| !i.resolved).unwrap();
        assert_eq!(there.secret, secret(1));
        assert_ne!(gone[0].secret, there.secret);
        // It is then replaced. The new value takes the item of one that is
        // gone from this place, as news: nothing more is listed or open.
        std::fs::write(&notes, format!("{}\n", token('C'))).unwrap();
        f.changes(&["notes.txt"]);
        let known = [secret(0), secret(1)];
        let replaced = f.wait("the new value to be listed", |s| {
            s.items
                .iter()
                .any(|i| !i.resolved && !known.contains(&i.secret))
        });
        assert_eq!((replaced.items.len(), open(&replaced).len()), (2, 1));
        let new = replaced.items.iter().find(|i| !i.resolved).unwrap();
        assert!(new.revision > left.revision);
        f.stop();
    }

    /// A list replaced while a check ran, as when its file is deleted or put
    /// back from a copy, has another key. What the check found was digested
    /// with the old one, and saved into the new list it was taken for
    /// another value: the next check marked it fixed and listed it as news.
    #[test]
    fn a_check_made_with_the_key_of_a_list_since_replaced_is_made_again() {
        let token = format!("gh{}_0123456789abcdefghijABCDEFGHIJ01234A", "p");
        let mut f = Fixture::start("replaced-list", &[], |_| {});
        f.first_pass();
        // Replaced unseen: the agent is not told, so it checks with the old key.
        f.app
            .update(|state| {
                *state = Review {
                    monitoring: true,
                    key: vec![9; 32],
                    agent: state.agent.clone(),
                    ..Review::default()
                };
                Ok(())
            })
            .unwrap();
        std::fs::write(f.home.join("notes.txt"), format!("{token}\n")).unwrap();
        f.changes(&["notes.txt"]);
        let listed = f.wait("the token to be listed", |s| open(s) == ["~/notes.txt"]);
        let checks = listed.agent.changes;
        f.changes(&["notes.txt"]);
        let again = f.wait("the file to be checked again", |s| s.agent.changes > checks);
        assert_eq!(again.items.len(), 1);
        assert!(!again.items[0].resolved, "marked fixed");
        assert_eq!(
            again.items[0].revision, listed.items[0].revision,
            "listed as news"
        );
        f.stop();
    }

    /// One read of a file keeps only so many tokens. A token listed before,
    /// and now after that many of another type, is not among them, and was
    /// marked fixed: the read found nothing of its type.
    #[test]
    fn a_value_past_the_tokens_one_read_keeps_is_not_fixed() {
        let old = format!("gh{}_0123456789abcdefghijABCDEFGHIJ01234A", "p");
        let other = |n: usize| format!("h{}_abcdefghijABCDEFGHIJabcdefghijA{n:03}\n", "f");
        let mut f = Fixture::tuned(
            "past-the-cap",
            &[],
            |_| {},
            |agent| agent.recheck_after = Duration::from_millis(50),
        );
        f.first_pass();
        let notes = f.home.join("notes.txt");
        std::fs::write(&notes, &old).unwrap();
        f.changes(&["notes.txt"]);
        let listed = f.wait("the token to be listed", |s| s.items.len() == 1);
        let id = listed.items[0].id;
        // A hundred of another type are put before it, as many as one read
        // keeps: they are listed, and it is not found again.
        let others: String = (0..100).map(other).collect();
        std::fs::write(&notes, format!("{others}{old}\n")).unwrap();
        f.changes(&["notes.txt"]);
        let state = f.wait("the other tokens to be listed", |s| s.items.len() > 1);
        assert_eq!(state.items.len(), 101);
        let first = state.items.iter().find(|i| i.id == id).unwrap();
        assert!(!first.resolved, "fixed while it is still in the file");
        // With the file gone, a read holds nothing and can tell.
        std::fs::remove_file(&notes).unwrap();
        f.changes(&["notes.txt"]);
        f.wait("every token to be fixed", |s| open(s).is_empty());
        f.stop();
    }

    /// A pass that ended while the clock was ahead is stamped in the future.
    /// Counted from that stamp, the weekly pass did not come round again
    /// until the clock was a week past it, and nothing said so.
    #[test]
    fn a_pass_stamped_in_the_future_does_not_hold_off_the_next() {
        let mut f = Fixture::start("future-pass", &["export.csv"], |_| {});
        f.first_pass();
        let ahead = crate::now() + 365 * 24 * 3600;
        f.app_sets(|state| state.agent.baseline_at = ahead);
        f.tick();
        f.wait("a full pass after one stamped a year ahead", |s| {
            s.agent.baseline_at < ahead
        });
        f.stop();
    }

    /// A state that could not be read at the quarter-hourly check was taken
    /// for one with no pass ever made, and a full pass was begun at every
    /// check while the read kept failing.
    #[test]
    fn a_state_that_cannot_be_read_at_a_check_begins_no_full_pass() {
        static PASSES: AtomicUsize = AtomicUsize::new(0);
        // Asked before each slice of a full pass, and only then.
        fn counted() -> bool {
            PASSES.fetch_add(1, Ordering::SeqCst);
            false
        }
        let f = Fixture::tuned(
            "unreadable-tick",
            &[],
            |_| {},
            |agent| agent.low_power = counted,
        );
        f.first_pass();
        let before = PASSES.load(Ordering::SeqCst);
        let file = f.agent.state_dir.join("state.json");
        std::fs::write(&file, "damaged synthetic state").unwrap();
        assert!(f.app.read().is_err());
        f.tick();
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            PASSES.load(Ordering::SeqCst),
            before,
            "a failed read began a full pass"
        );
        f.stop();
    }

    #[test]
    fn a_full_pass_says_how_many_places_it_did_not_read() {
        use std::os::unix::fs::PermissionsExt;
        let locked = "d5/export-3.csv";
        let pieces = ["fixture-private-", "unread-material"];
        let planted = pieces.concat();
        let mode = |home: &Path, mode| {
            let permissions = std::fs::Permissions::from_mode(mode);
            std::fs::set_permissions(home.join(locked), permissions).unwrap();
        };
        let files: Vec<String> = (0..12)
            .flat_map(|d| (0..10).map(move |n| format!("d{d}/export-{n}.csv")))
            .collect();
        let files: Vec<&str> = files.iter().map(String::as_str).collect();
        // A pass of several slices, each stopped by its entry budget: where
        // a slice stops is in its report too, and is not a place left unread.
        let mut f = Fixture::tuned(
            "unread",
            &files,
            |_| {},
            |agent| {
                agent.slice.entries = 25;
                agent.slice_pause = Duration::from_millis(20);
                std::fs::write(
                    agent.home.join(locked),
                    format!("url,username,password\nhttps://fixture.invalid,fixture,{planted}\n"),
                )
                .unwrap();
                mode(&agent.home, 0o000);
            },
        );
        // The file the helper may not open is no finding, and is not silence.
        let state = f.first_pass();
        assert_eq!(state.agent.unread, 1);
        let saved = serde_json::to_value(&state.agent).unwrap();
        assert_eq!(
            saved["unread_places"]["places"],
            serde_json::json!([["~/d5/export-3.csv", "permission-denied"]])
        );
        assert_eq!(saved["unread_places"]["truncated"], false);
        for output in [
            serde_json::to_string(&state).unwrap(),
            serde_json::to_string(&crate::automatic_coverage(&state.agent)).unwrap(),
        ] {
            for piece in pieces
                .iter()
                .copied()
                .chain(std::iter::once(planted.as_str()))
            {
                assert!(!output.contains(piece));
            }
        }
        assert_eq!(state.items.len(), files.len() - 1);
        // The count is of the last pass, not of every pass so far.
        mode(&f.home, 0o600);
        f.changes_lost();
        f.wait("a pass that read everything", |s| s.agent.unread == 0);
        let state = f.app.read().unwrap();
        assert!(state
            .agent
            .unread_places
            .as_ref()
            .unwrap()
            .places
            .is_empty());
        f.stop();
    }

    /// A full pass in slices read no listed item's file again until its
    /// last slice. A value replaced with no change delivered was then found
    /// by a slice that could not ask whether the old one was gone, so both
    /// were listed as open. The last slice, whose report has nothing at that
    /// file, let the old one be, and so did every pass after it.
    #[test]
    fn a_value_replaced_unseen_is_one_item_after_a_full_pass_in_slices() {
        let token = |last: char| format!("gh{}_0123456789abcdefghijABCDEFGHIJ01234{last}", "p");
        let files: Vec<String> = (0..12)
            .flat_map(|d| (0..10).map(move |n| format!("d{d}/export-{n}.csv")))
            .collect();
        let files: Vec<&str> = files.iter().map(String::as_str).collect();
        // A pass of several slices. The file is in the home folder itself,
        // which the first of them reads.
        let mut f = Fixture::tuned(
            "sliced-rotation",
            &files,
            |_| {},
            |agent| {
                agent.slice.entries = 25;
                agent.slice_pause = Duration::from_millis(20);
                std::fs::write(agent.home.join("a-notes.txt"), token('A')).unwrap();
            },
        );
        let tokens = |state: &Review| -> Vec<review::Item> {
            let tokens = state.items.iter();
            let tokens = tokens.filter(|i| i.rule == "secret.service-token");
            tokens.cloned().collect()
        };
        // A whole pass, asked for as lost changes ask for one. A file put
        // there first tells this pass from the one before: it is listed
        // only by this one, and no folder is left only once a pass is over.
        let pass = |f: &mut Fixture, marker: &str| -> Review {
            export(&f.home, marker);
            f.changes_lost();
            let marker = format!("~/{marker}");
            f.wait("another full pass", |s| {
                listed(s, &marker) && s.agent.left == 0
            })
        };
        let first = tokens(&f.first_pass());
        assert_eq!(first.len(), 1);
        let old = &first[0];

        // Replaced, and no change is delivered: only a pass finds it.
        let notes = f.home.join("a-notes.txt");
        std::fs::write(&notes, token('B')).unwrap();
        let replaced = tokens(&pass(&mut f, "pass-1.csv"));
        assert_eq!(
            replaced.len(),
            1,
            "a value changed in place is one item, not {:?}",
            replaced.iter().map(|i| i.resolved).collect::<Vec<_>>()
        );
        let new = &replaced[0];
        assert!(!new.resolved && new.secret != old.secret);
        assert_eq!(new.id, old.id);
        assert!(new.revision > old.revision);

        // The pass after that finds the file as it was left: the value in
        // it stays open, and the one that is gone does not come back.
        let again = tokens(&pass(&mut f, "pass-2.csv"));
        assert_eq!(again.len(), 1);
        assert!(!again[0].resolved);
        assert_eq!(
            (again[0].secret.clone(), again[0].revision),
            (new.secret.clone(), new.revision)
        );

        // Taken out for good, again with no change delivered.
        std::fs::remove_file(&notes).unwrap();
        let gone = tokens(&pass(&mut f, "pass-3.csv"));
        assert_eq!(gone.len(), 1);
        assert!(gone[0].resolved);
        f.stop();
    }

    #[test]
    fn the_first_run_walks_the_home_and_later_changes_are_checked_alone() {
        let mut f = Fixture::start("changes", &["Documents/old.csv"], |_| {});
        let state = f.first_pass();
        assert_eq!(open(&state), ["~/Documents/old.csv"]);
        assert_eq!((state.agent.left, state.agent.changes), (0, 0));

        // A new file, and a folder moved in with a file inside it.
        export(&f.home, "new.csv");
        export(&f.home, "Moved/inside.csv");
        f.changes(&["new.csv", "Moved"]);
        let state = f.wait("the changed paths", |s| s.items.len() == 3);
        assert_eq!(
            open(&state),
            ["~/Documents/old.csv", "~/Moved/inside.csv", "~/new.csv"]
        );
        assert_eq!(state.agent.changes, 2);

        // A deleted file is marked fixed, and its place in the change history
        // is saved with it.
        std::fs::remove_file(f.home.join("Documents/old.csv")).unwrap();
        f.changes(&["Documents/old.csv"]);
        let state = f.wait("the deleted file", |s| s.items.iter().any(|i| i.resolved));
        assert_eq!(open(&state), ["~/Moved/inside.csv", "~/new.csv"]);
        assert!(state.agent.event_id >= 1);
        f.stop();
    }

    /// The worker once held the lock on what it knows across a check that
    /// takes the same lock for the key. It stopped for good at its first
    /// check and reported nothing.
    #[test]
    fn the_worker_does_not_block_itself_on_what_it_knows() {
        let mut f = Fixture::start("lock", &["here.csv"], |_| {});
        assert_eq!(open(&f.first_pass()), ["~/here.csv"]);
        for (n, file) in ["one.csv", "two.csv", "three.csv"].iter().enumerate() {
            export(&f.home, file);
            f.changes(&[file]);
            f.wait("a changed file", |s| s.items.len() == n + 2);
        }
        f.stop();
    }

    /// A file that changes again straight after a check waits its turn, and
    /// the worker wakes itself for it. A wake asked for later, as a
    /// notification retry asks, once replaced the earlier one, and the file
    /// then waited for the next quarter-hourly check.
    #[test]
    fn a_file_that_changes_again_is_rechecked_whatever_else_asks_for_a_wake() {
        let mut f = Fixture::start("recheck", &[], |_| {});
        f.first_pass();
        export(&f.home, "busy.csv");
        f.changes(&["busy.csv"]);
        f.wait("the new file", |s| s.items.len() == 1);
        std::fs::remove_file(f.home.join("busy.csv")).unwrap();
        f.changes(&["busy.csv"]);
        // Long enough for the worker to have asked for its own wake first.
        std::thread::sleep(Duration::from_millis(300));
        f.agent.monitor.retry_in(Duration::from_secs(3600));
        f.wait("the second check", |s| s.items[0].resolved);
        f.stop();
    }

    #[test]
    fn power_sleep_holds_changes_and_wake_finishes_them() {
        let mut f = Fixture::tuned(
            "power-sleep",
            &["before-sleep.csv"],
            |_| {},
            |agent| agent.monitor.sleep(true),
        );
        export(&f.home, "during-sleep.csv");
        f.changes(&["during-sleep.csv"]);
        assert!(f.agent.monitor.cancel.load(Ordering::SeqCst));
        std::thread::sleep(Duration::from_millis(300));
        let held = f.app.read().unwrap();
        assert!(held.items.is_empty());
        assert!(held.agent.baseline.is_none());
        assert_eq!(held.agent.event_id, 0);

        f.agent.monitor.sleep(false);
        let state = f.wait("wake to finish the baseline and queued change", |s| {
            s.agent.baseline.is_some() && s.agent.event_id == f.event
        });
        assert_eq!(open(&state), ["~/before-sleep.csv", "~/during-sleep.csv"]);

        // Sleep again after a completed pass. Wake must also retain a
        // deletion, not just newly created findings or the first baseline.
        f.agent.monitor.sleep(true);
        std::fs::remove_file(f.home.join("before-sleep.csv")).unwrap();
        f.changes(&["before-sleep.csv"]);
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(open(&f.app.read().unwrap()), open(&state));
        assert_eq!(f.app.read().unwrap().agent.event_id, state.agent.event_id);
        f.agent.monitor.sleep(false);
        let state = f.wait("wake to resolve the queued deletion", |s| {
            s.agent.event_id == f.event
                && s.items
                    .iter()
                    .any(|i| i.path == "~/before-sleep.csv" && i.resolved)
        });
        assert_eq!(open(&state), ["~/during-sleep.csv"]);
        f.stop();
    }

    #[test]
    fn power_low_mode_checks_changes_and_resumes_the_held_pass() {
        static LOW: AtomicBool = AtomicBool::new(true);
        static ASKED: AtomicU32 = AtomicU32::new(0);
        fn low() -> bool {
            ASKED.fetch_add(1, Ordering::SeqCst);
            LOW.load(Ordering::SeqCst)
        }
        let mut f = Fixture::tuned(
            "power-low",
            &["only-in-full-pass.csv"],
            |_| {},
            |agent| {
                agent.low_power = low;
                agent.low_power_pause = Duration::from_millis(20);
            },
        );
        f.until("Low Power Mode to hold several full-pass attempts", || {
            ASKED.load(Ordering::SeqCst) >= 3
        });
        let held = f.app.read().unwrap();
        assert!(held.items.is_empty() && held.agent.baseline.is_none());

        export(&f.home, "changed-in-low-power.csv");
        f.changes(&["changed-in-low-power.csv"]);
        let state = f.wait("a changed file while the full pass is held", |s| {
            !s.items.is_empty()
        });
        assert_eq!(open(&state), ["~/changed-in-low-power.csv"]);
        assert!(state.agent.baseline.is_none());
        assert_eq!(
            state.agent.event_id, 0,
            "the held pass was acknowledged early"
        );

        // No file event or manual scan prompts this: the worker's own
        // retry must finish the retained pass once the setting is off.
        LOW.store(false, Ordering::SeqCst);
        let state = f.wait("the full pass after Low Power Mode ends", |s| {
            s.agent.baseline.is_some() && s.agent.event_id == f.event
        });
        assert_eq!(
            open(&state),
            ["~/changed-in-low-power.csv", "~/only-in-full-pass.csv"]
        );
        f.stop();
    }

    #[test]
    fn nothing_is_read_while_paused_and_a_held_change_is_checked_on_resume() {
        let mut f = Fixture::start("pause", &[], |_| {});
        let before = f.first_pass();
        f.app_sets(|state| state.paused = true);
        assert!(!f.agent.monitor.active());
        export(&f.home, "while-paused.csv");
        f.changes(&["while-paused.csv"]);
        std::thread::sleep(Duration::from_millis(300));
        let state = f.app.read().unwrap();
        assert!(state.items.is_empty());
        assert_eq!(state.agent.last_check, before.agent.last_check);

        f.app_sets(|state| state.paused = false);
        let state = f.wait("the held change", |s| s.items.len() == 1);
        assert_eq!(open(&state), ["~/while-paused.csv"]);
        f.stop();
    }

    #[test]
    fn nothing_is_read_while_monitoring_is_off_and_turning_it_on_walks_the_home() {
        let mut f = Fixture::start("off", &["already-here.csv"], |state| {
            state.monitoring = false;
        });
        export(&f.home, "arrived-while-off.csv");
        f.changes(&["arrived-while-off.csv"]);
        std::thread::sleep(Duration::from_millis(300));
        let state = f.app.read().unwrap();
        assert!(state.items.is_empty() && state.agent.last_check.is_none());

        f.app_sets(|state| state.monitoring = true);
        let state = f.first_pass();
        assert_eq!(
            open(&state),
            ["~/already-here.csv", "~/arrived-while-off.csv"]
        );
        f.stop();
    }

    #[test]
    fn a_skipped_folder_is_not_read_by_the_full_pass_or_when_it_changes() {
        let mut f = Fixture::start("skip", &["Private/kept.csv", "seen.csv"], |state| {
            state.skipped.push(review::Skip {
                path: "~/Private".into(),
                added: String::new(),
            });
        });
        assert_eq!(open(&f.first_pass()), ["~/seen.csv"]);
        export(&f.home, "Private/more.csv");
        export(&f.home, "also-seen.csv");
        f.changes(&["Private/more.csv", "Private", "also-seen.csv"]);
        let state = f.wait("the change outside the folder", |s| s.items.len() == 2);
        assert_eq!(open(&state), ["~/also-seen.csv", "~/seen.csv"]);
        f.stop();
    }

    #[test]
    fn more_changes_than_can_be_held_become_one_full_pass() {
        let mut f = Fixture::start("flood", &[], |_| {});
        f.first_pass();
        // Held while paused, so the worker takes none of them early.
        f.app_sets(|state| state.paused = true);
        export(&f.home, "not-among-the-events.csv");
        let flood: Vec<String> = (0..=INBOX_MAX).map(|n| format!("build/{n}.o")).collect();
        f.changes(&flood.iter().map(String::as_str).collect::<Vec<_>>());
        f.app_sets(|state| state.paused = false);
        let state = f.wait("the full pass", |s| s.items.len() == 1);
        assert_eq!(open(&state), ["~/not-among-the-events.csv"]);
        assert_eq!(state.agent.changes, 0);
        f.stop();
    }

    /// One file changed, once it is listed.
    fn change_listed(f: &mut Fixture, file: &str) -> Review {
        export(&f.home, file);
        f.changes(&[file]);
        let path = format!("~/{file}");
        f.wait(file, |s| listed(s, &path))
    }

    /// Whether `flood` started a full pass: it would list a file that no
    /// change names. Once a change made after the flood's own is listed, a
    /// pass the flood asked for has run.
    fn walked(f: &mut Fixture, flood: impl FnOnce(&mut Fixture)) -> bool {
        export(&f.home, "not-among-the-events.csv");
        flood(f);
        change_listed(f, "first.csv");
        let state = change_listed(f, "second.csv");
        open(&state).contains(&"~/not-among-the-events.csv")
    }

    /// A build writes thousands of files where scans do not read. Each was a
    /// change of its own, and more than could be held became a walk of the
    /// whole home, over and over while software was being built.
    #[test]
    fn a_flood_of_changes_where_scans_do_not_read_is_not_a_full_pass() {
        let mut f = Fixture::start("left-out-flood", &[], |_| {});
        f.first_pass();
        let walked = walked(&mut f, |f| {
            // Held while paused, so the worker takes none of them early.
            f.app_sets(|state| state.paused = true);
            let flood: Vec<String> = (0..=INBOX_MAX)
                .map(|n| format!("proj/target/debug/{n}.o"))
                .collect();
            f.changes(&flood.iter().map(String::as_str).collect::<Vec<_>>());
            f.app_sets(|state| state.paused = false);
        });
        assert!(!walked, "a flood of build output became a full pass");
        f.stop();
    }

    /// The same build in batches small enough to hold: every path it wrote
    /// was remembered as checked, and more than the worker keeps also became
    /// a walk of the whole home.
    #[test]
    fn many_batches_of_changes_where_scans_do_not_read_are_not_a_full_pass() {
        let mut f = Fixture::start("left-out-batches", &[], |_| {});
        f.first_pass();
        let walked = walked(&mut f, |f| {
            for round in 0..6 {
                let batch: Vec<String> = (0..INBOX_MAX - 500)
                    .map(|n| format!("proj/.git/objects/{round}/{n}"))
                    .collect();
                f.changes(&batch.iter().map(String::as_str).collect::<Vec<_>>());
                // Taken before the next batch: held together, they would be
                // the flood above.
                change_listed(f, &format!("round-{round}.csv"));
            }
        });
        assert!(!walked, "batches of repository changes became a full pass");
        f.stop();
    }

    /// Another project writing thousands of files, a few minutes on end:
    /// every path checked was remembered, to space out the checks of a file
    /// that keeps changing, and more than the worker keeps became a walk of
    /// the whole home, though each had been checked and none was lost.
    #[test]
    fn many_paths_checked_once_are_not_a_full_pass() {
        // Skipped, so each is remembered without anything read for it, and
        // checked again at once, so none is still waiting its turn.
        let mut f = Fixture::tuned(
            "checked-once",
            &[],
            |state| {
                state.skipped.push(review::Skip {
                    path: "~/Busy".into(),
                    added: String::new(),
                })
            },
            |agent| agent.recheck_after = Duration::ZERO,
        );
        f.first_pass();
        let walked = walked(&mut f, |f| {
            for round in 0..6 {
                let batch: Vec<String> = (0..INBOX_MAX - 500)
                    .map(|n| format!("Busy/{round}/{n}.json"))
                    .collect();
                f.changes(&batch.iter().map(String::as_str).collect::<Vec<_>>());
                change_listed(f, &format!("round-{round}.csv"));
            }
        });
        assert!(
            !walked,
            "paths that had all been checked became a full pass"
        );
        f.stop();
    }

    /// A repository's settings are read, though nothing else in `.git` is.
    #[test]
    fn a_password_added_to_a_repositorys_settings_is_found() {
        let mut f = Fixture::start("repo-config", &[], |_| {});
        f.first_pass();
        let config = f.home.join("proj/.git/config");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        let remote =
            "[remote \"origin\"]\n\turl = https://fixture:synthetic-only@git.example.invalid/r\n";
        std::fs::write(&config, remote).unwrap();
        f.changes(&["proj/.git/objects/ab/cdef", "proj/.git/config"]);
        let state = f.wait("the repository's settings", |s| s.items.len() == 1);
        assert_eq!(open(&state), ["~/proj/.git/config"]);
        f.stop();
    }

    /// A build that deleted thousands of files at once outran the helper,
    /// FSEvents dropped events for it, and it walked the whole home. The
    /// change history still holds them: the stream is opened again from the
    /// last batch handled before the drop, and they are replayed.
    #[test]
    fn events_dropped_for_falling_behind_are_read_again_not_walked() {
        static FROM: AtomicU64 = AtomicU64::new(0);
        let mut f = Fixture::tuned(
            "dropped",
            &[],
            |_| {},
            |agent| agent.resume_watch = |since| FROM.store(since, Ordering::SeqCst),
        );
        f.first_pass();
        let walked = walked(&mut f, |f| {
            f.changes(&["before.csv"]);
            let before = f.event;
            f.dropped();
            f.until("the stream to be opened again", || {
                FROM.load(Ordering::SeqCst) == before
            });
        });
        assert!(!walked, "dropped events became a full pass");
        f.stop();
    }

    /// The real event stream, on a synthetic folder: opened again from an
    /// event, it replays from the change history what came after that event,
    /// and not what came before. The only test that starts this process's
    /// stream. The files are made by a child: the stream ignores this process.
    #[test]
    fn the_event_stream_opened_again_replays_what_came_after() {
        static SEEN: Mutex<Vec<String>> = Mutex::new(Vec::new());
        static LAST: AtomicU64 = AtomicU64::new(0);
        extern "C" fn change(path: *const c_char, _: u32) {
            // SAFETY: FSEvents passes a NUL-terminated path valid for this call.
            let path = unsafe { CStr::from_ptr(path) }.to_string_lossy();
            let name = path.rsplit('/').next().unwrap_or_default().to_string();
            SEEN.lock().unwrap().push(name);
        }
        extern "C" fn batch(last: u64) {
            LAST.store(last, Ordering::SeqCst);
        }
        let seen = |name: &str| SEEN.lock().unwrap().iter().any(|n| n == name);
        let wait = |what: &str, done: &dyn Fn() -> bool| {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !done() {
                assert!(
                    Instant::now() < deadline,
                    "the stream never reported: {what}"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        let touch = |path: &Path| {
            let made = std::process::Command::new("touch").arg(path).status();
            assert!(made.unwrap().success());
        };
        let dir = std::env::temp_dir().join(format!(
            "credential-agent-test-{}-stream",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = CString::new(dir.as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated path, and plain functions that live for the
        // whole process.
        assert!(unsafe { ch_watch_start(path.as_ptr(), 0, 0.1, change, batch) });
        touch(&dir.join("before-the-place"));
        wait("the first file", &|| seen("before-the-place"));
        let place = LAST.load(Ordering::SeqCst);
        touch(&dir.join("after-the-place"));
        wait("the second file", &|| seen("after-the-place"));
        SEEN.lock().unwrap().clear();
        // SAFETY: takes a number; called from this thread, not the stream's queue.
        assert!(unsafe { ch_watch_resume(place) });
        wait("the second file again", &|| seen("after-the-place"));
        assert!(!seen("before-the-place"), "replayed from before the place");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A helper that keeps falling behind does not open the stream again for
    /// ever: a full pass makes up for what was dropped.
    #[test]
    fn events_dropped_again_and_again_become_a_full_pass() {
        static OPENED: AtomicUsize = AtomicUsize::new(0);
        let mut f = Fixture::tuned(
            "dropped-again",
            &[],
            |_| {},
            |agent| {
                agent.resume_watch = |_| {
                    OPENED.fetch_add(1, Ordering::SeqCst);
                }
            },
        );
        f.first_pass();
        let walked = walked(&mut f, |f| {
            f.changes(&["before.csv"]);
            let agent = f.agent;
            for _ in 0..=RESUMES_MAX {
                f.dropped();
                f.until("the drop to be handled", || {
                    agent.inbox.lock().unwrap().resume.is_none()
                });
            }
        });
        assert!(
            walked,
            "events dropped again and again were never made up for"
        );
        assert_eq!(OPENED.load(Ordering::SeqCst), RESUMES_MAX);
        f.stop();
    }

    /// The place to replay from was cleared once the stream had been opened
    /// again. A drop reported while it was being opened found that place
    /// already set, and was then taken as handled: never replayed.
    #[test]
    fn a_drop_while_the_stream_is_opened_again_is_replayed() {
        static AGENT: OnceLock<&'static Agent> = OnceLock::new();
        static FROM: Mutex<Vec<u64>> = Mutex::new(Vec::new());
        let mut f = Fixture::tuned(
            "dropped-while-opening",
            &[],
            |_| {},
            |agent| {
                agent.resume_watch = |since| {
                    let first = {
                        let mut from = FROM.lock().unwrap();
                        from.push(since);
                        from.len() == 1
                    };
                    // The stream opened again falls behind at once.
                    if let (true, Some(agent)) = (first, AGENT.get()) {
                        agent.changed(agent.home.clone(), 0x1 | USER_DROPPED);
                        agent.batch(since + 1);
                    }
                }
            },
        );
        assert!(AGENT.set(f.agent).is_ok());
        f.first_pass();
        f.changes(&["before.csv"]);
        let before = f.event;
        f.dropped();
        f.until("the stream to be opened again for the second drop", || {
            FROM.lock().unwrap().len() >= 2
        });
        assert_eq!(*FROM.lock().unwrap(), [before, before]);
        f.stop();
    }

    /// A full pass was started over whenever changes were lost or too many
    /// to hold. Lost often enough, as while software is being built, no pass
    /// ever reached its end.
    #[test]
    fn a_full_pass_under_way_is_finished_when_another_is_asked_for() {
        let files: Vec<String> = (0..12)
            .flat_map(|d| (0..10).map(move |n| format!("d{d}/export-{n}.csv")))
            .collect();
        let files: Vec<&str> = files.iter().map(String::as_str).collect();
        // A pass of several slices: each lists two folders or so.
        let mut f = Fixture::tuned(
            "pass-kept",
            &files,
            |_| {},
            |agent| {
                agent.slice.entries = 25;
                agent.slice_pause = Duration::from_millis(20);
            },
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        let state = loop {
            f.changes_lost();
            let state = f.app.read().unwrap();
            if state.agent.baseline.is_some() {
                break state;
            }
            assert!(
                Instant::now() < deadline,
                "the pass never ended while changes kept being lost"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(state.items.len(), files.len());
        f.stop();
    }

    /// A slice that a cancel cut short as it began was counted with the
    /// slices that got nowhere, and three of those give a pass up.
    #[test]
    fn a_slice_cut_short_by_a_cancel_does_not_count_against_the_pass() {
        static CUT: AtomicBool = AtomicBool::new(false);
        static CANCEL: OnceLock<std::sync::Arc<AtomicBool>> = OnceLock::new();
        // Asked just before each slice, so a cancel set here cuts the slice
        // before it has done anything.
        fn cut() -> bool {
            if CUT.load(Ordering::SeqCst) {
                if let Some(cancel) = CANCEL.get() {
                    cancel.store(true, Ordering::SeqCst);
                }
            }
            false
        }
        let mut f = Fixture::tuned(
            "cut-slices",
            &[],
            |_| {},
            |agent| {
                agent.low_power = cut;
                agent.slice_pause = Duration::from_millis(20);
            },
        );
        CANCEL.set(f.agent.monitor.cancel.clone()).unwrap();
        f.first_pass();
        // Another pass is needed, and each of its slices is cut as it starts,
        // as on a Mac that wakes for a moment and sleeps again.
        CUT.store(true, Ordering::SeqCst);
        export(&f.home, "found-by-the-pass.csv");
        f.changes_lost();
        // Time for many more than three such slices.
        std::thread::sleep(Duration::from_millis(600));
        CUT.store(false, Ordering::SeqCst);
        let state = f.wait("the pass, once its slices were let run", |s| {
            s.items.len() == 1
        });
        assert_eq!(open(&state), ["~/found-by-the-pass.csv"]);
        f.stop();
    }

    /// The count of slices that got nowhere outlived the pass it gave up.
    /// The next pass, its first slice cut by a cancel, was then given up
    /// too, before it had made one slice of its own.
    #[test]
    fn a_pass_after_one_given_up_is_not_given_up_for_a_cancel() {
        static CUT: AtomicBool = AtomicBool::new(false);
        static SLICES: AtomicUsize = AtomicUsize::new(0);
        static CANCEL: OnceLock<std::sync::Arc<AtomicBool>> = OnceLock::new();
        // Asked just before each slice: counts them, and cuts the one after
        // `CUT` is set before it has done anything.
        fn cut() -> bool {
            SLICES.fetch_add(1, Ordering::SeqCst);
            if CUT.swap(false, Ordering::SeqCst) {
                if let Some(cancel) = CANCEL.get() {
                    cancel.store(true, Ordering::SeqCst);
                }
            }
            false
        }
        // No time for a folder, so after the known locations every slice
        // leaves the pass as it found it.
        let mut f = Fixture::tuned(
            "given-up-then-cut",
            &[],
            |_| {},
            |agent| {
                agent.low_power = cut;
                agent.slice.time = Duration::ZERO;
                agent.slice_pause = Duration::from_millis(20);
            },
        );
        CANCEL.set(f.agent.monitor.cancel.clone()).unwrap();
        // One slice that lists the home, and three that get nowhere.
        f.until("the first pass to be given up", || {
            SLICES.load(Ordering::SeqCst) >= 4
        });
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            SLICES.load(Ordering::SeqCst),
            4,
            "the pass was not given up"
        );
        CUT.store(true, Ordering::SeqCst);
        f.changes_lost();
        f.until(
            "the next pass to go on after its first slice was cut",
            || SLICES.load(Ordering::SeqCst) >= 6,
        );
        f.stop();
    }

    /// The place in the change history was saved as far as the events had
    /// been received, not as far as they had been checked. A file whose
    /// change was waiting its turn was passed, so an agent that stopped then
    /// was never told of the change again.
    #[test]
    fn the_saved_place_in_the_change_history_does_not_pass_a_change_still_waiting() {
        let mut f = Fixture::start("event-id", &[], |_| {});
        f.first_pass();
        export(&f.home, "busy.csv");
        f.changes(&["busy.csv"]); // Event 1.
        f.wait("the new file", |s| s.items.len() == 1);
        std::fs::remove_file(f.home.join("busy.csv")).unwrap();
        f.changes(&["busy.csv"]); // Event 2: too soon, so it waits its turn.
        export(&f.home, "other.csv");
        f.changes(&["other.csv"]); // Event 3: checked at once and saved.
        let state = f.wait("the other file", |s| s.items.len() == 2);
        let busy = |s: &Review| s.items.iter().any(|i| i.path == "~/busy.csv" && i.resolved);
        let (rechecked, saved) = (busy(&state), state.agent.event_id);
        assert!(
            rechecked || saved < 2,
            "event {saved} was saved with the change of event 2 not checked"
        );
        // Once it has been checked, the place moves on.
        let state = f.wait("the change that waited", busy);
        assert_eq!(state.agent.event_id, 3);
        f.stop();
    }

    /// The rechecks at the end of a full pass read every open item's file
    /// with the store locked, however long that took, and the app waited.
    #[test]
    fn the_rechecks_of_one_save_stop_when_their_time_is_used() {
        let files = ["one.csv", "two.csv"];
        let mut f = Fixture::tuned(
            "recheck-time",
            &files,
            |_| {},
            |agent| {
                agent.rechecks = Duration::ZERO;
            },
        );
        assert_eq!(f.first_pass().items.len(), 2);
        std::fs::remove_file(f.home.join("one.csv")).unwrap();
        f.changes(&["one.csv"]);
        // The change is saved, and the item it would have rechecked is left
        // as it was: nothing is known of it.
        let state = f.wait("the change", |s| s.agent.changes == 1);
        assert_eq!(open(&state), ["~/one.csv", "~/two.csv"]);
        f.stop();
    }

    /// The window says how many folders a pass has left. The known
    /// locations, one step of a pass, were counted as a folder.
    #[test]
    fn the_folders_a_pass_has_left_are_folders() {
        let home = PathBuf::from("/synthetic/home");
        let folder = |name: &str| scan::Step::Folder(home.join(name), 1);
        assert_eq!(folders_left(&vec![]), 0);
        assert_eq!(
            folders_left(&vec![scan::Step::Known(0), folder("a"), folder("b")]),
            2
        );
        // Never none while something is left: none means the pass is over.
        assert_eq!(folders_left(&vec![scan::Step::Known(3)]), 1);
    }

    /// A check of changes that its own limits stopped left the rest of the
    /// batch unread and said nothing: no later check, no full pass. A folder
    /// moved in with more in it than one check lists was read as far as the
    /// check got, and no further until the weekly pass.
    #[test]
    fn a_folder_one_check_cannot_finish_is_finished_by_a_full_pass() {
        let mut f = Fixture::tuned(
            "cut-short",
            &[],
            |_| {},
            |agent| {
                agent.changes.entries = 30;
                agent.slice_pause = Duration::from_millis(20);
            },
        );
        f.first_pass();
        // More entries than one check may list, and a file beyond them.
        for folder in ["a", "b", "c"] {
            let folder = f.home.join("Moved").join(folder);
            std::fs::create_dir_all(&folder).unwrap();
            for n in 0..20 {
                std::fs::write(folder.join(format!("file-{n}")), "").unwrap();
            }
        }
        export(&f.home, "Moved/z/deep/export.csv");
        f.changes(&["Moved"]);
        // Only a full pass gets there: checked again, the folder would be
        // cut short at the same place.
        let state = f.wait("the file the check did not reach", |s| s.items.len() == 1);
        assert_eq!(open(&state), ["~/Moved/z/deep/export.csv"]);
        f.stop();
    }

    /// A changed folder that the check did not begin, because the folders
    /// before it had used up what one check may list, was dropped.
    #[test]
    fn a_changed_folder_the_check_did_not_begin_is_checked_in_the_next_round() {
        let mut f = Fixture::tuned("not-begun", &[], |_| {}, |agent| agent.changes.entries = 5);
        let before = f.first_pass();
        // The first folder is listed to its end and leaves nothing over.
        std::fs::create_dir(f.home.join("A")).unwrap();
        for n in 0..5 {
            std::fs::write(f.home.join("A").join(format!("file-{n}")), "").unwrap();
        }
        export(&f.home, "B/export.csv");
        f.changes(&["A", "B"]);
        let state = f.wait("the folder that was not begun", |s| s.items.len() == 1);
        assert_eq!(open(&state), ["~/B/export.csv"]);
        // In a round of its own: no full pass was needed for it.
        assert_eq!(state.agent.baseline, before.agent.baseline);
        assert_eq!(state.agent.changes, 1);
        f.stop();
    }

    /// A folder begun after the one before it had used most of what one check
    /// may list was taken for a folder no check can finish, and asked for a
    /// walk of the whole home. As the helper starts and replays a long batch,
    /// that was most starts. Checked on its own, it is finished.
    #[test]
    fn a_folder_the_one_before_it_left_unfinished_is_checked_again_not_walked() {
        let mut f = Fixture::tuned("shared", &[], |_| {}, |agent| agent.changes.entries = 40);
        f.first_pass();
        let walked = walked(&mut f, |f| {
            for folder in ["A", "B"] {
                for n in 0..30 {
                    export(&f.home, &format!("{folder}/export-{n}.csv"));
                }
            }
            f.changes(&["A", "B"]);
            f.wait("both folders", |s| s.items.len() >= 60);
        });
        assert!(
            !walked,
            "a folder cut short by the one before it became a full pass"
        );
        f.stop();
    }

    /// Paths a check left unfinished were checked again among the paths that
    /// changed since, in name order. While changes that sort before it kept
    /// coming, a folder too large for one check was never the first a check
    /// began, so it never asked for the full pass that finishes it.
    #[test]
    fn a_folder_too_large_for_a_check_is_finished_while_other_changes_keep_coming() {
        let mut f = Fixture::tuned(
            "carried-first",
            &[],
            |_| {},
            |agent| {
                agent.changes.entries = 40;
                agent.slice_pause = Duration::from_millis(20);
                // The folders that keep changing are due again at once.
                agent.recheck_after = Duration::ZERO;
            },
        );
        f.first_pass();
        // Folders that sort first, more of them than one check lists.
        let other = |n: u64| format!("A-{:02}", n % 100);
        for n in 0..100 {
            std::fs::create_dir(f.home.join(other(n))).unwrap();
            std::fs::write(f.home.join(other(n)).join("file"), "").unwrap();
        }
        // More entries than one check lists, and a file past them.
        let large = |home: &Path, folder: &str| {
            std::fs::create_dir(home.join(folder)).unwrap();
            for n in 0..60 {
                std::fs::write(home.join(folder).join(format!("file-{n}")), "").unwrap();
            }
            export(home, &format!("{folder}/zz/deep/export.csv"));
        };
        // "B" has had the full pass it asked for: cut short again, it asks
        // for none, and is not checked again.
        large(&f.home, "B");
        f.changes(&["B"]);
        f.wait("the full pass the first folder asked for", |s| {
            listed(s, "~/B/zz/deep/export.csv") && s.agent.left == 0
        });
        large(&f.home, "Z");
        // Both are left unfinished behind the others, which keep changing.
        f.changes(&[&other(0), "B", "Z"]);
        let halt = std::sync::Arc::new(AtomicBool::new(false));
        let (agent, home, mut event, stop) = (f.agent, f.home.clone(), f.event, halt.clone());
        let feeder = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
                agent.changed(home.join(other(event)), 0);
                event += 1;
                agent.batch(event);
                std::thread::sleep(Duration::from_micros(50));
            }
            event
        });
        f.wait("the file past what one check of the folder lists", |s| {
            listed(s, "~/Z/zz/deep/export.csv")
        });
        halt.store(true, Ordering::SeqCst);
        f.event = feeder.join().unwrap();
        f.stop();
    }

    /// Whether a place is on the list, fixed or not.
    fn listed(state: &Review, path: &str) -> bool {
        state.items.iter().any(|i| i.path == path)
    }

    /// A save that failed was a log line, and the worker went on as if what
    /// the check found were on the list: the change was not checked again,
    /// and the next save put the place in the change history past it. An
    /// agent started again was then never told of that change.
    #[test]
    fn a_change_whose_save_failed_is_checked_again_and_its_place_is_not_passed() {
        let mut f = Fixture::start("unsaved-change", &[], |_| {});
        f.first_pass();
        export(&f.home, "saved.csv");
        f.changes(&["saved.csv"]); // Event 1.
        f.wait("a change that is saved", |s| s.agent.event_id == 1);
        f.storage(false);
        export(&f.home, "lost.csv");
        f.changes(&["lost.csv"]); // Event 2: found, and the save fails.
        f.until("the save that fails", || f.unsaved() > 0);
        assert_eq!(f.app.read().unwrap().agent.event_id, 1);
        f.storage(true);
        export(&f.home, "next.csv");
        f.changes(&["next.csv"]); // Event 3: saved.
        let state = f.wait("the next change", |s| listed(s, "~/next.csv"));
        // Started again here, the agent is told of every change after the
        // place saved. That has to include the one that is on no list.
        let place = state.agent.event_id;
        assert!(
            listed(&state, "~/lost.csv") || place < 2,
            "event {place} was saved with what event 2 found on no list"
        );
        // It is checked again in its turn, and then the place moves on.
        let state = f.wait("the change whose save failed", |s| listed(s, "~/lost.csv"));
        assert_eq!(state.agent.event_id, 3);
        assert_eq!(f.unsaved(), 0);
        f.stop();
    }

    /// With nothing else to save, the quarter-hourly check saved the place
    /// in the change history, past a change whose finding was on no list.
    #[test]
    fn the_quarter_hourly_check_does_not_pass_a_change_whose_save_failed() {
        let mut f = Fixture::start("unsaved-tick", &[], |_| {});
        f.first_pass();
        f.storage(false);
        export(&f.home, "lost.csv");
        f.changes(&["lost.csv"]); // Event 1: found, and the save fails.
        f.until("the save that fails", || f.unsaved() > 0);
        f.storage(true);
        // Event 2 has nothing to save, and then the check comes round.
        std::fs::write(f.home.join("plain.txt"), "ordinary synthetic data").unwrap();
        f.changes(&["plain.txt"]);
        f.tick();
        let state = f.wait("the place to move, or the finding to be saved", |s| {
            s.agent.event_id == 2 || listed(s, "~/lost.csv")
        });
        let place = state.agent.event_id;
        assert!(
            listed(&state, "~/lost.csv"),
            "event {place} was saved with what event 1 found on no list"
        );
        f.wait("the place, once the finding is saved", |s| {
            s.agent.event_id == 2
        });
        f.stop();
    }

    /// A slice of a full pass whose save failed was passed like any other:
    /// the pass went on from where the slice stopped, and what the slice had
    /// found was on no list until the pass of the week after.
    #[test]
    fn a_slice_whose_save_failed_is_made_again() {
        let files: Vec<String> = (0..12)
            .flat_map(|d| (0..10).map(move |n| format!("d{d}/export-{n}.csv")))
            .collect();
        let files: Vec<&str> = files.iter().map(String::as_str).collect();
        // A pass of several slices, and the first of them cannot be saved.
        let f = Fixture::tuned(
            "unsaved-slice",
            &files,
            |_| {},
            |agent| {
                agent.slice.entries = 25;
                agent.slice_pause = Duration::from_millis(20);
                use std::os::unix::fs::PermissionsExt;
                let permissions = std::fs::Permissions::from_mode(0o500);
                std::fs::set_permissions(&agent.state_dir, permissions).unwrap();
            },
        );
        f.until("the save that fails", || f.unsaved() > 0);
        f.storage(true);
        let state = f.first_pass();
        assert_eq!(
            state.items.len(),
            files.len(),
            "the pass ended without what a slice found and could not save"
        );
        assert_eq!(f.unsaved(), 0);
        f.stop();
    }

    /// The same for a pass of one slice, which is also its last: the pass
    /// was over, with nothing of it saved and nothing to bring it back.
    #[test]
    fn a_pass_whose_last_save_failed_is_not_over() {
        let f = Fixture::tuned(
            "unsaved-pass",
            &["here.csv"],
            |_| {},
            |agent| {
                agent.slice_pause = Duration::from_millis(20);
                use std::os::unix::fs::PermissionsExt;
                let permissions = std::fs::Permissions::from_mode(0o500);
                std::fs::set_permissions(&agent.state_dir, permissions).unwrap();
            },
        );
        // Tried again, and again: not given up after one.
        f.until("a second save that fails", || f.unsaved() > 1);
        assert!(f.app.read().unwrap().agent.baseline.is_none());
        f.storage(true);
        assert_eq!(open(&f.first_pass()), ["~/here.csv"]);
        f.stop();
    }

    #[test]
    fn the_wait_after_a_save_that_failed_grows_and_has_an_end() {
        let pause = Duration::from_secs(30);
        let waits: Vec<u64> = (1..=8).map(|n| unsaved_wait(pause, n).as_secs()).collect();
        assert_eq!(waits, [30, 60, 120, 240, 480, 900, 900, 900]);
        assert_eq!(unsaved_wait(pause, u32::MAX), CADENCE);
    }

    /// The time is read from the saved state, which can hold any number.
    /// One too far ahead to add to the clock ended the helper, and launchd
    /// started it again into the same state.
    #[test]
    fn a_notification_retry_too_far_ahead_asks_for_no_wake() {
        assert_eq!(notify_wake(u64::MAX), None);
        let soon = notify_wake(0).unwrap();
        assert!(soon > Instant::now() + Duration::from_secs(50));
    }

    /// FSEvents numbers some events 0, such as the one that ends replayed
    /// history. Taken as the last event of a batch, or saved as the place,
    /// it made the next start read from now and miss what came before.
    #[test]
    fn an_event_numbered_zero_moves_no_place() {
        let mut f = Fixture::start("event-zero", &[], |_| {});
        f.first_pass();
        // The quarter-hourly save: nothing has been handled yet, and the
        // saved place stays as it is.
        f.app
            .update(|state| {
                state.agent.event_id = 7;
                Ok(())
            })
            .unwrap();
        f.tick();
        f.until("the quarter-hourly check to read the place", || {
            f.agent.known.lock().unwrap().saved_event == 7
        });
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(f.app.read().unwrap().agent.event_id, 7);
        f.changes(&["a.txt"]);
        f.agent.batch(0);
        assert_eq!(f.agent.inbox.lock().unwrap().last_event, f.event);
        f.stop();
    }

    /// While notifications were not allowed and something waited to be
    /// sent, every wake of the worker asked macOS again.
    #[test]
    fn notification_permission_is_asked_again_once_in_a_while_not_at_every_wake() {
        static ASKED: AtomicUsize = AtomicUsize::new(0);
        let mut f = Fixture::tuned(
            "ask-permission",
            &["export.csv"],
            |_| {},
            |agent| {
                agent.refresh = || {
                    ASKED.fetch_add(1, Ordering::SeqCst);
                }
            },
        );
        f.first_pass();
        f.until("permission to be asked for what was found", || {
            ASKED.load(Ordering::SeqCst) >= 1
        });
        for n in 0..3 {
            change_listed(&mut f, &format!("more-{n}.csv"));
        }
        assert_eq!(ASKED.load(Ordering::SeqCst), 1, "asked at every wake");
        // The app saves the shared state when notifications are allowed
        // there: the helper may ask again at once.
        f.app_sets(|_| {});
        f.until(
            "permission to be asked again after the app's change",
            || ASKED.load(Ordering::SeqCst) == 2,
        );
        f.stop();
    }

    /// Notifications turned off in System Settings while the helper ran:
    /// each send was refused, and each refusal spent one of the three
    /// attempts, so none was made again once they were turned back on.
    #[test]
    fn a_send_refused_for_want_of_permission_spends_no_attempt() {
        let f = Fixture::start("refused", &["export.csv"], |_| {});
        let state = f.first_pass();
        assert!(state.pending(crate::now()));
        let attempt = || {
            let (_, revision) = f
                .agent
                .store
                .update(|state| {
                    state.attempted(crate::now());
                    Ok(state.revision)
                })
                .unwrap();
            revision
        };
        for _ in 0..3 {
            f.agent.delivered(attempt(), false, false);
        }
        assert_eq!(
            f.app.read().unwrap().attempts,
            0,
            "a refusal spent an attempt"
        );
        // A delivery that failed with notifications allowed still counts.
        f.agent.delivered(attempt(), false, true);
        assert_eq!(f.app.read().unwrap().attempts, 1);
        f.stop();
    }

    /// A notification whose completion never came back held off every
    /// notification after it until the helper was started again.
    #[test]
    fn a_delivery_that_never_hears_back_stops_holding_up_the_next() {
        let now = Instant::now();
        assert!(!delivery_under_way(None, now));
        assert!(delivery_under_way(Some(now), now));
        assert!(delivery_under_way(Some(now), now + Duration::from_secs(1)));
        assert!(!delivery_under_way(Some(now), now + DELIVERY_WAIT));
    }

    /// A full pass under way was not saved: a helper started again began
    /// none until the weekly one, though the window showed folders left.
    #[test]
    fn a_full_pass_under_way_is_made_after_a_restart() {
        let now = crate::now();
        let saved = |left| review::Agent {
            baseline_at: now,
            left,
            ..review::Agent::default()
        };
        assert!(!pass_at_start(&saved(0), 5, now));
        assert!(pass_at_start(&saved(3), 5, now));
        assert!(pass_at_start(&saved(0), 0, now));
    }

    /// A pass that ends while another is owed leaves a folder to check, so
    /// that a restart before the next begins still makes it.
    #[test]
    fn a_pass_that_ends_with_another_owed_leaves_it_saved() {
        let files: Vec<String> = (0..12)
            .flat_map(|d| (0..10).map(move |n| format!("d{d}/export-{n}.csv")))
            .collect();
        let files: Vec<&str> = files.iter().map(String::as_str).collect();
        let mut f = Fixture::tuned(
            "pass-owed",
            &files,
            |_| {},
            |agent| {
                agent.slice.entries = 25;
                agent.slice_pause = Duration::from_millis(300);
            },
        );
        f.wait("the first slice", |s| s.agent.left > 0);
        f.changes_lost();
        let ended = f.first_pass();
        assert_ne!(ended.agent.left, 0, "the pass owed was not saved");
        f.wait("the pass that was owed", |s| s.agent.left == 0);
        f.stop();
    }

    /// The state was taken in by whichever thread came last, though it may
    /// have read it first: a pause read before monitoring was resumed left
    /// the checks paused until the next change of a setting.
    #[test]
    fn a_state_read_earlier_does_not_replace_one_read_later() {
        let f = Fixture::start("read-order", &[], |_| {});
        f.first_pass();
        let state = f.app.read().unwrap();
        let earlier = f.agent.ticket();
        let paused = Review {
            paused: true,
            ..state.clone()
        };
        let later = f.agent.ticket();
        f.agent.remember(&state, later);
        f.agent.remember(&paused, earlier);
        assert!(
            f.agent.monitor.active(),
            "an earlier read paused the checks"
        );
        f.stop();
    }

    #[test]
    fn what_a_stopped_check_leaves_to_do() {
        let path = |name: &str| PathBuf::from("/synthetic/home").join(name);
        let left = || scan::Unreached {
            cancelled: vec![path("c")],
            out_of_budget: vec![path("o")],
            cut_short: vec![path("s")],
        };
        let set = |names: &[&str]| names.iter().map(|n| path(n)).collect::<BTreeSet<_>>();
        let now = Instant::now();
        let mut asked = HashMap::new();
        // After a cancel every path is checked again, and no pass is needed:
        // one cut short before the cancel came may now be finished.
        assert_eq!(
            unfinished(left(), true, 5, &mut asked, now),
            (set(&["c", "o", "s"]), false)
        );
        assert!(asked.is_empty());
        // A path its own limits cut short asks for a pass, which stands for
        // the paths not begun as well.
        assert_eq!(
            unfinished(left(), false, 5, &mut asked, now),
            (set(&[]), true)
        );
        // Cut short again soon after, it does not ask again, and the paths
        // not begun get a check to themselves.
        let later = now + Duration::from_secs(3600);
        assert_eq!(
            unfinished(left(), false, 5, &mut asked, later),
            (set(&["o"]), false)
        );
        // A day on, it may ask once more.
        let next_day = now + PASS_AGAIN + Duration::from_secs(1);
        assert_eq!(
            unfinished(left(), false, 5, &mut asked, next_day),
            (set(&[]), true)
        );
        // A check that began nothing is not made again as it was.
        let none_begun = scan::Unreached {
            out_of_budget: vec![path("a"), path("b")],
            ..scan::Unreached::default()
        };
        assert_eq!(
            unfinished(none_begun, false, 2, &mut HashMap::new(), now),
            (set(&[]), true)
        );
        // Nothing left over: nothing to do.
        let finished = scan::Unreached::default();
        assert_eq!(
            unfinished(finished, false, 2, &mut HashMap::new(), now),
            (set(&[]), false)
        );
    }
}
