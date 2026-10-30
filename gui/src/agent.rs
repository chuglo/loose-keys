//! The background agent: this executable run with `--agent`. It has no
//! window, Dock icon or web view. launchd starts it at login and restarts it
//! if it fails (gui/macos/dev.loosekeys.agent.plist).
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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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

// FSEvents flags: events were dropped or coalesced, so the folder must be
// walked; and the marker that ends replayed history.
const MUST_RESCAN: u32 = 0x1 | 0x2 | 0x4 | 0x8;
const HISTORY_DONE: u32 = 0x10;

unsafe extern "C" {
    fn ch_watch_start(
        path: *const c_char,
        since: u64,
        latency: f64,
        change: extern "C" fn(*const c_char, u32),
        batch: extern "C" fn(u64),
    ) -> bool;
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
    delivering: AtomicBool,
    /// From the last state read or written: what the next step needs without
    /// reading the store again.
    known: Mutex<Known>,
    /// How long a path that changed again waits for its next check, before
    /// doubling. `RECHECK_AFTER`, except in tests.
    recheck_after: Duration,
    /// What one slice of a full pass may spend, and the rest between slices.
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
    /// Wait before retrying a full pass held by Low Power Mode: ten minutes,
    /// shortened only by synthetic worker tests.
    low_power_pause: Duration,
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
}

#[derive(Default)]
struct Known {
    key: Vec<u8>,
    enabled: bool,
    paused: bool,
    /// Paths of unresolved review items.
    open: Vec<PathBuf>,
    unnotified: bool,
    /// Folders the person asked not to be checked.
    skip: Vec<PathBuf>,
    /// When the next notification attempt may be made, if one is owed.
    retry_at: Option<u64>,
    saved_event: u64,
}

static AGENT: OnceLock<Agent> = OnceLock::new();

impl Agent {
    fn remember(&self, state: &Review) {
        let mut known = self.known.lock().unwrap();
        known.key = state.key.clone();
        known.open = state
            .items
            .iter()
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

    fn fingerprint(&self) -> impl Fn(&str, &[u8], bool) -> String + Send + 'static {
        let key = self.known.lock().unwrap().key.clone();
        move |rule, bytes, shared| crate::material_fingerprint(rule, &key, bytes, shared)
    }

    /// Save what a check found. `only` limits the recheck of open items to
    /// those at or under the changed paths, and those in a file the check
    /// lists a finding in: it read that file, and what it found there may
    /// stand in place of what was listed. `place` is how far in the change
    /// history every change has now been checked, when that has moved.
    /// Returns whether it was saved. If not, what was found is on no list,
    /// and the check has to be made again before anything is saved that
    /// says it was made.
    #[must_use]
    fn record(
        &self,
        report: &Report,
        only: Option<&[PathBuf]>,
        place: Option<u64>,
        health: impl FnOnce(&mut review::Agent),
    ) -> bool {
        let saved = self.store.update(|state| {
            let key = state.key.clone();
            // Counted from here: the store is locked from here on.
            let rechecking = Instant::now();
            let found: HashSet<&str> = report.findings.iter().map(|f| f.path.as_str()).collect();
            state.merge(report, |item| {
                let path = crate::recheck_path(&item.path, Some(&self.home))?;
                let changed = |only: &[PathBuf]| only.iter().any(|p| path.starts_with(p));
                if only.is_some_and(|only| !changed(only)) && !found.contains(item.path.as_str()) {
                    return None;
                }
                // Out of time, or told to stop: nothing is known of the rest,
                // and they stay as they are until they are next checked.
                if rechecking.elapsed() >= self.rechecks
                    || self.monitor.cancel.load(Ordering::SeqCst)
                {
                    return None;
                }
                crate::still_there(item, &self.home, &key)
            });
            state.agent.last_check = Some(report.generated_at.clone());
            state.agent.error = None;
            if let Some(place) = place.filter(|place| *place != 0) {
                state.agent.event_id = place;
            }
            health(&mut state.agent);
            Ok(())
        });
        match saved {
            Ok((state, ())) => {
                self.unsaved.store(0, Ordering::SeqCst);
                self.remember(&state);
                true
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

    /// Whether a batch of changes needs the store at all. Most do not.
    fn concerns_review(&self, report: &Report, changed: &[PathBuf]) -> bool {
        report.findings.iter().any(|f| f.kind == "review")
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
            // another try when it is yes.
            unsafe { crate::ch_notifications_refresh() };
            return;
        }
        // The app shows new items itself while it is in front.
        if unsafe { crate::ch_app_active() } {
            return self.monitor.retry_in(Duration::from_secs(60));
        }
        let due = |state: &Review| state.monitoring && !state.paused && state.pending(crate::now());
        if !self.store.read().is_ok_and(|state| due(&state))
            || self.delivering.swap(true, Ordering::SeqCst)
        {
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
                self.delivering.store(false, Ordering::SeqCst);
            }
        }
    }

    /// One file-change event: hold the path for the worker.
    fn changed(&self, path: PathBuf, flags: u32) {
        if flags & HISTORY_DONE != 0 {
            return;
        }
        let mut inbox = self.inbox.lock().unwrap();
        if path.starts_with(&self.state_dir) {
            inbox.settings = true;
        } else if !self.known.lock().unwrap().enabled
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
            inbox.last_event = last_event;
            std::mem::take(&mut inbox.settings)
        };
        // The app changed the shared state: a setting, a decision or a retry.
        if settings {
            match self.store.read() {
                Ok(state) => self.remember(&state),
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
    let Some(agent) = AGENT.get() else {
        return;
    };
    let state = if success {
        agent
            .store
            .update(|state| {
                state.delivered(revision);
                Ok(())
            })
            .map(|(state, ())| state)
    } else {
        agent.store.read()
    };
    agent.delivering.store(false, Ordering::SeqCst);
    match state {
        Ok(state) => {
            agent.remember(&state);
            if state.attempts < 3 {
                let delay = state.retry_at.saturating_sub(crate::now()).max(1);
                agent.monitor.retry_in(Duration::from_secs(delay));
            }
        }
        Err(e) => eprintln!("loose-keys agent: {e}"),
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
    while let Some(tick) = agent.monitor.wait() {
        if !agent.monitor.arm(ScanKind::Automatic) {
            continue;
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
            let state = agent.store.read();
            let last = state.as_ref().map_or(0, |s| s.agent.baseline_at);
            // What is to be notified can change by the clock alone, as when
            // a set-aside reason ends, with nothing read or written to say
            // so. What is known is from before; this is as it is now.
            if let Ok(state) = &state {
                agent.remember(state);
            }
            if full_pass.is_none() && crate::now().saturating_sub(last) > FULL_PASS_EVERY {
                full_pass = Some(None);
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
            let (report, left) = Scan::changed(
                &agent.home,
                &skip,
                &ready,
                agent.changes,
                cancel.clone(),
                agent.fingerprint(),
            );
            let cancelled = cancel.load(Ordering::SeqCst);
            let (again, pass) = unfinished(left, cancelled, ready.len(), &mut asked, now);
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
                if !agent.record(&report, Some(&ready), place, |h| h.changes += done) {
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
                if resume.is_none() {
                    unread = review::UnreadPlaces::default();
                }
                let before = resume.clone();
                let (report, pending) = Scan::sweep(
                    &agent.home,
                    &skip,
                    resume,
                    agent.slice,
                    cancel.clone(),
                    agent.fingerprint(),
                );
                unread.record(&report);
                let done = pending.is_empty();
                let nothing: &[PathBuf] = &[];
                let place = (done && !owed).then(|| handled(&waiting, event));
                let not_read = unread.places.len();
                let saved = agent.record(&report, (!done).then_some(nothing), place, |h| {
                    h.left = folders_left(&pending);
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
        } else if tick && handled(&waiting, event) != agent.known.lock().unwrap().saved_event {
            // Keep the place in the change history, so a restart replays little.
            let place = handled(&waiting, event);
            let saved = agent.store.update(|state| {
                state.agent.event_id = place;
                Ok(())
            });
            if let Ok((state, ())) = saved {
                agent.remember(&state);
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
            .chain(notify.map(|at| {
                Instant::now() + Duration::from_secs(at.saturating_sub(crate::now()).max(60))
            }))
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
/// fix, so launchd does not start it again in a loop.
pub fn run() -> ! {
    fn stop(reason: &str) -> ! {
        eprintln!("loose-keys agent: {reason}");
        std::process::exit(0)
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
    let store = Store::open(&home).unwrap_or_else(|e| stop(&e));
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
    let (state, ()) = started.unwrap_or_else(|e| stop(&e));
    let overdue = crate::now().saturating_sub(state.agent.baseline_at) > FULL_PASS_EVERY;
    let agent = AGENT.get_or_init(|| Agent {
        state_dir: home.join(review::STATE_DIR),
        home,
        store,
        monitor: Monitor::new(false, false),
        inbox: Mutex::new(Inbox {
            last_event: since,
            ..Inbox::default()
        }),
        delivering: AtomicBool::new(false),
        known: Mutex::new(Known::default()),
        recheck_after: RECHECK_AFTER,
        slice: SLICE,
        slice_pause: SLICE_PAUSE,
        rechecks: RECHECKS,
        changes: CHANGES,
        // SAFETY: reads one process-wide setting; no preconditions.
        low_power: || unsafe { ch_low_power() },
        low_power_pause: Duration::from_secs(600),
        unsaved: AtomicU32::new(0),
    });
    agent.remember(&state);
    // SAFETY: the callbacks are plain functions that live for the whole process.
    unsafe {
        crate::ch_notifications_init(open_review, permission);
        crate::ch_background_init(sleeping, delivered, allowed);
        if !ch_watch_start(path.as_ptr(), since, LATENCY, changed, batch) {
            let _ = agent.store.update(|state| {
                state.agent.error = Some("Could not watch the home folder for changes.".into());
                Ok(())
            });
            stop("could not watch the home folder");
        }
    }
    let full_pass = (since == 0 || overdue).then_some(None);
    std::thread::Builder::new()
        .name("credential-agent".into())
        .spawn(move || {
            // SAFETY: sets this thread's own quality of service; no preconditions.
            unsafe {
                libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_BACKGROUND, 0);
            }
            work(agent, full_pass)
        })
        .unwrap_or_else(|_| stop("could not start the worker"));
    // SAFETY: runs the main run loop; called once, on the main thread.
    unsafe { ch_agent_run() };
    std::process::exit(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

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
                delivering: AtomicBool::new(false),
                known: Mutex::default(),
                recheck_after: Duration::from_secs(2),
                slice: SLICE,
                slice_pause: SLICE_PAUSE,
                rechecks: RECHECKS,
                changes: CHANGES,
                low_power: || false,
                low_power_pause: Duration::from_secs(600),
                unsaved: AtomicU32::new(0),
            };
            tune(&mut agent);
            let agent: &'static Agent = Box::leak(Box::new(agent));
            agent.remember(&saved.unwrap().0);
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
