//! The desktop app's engine: the same scan and report as the CLI, behind the
//! C interface in `app/Bridge.h`. The window is the front end's.
//!
//! File names are attacker-controlled. The front end only ever receives them
//! as `report::escape`d display text. Actions on a file ("Copy path", "Show in
//! Finder") name a finding by its id; the real path stays here and is
//! handed over only when it is plain printable ASCII.

mod agent;
#[cfg(test)]
mod background_tests;
#[cfg(test)]
#[path = "../../tests/support/detection.rs"]
mod detection_corpus;
#[cfg(test)]
mod engine_text_tests;
#[cfg(test)]
#[path = "../../tests/support/fixture_body.rs"]
mod fixture_body;
mod monitor;
mod release;
mod review;
#[cfg(test)]
mod stored_tests;

// The scanner the `loose-keys` command uses.
use loose_keys::{fsutil, report, rules, scan};

use report::Report;
use serde::{Deserialize, Serialize};
use std::ffi::{c_char, CStr, CString};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

/// Paths listed per "not checked" reason; saved reports have all of them.
const GAPS_SHOWN: usize = 20;

struct App {
    /// Gates and cancels this app's manual scans. Automatic checks are the
    /// background agent's job, in its own process.
    monitor: monitor::Monitor,
    home: Result<PathBuf, &'static str>,
    report: Mutex<Option<Report>>,
    scanning: AtomicBool,
    review: Mutex<review::Review>,
    store: Result<review::Store, String>,
    storage_error: Mutex<Option<String>>,
    /// Whether `storage_error` is from a change that could not be saved.
    /// What it would have saved is lost, so a later read that works does not
    /// clear it, as it does an error from reading. Changed only while
    /// `storage_error` is locked.
    storage_unsaved: AtomicBool,
    /// Held for the whole of a change that decides the app's Login Items
    /// entry, so the last change decides it. Holds no data.
    app_login: Mutex<()>,
    /// How long a scan's rechecks of the listed items may take.
    rechecks: std::time::Duration,
    /// Set once the store has been read, which the first command does.
    read: OnceLock<()>,
}

/// The rechecks run with the store locked, which the background agent and a
/// second launch wait for, so they get less time than the scan itself.
const RECHECKS: std::time::Duration = std::time::Duration::from_secs(10);

type Answer<T> = Result<T, String>;

/// The front end's function for events: a name and a JSON payload.
type Handler = extern "C" fn(*const c_char, *const c_char);

static APP: OnceLock<App> = OnceLock::new();
static EVENTS: Mutex<Option<Handler>> = Mutex::new(None);
static REVIEW_ROUTE: AtomicBool = AtomicBool::new(false);
static PERMISSION: AtomicU8 = AtomicU8::new(0);
unsafe extern "C" {
    fn ch_notifications_init(callback: extern "C" fn(), permission: extern "C" fn(u8));
    fn ch_notifications_permission();
    fn ch_notifications_refresh();
    fn ch_notifications_send(revision: u64);
    fn ch_app_active() -> bool;
    fn ch_background_init(
        sleep: extern "C" fn(bool),
        delivery: extern "C" fn(u64, bool),
        allowed: extern "C" fn(u64) -> bool,
    );
    fn ch_login_status() -> u8;
    fn ch_login_set(enabled: bool) -> u8;
    fn ch_app_login_status() -> u8;
    fn ch_app_login_set(enabled: bool) -> u8;
    fn ch_fingerprint(key: *const u8, bytes: *const u8, length: usize, shared: bool, out: *mut u8);
}

/// What the background agent last reported, read from the shared state.
#[derive(Default, Serialize, Clone)]
struct Health {
    /// Whether the agent's process is alive.
    running: bool,
    last_scan: Option<String>,
    /// When the last full pass finished, and folders the current one has left.
    full_pass: Option<String>,
    left: usize,
    /// Places the last full pass did not read.
    unread: usize,
    error: Option<String>,
}

/// Whether the helper runs: a process of ours, other than this one, has the
/// number the helper saved when it started, and runs this program. Nothing
/// clears that number when the helper ends, and any process can be given
/// it later.
fn helper_running(pid: u32) -> bool {
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // SAFETY: getpid has no preconditions and cannot fail.
    if pid <= 0 || pid == unsafe { libc::getpid() } {
        return false;
    }
    // SAFETY: signal 0 only tests whether the process exists and is ours.
    if unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
    let mut path = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let Ok(size) = u32::try_from(path.len()) else {
        return false;
    };
    // SAFETY: the buffer is writable for the size passed, the most
    // proc_pidpath writes.
    let length = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), size) };
    let Some(path) = usize::try_from(length).ok().and_then(|n| path.get(..n)) else {
        return false;
    };
    let path = path.split(|b| *b == 0).next().unwrap_or_default();
    if path.is_empty() {
        return false;
    }
    // The program's own file, compared and never opened. The helper runs
    // the app's program; a path may name it through a link.
    let theirs = std::fs::metadata(std::ffi::OsStr::from_bytes(path));
    let ours = std::env::current_exe().and_then(std::fs::metadata);
    matches!((theirs, ours), (Ok(a), Ok(b)) if a.dev() == b.dev() && a.ino() == b.ino())
}

/// Whether a refusal the helper saved still stands. One that an older
/// build's pass saved, for a place this build leaves out, would be shown
/// until the next weekly pass. Paths are saved below the home as `~/…`.
fn still_unread(path: &str, reason: &str) -> bool {
    reason != "permission-denied"
        || !path
            .strip_prefix("~/")
            .is_some_and(|rel| scan::not_tried(Path::new(rel)))
}

/// The helper's count of places it couldn't read, less the saved ones that
/// no longer stand.
fn unread_count(agent: &review::Agent) -> usize {
    let gone = agent.unread_places.as_ref().map_or(0, |snapshot| {
        snapshot
            .places
            .iter()
            .filter(|(path, reason)| !still_unread(path, reason))
            .count()
    });
    agent.unread.saturating_sub(gone)
}

fn health(agent: &review::Agent) -> Health {
    Health {
        running: helper_running(agent.pid),
        last_scan: agent.last_check.clone(),
        full_pass: agent.baseline.clone(),
        left: agent.left,
        unread: unread_count(agent),
        error: agent.error.clone(),
    }
}

/// Details are read on demand; frequent status polls carry only counts.
#[derive(Serialize)]
struct AutomaticCoverage {
    full_pass: Option<String>,
    unread: usize,
    unread_gaps: Option<Vec<GapView>>,
    unread_truncated: bool,
}

fn automatic_coverage(agent: &review::Agent) -> AutomaticCoverage {
    AutomaticCoverage {
        full_pass: agent.baseline.clone(),
        unread: unread_count(agent),
        unread_gaps: agent.unread_places.as_ref().map(|snapshot| {
            let mut grouped = std::collections::BTreeMap::<&str, Vec<String>>::new();
            for (path, reason) in snapshot.places.iter().filter(|(p, r)| still_unread(p, r)) {
                grouped
                    .entry(reason)
                    .or_default()
                    .push(report::escape(path));
            }
            grouped
                .into_iter()
                .map(|(reason, paths)| {
                    // Kept by the helper, which never runs as root.
                    let (label, help) = gap_text(reason, false);
                    GapView {
                        label: report::escape(label),
                        help: help.to_owned(),
                        count: paths.len(),
                        paths,
                    }
                })
                .collect()
        }),
        unread_truncated: agent.unread_places.as_ref().is_some_and(|p| p.truncated),
    }
}

/// Change the shared state on disk as one step, and keep this app's copy
/// current. The agent may have changed the state since this app last read it.
fn update_state<T>(app: &App, change: impl FnOnce(&mut review::Review) -> T) -> Answer<T> {
    try_update_state(app, |state| Ok(change(state)))
}

/// As `update_state`, for a change the command can refuse. A refusal saves
/// nothing, leaves this app's copy as it was and is not a storage failure.
/// A store that could not be read or locked is a failure to read, which a
/// later read that works clears: the change was never made, and the command
/// says it failed.
fn try_update_state<T>(
    app: &App,
    change: impl FnOnce(&mut review::Review) -> Answer<T>,
) -> Answer<T> {
    let store = app.store.as_ref().map_err(Clone::clone)?;
    let (mut refused, mut made) = (false, false);
    let result = store.update(|state| {
        let out = change(state);
        (refused, made) = (out.is_err(), out.is_ok());
        out
    });
    match result {
        Ok((state, out)) => {
            *app.review.lock().unwrap() = state;
            Ok(out)
        }
        Err(e) if refused => Err(e),
        Err(e) => {
            let mut error = app.storage_error.lock().unwrap();
            *error = Some(e.clone());
            if made {
                app.storage_unsaved.store(true, Ordering::SeqCst);
            }
            drop(error);
            Err(e)
        }
    }
}

/// As `try_update_state`, for a change that may find nothing to do: one that
/// answers `Ok(false)` takes the refusal path, so nothing is saved and the
/// helper is not woken, and the command succeeds.
fn update_if_changed(
    app: &App,
    change: impl FnOnce(&mut review::Review) -> Answer<bool>,
) -> Answer<()> {
    let mut unchanged = false;
    let saved = try_update_state(app, |state| match change(state) {
        Ok(false) => {
            unchanged = true;
            Err(String::new())
        }
        changed => changed.map(drop),
    });
    if unchanged {
        return Ok(());
    }
    saved
}

/// Save the shared state as it is, which wakes the helper and makes the
/// fingerprint key where there is none. Nothing of the person's changes, so
/// a save that fails loses nothing and is no storage error: the caller
/// decides what to say.
fn save_unchanged(app: &App) -> Answer<review::Review> {
    let store = app.store.as_ref().map_err(Clone::clone)?;
    let (state, ()) = store.update(|_| Ok(()))?;
    *app.review.lock().unwrap() = state.clone();
    Ok(state)
}

/// The shared state as the store has it now, with what the agent has written
/// since this app last looked. A command answers from the state it is handed
/// here, never from the app's copy after it: commands run at once, and a
/// read that began before a change may be the last to leave its state in the
/// copy. The copy is what is left to answer from once the store cannot be
/// read. A read that works clears an error from an earlier read, and not
/// one from a change that could not be saved.
fn refresh_state(app: &App) -> review::Review {
    let unsaved = {
        let error = app.storage_error.lock().unwrap();
        error.is_some() && app.storage_unsaved.load(Ordering::SeqCst)
    };
    if !unsaved {
        if let Ok(store) = &app.store {
            match store.read() {
                Ok(state) => {
                    *app.review.lock().unwrap() = state.clone();
                    let mut error = app.storage_error.lock().unwrap();
                    if !app.storage_unsaved.load(Ordering::SeqCst) {
                        *error = None;
                    }
                    return state;
                }
                Err(e) => *app.storage_error.lock().unwrap() = Some(e),
            }
        }
    }
    app.review.lock().unwrap().clone()
}

#[derive(Serialize)]
struct MonitorView {
    enabled: bool,
    paused: bool,
    login: u8,
    menu_bar: bool,
    /// The app itself in Login Items, with the same codes as `login`.
    app_login: u8,
    /// May the window check GitHub for a newer version: null until asked.
    update_check: Option<bool>,
    health: Health,
    error: Option<String>,
    pending_delivery: bool,
    attempts: u8,
    results: Option<ResultsView>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn material_fingerprint(rule: &str, key: &[u8], bytes: &[u8], shared: bool) -> String {
    let material = rules::material(rule, bytes);
    // ch_fingerprint reads 32 bytes of key without being told a length.
    assert_eq!(key.len(), 32, "the fingerprint key is 32 bytes");
    let mut digest = [0u8; 32];
    // SAFETY: the key is 32 bytes, as just asserted; `material` is read for
    // the length given; `digest` has room for the 32 bytes that are written.
    unsafe {
        ch_fingerprint(
            key.as_ptr(),
            material.as_ptr(),
            material.len(),
            shared,
            digest.as_mut_ptr(),
        );
    }
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn monitor_status(app: &App) -> MonitorView {
    let r = refresh_state(app);
    // Each copied out on its own, so no lock is held while another is taken.
    let error = app.storage_error.lock().unwrap().clone();
    let results = app.report.lock().unwrap().as_ref().map(results_view);
    MonitorView {
        enabled: r.monitoring,
        paused: r.paused,
        // SAFETY: takes no argument and touches no memory of ours.
        login: unsafe { ch_login_status() },
        menu_bar: !r.menu_bar_off,
        // SAFETY: takes no argument and touches no memory of ours.
        app_login: unsafe { ch_app_login_status() },
        update_check: r.update_check,
        health: health(&r.agent),
        error: error.or_else(|| {
            r.full.then(|| {
                "Worth Reviewing is full, so some findings aren't in it. Fix some items, then scan again.".to_string()
            })
        }),
        pending_delivery: r.items.iter().any(|i| r.alerting(i, now())),
        attempts: r.attempts,
        results,
    }
}

fn set_monitoring(app: &App, enabled: bool, paused: bool) -> Answer<()> {
    // SAFETY: takes no argument and touches no memory of ours.
    let status = unsafe { ch_login_status() };
    set_monitoring_with_login(
        app,
        enabled,
        paused,
        status,
        |on| {
            // SAFETY: the bridge takes a bool and borrows no Rust memory.
            unsafe { ch_login_set(on) }
        },
        // SAFETY: takes no argument and touches no memory of ours.
        || unsafe { ch_app_login_status() },
        |on| {
            // SAFETY: the bridge takes a bool and borrows no Rust memory.
            unsafe { ch_app_login_set(on) }
        },
    )
}

/// The injected native operations let tests exercise consent and registration
/// together without registering a helper or scanning the test account's home.
fn set_monitoring_with_login(
    app: &App,
    enabled: bool,
    paused: bool,
    mut status: u8,
    mut set_login: impl FnMut(bool) -> u8,
    app_status: impl FnOnce() -> u8,
    set_app_login: impl FnMut(bool) -> u8,
) -> Answer<()> {
    if app.storage_error.lock().unwrap().is_some() {
        return Err(
            "Automatic scanning cannot start because Loose Keys could not open its saved data."
                .into(),
        );
    }
    if scan::is_root() {
        return Err("Automatic scanning is not available when running as root.".into());
    }
    let one_change = app.app_login.lock().unwrap();
    let (was_enabled, menu_bar) = update_state(app, |state| {
        let was_enabled = state.monitoring;
        state.monitoring = enabled;
        state.paused = paused;
        (was_enabled, !state.menu_bar_off)
    })?;
    let helper = 'helper: {
        // Registration survives a state reset or a launchctl bootout. New consent
        // refreshes an already-approved registration; it is not proof that the
        // job is loaded. Pause/resume leaves an existing registration alone.
        if enabled && !was_enabled && status == 2 {
            status = set_login(false);
            if status != 1 {
                break 'helper Err("macOS could not restart the background helper. If Settings says it is not running, use Restart Helper there.".into());
            }
        }
        // Do not repeat a request awaiting approval, but withdrawing consent must
        // unregister that pending request too. Native failures are never success.
        if !matches!((enabled, status), (true, 2 | 3) | (false, 1)) {
            status = set_login(enabled);
        }
        if matches!((enabled, status), (true, 2 | 3) | (false, 1)) {
            Ok(())
        } else if enabled {
            // Consent is kept, so Settings offers Restart Helper.
            Err("macOS could not start the background helper. Use Restart Helper in Settings, or check System Settings > General > Login Items.".into())
        } else {
            Err("macOS could not stop the background helper. Check System Settings > General > Login Items.".into())
        }
    };
    let login = reconcile_app_login(enabled && menu_bar, app_status(), set_app_login);
    drop(one_change);
    emit(c"monitor-status", ());
    // The helper's failure is the one to report: it stops the checks.
    helper.and(login)
}

/// The app opens at login, in the menu bar, only while it is wanted there:
/// Show in Menu Bar and background checks both on. `status` has the codes of
/// `ch_app_login_status`. A request awaiting approval is not repeated.
fn reconcile_app_login(want: bool, status: u8, mut set: impl FnMut(bool) -> u8) -> Answer<()> {
    let status = match (want, status) {
        (true, 1 | 4) => set(true),
        (false, 2 | 3) => set(false),
        _ => return Ok(()),
    };
    if matches!((want, status), (true, 2 | 3) | (false, 1)) {
        Ok(())
    } else {
        Err("macOS could not change Loose Keys in Login Items. Check System Settings > General > Login Items.".into())
    }
}

fn set_menu_bar(app: &App, enabled: bool) -> Answer<()> {
    // SAFETY: takes no argument and touches no memory of ours.
    let status = || unsafe { ch_app_login_status() };
    set_menu_bar_with_login(app, enabled, status, |on| {
        // SAFETY: the bridge takes a bool and borrows no Rust memory.
        unsafe { ch_app_login_set(on) }
    })
}

fn set_menu_bar_with_login(
    app: &App,
    enabled: bool,
    status: impl FnOnce() -> u8,
    set: impl FnMut(bool) -> u8,
) -> Answer<()> {
    if app.storage_error.lock().unwrap().is_some() {
        return Err(
            "The menu bar setting cannot be saved because Loose Keys could not open its saved data."
                .into(),
        );
    }
    let one_change = app.app_login.lock().unwrap();
    let monitoring = update_state(app, |state| {
        state.menu_bar_off = !enabled;
        state.monitoring
    })?;
    let login = reconcile_app_login(enabled && monitoring && !scan::is_root(), status(), set);
    drop(one_change);
    emit(c"monitor-status", ());
    login
}

fn set_update_check(app: &App, enabled: bool) -> Answer<()> {
    if scan::is_root() {
        return Err("Not available when running as root.".into());
    }
    if app.storage_error.lock().unwrap().is_some() {
        return Err(
            "The update setting cannot be saved because Loose Keys could not open its saved data."
                .into(),
        );
    }
    let store = app.store.as_ref().map_err(Clone::clone)?;
    try_update_state(app, |state| {
        store.keep_update_answer(enabled)?;
        state.update_check = Some(enabled);
        Ok(())
    })?;
    emit(c"monitor-status", ());
    Ok(())
}

fn set_login_startup(app: &App, enabled: bool) -> Answer<u8> {
    set_login_startup_with(app, enabled, |on| {
        // SAFETY: takes a bool and touches no memory of ours.
        unsafe { ch_login_set(on) }
    })
}

/// Restart Helper changes the registration `set_monitoring_with_login`
/// changes, so it holds the same lock: checks turned off while it runs are
/// not followed by the helper registered again.
fn set_login_startup_with(
    app: &App,
    enabled: bool,
    set_login: impl FnOnce(bool) -> u8,
) -> Answer<u8> {
    let unreadable = || {
        app.storage_error.lock().unwrap().is_some().then(|| {
            "Automatic scanning cannot start because Loose Keys could not open its saved data."
                .to_string()
        })
    };
    if let Some(error) = unreadable() {
        return Err(error);
    }
    if scan::is_root() {
        return Err("Automatic scanning is not available when running as root.".into());
    }
    let one_change = app.app_login.lock().unwrap();
    let monitoring = refresh_state(app).monitoring;
    if let Some(error) = unreadable() {
        return Err(error);
    }
    if enabled && !monitoring {
        return Err("Turn on Scan Automatically first.".into());
    }
    let status = set_login(enabled);
    drop(one_change);
    Ok(status)
}

/// What quitting needs first: a running scan is cancelled and no other starts.
/// The front end then ends the process.
fn prepare_quit(app: &App) {
    app.monitor.stop();
}

fn cancel_scan(app: &App) {
    app.monitor.cancel.store(true, Ordering::SeqCst);
}

/// The review notification was clicked. The front end brings its window
/// forward; the next `pending_review` says to show the list.
extern "C" fn open_review() {
    REVIEW_ROUTE.store(true, Ordering::SeqCst);
    emit(c"open-review", ());
}

/// Called on the notifications' own queue, outside `call`: a panic ends
/// here, and the save waits for the store on a thread of its own.
extern "C" fn notification_permission(value: u8) {
    let _ = std::panic::catch_unwind(|| {
        let was = PERMISSION.swap(value, Ordering::SeqCst);
        emit(c"notification-permission", value);
        if newly_allowed(was, value) {
            if let Some(app) = APP.get() {
                let _ = std::thread::Builder::new().spawn(move || wake_helper(app));
            }
        }
    });
}

/// The helper is started by consent, which comes before notifications are
/// allowed, and is not told of it. A change to the shared state wakes it,
/// and it asks macOS again when it has something to send. Nothing is saved
/// while the state cannot be read.
fn wake_helper(app: &App) {
    let woken = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        app.ready();
        if app.storage_error.lock().unwrap().is_none() {
            let _ = save_unchanged(app);
        }
    }));
    if woken.is_err() {
        app.recover();
    }
}

/// Whether notifications have just been allowed in this app: an answer that
/// follows another one. Not the first answer after a start, which says only
/// how things already stood.
fn newly_allowed(was: u8, now: u8) -> bool {
    now == 3 && !matches!(was, 0 | 3)
}

fn enable_notifications() {
    unsafe {
        ch_notifications_permission();
    }
}

/// Asks macOS again whether notifications are allowed, as when the window
/// comes forward after a change in System Settings. The answer comes back as
/// a `notification-permission` event.
fn refresh_notifications() {
    // SAFETY: takes nothing and touches no memory of ours.
    unsafe { ch_notifications_refresh() }
}

/// One credential, or one finding with no single value, as the app shows it.
#[derive(Serialize)]
struct ReviewItem {
    #[serde(flatten)]
    item: review::Item,
    /// "review" for one worth reviewing, "inventory" for a stored sign-in.
    kind: &'static str,
    /// "open", "set-aside" or "fixed". A stored sign-in is never "fixed":
    /// one no longer found is not listed.
    state: &'static str,
    /// Why it was set aside, using review::Reason's fixed serialized names.
    set_aside: Option<review::Reason>,
    /// When the decision behind `set_aside` was made.
    set_aside_at: Option<String>,
    /// Every place the same credential is stored, this one included.
    places: Vec<PlaceView>,
    /// The folder a "stop checking this folder" would name, if one may be.
    /// None for a stored sign-in.
    folder: Option<String>,
    /// Whether the app will act on this file: show it, or copy its path.
    actionable: bool,
}

#[derive(Serialize)]
struct PlaceView {
    id: u64,
    path: String,
    line: Option<usize>,
    fixed: bool,
    /// Still there, and set aside by a decision that covers this place.
    set_aside: bool,
    /// Determined from the unescaped name; item_path checks it again on use.
    actionable: bool,
}

/// Of what is worth reviewing, except `stored` and `stored_set_aside`.
#[derive(Serialize, Default)]
struct Counts {
    open: usize,
    set_aside: usize,
    fixed: usize,
    /// Stored sign-ins still to look at, and those set aside.
    stored: usize,
    stored_set_aside: usize,
    /// Stored sign-ins saved but no longer found, which are not listed, so
    /// the window can tell a list emptied by them from one never filled.
    stored_gone: usize,
}

#[derive(Serialize)]
struct ReviewView {
    items: Vec<ReviewItem>,
    counts: Counts,
    /// Folders not checked at the person's request. Always shown.
    skipped: Vec<String>,
    /// Why the list could not be read or saved. It is then not what was found.
    error: Option<String>,
    /// A finding was left out for lack of room, and no scan the person ran
    /// to its end has since found room on the list.
    full: bool,
    /// The same, for stored sign-ins, which have a share of the room.
    stored_full: bool,
    /// Whether a manual scan or the helper's full pass has ended since
    /// stored sign-ins were saved, so that each was looked for.
    stored_checked: bool,
    route: bool,
    permission: &'static str,
}

/// The folder holding an item, if skipping it is allowed: not the home folder.
fn folder_of(path: &str) -> Option<&str> {
    let (folder, _) = path.rsplit_once('/')?;
    (folder.starts_with("~/") && folder.len() > 2).then_some(folder)
}

/// The folder to offer for an item, as the front end may show it: one that
/// `skip_folder` would accept. The folder is a separate question from the
/// file, so a plain folder is offered whatever the file in it is called.
fn offered_folder(path: &str) -> Option<String> {
    folder_of(path).filter(|f| plain(f)).map(report::escape)
}

/// A stored item as the front end may have it: its names and text escaped,
/// and without the fingerprint, the digest and what is kept about the file's
/// volume, which stay on this side.
fn shown(item: &review::Item) -> review::Item {
    let mut shown = item.clone();
    shown.path = report::escape(&shown.path);
    shown.reason = shown.reason.as_ref().map(|s| report::escape(s));
    // What the scanner writes here is printable already; the store is a
    // file other programs can edit.
    shown.subject = shown.subject.as_ref().map(|s| report::escape(s));
    shown.detail = shown.detail.as_ref().map(|s| report::escape(s));
    for text in [
        &mut shown.rule,
        &mut shown.title,
        &mut shown.explanation,
        &mut shown.severity,
    ]
    .into_iter()
    .chain(&mut shown.steps)
    .chain(shown.next_step.as_mut())
    .chain(shown.link.as_mut())
    .chain(shown.token_type.as_mut())
    .chain(shown.first_seen.as_mut())
    .chain(shown.resolved_at.as_mut())
    {
        *text = fixed_text(text);
    }
    (shown.fingerprint, shown.secret, shown.mount, shown.scope) = (None, None, None, None);
    shown
}

/// The scanner's own text read back from the store, as the window may have
/// it. That text is printable ASCII, and the window's translations are keyed
/// by it exactly, quotes and all, so it passes as it is. Anything else was
/// not written by the scanner and is escaped.
fn fixed_text(text: &str) -> String {
    if plain(text) {
        text.to_owned()
    } else {
        report::escape(text)
    }
}

/// What is worth reviewing, then the stored sign-ins still found, as the
/// window lists them, and how many of each are in each state.
fn review_items(state: &review::Review) -> (Vec<ReviewItem>, Counts) {
    let at = now();
    let mut counts = Counts::default();
    // What sets aside each item that is still there, looked up once: it is
    // asked several times below, and a lookup goes through every decision.
    let items: Vec<&review::Item> = state.items.iter().collect();
    let decided: Vec<Option<&review::Decision>> = items
        .iter()
        .map(|i| (!i.resolved).then(|| state.decision(i, at)).flatten())
        .collect();
    let mut out = entries(&items, &decided, "review");
    for entry in &out {
        match entry.state {
            "fixed" => counts.fixed += 1,
            "set-aside" => counts.set_aside += 1,
            _ => counts.open += 1,
        }
    }
    let stored: Vec<&review::Item> = state.stored.items.iter().filter(|i| !i.resolved).collect();
    counts.stored_gone = state.stored.items.len() - stored.len();
    let decided: Vec<Option<&review::Decision>> = stored
        .iter()
        .map(|i| state.decision_stored(i, at))
        .collect();
    for mut entry in entries(&stored, &decided, "inventory") {
        match entry.state {
            "set-aside" => counts.stored_set_aside += 1,
            _ => counts.stored += 1,
        }
        entry.folder = None;
        out.push(entry);
    }
    (out, counts)
}

/// `items` as entries of the window's list, with `decided` holding what
/// sets each aside, if anything does.
fn entries(
    items: &[&review::Item],
    decided: &[Option<&review::Decision>],
    kind: &'static str,
) -> Vec<ReviewItem> {
    let mut out: Vec<ReviewItem> = Vec::new();
    let mut grouped: std::collections::HashMap<&str, usize> = Default::default();
    for (&item, decision) in items.iter().zip(decided) {
        let place = PlaceView {
            id: item.id,
            path: report::escape(&item.path),
            line: item.line,
            fixed: item.resolved,
            set_aside: decision.is_some(),
            actionable: plain(&item.path),
        };
        // Copies of one credential are one entry with several places.
        if let Some(&n) = item.secret.as_deref().and_then(|s| grouped.get(s)) {
            out[n].places.push(place);
            continue;
        }
        if let Some(secret) = item.secret.as_deref() {
            grouped.insert(secret, out.len());
        }
        out.push(ReviewItem {
            folder: offered_folder(&item.path),
            actionable: plain(&item.path),
            item: shown(item),
            kind,
            state: "open",
            set_aside: None,
            set_aside_at: None,
            places: vec![place],
        });
    }
    for entry in &mut out {
        // Each copy, with the decision that sets it aside.
        let copies: Vec<(&review::Item, Option<&review::Decision>)> = entry
            .places
            .iter()
            .filter_map(|p| items.iter().position(|i| i.id == p.id))
            .map(|n| (items[n], decided[n]))
            .collect();
        let open: Vec<_> = copies
            .iter()
            .filter(|(i, _)| !i.resolved)
            .copied()
            .collect();
        // The entry's path is the one the person is shown and acts on. It is
        // a copy that still needs a decision, or failing that one that is
        // still there: never a fixed copy while another remains. Within each
        // of those, a copy found by its file's own rule, whose title and
        // steps are about that file, before one found by a rule for a kind of
        // value rather than a file (an id starting `secret.`).
        let lead = copies
            .iter()
            .min_by_key(|(i, d)| (i.resolved, d.is_some(), i.rule.starts_with("secret.")));
        if let Some((lead, _)) = lead.filter(|(i, _)| i.id != entry.item.id) {
            entry.item = shown(lead);
            entry.folder = offered_folder(&lead.path);
            entry.actionable = plain(&lead.path);
        }
        // Its risk is the highest of the copies like the lead: those needing
        // a decision, else those set aside, else the fixed ones, which the
        // entry's state comes from too. The lead's title and steps may be
        // those of a rule that rates the value lower than another rule
        // finding it, and nothing may look safer than it is. A copy set
        // aside or fixed while another needs a decision does not count, as
        // it did not when each copy was a row of its own.
        if let Some(&(lead, decision)) = lead {
            let tier = (lead.resolved, decision.is_some());
            let highest = copies
                .iter()
                .filter(|(i, d)| (i.resolved, d.is_some()) == tier)
                .map(|(i, _)| &i.severity)
                .min_by_key(|severity| review::rank(severity));
            entry.item.severity = fixed_text(highest.unwrap_or(&lead.severity));
        }
        // The credential was first seen where it was found first, fixed or
        // not. The same clock writes every date, so text order is time order.
        entry.item.first_seen = items
            .iter()
            .filter(|i| entry.places.iter().any(|p| p.id == i.id))
            .filter_map(|i| i.first_seen.as_deref())
            .min()
            .map(fixed_text);
        let decision = open.iter().find_map(|(_, d)| *d);
        entry.set_aside = decision.map(|d| d.reason);
        // The organization's list was not decided at a time: it has none.
        entry.set_aside_at = decision
            .filter(|d| d.reason != review::Reason::Expected)
            .map(|d| fixed_text(&d.decided));
        entry.state = if open.is_empty() {
            "fixed"
        } else if open.iter().all(|(_, d)| d.is_some()) {
            "set-aside"
        } else {
            "open"
        };
        entry.item.resolved = entry.state == "fixed";
    }
    out
}

fn pending_review(app: &App) -> ReviewView {
    let state = refresh_state(app);
    let (items, counts) = review_items(&state);
    ReviewView {
        items,
        counts,
        skipped: state
            .skipped
            .iter()
            .map(|s| report::escape(&s.path))
            .collect(),
        error: app.storage_error.lock().unwrap().clone(),
        full: state.full,
        stored_full: state.stored.full,
        stored_checked: state.stored.checked_at.is_some(),
        route: REVIEW_ROUTE.swap(false, Ordering::SeqCst),
        permission: match PERMISSION.load(Ordering::SeqCst) {
            1 => "not requested",
            2 => "denied",
            3 => "allowed",
            4 => "unavailable outside an app bundle",
            5 => "request failed",
            _ => "checking",
        },
    }
}

/// Set an item aside for one of review::Reason's fixed reasons, or undo that.
/// The item is still found and still counted; it stops asking for attention.
/// `revision` is the one the front end drew the item with. The decision is
/// about what the item holds as the store has it now, so it is refused once
/// that is no longer what was shown. The item is the one its entry speaks
/// for. Kept is about a file, so it is recorded for each copy of the value
/// in that file as well, each with its own decision, and moving the entry
/// back returns each; a reason about the value covers every copy already.
/// A refusal for one copy saves nothing for any. A stored sign-in takes
/// Kept alone, and its copies are other stored sign-ins only.
fn decide_review(app: &App, id: u64, revision: u64, reason: Option<review::Reason>) -> Answer<()> {
    if app.storage_error.lock().unwrap().is_some() {
        return Err("Loose Keys could not open its saved data.".into());
    }
    try_update_state(app, |state| {
        state.as_shown(id, revision)?;
        let mut here = std::iter::once(id).chain(state.copies_in_its_file(id));
        match reason {
            Some(review::Reason::Kept) => {
                let (at, stamp) = (now(), report::utc_now());
                here.try_for_each(|id| state.decide(id, review::Reason::Kept, at, stamp.clone()))
            }
            Some(reason) => state.decide(id, reason, now(), report::utc_now()),
            None => {
                here.for_each(|id| state.undo(id));
                Ok(())
            }
        }
    })
}

/// The organization's expected findings, as the window read them from a
/// forced preference. An entry of another shape is dropped on its own, so
/// one typo neither keeps the old list in force nor empties the new one.
/// The engine checks each entry again before saving it, and saves nothing
/// for a list that changes nothing, since the window sends it each time
/// the app comes to the front.
fn set_expected(app: &App, entries: Vec<serde_json::Value>) -> Answer<()> {
    if app.storage_error.lock().unwrap().is_some() {
        return Err("Loose Keys could not open its saved data.".into());
    }
    let list: Vec<review::Expected> = entries
        .into_iter()
        .filter_map(|entry| serde_json::from_value(entry).ok())
        .collect();
    // Compared with the store, which may no longer hold what this app last
    // saved there.
    update_if_changed(app, |state| {
        let changes = state.expected_changes(&list);
        if changes {
            state.set_expected(list);
        }
        Ok(changes)
    })
}

/// Stop checking the folder that holds this item. The front end names an
/// item, never a path. The folder stays listed wherever results are shown.
fn skip_folder(app: &App, id: u64) -> Answer<()> {
    if app.storage_error.lock().unwrap().is_some() {
        return Err("Loose Keys could not open its saved data.".into());
    }
    let home = app.home.clone().map_err(|e| e.to_string())?;
    try_update_state(app, |state| {
        let item = state
            .items
            .iter()
            .find(|i| i.id == id)
            .ok_or("That item is no longer in the list.")?;
        let folder = folder_of(&item.path).ok_or("The home folder cannot be skipped.")?;
        let real = full_path(folder, Some(&home)).ok_or("That folder's name cannot be used.")?;
        scan::skipped_folder(real.as_os_str(), &home).map_err(|e| format!("Cannot skip: {e}."))?;
        if !state.skips(folder) {
            if state.skipped.len() >= review::MAX_SKIPS {
                return Err("Too many folders are skipped. Remove one first.".to_string());
            }
            let (path, added) = (folder.to_string(), report::utc_now());
            state.skipped.push(review::Skip { path, added });
        }
        Ok(())
    })
}

/// `index` is the folder's place in the list the front end drew, and `shown`
/// the text it drew there. A press that arrives after the list has moved up
/// names the wrong place, so it is acted on only while the two still agree.
fn unskip_folder(app: &App, index: usize, shown: String) -> Answer<()> {
    if app.storage_error.lock().unwrap().is_some() {
        return Err("Loose Keys could not open its saved data.".into());
    }
    update_if_changed(app, |state| {
        let there = state.skipped.get(index);
        let named = there.is_some_and(|skip| report::escape(&skip.path) == shown);
        if named {
            state.skipped.remove(index);
        }
        Ok(named)
    })
}

/// The real paths of the folders the person asked not to be checked.
fn skipped_paths(state: &review::Review, home: &Path) -> Vec<PathBuf> {
    state
        .honoured_skips()
        .filter_map(|s| full_path(&s.path, Some(home)))
        .collect()
}

fn retry_notifications(app: &App) -> Answer<()> {
    if app.storage_error.lock().unwrap().is_some() {
        return Err("Loose Keys could not open its saved data.".into());
    }
    // The agent sees the state change and tries again.
    update_state(app, |state| {
        state.attempts = 0;
        state.retry_at = 0;
    })
}

// ---- The C interface (app/Bridge.h) ----

impl App {
    /// The state for one home folder. Its review store is opened and not yet
    /// read: reading waits while the background agent holds the store, and
    /// the front end starts the app on its main thread.
    fn open(home: Result<PathBuf, &'static str>) -> Self {
        let store = home
            .as_ref()
            .map_err(|e| e.to_string())
            .and_then(|h| review::Store::open(h));
        App {
            monitor: monitor::Monitor::new(false, false),
            home,
            report: Mutex::new(None),
            scanning: AtomicBool::new(false),
            review: Mutex::new(review::Review::default()),
            store,
            storage_error: Mutex::new(None),
            storage_unsaved: AtomicBool::new(false),
            app_login: Mutex::new(()),
            rechecks: RECHECKS,
            read: OnceLock::new(),
        }
    }

    /// Read the store, once, before the first command runs.
    fn ready(&self) {
        self.ready_with(
            // SAFETY: takes no argument and touches no memory of ours.
            || unsafe { ch_app_login_status() },
            // SAFETY: the bridge takes a bool and borrows no Rust memory.
            |on| unsafe { ch_app_login_set(on) },
        );
    }

    /// Also removes the app from Login Items when the state says it is not
    /// wanted there: a registration outlives a state reset. Every other
    /// command waits for this, so none changes the settings meanwhile.
    fn ready_with(&self, app_login: impl FnOnce() -> u8, set_app_login: impl FnMut(bool) -> u8) {
        self.read.get_or_init(|| {
            let loaded = self
                .store
                .as_ref()
                .map_err(Clone::clone)
                .and_then(review::Store::read);
            let storage_error = loaded.as_ref().err().cloned();
            let loaded = loaded.unwrap_or_default();
            let wanted = loaded.monitoring && !loaded.menu_bar_off && !scan::is_root();
            *self.review.lock().unwrap() = loaded;
            let readable = storage_error.is_none();
            *self.storage_error.lock().unwrap() = storage_error;
            // Only taken away: one the person removed is not added back. A
            // failure shows in Settings, which reads the status again.
            if readable && !wanted {
                let _ = reconcile_app_login(false, app_login(), set_app_login);
            }
        });
    }

    /// After a command panicked: let later ones take the locks it held. What
    /// each guards is only ever replaced whole, so none is left half-made.
    fn recover(&self) {
        self.report.clear_poison();
        self.review.clear_poison();
        self.storage_error.clear_poison();
        self.app_login.clear_poison();
    }
}

/// Tell the front end something happened. Its function runs on this thread
/// and outside the lock, so it may call back in.
fn emit(name: &CStr, payload: impl Serialize) {
    let Some(handler) = *EVENTS.lock().unwrap() else {
        return;
    };
    // JSON text has no NUL in it.
    if let Some(payload) = serde_json::to_string(&payload)
        .ok()
        .and_then(|json| CString::new(json).ok())
    {
        handler(name.as_ptr(), payload.as_ptr());
    }
}

/// A command's arguments: the JSON object the front end sent.
struct Args(serde_json::Map<String, serde_json::Value>);

impl Args {
    /// One argument by name. A missing one reads as null, which only an
    /// optional argument accepts.
    fn get<'a, T: Deserialize<'a>>(&'a self, name: &str) -> Answer<T> {
        T::deserialize(self.0.get(name).unwrap_or(&serde_json::Value::Null))
            .map_err(|_| format!("The request has no usable \"{name}\"."))
    }
}

/// A command's result as JSON text.
fn done(out: impl Serialize) -> Answer<String> {
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

fn dispatch(app: &App, command: &str, args: &Args) -> Answer<String> {
    match command {
        "places" => done(places(app)),
        "type_place" => done(type_place(app, args.get("text")?)),
        "remove_place" => done(remove_place(app, args.get("index")?, args.get("shown")?)),
        "start_scan" => done(start_scan(app)?),
        "prepare_access" => done(prepare_access(app, args.get("index")?)?),
        "save_report" => done(save_report(app, args.get("path")?, args.get("feedback")?)?),
        "summary_text" => done(summary_text(app)?),
        "item_path" => done(item_path(app, args.get("index")?)?),
        "open_link" => done(open_link(args.get("url")?)?),
        "decide_review" => done(decide_review(
            app,
            args.get("id")?,
            args.get("revision")?,
            args.get("reason")?,
        )?),
        "set_expected" => done(set_expected(app, args.get("entries")?)?),
        "skip_folder" => done(skip_folder(app, args.get("id")?)?),
        "unskip_folder" => done(unskip_folder(app, args.get("index")?, args.get("shown")?)?),
        "check_release" => done(release::check(
            &args.get::<String>("body")?,
            env!("CARGO_PKG_VERSION"),
        )?),
        "pending_review" => done(pending_review(app)),
        "retry_notifications" => done(retry_notifications(app)?),
        "enable_notifications" => {
            enable_notifications();
            done(())
        }
        "refresh_notifications" => {
            refresh_notifications();
            done(())
        }
        "monitor_status" => done(monitor_status(app)),
        "automatic_coverage" => {
            let state = refresh_state(app);
            if app.storage_error.lock().unwrap().is_some() {
                return Err("Loose Keys could not open its saved data.".into());
            }
            done(automatic_coverage(&state.agent))
        }
        "set_monitoring" => done(set_monitoring(
            app,
            args.get("enabled")?,
            args.get("paused")?,
        )?),
        "set_login_startup" => done(set_login_startup(app, args.get("enabled")?)?),
        "set_menu_bar" => done(set_menu_bar(app, args.get("enabled")?)?),
        "set_update_check" => done(set_update_check(app, args.get("enabled")?)?),
        "prepare_quit" => {
            prepare_quit(app);
            done(())
        }
        "cancel_scan" => {
            cancel_scan(app);
            done(())
        }
        other => Err(format!("Unknown command: {}.", report::escape(other))),
    }
}

/// An answer as Bridge.h words it: `{"ok": value}` or `{"error": text}`.
fn reply(answer: Answer<String>) -> String {
    match answer {
        Ok(value) => format!("{{\"ok\":{value}}}"),
        Err(text) => serde_json::json!({ "error": text }).to_string(),
    }
}

/// Run one command by the name and arguments the front end sent.
fn call(app: Option<&App>, command: &str, args: &str) -> String {
    let run = || -> Answer<String> {
        let app = app.ok_or("The app has not started.")?;
        // Quitting needs nothing from the store and must not wait for it.
        if command != "prepare_quit" {
            app.ready();
        }
        let args = serde_json::from_str(args)
            .map_err(|_| "The request's arguments are not a JSON object.")?;
        dispatch(app, command, &Args(args))
    };
    // A panic ends here, as one failed command. It never unwinds into the
    // front end's code.
    let answer = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).unwrap_or_else(|_| {
        if let Some(app) = app {
            app.recover();
        }
        Err(match command {
            "start_scan" => "The scan stopped unexpectedly.",
            _ => "That action stopped unexpectedly.",
        }
        .into())
    });
    reply(answer)
}

/// Start the app side: notifications, and the state every command works on.
#[unsafe(no_mangle)]
pub extern "C" fn ch_app_start(review_route: bool) {
    // The agent opens the app this way when its notification is clicked.
    if review_route {
        REVIEW_ROUTE.store(true, Ordering::SeqCst);
    }
    // The state first, so no event arrives before commands work. The first
    // command reads the store, off this thread.
    APP.get_or_init(|| App::open(scan::home()));
    // Install the delegate before macOS finishes launching the app.
    unsafe {
        ch_notifications_init(open_review, notification_permission);
    }
}

/// # Safety
/// `command` and `args` are each null or a NUL-terminated string that stays
/// valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ch_call(command: *const c_char, args: *const c_char) -> *mut c_char {
    let text = |at: *const c_char| {
        // SAFETY: not null, and the caller promises a NUL-terminated string.
        (!at.is_null())
            .then(|| unsafe { CStr::from_ptr(at) })?
            .to_str()
            .ok()
    };
    let answer = match (text(command), text(args)) {
        (Some(command), Some(args)) => call(APP.get(), command, args),
        _ => reply(Err("The request is not valid text.".into())),
    };
    // JSON text has no NUL in it.
    CString::new(answer).unwrap_or_default().into_raw()
}

/// # Safety
/// `text` is null or came from `ch_call` and has not been released yet.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ch_free(text: *mut c_char) {
    if !text.is_null() {
        // SAFETY: `ch_call` made it with `CString::into_raw`.
        drop(unsafe { CString::from_raw(text) });
    }
}

/// Where events go from now on. Null for nowhere.
#[unsafe(no_mangle)]
pub extern "C" fn ch_set_event_handler(handler: Option<Handler>) {
    *EVENTS.lock().unwrap() = handler;
}

/// Run as the background agent: the executable's `--agent` mode, which has
/// no window.
#[unsafe(no_mangle)]
pub extern "C" fn ch_agent_main() -> ! {
    agent::run()
}

// ---- Places to check ----

/// The home folders macOS asks about one at a time, before a scan.
const ACCESS_FOLDERS: [&str; 3] = ["Desktop", "Documents", "Downloads"];

/// A user-initiated preparation step, not a scan or a permission verdict.
/// The fixed locations are already in home scan scope. Listing with a zero
/// entry budget asks macOS for directory access without retaining names or
/// opening file contents. No locks are held across a possible system prompt.
fn prepare_access(app: &App, index: usize) -> Answer<()> {
    let folder = ACCESS_FOLDERS
        .get(index)
        .ok_or("That folder access request is not valid.")?;
    let home = app
        .home
        .as_ref()
        .map_err(|e| format!("Cannot scan: {e}."))?;
    // A denial, absent folder or link must not prevent checking other places.
    // The subsequent scan reads afresh and reports its own gaps; this command
    // neither claims coverage nor caches an authorization result.
    let _ = fsutil::list_dir(&home.join(folder), false, &mut 0);
    Ok(())
}

#[derive(Clone, Serialize)]
struct PlacesView {
    home: Option<String>,
    home_error: Option<&'static str>,
    extra: Vec<String>,
    error: Option<String>,
}

fn places_view(app: &App, error: Option<String>) -> PlacesView {
    let state = refresh_state(app);
    let error = error.or_else(|| app.storage_error.lock().unwrap().clone());
    PlacesView {
        home: app.home.as_ref().ok().map(|h| show(h)),
        home_error: app.home.as_ref().err().copied(),
        extra: state.selected_places.iter().map(|p| show(p)).collect(),
        error,
    }
}

fn show(p: &Path) -> String {
    report::escape(&p.to_string_lossy())
}

fn add_place(app: &App, path: &Path) -> Answer<()> {
    if app.storage_error.lock().unwrap().is_some() {
        return Err("Loose Keys could not open its saved data.".into());
    }
    if app.scanning.load(Ordering::SeqCst) {
        return Err("Wait for the scan to finish.".into());
    }
    let p = scan::selected_root(path.as_os_str())
        .map_err(|e| format!("Cannot add that folder: {e}."))?;
    if !p.to_str().is_some_and(|text| !text.contains('\0')) {
        return Err("That folder's name cannot be used.".into());
    }
    try_update_state(app, |state| {
        if !state.selected_places.contains(&p) && app.home.as_ref() != Ok(&p) {
            if state.selected_places.len() >= review::MAX_SELECTED_PLACES
                || p.as_os_str().len() > review::MAX_SELECTED_PATH_BYTES
            {
                return Err(
                    "You can add up to eight folders. Very long folder paths cannot be added."
                        .into(),
                );
            }
            state.selected_places.push(p);
        }
        Ok(())
    })
}

fn places(app: &App) -> PlacesView {
    places_view(app, None)
}

/// A folder the person picked or dropped on the window, by its path as it
/// is: spaces at either end are part of the name.
fn type_place(app: &App, text: String) -> PlacesView {
    let error = add_place(app, Path::new(&text)).err();
    places_view(app, error)
}

/// As for `unskip_folder`: the place in the list, and what was shown there.
fn remove_place(app: &App, index: usize, shown: String) -> PlacesView {
    if app.storage_error.lock().unwrap().is_some() {
        return places_view(
            app,
            Some("Loose Keys could not open its saved data.".into()),
        );
    }
    let error = update_if_changed(app, |state| {
        if app.scanning.load(Ordering::SeqCst) {
            return Err("Wait for the scan to finish.".into());
        }
        let places = &mut state.selected_places;
        let named = places.get(index).is_some_and(|place| show(place) == shown);
        if named {
            places.remove(index);
        }
        Ok(named)
    })
    .err();
    places_view(app, error)
}

// ---- Scan and results ----

#[derive(Serialize)]
struct ResultsView {
    status: &'static str,
    generated_at: String,
    review: usize,
    stored: usize,
    not_checked: usize,
    gaps: Vec<GapView>,
    /// Which of the folders `prepare_access` asks for the scan was denied,
    /// as fixed words: the person can allow access to these again.
    blocked: Vec<&'static str>,
}

#[derive(Serialize, Clone)]
struct GapView {
    label: String,
    help: String,
    count: usize,
    paths: Vec<String>,
}

fn results_view(r: &Report) -> ResultsView {
    let review = r.findings.iter().filter(|f| f.kind == "review").count();
    let gaps = report::group_gaps(r)
        .into_iter()
        .map(|(reason, paths)| {
            let (label, help) = gap_text(reason, r.context == "system");
            GapView {
                label: label.to_owned(),
                help: help.to_owned(),
                count: paths.len(),
                paths: paths
                    .iter()
                    .take(GAPS_SHOWN)
                    .map(|p| report::escape(p))
                    .collect(),
            }
        })
        .collect();
    let blocked = ACCESS_FOLDERS
        .into_iter()
        .filter(|folder| {
            r.not_checked
                .iter()
                .any(|gap| gap.reason == "permission-denied" && gap.path == format!("~/{folder}"))
        })
        .collect();
    ResultsView {
        status: r.status,
        generated_at: r.generated_at.clone(),
        review,
        stored: r.findings.len() - review,
        not_checked: r.not_checked.len(),
        gaps,
        blocked,
    }
}

/// Returns when the scan ends, so the front end calls it off its main thread.
fn start_scan(app: &App) -> Answer<ResultsView> {
    perform_scan(app)
}

/// Said when the monitor refuses a scan the person asked for. In this process
/// only `prepare_quit` brings that about: nothing here puts the monitor to
/// sleep.
const SCAN_BLOCKED: &str =
    "Loose Keys is quitting, so the scan did not start. Open it again to scan.";

/// Said when the list was replaced during the scan, as when its file is
/// deleted or put back from a copy. The new list has another key, and what
/// the scan found, digested with the old one, would be taken there for
/// other values: marked fixed by the next scan and listed again as news.
const LIST_REPLACED: &str =
    "The review list was replaced during the scan, so nothing it found was saved. Scan again.";

fn perform_scan(app: &App) -> Answer<ResultsView> {
    let home = app.home.clone().map_err(|e| format!("Cannot scan: {e}."))?;
    if app.store.is_err() {
        return Err(
            "Loose Keys could not open its saved data, maybe because another copy of it is running. Scanning is turned off."
                .into(),
        );
    }
    if app.scanning.swap(true, Ordering::SeqCst) {
        return Err("A scan is already running.".into());
    }
    struct Guard<'a>(&'a AtomicBool);
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }
    let _guard = Guard(&app.scanning);
    if !app.monitor.arm(monitor::ScanKind::Manual) {
        return Err(SCAN_BLOCKED.into());
    }
    emit(c"monitor-status", ());
    // The places to check and the folders to leave out are the store's as
    // the scan starts, from one read, for the reason `refresh_state` gives.
    // A store that cannot be read is the save's to report, below: it must
    // not erase the chosen places or cancel a scan, so until then the app's
    // copy has to do.
    let read = app.store.as_ref().ok().and_then(|store| store.read().ok());
    let state = read.unwrap_or_else(|| app.review.lock().unwrap().clone());
    // The store creates the fingerprint key the first time it is saved.
    // Where it cannot be, as when it was unreadable from the start, the scan
    // digests with a key of its own and runs to its end. Its save, below,
    // then saves nothing and says why: the storage error is set, and a store
    // that reads again by then has another key.
    let mut key = state.key.clone();
    if key.is_empty() && app.storage_error.lock().unwrap().is_none() {
        match save_unchanged(app) {
            Ok(saved) => key = saved.key,
            Err(e) => *app.storage_error.lock().unwrap() = Some(e),
        }
    }
    if key.is_empty() {
        key = review::new_key();
    }
    let skip = skipped_paths(&state, &home);
    let made_with = key.clone();
    let r = scan::Scan::report_controlled(
        &home,
        &state.selected_places,
        &skip,
        app.monitor.cancel.clone(),
        move |rule, bytes, shared| material_fingerprint(rule, &key, bytes, shared),
        |p| emit(c"scan-progress", p),
    );
    let view = results_view(&r);
    // Merge into the shared state in one step; the agent may be writing too.
    // The rechecks get their own time, counted once the store is locked:
    // from before the scan, or while the agent held the store, they could
    // have none left, and nothing was marked fixed.
    let unreadable = app.storage_error.lock().unwrap().clone();
    let saved = match unreadable {
        Some(error) => Err(error),
        None => update_state(app, |review| {
            if review.key != made_with {
                return None;
            }
            let rechecking = std::time::Instant::now();
            // ingest only ever sets `full`, so it is cleared here for this
            // scan to decide again, and put back below unless the scan ran to
            // its end and the list has room. The same for stored sign-ins.
            let was_full = std::mem::take(&mut review.full);
            let stored_was_full = std::mem::take(&mut review.stored.full);
            let key = review.key.clone();
            // Asked between items and while one large file is read.
            let stop = || {
                rechecking.elapsed() >= app.rechecks || app.monitor.cancel.load(Ordering::SeqCst)
            };
            let new = review.merge(&r, |item, want| {
                if stop() {
                    return None;
                }
                still_there(item, &home, &key, want, &stop)
            });
            // A cancelled scan says nothing about what was left out before
            // it. One that stopped at a work limit did not present every
            // finding either, so room on the list is what settles it: without
            // room the next finding is left out whatever this scan saw.
            let cancelled = app.monitor.cancel.load(Ordering::SeqCst);
            if was_full && (cancelled || !review.has_room()) {
                review.full = true;
            }
            if stored_was_full && (cancelled || !review.stored_has_room()) {
                review.stored.full = true;
            }
            // Every stored sign-in was looked for, though a work limit may
            // have left some places unread, as the results say.
            if !cancelled {
                review.stored.checked_at = Some(r.generated_at.clone());
            }
            Some(new)
        }),
    };
    // Where nothing was saved, what the scan found and could have marked
    // fixed is lost, so the error stays once the store reads again.
    // A cancelled scan with nothing to list, of either kind, would have
    // changed nothing. A read that worked meanwhile may have cleared the
    // error, which is then put back.
    if let Err(e) = &saved {
        let found = r
            .findings
            .iter()
            .any(|f| matches!(f.kind, "review" | "inventory"));
        if found || !app.monitor.cancel.load(Ordering::SeqCst) {
            let mut error = app.storage_error.lock().unwrap();
            error.get_or_insert_with(|| e.clone());
            app.storage_unsaved.store(true, Ordering::SeqCst);
        }
    }
    let replaced = matches!(saved, Ok(None));
    let new = matches!(saved, Ok(Some(true)));
    if !replaced {
        *app.report.lock().unwrap() = Some(r);
    }
    if new {
        emit(c"review-ready", ());
    }
    drop(_guard);
    emit(c"monitor-status", ());
    if replaced {
        return Err(LIST_REPLACED.into());
    }
    Ok(view)
}

/// Write the report where the person chose, as a new file that only they can
/// read. Returns the saved file's display name.
fn save_report(app: &App, path: String, feedback: bool) -> Answer<String> {
    let json = {
        let r = app.report.lock().unwrap();
        let r = r.as_ref().ok_or("Run a scan first.")?;
        if feedback {
            report::to_feedback_json(r)
        } else {
            report::to_ascii_json(r)
        }
    };
    let path = Path::new(&path);
    if !path.is_absolute() {
        return Err("That location is not a local folder.".into());
    }
    match fsutil::write_export(path, &json, scan::is_root()) {
        Ok(()) => Ok(show(path)),
        Err(e) if e == "file already exists" => Err(
            "A file with that name already exists, and Loose Keys never replaces files. Choose another name.".into(),
        ),
        Err(e) => Err(format!("Could not save: {e}.")),
    }
}

/// The plain-text summary, for the front end to put on the clipboard.
fn summary_text(app: &App) -> Answer<String> {
    let r = app.report.lock().unwrap();
    Ok(report::to_text(
        r.as_ref().ok_or("Run a scan first.")?,
        true,
    ))
}

/// `index` is a listed item's id, worth reviewing or stored.
fn finding_path(app: &App, index: usize) -> Answer<PathBuf> {
    let state = refresh_state(app);
    state
        .locate(index as u64)
        .and_then(|(_, i)| full_path(&i.path, app.home.as_deref().ok()))
        .ok_or_else(|| "This item has no file on this Mac to open.".into())
}

/// The real path of a result, for the front end to copy or to show in the
/// file manager. Its parent must open without following links, and root
/// actions are refused. The path can still change before Finder uses it.
fn item_path(app: &App, index: usize) -> Answer<String> {
    if scan::is_root() {
        return Err("Not available when running as root.".into());
    }
    let path = finding_path(app, index)?;
    let parent = path.parent().ok_or("no folder")?;
    fsutil::open_directory(parent).map_err(|g| format!("Could not open the folder ({g})."))?;
    // Text that had to be repaired would name some other file.
    path.into_os_string().into_string().map_err(|_| {
        "This name has unusual characters, so Loose Keys will not open or copy it.".into()
    })
}

/// One of the fixed issuer pages named in the rules, for the front end to
/// open. Anything else, including a link altered in stored state, is refused.
fn open_link(url: String) -> Answer<String> {
    if scan::is_root() {
        return Err("Not available when running as root.".into());
    }
    if !rules::known_link(&url) {
        return Err("Loose Keys does not open that link.".into());
    }
    Ok(url)
}

/// Whether a name is one the app acts on: printable ASCII and nothing else.
fn plain(name: &str) -> bool {
    name.chars().all(|c| (' '..='~').contains(&c))
}

/// The real path, only for plain printable names: anything else (control
/// characters, bidi overrides, non-UTF-8) is shown escaped and not acted on.
fn full_path(rel: &str, home: Option<&Path>) -> Option<PathBuf> {
    plain(rel).then(|| real_path(rel, home)).flatten()
}

/// A path as results list it, "~/..." or absolute, as the path it stands for.
/// A "~/" name is always below the home: `join` would put an absolute rest,
/// as in "~//Users", in the home's place, and ".." climbs out of it.
fn real_path(rel: &str, home: Option<&Path>) -> Option<PathBuf> {
    match rel.strip_prefix("~/") {
        Some(rest) => {
            let rest = Path::new(rest);
            let below = rest
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_)));
            home.filter(|_| below).map(|h| h.join(rest))
        }
        None if rel.starts_with('/') => Some(PathBuf::from(rel)),
        None => None,
    }
}

/// The real path of a listed item, for reading its file again and for
/// nothing else: it is never handed to the front end, so the name need not
/// be plain. Only a name that could not be listed as it is has none: where
/// bytes that are not UTF-8 were replaced, the text names some other file,
/// and not finding that one would say the credential is gone.
fn recheck_path(rel: &str, home: Option<&Path>) -> Option<PathBuf> {
    let repaired = rel.contains(char::REPLACEMENT_CHARACTER);
    (!repaired).then(|| real_path(rel, home)).flatten()
}

/// What a listed item's file holds now, read again as its rule reads it,
/// with each value's digest under the store's key: what marks an item fixed.
/// Only what a scan would list as `want`'s kind of item counts. None where
/// the file cannot be read again, was listed under a name that does not
/// name it (`recheck_path`), or `stop` said to stop before it was read to
/// its end.
fn still_there(
    item: &review::Item,
    home: &Path,
    key: &[u8],
    want: scan::Want,
    stop: &dyn Fn() -> bool,
) -> Option<review::Still> {
    let path = recheck_path(&item.path, Some(home))?;
    let digest = |rule: &str, bytes: &[u8], shared| material_fingerprint(rule, key, bytes, shared);
    scan::recheck_identities(&item.rule, &path, home, item.mount, &digest, want, stop)
}

/// `root`: the scan ran as root, where no link is followed.
fn gap_text(reason: &str, root: bool) -> (&str, &str) {
    match reason {
        // Labels are headings in the window, so they use title case.
        "permission-denied" => (
            "No Access",
            "macOS privacy protection or file permissions don't let Loose Keys read these. Nearly every Mac has some.",
        ),
        "unreadable" => (
            "Couldn't Be Read",
            "If an app such as a browser is using any of these, quit the app, then scan again.",
        ),
        // The heading says it; the limits are in the usage guide.
        "too-large" => ("Too Large to Check", ""),
        "cloud-only-file" => (
            "Stored Only in the Cloud",
            "Download these to this Mac, then scan again.",
        ),
        // The heading and the list's opening line say it; the limits are in
        // the usage guide.
        "scan-limit" => ("Only Partly Checked", ""),
        "symlink" if root => (
            "Link Not Followed",
            "These sign-in files are links. Loose Keys follows no links when running as root.",
        ),
        "symlink" => (
            "Link Not Followed",
            "These sign-in files are links to places outside your home folder. \
             Loose Keys does not follow such links.",
        ),
        other => (other, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    use crate::detection_corpus as detection;

    #[test]
    fn shared_detection_corpus_matches_manifest() {
        let cli = std::env::var_os("LOOSE_KEYS_DETECTION_CLI").map(PathBuf::from);
        if let Some(binary) = &cli {
            assert!(
                binary.is_absolute(),
                "LOOSE_KEYS_DETECTION_CLI must be absolute"
            );
        }
        let cases = detection::cases();
        for case in &cases {
            for positive in [true, false] {
                let fixture = detection::Fixture::new(case, positive);
                let app = App::open(Ok(fixture.home.clone()));
                app.ready();
                // The shared event handler belongs to the other engine tests.
                let alone = one_scan();
                let result = ask(&app, "start_scan", "{}");
                drop(alone);
                let encoded = serde_json::to_vec(&result).unwrap();
                detection::assert_no_values(&encoded);
                assert!(
                    result.get("ok").is_some(),
                    "engine scan failed for {}",
                    case.name
                );
                let output = fixture.root.join("engine.json");
                let saved = ask(
                    &app,
                    "save_report",
                    &json!({"path":output,"feedback":false}).to_string(),
                );
                assert!(
                    saved.get("ok").is_some(),
                    "engine export failed for {}",
                    case.name
                );
                let engine = case.check(&std::fs::read(output).unwrap(), positive);
                if let Some(binary) = &cli {
                    let report = fixture.cli(binary, case, positive);
                    detection::compare_reports(report, engine, &case.name);
                }
                drop(app);
            }
        }
        if cli.is_some() {
            println!(
                "Compared CLI and engine exports for {} positive and negative cases",
                cases.len()
            );
            println!("PASS: CLI and engine detection parity");
        }
    }

    /// The app's state on a synthetic home folder, as the first command
    /// finds it for the real one.
    pub(crate) fn engine(name: &str) -> (PathBuf, App) {
        let home = std::env::temp_dir().join(format!(
            "credential-engine-test-{}-{name}",
            std::process::id()
        ));
        std::fs::create_dir(&home).unwrap();
        let app = App::open(Ok(home.clone()));
        app.ready();
        (home, app)
    }

    /// One command through the dispatcher, and its answer as the front end
    /// reads it.
    pub(crate) fn ask(app: &App, command: &str, args: &str) -> Value {
        serde_json::from_str(&call(Some(app), command, args)).unwrap()
    }

    #[test]
    fn npm_registry_credentials_do_not_leave_the_engine() {
        let _alone = one_scan();
        let (home, app) = engine("npm-registry-label");
        let password = ["synthetic-userinfo", "private-suffix"].join("-");
        let value = ["synthetic-stored", "value-suffix"].join("-");
        std::fs::write(
            home.join(".npmrc"),
            format!("//fixture:{password}@registry.invalid/:_authToken={value}\n"),
        )
        .unwrap();
        for (file, prefix) in [(".gem/credentials", ""), (".bundle/config", "BUNDLE_")] {
            let path = home.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(
                path,
                format!(
                    "{prefix}https://fixture:{password}@registry.invalid/private-scope: {value}\n"
                ),
            )
            .unwrap();
        }
        SEEN.lock().unwrap().clear();
        ch_set_event_handler(Some(seen));
        let scanned = ask(&app, "start_scan", "{}");
        ch_set_event_handler(None);
        let events = std::mem::take(&mut *SEEN.lock().unwrap());
        let review = ask(&app, "pending_review", "{}");
        let summary = ask(&app, "summary_text", "{}");
        let mut outputs = vec![
            scanned.to_string(),
            review.to_string(),
            summary.to_string(),
            serde_json::to_string(&events).unwrap(),
        ];
        let state = app.store.as_ref().unwrap().read().unwrap();
        let scopes: Vec<_> = state
            .items
            .iter()
            .map(|i| i.scope.clone().expect("registry identity"))
            .collect();
        let saved_state =
            std::fs::read_to_string(home.join(review::STATE_DIR).join("state.json")).unwrap();
        for feedback in [false, true] {
            let export = home.with_extension(if feedback {
                "feedback.json"
            } else {
                "report.json"
            });
            let saved = ask(
                &app,
                "save_report",
                &json!({"path": export, "feedback": feedback}).to_string(),
            );
            assert!(saved.get("ok").is_some());
            outputs.push(saved.to_string());
            outputs.push(std::fs::read_to_string(&export).unwrap());
            std::fs::remove_file(export).unwrap();
        }
        drop(app);
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(scanned["ok"]["review"], 3);
        // The same value in npm's and RubyGems' files is one credential, one
        // item with both places. Bundler's finding records no value.
        let mut copies: Vec<usize> = review["ok"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["places"].as_array().unwrap().len())
            .collect();
        copies.sort();
        assert_eq!(copies, [1, 2]);
        for text in &outputs {
            for scope in &scopes {
                assert!(
                    !text.contains(scope),
                    "private scope digest left through public output"
                );
            }
        }
        outputs.push(saved_state);
        assert!(summary["ok"].as_str().unwrap().contains("registry.invalid"));
        for text in outputs {
            for secret in [&password, &value] {
                for fragment in [secret.as_str(), &secret[..12], &secret[secret.len() - 12..]] {
                    assert!(
                        !text.contains(fragment),
                        "registry credential appeared in engine output or state"
                    );
                }
            }
        }
    }

    #[test]
    fn npm_scopes_on_one_host_keep_separate_decisions() {
        let _alone = one_scan();
        let (home, app) = engine("npm-scope-identity");
        let path = home.join(".npmrc");
        let root = "//registry.invalid/:_authToken=synthetic-root-value\n";
        let a = "//registry.invalid/team-a/:_authToken=synthetic-a-value\n";
        let b = "//registry.invalid/team-b/:_authToken=synthetic-b-value\n";
        std::fs::write(&path, root).unwrap();
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 1);
        let store = app.store.as_ref().unwrap();
        let before = store.read().unwrap();
        let root_id = before.items[0].id;
        let scope = before.items[0].scope.clone();
        std::fs::write(
            &path,
            root.replace("synthetic-root-value", "synthetic-rotated-value"),
        )
        .unwrap();
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 1);
        let rotated = store.read().unwrap();
        assert_eq!(rotated.items.len(), 1);
        assert_eq!(rotated.items[0].id, root_id);
        assert_eq!(
            rotated.items[0].scope, scope,
            "place identity must not include the stored value"
        );
        store
            .update(|state| state.decide(root_id, review::Reason::Kept, now(), "then".into()))
            .unwrap();
        std::fs::write(&path, format!("{root}{a}{b}")).unwrap();
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 3);
        let state = store.read().unwrap();
        assert_eq!(
            state.items.len(),
            3,
            "same-host scopes must remain separate items"
        );
        assert_eq!(
            state
                .items
                .iter()
                .filter(|i| state.decision(i, now()).is_some())
                .count(),
            1,
            "keeping the root must not keep newly found scopes"
        );
        assert_eq!(
            state.items.iter().find(|i| i.id == root_id).unwrap().line,
            Some(1)
        );
        let a_id = state.items.iter().find(|i| i.line == Some(2)).unwrap().id;
        let b_id = state.items.iter().find(|i| i.line == Some(3)).unwrap().id;
        std::fs::write(&path, format!("{b}{root}")).unwrap();
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 2);
        let state = store.read().unwrap();
        assert!(state.items.iter().find(|i| i.id == a_id).unwrap().resolved);
        assert!(!state.items.iter().find(|i| i.id == b_id).unwrap().resolved);
        assert_eq!(
            state.items.iter().find(|i| i.id == b_id).unwrap().line,
            Some(1)
        );
        assert!(state
            .decision(state.items.iter().find(|i| i.id == root_id).unwrap(), now())
            .is_some());
        drop(app);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn other_registry_url_scopes_keep_separate_decisions() {
        let _alone = one_scan();
        for (name, file, prefix) in [
            ("gem-scopes", ".gem/credentials", ""),
            ("bundler-scopes", ".bundle/config", "BUNDLE_"),
        ] {
            let (home, app) = engine(name);
            let path = home.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let a = format!("{prefix}https://registry.invalid/team-a: synthetic-a-value\n");
            let b = format!("{prefix}https://registry.invalid/team-b: synthetic-b-value\n");
            std::fs::write(&path, &a).unwrap();
            assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 1);
            let store = app.store.as_ref().unwrap();
            let id = store.read().unwrap().items[0].id;
            store
                .update(|state| state.decide(id, review::Reason::Kept, now(), "then".into()))
                .unwrap();
            std::fs::write(&path, format!("{b}{a}")).unwrap();
            assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 2);
            let state = store.read().unwrap();
            assert_eq!(
                state.items.len(),
                2,
                "{name}: URL scopes must remain distinct"
            );
            assert_eq!(
                state
                    .items
                    .iter()
                    .filter(|i| state.decision(i, now()).is_some())
                    .count(),
                1
            );
            assert_eq!(
                state.items.iter().find(|i| i.id == id).unwrap().line,
                Some(2)
            );
            drop(app);
            std::fs::remove_dir_all(home).unwrap();
        }
    }

    #[test]
    fn migrated_registry_collisions_stay_separate_after_rescanning() {
        let _alone = one_scan();
        let (home, app) = engine("migrated-registry-collisions");
        let config = home.join(".npmrc");
        let entries = "//registry.invalid/team-a/:_authToken=synthetic-a-value\n//registry.invalid/team-b/:_authToken=synthetic-b-value\n";
        std::fs::write(&config, entries).unwrap();
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 2);
        let store = app.store.as_ref().unwrap();
        store
            .update(|state| {
                let id = state.items[0].id;
                state.decide(id, review::Reason::Kept, now(), "then".into())
            })
            .unwrap();
        let path = home.join(review::STATE_DIR).join("state.json");
        let mut legacy: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        legacy.as_object_mut().unwrap().remove("registry_labels");
        for item in legacy["items"].as_array_mut().unwrap() {
            item.as_object_mut().unwrap().remove("scope");
            item["subject"] = json!("fixture:synthetic-legacy-private-tail@registry.invalid/team");
        }
        std::fs::write(&path, legacy.to_string()).unwrap();
        let pending = ask(&app, "pending_review", "{}");
        assert!(!pending.to_string().contains("legacy-private"));
        assert!(store.read().unwrap().decisions.is_empty());
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 2);
        let state = store.read().unwrap();
        let old: Vec<_> = state.items.iter().filter(|i| i.scope.is_none()).collect();
        assert_eq!(old.len(), 2, "legacy history is retained, not collapsed");
        assert!(
            old.iter().all(|i| !i.resolved),
            "an unknown legacy scope is not evidence of removal"
        );
        let fresh: Vec<_> = state.items.iter().filter(|i| i.scope.is_some()).collect();
        assert_eq!(fresh.len(), 2);
        assert!(fresh.iter().all(|i| state.decision(i, now()).is_none()));
        let a_id = fresh.iter().find(|i| i.line == Some(1)).unwrap().id;
        store
            .update(|state| state.decide(a_id, review::Reason::Kept, now(), "now".into()))
            .unwrap();
        // A later scan cannot merge the distinct scopes or spread that choice.
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 2);
        let state = store.read().unwrap();
        assert_eq!(state.items.len(), 4);
        assert_eq!(
            state
                .items
                .iter()
                .filter(|i| state.decision(i, now()).is_some())
                .count(),
            1
        );
        std::fs::write(config, "").unwrap();
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 0);
        assert!(store.read().unwrap().items.iter().all(|i| i.resolved));
        drop(app);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn new_consent_reloads_a_registration_left_after_a_reset() {
        let _alone = one_scan();
        let (home, app) = engine("helper-reset-registration");
        // Show in Menu Bar off: only the helper is registered.
        update_state(&app, |state| state.menu_bar_off = true).unwrap();
        let mut calls = Vec::new();
        set_monitoring_with_login(
            &app,
            true,
            false,
            2,
            |on| {
                calls.push(on);
                if on {
                    2
                } else {
                    1
                }
            },
            || 1,
            |_| panic!("no app login item without the menu bar"),
        )
        .unwrap();
        assert_eq!(
            calls,
            [false, true],
            "new consent must reload an old registration, not assume a helper is running"
        );
        assert!(app.store.as_ref().unwrap().read().unwrap().monitoring);
        calls.clear();
        set_monitoring_with_login(
            &app,
            true,
            true,
            2,
            |on| {
                calls.push(on);
                2
            },
            || 1,
            |_| panic!("no app login item without the menu bar"),
        )
        .unwrap();
        assert!(
            calls.is_empty(),
            "pausing an enabled helper must not restart it"
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn helper_registration_failures_are_errors_and_pending_approval_can_be_withdrawn() {
        let _alone = one_scan();
        for (name, enabled, status, answers, expected_calls, succeeds) in [
            ("start-failed", true, 1, vec![4], vec![true], false),
            ("reload-stop-failed", true, 2, vec![4], vec![false], false),
            (
                "reload-start-failed",
                true,
                2,
                vec![1, 4],
                vec![false, true],
                false,
            ),
            ("approval-pending", true, 3, vec![], vec![], true),
            ("approval-new", true, 1, vec![3], vec![true], true),
            ("approval-withdrawn", false, 3, vec![1], vec![false], true),
            ("stop-failed", false, 2, vec![4], vec![false], false),
        ] {
            let (home, app) = engine(name);
            // Show in Menu Bar off: only the helper is registered.
            update_state(&app, |state| state.menu_bar_off = true).unwrap();
            let mut calls = Vec::new();
            let mut answers = answers.into_iter();
            let result = set_monitoring_with_login(
                &app,
                enabled,
                false,
                status,
                |on| {
                    calls.push(on);
                    answers.next().expect("no extra native operation")
                },
                || 1,
                |_| panic!("no app login item without the menu bar"),
            );
            assert_eq!(result.is_ok(), succeeds, "{name}");
            assert_eq!(calls, expected_calls, "{name}");
            assert_eq!(
                app.store.as_ref().unwrap().read().unwrap().monitoring,
                enabled
            );
            std::fs::remove_dir_all(home).unwrap();
        }
    }

    #[test]
    fn a_state_saved_before_the_menu_bar_setting_shows_the_icon() {
        let state: review::Review =
            serde_json::from_str(r#"{"items":[],"monitoring":true}"#).unwrap();
        assert!(state.monitoring && !state.menu_bar_off);
        assert!(!review::Review::default().menu_bar_off);
    }

    #[test]
    fn background_checks_alone_put_the_app_in_login_items_by_default() {
        let _alone = one_scan();
        let (home, app) = engine("menu-bar-default");
        let mut calls = Vec::new();
        set_monitoring_with_login(
            &app,
            true,
            false,
            1,
            |_| 2,
            || 1,
            |on| {
                calls.push(on);
                2
            },
        )
        .unwrap();
        assert_eq!(calls, [true], "Show in Menu Bar is on until turned off");
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn a_state_saved_before_the_update_question_asks_it() {
        let state: review::Review =
            serde_json::from_str(r#"{"items":[],"monitoring":true}"#).unwrap();
        assert_eq!(state.update_check, None);
        assert_eq!(review::Review::default().update_check, None);
    }

    #[test]
    fn the_update_choice_is_kept_and_needs_private_state() {
        // Saving a setting tells the window, through the shared event handler.
        let _alone = one_scan();
        let (home, app) = engine("update-choice");
        assert_eq!(
            ask(&app, "monitor_status", "{}")["ok"]["update_check"],
            Value::Null
        );
        let saved = ask(&app, "set_update_check", r#"{"enabled":true}"#);
        assert_eq!(saved["ok"], Value::Null, "{saved}");
        let reopened = App::open(Ok(home.clone()));
        reopened.ready();
        assert_eq!(reopened.review.lock().unwrap().update_check, Some(true));
        assert_eq!(
            ask(&reopened, "monitor_status", "{}")["ok"]["update_check"],
            true
        );
        ask(&reopened, "set_update_check", r#"{"enabled":false}"#);
        assert_eq!(
            ask(&reopened, "monitor_status", "{}")["ok"]["update_check"],
            false
        );
        *reopened.storage_error.lock().unwrap() = Some("synthetic failure".into());
        assert_eq!(
            ask(&reopened, "set_update_check", r#"{"enabled":true}"#)["error"],
            "The update setting cannot be saved because Loose Keys could not open its saved data."
        );
        assert_eq!(
            app.store.as_ref().unwrap().read().unwrap().update_check,
            Some(false)
        );
        assert_eq!(
            ask(&app, "set_update_check", "{}")["error"],
            "The request has no usable \"enabled\"."
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    /// A process of this program that runs none of it: started suspended,
    /// with no file of the test's open, until `end` kills it.
    fn idle_copy() -> libc::pid_t {
        use std::os::unix::ffi::OsStringExt;
        let exe = std::env::current_exe().unwrap().into_os_string().into_vec();
        let exe = CString::new(exe).unwrap();
        let argv = [exe.as_ptr().cast_mut(), std::ptr::null_mut()];
        let envp = [std::ptr::null_mut()];
        let flags = libc::POSIX_SPAWN_START_SUSPENDED | libc::POSIX_SPAWN_CLOEXEC_DEFAULT;
        let flags = libc::c_short::try_from(flags).unwrap();
        let mut attr = std::mem::MaybeUninit::uninit();
        let mut pid = 0;
        // SAFETY: the attributes are set up before they are used and freed
        // after; the path and both lists are NUL-terminated and outlive the
        // call, and `pid` is a place for one process number.
        let spawned = unsafe {
            assert_eq!(libc::posix_spawnattr_init(attr.as_mut_ptr()), 0);
            let set = libc::posix_spawnattr_setflags(attr.as_mut_ptr(), flags);
            let spawned = libc::posix_spawn(
                &mut pid,
                exe.as_ptr(),
                std::ptr::null(),
                attr.as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
            );
            libc::posix_spawnattr_destroy(attr.as_mut_ptr());
            assert_eq!(set, 0);
            spawned
        };
        assert_eq!(spawned, 0, "could not start a copy of the test");
        pid
    }

    fn end(pid: libc::pid_t) {
        let mut status = 0;
        // SAFETY: the process is a child of this one, and `status` is a
        // place for its exit status.
        unsafe {
            assert_eq!(libc::kill(pid, libc::SIGKILL), 0);
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
        }
    }

    /// The helper saves its process number when it starts, and nothing
    /// clears it when the helper ends. Another program given that number
    /// later is not the helper running, and neither is the app asking.
    #[test]
    fn only_this_program_at_the_saved_number_is_the_helper_running() {
        let (home, app) = engine("helper-pid");
        let running = |pid: u32| {
            update_state(&app, |state| state.agent.pid = pid).unwrap();
            ask(&app, "monitor_status", "{}")["ok"]["health"]["running"].clone()
        };
        let mut other = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let another_program = running(other.id());
        other.kill().unwrap();
        other.wait().unwrap();
        let copy = idle_copy();
        let this_program = running(u32::try_from(copy).unwrap());
        end(copy);
        let asking = running(std::process::id());
        let ended = running(u32::try_from(copy).unwrap());
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(another_program, false, "another program has the number");
        assert_eq!(this_program, true, "a copy of this program has it");
        assert_eq!(asking, false, "the app asking has it");
        assert_eq!(ended, false, "no process has it");
    }

    /// A helper of an older build, still running after an update, saves the
    /// state without `update_check`, which it does not know. The answer is
    /// kept in a file of its own as well, and taken from there.
    #[test]
    fn the_update_choice_outlasts_a_save_by_an_older_build() {
        use std::os::unix::fs::PermissionsExt;
        let _alone = one_scan();
        let (home, app) = engine("update-choice-older");
        let dir = home.join(review::STATE_DIR);
        let (state, copy) = (dir.join("state.json"), dir.join("update-check.json"));
        // Saved as an older build saves it: the state without the field.
        let older_save = || {
            let mut saved: Value = serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
            saved.as_object_mut().unwrap().remove("update_check");
            std::fs::write(&state, saved.to_string()).unwrap();
        };
        let answer = || ask(&app, "monitor_status", "{}")["ok"]["update_check"].clone();
        let stored =
            || -> Value { serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap() };
        let mut seen = Vec::new();
        for enabled in [true, false] {
            let set = json!({ "enabled": enabled }).to_string();
            assert_eq!(ask(&app, "set_update_check", &set), json!({ "ok": null }));
            older_save();
            seen.push(answer());
            // The next save by this build puts it back in the state.
            update_state(&app, |_| ()).unwrap();
            seen.push(stored()["update_check"].clone());
        }
        // A copy that is not a private file of its own, is too large or holds
        // anything but an answer is not one: the question is asked again.
        older_save();
        let put = |text: &str, mode: u32| {
            // In place of what is there, a link included.
            let _ = std::fs::remove_file(&copy);
            std::fs::write(&copy, text).unwrap();
            std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(mode)).unwrap();
            answer()
        };
        let padded = format!("{}true", " ".repeat(16));
        let mut broken = vec![put("yes", 0o600), put("true", 0o644), put(&padded, 0o600)];
        std::fs::remove_file(&copy).unwrap();
        std::fs::write(dir.join("elsewhere"), "true").unwrap();
        std::os::unix::fs::symlink(dir.join("elsewhere"), &copy).unwrap();
        broken.push(answer());
        let restored = put("true", 0o600);
        // A copy that cannot be written saves no answer at all.
        std::fs::create_dir(dir.join("update-check.tmp")).unwrap();
        let unwritable = ask(&app, "set_update_check", r#"{"enabled":false}"#);
        let after = (answer(), stored()["update_check"].clone());
        drop(app);
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(seen, [true, true, false, false]);
        assert_eq!(broken, [Value::Null, Value::Null, Value::Null, Value::Null]);
        assert_eq!(restored, true);
        assert!(unwritable["error"].is_string(), "{unwritable}");
        assert_eq!(after, (json!(true), Value::Null));
    }

    #[test]
    fn check_release_answers_through_dispatch() {
        let (home, app) = engine("check-release");
        let reply = json!({"tag_name": "v0.0.1", "draft": false, "prerelease": false});
        let answer = ask(
            &app,
            "check_release",
            &json!({"body": reply.to_string()}).to_string(),
        );
        assert_eq!(answer["ok"]["current"], env!("CARGO_PKG_VERSION"));
        assert_eq!(answer["ok"]["newer"], Value::Null);
        assert_eq!(
            ask(&app, "check_release", "{}")["error"],
            "The request has no usable \"body\"."
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn the_menu_bar_setting_is_kept_and_needs_private_state() {
        let _alone = one_scan();
        let (home, app) = engine("menu-bar-setting");
        assert_eq!(ask(&app, "monitor_status", "{}")["ok"]["menu_bar"], true);
        set_menu_bar_with_login(&app, false, || 1, |_| panic!("not in Login Items")).unwrap();
        let reopened = App::open(Ok(home.clone()));
        reopened.ready();
        assert!(reopened.review.lock().unwrap().menu_bar_off);
        let status = ask(&reopened, "monitor_status", "{}");
        assert_eq!(status["ok"]["menu_bar"], false);
        assert!(status["ok"]["app_login"].is_u64());
        *reopened.storage_error.lock().unwrap() = Some("synthetic failure".into());
        assert!(
            set_menu_bar_with_login(&reopened, true, || 1, |_| panic!("refused first")).is_err()
        );
        assert!(app.store.as_ref().unwrap().read().unwrap().menu_bar_off);
        assert_eq!(
            ask(&app, "set_menu_bar", "{}")["error"],
            "The request has no usable \"enabled\"."
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn the_app_login_item_is_changed_only_when_it_differs() {
        for (name, want, status, answers, expected_calls, succeeds) in [
            ("register", true, 1, vec![2], vec![true], true),
            ("register-after-error", true, 4, vec![2], vec![true], true),
            ("approval-new", true, 1, vec![3], vec![true], true),
            ("approval-pending", true, 3, vec![], vec![], true),
            ("already-on", true, 2, vec![], vec![], true),
            ("unregister", false, 2, vec![1], vec![false], true),
            ("approval-withdrawn", false, 3, vec![1], vec![false], true),
            ("already-off", false, 1, vec![], vec![], true),
            ("register-failed", true, 1, vec![4], vec![true], false),
            ("unregister-failed", false, 2, vec![4], vec![false], false),
        ] {
            let mut calls = Vec::new();
            let mut answers = answers.into_iter();
            let result = reconcile_app_login(want, status, |on| {
                calls.push(on);
                answers.next().expect("no extra native operation")
            });
            assert_eq!(result.is_ok(), succeeds, "{name}");
            assert_eq!(calls, expected_calls, "{name}");
        }
    }

    #[test]
    fn the_app_opens_at_login_only_while_both_settings_are_on() {
        let _alone = one_scan();
        let (home, app) = engine("menu-bar-login");
        let mut calls = Vec::new();
        set_menu_bar_with_login(
            &app,
            true,
            || 1,
            |on| {
                calls.push(on);
                2
            },
        )
        .unwrap();
        assert!(calls.is_empty(), "the menu bar alone adds no login item");
        set_monitoring_with_login(
            &app,
            true,
            false,
            1,
            |_| 2,
            || 1,
            |on| {
                calls.push(on);
                2
            },
        )
        .unwrap();
        assert_eq!(calls, [true], "both on adds the app");
        calls.clear();
        set_menu_bar_with_login(
            &app,
            false,
            || 2,
            |on| {
                calls.push(on);
                1
            },
        )
        .unwrap();
        assert_eq!(calls, [false], "menu bar off removes the app");
        calls.clear();
        set_menu_bar_with_login(
            &app,
            true,
            || 1,
            |on| {
                calls.push(on);
                2
            },
        )
        .unwrap();
        assert_eq!(calls, [true]);
        calls.clear();
        set_monitoring_with_login(
            &app,
            true,
            true,
            2,
            |_| 2,
            || 2,
            |on| {
                calls.push(on);
                2
            },
        )
        .unwrap();
        assert!(calls.is_empty(), "pausing leaves the login item alone");
        set_monitoring_with_login(
            &app,
            false,
            false,
            2,
            |_| 1,
            || 2,
            |on| {
                calls.push(on);
                1
            },
        )
        .unwrap();
        assert_eq!(calls, [false], "checks off removes the app");
        calls.clear();

        // The helper's failure is the one reported, though the app's change worked.
        set_monitoring_with_login(&app, true, false, 1, |_| 2, || 1, |_| 2).unwrap();
        let helper = set_monitoring_with_login(
            &app,
            false,
            false,
            2,
            |_| 4,
            || 2,
            |on| {
                calls.push(on);
                1
            },
        )
        .unwrap_err();
        assert_eq!(calls, [false], "the app's login item is still removed");
        assert!(helper.contains("background helper"), "{helper}");
        let login =
            set_monitoring_with_login(&app, true, false, 1, |_| 2, || 1, |_| 4).unwrap_err();
        assert!(login.contains("Login Items"), "{login}");
        assert!(app.store.as_ref().unwrap().read().unwrap().monitoring);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn a_login_item_its_settings_no_longer_want_is_removed_at_start() {
        let _alone = one_scan();
        for (name, saved, status, expected_calls) in [
            // No state file: reset, or the documented removal step.
            ("reset", None, 2, vec![false]),
            ("menu-bar-only", Some((false, true)), 3, vec![false]),
            ("checks-only", Some((true, false)), 2, vec![false]),
            ("both-on", Some((true, true)), 2, vec![]),
            // Removed by the person in System Settings: not added back.
            ("both-on-removed", Some((true, true)), 1, vec![]),
            ("already-off", None, 1, vec![]),
        ] {
            let (home, first) = engine(&format!("start-login-{name}"));
            if let Some((monitoring, menu_bar)) = saved {
                update_state(&first, |state| {
                    state.monitoring = monitoring;
                    state.menu_bar_off = !menu_bar;
                })
                .unwrap();
            }
            let app = App::open(Ok(home.clone()));
            let mut calls = Vec::new();
            app.ready_with(
                || status,
                |on| {
                    calls.push(on);
                    1
                },
            );
            assert_eq!(calls, expected_calls, "{name}");
            std::fs::remove_dir_all(home).unwrap();
        }

        // State that cannot be read says nothing of what is wanted.
        use std::os::unix::fs::PermissionsExt;
        let (home, first) = engine("start-login-unreadable");
        update_state(&first, |state| state.menu_bar_off = false).unwrap();
        let state = home.join(review::STATE_DIR).join("state.json");
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644)).unwrap();
        let app = App::open(Ok(home.clone()));
        app.ready_with(
            || 2,
            |_| panic!("no change from state that could not be read"),
        );
        assert!(app.storage_error.lock().unwrap().is_some());
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn the_app_login_item_follows_the_last_of_two_changes_at_once() {
        use std::sync::mpsc;
        use std::time::Duration;
        let _alone = one_scan();
        let (home, app) = engine("menu-bar-login-race");
        // Show in Menu Bar off: only the helper is registered.
        update_state(&app, |state| state.menu_bar_off = true).unwrap();
        set_monitoring_with_login(
            &app,
            true,
            false,
            1,
            |_| 2,
            || 1,
            |_| panic!("no login item without the menu bar"),
        )
        .unwrap();
        let registered = AtomicU8::new(1);
        let fake = |on: bool| {
            let status = if on { 2 } else { 1 };
            registered.store(status, Ordering::SeqCst);
            status
        };
        let (app, registered_now) = (&app, || registered.load(Ordering::SeqCst));
        let (reached, at_status) = mpsc::channel();
        let (release, gate) = mpsc::channel::<()>();
        std::thread::scope(|scope| {
            // Show in Menu Bar turned on, held as it reads the Login Items status...
            let menu = scope.spawn(move || {
                set_menu_bar_with_login(
                    app,
                    true,
                    move || {
                        reached.send(()).unwrap();
                        gate.recv().unwrap();
                        registered_now()
                    },
                    fake,
                )
            });
            at_status
                .recv_timeout(Duration::from_secs(10))
                .expect("Show in Menu Bar reads the Login Items status");
            // ...while background checks are turned off.
            let (finished, done) = mpsc::channel();
            let checks = scope.spawn(move || {
                let result =
                    set_monitoring_with_login(app, false, false, 2, |_| 1, registered_now, fake);
                finished.send(()).unwrap();
                result
            });
            // One change at a time keeps the second waiting here. Without that,
            // it finishes now, before the first has added the app.
            let _ = done.recv_timeout(Duration::from_millis(500));
            release.send(()).unwrap();
            menu.join().unwrap().unwrap();
            checks.join().unwrap().unwrap();
        });
        assert!(!app.store.as_ref().unwrap().read().unwrap().monitoring);
        assert_eq!(
            registered.load(Ordering::SeqCst),
            1,
            "with background checks off, the app is not left in Login Items"
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn restart_helper_does_not_register_the_helper_once_checks_are_off() {
        use std::sync::mpsc;
        use std::time::Duration;
        let _alone = one_scan();
        let (home, app) = engine("restart-helper-race");
        // Show in Menu Bar off: only the helper is registered.
        update_state(&app, |state| state.menu_bar_off = true).unwrap();
        set_monitoring_with_login(
            &app,
            true,
            false,
            1,
            |_| 2,
            || 1,
            |_| panic!("no login item without the menu bar"),
        )
        .unwrap();
        let registered = AtomicU8::new(2);
        let fake = |on: bool| {
            let status = if on { 2 } else { 1 };
            registered.store(status, Ordering::SeqCst);
            status
        };
        let (app, registered_now) = (&app, || registered.load(Ordering::SeqCst));
        let (reached, at_call) = mpsc::channel();
        let (release, gate) = mpsc::channel::<()>();
        std::thread::scope(|scope| {
            // Restart Helper found checks on, and is held as it asks macOS...
            let restart = scope.spawn(move || {
                set_login_startup_with(app, true, move |on| {
                    reached.send(()).unwrap();
                    gate.recv().unwrap();
                    fake(on)
                })
            });
            at_call
                .recv_timeout(Duration::from_secs(10))
                .expect("Restart Helper asks macOS to register the helper");
            // ...while background checks are turned off.
            let (finished, done) = mpsc::channel();
            let checks = scope.spawn(move || {
                let result = set_monitoring_with_login(
                    app,
                    false,
                    false,
                    registered_now(),
                    fake,
                    || 1,
                    |_| panic!("no login item without the menu bar"),
                );
                finished.send(()).unwrap();
                result
            });
            // One change at a time keeps the second waiting here. Without that,
            // it finishes now, before Restart Helper registers the helper.
            let _ = done.recv_timeout(Duration::from_millis(500));
            release.send(()).unwrap();
            restart.join().unwrap().unwrap();
            checks.join().unwrap().unwrap();
        });
        assert!(!app.store.as_ref().unwrap().read().unwrap().monitoring);
        assert_eq!(
            registered.load(Ordering::SeqCst),
            1,
            "with background checks off, the helper is not left registered"
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn restart_helper_needs_readable_state() {
        let (home, app) = engine("restart-helper-storage");
        update_state(&app, |state| state.monitoring = true).unwrap();
        *app.storage_error.lock().unwrap() = Some("synthetic failure".into());
        for enabled in [false, true] {
            assert_eq!(
                set_login_startup_with(&app, enabled, |_| panic!("refused first")),
                Err("Automatic scanning cannot start because Loose Keys could not open its saved data.".into())
            );
        }
        std::fs::remove_dir_all(home).unwrap();
    }

    /// The status holds no lock while it waits for another: a scan saving
    /// its results holds the report, and the storage error is asked for by
    /// every command meanwhile.
    #[test]
    fn the_status_holds_no_lock_while_it_waits_for_the_report() {
        use std::sync::mpsc;
        use std::time::Duration;
        let (home, app) = engine("status-locks");
        let report = app.report.lock().unwrap();
        let app = &app;
        std::thread::scope(|scope| {
            let (finished, done) = mpsc::channel();
            let status = scope.spawn(move || {
                let enabled = monitor_status(app).enabled;
                finished.send(()).unwrap();
                enabled
            });
            // The report is held, so the status waits for it here.
            assert!(done.recv_timeout(Duration::from_millis(500)).is_err());
            let (got, asked) = mpsc::channel();
            scope.spawn(move || {
                let error = app.storage_error.lock().unwrap().clone();
                got.send(error).unwrap();
            });
            let error = asked.recv_timeout(Duration::from_secs(5));
            drop(report);
            assert_eq!(
                error,
                Ok(None),
                "the storage error was held while the status waited for the report"
            );
            assert!(!status.join().unwrap());
        });
        std::fs::remove_dir_all(home).unwrap();
    }

    /// Notifications allowed wake the helper by saving the state. Nothing is
    /// saved while the state cannot be read.
    #[test]
    fn a_permission_answer_saves_nothing_while_state_is_unavailable() {
        use std::os::unix::fs::MetadataExt;
        let (home, app) = engine("permission-storage-error");
        update_state(&app, |_| ()).unwrap();
        let state = home.join(review::STATE_DIR).join("state.json");
        let saved = || std::fs::symlink_metadata(&state).unwrap().ino();
        let before = saved();
        *app.storage_error.lock().unwrap() = Some("synthetic failure".into());
        wake_helper(&app);
        assert_eq!(saved(), before, "the state was saved");
        *app.storage_error.lock().unwrap() = None;
        wake_helper(&app);
        assert_ne!(saved(), before, "the helper is woken by a save");
        std::fs::remove_dir_all(home).unwrap();
    }

    /// A read that fails once, as when the state's permissions are put
    /// right, is cleared by a later read that works. A change that could not
    /// be saved is not: what it would have saved is lost.
    #[test]
    fn a_failed_read_is_cleared_by_a_later_one_and_a_failed_save_is_not() {
        use std::os::unix::fs::PermissionsExt;
        let (home, app) = engine("storage-error-clears");
        update_state(&app, |_| ()).unwrap();
        let dir = home.join(review::STATE_DIR);
        let state = dir.join("state.json");
        let error = |app: &App| ask(app, "pending_review", "{}")["ok"]["error"].clone();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(error(&app).is_string());
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(error(&app), Value::Null);
        assert_eq!(
            ask(&app, "retry_notifications", "{}"),
            json!({ "ok": null })
        );
        // A save that leaves a file it cannot trust.
        std::fs::create_dir(dir.join("state.tmp")).unwrap();
        assert!(ask(&app, "retry_notifications", "{}")["error"].is_string());
        std::fs::remove_dir(dir.join("state.tmp")).unwrap();
        assert!(error(&app).is_string());
        assert!(ask(&app, "retry_notifications", "{}")["error"].is_string());
        std::fs::remove_dir_all(home).unwrap();
    }

    /// A change refused because the state could not be read changed
    /// nothing, and neither does a save that only wakes the helper, so
    /// neither keeps the error once the state reads and saves again.
    #[test]
    fn a_failure_that_lost_no_change_is_cleared_by_a_later_read() {
        use std::os::unix::fs::PermissionsExt;
        let (home, app) = engine("storage-error-nothing-lost");
        update_state(&app, |_| ()).unwrap();
        let dir = home.join(review::STATE_DIR);
        let state = dir.join("state.json");
        let error = |app: &App| ask(app, "pending_review", "{}")["ok"]["error"].clone();
        assert_eq!(error(&app), Value::Null);
        // Unreadable before the change is made: no read has seen it yet.
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ask(&app, "retry_notifications", "{}")["error"].is_string());
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(error(&app), Value::Null, "a failed read was kept");
        // A wake that could not be saved.
        std::fs::create_dir(dir.join("state.tmp")).unwrap();
        wake_helper(&app);
        std::fs::remove_dir(dir.join("state.tmp")).unwrap();
        assert_eq!(error(&app), Value::Null, "a failed wake was kept");
        assert_eq!(
            ask(&app, "retry_notifications", "{}"),
            json!({ "ok": null })
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    /// A scan made while the state cannot be read saves nothing. Once the
    /// state reads again, the list would be shown without what that scan
    /// found, so the error stays as it does for a save that failed.
    #[test]
    fn a_scan_not_saved_keeps_the_error_after_the_state_reads_again() {
        use std::os::unix::fs::PermissionsExt;
        let _alone = one_scan();
        let (home, app) = engine("scan-not-saved");
        update_state(&app, |_| ()).unwrap();
        std::fs::create_dir(home.join(".claude")).unwrap();
        let record = home.join(".claude/session.jsonl");
        std::fs::write(&record, format!("{{\"out\":\"{}\"}}\n", token('A'))).unwrap();
        let state = home.join(review::STATE_DIR).join("state.json");
        let error = |app: &App| ask(app, "pending_review", "{}")["ok"]["error"].clone();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(error(&app).is_string());
        let scan = ask(&app, "start_scan", "{}");
        assert!(scan["ok"]["review"].as_u64() > Some(0), "{scan}");
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
        let after = error(&app);
        let items = app.store.as_ref().unwrap().read().unwrap().items.len();
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(items, 0, "the scan saved nothing");
        assert!(after.is_string(), "{after}");
    }

    /// A scan stopped before it found anything would have changed nothing
    /// on the list, so the error clears once the state reads again. One
    /// stopped after it found something has lost that, and the error stays.
    #[test]
    fn a_stopped_scan_keeps_the_error_only_when_it_found_something() {
        use std::os::unix::fs::PermissionsExt;
        type StopAt = Option<(std::sync::Arc<AtomicBool>, u64)>;
        static STOP_AT: Mutex<StopAt> = Mutex::new(None);
        /// Stops the scan, as the Stop button would, at the first progress
        /// that counts at least the findings asked for.
        extern "C" fn stop(name: *const c_char, payload: *const c_char) {
            // SAFETY: the engine passes two NUL-terminated strings.
            let (name, payload) = unsafe { (CStr::from_ptr(name), CStr::from_ptr(payload)) };
            let progress: Value = serde_json::from_slice(payload.to_bytes()).unwrap();
            if let Some((cancel, findings)) = &*STOP_AT.lock().unwrap() {
                if name == c"scan-progress" && progress["findings"].as_u64() >= Some(*findings) {
                    cancel.store(true, Ordering::SeqCst);
                }
            }
        }
        let _alone = one_scan();
        let stopped = |name: &str, findings: u64| {
            let (home, app) = engine(name);
            update_state(&app, |_| ()).unwrap();
            if findings > 0 {
                std::fs::create_dir(home.join(".claude")).unwrap();
                let record = home.join(".claude/session.jsonl");
                std::fs::write(&record, format!("{{\"out\":\"{}\"}}\n", token('A'))).unwrap();
            }
            let state = home.join(review::STATE_DIR).join("state.json");
            let error = |app: &App| ask(app, "pending_review", "{}")["ok"]["error"].clone();
            std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(error(&app).is_string());
            *STOP_AT.lock().unwrap() = Some((app.monitor.cancel.clone(), findings));
            ch_set_event_handler(Some(stop));
            let scan = ask(&app, "start_scan", "{}");
            ch_set_event_handler(None);
            *STOP_AT.lock().unwrap() = None;
            let cancelled = app.monitor.cancel.load(Ordering::SeqCst);
            std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
            let after = error(&app);
            std::fs::remove_dir_all(home).unwrap();
            assert!(cancelled, "the scan was not stopped: {scan}");
            assert_eq!(scan["ok"]["review"].as_u64(), Some(findings), "{scan}");
            after
        };
        assert_eq!(stopped("stopped-scan-empty", 0), Value::Null);
        assert!(stopped("stopped-scan-found", 1).is_string());
    }

    /// Commands that change the folders checked save nothing while the
    /// state cannot be read, as other changes do.
    #[test]
    fn folder_changes_need_readable_state() {
        let (home, app, _) = found_since("folders-storage-error");
        let extra = home.join("Extra");
        std::fs::create_dir(&extra).unwrap();
        assert_eq!(
            ask(&app, "skip_folder", r#"{"id":1}"#),
            json!({ "ok": null })
        );
        assert!(add_place(&app, &extra).is_ok());
        let stored = || app.store.as_ref().unwrap().read().unwrap();
        // As a change that could not be saved leaves it: a read does not
        // clear it.
        *app.storage_error.lock().unwrap() = Some("synthetic failure".into());
        app.storage_unsaved.store(true, Ordering::SeqCst);
        let refused = "Loose Keys could not open its saved data.";
        let shown = json!({ "index": 0, "shown": "~/Documents" }).to_string();
        assert_eq!(ask(&app, "unskip_folder", &shown)["error"], refused);
        let shown = json!({ "index": 0, "shown": show(&extra) }).to_string();
        assert_eq!(ask(&app, "remove_place", &shown)["ok"]["error"], refused);
        update_state(&app, |state| state.skipped.clear()).unwrap();
        let skipped = serde_json::to_string(&stored()).unwrap();
        assert_eq!(ask(&app, "skip_folder", r#"{"id":1}"#)["error"], refused);
        assert_eq!(serde_json::to_string(&stored()).unwrap(), skipped);
        update_state(&app, |state| state.selected_places.clear()).unwrap();
        let removed = serde_json::to_string(&stored()).unwrap();
        assert_eq!(add_place(&app, &extra), Err(refused.into()));
        assert_eq!(serde_json::to_string(&stored()).unwrap(), removed);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn a_folder_already_skipped_can_be_skipped_again_with_the_list_full() {
        let (home, app, _) = found_since("skip-again-full");
        assert_eq!(
            ask(&app, "skip_folder", r#"{"id":1}"#),
            json!({ "ok": null })
        );
        update_state(&app, |state| {
            for n in 1..review::MAX_SKIPS {
                let (path, added) = (format!("~/Other-{n}"), "synthetic".into());
                state.skipped.push(review::Skip { path, added });
            }
        })
        .unwrap();
        assert_eq!(
            ask(&app, "skip_folder", r#"{"id":1}"#),
            json!({ "ok": null })
        );
        let stored = app.store.as_ref().unwrap().read().unwrap();
        assert_eq!(stored.skipped.len(), review::MAX_SKIPS);
        std::fs::remove_dir_all(home).unwrap();
    }

    /// The organization's list is compared with what the store holds: a
    /// list whose file was deleted takes it again.
    #[test]
    fn the_expected_list_is_compared_with_the_store() {
        let (home, app, _) = found_since("expected-against-store");
        let entries = json!({ "entries": [{ "rule": "export.password-csv", "path": "~/Documents/export.csv" }] })
            .to_string();
        assert_eq!(ask(&app, "set_expected", &entries), json!({ "ok": null }));
        std::fs::remove_file(home.join(review::STATE_DIR).join("state.json")).unwrap();
        assert_eq!(ask(&app, "set_expected", &entries), json!({ "ok": null }));
        let stored = app.store.as_ref().unwrap().read().unwrap();
        assert_eq!(stored.expected.len(), 1);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn automatic_coverage_needs_readable_state() {
        use std::os::unix::fs::PermissionsExt;
        let (home, app) = engine("coverage-storage-error");
        update_state(&app, |_| ()).unwrap();
        let state = home.join(review::STATE_DIR).join("state.json");
        assert!(ask(&app, "automatic_coverage", "{}")["ok"].is_object());
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            ask(&app, "automatic_coverage", "{}")["error"],
            "Loose Keys could not open its saved data."
        );
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(ask(&app, "automatic_coverage", "{}")["ok"].is_object());
        // A change that could not be saved is not cleared by a read.
        *app.storage_error.lock().unwrap() = Some("synthetic failure".into());
        app.storage_unsaved.store(true, Ordering::SeqCst);
        assert_eq!(
            ask(&app, "automatic_coverage", "{}")["error"],
            "Loose Keys could not open its saved data."
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    /// The store is a file other programs can edit: what it says an item
    /// concerns reaches the window escaped, as a path does.
    #[test]
    fn stored_subjects_reach_the_window_escaped() {
        let (home, app, _) = found_since("stored-subject");
        update_state(&app, |state| {
            state.items[0].subject = Some("profile\u{202e}txt".into());
            state.items[0].detail = Some("\u{7}2 saved logins".into());
        })
        .unwrap();
        let item = ask(&app, "pending_review", "{}")["ok"]["items"][0].clone();
        assert_eq!(item["subject"], "profile\\u{202e}txt");
        assert_eq!(item["detail"], "\\u{7}2 saved logins");
        // The scanner's own text, which the window's translations are keyed
        // by, quotes and all, reaches it as it is.
        let quoted = r#"Set "credsStore": "osxkeychain" in ~/.docker/config.json."#;
        update_state(&app, |state| state.items[0].steps = vec![quoted.into()]).unwrap();
        let item = ask(&app, "pending_review", "{}")["ok"]["items"][0].clone();
        assert_eq!(item["steps"], json!([quoted]));
        // Anything else in that text was not written by the scanner.
        update_state(&app, |state| {
            let item = &mut state.items[0];
            item.rule = "export.password-csv\u{202e}".into();
            item.title = "Title\u{202e}".into();
            item.explanation = "\u{1b}[2J".into();
            item.next_step = Some("next\u{7}".into());
            item.steps = vec!["step\u{202e}".into(), quoted.into()];
            item.link = Some("https://example.invalid/\u{202e}".into());
            item.token_type = Some("type\u{7}".into());
            item.severity = "high\u{202e}".into();
            item.first_seen = Some("2026\u{202e}".into());
            item.resolved_at = Some("2026\u{7}".into());
        })
        .unwrap();
        let item = ask(&app, "pending_review", "{}")["ok"]["items"][0].clone();
        let expected = [
            ("rule", json!("export.password-csv\\u{202e}")),
            ("title", json!("Title\\u{202e}")),
            ("explanation", json!("\\u{1b}[2J")),
            ("next_step", json!("next\\u{7}")),
            ("steps", json!(["step\\u{202e}", quoted])),
            ("link", json!("https://example.invalid/\\u{202e}")),
            ("token_type", json!("type\\u{7}")),
            ("severity", json!("high\\u{202e}")),
            ("first_seen", json!("2026\\u{202e}")),
            ("resolved_at", json!("2026\\u{7}")),
        ];
        for (field, escaped) in expected {
            assert_eq!(item[field], escaped, "{field}");
        }
        // And when the item was set aside.
        assert_eq!(
            ask(
                &app,
                "decide_review",
                r#"{"id":1,"revision":0,"reason":"testing"}"#
            ),
            json!({ "ok": null })
        );
        update_state(&app, |state| {
            state.decisions[0].decided = "2026\u{202e}".into()
        })
        .unwrap();
        let item = ask(&app, "pending_review", "{}")["ok"]["items"][0].clone();
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(item["set_aside_at"], "2026\\u{202e}");
    }

    #[test]
    fn access_preparation_is_bounded_and_does_not_claim_coverage() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let (home, app) = engine("prepare-access");
        let documents = home.join("Documents");
        std::fs::create_dir(&documents).unwrap();
        let planted = ["synthetic-access-", "private-fixture"].concat();
        std::fs::write(documents.join(&planted), planted.as_bytes()).unwrap();
        // The other probes encounter a link and an absent folder.
        symlink(&documents, home.join("Desktop")).unwrap();
        for index in 0..3 {
            let result = ask(&app, "prepare_access", &json!({"index": index}).to_string());
            assert_eq!(result, json!({"ok": null}));
            for piece in [&planted[..], "synthetic-access-", "private-fixture"] {
                assert!(!result.to_string().contains(piece));
            }
        }
        assert!(ask(&app, "prepare_access", r#"{"index":3}"#)["error"].is_string());
        assert!(app.report.lock().unwrap().is_none());
        // A folder macOS let the scan read, or a link, is nothing to fix.
        let alone = one_scan();
        let open = ask(&app, "start_scan", "{}");
        drop(alone);
        assert_eq!(open["ok"]["blocked"], json!([]));
        assert!(!app.scanning.load(Ordering::SeqCst));
        assert_eq!(
            std::fs::read(documents.join(&planted)).unwrap(),
            planted.as_bytes()
        );
        // A denied probe still permits scanning, whose report retains the gap.
        std::fs::set_permissions(&documents, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = ask(&app, "prepare_access", r#"{"index":1}"#);
        assert_eq!(result, json!({"ok": null}));
        let alone = one_scan();
        let scanned = ask(&app, "start_scan", "{}");
        drop(alone);
        std::fs::set_permissions(&documents, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(scanned["ok"]["status"], "partial");
        // The window names it by a fixed word, never by the path.
        assert_eq!(scanned["ok"]["blocked"], json!(["Documents"]));
        assert!(app
            .report
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .not_checked
            .iter()
            .any(|gap| gap.path == "~/Documents" && gap.reason == "permission-denied"));
        std::fs::remove_dir_all(home).unwrap();
    }

    pub(crate) static SEEN: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

    /// Held by a test while it scans through the app's side: every scan's
    /// events go to the one handler, whichever test set it. The lock guards
    /// no data, so a test that failed holding it does not fail the next.
    pub(crate) fn one_scan() -> std::sync::MutexGuard<'static, ()> {
        static ONE_SCAN: Mutex<()> = Mutex::new(());
        ONE_SCAN.lock().unwrap_or_else(|held| held.into_inner())
    }

    pub(crate) extern "C" fn seen(name: *const c_char, payload: *const c_char) {
        // SAFETY: the engine passes two NUL-terminated strings.
        let text = |at| unsafe { CStr::from_ptr(at) }.to_str().unwrap().to_string();
        SEEN.lock().unwrap().push((text(name), text(payload)));
    }

    /// What `mid_scan` does, once, when a scan first reports progress.
    static MID_SCAN: Mutex<Option<Box<dyn FnOnce() + Send>>> = Mutex::new(None);

    extern "C" fn mid_scan(name: *const c_char, _payload: *const c_char) {
        // SAFETY: the engine passes a NUL-terminated string.
        if unsafe { CStr::from_ptr(name) } == c"scan-progress" {
            let act = MID_SCAN.lock().unwrap().take();
            if let Some(act) = act {
                act();
            }
        }
    }

    #[test]
    fn capped_scan_exports_a_gap_and_keeps_an_omitted_item_unresolved() {
        let _alone = one_scan();
        let (home, app) = engine("capped-findings");
        let file = home.join(".env");
        let retained = "LAST_TOKEN=synthetic-retained-value\n";
        std::fs::write(&file, retained).unwrap();
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["status"], "complete");
        let first = ask(&app, "pending_review", "{}")["ok"]["items"][0]["id"].clone();
        let before: String = (0..100)
            .map(|i| format!("SERVICE_{i}_TOKEN=synthetic-value-{i}\n"))
            .collect();
        std::fs::write(&file, format!("{before}{retained}")).unwrap();
        let result = ask(&app, "start_scan", "{}");
        assert_eq!(result["ok"]["status"], "partial");
        assert_eq!(result["ok"]["review"], 100);
        let state = || {
            let review = ask(&app, "pending_review", "{}");
            review["ok"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["id"] == first)
                .unwrap()["state"]
                .clone()
        };
        assert_eq!(state(), "open");
        // Export outside the scanned home, through the real dispatcher.
        let export = home.with_extension("json");
        let saved = ask(
            &app,
            "save_report",
            &json!({"path": export, "feedback": false}).to_string(),
        );
        assert!(saved.get("ok").is_some());
        let bytes = std::fs::read(&export).unwrap();
        assert!(!bytes.windows(10).any(|w| w == b"synthetic-"));
        let report: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report["status"], "partial");
        assert_eq!(report["findings"].as_array().unwrap().len(), 100);
        assert_eq!(
            report["not_checked"],
            json!([{"path": "~/.env", "reason": "scan-limit"}])
        );
        std::fs::remove_file(export).unwrap();
        // Removing the assignments allows a complete recheck to mark the
        // old item fixed. The store conservatively refuses removal evidence
        // at 100 hits even when the matcher finished exactly at that cap.
        std::fs::write(file, "").unwrap();
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["status"], "complete");
        assert_eq!(state(), "fixed");
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn added_folders_and_their_removal_survive_reopening_the_app() {
        let (home, app) = engine("saved-places");
        // An unavailable drive is still a chosen root, not silently dropped.
        let folder = home.join("Unavailable drive");
        let typed = json!({ "text": folder }).to_string();
        let added = ask(&app, "type_place", &typed);
        assert_eq!(added["ok"]["error"], Value::Null);
        let reopened = App::open(Ok(home.clone()));
        reopened.ready();
        let restored = ask(&reopened, "places", "{}");
        let remove = json!({ "index": 0, "shown": show(&folder) }).to_string();
        let removed = ask(&reopened, "remove_place", &remove);
        let again = App::open(Ok(home.clone()));
        again.ready();
        let after_removal = ask(&again, "places", "{}");
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(restored["ok"]["extra"], json!([show(&folder)]));
        assert_eq!(removed["ok"]["extra"], json!([]));
        assert_eq!(after_removal["ok"]["extra"], json!([]));
    }

    #[test]
    fn saved_added_folders_are_scanned_without_following_links() {
        use std::os::unix::fs::symlink;
        let _alone = one_scan();
        let (home, app) = engine("saved-places-scan");
        let extra = home.with_extension("extra");
        let link = home.with_extension("link");
        std::fs::create_dir(&extra).unwrap();
        std::fs::write(
            extra.join(".env"),
            "SERVICE_PASSWORD=synthetic-only-value\n",
        )
        .unwrap();
        symlink(&extra, &link).unwrap();
        assert!(add_place(&app, &extra).is_ok());
        let reopened = App::open(Ok(home.clone()));
        reopened.ready();
        let scanned = ask(&reopened, "start_scan", "{}");
        assert_eq!(scanned["ok"]["review"], 1);
        let removed = remove_place(&reopened, 0, show(&extra));
        assert!(removed.error.is_none());
        assert!(add_place(&reopened, &link).is_ok());
        let with_link = App::open(Ok(home.clone()));
        with_link.ready();
        let scanned_link = ask(&with_link, "start_scan", "{}");
        assert_eq!(scanned_link["ok"]["review"], 0);
        assert_eq!(scanned_link["ok"]["status"], "partial");
        assert!(scanned_link["ok"]["gaps"]
            .to_string()
            .contains(&show(&link)));
        std::fs::remove_file(link).unwrap();
        std::fs::remove_dir_all(extra).unwrap();
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn invalid_added_folder_input_does_not_poison_the_saved_list() {
        let (home, app) = engine("saved-places-invalid-input");
        let first = home.join("One");
        assert!(add_place(&app, &first).is_ok());
        let invalid = json!({ "text": format!("{}/bad\0name", show(&home)) }).to_string();
        let refused = ask(&app, "type_place", &invalid);
        let poisoned = app.storage_error.lock().unwrap().is_some();
        let retained = places(&app).extra;
        std::fs::remove_dir_all(home).unwrap();
        assert!(refused["ok"]["error"].is_string());
        assert_eq!(retained, vec![show(&first)]);
        assert!(
            !poisoned,
            "invalid folder input is not a saved-state failure"
        );
    }

    #[test]
    fn added_folder_changes_are_shared_and_failed_saves_keep_the_previous_list() {
        let (home, app) = engine("saved-places-failure");
        let first = home.join("One");
        let second = home.join("Two");
        assert!(add_place(&app, &first).is_ok());
        let other = App::open(Ok(home.clone()));
        other.ready();
        assert!(add_place(&other, &second).is_ok());
        assert_eq!(places(&app).extra, vec![show(&first), show(&second)]);
        // A helper saving its own state must preserve manual-only roots.
        app.store
            .as_ref()
            .unwrap()
            .update(|state| {
                state.agent.changes += 1;
                Ok(())
            })
            .unwrap();
        std::fs::create_dir(home.join(review::STATE_DIR).join("state.tmp")).unwrap();
        assert!(add_place(&app, &home.join("Three")).is_err());
        let failed = remove_place(&app, 0, show(&first));
        assert!(failed.error.is_some());
        assert_eq!(failed.extra, vec![show(&first), show(&second)]);
        let reopened = App::open(Ok(home.clone()));
        reopened.ready();
        assert_eq!(places(&reopened).extra, vec![show(&first), show(&second)]);
        std::fs::remove_dir_all(home).unwrap();
    }

    /// The window sends the path of a folder picked or dropped, never text
    /// typed, so spaces at either end are part of the name.
    #[test]
    fn a_folder_whose_name_ends_in_a_space_is_the_one_added() {
        let (home, app) = engine("spaced-place");
        for name in ["Spaced", "Spaced "] {
            std::fs::create_dir(home.join(name)).unwrap();
        }
        let spaced = home.join("Spaced ");
        let picked = json!({ "text": spaced.to_str().unwrap() }).to_string();
        let places = ask(&app, "type_place", &picked);
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(places["ok"]["error"], Value::Null, "{places}");
        assert_eq!(places["ok"]["extra"], json!([show(&spaced)]));
    }

    #[test]
    fn a_folder_is_removed_or_put_back_only_while_it_is_the_one_shown() {
        use std::os::unix::fs::MetadataExt;
        let (home, app) = engine("by-name");
        let shown = show(&home);
        // A save replaces the file. One that changes nothing wakes the helper
        // for nothing.
        let state = home.join(review::STATE_DIR).join("state.json");
        let saved = || std::fs::symlink_metadata(&state).unwrap().ino();
        // The window names a folder by its place in a list. By the time a
        // second press arrives the list may have moved up, so the press also
        // says which folder it was shown for, and only that one is acted on.
        for name in ["One", "Two"] {
            let typed = json!({ "text": format!("{shown}/{name}") }).to_string();
            assert_eq!(ask(&app, "type_place", &typed)["ok"]["error"], Value::Null);
        }
        let first = json!({ "index": 0, "shown": format!("{shown}/One") }).to_string();
        let left = json!([format!("{shown}/Two")]);
        assert_eq!(ask(&app, "remove_place", &first)["ok"]["extra"], left);
        let before = saved();
        assert_eq!(ask(&app, "remove_place", &first)["ok"]["extra"], left);
        assert_eq!(saved(), before, "a stale removal saved the state");

        update_state(&app, |state| {
            for path in ["~/a", "~/b"] {
                let (path, added) = (path.to_string(), report::utc_now());
                state.skipped.push(review::Skip { path, added });
            }
        })
        .unwrap();
        let skipped = || ask(&app, "pending_review", "{}")["ok"]["skipped"].clone();
        let first = r#"{"index":0,"shown":"~/a"}"#;
        assert_eq!(ask(&app, "unskip_folder", first), json!({ "ok": null }));
        assert_eq!(skipped(), json!(["~/b"]));
        let before = saved();
        assert_eq!(ask(&app, "unskip_folder", first), json!({ "ok": null }));
        assert_eq!(skipped(), json!(["~/b"]));
        assert_eq!(saved(), before, "a stale press saved the state");
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn a_permission_gap_does_not_guess_which_access_control_denied_it() {
        let (label, help) = gap_text("permission-denied", false);
        assert_eq!(label, "No Access");
        assert_eq!(help, "macOS privacy protection or file permissions don't let Loose Keys read these. Nearly every Mac has some.");
    }

    #[test]
    fn every_grouped_copy_has_its_own_validated_file_action() {
        let _alone = one_scan();
        let (home, app) = engine("copy-actions");
        let secret = ["synthetic-copy", "only-value"].join("-");
        for folder in ["One", "Two", "caf\u{e9}"] {
            std::fs::create_dir(home.join(folder)).unwrap();
            std::fs::write(
                home.join(folder).join(".env"),
                format!("PASSWORD={secret}\n"),
            )
            .unwrap();
        }
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 3);
        let listed = ask(&app, "pending_review", "{}");
        let items = listed["ok"]["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        let copies = items[0]["places"].as_array().unwrap();
        assert_eq!(copies.len(), 3);
        assert!(!listed.to_string().contains(&secret));
        let mut flags = Vec::new();
        for copy in copies {
            let path = copy["path"].as_str().unwrap();
            let args = json!({"index":copy["id"]}).to_string();
            let answer = ask(&app, "item_path", &args);
            let expected = path.starts_with("~/One/") || path.starts_with("~/Two/");
            flags.push((copy["actionable"].clone(), expected));
            assert_eq!(answer.get("ok").is_some(), expected);
            if expected {
                assert_eq!(
                    answer["ok"],
                    home.join(path.strip_prefix("~/").unwrap())
                        .to_str()
                        .unwrap()
                );
            }
        }
        std::fs::remove_dir_all(home).unwrap();
        for (actual, expected) in flags {
            assert_eq!(
                actual,
                json!(expected),
                "copy actionability must be explicit"
            );
        }
    }

    /// A token in a known sign-in file is found by the file's own rule and by
    /// the service-token rule. Worth Reviewing had an item for each.
    #[test]
    fn a_token_two_rules_find_in_one_file_is_one_item() {
        let _alone = one_scan();
        let (home, app) = engine("one-item-per-token");
        let run = |n: usize, set: &str| -> String { set.chars().cycle().take(n).collect() };
        let alnum = "0123456789abcdefghijABCDEFGHIJklmnopKLMNOP";
        let tokens = [
            format!("{}{}", concat!("np", "m_"), run(36, alnum)),
            format!(
                "{}{}",
                concat!("ruby", "gems_"),
                run(48, "0123456789abcdef")
            ),
            format!("{}{}", concat!("pypi-", "AgEIcHlwaS5vcmc"), run(60, alnum)),
            format!("{}{}", concat!("gh", "p_"), run(36, &alnum[1..])),
        ];
        let files = [
            (
                ".npmrc",
                format!("//registry.npmjs.org/:_authToken={}\n", tokens[0]),
            ),
            (
                ".gem/credentials",
                format!("---\n:rubygems_api_key: {}\n", tokens[1]),
            ),
            (
                ".pypirc",
                format!("[pypi]\nusername = __token__\npassword = {}\n", tokens[2]),
            ),
            (
                "Library/Application Support/Claude/claude_desktop_config.json",
                json!({"mcpServers": {"github": {"command": "npx",
                    "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": tokens[3]}}}})
                .to_string(),
            ),
        ];
        for (path, body) in &files {
            let path = home.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
        let scanned = ask(&app, "start_scan", "{}");
        let listed = ask(&app, "pending_review", "{}");
        std::fs::remove_dir_all(home).unwrap();
        // Each file has two findings, one from each rule.
        assert_eq!(scanned["ok"]["review"], 8);
        let items = listed["ok"]["items"].as_array().unwrap();
        let mut places: Vec<Vec<String>> = items
            .iter()
            .map(|item| {
                let places = item["places"].as_array().unwrap().iter();
                places.map(|p| p["path"].as_str().unwrap().into()).collect()
            })
            .collect();
        let mut expected: Vec<Vec<String>> = files
            .iter()
            .map(|(path, _)| vec![format!("~/{path}"); 2])
            .collect();
        places.sort();
        expected.sort();
        // One item for each file, with both findings as its places.
        assert_eq!(places, expected);
        let text = listed.to_string();
        assert!(tokens.iter().all(|token| !text.contains(token)));
    }

    /// The one item for a token in GitHub CLI's hosts file says what the
    /// file's own rule says, such as signing out with gh, not what the
    /// service-token rule says of a token in any file.
    #[test]
    fn a_token_in_a_known_file_is_shown_with_that_file_s_advice() {
        let _alone = one_scan();
        let (home, app) = engine("known-file-advice");
        let run = |n: usize, set: &str| -> String { set.chars().cycle().take(n).collect() };
        let token = format!(
            "{}{}",
            concat!("gh", "o_"),
            run(36, "0123456789abcdefghijABCDEFGHIJklmnop")
        );
        let hosts = home.join(".config/gh/hosts.yml");
        std::fs::create_dir_all(hosts.parent().unwrap()).unwrap();
        std::fs::write(
            &hosts,
            format!("github.com:\n    user: fixture\n    oauth_token: {token}\n"),
        )
        .unwrap();
        let scanned = ask(&app, "start_scan", "{}");
        let listed = ask(&app, "pending_review", "{}");
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(scanned["ok"]["review"], 2);
        let items = listed["ok"]["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["places"].as_array().unwrap().len(), 2);
        let gh = rules::RULES
            .iter()
            .find(|r| r.id == "dev.gh.inline-token")
            .unwrap();
        let shown = (
            items[0]["rule"].as_str(),
            items[0]["title"].as_str(),
            items[0]["steps"].clone(),
        );
        assert_eq!(
            shown,
            (Some(gh.id), Some(gh.title), json!(gh.advice.steps)),
            "the entry speaks for the hosts file's own rule"
        );
        assert!(!listed.to_string().contains(&token));
    }

    /// Which copy an entry of several speaks for: one that needs a decision,
    /// then one set aside, never a fixed one while another is still there,
    /// and within each of those, one the file's own rule found before one
    /// found by a rule for any file's content.
    #[test]
    fn an_entry_speaks_for_the_file_s_own_rule_within_what_needs_attention() {
        let copy = |id: u64, rule: &str, title: &str| -> review::Item {
            serde_json::from_value(json!({
                "id": id, "revision": id, "rule": rule,
                "path": "~/.config/gh/hosts.yml", "secret": "digest-a", "line": 3,
                "title": title, "explanation": "e", "reason": null, "next_step": null,
            }))
            .unwrap()
        };
        let fresh = || review::Review {
            items: vec![
                copy(1, "secret.service-token", "generic"),
                copy(2, "dev.gh.inline-token", "own"),
            ],
            ..Default::default()
        };
        let lead = |state: &review::Review| {
            let entries = review_items(state).0;
            assert_eq!(entries.len(), 1);
            (
                entries[0].item.id,
                entries[0].item.title.clone(),
                entries[0].state,
            )
        };
        // Both need a decision: the file's own rule's copy.
        let mut state = fresh();
        assert_eq!(lead(&state), (2, "own".into(), "open"));
        // That copy kept, the other still needs a decision: that one.
        state
            .decide(2, review::Reason::Kept, now(), "then".into())
            .unwrap();
        assert_eq!(lead(&state), (1, "generic".into(), "open"));
        // Both set aside: the file's own rule's copy again.
        state
            .decide(1, review::Reason::Kept, now(), "then".into())
            .unwrap();
        assert_eq!(lead(&state), (2, "own".into(), "set-aside"));
        // That copy fixed while the other is still there, even set aside.
        state.items[1].resolved = true;
        assert_eq!(lead(&state), (1, "generic".into(), "set-aside"));
        let mut state = fresh();
        state.items[1].resolved = true;
        assert_eq!(lead(&state), (1, "generic".into(), "open"));
        // Both fixed: the file's own rule's copy.
        state.items[0].resolved = true;
        assert_eq!(lead(&state), (2, "own".into(), "fixed"));
    }

    /// GitHub CLI's hosts file in a synthetic home, signed in with a token
    /// put together here. Its own rule and the service-token rule find it.
    fn gh_hosts(home: &std::path::Path) -> String {
        let run: String = "0123456789abcdefghijABCDEFGHIJklmnop"
            .chars()
            .cycle()
            .take(36)
            .collect();
        let token = format!("{}{run}", concat!("gh", "o_"));
        let hosts = home.join(".config/gh/hosts.yml");
        std::fs::create_dir_all(hosts.parent().unwrap()).unwrap();
        std::fs::write(
            &hosts,
            format!("github.com:\n    user: fixture\n    oauth_token: {token}\n"),
        )
        .unwrap();
        token
    }

    /// The one entry for a token in GitHub CLI's hosts file speaks for that
    /// file's rule, which rates it lower than the service-token rule does.
    /// It was shown at the lower risk, where one of the two rows it replaced
    /// had the higher.
    #[test]
    fn a_known_file_entry_shows_the_highest_risk_of_its_copies() {
        let _alone = one_scan();
        let (home, app) = engine("known-file-risk");
        let token = gh_hosts(&home);
        let scanned = ask(&app, "start_scan", "{}");
        let listed = ask(&app, "pending_review", "{}");
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(scanned["ok"]["review"], 2);
        let rule = |id: &str| rules::RULES.iter().find(|r| r.id == id).unwrap();
        let (gh, any) = (rule("dev.gh.inline-token"), rule("secret.service-token"));
        assert_eq!((gh.severity, any.severity), ("medium", "high"));
        let items = listed["ok"]["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        let shown = (
            items[0]["rule"].as_str(),
            items[0]["title"].as_str(),
            items[0]["steps"].clone(),
            items[0]["severity"].as_str(),
        );
        assert_eq!(
            shown,
            (
                Some(gh.id),
                Some(gh.title),
                json!(gh.advice.steps),
                Some("high")
            ),
            "the file's own rule's advice, at the higher of the two risks"
        );
        assert!(!listed.to_string().contains(&token));
    }

    /// Which risk an entry of several shows: the highest of the copies its
    /// state comes from. Those needing a decision, else those set aside,
    /// else the fixed ones, as each was shown as a row of its own before.
    #[test]
    fn an_entry_s_risk_is_the_highest_of_the_copies_its_state_comes_from() {
        let copy = |id: u64, rule: &str, severity: &str| -> review::Item {
            serde_json::from_value(json!({
                "id": id, "revision": id, "rule": rule, "severity": severity,
                "path": "~/.config/gh/hosts.yml", "secret": "digest-a", "line": 3,
                "title": "t", "explanation": "e", "reason": null, "next_step": null,
            }))
            .unwrap()
        };
        let mut state = review::Review {
            items: vec![
                copy(1, "secret.service-token", "high"),
                copy(2, "dev.gh.inline-token", "medium"),
            ],
            ..Default::default()
        };
        let shown = |state: &review::Review| {
            let entries = review_items(state).0;
            assert_eq!(entries.len(), 1);
            let entry = &entries[0];
            (entry.item.id, entry.item.severity.clone(), entry.state)
        };
        // Both need a decision: the file's own rule's copy, at the higher.
        assert_eq!(shown(&state), (2, "high".into(), "open"));
        // Only the lower-rated copy needs one: its risk.
        state
            .decide(1, review::Reason::Kept, now(), "then".into())
            .unwrap();
        assert_eq!(shown(&state), (2, "medium".into(), "open"));
        // Both set aside: the higher again.
        state
            .decide(2, review::Reason::Kept, now(), "then".into())
            .unwrap();
        assert_eq!(shown(&state), (2, "high".into(), "set-aside"));
        // The higher-rated copy fixed, the other still there.
        state.items[0].resolved = true;
        assert_eq!(shown(&state), (2, "medium".into(), "set-aside"));
        // Both fixed: the higher.
        state.items[1].resolved = true;
        assert_eq!(shown(&state), (2, "high".into(), "fixed"));
    }

    /// The window's list, and the entry with a place in GitHub CLI's hosts
    /// file, as the window has them.
    fn hosts_entry(app: &App) -> (Value, Value) {
        let list = ask(app, "pending_review", "{}")["ok"].clone();
        let items = list["items"].as_array().unwrap();
        let in_hosts = |item: &&Value| {
            let mut places = item["places"].as_array().unwrap().iter();
            places.any(|p| p["path"] == "~/.config/gh/hosts.yml")
        };
        let entry = items.iter().find(in_hosts).unwrap().clone();
        (list, entry)
    }

    /// Each place of an entry, by path, and whether it is set aside.
    fn set_aside_places(entry: &Value) -> Vec<(String, bool)> {
        let places = entry["places"].as_array().unwrap().iter();
        let mut places: Vec<(String, bool)> = places
            .map(|p| {
                let path = p["path"].as_str().unwrap().to_string();
                (path, p["set_aside"].as_bool().unwrap())
            })
            .collect();
        places.sort();
        places
    }

    /// A press on an entry as the window makes it: its id, the revision it
    /// was drawn with and the reason, or null to move it back.
    fn press(app: &App, entry: &Value, reason: Value) -> Value {
        let args = json!({ "id": entry["id"], "revision": entry["revision"], "reason": reason });
        ask(app, "decide_review", &args.to_string())
    }

    fn mcp_password_config(prefix: &str) -> String {
        let password = [prefix, " ", "synthetic-shared-suffix"].concat();
        json!({"mcpServers":{"fixture":{"env":{"DATABASE_PASSWORD": password}}}}).to_string()
    }

    #[test]
    fn mcp_passwords_do_not_share_value_decisions() {
        let _alone = one_scan();
        let (home, app) = engine("mcp-password-collision");
        std::fs::create_dir_all(home.join(".cursor")).unwrap();
        std::fs::write(home.join(".cursor/mcp.json"), mcp_password_config("First")).unwrap();
        std::fs::write(home.join(".mcp.json"), mcp_password_config("Second")).unwrap();
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 2);
        let listed = ask(&app, "pending_review", "{}")["ok"].clone();
        let row = listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| {
                row["places"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|p| p["path"] == "~/.cursor/mcp.json")
            })
            .unwrap();
        assert_eq!(press(&app, row, json!("testing")), json!({"ok": null}));
        let stored = app.store.as_ref().unwrap().read().unwrap();
        let other = stored
            .items
            .iter()
            .find(|i| i.path == "~/.mcp.json")
            .unwrap();
        let undecided = stored.decision(other, now()).is_none();
        drop(app);
        std::fs::remove_dir_all(home).unwrap();
        assert!(
            undecided,
            "a value decision must not cover a different MCP environment password"
        );
        assert_eq!(listed["items"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn mcp_rotated_password_returns_to_review() {
        let _alone = one_scan();
        let (home, app) = engine("mcp-password-rotation");
        std::fs::create_dir_all(home.join(".cursor")).unwrap();
        let path = home.join(".cursor/mcp.json");
        std::fs::write(&path, mcp_password_config("First")).unwrap();
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 1);
        let row = ask(&app, "pending_review", "{}")["ok"]["items"][0].clone();
        assert_eq!(
            press(&app, &row, json!("no-longer-works")),
            json!({"ok": null})
        );
        std::fs::write(&path, mcp_password_config("Second")).unwrap();
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 1);
        let listed = ask(&app, "pending_review", "{}")["ok"].clone();
        let open = listed["counts"]["open"].as_u64().unwrap();
        drop(app);
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(
            open, 1,
            "a rotated MCP password must not inherit No Longer Works"
        );
        assert_eq!(listed["items"][0]["id"], row["id"]);
        assert_ne!(listed["items"][0]["revision"], row["revision"]);
    }

    /// Keeping It Here on Purpose is about a file. Chosen for the one entry
    /// of a token two rules find in GitHub CLI's hosts file, it covered only
    /// the copy the entry spoke for, and the entry stayed in Worth
    /// Reviewing. It covers each copy in that file, each by a decision of its
    /// own, and not a copy of the value in another file.
    #[test]
    fn keeping_an_entry_covers_each_copy_of_its_value_in_that_file() {
        let _alone = one_scan();
        let hosts = "~/.config/gh/hosts.yml".to_string();
        // Only in the hosts file.
        let (home, app) = engine("kept-in-one-file");
        let token = gh_hosts(&home);
        let scanned = ask(&app, "start_scan", "{}");
        let (_, entry) = hosts_entry(&app);
        let pressed = press(&app, &entry, json!("kept"));
        let (list, entry) = hosts_entry(&app);
        let stored = review::Store::open(&home).unwrap().read().unwrap();
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(scanned["ok"]["review"], 2);
        assert_eq!(pressed, json!({ "ok": null }));
        assert_eq!(
            set_aside_places(&entry),
            [(hosts.clone(), true), (hosts.clone(), true)]
        );
        assert_eq!(
            (&entry["state"], &entry["set_aside"]),
            (&json!("set-aside"), &json!("kept"))
        );
        assert_eq!(
            list["counts"],
            json!({ "open": 0, "set_aside": 1, "fixed": 0, "stored": 0, "stored_set_aside": 0, "stored_gone": 0 })
        );
        // Each copy by a decision of its own, with what was agreed to there:
        // its rule, kind, risk, what the file held and its place.
        assert_eq!(stored.decisions.len(), 2);
        let mut rules: Vec<&str> = stored.decisions.iter().map(|d| d.rule.as_str()).collect();
        rules.sort();
        assert_eq!(rules, ["dev.gh.inline-token", "secret.service-token"]);
        assert!(stored.decisions.iter().all(|d| {
            d.reason == review::Reason::Kept
                && d.secret.is_none()
                && stored.items.iter().any(|i| {
                    (&i.rule, &i.path, &i.subject, &i.scope, &i.fingerprint)
                        == (&d.rule, &d.path, &d.subject, &d.scope, &d.fingerprint)
                        && (&i.token_type, i.shared, &i.severity)
                            == (&d.token_type, d.shared, &d.severity)
                })
        }));
        assert!(!list.to_string().contains(&token));

        // In the hosts file and in a note: kept in the hosts file only.
        let (home, app) = engine("kept-not-elsewhere");
        let token = gh_hosts(&home);
        std::fs::write(home.join("notes.txt"), format!("{token}\n")).unwrap();
        let scanned = ask(&app, "start_scan", "{}");
        let (_, entry) = hosts_entry(&app);
        let lead = entry["path"].clone();
        let pressed = press(&app, &entry, json!("kept"));
        let (list, entry) = hosts_entry(&app);
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(scanned["ok"]["review"], 3);
        assert_eq!(lead, json!(hosts));
        assert_eq!(pressed, json!({ "ok": null }));
        assert_eq!(
            set_aside_places(&entry),
            [
                (hosts.clone(), true),
                (hosts.clone(), true),
                ("~/notes.txt".to_string(), false)
            ]
        );
        assert_eq!(entry["state"], "open");
        assert_eq!(
            list["counts"],
            json!({ "open": 1, "set_aside": 0, "fixed": 0, "stored": 0, "stored_set_aside": 0, "stored_gone": 0 })
        );
        assert!(!list.to_string().contains(&token));
    }

    /// Move to Worth Reviewing on such an entry returned the copy it spoke
    /// for and left the other set aside, so the entry was half set aside.
    #[test]
    fn moving_an_entry_back_returns_each_copy_of_its_value_in_that_file() {
        let _alone = one_scan();
        let hosts = "~/.config/gh/hosts.yml".to_string();
        let (home, app) = engine("returned-in-one-file");
        let token = gh_hosts(&home);
        let scanned = ask(&app, "start_scan", "{}");
        // Each copy kept by a decision of its own.
        update_state(&app, |state| {
            let ids: Vec<u64> = state.items.iter().map(|i| i.id).collect();
            for id in ids {
                state
                    .decide(id, review::Reason::Kept, now(), "then".into())
                    .unwrap();
            }
        })
        .unwrap();
        let (_, entry) = hosts_entry(&app);
        let kept = (entry["state"].clone(), set_aside_places(&entry));
        let pressed = press(&app, &entry, Value::Null);
        let (list, entry) = hosts_entry(&app);
        let stored = review::Store::open(&home).unwrap().read().unwrap();
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(scanned["ok"]["review"], 2);
        assert_eq!(
            kept,
            (
                json!("set-aside"),
                vec![(hosts.clone(), true), (hosts.clone(), true)]
            )
        );
        assert_eq!(pressed, json!({ "ok": null }));
        assert_eq!(
            set_aside_places(&entry),
            [(hosts.clone(), false), (hosts.clone(), false)]
        );
        assert_eq!(
            (&entry["state"], &entry["set_aside"]),
            (&json!("open"), &Value::Null)
        );
        assert_eq!(
            list["counts"],
            json!({ "open": 1, "set_aside": 0, "fixed": 0, "stored": 0, "stored_set_aside": 0, "stored_gone": 0 })
        );
        assert!(stored.decisions.is_empty());
        assert!(!list.to_string().contains(&token));
    }

    /// Keeping such an entry takes a decision for each copy. With room for
    /// one only, nothing is kept and nothing saved, not one copy of the two.
    #[test]
    fn keeping_an_entry_without_room_for_each_copy_keeps_none() {
        let _alone = one_scan();
        let (home, app) = engine("kept-without-room");
        let hosts_token = gh_hosts(&home);
        std::fs::write(home.join("notes.txt"), format!("{}\n", token('B'))).unwrap();
        let scanned = ask(&app, "start_scan", "{}");
        // Decisions about the note's place fill all the room for decisions
        // but one. A listed item uses them, so none makes room.
        update_state(&app, |state| {
            let other = state
                .items
                .iter()
                .find(|i| i.path == "~/notes.txt")
                .unwrap()
                .clone();
            for _ in 1..review::MAX_ITEMS {
                state.decisions.push(review::Decision {
                    reason: review::Reason::Kept,
                    secret: None,
                    rule: other.rule.clone(),
                    path: other.path.clone(),
                    subject: other.subject.clone(),
                    scope: other.scope.clone(),
                    fingerprint: None,
                    token_type: None,
                    shared: false,
                    severity: "high".into(),
                    decided: "2026-01-01T00:00:00Z".into(),
                    decided_at: 0,
                });
            }
        })
        .unwrap();
        let path = home.join(review::STATE_DIR).join("state.json");
        let before = std::fs::read(&path).unwrap();
        let (_, entry) = hosts_entry(&app);
        let refused = press(&app, &entry, json!("kept"));
        let unchanged = std::fs::read(&path).unwrap() == before;
        let (list, entry) = hosts_entry(&app);
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(scanned["ok"]["review"], 3);
        assert_eq!(
            refused["error"],
            "Too many findings are set aside. Move some back to Worth Reviewing."
        );
        assert!(unchanged, "a refused choice saved part of itself");
        let hosts = "~/.config/gh/hosts.yml".to_string();
        assert_eq!(
            set_aside_places(&entry),
            [(hosts.clone(), false), (hosts, false)]
        );
        assert_eq!(entry["state"], "open");
        assert!(!list.to_string().contains(&hosts_token));
    }

    #[test]
    fn a_review_item_the_app_cannot_act_on_says_so() {
        let (home, app) = engine("accented");
        // The app acts only on names in printable ASCII. An accented folder
        // name, an accented file name in a plain folder, and a plain path.
        let paths = [
            "~/Documents/Contrase\u{f1}as/claves.csv",
            "~/Documents/contrase\u{f1}as.csv",
            "~/Documents/passwords.csv",
        ];
        update_state(&app, |state| {
            for (n, path) in paths.iter().enumerate() {
                state.items.push(review::Item {
                    id: n as u64 + 1,
                    rule: "export.password-csv".into(),
                    path: path.to_string(),
                    ..serde_json::from_str(
                        r#"{"rule":"","path":"","line":null,"title":"t","explanation":"e","reason":null,"next_step":null,"deferred":false}"#,
                    )
                    .unwrap()
                });
            }
            state.next_id = paths.len() as u64;
        })
        .unwrap();
        let review = ask(&app, "pending_review", "{}");
        let items = review["ok"]["items"].as_array().unwrap();
        let at = |id: u64| items.iter().find(|i| i["id"] == id).unwrap();
        let path = ask(&app, "item_path", r#"{"index":1}"#);
        let skip = ask(&app, "skip_folder", r#"{"id":1}"#);
        std::fs::remove_dir_all(home).unwrap();
        // What the engine would refuse, the list says before a button is drawn.
        assert_eq!(path["error"], "This item has no file on this Mac to open.");
        assert_eq!(skip["error"], "That folder's name cannot be used.");
        assert_eq!(at(1)["path"], "~/Documents/Contrase\\u{f1}as/claves.csv");
        assert_eq!(at(1)["actionable"], false);
        assert_eq!(at(1)["folder"], Value::Null);
        // The folder is a separate question from the file in it.
        assert_eq!(at(2)["actionable"], false);
        assert_eq!(at(2)["folder"], "~/Documents");
        assert_eq!(at(3)["actionable"], true);
        assert_eq!(at(3)["folder"], "~/Documents");
    }

    #[test]
    fn unknown_commands_and_bad_arguments_are_errors() {
        let (home, app) = engine("refusals");
        let error = |command, args| ask(&app, command, args)["error"].clone();
        // A command this change removed, and a name shown escaped like any
        // other text from outside.
        assert_eq!(error("pick_place", "{}"), "Unknown command: pick_place.");
        assert_eq!(error("\u{1b}[31m", "{}"), "Unknown command: \\u{1b}[31m.");
        for args in ["", "not json", "[]", "null", "{\"index\":"] {
            assert_eq!(
                error("remove_place", args),
                "The request's arguments are not a JSON object."
            );
        }
        for args in [
            "{}",
            r#"{"index":"0"}"#,
            r#"{"index":-1}"#,
            r#"{"index":1.5}"#,
            r#"{"Index":0}"#,
        ] {
            assert_eq!(
                error("remove_place", args),
                "The request has no usable \"index\"."
            );
        }
        // An optional argument may be left out or null, but not wrong.
        assert_eq!(
            error(
                "decide_review",
                r#"{"id":1,"revision":0,"reason":"because"}"#
            ),
            "The request has no usable \"reason\"."
        );
        for args in [
            r#"{"id":1,"revision":0}"#,
            r#"{"id":1,"revision":0,"reason":null,"extra":true}"#,
        ] {
            assert_eq!(ask(&app, "decide_review", args), json!({ "ok": null }));
        }
        // A refusal by the command itself is the same kind of answer.
        assert_eq!(
            error("decide_review", r#"{"id":1,"revision":0,"reason":"kept"}"#),
            "That item is no longer in the list."
        );
        // Before ch_app_start there is nothing to run a command on.
        let early: Value = serde_json::from_str(&call(None, "places", "{}")).unwrap();
        assert_eq!(early, json!({ "error": "The app has not started." }));
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn starting_the_app_does_not_wait_for_the_store() {
        use std::os::fd::AsRawFd;
        use std::sync::{mpsc::channel, Arc};
        use std::time::Duration;
        let (home, app) = engine("store-held");
        let store = app.store.as_ref().unwrap();
        let fill = |state: &mut review::Review| {
            state.full = true;
            Ok(())
        };
        store.update(fill).unwrap();
        drop(app);
        // The background agent holds the store while it rechecks. Another
        // open of the folder holds it here, which locks as another process
        // would.
        let folder = home.join(review::STATE_DIR);
        let held = std::fs::File::open(&folder).unwrap();
        // SAFETY: `held` is an open file for the whole test.
        let lock = |kind| assert_eq!(unsafe { libc::flock(held.as_raw_fd(), kind) }, 0);
        lock(libc::LOCK_EX);
        let (opened, wait) = channel();
        let at = home.clone();
        std::thread::spawn(move || opened.send(Arc::new(App::open(Ok(at)))));
        let Ok(app) = wait.recv_timeout(Duration::from_secs(5)) else {
            lock(libc::LOCK_UN);
            panic!("starting waited for the store, which another process held");
        };

        // A command does wait for it, and then has what was stored.
        let (answered, answer) = channel();
        let asking = app.clone();
        std::thread::spawn(move || answered.send(ask(&asking, "pending_review", "{}")));
        let early = answer.recv_timeout(Duration::from_millis(300));
        lock(libc::LOCK_UN);
        assert!(
            early.is_err(),
            "a command answered while the store was held"
        );
        let list = answer
            .recv_timeout(Duration::from_secs(10))
            .expect("the command never answered once the store was free");
        assert_eq!(list["ok"]["full"], true);

        // The first command reads the store whatever it is: one that does
        // not read for itself still knows the store cannot be used.
        std::fs::write(folder.join("state.json"), "not a store").unwrap();
        let app = App::open(Ok(home.clone()));
        assert_eq!(
            ask(&app, "retry_notifications", "{}"),
            json!({ "error": "Loose Keys could not open its saved data." })
        );
        // A choice is refused too, and what was stored is left as it was.
        assert_eq!(
            ask(
                &app,
                "decide_review",
                r#"{"id":1,"revision":0,"reason":"kept"}"#
            ),
            json!({ "error": "Loose Keys could not open its saved data." })
        );
        assert_eq!(
            std::fs::read_to_string(folder.join("state.json")).unwrap(),
            "not a store"
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    /// The older version's folder stays once its state is moved out if
    /// anything else is in it, such as a save it left half done. Every start
    /// then took the store's lock to look for state to move, and waited for
    /// the background agent to let go of it.
    #[test]
    fn starting_the_app_does_not_wait_for_the_store_while_the_old_folder_remains() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::{mpsc::channel, Arc};
        use std::time::Duration;
        let home = std::env::temp_dir().join(format!(
            "credential-engine-test-{}-old-folder-left",
            std::process::id()
        ));
        let old = home.join(".loose-keys-review");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o700)).unwrap();
        let saved = review::Review {
            full: true,
            ..review::Review::default()
        };
        let saved = serde_json::to_vec(&saved).unwrap();
        for name in ["state.json", "state.tmp"] {
            std::fs::write(old.join(name), &saved).unwrap();
            std::fs::set_permissions(old.join(name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        drop(App::open(Ok(home.clone())));
        let folder = home.join(review::STATE_DIR);
        assert!(std::fs::symlink_metadata(folder.join("state.json")).is_ok());
        assert!(std::fs::symlink_metadata(old.join("state.tmp")).is_ok());

        // Another open of the folder holds the store, as the agent would.
        let held = std::fs::File::open(&folder).unwrap();
        // SAFETY: `held` is an open file for the whole test.
        let lock = |kind| assert_eq!(unsafe { libc::flock(held.as_raw_fd(), kind) }, 0);
        lock(libc::LOCK_EX);
        let (opened, wait) = channel();
        let at = home.clone();
        std::thread::spawn(move || opened.send(Arc::new(App::open(Ok(at)))));
        let Ok(app) = wait.recv_timeout(Duration::from_secs(5)) else {
            lock(libc::LOCK_UN);
            panic!("starting waited for the store, which another process held");
        };
        lock(libc::LOCK_UN);
        let list = ask(&app, "pending_review", "{}");
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(list["ok"]["full"], true);
    }

    #[test]
    fn a_scan_and_what_is_done_with_its_results_go_through_the_dispatcher() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let (home, app) = engine("round-trip");
        let shown = home.to_str().unwrap();
        std::fs::create_dir(home.join("Documents")).unwrap();
        std::fs::write(
            home.join("Documents/export.csv"),
            "url,username,password\nhttps://fixture.invalid,fixture,synthetic\n",
        )
        .unwrap();

        // A picked folder is added; a refused one says why.
        assert_eq!(ask(&app, "places", "{}")["ok"]["home"], shown);
        let typed = json!({ "text": format!("{shown}/Backup") }).to_string();
        let added = ask(&app, "type_place", &typed);
        assert_eq!(added["ok"]["extra"], json!([format!("{shown}/Backup")]));
        assert_eq!(added["ok"]["error"], Value::Null);
        assert_eq!(
            ask(&app, "type_place", r#"{"text":"/a/../b"}"#)["ok"]["error"],
            "Cannot add that folder: selected paths must not contain '..'."
        );
        let first = json!({ "index": 0, "shown": format!("{shown}/Backup") }).to_string();
        let removed = ask(&app, "remove_place", &first);
        assert_eq!(removed["ok"]["extra"], json!([]));
        assert_eq!(
            ask(&app, "summary_text", "{}")["error"],
            "Run a scan first."
        );

        // No other test scans through the app's side while this is held, so
        // these events are this scan's.
        let alone = one_scan();
        ch_set_event_handler(Some(seen));
        let results = ask(&app, "start_scan", "{}");
        ch_set_event_handler(None);
        drop(alone);
        let review = ask(&app, "pending_review", "{}");
        let item = &review["ok"]["items"][0];
        assert_eq!(results["ok"]["review"], 1);
        assert_eq!(item["path"], "~/Documents/export.csv");
        let seen = std::mem::take(&mut *SEEN.lock().unwrap());
        assert_eq!(seen[0], ("monitor-status".to_string(), "null".to_string()));
        let progress: Vec<&String> = seen[1..seen.len() - 2]
            .iter()
            .map(|(name, payload)| {
                assert_eq!(name, "scan-progress");
                payload
            })
            .collect();
        let last: Value = serde_json::from_str(progress.last().unwrap()).unwrap();
        assert_eq!(
            (&last["phase"], &last["findings"]),
            (&json!("finished"), &json!(1))
        );
        let names: Vec<&str> = seen.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names[names.len() - 2..], ["review-ready", "monitor-status"]);

        // The real path is handed over by a listed item's id.
        let real = format!("{shown}/Documents/export.csv");
        let by_id = json!({ "index": item["id"] }).to_string();
        assert_eq!(ask(&app, "item_path", &by_id)["ok"], real);

        let text = ask(&app, "summary_text", "{}");
        assert!(text["ok"]
            .as_str()
            .unwrap()
            .contains("Documents/export.csv"));

        // A report is a new file only its owner can read, and nothing in the
        // way of one is replaced or followed.
        let report = home.join("report.json");
        let save = |path: &Path, feedback: bool| {
            let args = json!({ "path": path, "feedback": feedback }).to_string();
            ask(&app, "save_report", &args)
        };
        assert_eq!(save(&report, false)["ok"], format!("{shown}/report.json"));
        let saved = std::fs::metadata(&report).unwrap();
        assert_eq!(saved.permissions().mode() & 0o777, 0o600);
        let full = std::fs::read_to_string(&report).unwrap();
        assert!(full.contains("~/Documents/export.csv"));
        const EXISTS: &str =
            "A file with that name already exists, and Loose Keys never replaces files. Choose another name.";
        assert_eq!(save(&report, true)["error"], EXISTS);
        symlink(home.join("elsewhere.json"), home.join("link.json")).unwrap();
        assert_eq!(save(&home.join("link.json"), true)["error"], EXISTS);
        assert!(!home.join("elsewhere.json").exists());
        assert_eq!(
            save(Path::new("report.json"), true)["error"],
            "That location is not a local folder."
        );
        assert_eq!(std::fs::read_to_string(&report).unwrap(), full);
        assert_eq!(
            save(&home.join("counts.json"), true)["ok"],
            format!("{shown}/counts.json")
        );
        let counts = std::fs::read_to_string(home.join("counts.json")).unwrap();
        assert!(!counts.contains("export.csv"));

        // A folder swapped for a link is not handed over.
        std::fs::rename(home.join("Documents"), home.join("Moved")).unwrap();
        symlink(home.join("Moved"), home.join("Documents")).unwrap();
        assert_eq!(
            ask(&app, "item_path", &by_id)["error"],
            "Could not open the folder (unreadable)."
        );

        // Only the issuer pages named in the rules are handed back.
        let known = rules::RULES.iter().find_map(|r| r.advice.link).unwrap();
        let link = |url: &str| ask(&app, "open_link", &json!({ "url": url }).to_string());
        assert_eq!(link(known)["ok"], known);
        assert_eq!(
            link("https://fixture.invalid/")["error"],
            "Loose Keys does not open that link."
        );

        // Quitting stops scans; the process itself is the front end's to end.
        assert_eq!(ask(&app, "prepare_quit", "{}"), json!({ "ok": null }));
        assert_eq!(ask(&app, "start_scan", "{}")["error"], SCAN_BLOCKED);
        // The app's monitor refuses a manual scan for quitting and nothing
        // else, so the refusal names that, and not a pause, sleep or the
        // background checks.
        for cause in ["paused", "sleeping", "monitoring"] {
            assert!(!SCAN_BLOCKED.contains(cause), "the refusal blames: {cause}");
        }
        assert!(SCAN_BLOCKED.contains("quitting"));
        std::fs::remove_dir_all(home).unwrap();
    }

    /// A save that fails turns the app's own background checks off and
    /// paused. That once cancelled whatever was running, so a scan the person
    /// had started ended early, as incomplete.
    #[test]
    fn a_scan_that_took_long_still_rechecks_the_listed_items() {
        let (home, mut app) = engine("long-scan");
        app.rechecks = std::time::Duration::from_millis(300);
        std::fs::create_dir(home.join("Documents")).unwrap();
        let export = home.join("Documents/export.csv");
        std::fs::write(
            &export,
            "url,username,password\nhttps://fixture.invalid,fixture,synthetic\n",
        )
        .unwrap();
        let alone = one_scan();
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 1);
        // The file is removed, and the next scan takes longer than all the
        // time its rechecks are given.
        std::fs::remove_file(&export).unwrap();
        *MID_SCAN.lock().unwrap() = Some(Box::new(|| {
            std::thread::sleep(std::time::Duration::from_millis(600));
        }));
        ch_set_event_handler(Some(mid_scan));
        let again = ask(&app, "start_scan", "{}");
        ch_set_event_handler(None);
        drop(alone);
        let state = ask(&app, "pending_review", "{}")["ok"]["items"][0]["state"].clone();
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(again["ok"]["review"], 0);
        assert_eq!(state, "fixed");
    }

    /// The rechecks' time is checked while a large file is read, and not
    /// only between items: one record could hold the store for as long as
    /// reading all of it took.
    #[test]
    fn a_recheck_of_a_large_record_stops_when_the_rechecks_run_out_of_time() {
        let (home, mut app) = engine("long-recheck");
        std::fs::create_dir(home.join(".claude")).unwrap();
        let record = home.join(".claude/session.jsonl");
        std::fs::write(&record, format!("{{\"out\":\"{}\"}}\n", token('A'))).unwrap();
        let alone = one_scan();
        ask(&app, "start_scan", "{}");
        let open = |app: &App| {
            let stored = app.store.as_ref().unwrap().read().unwrap();
            let rule = "secret.agent-record";
            stored
                .items
                .iter()
                .find(|i| i.rule == rule)
                .map(|i| !i.resolved)
        };
        assert_eq!(open(&app), Some(true));
        // The token is gone, before more of the record than can be read in
        // the time the rechecks are given.
        std::fs::write(&record, "{\"type\":\"filler\"}\n".repeat(2_000_000)).unwrap();
        app.rechecks = std::time::Duration::from_millis(20);
        let again = ask(&app, "start_scan", "{}");
        drop(alone);
        let open = open(&app);
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(again["ok"]["review"], 0, "{again}");
        assert_eq!(open, Some(true), "an item not reached in time stays open");
    }

    /// The background agent holds the store for its own rechecks, which can
    /// take longer than the app's. Waiting for it used up the app's, and an
    /// item whose file was deleted stayed open.
    #[test]
    fn rechecks_still_run_after_waiting_for_the_store() {
        use std::os::fd::AsRawFd;
        use std::sync::mpsc::channel;
        use std::time::Duration;
        let (home, mut app) = engine("store-held-rechecks");
        app.rechecks = Duration::from_millis(300);
        std::fs::create_dir(home.join("Documents")).unwrap();
        let export = home.join("Documents/export.csv");
        std::fs::write(&export, EXPORT).unwrap();
        let alone = one_scan();
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 1);
        std::fs::remove_file(&export).unwrap();
        // Mid-scan, another open of the folder takes the store, as the
        // agent's process would, for longer than the app's rechecks.
        let folder = home.join(review::STATE_DIR);
        let (took, taken) = channel();
        *MID_SCAN.lock().unwrap() = Some(Box::new(move || {
            let (held, wait) = channel();
            std::thread::spawn(move || {
                let open = std::fs::File::open(folder).unwrap();
                // SAFETY: `open` is an open file until the end of this thread.
                let lock = |kind| unsafe { libc::flock(open.as_raw_fd(), kind) };
                held.send(lock(libc::LOCK_EX)).unwrap();
                std::thread::sleep(Duration::from_millis(600));
                lock(libc::LOCK_UN);
            });
            took.send(wait.recv_timeout(Duration::from_secs(5)))
                .unwrap();
        }));
        ch_set_event_handler(Some(mid_scan));
        let again = ask(&app, "start_scan", "{}");
        ch_set_event_handler(None);
        drop(alone);
        let state = ask(&app, "pending_review", "{}")["ok"]["items"][0]["state"].clone();
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(
            taken.try_recv(),
            Ok(Ok(0)),
            "the store was not taken mid-scan"
        );
        assert_eq!(again["ok"]["review"], 0);
        assert_eq!(state, "fixed");
    }

    const EXPORT: &str = "url,username,password\nhttps://fixture.invalid,fixture,synthetic\n";

    /// A list replaced during a scan, as when its file is deleted or put
    /// back from a copy, has another key than the one the scan's digests
    /// were made with. Saved into it, what the scan found was taken for other
    /// values: the next scan marked it fixed and listed it again as news.
    #[test]
    fn a_scan_whose_list_was_replaced_saves_nothing() {
        let (home, app) = engine("replaced-list");
        std::fs::write(home.join("notes.txt"), format!("{}\n", token('A'))).unwrap();
        let replaced = vec![9u8; 32];
        let (key, during) = (replaced.clone(), home.clone());
        let alone = one_scan();
        *MID_SCAN.lock().unwrap() = Some(Box::new(move || {
            let store = review::Store::open(&during).unwrap();
            let fresh = |state: &mut review::Review| {
                *state = review::Review {
                    key,
                    ..review::Review::default()
                };
                Ok(())
            };
            store.update(fresh).unwrap();
        }));
        ch_set_event_handler(Some(mid_scan));
        let scan = ask(&app, "start_scan", "{}");
        ch_set_event_handler(None);
        // The next scan is made with the new list's key, and saved.
        let next = ask(&app, "start_scan", "{}");
        drop(alone);
        let stored = review::Store::open(&home).unwrap().read().unwrap();
        std::fs::remove_dir_all(&home).unwrap();
        assert_eq!(
            scan["error"],
            "The review list was replaced during the scan, so nothing it found was saved. Scan again."
        );
        assert_eq!(next["ok"]["review"], 1);
        assert_eq!(stored.key, replaced);
        assert_eq!(stored.items.len(), 1);
    }

    /// The app acts only on a plain name, and it took looking at a listed
    /// file again for acting on it: an item whose name had an accent was
    /// never rechecked, and stayed open after its file was deleted.
    #[test]
    fn an_item_with_an_accented_name_is_fixed_once_its_file_is_gone() {
        let (home, app) = engine("accented-gone");
        std::fs::create_dir(home.join("Documents")).unwrap();
        let export = home.join("Documents/contrase\u{f1}as.csv");
        std::fs::write(&export, EXPORT).unwrap();
        let alone = one_scan();
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 1);
        std::fs::remove_file(&export).unwrap();
        let again = ask(&app, "start_scan", "{}");
        drop(alone);
        let item = ask(&app, "pending_review", "{}")["ok"]["items"][0].clone();
        let path = ask(&app, "item_path", r#"{"index":1}"#);
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(again["ok"]["review"], 0);
        assert_eq!(item["state"], "fixed");
        // Reading it again is all: the front end is still handed no such path.
        assert_eq!(item["actionable"], false);
        assert_eq!(path["error"], "This item has no file on this Mac to open.");
    }

    /// A drive that is ejected takes its mount point with it: a file on it
    /// is not there, and neither is its folder. That was taken for the file
    /// having been removed, and its item was marked fixed.
    #[test]
    fn an_item_on_an_ejected_drive_stays_open() {
        let _alone = one_scan();
        /// What an item is to hold about its volume, given the drive's
        /// folder and what the scan kept.
        type Kept = fn(&Path, Option<u32>) -> Option<u32>;
        // A file is found on a drive, which is then ejected, either while it
        // is still a place to scan or after it was taken off the list.
        // Returns what the scan kept about the file's volume, how the scan
        // after the drive went ended, and the item's state then.
        let ejected = |name: &str, included: bool, kept: Kept| {
            let (home, app) = engine(name);
            let drive = format!("credential-engine-test-{}-{name}-drive", std::process::id());
            let drive = home.with_file_name(drive);
            std::fs::create_dir_all(drive.join("dir")).unwrap();
            std::fs::write(drive.join("dir/export.csv"), EXPORT).unwrap();
            let shown = drive.to_str().unwrap();
            let typed = json!({ "text": shown }).to_string();
            assert_eq!(ask(&app, "type_place", &typed)["ok"]["error"], Value::Null);
            assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 1);
            let found = update_state(&app, |state| {
                let found = state.items[0].mount;
                state.items[0].mount = kept(&drive, found);
                found
            });
            // Ejected: the mount point is gone, the file was not removed.
            let away = drive.with_extension("ejected");
            std::fs::rename(&drive, &away).unwrap();
            if !included {
                let first = json!({ "index": 0, "shown": shown }).to_string();
                assert_eq!(ask(&app, "remove_place", &first)["ok"]["extra"], json!([]));
            }
            let status = ask(&app, "start_scan", "{}")["ok"]["status"].clone();
            let state = ask(&app, "pending_review", "{}")["ok"]["items"][0]["state"].clone();
            std::fs::remove_dir_all(home).unwrap();
            std::fs::remove_dir_all(away).unwrap();
            (found, status, state)
        };
        let as_found: Kept = |_, found| found;
        // What a test can make is on the volume its home folder is on.
        let found = Ok(Some(0));
        // Still a place to scan: the scan says it could not read it.
        assert_eq!(
            ejected("eject", true, as_found),
            (found.clone(), json!("partial"), json!("open"))
        );
        // No longer one. A real drive is a volume of its own, mounted at its
        // folder, so the item is given what a scan keeps for one.
        let mounted: Kept = |drive, _| u32::try_from(drive.components().count()).ok();
        assert_eq!(
            ejected("eject-unlisted", false, mounted),
            (found.clone(), json!("complete"), json!("open"))
        );
        // An item listed before anything was kept about its volume.
        assert_eq!(
            ejected("eject-old", false, |_, _| None),
            (found.clone(), json!("complete"), json!("open"))
        );
        // A folder on the home folder's own volume does not go away with a
        // drive. One that is gone was deleted, wherever it was.
        assert_eq!(
            ejected("eject-folder", false, as_found),
            (found, json!("complete"), json!("fixed"))
        );
    }

    /// A share mounted in the home folder leaves its mount point behind,
    /// empty, when it is disconnected. Its files are then not there, in a
    /// folder that is, as if they had been deleted.
    #[test]
    fn an_item_on_a_share_disconnected_in_the_home_folder_stays_open() {
        let _alone = one_scan();
        let (home, app) = engine("share");
        for dir in ["mnt/share", "mnt/share/dir", "Documents/old"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
            std::fs::write(home.join(dir).join("export.csv"), EXPORT).unwrap();
        }
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 3);
        // A real share is a volume of its own, mounted at its folder, so its
        // two items are given what a scan keeps for one.
        let share = u32::try_from(home.join("mnt/share").components().count()).unwrap();
        update_state(&app, |state| {
            let on_share = |i: &&mut review::Item| i.path.starts_with("~/mnt/share/");
            for item in state.items.iter_mut().filter(on_share) {
                item.mount = Some(share);
            }
        })
        .unwrap();
        // Disconnected. And a folder of the home's own is deleted.
        std::fs::remove_dir_all(home.join("mnt/share/dir")).unwrap();
        std::fs::remove_file(home.join("mnt/share/export.csv")).unwrap();
        std::fs::remove_dir_all(home.join("Documents/old")).unwrap();
        let again = ask(&app, "start_scan", "{}");
        let review = ask(&app, "pending_review", "{}");
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(again["ok"]["review"], 0);
        let items = review["ok"]["items"].as_array().unwrap();
        let text = |item: &Value, field: &str| item[field].as_str().unwrap().to_string();
        let state = |i: &Value| (text(i, "path"), text(i, "state"));
        let mut states: Vec<_> = items.iter().map(state).collect();
        states.sort();
        let expected = [
            ("~/Documents/old/export.csv", "fixed"),
            ("~/mnt/share/dir/export.csv", "open"),
            ("~/mnt/share/export.csv", "open"),
        ];
        let expected = expected.map(|(path, state)| (path.to_string(), state.to_string()));
        assert_eq!(states, expected);
        // What is kept about a volume stays on this side of the interface.
        assert!(items.iter().all(|item| item.get("mount").is_none()));
    }

    #[test]
    fn a_save_that_fails_during_a_scan_leaves_the_scan_to_finish() {
        let (home, app) = engine("failed-save");
        let app = std::sync::Arc::new(app);
        std::fs::create_dir(home.join("Documents")).unwrap();
        std::fs::write(
            home.join("Documents/export.csv"),
            "url,username,password\nhttps://fixture.invalid,fixture,synthetic\n",
        )
        .unwrap();
        // Setting an item aside is a save. The first one makes the state file,
        // with the key a scan needs. The file is then damaged, so the next
        // one fails.
        let set_aside = |app: &App| call(Some(app), "decide_review", r#"{"id":1,"revision":0}"#);
        let answer = |text: String| serde_json::from_str::<Value>(&text).unwrap();
        assert_eq!(answer(set_aside(&app)), json!({ "ok": null }));
        let state = home.join(review::STATE_DIR).join("state.json");
        std::fs::write(state, "{damaged").unwrap();

        // That next save comes while the scan is running.
        let (during, (tx, rx)) = (app.clone(), std::sync::mpsc::channel());
        let alone = one_scan();
        *MID_SCAN.lock().unwrap() = Some(Box::new(move || {
            let _ = tx.send(set_aside(&during));
        }));
        ch_set_event_handler(Some(mid_scan));
        let results = ask(&app, "start_scan", "{}");
        let again = ask(&app, "start_scan", "{}");
        ch_set_event_handler(None);
        drop(alone);

        const UNREADABLE: &str = "The review list file is damaged or in an unknown format.";
        let failed = rx.try_recv().expect("no save was tried during the scan");
        assert_eq!(answer(failed), json!({ "error": UNREADABLE }));
        // The scan went on to its end and found the file.
        let found = |scan: &Value| {
            let scan = &scan["ok"];
            (
                scan["status"].clone(),
                scan["review"].clone(),
                scan["not_checked"].clone(),
            )
        };
        assert_eq!(found(&results), (json!("complete"), json!(1), json!(0)));
        // The next scan is not refused either, and the list says that it is
        // unavailable, not that it is empty.
        assert_eq!(found(&again), found(&results));
        assert_eq!(ask(&app, "pending_review", "{}")["ok"]["error"], UNREADABLE);
        std::fs::remove_dir_all(home).unwrap();
    }

    /// A scan whose own save could not read the state has lost what it
    /// found, though no other command saw the state unreadable first.
    #[test]
    fn a_scan_whose_save_could_not_read_the_state_keeps_the_error() {
        let (home, app) = engine("scan-save-unreadable");
        update_state(&app, |_| ()).unwrap();
        std::fs::create_dir(home.join("Documents")).unwrap();
        std::fs::write(
            home.join("Documents/export.csv"),
            "url,username,password\nhttps://fixture.invalid,fixture,synthetic\n",
        )
        .unwrap();
        let state = home.join(review::STATE_DIR).join("state.json");
        let damaged = state.clone();
        let alone = one_scan();
        *MID_SCAN.lock().unwrap() = Some(Box::new(move || {
            std::fs::write(damaged, "{damaged").unwrap();
        }));
        ch_set_event_handler(Some(mid_scan));
        let scan = ask(&app, "start_scan", "{}");
        ch_set_event_handler(None);
        drop(alone);
        std::fs::remove_file(&state).unwrap();
        let after = ask(&app, "pending_review", "{}")["ok"]["error"].clone();
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(scan["ok"]["review"], 1, "{scan}");
        assert_eq!(
            after, "The review list file is damaged or in an unknown format.",
            "the scan's lost findings were not reported"
        );
    }

    /// State that could not be read from the start gives the app no key to
    /// digest with. A scan the person asks for still runs, saves nothing,
    /// and the list says it is unavailable, not that it is empty.
    #[test]
    fn a_scan_runs_when_the_state_could_not_be_read_from_the_start() {
        use std::os::unix::fs::PermissionsExt;
        let home = std::env::temp_dir().join(format!(
            "credential-engine-test-{}-unreadable-from-start",
            std::process::id()
        ));
        std::fs::create_dir(&home).unwrap();
        drop(review::Store::open(&home).unwrap());
        let state = home.join(review::STATE_DIR).join("state.json");
        std::fs::write(&state, "{damaged").unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::create_dir(home.join("Documents")).unwrap();
        std::fs::write(
            home.join("Documents/export.csv"),
            "url,username,password\nhttps://fixture.invalid,fixture,synthetic\n",
        )
        .unwrap();
        let app = App::open(Ok(home.clone()));
        app.ready();
        const UNREADABLE: &str = "The review list file is damaged or in an unknown format.";
        assert_eq!(ask(&app, "pending_review", "{}")["ok"]["error"], UNREADABLE);

        let alone = one_scan();
        SEEN.lock().unwrap().clear();
        ch_set_event_handler(Some(seen));
        let scan = ask(&app, "start_scan", "{}");
        ch_set_event_handler(None);
        let events = std::mem::take(&mut *SEEN.lock().unwrap());
        drop(alone);

        let saved = std::fs::read_to_string(&state).unwrap();
        // What it found is lost, so the error stays once the state reads.
        std::fs::remove_file(&state).unwrap();
        let after = ask(&app, "pending_review", "{}")["ok"]["error"].clone();
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(scan["ok"]["review"], 1, "{scan}");
        assert_eq!(
            events.last().map(|(name, _)| name.as_str()),
            Some("monitor-status"),
            "the window was not told the scan ended"
        );
        assert_eq!(saved, "{damaged", "the scan saved over the state");
        assert_eq!(after, UNREADABLE);
    }

    #[test]
    fn a_scan_run_to_its_end_decides_whether_the_list_is_still_full() {
        static STOP: OnceLock<std::sync::Arc<AtomicBool>> = OnceLock::new();
        /// Stops the scan at its first event, as the Stop button would.
        extern "C" fn stop(_: *const c_char, _: *const c_char) {
            if let Some(cancel) = STOP.get() {
                cancel.store(true, Ordering::SeqCst);
            }
        }
        let _alone = one_scan();
        let (home, app) = engine("list-full");
        std::fs::create_dir(home.join("corpus")).unwrap();
        // One folder's findings fill the list and one more is left out, as
        // the background agent would record them.
        let found = Report {
            schema: "loose-keys/report/1",
            tool_version: "test",
            generated_at: report::utc_now(),
            status: "partial",
            context: "user",
            coverage: report::Coverage::default(),
            findings: (0..=review::MAX_ITEMS)
                .map(|n| report::Finding {
                    rule: "export.password-csv",
                    category: "password-export",
                    kind: "review",
                    title: "Synthetic finding",
                    explanation: "Synthetic match",
                    path: format!("~/corpus/export-{n}.csv"),
                    ..report::Finding::default()
                })
                .collect(),
            not_checked: Vec::new(),
        };
        let store = app.store.as_ref().unwrap();
        let (state, _) = store.update(|state| Ok(state.ingest(&found))).unwrap();
        assert!(state.full);
        let full = || ask(&app, "pending_review", "{}")["ok"]["full"].clone();
        let scan = || ask(&app, "start_scan", "{}");

        // The person stops checking that folder, so nothing new arrives from
        // it. Their next scan leaves nothing out, but every item is still on
        // the list and it has no room: the notice stays, because the next
        // finding would be left out.
        let skip = json!({ "id": state.items[0].id }).to_string();
        assert_eq!(ask(&app, "skip_folder", &skip), json!({ "ok": null }));
        assert_eq!(full(), true);
        assert_eq!(scan()["ok"]["review"], 0);
        assert_eq!(full(), true);

        // And a new finding is left out.
        std::fs::create_dir(home.join("Documents")).unwrap();
        std::fs::write(
            home.join("Documents/export.csv"),
            "url,username,password\nhttps://fixture.invalid,fixture,synthetic\n",
        )
        .unwrap();
        assert_eq!(scan()["ok"]["review"], 1);
        assert_eq!(full(), true);

        // Ten items are fixed and that file is gone, so a scan would leave
        // nothing out and find room. One stopped part-way has not shown
        // that: it did not present every finding.
        std::fs::remove_file(home.join("Documents/export.csv")).unwrap();
        store
            .update(|state| {
                for item in state.items.iter_mut().take(10) {
                    item.resolved = true;
                }
                Ok(())
            })
            .unwrap();
        STOP.set(app.monitor.cancel.clone()).unwrap();
        ch_set_event_handler(Some(stop));
        let stopped = scan();
        ch_set_event_handler(None);
        assert_eq!(stopped["ok"]["gaps"][0]["label"], "Only Partly Checked");
        assert_eq!(full(), true);
        // One that runs to its end has.
        assert_eq!(scan()["ok"]["review"], 0);
        assert_eq!(full(), false);
        std::fs::remove_dir_all(home).unwrap();
    }

    /// A scan still reads a known sign-in file in a folder the person
    /// stopped checking, so its item is marked fixed when that read shows
    /// the credential gone. Any other file there is not read, and its item
    /// stays as it was.
    #[test]
    fn a_known_file_in_a_skipped_folder_is_still_marked_fixed() {
        let _alone = one_scan();
        let (home, app) = engine("skipped-known-file");
        let folder = home.join(".config/gh");
        std::fs::create_dir_all(&folder).unwrap();
        let host = ["git", "hub.com"].concat();
        let hosts = folder.join("hosts.yml");
        std::fs::write(
            &hosts,
            format!("{host}:\n    oauth_token: synthetic-only\n"),
        )
        .unwrap();
        let export = folder.join("export.csv");
        std::fs::write(
            &export,
            "url,username,password\nhttps://fixture.invalid,fixture,synthetic\n",
        )
        .unwrap();
        let first = ask(&app, "start_scan", "{}");
        let items = || ask(&app, "pending_review", "{}")["ok"]["items"].clone();
        let listed = items();
        let at = |items: &Value, path: &str| {
            let items = items.as_array().unwrap();
            items.iter().find(|i| i["path"] == path).unwrap().clone()
        };
        let skip = json!({ "id": at(&listed, "~/.config/gh/hosts.yml")["id"] }).to_string();
        let skipped = ask(&app, "skip_folder", &skip);
        // Signed out, and the other file removed.
        std::fs::write(&hosts, format!("{host}:\n    user: fixture\n")).unwrap();
        std::fs::remove_file(&export).unwrap();
        let second = ask(&app, "start_scan", "{}");
        let after = items();
        drop(app);
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(first["ok"]["review"], 2, "{first}");
        assert_eq!(skipped, json!({ "ok": null }));
        assert_eq!(second["ok"]["review"], 0, "{second}");
        assert_eq!(at(&after, "~/.config/gh/hosts.yml")["state"], "fixed");
        assert_eq!(at(&after, "~/.config/gh/export.csv")["state"], "open");
    }

    #[test]
    fn a_command_that_panics_is_an_error_and_the_next_one_still_works() {
        let (home, app) = engine("panic");
        // Poison a lock, as a command that panicked while holding it would.
        std::thread::scope(|scope| {
            let held = scope.spawn(|| {
                let _review = app.review.lock().unwrap();
                panic!("synthetic");
            });
            assert!(held.join().is_err());
        });
        assert_eq!(
            ask(&app, "places", "{}"),
            json!({ "error": "That action stopped unexpectedly." })
        );
        assert_eq!(ask(&app, "places", "{}")["ok"]["extra"], json!([]));
        // The same for the store, after a change that panicked half-way.
        let store = app.store.as_ref().unwrap();
        let change = || store.update(|_| -> Answer<()> { panic!("synthetic") });
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(change)).is_err());
        assert_eq!(ask(&app, "pending_review", "{}")["ok"]["items"], json!([]));
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn the_c_functions_answer_in_json_whatever_they_are_handed() {
        // No test calls ch_app_start: it would open the real home folder.
        let ask = |command: *const c_char, args: *const c_char| {
            // SAFETY: each is null or a NUL-terminated literal, and the
            // answer is released once.
            unsafe {
                let answer = ch_call(command, args);
                let read = serde_json::from_str::<Value>(CStr::from_ptr(answer).to_str().unwrap());
                ch_free(answer);
                read.unwrap()
            }
        };
        let (places, none) = (c"places".as_ptr(), c"{}".as_ptr());
        assert_eq!(ask(places, none)["error"], "The app has not started.");
        for (command, args) in [
            (std::ptr::null(), none),
            (places, std::ptr::null()),
            (c"\xff".as_ptr(), none),
        ] {
            assert_eq!(
                ask(command, args)["error"],
                "The request is not valid text."
            );
        }
        // SAFETY: null is allowed, and nothing is released.
        unsafe { ch_free(std::ptr::null_mut()) };
    }

    /// As root no link is followed, wherever it leads, so a link that was
    /// not followed then is not said to lead out of the home folder.
    #[test]
    fn a_link_not_followed_as_root_is_not_said_to_leave_the_home() {
        let mut r = Report {
            schema: "loose-keys/report/1",
            tool_version: "0.1.0",
            generated_at: report::utc_now(),
            status: "partial",
            context: "user",
            coverage: report::Coverage::default(),
            findings: vec![],
            not_checked: vec![report::NotChecked {
                path: "~/.npmrc".into(),
                reason: "symlink",
            }],
        };
        let help = |r: &Report| results_view(r).gaps[0].help.clone();
        assert!(help(&r).contains("outside your home folder"));
        r.context = "system";
        let root = help(&r);
        assert!(!root.contains("outside"), "{root}");
        assert!(root.contains("as root"), "{root}");
    }

    #[test]
    fn work_limit_is_named_without_a_note() {
        assert_eq!(gap_text("scan-limit", false), ("Only Partly Checked", ""));
    }

    // Read limits differ by kind of file, and are in the usage guide.
    #[test]
    fn size_limit_is_named_without_a_note() {
        assert_eq!(gap_text("too-large", false), ("Too Large to Check", ""));
    }

    // Also a file in a form the scanner doesn't read, or a database an open
    // app has unsaved changes in: not always an error from macOS.
    #[test]
    fn an_unreadable_gap_says_what_to_try_without_blaming_macos() {
        let (label, help) = gap_text("unreadable", false);
        assert_eq!(label, "Couldn't Be Read");
        assert_eq!(
            help,
            "If an app such as a browser is using any of these, quit the app, then scan again."
        );
    }

    // A folder is listed when it holds files kept only in the cloud: the
    // folder itself is on this Mac.
    #[test]
    fn a_cloud_only_gap_does_not_say_its_place_is_off_this_mac() {
        let (label, help) = gap_text("cloud-only-file", false);
        assert_eq!(label, "Stored Only in the Cloud");
        assert_eq!(help, "Download these to this Mac, then scan again.");
    }

    #[test]
    fn the_review_list_groups_copies_and_counts_what_was_set_aside() {
        let item = |id: u64, path: &str, secret: Option<&str>| {
            review::Item {
            id,
            path: path.into(),
            secret: secret.map(str::to_string),
            fingerprint: Some("private-file-digest".into()),
            rule: "secret.service-token".into(),
            revision: id,
            ..serde_json::from_str(r#"{"rule":"","path":"","line":null,"title":"t","explanation":"e","reason":null,"next_step":null,"deferred":false}"#).unwrap()
        }
        };
        let mut state = review::Review {
            items: vec![
                item(1, "~/app/.env", Some("digest-a")),
                item(2, "~/.claude/projects/p/s.jsonl", Some("digest-a")),
                item(3, "~/.npmrc", Some("digest-b")),
                item(4, "~/Downloads/export.csv", None),
                item(5, "~/old/export.csv", None),
            ],
            ..Default::default()
        };
        state.items[4].resolved = true;
        state
            .decide(3, review::Reason::Kept, now(), "then".into())
            .unwrap();
        let (items, counts) = review_items(&state);
        // Five places, four entries: the two copies of one credential are one.
        assert_eq!(items.len(), 4);
        assert_eq!(
            items[0].places.iter().map(|p| p.id).collect::<Vec<_>>(),
            [1, 2]
        );
        assert_eq!(items[0].state, "open");
        assert_eq!(
            (items[1].state, items[1].set_aside),
            ("set-aside", Some(review::Reason::Kept))
        );
        assert_eq!(items[3].state, "fixed");
        assert_eq!((counts.open, counts.set_aside, counts.fixed), (2, 1, 1));
        // A folder may be skipped, but never the home folder itself.
        assert_eq!(items[0].folder.as_deref(), Some("~/app"));
        assert_eq!(items[1].folder, None);
        // Digests never reach the front end.
        let json = serde_json::to_string(&items).unwrap();
        assert!(!json.contains("digest-a") && !json.contains("private-file-digest"));

        // Once the first copy is fixed, the entry speaks for the copy that is
        // still there: its path is what the person is shown and acts on.
        state.items[0].resolved = true;
        let (items, _) = review_items(&state);
        assert_eq!(
            (
                items[0].item.id,
                items[0].item.path.as_str(),
                items[0].state
            ),
            (2, "~/.claude/projects/p/s.jsonl", "open")
        );
        assert_eq!(items[0].folder.as_deref(), Some("~/.claude/projects/p"));
        assert!(!items[0].item.resolved);
        assert!(!serde_json::to_string(&items).unwrap().contains("digest-a"));
        // Keeping it covers one place. With two, the entry moves on to the
        // place still to be decided, and says which one was set aside.
        state.items[0].resolved = false;
        state
            .decide(1, review::Reason::Kept, now(), "then".into())
            .unwrap();
        let (items, _) = review_items(&state);
        assert_eq!((items[0].item.id, items[0].state), (2, "open"));
        assert_eq!(
            items[0]
                .places
                .iter()
                .map(|p| p.set_aside)
                .collect::<Vec<_>>(),
            [true, false]
        );
        state
            .decide(2, review::Reason::Kept, now(), "then".into())
            .unwrap();
        assert_eq!(review_items(&state).0[0].state, "set-aside");
    }

    #[test]
    fn a_set_aside_entry_says_when_it_was_set_aside() {
        let copy = |id: u64, path: &str, secret: &str| -> review::Item {
            serde_json::from_value(json!({
                "id": id, "revision": id, "rule": "secret.service-token", "path": path,
                "secret": secret, "line": null, "title": "t", "explanation": "e",
                "reason": null, "next_step": null,
            }))
            .unwrap()
        };
        let mut state = review::Review {
            items: vec![
                copy(1, "~/a.txt", "digest-a"),
                copy(2, "~/b.txt", "digest-b"),
            ],
            ..Default::default()
        };
        let stamp = "2026-10-24T18:00:00Z";
        state
            .decide(1, review::Reason::Testing, now(), stamp.into())
            .unwrap();
        let (items, _) = review_items(&state);
        assert_eq!(items[0].state, "set-aside");
        assert_eq!(items[0].set_aside_at.as_deref(), Some(stamp));
        // An open entry has none.
        assert_eq!(items[1].set_aside_at, None);
        let json = serde_json::to_value(&items).unwrap();
        assert_eq!(json[0]["set_aside_at"], stamp);
        // Returned to review, it has none either.
        state.undo(1);
        assert_eq!(review_items(&state).0[0].set_aside_at, None);
    }

    /// A known file's item saved before its rule gave the digest of its
    /// value, beside the service-token rule's item for that value in the same
    /// file. After the next scan they are one entry, whatever was decided.
    #[test]
    fn a_known_file_item_saved_without_its_value_joins_the_token_s_entry() {
        use review::Reason::*;
        let finding = |rule: &'static str, secret: Option<&str>| report::Finding {
            rule,
            category: "developer-cloud",
            kind: "review",
            severity: "high",
            title: "t",
            explanation: "e",
            path: "~/.npmrc".into(),
            secret: secret.map(str::to_string),
            fingerprint: Some(format!("{rule}-file-digest")),
            ..report::Finding::default()
        };
        let scan = |known: Option<&str>| Report {
            schema: "loose-keys/report/1",
            tool_version: "0.1.0",
            generated_at: report::utc_now(),
            status: "complete",
            context: "user",
            coverage: report::Coverage::default(),
            findings: vec![
                finding("dev.npm.inline-credentials", known),
                finding("secret.service-token", Some("digest-a")),
            ],
            not_checked: Vec::new(),
        };
        // The entries before and after, given what was decided about which item.
        let entries = |decided: Option<(usize, review::Reason)>| {
            let mut state = review::Review::default();
            state.ingest(&scan(None));
            if let Some((n, reason)) = decided {
                let id = state.items[n].id;
                state.decide(id, reason, now(), "then".into()).unwrap();
            }
            let shown = |state: &review::Review| -> Vec<_> {
                let entries = review_items(state).0;
                entries
                    .iter()
                    .map(|e| (e.places.len(), e.state, e.set_aside))
                    .collect()
            };
            let before = shown(&state);
            state.ingest(&scan(Some("digest-a")));
            (before, shown(&state))
        };
        assert_eq!(
            entries(None),
            (
                vec![(1, "open", None), (1, "open", None)],
                vec![(2, "open", None)]
            )
        );
        // Decided at the known file: still so there, and the token's copy,
        // never decided, keeps the entry in review.
        for reason in [Kept, Testing, NotACredential, NoLongerWorks] {
            assert_eq!(
                entries(Some((0, reason))),
                (
                    vec![(1, "set-aside", Some(reason)), (1, "open", None)],
                    vec![(2, "open", Some(reason))]
                )
            );
        }
        // A value decided on at the token's copy now covers both copies.
        for reason in [Testing, NotACredential, NoLongerWorks] {
            assert_eq!(
                entries(Some((1, reason))),
                (
                    vec![(1, "open", None), (1, "set-aside", Some(reason))],
                    vec![(2, "set-aside", Some(reason))]
                )
            );
        }
    }

    #[test]
    fn a_credential_in_several_places_was_first_seen_in_the_first() {
        let copy = |id: u64, path: &str, seen: &str| -> review::Item {
            serde_json::from_value(json!({
                "id": id, "revision": id, "rule": "secret.service-token", "path": path,
                "secret": "digest-a", "line": null, "title": "t", "explanation": "e",
                "reason": null, "next_step": null, "first_seen": seen,
            }))
            .unwrap()
        };
        let mut state = review::Review {
            items: vec![
                copy(1, "~/later.txt", "2026-10-05T00:00:00Z"),
                copy(2, "~/earlier.txt", "2026-10-01T00:00:00Z"),
            ],
            ..Default::default()
        };
        let first = |state: &review::Review| review_items(state).0[0].item.first_seen.clone();
        assert_eq!(first(&state).as_deref(), Some("2026-10-01T00:00:00Z"));
        // Still so when the entry speaks for the later copy, or once the
        // earlier one is fixed.
        state.items[1].resolved = true;
        assert_eq!(review_items(&state).0[0].item.path, "~/later.txt");
        assert_eq!(first(&state).as_deref(), Some("2026-10-01T00:00:00Z"));
        // A copy saved before the date was kept says nothing either way.
        state.items[1].first_seen = None;
        assert_eq!(first(&state).as_deref(), Some("2026-10-05T00:00:00Z"));
    }

    #[test]
    fn a_credential_said_to_be_only_for_testing_is_not_listed_as_kept() {
        let copy = |id: u64, path: &str| -> review::Item {
            serde_json::from_value(json!({
                "id": id, "revision": id, "rule": "secret.service-token", "path": path,
                "secret": "digest-a", "line": null, "title": "t", "explanation": "e",
                "reason": null, "next_step": null, "deferred": false,
            }))
            .unwrap()
        };
        let mut state = review::Review {
            items: vec![
                copy(1, "~/a/.env"),
                copy(2, "~/b/.env"),
                copy(3, "~/c/.env"),
            ],
            ..Default::default()
        };
        // Kept in one place, the entry moves to the next still to be decided.
        for lead in [1, 2] {
            let (items, _) = review_items(&state);
            assert_eq!((items[0].item.id, items[0].state), (lead, "open"));
            state
                .decide(lead, review::Reason::Kept, now(), "then".into())
                .unwrap();
        }
        // At the last place the person says the value is only for testing.
        // That is about the credential, so about every place it is in: the
        // entry does not go on saying it is real and kept.
        let (items, _) = review_items(&state);
        assert_eq!((items[0].item.id, items[0].state), (3, "open"));
        state
            .decide(3, review::Reason::TestOrRevoked, now(), "then".into())
            .unwrap();
        let (items, counts) = review_items(&state);
        assert_eq!(
            (items[0].state, items[0].set_aside),
            ("set-aside", Some(review::Reason::TestOrRevoked))
        );
        assert_eq!(counts.set_aside, 1);
        // Shown again, the whole entry is open, not still kept in one place.
        state.undo(items[0].item.id);
        let (items, counts) = review_items(&state);
        assert_eq!((items[0].state, counts.open), ("open", 1));
        assert_eq!(
            items[0]
                .places
                .iter()
                .map(|p| p.set_aside)
                .collect::<Vec<_>>(),
            [false, false, false]
        );
    }

    #[test]
    fn a_permission_just_given_is_told_apart_from_one_already_held() {
        // 0 is before any answer; 1 not asked, 2 denied, 3 allowed, 5 the
        // request failed.
        assert!(newly_allowed(1, 3) && newly_allowed(2, 3) && newly_allowed(5, 3));
        // Allowed at the start, or still allowed, is not news.
        assert!(!newly_allowed(0, 3) && !newly_allowed(3, 3));
        assert!(!newly_allowed(1, 2) && !newly_allowed(3, 2) && !newly_allowed(0, 1));
    }

    #[test]
    fn only_plain_paths_are_acted_on() {
        let home = Path::new("/Users/a");
        assert_eq!(
            full_path("~/x/key.pem", Some(home)),
            Some(PathBuf::from("/Users/a/x/key.pem"))
        );
        assert_eq!(
            full_path("/Volumes/B/k", Some(home)),
            Some(PathBuf::from("/Volumes/B/k"))
        );
        for hostile in [
            "~/a\u{1b}]0;x",
            "~/p-\u{202e}vsc.exe",
            "~/x\ny",
            "~/\u{fffd}",
        ] {
            assert_eq!(full_path(hostile, Some(home)), None);
        }
        assert_eq!(full_path("~/x", None), None);
        assert_eq!(full_path("relative", Some(home)), None);
        // A `~/` name stays below the home, whatever the store holds.
        for outside in ["~//etc/x", "~//Users/a", "~/../x", "~/x/../../y", "~/./x"] {
            assert_eq!(full_path(outside, Some(home)), None, "{outside}");
            assert_eq!(recheck_path(outside, Some(home)), None, "{outside}");
        }
        assert_eq!(
            full_path("~/x/", Some(home)),
            Some(PathBuf::from("/Users/a/x/"))
        );
        // One skip of the home's own path, or of the folder above it, would
        // leave out the whole home.
        let mut state = review::Review::default();
        for path in ["~//Users/a", "~//Users", "~/../a", "~/kept"] {
            let added = "then".into();
            state.skipped.push(review::Skip {
                path: path.into(),
                added,
            });
        }
        assert_eq!(
            skipped_paths(&state, home),
            [PathBuf::from("/Users/a/kept")]
        );
        // A listed file is read again under any name it can be listed by.
        assert_eq!(
            recheck_path("~/Documents/contrase\u{f1}as.csv", Some(home)),
            Some(PathBuf::from("/Users/a/Documents/contrase\u{f1}as.csv"))
        );
        assert_eq!(
            recheck_path("/Volumes/B/k", Some(home)),
            Some(PathBuf::from("/Volumes/B/k"))
        );
        // Not one whose bytes had to be replaced to list it, nor a path
        // that is not one results list.
        assert_eq!(recheck_path("~/\u{fffd}.csv", Some(home)), None);
        assert_eq!(recheck_path("relative", Some(home)), None);
        assert_eq!(recheck_path("~/x", None), None);
    }

    /// An older build's pass saved refusals of places this build leaves out.
    /// They are not shown or counted, so an update takes effect before the
    /// next full pass; any other saved refusal still is.
    #[test]
    fn saved_refusals_of_places_no_longer_tried_are_left_out() {
        let mut saved = serde_json::to_value(review::Agent::default()).unwrap();
        saved["unread"] = json!(4);
        saved["unread_places"] = json!({
            "places": [
                ["~/Library/Accounts", "permission-denied"],
                ["~/Library/Preferences/com.apple.madrid.plist", "permission-denied"],
                ["~/locked", "permission-denied"],
                ["~/Library/Accounts", "unreadable"],
            ],
            "truncated": false,
        });
        let agent: review::Agent = serde_json::from_value(saved).unwrap();
        let output = serde_json::to_value(automatic_coverage(&agent)).unwrap();
        let shown: Vec<_> = output["unread_gaps"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|g| g["paths"].as_array().unwrap().clone())
            .collect();
        assert_eq!(shown, [json!("~/locked"), json!("~/Library/Accounts")]);
        assert_eq!(output["unread"], 2);
        assert_eq!(health(&agent).unread, 2);
    }

    #[test]
    fn automatic_gap_details_are_escaped() {
        let mut saved = serde_json::to_value(review::Agent::default()).unwrap();
        saved["unread_places"] = json!({
            "places": [["~/hostile\u{202e}\u{1b}", "unreadable"]],
            "truncated": true,
        });
        let agent: review::Agent = serde_json::from_value(saved).unwrap();
        let output = serde_json::to_value(automatic_coverage(&agent)).unwrap();
        assert_eq!(
            output["unread_gaps"][0]["paths"][0],
            "~/hostile\\u{202e}\\u{1b}"
        );
        assert_eq!(output["unread_truncated"], true);
    }

    #[test]
    fn page_gets_only_escaped_paths() {
        let finding = |path: &str| report::Finding {
            fingerprint: None,
            rule: "export.password-csv",
            category: "password-export",
            kind: "review",
            title: "t",
            explanation: "e",
            path: path.into(),
            ..report::Finding::default()
        };
        let r = Report {
            schema: "loose-keys/report/1",
            tool_version: "0.1.0",
            generated_at: report::utc_now(),
            status: "partial",
            context: "user",
            coverage: report::Coverage::default(),
            findings: vec![finding("~/ok.csv"), finding("~/p-\u{202e}vsc.csv")],
            not_checked: vec![report::NotChecked {
                path: "~/\u{1b}[31m".into(),
                reason: "unreadable",
            }],
        };
        let v = results_view(&r);
        let json = serde_json::to_string(&v).unwrap();
        let back: serde_json::Value = serde_json::from_str(&json).unwrap();
        let text = back.to_string();
        assert!(!text.contains('\u{202e}') && !text.contains('\u{1b}'));
        assert_eq!(back["gaps"][0]["paths"][0], "~/\\u{1b}[31m");
    }

    /// A synthetic token of one type, ending in the letter given. Put
    /// together here, so that no source file holds one whole.
    fn token(last: char) -> String {
        format!("gh{}_0123456789abcdefghijABCDEFGHIJ01234{last}", "p")
    }

    /// A stand-in for the keyed digest, the same on every system: it only
    /// has to tell the synthetic values apart.
    fn stand_in(rule: &str, bytes: &[u8], shared: bool) -> String {
        format!("{rule}:{shared}:{}:{:?}", bytes.len(), bytes.last())
    }

    /// A synthetic home folder with one note in it, and scans of it as the
    /// app and the helper make them.
    struct Notes(PathBuf);

    impl Notes {
        fn new(name: &str, text: &str) -> Self {
            let home = std::env::temp_dir().join(format!(
                "credential-engine-notes-{}-{name}",
                std::process::id()
            ));
            std::fs::create_dir(&home).unwrap();
            let notes = Notes(home);
            notes.write(text);
            notes
        }

        fn write(&self, text: &str) {
            std::fs::write(self.0.join("notes.txt"), text).unwrap();
        }

        fn scan(&self) -> Report {
            let cancel = std::sync::Arc::new(AtomicBool::new(false));
            scan::Scan::report_controlled(&self.0, &[], &[], cancel, stand_in, |_| {})
        }

        /// Save a report as the app and the helper do, with each listed
        /// file they would look at again read as they read it.
        fn save(&self, state: &mut review::Review, report: &Report) -> bool {
            state.merge(report, |item, want| {
                let path = recheck_path(&item.path, Some(&self.0))?;
                let never = || false;
                scan::recheck_identities(
                    &item.rule, &path, &self.0, item.mount, &stand_in, want, &never,
                )
            })
        }
    }

    impl Drop for Notes {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    /// The token items of a state: the letter each one's value ends with, as
    /// `stand_in` keeps it, and whether it is still open.
    fn tokens(state: &review::Review) -> Vec<(char, bool)> {
        let mut tokens: Vec<(char, bool)> = state
            .items
            .iter()
            .filter(|i| i.rule == "secret.service-token")
            .map(|i| {
                let secret = i.secret.as_deref().unwrap();
                let last = if secret.ends_with("Some(65)") {
                    'A'
                } else {
                    'B'
                };
                (last, !i.resolved)
            })
            .collect();
        tokens.sort_unstable();
        tokens
    }

    /// Two tokens of one type were one finding once they shared a line, and
    /// the one left out was marked fixed while it was still in the file.
    #[test]
    fn two_tokens_joined_on_one_line_are_both_still_open() {
        let (a, b) = (token('A'), token('B'));
        let notes = Notes::new("same-line", &format!("{a}\n{b}\n"));
        let mut state = review::Review::default();
        notes.save(&mut state, &notes.scan());
        assert_eq!(tokens(&state), [('A', true), ('B', true)]);
        notes.write(&format!("{a} {b}\n"));
        let joined = notes.scan();
        assert!(joined.not_checked.is_empty());
        assert!(!notes.save(&mut state, &joined), "nothing here is news");
        assert_eq!(tokens(&state), [('A', true), ('B', true)]);
    }

    /// The store's lock orders the saves, not the reads before them. A scan
    /// that read a file early and saved late said what the file had held,
    /// and a value found since was marked fixed on its word.
    #[test]
    fn an_older_scan_does_not_fix_what_a_newer_check_found() {
        let (a, b) = (token('A'), token('B'));
        let notes = Notes::new("stale-report", &a);
        // The app's scan has read the file and is still at work elsewhere.
        let older = notes.scan();
        let mut state = review::Review::default();
        notes.save(&mut state, &older);
        // A second value is added, and the helper finds it and saves first.
        notes.write(&format!("{a}\n{b}\n"));
        let newer = notes.scan();
        notes.save(&mut state, &newer);
        assert_eq!(tokens(&state), [('A', true), ('B', true)]);
        notes.save(&mut state, &older);
        assert_eq!(tokens(&state), [('A', true), ('B', true)]);
    }

    /// The same with one value replaced by another. The older report put the
    /// value it had read back in the item, and what the person had said of
    /// that one then covered the place: the credential in the file, which
    /// they had said nothing about, was set aside and no longer listed.
    #[test]
    fn an_older_scan_does_not_put_back_a_value_that_was_replaced() {
        let (a, b) = (token('A'), token('B'));
        let notes = Notes::new("stale-rotation", &a);
        let older = notes.scan();
        let mut state = review::Review::default();
        notes.save(&mut state, &older);
        let id = state.items[0].id;
        state
            .decide(id, review::Reason::TestOrRevoked, now(), "then".into())
            .unwrap();
        notes.write(&b);
        notes.save(&mut state, &notes.scan());
        notes.save(&mut state, &older);
        let open: Vec<&review::Item> = state.items.iter().filter(|i| !i.resolved).collect();
        let listed = |last: char| tokens(&state).contains(&(last, true));
        assert!(listed('B'), "the value in the file is no longer listed");
        let asks = |i: &&review::Item| state.decision(i, now()).is_none();
        assert!(
            open.iter().any(asks),
            "every item at the place is set aside, and its value was never decided on"
        );
    }

    /// A name that held bytes that are not UTF-8 is listed with them
    /// replaced, and the text names some other file. Nothing is read under
    /// it, and a report that lists it must not stand in for the read.
    #[test]
    fn a_report_does_not_fix_an_item_under_a_name_that_was_repaired() {
        let notes = Notes::new("repaired", &format!("{}\n{}\n", token('A'), token('B')));
        let mut both = notes.scan();
        for finding in &mut both.findings {
            finding.path = "~/notes-\u{fffd}.txt".into();
        }
        let mut state = review::Review::default();
        notes.save(&mut state, &both);
        let mut one = both;
        one.findings.truncate(1);
        assert!(recheck_path(&one.findings[0].path, Some(&notes.0)).is_none());
        notes.save(&mut state, &one);
        assert_eq!(tokens(&state), [('A', true), ('B', true)]);
    }

    /// What must go on working: a value taken out of its file is marked
    /// fixed, the one beside it is not, and one put back is open again.
    #[test]
    fn a_value_taken_out_is_fixed_and_one_put_back_is_open_again() {
        let (a, b) = (token('A'), token('B'));
        let notes = Notes::new("removal", &format!("{a} {b}\n"));
        let mut state = review::Review::default();
        notes.save(&mut state, &notes.scan());
        assert_eq!(tokens(&state), [('A', true), ('B', true)]);
        notes.write(&format!("{a}\n"));
        assert!(!notes.save(&mut state, &notes.scan()));
        assert_eq!(tokens(&state), [('A', true), ('B', false)]);
        // The value that is left is replaced by one that was there before:
        // its own item is open again, as news, and no third item is listed.
        let revision = state.revision;
        notes.write(&format!("{b}\n"));
        assert!(notes.save(&mut state, &notes.scan()), "a new value is news");
        assert_eq!(tokens(&state), [('A', false), ('B', true)]);
        let open: Vec<&review::Item> = state.items.iter().filter(|i| !i.resolved).collect();
        assert!(open[0].revision > revision);
        // The file is removed: nothing is left open.
        std::fs::remove_file(notes.0.join("notes.txt")).unwrap();
        notes.save(&mut state, &notes.scan());
        assert!(state.items.iter().all(|i| i.resolved));
    }

    /// The same through a scan in the app, with the store's own digests. A
    /// scan whose rechecks get no time marks nothing fixed: what its report
    /// leaves out was once taken as gone with no file read again.
    #[test]
    fn a_scan_marks_a_value_fixed_only_when_its_file_was_read_again() {
        let (home, mut app) = engine("fresh-read");
        let notes = home.join("notes.txt");
        std::fs::write(&notes, format!("{} {}\n", token('A'), token('B'))).unwrap();
        let alone = one_scan();
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 2);
        let states = |app: &App| -> Vec<Value> {
            let rows = ask(app, "pending_review", "{}")["ok"]["items"].clone();
            let rows = rows.as_array().unwrap().iter();
            rows.map(|row| row["state"].clone()).collect()
        };
        assert_eq!(states(&app), ["open", "open"]);
        // One of the two is taken out. Without a read of the file as it is
        // now, the report leaving it out is not enough.
        std::fs::write(&notes, format!("{}\n", token('B'))).unwrap();
        app.rechecks = std::time::Duration::ZERO;
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 1);
        assert_eq!(states(&app), ["open", "open"]);
        app.rechecks = RECHECKS;
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 1);
        assert_eq!(states(&app), ["fixed", "open"]);
        // The one that is left is replaced. The new value takes the row of
        // one that is gone from this place, as news: no third row, one open.
        let rows = |app: &App| ask(app, "pending_review", "{}")["ok"]["items"].clone();
        let newest = |rows: &Value| {
            let rows = rows.as_array().unwrap().iter();
            rows.map(|row| row["revision"].as_u64().unwrap()).max()
        };
        let before = rows(&app);
        std::fs::write(&notes, format!("{}\n", token('C'))).unwrap();
        assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 1);
        drop(alone);
        let after = rows(&app);
        let mut now = states(&app);
        std::fs::remove_dir_all(home).unwrap();
        now.sort_by_key(|state| state.to_string());
        assert_eq!(now, ["fixed", "open"]);
        let open = after.as_array().unwrap().iter();
        let open: Vec<&Value> = open.filter(|row| row["state"] == "open").collect();
        assert!(open[0]["revision"].as_u64() > newest(&before));
    }

    /// The window names a row by its id, and an id stays with its place when
    /// the value there changes. A press on a row drawn for the old value was
    /// taken as a decision about the new one, which the person had not seen.
    #[test]
    fn a_press_on_a_row_drawn_for_another_value_is_refused() {
        const CHANGED: &str =
            "That item changed after it was shown, so nothing was done. Look at it again.";
        let notes = Notes::new("stale-press", &token('A'));
        let app = App::open(Ok(notes.0.clone()));
        app.ready();
        update_state(&app, |state| notes.save(state, &notes.scan())).unwrap();
        let row = |app: &App| ask(app, "pending_review", "{}")["ok"]["items"][0].clone();
        let drawn = row(&app);
        // The helper finds another value there while the row is on screen.
        notes.write(&token('B'));
        let helper = review::Store::open(&notes.0).unwrap();
        helper
            .update(|state| Ok(notes.save(state, &notes.scan())))
            .unwrap();
        let press = |command: &str, row: &Value, more: Value| {
            let mut args = json!({ "id": row["id"], "revision": row["revision"] });
            args.as_object_mut()
                .unwrap()
                .extend(more.as_object().unwrap().clone());
            ask(&app, command, &args.to_string())
        };
        for (command, more) in [
            ("decide_review", json!({ "reason": "testing" })),
            ("decide_review", json!({ "reason": "no-longer-works" })),
            ("decide_review", json!({ "reason": "test-or-revoked" })),
            ("decide_review", json!({ "reason": "kept" })),
            ("decide_review", json!({ "reason": null })),
        ] {
            assert_eq!(press(command, &drawn, more)["error"], CHANGED, "{command}");
        }
        let now_drawn = row(&app);
        assert_eq!(now_drawn["id"], drawn["id"]);
        assert_ne!(now_drawn["revision"], drawn["revision"]);
        assert_eq!(now_drawn["state"], "open");
        let stored = helper.read().unwrap();
        assert!(stored.decisions.is_empty());
        // A press that does not say what it was drawn for is not acted on.
        let bare = json!({ "id": drawn["id"], "reason": "kept" });
        assert_eq!(
            ask(&app, "decide_review", &bare.to_string())["error"],
            "The request has no usable \"revision\"."
        );
        // The row as it is now drawn is acted on, and so is its undo.
        let decided = press(
            "decide_review",
            &now_drawn,
            json!({ "reason": "test-or-revoked" }),
        );
        assert_eq!(decided, json!({ "ok": null }));
        assert_eq!(row(&app)["set_aside"], "test-or-revoked");
        let undone = press("decide_review", &row(&app), json!({ "reason": null }));
        assert_eq!(undone, json!({ "ok": null }));
        assert_eq!(row(&app)["set_aside"], Value::Null);
    }

    /// A synthetic home folder with a password export in `~/Documents`, the
    /// state its store held before anything was found, and the export listed
    /// in the store as the helper would list it.
    fn found_since(name: &str) -> (PathBuf, App, review::Review) {
        let (home, app) = engine(name);
        std::fs::create_dir(home.join("Documents")).unwrap();
        std::fs::write(
            home.join("Documents/export.csv"),
            "url,username,password\nhttps://fixture.invalid,fixture,synthetic\n",
        )
        .unwrap();
        let helper = review::Store::open(&home).unwrap();
        // The first change gives the store its key, which a scan asks for.
        let (before, ()) = helper.update(|_| Ok(())).unwrap();
        helper
            .update(|state| {
                state.items.push(review::Item {
                    id: 1,
                    rule: "export.password-csv".into(),
                    path: "~/Documents/export.csv".into(),
                    ..serde_json::from_str(
                        r#"{"rule":"","path":"","line":null,"title":"t","explanation":"e","reason":null,"next_step":null,"deferred":false}"#,
                    )
                    .unwrap()
                });
                state.next_id = 1;
                Ok(())
            })
            .unwrap();
        (home, app, before)
    }

    /// Commands run at once. Each left the state it had read in the app's
    /// one copy and then answered from the copy, so a read that began before
    /// a change and finished after it put the older state back: a row the
    /// list had shown was then unknown, and a scan read a folder the person
    /// had just said to stop checking.
    #[test]
    fn a_command_acts_on_the_store_and_not_on_what_an_older_read_left() {
        let (home, app, before) = found_since("older-read");
        let late = || *app.review.lock().unwrap() = before.clone();
        let listed = ask(&app, "pending_review", "{}");
        assert_eq!(listed["ok"]["items"][0]["id"], 1);
        late();
        let path = ask(&app, "item_path", r#"{"index":1}"#);
        let real = format!("{}/Documents/export.csv", home.to_str().unwrap());
        assert_eq!(path["ok"], real, "a row the list showed is not known");

        assert_eq!(
            ask(&app, "skip_folder", r#"{"id":1}"#),
            json!({ "ok": null })
        );
        late();
        let alone = one_scan();
        let scan = ask(&app, "start_scan", "{}");
        drop(alone);
        let skipped = ask(&app, "pending_review", "{}")["ok"]["skipped"].clone();
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(skipped, json!(["~/Documents"]));
        assert_eq!(
            scan["ok"]["review"], 0,
            "a folder the person stopped checking was read"
        );
    }

    /// The same for the list itself: it is drawn from the state its own
    /// command read. A thread stands in for older reads that finish late,
    /// one after another, for as long as the list is being asked for. It
    /// stops by itself as well, so a failure below is not waited on for ever.
    #[test]
    fn the_list_is_the_one_its_command_read_whatever_older_reads_leave() {
        let (home, app, before) = found_since("older-reads");
        let done = AtomicBool::new(false);
        let empty = std::thread::scope(|threads| {
            threads.spawn(|| {
                let started = std::time::Instant::now();
                while !done.load(Ordering::SeqCst) && started.elapsed().as_secs() < 10 {
                    *app.review.lock().unwrap() = before.clone();
                }
            });
            let empty = (0..2000)
                .filter(|_| ask(&app, "pending_review", "{}")["ok"]["items"] == json!([]))
                .count();
            done.store(true, Ordering::SeqCst);
            empty
        });
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(empty, 0, "of 2000 lists, drawn from an older read's state");
    }

    #[test]
    fn an_expected_entry_sets_the_row_aside_until_the_person_returns_it() {
        let notes = Notes::new("expected-entry", &token('A'));
        let app = App::open(Ok(notes.0.clone()));
        app.ready();
        update_state(&app, |state| notes.save(state, &notes.scan())).unwrap();
        let list = |app: &App| ask(app, "pending_review", "{}")["ok"].clone();
        let row = list(&app)["items"][0].clone();
        let entries = json!({ "entries": [{ "rule": row["rule"], "path": row["path"] }] });
        assert_eq!(
            ask(&app, "set_expected", &entries.to_string()),
            json!({ "ok": null })
        );
        let shown = list(&app);
        assert_eq!(shown["items"][0]["state"], "set-aside");
        assert_eq!(shown["items"][0]["set_aside"], "expected");
        // The organization's list has no time of its own: none is sent for
        // the window to show where a date goes.
        assert_eq!(shown["items"][0]["set_aside_at"], json!(null));
        assert_eq!(shown["counts"]["set_aside"], 1);
        // The person cannot choose the reason themselves.
        let revision = shown["items"][0]["revision"].clone();
        let press = json!({ "id": row["id"], "revision": revision, "reason": "expected" });
        assert_eq!(
            ask(&app, "decide_review", &press.to_string())["error"],
            "That reason is set by your organization's settings."
        );
        // Move to Worth Reviewing opens it, and the list sent again leaves it open.
        let back = json!({ "id": row["id"], "revision": revision, "reason": null });
        assert_eq!(
            ask(&app, "decide_review", &back.to_string()),
            json!({ "ok": null })
        );
        assert_eq!(
            ask(&app, "set_expected", &entries.to_string()),
            json!({ "ok": null })
        );
        assert_eq!(list(&app)["items"][0]["state"], "open");
        let stored = review::Store::open(&notes.0).unwrap().read().unwrap();
        assert_eq!(stored.returned.len(), 1);
        // Nothing is saved while private state is unavailable.
        *app.storage_error.lock().unwrap() = Some("gone".into());
        assert_eq!(
            ask(&app, "set_expected", r#"{"entries":[]}"#)["error"],
            "Loose Keys could not open its saved data."
        );
    }

    /// A refused decision saves nothing: here the person's earlier Move to
    /// Worth Reviewing must survive a decision refused at the cap, or the
    /// organization's list sent again sets the row aside against that choice.
    #[test]
    fn a_refused_decision_changes_nothing_saved() {
        let notes = Notes::new("refused-decision", &token('A'));
        std::fs::create_dir(notes.0.join("other")).unwrap();
        std::fs::write(notes.0.join("other/notes.txt"), token('B')).unwrap();
        let app = App::open(Ok(notes.0.clone()));
        app.ready();
        update_state(&app, |state| notes.save(state, &notes.scan())).unwrap();
        let list = |app: &App| ask(app, "pending_review", "{}")["ok"].clone();
        let row = list(&app)["items"][0].clone();
        let shown = |app: &App| {
            let items = list(app)["items"].as_array().unwrap().clone();
            items.into_iter().find(|i| i["id"] == row["id"]).unwrap()
        };
        let entries = json!({ "entries": [{ "rule": row["rule"], "path": row["path"] }] });
        ask(&app, "set_expected", &entries.to_string());
        let revision = shown(&app)["revision"].clone();
        let back = json!({ "id": row["id"], "revision": revision, "reason": null });
        assert_eq!(
            ask(&app, "decide_review", &back.to_string()),
            json!({ "ok": null })
        );
        // Decisions about the other note's place fill the list of
        // decisions. A listed item uses them, so none makes room.
        update_state(&app, |state| {
            let other = state
                .items
                .iter()
                .find(|i| json!(i.id) != row["id"])
                .unwrap()
                .clone();
            for _ in 0..review::MAX_ITEMS {
                state.decisions.push(review::Decision {
                    reason: review::Reason::Kept,
                    secret: None,
                    rule: other.rule.clone(),
                    path: other.path.clone(),
                    subject: other.subject.clone(),
                    scope: other.scope.clone(),
                    fingerprint: None,
                    token_type: None,
                    shared: false,
                    severity: "high".into(),
                    decided: "2026-01-01T00:00:00Z".into(),
                    decided_at: 0,
                });
            }
        })
        .unwrap();
        let path = notes.0.join(review::STATE_DIR).join("state.json");
        let before = std::fs::read(&path).unwrap();
        let press = json!({ "id": row["id"], "revision": revision, "reason": "kept" });
        assert_eq!(
            ask(&app, "decide_review", &press.to_string())["error"],
            "Too many findings are set aside. Move some back to Worth Reviewing."
        );
        assert!(
            std::fs::read(&path).unwrap() == before,
            "a refused decision rewrote the saved state"
        );
        assert_eq!(
            ask(&app, "set_expected", &entries.to_string()),
            json!({ "ok": null })
        );
        assert_eq!(shown(&app)["state"], "open");
    }

    /// An admin's typo in one entry drops that entry, not the list: the
    /// others still apply, and a list of nothing usable replaces the old one.
    #[test]
    fn a_malformed_entry_is_dropped_without_touching_the_others() {
        let notes = Notes::new("malformed-entry", &token('A'));
        let app = App::open(Ok(notes.0.clone()));
        app.ready();
        update_state(&app, |state| notes.save(state, &notes.scan())).unwrap();
        let row = ask(&app, "pending_review", "{}")["ok"]["items"][0].clone();
        let good = json!({ "rule": row["rule"], "path": row["path"] });
        let state_of =
            |app: &App| ask(app, "pending_review", "{}")["ok"]["items"][0]["state"].clone();
        let mixed = json!({ "entries": [
            { "rule": "key.ssh.private", "Path": "~/x" },
            { "rule": 7, "path": "~/y" },
            "~/z",
            good,
        ] });
        assert_eq!(
            ask(&app, "set_expected", &mixed.to_string()),
            json!({ "ok": null })
        );
        assert_eq!(state_of(&app), "set-aside");
        let typo = json!({ "entries": [{ "rule": "key.ssh.private", "Path": "~/x" }] });
        assert_eq!(
            ask(&app, "set_expected", &typo.to_string()),
            json!({ "ok": null })
        );
        assert_eq!(state_of(&app), "open");
    }

    /// The window sends the list each time the app comes to the front; a
    /// list that changes nothing must not rewrite the state file.
    #[test]
    fn an_unchanged_list_does_not_rewrite_the_state() {
        use std::os::unix::fs::MetadataExt;
        let notes = Notes::new("unchanged-list", &token('A'));
        let app = App::open(Ok(notes.0.clone()));
        app.ready();
        update_state(&app, |state| notes.save(state, &notes.scan())).unwrap();
        let row = ask(&app, "pending_review", "{}")["ok"]["items"][0].clone();
        let entries = json!({ "entries": [{ "rule": row["rule"], "path": row["path"] }] });
        let file = notes.0.join(review::STATE_DIR).join("state.json");
        let inode = || std::fs::metadata(&file).unwrap().ino();
        assert_eq!(
            ask(&app, "set_expected", &entries.to_string()),
            json!({ "ok": null })
        );
        let written = inode();
        assert_eq!(
            ask(&app, "set_expected", &entries.to_string()),
            json!({ "ok": null })
        );
        assert_eq!(
            inode(),
            written,
            "the state was rewritten for an unchanged list"
        );
        assert_eq!(
            ask(&app, "set_expected", r#"{"entries":[]}"#),
            json!({ "ok": null })
        );
        assert_ne!(inode(), written, "a changed list is saved");
    }
}
