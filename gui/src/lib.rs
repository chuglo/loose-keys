//! The desktop app's engine: the same scan and report as the CLI, behind the
//! C interface in `app/Bridge.h`. The window is the front end's.
//!
//! File names are attacker-controlled. The front end only ever receives them
//! as `report::escape`d display text. Actions on a file ("Copy path", "Show in
//! Finder") name a finding by its index; the real path stays here and is
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
mod review;

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
    places: Mutex<Vec<PathBuf>>,
    report: Mutex<Option<Report>>,
    scanning: AtomicBool,
    review: Mutex<review::Review>,
    store: Result<review::Store, String>,
    storage_error: Mutex<Option<String>>,
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
    /// "complete" once the agent has been through the whole home folder.
    coverage: &'static str,
    /// When the last full pass finished, and folders the current one has left.
    full_pass: Option<String>,
    left: usize,
    /// Places the last full pass did not read.
    unread: usize,
    changes: u64,
    error: Option<String>,
}

fn health(agent: &review::Agent) -> Health {
    Health {
        // SAFETY: signal 0 only tests whether the process exists.
        running: agent.pid != 0 && unsafe { libc::kill(agent.pid as libc::pid_t, 0) } == 0,
        last_scan: agent.last_check.clone(),
        coverage: if agent.baseline.is_some() && agent.left == 0 {
            "complete"
        } else {
            "partial"
        },
        full_pass: agent.baseline.clone(),
        left: agent.left,
        unread: agent.unread,
        changes: agent.changes,
        error: agent.error.clone(),
    }
}

/// Change the shared state on disk as one step, and keep this app's copy
/// current. The agent may have changed the state since this app last read it.
fn update_state<T>(app: &App, change: impl FnOnce(&mut review::Review) -> T) -> Answer<T> {
    let store = app.store.as_ref().map_err(Clone::clone)?;
    match store.update(|state| Ok(change(state))) {
        Ok((state, out)) => {
            *app.review.lock().unwrap() = state;
            Ok(out)
        }
        Err(e) => {
            *app.storage_error.lock().unwrap() = Some(e.clone());
            app.monitor.configure(false, true);
            Err(e)
        }
    }
}

/// The shared state as the store has it now, with what the agent has written
/// since this app last looked. A command answers from the state it is handed
/// here, never from the app's copy after it: commands run at once, and a
/// read that began before a change may be the last to leave its state in the
/// copy. The copy is what is left to answer from once the store cannot be
/// read.
fn refresh_state(app: &App) -> review::Review {
    if app.storage_error.lock().unwrap().is_none() {
        if let Ok(store) = &app.store {
            match store.read() {
                Ok(state) => {
                    *app.review.lock().unwrap() = state.clone();
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
    scanning: bool,
    login: u8,
    menu_bar: bool,
    /// The app itself in Login Items, with the same codes as `login`.
    app_login: u8,
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
    MonitorView {
        enabled: r.monitoring,
        paused: r.paused,
        scanning: app.scanning.load(Ordering::SeqCst),
        // SAFETY: takes no argument and touches no memory of ours.
        login: unsafe { ch_login_status() },
        menu_bar: !r.menu_bar_off,
        // SAFETY: takes no argument and touches no memory of ours.
        app_login: unsafe { ch_app_login_status() },
        health: health(&r.agent),
        error: app.storage_error.lock().unwrap().clone().or_else(|| {
            r.full.then(|| {
                "The review list is full, so some findings were left out. Fix some items, then scan again.".to_string()
            })
        }),
        pending_delivery: r.items.iter().any(|i| r.alerting(i, now())),
        attempts: r.attempts,
        results: app
            .report
            .lock()
            .unwrap()
            .as_ref()
            .map(|r| results_view(r, app.home.as_deref().ok())),
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
        return Err("Monitoring cannot start while private state is unavailable.".into());
    }
    if scan::is_root() {
        return Err("Automatic monitoring is not available as root.".into());
    }
    let one_change = app.app_login.lock().unwrap();
    let (was_enabled, menu_bar) = update_state(app, |state| {
        let was_enabled = state.monitoring;
        state.monitoring = enabled;
        state.paused = paused;
        (was_enabled, !state.menu_bar_off)
    })?;
    app.monitor.configure(enabled, paused);
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
            "The menu bar setting cannot be saved while private state is unavailable.".into(),
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

fn set_login_startup(app: &App, enabled: bool) -> Answer<u8> {
    if enabled && !refresh_state(app).monitoring {
        return Err("Consent to home monitoring before enabling login startup.".into());
    }
    // SAFETY: takes a bool and touches no memory of ours.
    Ok(unsafe { ch_login_set(enabled) })
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

extern "C" fn notification_permission(value: u8) {
    let was = PERMISSION.swap(value, Ordering::SeqCst);
    emit(c"notification-permission", value);
    // The helper is started by consent, which comes before this answer, and
    // is not told of it. A change to the shared state wakes it, and it asks
    // macOS again when it has something to send.
    if newly_allowed(was, value) {
        if let Some(app) = APP.get() {
            let _ = update_state(app, |_| ());
        }
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
    /// "open", "set-aside" or "fixed".
    state: &'static str,
    /// Why it was set aside, using review::Reason's fixed serialized names.
    set_aside: Option<review::Reason>,
    /// Every place the same credential is stored, this one included.
    places: Vec<PlaceView>,
    /// The folder a "stop checking this folder" would name, if one may be.
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
}

#[derive(Serialize, Default)]
struct Counts {
    open: usize,
    set_aside: usize,
    /// Of those set aside, the ones that are real and kept.
    kept: usize,
    fixed: usize,
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

/// A stored item as the front end may have it: its names escaped, and
/// without the fingerprint, the digest and what is kept about the file's
/// volume, which stay on this side.
fn shown(item: &review::Item) -> review::Item {
    let mut shown = item.clone();
    shown.path = report::escape(&shown.path);
    shown.reason = shown.reason.as_ref().map(|s| report::escape(s));
    (shown.fingerprint, shown.secret, shown.mount) = (None, None, None);
    shown
}

fn review_items(state: &review::Review) -> (Vec<ReviewItem>, Counts) {
    let at = now();
    let mut counts = Counts::default();
    let mut out: Vec<ReviewItem> = Vec::new();
    let mut grouped: std::collections::HashMap<&str, usize> = Default::default();
    // What sets aside each item that is still there, looked up once: it is
    // asked several times below, and a lookup goes through every decision.
    let decided: Vec<Option<&review::Decision>> = state
        .items
        .iter()
        .map(|i| (!i.resolved).then(|| state.decision(i, at)).flatten())
        .collect();
    for (item, decision) in state.items.iter().zip(&decided) {
        let place = PlaceView {
            id: item.id,
            path: report::escape(&item.path),
            line: item.line,
            fixed: item.resolved,
            set_aside: decision.is_some(),
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
            state: "open",
            set_aside: None,
            places: vec![place],
        });
    }
    for entry in &mut out {
        // Each copy that is still there, with the decision that sets it aside.
        let open: Vec<(&review::Item, Option<&review::Decision>)> = entry
            .places
            .iter()
            .filter_map(|p| state.items.iter().position(|i| i.id == p.id))
            .map(|n| (&state.items[n], decided[n]))
            .filter(|(i, _)| !i.resolved)
            .collect();
        // The entry's path is the one the person is shown and acts on. It is
        // a copy that still needs a decision, or failing that one that is
        // still there: never a fixed copy while another remains.
        let lead = open.iter().find(|(_, d)| d.is_none()).or(open.first());
        if let Some((lead, _)) = lead.filter(|(i, _)| i.id != entry.item.id) {
            entry.item = shown(lead);
            entry.folder = offered_folder(&lead.path);
            entry.actionable = plain(&lead.path);
        }
        let decision = open.iter().find_map(|(_, d)| *d);
        entry.set_aside = decision.map(|d| d.reason);
        entry.state = if open.is_empty() {
            counts.fixed += 1;
            "fixed"
        } else if open.iter().all(|(_, d)| d.is_some()) {
            counts.set_aside += 1;
            counts.kept += usize::from(entry.set_aside == Some(review::Reason::Kept));
            "set-aside"
        } else {
            counts.open += 1;
            "open"
        };
        entry.item.resolved = entry.state == "fixed";
    }
    (out, counts)
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
/// that is no longer what was shown.
fn decide_review(app: &App, id: u64, revision: u64, reason: Option<review::Reason>) -> Answer<()> {
    if app.storage_error.lock().unwrap().is_some() {
        return Err("Private state is unavailable.".into());
    }
    update_state(app, |state| {
        state.as_shown(id, revision)?;
        match reason {
            Some(reason) => state.decide(id, reason, now(), report::utc_now()),
            None => {
                state.undo(id);
                Ok(())
            }
        }
    })?
}

/// Stop checking the folder that holds this item. The front end names an
/// item, never a path. The folder stays listed wherever results are shown.
fn skip_folder(app: &App, id: u64) -> Answer<()> {
    let home = app.home.clone().map_err(|e| e.to_string())?;
    update_state(app, |state| {
        let item = state
            .items
            .iter()
            .find(|i| i.id == id)
            .ok_or("That review item is no longer available.")?;
        let folder = folder_of(&item.path).ok_or("The home folder cannot be skipped.")?;
        let real = full_path(folder, Some(&home)).ok_or("That folder's name cannot be used.")?;
        scan::skipped_folder(real.as_os_str(), &home).map_err(|e| format!("Cannot skip: {e}."))?;
        if state.skipped.len() >= review::MAX_SKIPS {
            return Err("Too many folders are skipped. Remove one first.".to_string());
        }
        if !state.skips(folder) {
            let (path, added) = (folder.to_string(), report::utc_now());
            state.skipped.push(review::Skip { path, added });
        }
        Ok(())
    })?
}

/// `index` is the folder's place in the list the front end drew, and `shown`
/// the text it drew there. A press that arrives after the list has moved up
/// names the wrong place, so it is acted on only while the two still agree.
fn unskip_folder(app: &App, index: usize, shown: String) -> Answer<()> {
    update_state(app, |state| {
        let there = state.skipped.get(index);
        if there.is_some_and(|skip| report::escape(&skip.path) == shown) {
            state.skipped.remove(index);
        }
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
        return Err("Private state is unavailable.".into());
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
            places: Mutex::new(Vec::new()),
            report: Mutex::new(None),
            scanning: AtomicBool::new(false),
            review: Mutex::new(review::Review::default()),
            store,
            storage_error: Mutex::new(None),
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
            self.monitor.configure(
                storage_error.is_none() && loaded.monitoring && !scan::is_root(),
                loaded.paused,
            );
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
        self.places.clear_poison();
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
        "item_path" => done(item_path(app, args.get("index")?, args.get("review")?)?),
        "open_link" => done(open_link(args.get("url")?)?),
        "decide_review" => done(decide_review(
            app,
            args.get("id")?,
            args.get("revision")?,
            args.get("reason")?,
        )?),
        "skip_folder" => done(skip_folder(app, args.get("id")?)?),
        "unskip_folder" => done(unskip_folder(app, args.get("index")?, args.get("shown")?)?),
        "version" => done(env!("CARGO_PKG_VERSION")),
        "rules_text" => done(rules_text()),
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
        "set_monitoring" => done(set_monitoring(
            app,
            args.get("enabled")?,
            args.get("paused")?,
        )?),
        "set_login_startup" => done(set_login_startup(app, args.get("enabled")?)?),
        "set_menu_bar" => done(set_menu_bar(app, args.get("enabled")?)?),
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

/// A user-initiated preparation step, not a scan or a permission verdict.
/// The fixed locations are already in home scan scope. Listing with a zero
/// entry budget asks macOS for directory access without retaining names or
/// opening file contents. No locks are held across a possible system prompt.
fn prepare_access(app: &App, index: usize) -> Answer<()> {
    let folder = ["Desktop", "Documents", "Downloads"]
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
    PlacesView {
        home: app.home.as_ref().ok().map(|h| show(h)),
        home_error: app.home.as_ref().err().copied(),
        extra: app.places.lock().unwrap().iter().map(|p| show(p)).collect(),
        error,
    }
}

fn show(p: &Path) -> String {
    report::escape(&p.to_string_lossy())
}

fn add_place(app: &App, path: &Path) -> Answer<()> {
    if app.scanning.load(Ordering::SeqCst) {
        return Err("Wait for the scan to finish.".into());
    }
    let p = scan::selected_root(path.as_os_str())
        .map_err(|e| format!("Cannot add that folder: {e}."))?;
    let mut places = app.places.lock().unwrap();
    if !places.contains(&p) && app.home.as_ref() != Ok(&p) {
        if places.len() >= 8 || p.as_os_str().len() > 4096 {
            return Err(
                "Use at most eight additional folders with paths within 4096 bytes.".into(),
            );
        }
        places.push(p);
    }
    Ok(())
}

fn places(app: &App) -> PlacesView {
    places_view(app, None)
}

/// A folder the person typed, or one they picked or dropped on the window.
fn type_place(app: &App, text: String) -> PlacesView {
    let text = text.trim();
    let error = if text.is_empty() {
        None
    } else {
        add_place(app, Path::new(text)).err()
    };
    places_view(app, error)
}

/// As for `unskip_folder`: the place in the list, and what was shown there.
fn remove_place(app: &App, index: usize, shown: String) -> PlacesView {
    let mut places = app.places.lock().unwrap();
    let there = places.get(index).is_some_and(|place| show(place) == shown);
    if there && !app.scanning.load(Ordering::SeqCst) {
        places.remove(index);
    }
    drop(places);
    places_view(app, None)
}

// ---- Scan and results ----

#[derive(Serialize)]
struct ResultsView {
    status: &'static str,
    context: &'static str,
    tool_version: &'static str,
    generated_at: String,
    review: usize,
    stored: usize,
    not_checked: usize,
    groups: Vec<GroupView>,
    gaps: Vec<GapView>,
    roots: Vec<String>,
    excluded: Vec<&'static str>,
    limitations: &'static str,
}

#[derive(Serialize)]
struct GroupView {
    kind: &'static str,
    severity: &'static str,
    title: &'static str,
    explanation: &'static str,
    reason: Option<String>,
    next_step: Option<&'static str>,
    steps: &'static [&'static str],
    link: Option<&'static str>,
    items: Vec<ItemView>,
}

#[derive(Serialize)]
struct ItemView {
    index: usize,
    path: String,
    line: Option<usize>,
    subject: Option<String>,
    /// Only plain names can be copied or revealed.
    actionable: bool,
}

#[derive(Serialize)]
struct GapView {
    label: &'static str,
    help: &'static str,
    count: usize,
    paths: Vec<String>,
    more: usize,
}

fn results_view(r: &Report, home: Option<&Path>) -> ResultsView {
    let review = r.findings.iter().filter(|f| f.kind == "review").count();
    let indexes: std::collections::HashMap<_, _> = r
        .findings
        .iter()
        .enumerate()
        .map(|(index, finding)| (finding as *const report::Finding, index))
        .collect();
    let mut groups = Vec::new();
    for kind in ["review", "inventory"] {
        for group in report::group_findings(r, kind) {
            let f = group[0];
            groups.push(GroupView {
                kind,
                severity: f.severity,
                title: f.title,
                explanation: f.explanation,
                reason: f.reason.clone(),
                next_step: f.next_step,
                steps: f.steps,
                link: f.link,
                items: group
                    .iter()
                    .map(|g| ItemView {
                        index: indexes[&(*g as *const report::Finding)],
                        path: report::escape(&g.path),
                        line: g.line,
                        subject: g.subject.clone().or_else(|| g.detail.clone()),
                        actionable: full_path(&g.path, home).is_some(),
                    })
                    .collect(),
            });
        }
    }
    let gaps = report::group_gaps(r)
        .into_iter()
        .map(|(reason, paths)| {
            let (label, help) = gap_text(reason);
            GapView {
                label,
                help,
                count: paths.len(),
                paths: paths
                    .iter()
                    .take(GAPS_SHOWN)
                    .map(|p| report::escape(p))
                    .collect(),
                more: paths.len().saturating_sub(GAPS_SHOWN),
            }
        })
        .collect();
    let coverage = r.coverage.as_ref();
    ResultsView {
        status: r.status,
        context: r.context,
        tool_version: r.tool_version,
        generated_at: r.generated_at.clone(),
        review,
        stored: r.findings.len() - review,
        not_checked: r.not_checked.len(),
        groups,
        gaps,
        roots: coverage.map_or(Vec::new(), |c| {
            c.roots.iter().map(|p| report::escape(p)).collect()
        }),
        excluded: coverage.map_or(Vec::new(), |c| c.excluded_directories.to_vec()),
        limitations: report::LIMITATIONS,
    }
}

/// Returns when the scan ends, so the front end calls it off its main thread.
fn start_scan(app: &App) -> Answer<ResultsView> {
    let extra = app.places.lock().unwrap().clone();
    perform_scan(app, &extra, monitor::ScanKind::Manual)
}

/// Said when the monitor refuses a scan the person asked for. In this process
/// only `prepare_quit` brings that about: nothing here puts the monitor to
/// sleep, and a pause or withdrawn consent refuses automatic work only.
const SCAN_BLOCKED: &str =
    "This app is quitting, so the scan was not started. Open it again to scan.";

fn perform_scan(app: &App, extra: &[PathBuf], kind: monitor::ScanKind) -> Answer<ResultsView> {
    let home = app.home.clone().map_err(|e| format!("Cannot scan: {e}."))?;
    if app.store.is_err() {
        return Err(
            "Private state is unavailable; another instance may be running. Scanning is disabled."
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
    if !app.monitor.arm(kind) {
        return Err(SCAN_BLOCKED.into());
    }
    emit(c"monitor-status", ());
    // The folders to leave out are the store's as the scan starts, for the
    // reason `refresh_state` gives. A store that cannot be read is the save's
    // to report, below: until then the app's copy has to do.
    let read = app.store.as_ref().ok().and_then(|store| store.read().ok());
    let state = read.unwrap_or_else(|| app.review.lock().unwrap().clone());
    // The store creates the fingerprint key the first time it is changed.
    let mut key = state.key.clone();
    if key.is_empty() {
        key = update_state(app, |state| state.key.clone())?;
    }
    let skip = skipped_paths(&state, &home);
    let r = scan::Scan::report_controlled(
        &home,
        extra,
        &skip,
        app.monitor.cancel.clone(),
        move |rule, bytes, shared| material_fingerprint(rule, &key, bytes, shared),
        move |p| {
            if kind == monitor::ScanKind::Manual {
                emit(c"scan-progress", p);
            }
        },
    );
    let view = results_view(&r, app.home.as_deref().ok());
    // Merge into the shared state in one step; the agent may be writing too.
    // The rechecks get their own time. Counted from before the scan, a scan
    // that used all of its own left them none, and nothing was marked fixed.
    let rechecking = std::time::Instant::now();
    let saved = if app.storage_error.lock().unwrap().is_none() {
        update_state(app, |review| {
            // ingest only ever sets `full`, so it is cleared here for this
            // scan to decide again, and put back below unless the scan ran to
            // its end and the list has room.
            let was_full = std::mem::take(&mut review.full);
            let key = review.key.clone();
            let new = review.merge(&r, |item| {
                if rechecking.elapsed() >= app.rechecks || app.monitor.cancel.load(Ordering::SeqCst)
                {
                    return None;
                }
                still_there(item, &home, &key)
            });
            // A cancelled scan says nothing about what was left out before
            // it. One that stopped at a work limit did not present every
            // finding either, so room on the list is what settles it: without
            // room the next finding is left out whatever this scan saw.
            if was_full && (app.monitor.cancel.load(Ordering::SeqCst) || !review.has_room()) {
                review.full = true;
            }
            new
        })
    } else {
        Err("Local review storage is unavailable.".into())
    };
    let new = saved.unwrap_or(false);
    *app.report.lock().unwrap() = Some(r);
    if new {
        emit(c"review-ready", ());
    }
    drop(_guard);
    emit(c"monitor-status", ());
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
            "That file already exists. This app never replaces files. Choose a new name.".into(),
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

/// `index` is a result's position, or for a review item its id.
fn finding_path(app: &App, index: usize, review: bool) -> Answer<PathBuf> {
    if review {
        return refresh_state(app)
            .items
            .iter()
            .find(|i| i.id == index as u64)
            .and_then(|i| full_path(&i.path, app.home.as_deref().ok()))
            .ok_or_else(|| "This review item has no usable local path.".into());
    }
    let r = app.report.lock().unwrap();
    let f = r
        .as_ref()
        .and_then(|r| r.findings.get(index))
        .ok_or("That result is no longer shown.")?;
    full_path(&f.path, app.home.as_deref().ok())
        .ok_or_else(|| "This name has unusual characters, so the app does not act on it.".into())
}

/// The real path of a result, for the front end to copy or to show in the
/// file manager. Its parent must open without following links, and root
/// actions are refused. The path can still change before Finder uses it.
fn item_path(app: &App, index: usize, review: bool) -> Answer<String> {
    if scan::is_root() {
        return Err("Not available when running as root.".into());
    }
    let path = finding_path(app, index, review)?;
    let parent = path.parent().ok_or("no folder")?;
    fsutil::open_directory(parent).map_err(|g| format!("Could not open the folder ({g})."))?;
    // Text that had to be repaired would name some other file.
    path.into_os_string()
        .into_string()
        .map_err(|_| "This name has unusual characters, so the app does not act on it.".into())
}

/// One of the fixed issuer pages named in the rules, for the front end to
/// open. Anything else, including a link altered in stored state, is refused.
fn open_link(url: String) -> Answer<String> {
    if scan::is_root() {
        return Err("Not available when running as root.".into());
    }
    if !rules::known_link(&url) {
        return Err("That link is not one this app opens.".into());
    }
    Ok(url)
}

fn rules_text() -> String {
    rules::rule_list()
}

/// The real path, only for plain printable names: anything else (control
/// characters, bidi overrides, non-UTF-8) is shown escaped and not acted on.
/// Whether a name is one the app acts on: printable ASCII and nothing else.
fn plain(name: &str) -> bool {
    name.chars().all(|c| (' '..='~').contains(&c))
}

fn full_path(rel: &str, home: Option<&Path>) -> Option<PathBuf> {
    plain(rel).then(|| real_path(rel, home)).flatten()
}

/// A path as results list it, "~/..." or absolute, as the path it stands for.
fn real_path(rel: &str, home: Option<&Path>) -> Option<PathBuf> {
    match rel.strip_prefix("~/") {
        Some(rest) => home.map(|h| h.join(rest)),
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
/// None where the file cannot be read again, or was listed under a name
/// that does not name it (`recheck_path`).
fn still_there(item: &review::Item, home: &Path, key: &[u8]) -> Option<review::Still> {
    let path = recheck_path(&item.path, Some(home))?;
    let digest = |rule: &str, bytes: &[u8], shared| material_fingerprint(rule, key, bytes, shared);
    scan::recheck_values(&item.rule, &path, home, item.mount, &digest)
}

fn gap_text(reason: &'static str) -> (&'static str, &'static str) {
    match reason {
        "permission-denied" => (
            "Blocked by system permissions",
            "macOS protects these folders, so the app could not look inside them. \
             The results do not cover them.",
        ),
        "unreadable" => (
            "Could not be read",
            "The system returned an error for these.",
        ),
        "too-large" => (
            "Too large to check",
            "Config and JSON files over 1 MiB are not read.",
        ),
        "cloud-only-file" => (
            "Stored only in the cloud",
            "These files are not on this computer. The app does not download them.",
        ),
        // The heading and the page's opening line say it; the limits are in
        // the usage guide.
        "scan-limit" => ("Only partly checked", ""),
        "symlink" => (
            "Link not followed",
            "A known sign-in location is a link that leads outside your home folder, \
             so the app did not read it. Links that stay inside the home folder are followed.",
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
    fn engine(name: &str) -> (PathBuf, App) {
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
    fn ask(app: &App, command: &str, args: &str) -> Value {
        serde_json::from_str(&call(Some(app), command, args)).unwrap()
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

    static SEEN: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

    /// Held by a test while it scans through the app's side: every scan's
    /// events go to the one handler, whichever test set it. The lock guards
    /// no data, so a test that failed holding it does not fail the next.
    fn one_scan() -> std::sync::MutexGuard<'static, ()> {
        static ONE_SCAN: Mutex<()> = Mutex::new(());
        ONE_SCAN.lock().unwrap_or_else(|held| held.into_inner())
    }

    extern "C" fn seen(name: *const c_char, payload: *const c_char) {
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
    fn a_folder_is_removed_or_put_back_only_while_it_is_the_one_shown() {
        let (home, app) = engine("by-name");
        let shown = show(&home);
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
        assert_eq!(ask(&app, "remove_place", &first)["ok"]["extra"], left);

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
        assert_eq!(ask(&app, "unskip_folder", first), json!({ "ok": null }));
        assert_eq!(skipped(), json!(["~/b"]));
        std::fs::remove_dir_all(home).unwrap();
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
        let path = ask(&app, "item_path", r#"{"index":1,"review":true}"#);
        let skip = ask(&app, "skip_folder", r#"{"id":1}"#);
        std::fs::remove_dir_all(home).unwrap();
        // What the engine would refuse, the list says before a button is drawn.
        assert_eq!(path["error"], "This review item has no usable local path.");
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
    fn the_version_can_be_asked_for_before_any_scan() {
        let (home, app) = engine("version");
        let _alone = one_scan();
        let version = ask(&app, "version", "{}");
        let scanned = ask(&app, "start_scan", "{}");
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(version["ok"], env!("CARGO_PKG_VERSION"));
        assert_eq!(version["ok"], scanned["ok"]["tool_version"]);
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
            "That review item is no longer available."
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
            json!({ "error": "Private state is unavailable." })
        );
        // A choice is refused too, and what was stored is left as it was.
        assert_eq!(
            ask(
                &app,
                "decide_review",
                r#"{"id":1,"revision":0,"reason":"kept"}"#
            ),
            json!({ "error": "Private state is unavailable." })
        );
        assert_eq!(
            std::fs::read_to_string(folder.join("state.json")).unwrap(),
            "not a store"
        );
        std::fs::remove_dir_all(home).unwrap();
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

        // A typed folder is trimmed and added; a refused one says why.
        assert_eq!(ask(&app, "places", "{}")["ok"]["home"], shown);
        let typed = json!({ "text": format!("  {shown}/Backup ") }).to_string();
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
        let item = &results["ok"]["groups"][0]["items"][0];
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

        // The real path is handed over by a result's index or a review item's id.
        let real = format!("{shown}/Documents/export.csv");
        let by_index = json!({ "index": item["index"], "review": false }).to_string();
        assert_eq!(ask(&app, "item_path", &by_index)["ok"], real);
        let review = ask(&app, "pending_review", "{}");
        let by_id = json!({ "index": review["ok"]["items"][0]["id"], "review": true }).to_string();
        assert_eq!(ask(&app, "item_path", &by_id)["ok"], real);
        assert_eq!(
            ask(&app, "item_path", r#"{"index":7,"review":false}"#)["error"],
            "That result is no longer shown."
        );

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
            "That file already exists. This app never replaces files. Choose a new name.";
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
            ask(&app, "item_path", &by_index)["error"],
            "Could not open the folder (unreadable)."
        );

        // Only the issuer pages named in the rules are handed back.
        let known = rules::RULES.iter().find_map(|r| r.advice.link).unwrap();
        let link = |url: &str| ask(&app, "open_link", &json!({ "url": url }).to_string());
        assert_eq!(link(known)["ok"], known);
        assert_eq!(
            link("https://fixture.invalid/")["error"],
            "That link is not one this app opens."
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

    const EXPORT: &str = "url,username,password\nhttps://fixture.invalid,fixture,synthetic\n";

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
        let path = ask(&app, "item_path", r#"{"index":1,"review":true}"#);
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(again["ok"]["review"], 0);
        assert_eq!(item["state"], "fixed");
        // Reading it again is all: the front end is still handed no such path.
        assert_eq!(item["actionable"], false);
        assert_eq!(path["error"], "This review item has no usable local path.");
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
        let mounted: Kept = |drive, _| Some(drive.components().count() as u32);
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
        let share = home.join("mnt/share").components().count() as u32;
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

        const UNREADABLE: &str = "Local review storage could not be decoded.";
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
            coverage: None,
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
        assert_eq!(stopped["ok"]["gaps"][0]["label"], "Only partly checked");
        assert_eq!(full(), true);
        // One that runs to its end has.
        assert_eq!(scan()["ok"]["review"], 0);
        assert_eq!(full(), false);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn a_command_that_panics_is_an_error_and_the_next_one_still_works() {
        let (home, app) = engine("panic");
        // Poison a lock, as a command that panicked while holding it would.
        std::thread::scope(|scope| {
            let held = scope.spawn(|| {
                let _places = app.places.lock().unwrap();
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

    #[test]
    fn work_limit_is_named_without_a_note() {
        assert_eq!(gap_text("scan-limit"), ("Only partly checked", ""));
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
        assert_eq!(
            (counts.open, counts.set_aside, counts.kept, counts.fixed),
            (2, 1, 1, 1)
        );
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
        assert_eq!((counts.set_aside, counts.kept), (1, 0));
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

    #[test]
    fn large_result_groups_keep_original_action_indexes() {
        let r = Report {
            schema: "loose-keys/report/1",
            tool_version: "test",
            generated_at: report::utc_now(),
            status: "complete",
            context: "user",
            coverage: None,
            findings: (0..10_000)
                .map(|index| report::Finding {
                    fingerprint: None,
                    rule: "export.password-csv",
                    category: "password-export",
                    kind: if index % 2 == 0 {
                        "review"
                    } else {
                        "inventory"
                    },
                    title: "Synthetic finding",
                    explanation: "Synthetic match",
                    path: format!("~/synthetic-{index}.csv"),
                    ..report::Finding::default()
                })
                .collect(),
            not_checked: Vec::new(),
        };
        let start = std::time::Instant::now();
        let v = results_view(&r, Some(Path::new("/synthetic")));
        println!(
            "10000 synthetic findings: results_view {:.3} ms",
            start.elapsed().as_secs_f64() * 1000.0
        );
        assert_eq!(v.review, 5_000);
        assert_eq!(v.stored, 5_000);
        let mut indexes = std::collections::HashSet::new();
        for item in v.groups.iter().flat_map(|g| &g.items) {
            assert_eq!(item.path, r.findings[item.index].path);
            assert!(item.actionable);
            assert!(indexes.insert(item.index));
        }
        assert_eq!(indexes.len(), 10_000);
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
            coverage: None,
            findings: vec![finding("~/ok.csv"), finding("~/p-\u{202e}vsc.csv")],
            not_checked: vec![report::NotChecked {
                path: "~/\u{1b}[31m".into(),
                reason: "unreadable",
            }],
        };
        let v = results_view(&r, Some(Path::new("/Users/a")));
        let json = serde_json::to_string(&v).unwrap();
        let back: serde_json::Value = serde_json::from_str(&json).unwrap();
        let text = back.to_string();
        assert!(!text.contains('\u{202e}') && !text.contains('\u{1b}'));
        let items = &back["groups"][0]["items"];
        assert_eq!(items[0]["actionable"], true);
        assert_eq!(items[1]["actionable"], false);
        assert_eq!(items[1]["path"], "~/p-\\u{202e}vsc.csv");
        assert_eq!(items[1]["index"], 1);
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
            state.merge(report, |item| {
                let path = recheck_path(&item.path, Some(&self.0))?;
                scan::recheck_values(&item.rule, &path, &self.0, item.mount, &stand_in)
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
            "That review item has changed since it was shown. Nothing was done; look at it again.";
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
        let path = ask(&app, "item_path", r#"{"index":1,"review":true}"#);
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
}
