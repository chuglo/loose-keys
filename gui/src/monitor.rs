//! The background agent's schedule, and the gate for the app's manual scans.
//! Triggers coalesce. Sleep and quitting cancel cooperative work; a pause or a
//! change of consent cancels automatic work only.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, Mutex,
};
use std::time::{Duration, Instant};

pub const CADENCE: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Copy, PartialEq)]
pub enum ScanKind {
    Manual,
    Automatic,
}

pub struct Monitor {
    pub cancel: Arc<AtomicBool>,
    state: Mutex<Schedule>,
    ready: Condvar,
}

struct Schedule {
    enabled: bool,
    paused: bool,
    sleeping: bool,
    stopped: bool,
    /// The work `arm` last let through is a scan the person started.
    manual: bool,
    due: Instant,
    retry: Option<Instant>,
}

impl Monitor {
    pub fn new(enabled: bool, paused: bool) -> Self {
        Self {
            cancel: Arc::new(AtomicBool::new(false)),
            state: Mutex::new(Schedule {
                enabled,
                paused,
                sleeping: false,
                stopped: false,
                manual: false,
                due: Instant::now(),
                retry: None,
            }),
            ready: Condvar::new(),
        }
    }

    pub fn configure(&self, enabled: bool, paused: bool) {
        let mut s = self.state.lock().unwrap();
        s.enabled = enabled;
        s.paused = paused;
        s.due = Instant::now();
        // A setting is of the background checks. It stops automatic work and
        // leaves a scan the person started to finish.
        if !s.manual {
            self.cancel.store(true, Ordering::SeqCst);
        }
        self.ready.notify_one();
    }

    pub fn sleep(&self, sleeping: bool) {
        let mut s = self.state.lock().unwrap();
        s.sleeping = sleeping;
        s.due = Instant::now();
        self.cancel.store(true, Ordering::SeqCst);
        self.ready.notify_one();
    }

    pub fn stop(&self) {
        self.state.lock().unwrap().stopped = true;
        self.cancel.store(true, Ordering::SeqCst);
        self.ready.notify_one();
    }

    pub fn arm(&self, kind: ScanKind) -> bool {
        let mut s = self.state.lock().unwrap();
        // A pause is of the background checks. A scan the person asks for still runs.
        let automatic_off = kind == ScanKind::Automatic && (!s.enabled || s.paused);
        if s.sleeping || s.stopped || automatic_off {
            return false;
        }
        s.manual = kind == ScanKind::Manual;
        self.cancel.store(false, Ordering::SeqCst);
        true
    }

    pub fn active(&self) -> bool {
        let s = self.state.lock().unwrap();
        s.enabled && !s.paused && !s.sleeping && !s.stopped
    }

    /// Wait without polling. One missed interval produces one scan, not a backlog.
    pub fn wait(&self) -> Option<bool> {
        let mut s = self.state.lock().unwrap();
        loop {
            if s.stopped {
                return None;
            }
            if !s.enabled || s.paused || s.sleeping {
                s = self.ready.wait(s).unwrap();
            } else if Instant::now() >= s.due {
                s.due = Instant::now() + CADENCE;
                return Some(true);
            } else if s.retry.is_some_and(|due| Instant::now() >= due) {
                s.retry = None;
                return Some(false);
            } else {
                let due = s.retry.map_or(s.due, |r| r.min(s.due));
                let delay = due.saturating_duration_since(Instant::now());
                s = self.ready.wait_timeout(s, delay).unwrap().0;
            }
        }
    }

    /// Wake the worker after `delay` without a scan being due. Several
    /// requests keep the earliest; the worker asks again for whatever is left.
    pub fn retry_in(&self, delay: Duration) {
        let mut s = self.state.lock().unwrap();
        let at = Instant::now() + delay;
        s.retry = Some(s.retry.map_or(at, |earlier| earlier.min(at)));
        self.ready.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disable_after_wait_blocks_automatic_arm_but_allows_manual_scan() {
        let m = Monitor::new(true, false);
        assert_eq!(m.wait(), Some(true));
        m.configure(false, false);
        assert!(!m.arm(ScanKind::Automatic));
        assert!(m.cancel.load(Ordering::SeqCst));
        assert!(m.arm(ScanKind::Manual));
        assert!(!m.cancel.load(Ordering::SeqCst));
        // A pause is of the background checks only.
        m.configure(true, true);
        assert!(!m.arm(ScanKind::Automatic));
        assert!(m.arm(ScanKind::Manual));
        m.configure(false, false);
        m.sleep(true);
        assert!(!m.arm(ScanKind::Manual));
        m.sleep(false);
        m.stop();
        assert!(!m.arm(ScanKind::Manual));
        assert!(!m.arm(ScanKind::Automatic));
        assert!(m.cancel.load(Ordering::SeqCst));
    }

    #[test]
    fn a_changed_setting_stops_automatic_work_but_not_a_manual_scan() {
        let m = Monitor::new(true, false);
        // A scan the person started. A pause, consent given or withdrawn, and
        // what a failed save asks for are all of the background checks.
        assert!(m.arm(ScanKind::Manual));
        for (enabled, paused) in [(true, true), (true, false), (false, false), (false, true)] {
            m.configure(enabled, paused);
            assert!(
                !m.cancel.load(Ordering::SeqCst),
                "a setting stopped a manual scan"
            );
        }
        // Sleep still stops it.
        m.sleep(true);
        assert!(m.cancel.load(Ordering::SeqCst));
        m.sleep(false);
        // The agent's work, armed after a manual scan: each change stops it.
        for (enabled, paused) in [(true, true), (false, false), (true, false)] {
            m.configure(true, false);
            assert!(m.arm(ScanKind::Automatic));
            m.configure(enabled, paused);
            assert!(
                m.cancel.load(Ordering::SeqCst),
                "a setting left automatic work running"
            );
        }
        // Quitting stops a manual scan, as sleep does.
        m.configure(true, false);
        assert!(m.arm(ScanKind::Manual));
        m.stop();
        assert!(m.cancel.load(Ordering::SeqCst));
    }

    #[test]
    fn pause_sleep_and_shutdown_do_not_queue_work() {
        let m = Arc::new(Monitor::new(false, false));
        let worker = m.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            while worker.wait().is_some() {
                tx.send(()).unwrap();
            }
        });
        assert!(rx.recv_timeout(Duration::from_millis(20)).is_err());
        m.configure(true, false);
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
        m.configure(true, true);
        assert!(m.cancel.load(Ordering::SeqCst));
        assert!(rx.recv_timeout(Duration::from_millis(20)).is_err());
        m.sleep(true);
        m.configure(true, false);
        assert!(rx.recv_timeout(Duration::from_millis(20)).is_err());
        m.sleep(false);
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(20)).is_err());
        m.stop();
        t.join().unwrap();
    }
    #[test]
    fn wake_triggers_coalesce_and_restart_catches_up_once() {
        let m = Monitor::new(true, false);
        for _ in 0..1000 {
            m.sleep(false);
        }
        assert_eq!(m.wait(), Some(true));
        let s = m.state.lock().unwrap();
        assert!(s.due > Instant::now());
        drop(s);
        m.stop();
        assert_eq!(m.wait(), None);
    }

    #[test]
    fn a_later_wake_request_does_not_postpone_an_earlier_one() {
        let m = Arc::new(Monitor::new(true, false));
        assert_eq!(m.wait(), Some(true));
        m.retry_in(Duration::ZERO);
        m.retry_in(Duration::from_secs(3600));
        // Waited for on another thread, so that a postponed wake fails here
        // instead of holding the test until the next check is due.
        let (worker, (tx, rx)) = (m.clone(), std::sync::mpsc::channel());
        std::thread::spawn(move || tx.send(worker.wait()));
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok(Some(false)));
        m.stop();
    }

    #[test]
    fn delivery_retry_is_not_a_scan_and_pause_blocks_delivery() {
        let m = Monitor::new(true, false);
        assert!(m.active());
        assert_eq!(m.wait(), Some(true));
        m.retry_in(Duration::ZERO);
        assert_eq!(m.wait(), Some(false));
        m.configure(true, true);
        assert!(!m.active());
        m.stop();
        assert_eq!(m.wait(), None);
    }
}
