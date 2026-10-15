//! Synthetic resident-worker measurement. No WebView, native delivery, or user HOME.
#[test]
fn keyed_material_ignores_comments_and_detects_credentials_and_mode_changes() {
    let digest =
        |rule, bytes: &[u8], shared| crate::material_fingerprint(rule, &[7; 32], bytes, shared);
    let original = b"_authToken=synthetic-first\n";
    let comment = b"# ordinary comment\n_authToken = 'synthetic-first' # ordinary comment\n";
    assert_eq!(
        digest("dev.npm.inline-credentials", original, false),
        digest("dev.npm.inline-credentials", comment, false)
    );
    assert_ne!(
        digest("dev.npm.inline-credentials", original, false),
        digest(
            "dev.npm.inline-credentials",
            b"_authToken=synthetic-second\n",
            false
        )
    );
    assert_ne!(
        digest("dev.npm.inline-credentials", original, false),
        digest("dev.npm.inline-credentials", original, true)
    );
    let docker = br#"{"auths":{"fixture":{"auth":"c3ludGhldGlj"}},"ordinary":1}"#;
    let changed_layout = br#"{"ordinary":2,"auths":{"fixture":{"auth":"c3ludGhldGlj"}}}"#;
    assert_eq!(
        digest("dev.docker.inline-auth", docker, false),
        digest("dev.docker.inline-auth", changed_layout, false)
    );
}

#[test]
#[ignore = "isolated resource measurement; run alone with --nocapture"]
fn resident_fixture_measurement() {
    use crate::{
        material_fingerprint,
        monitor::Monitor,
        review::{Review, Store},
        scan::{Progress, Scan},
    };
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    const FIRST: &str = "url,username,password\nhttps://fixture.invalid,fixture,synthetic-first\n";
    const SECOND: &str =
        "url,username,password\nhttps://fixture.invalid,fixture,synthetic-second\n";
    let root = std::env::temp_dir().join(format!(
        "credential-resident-measure-{}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let home = root.join("home");
    std::fs::create_dir(&home).unwrap();
    let ordinary = "ordinary synthetic document\n";
    for n in 0..1600 {
        std::fs::write(home.join(format!("file-{n:04}.txt")), ordinary).unwrap();
    }
    std::fs::write(home.join("export.csv"), FIRST).unwrap();
    let monitor = Arc::new(Monitor::new(true, false));
    let worker_monitor = monitor.clone();
    let worker_home = home.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let store = Store::open(&worker_home).unwrap();
        let mut state = Review {
            monitoring: true,
            key: vec![7; 32],
            ..Review::default()
        };
        let mut notifications = 0;
        while let Some(scan_due) = worker_monitor.wait() {
            if !scan_due {
                continue;
            }
            assert!(worker_monitor.arm(crate::monitor::ScanKind::Automatic));
            let progress = Arc::new(Mutex::new(Progress::default()));
            let observed = progress.clone();
            let start = Instant::now();
            let report = Scan::report_controlled(
                &worker_home,
                &[],
                &[],
                worker_monitor.cancel.clone(),
                |rule, bytes, shared| material_fingerprint(rule, &[7; 32], bytes, shared),
                move |p| *observed.lock().unwrap() = p,
            );
            state.ingest(&report);
            store.save(&state).unwrap();
            if state.pending(crate::now()) {
                notifications += 1; // Synthetic successful submission, not a native notification.
                state.notified_revision = state.revision;
                store.save(&state).unwrap();
            }
            state = store.load().unwrap();
            assert!(!state.ingest(&report));
            tx.send((
                start.elapsed().as_secs_f64() * 1000.0,
                *progress.lock().unwrap(),
                notifications,
            ))
            .unwrap();
        }
    });
    let first = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(first.2, 1);
    let usage = || {
        let mut u = std::mem::MaybeUninit::<libc::rusage>::uninit();
        assert_eq!(
            unsafe { libc::getrusage(libc::RUSAGE_SELF, u.as_mut_ptr()) },
            0
        );
        unsafe { u.assume_init() }
    };
    let before = usage();
    let idle = Instant::now();
    std::thread::sleep(Duration::from_secs(2));
    let after = usage();
    assert!(rx.try_recv().is_err(), "idle worker must not rescan");
    let seconds = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1_000_000.0;
    let cpu = seconds(after.ru_utime) + seconds(after.ru_stime)
        - seconds(before.ru_utime)
        - seconds(before.ru_stime);
    assert!(cpu <= 0.05, "isolated worker idle CPU budget exceeded");
    assert!(
        after.ru_maxrss <= 32 * 1024 * 1024,
        "isolated test-process RSS budget exceeded"
    );
    println!("{{\"measurement\":\"resident-test-process-idle\",\"wall_seconds\":{},\"cpu_seconds\":{},\"max_rss_bytes\":{},\"webview\":false}}", idle.elapsed().as_secs_f64(), cpu, after.ru_maxrss);
    monitor.configure(true, false);
    let unchanged = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(unchanged.2, 1);
    std::fs::write(home.join("export.csv"), SECOND).unwrap();
    let changed_start = Instant::now();
    monitor.configure(true, false);
    let changed = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(changed.2, 2);
    assert!(
        [first.0, unchanged.0, changed.0]
            .iter()
            .all(|ms| *ms <= 1000.0),
        "synthetic worker scan budget exceeded"
    );
    println!("{{\"measurement\":\"synthetic-catchup\",\"files\":1601,\"fixture_bytes\":{},\"scan_ms\":[{},{},{}],\"entries\":{},\"header_attempts\":{},\"config_attempts\":{},\"catchup_latency_ms\":{},\"synthetic_notification_counts\":[1,1,2]}}", 1600 * ordinary.len() + FIRST.len(), first.0, unchanged.0, changed.0, changed.1.entries, changed.1.header_attempts, changed.1.config_attempts, changed_start.elapsed().as_secs_f64() * 1000.0);
    monitor.stop();
    worker.join().unwrap();
    let saved =
        std::fs::read_to_string(home.join(crate::review::STATE_DIR).join("state.json")).unwrap();
    assert!(!saved.contains("synthetic-first") && !saved.contains("synthetic-second"));
    for n in 0..1600 {
        std::fs::remove_file(home.join(format!("file-{n:04}.txt"))).unwrap();
    }
    std::fs::remove_file(home.join("export.csv")).unwrap();
    std::fs::remove_file(home.join(crate::review::STATE_DIR).join("state.json")).unwrap();
    for dir in [
        crate::review::STATE_DIR,
        "Library/Application Support",
        "Library",
    ] {
        std::fs::remove_dir(home.join(dir)).unwrap();
    }
    std::fs::remove_dir(home).unwrap();
    std::fs::remove_dir(root).unwrap();
}
