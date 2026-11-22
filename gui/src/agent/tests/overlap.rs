use super::*;
use std::sync::mpsc;

type Gate = (mpsc::SyncSender<()>, mpsc::Receiver<()>);
static BEFORE_SAVE: Mutex<Option<Gate>> = Mutex::new(None);

extern "C" fn hold_finished_scan(name: *const c_char, info: *const c_char) {
    // SAFETY: the engine keeps both strings alive during the callback.
    let (name, info) = unsafe { (CStr::from_ptr(name), CStr::from_ptr(info)) };
    if name == c"scan-progress"
        && serde_json::from_slice::<serde_json::Value>(info.to_bytes())
            .is_ok_and(|progress| progress["phase"] == "finished")
    {
        let gate = BEFORE_SAVE.lock().unwrap().take();
        if let Some((reached, resume)) = gate {
            let _ = reached.send(());
            let _ = resume.recv_timeout(Duration::from_secs(40));
        }
    }
}

#[test]
fn a_manual_scan_does_not_undo_a_later_worker_resolution() {
    let _one = crate::tests::one_scan();
    let mut fixture = Fixture::start("manual-overlaps-worker", &["export.csv"], |_| {});
    assert_eq!(open(&fixture.first_pass()), ["~/export.csv"]);
    let app = crate::App::open(Ok(fixture.home.clone()));
    app.ready_with(|| 0, |_| 0);
    let (reached, ready) = mpsc::sync_channel(1);
    let (release, resume) = mpsc::sync_channel(1);

    std::thread::scope(|scope| {
        *BEFORE_SAVE.lock().unwrap() = Some((reached, resume));
        crate::ch_set_event_handler(Some(hold_finished_scan));
        let manual = scope.spawn(|| crate::tests::ask(&app, "start_scan", "{}"));
        ready
            .recv_timeout(Duration::from_secs(10))
            .expect("manual scan did not finish reading");
        std::fs::remove_file(fixture.home.join("export.csv")).unwrap();
        fixture.changes(&["export.csv"]);
        fixture.wait("worker fixes the removed export", |state| {
            state
                .items
                .iter()
                .any(|i| i.path == "~/export.csv" && i.resolved)
        });
        release.send(()).unwrap();
        let result = manual.join().unwrap();
        crate::ch_set_event_handler(None);
        assert!(result.get("ok").is_some());
    });

    let shown = crate::tests::ask(&app, "pending_review", "{}");
    assert_eq!(shown["ok"]["counts"]["open"], 0);
    assert_eq!(shown["ok"]["counts"]["fixed"], 1);
    fixture.stop();
}

#[test]
fn an_automatic_report_does_not_undo_a_later_manual_resolution() {
    let _one = crate::tests::one_scan();
    let fixture = Fixture::start("worker-overlaps-manual", &["export.csv"], |_| {});
    assert_eq!(open(&fixture.first_pass()), ["~/export.csv"]);
    let (started, digest) = fixture.agent.fingerprint();
    let path = fixture.home.join("export.csv");
    let (report, left) = Scan::changed(
        &fixture.home,
        &[],
        std::slice::from_ref(&path),
        fixture.agent.changes,
        fixture.agent.monitor.cancel.clone(),
        digest,
    );
    assert!(left.out_of_budget.is_empty());
    assert_eq!(report.findings.len(), 1);

    std::fs::remove_file(&path).unwrap();
    let app = crate::App::open(Ok(fixture.home.clone()));
    app.ready_with(|| 0, |_| 0);
    let result = crate::tests::ask(&app, "start_scan", "{}");
    assert!(result.get("ok").is_some());
    let manually_fixed = fixture.app.read().unwrap();
    assert!(manually_fixed.items[0].resolved);

    assert!(fixture
        .agent
        .record(&report, &started, Some(&[path]), None, |_| {},));
    let final_state = fixture.app.read().unwrap();
    assert!(final_state.items[0].resolved);
    fixture.stop();
}
