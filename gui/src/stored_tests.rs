//! Stored sign-ins on the engine's side: what the window is given for them,
//! what it can do with one, and what a manual scan saves.

use crate::tests::{ask, engine, one_scan, seen, SEEN};
use crate::*;
use serde_json::{json, Value};

const LOGIN: &str = "dev.cli.stored-login";

/// A sign-in file a command-line tool keeps, which a scan lists as stored
/// while only its owner can read it.
fn hub(home: &Path, value: &str) {
    let path = home.join(".config/hub");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    private(&path, &format!("access_token: {value}\n"));
}

fn private(path: &Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A report of findings of one kind at these paths, as a scan lists them.
fn listed(kind: &'static str, paths: &[String]) -> Report {
    let rule = if kind == "review" {
        "export.password-csv"
    } else {
        LOGIN
    };
    Report {
        schema: "loose-keys/report/1",
        tool_version: "test",
        generated_at: report::utc_now(),
        status: "partial",
        context: "user",
        coverage: report::Coverage::default(),
        findings: paths
            .iter()
            .map(|path| report::Finding {
                rule,
                category: "developer-cloud",
                kind,
                severity: "medium",
                title: "Synthetic finding",
                explanation: "Synthetic match",
                path: path.clone(),
                ..report::Finding::default()
            })
            .collect(),
        not_checked: Vec::new(),
    }
}

fn paths(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|p| p.to_string()).collect()
}

/// Each listed entry's kind, path and state, in the order given.
fn rows(list: &Value) -> Vec<(String, String, String)> {
    let text = |v: &Value| v.as_str().unwrap_or_default().to_string();
    list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| (text(&i["kind"]), text(&i["path"]), text(&i["state"])))
        .collect()
}

fn row(kind: &str, path: &str, state: &str) -> (String, String, String) {
    (kind.into(), path.into(), state.into())
}

#[test]
fn pending_review_counts_stored_sign_ins_apart() {
    let (home, app) = engine("stored-counts");
    let store = app.store.as_ref().unwrap();
    store
        .update(|state| {
            state.ingest(&listed("review", &paths(&["~/Documents/export.csv"])));
            let stored = ["~/.config/hub", "~/.netrc", "~/.kube/cache/oidc-login/a"];
            state.ingest_stored(&listed("inventory", &paths(&stored)));
            let kept = state.stored.items[1].id;
            state.decide(kept, review::Reason::Kept, now(), report::utc_now())?;
            state.stored.items[2].resolved = true;
            Ok(())
        })
        .unwrap();
    let list = ask(&app, "pending_review", "{}")["ok"].clone();
    // One list, worth reviewing first; one no longer found is left out,
    // and only counted.
    assert_eq!(
        rows(&list),
        [
            row("review", "~/Documents/export.csv", "open"),
            row("inventory", "~/.config/hub", "open"),
            row("inventory", "~/.netrc", "set-aside"),
        ]
    );
    let items = list["items"].as_array().unwrap();
    assert_eq!(items[0]["folder"], "~/Documents");
    assert!(items[1..].iter().all(|i| i["folder"].is_null()));
    assert_eq!(items[2]["set_aside"], "kept");
    assert_eq!(
        list["counts"],
        json!({"open": 1, "set_aside": 0, "kept": 0, "fixed": 0, "stored": 1, "stored_set_aside": 1, "stored_gone": 1})
    );
    assert_eq!(list["stored_full"], false);
    assert_eq!(list["stored_checked"], false);
    store
        .update(|state| {
            state.stored.full = true;
            state.stored.checked_at = Some(report::utc_now());
            Ok(())
        })
        .unwrap();
    let list = ask(&app, "pending_review", "{}")["ok"].clone();
    assert_eq!(list["stored_full"], true);
    assert_eq!(list["stored_checked"], true);
    assert_eq!(list["full"], false);
    drop(app);
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn decide_review_sets_aside_and_returns_a_stored_sign_in() {
    let (home, app) = engine("stored-decide");
    hub(&home, "synthetic-only-value-1234");
    let store = app.store.as_ref().unwrap();
    store
        .update(|state| {
            state.ingest_stored(&listed("inventory", &paths(&["~/.config/hub"])));
            Ok(())
        })
        .unwrap();
    let entry = ask(&app, "pending_review", "{}")["ok"]["items"][0].clone();
    assert_eq!(entry["kind"], "inventory");
    let (id, revision) = (
        entry["id"].as_u64().unwrap(),
        entry["revision"].as_u64().unwrap(),
    );
    let press = |reason: Value, revision: u64| {
        let args = json!({ "id": id, "revision": revision, "reason": reason });
        ask(&app, "decide_review", &args.to_string())
    };
    assert_eq!(
        press(json!("testing"), revision)["error"],
        "That reason doesn't apply to a stored sign-in."
    );
    assert_eq!(
        press(json!("kept"), revision + 1)["error"],
        "That item changed after it was shown, so nothing was done. Look at it again."
    );
    assert_eq!(press(json!("kept"), revision), json!({ "ok": null }));
    let list = ask(&app, "pending_review", "{}")["ok"].clone();
    assert_eq!(
        rows(&list),
        [row("inventory", "~/.config/hub", "set-aside")]
    );
    assert!(!list["items"][0]["set_aside_at"].is_null());
    assert_eq!(list["counts"]["stored"], 0);
    assert_eq!(list["counts"]["stored_set_aside"], 1);
    assert_eq!(list["counts"]["set_aside"], 0);
    // Move to Stored Sign-ins.
    assert_eq!(press(Value::Null, revision), json!({ "ok": null }));
    let list = ask(&app, "pending_review", "{}")["ok"].clone();
    assert_eq!(rows(&list), [row("inventory", "~/.config/hub", "open")]);
    assert_eq!(list["counts"]["stored"], 1);
    // Its file is handed over by its id, as a finding's is, and no longer
    // by a result's place in the report.
    let real = format!("{}/.config/hub", home.display());
    let by_id = json!({ "index": id, "review": true }).to_string();
    assert_eq!(ask(&app, "item_path", &by_id)["ok"], real);
    let by_index = json!({ "index": 0, "review": false }).to_string();
    assert_eq!(
        ask(&app, "item_path", &by_index)["error"],
        "That result is no longer shown."
    );
    drop(app);
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn a_manual_scan_saves_stored_sign_ins_and_settles_stored_full() {
    static STOP: OnceLock<std::sync::Arc<AtomicBool>> = OnceLock::new();
    /// Stops the scan at its first event, as the Stop button would.
    extern "C" fn stop(_: *const c_char, _: *const c_char) {
        if let Some(cancel) = STOP.get() {
            cancel.store(true, Ordering::SeqCst);
        }
    }
    let _alone = one_scan();
    let (home, app) = engine("stored-scan");
    hub(&home, "synthetic-only-value-1234");
    let store = app.store.as_ref().unwrap();
    store
        .update(|state| {
            state.stored.full = true;
            Ok(())
        })
        .unwrap();
    let list = || ask(&app, "pending_review", "{}")["ok"].clone();
    let scan = || ask(&app, "start_scan", "{}");

    // A scan stopped part-way settles nothing.
    STOP.set(app.monitor.cancel.clone()).unwrap();
    ch_set_event_handler(Some(stop));
    let stopped = scan();
    ch_set_event_handler(None);
    assert_eq!(stopped["ok"]["gaps"][0]["label"], "Only Partly Checked");
    assert_eq!(
        (
            list()["stored_full"].clone(),
            list()["stored_checked"].clone()
        ),
        (json!(true), json!(false))
    );

    // One run to its end saves the sign-in, says nothing new is worth
    // reviewing, and settles whether there is room.
    SEEN.lock().unwrap().clear();
    ch_set_event_handler(Some(seen));
    let scanned = scan();
    ch_set_event_handler(None);
    let events = std::mem::take(&mut *SEEN.lock().unwrap());
    assert_eq!(
        (
            scanned["ok"]["review"].clone(),
            scanned["ok"]["stored"].clone()
        ),
        (json!(0), json!(1))
    );
    let after = list();
    assert_eq!(rows(&after), [row("inventory", "~/.config/hub", "open")]);
    assert_eq!(
        (
            after["stored_full"].clone(),
            after["stored_checked"].clone()
        ),
        (json!(false), json!(true))
    );
    assert!(events.iter().all(|(name, _)| name != "review-ready"));
    let status = ask(&app, "monitor_status", "{}")["ok"].clone();
    assert_eq!(status["pending_delivery"], false);
    assert_eq!(status["error"], Value::Null);

    // With no room left for stored sign-ins, a complete scan leaves the
    // list full, and Worth Reviewing is not said to be.
    std::fs::create_dir(home.join("corpus")).unwrap();
    let corpus: Vec<String> = (0..review::MAX_STORED)
        .map(|n| format!("~/corpus/sign-in-{n}.json"))
        .collect();
    store
        .update(|state| {
            state.skipped.push(review::Skip {
                path: "~/corpus".into(),
                added: report::utc_now(),
            });
            state.ingest_stored(&listed("inventory", &corpus));
            Ok(())
        })
        .unwrap();
    assert_eq!(list()["stored_full"], true);
    assert!(scan().get("ok").is_some());
    let after = list();
    assert_eq!(
        (after["stored_full"].clone(), after["full"].clone()),
        (json!(true), json!(false))
    );
    let status = ask(&app, "monitor_status", "{}")["ok"].clone();
    assert_eq!(status["error"], Value::Null);
    assert_eq!(status["pending_delivery"], false);
    drop(app);
    std::fs::remove_dir_all(home).unwrap();
}

/// A stored sign-in's value, and the keyed digests kept of it, never reach
/// what the window is given, and the value is not in the saved state.
#[test]
fn stored_sign_in_values_never_leave_the_engine() {
    let _alone = one_scan();
    let (home, app) = engine("stored-leak");
    let login = ["synthetic", "hub", "Kx9mQ2vLp7Rt4Wn8"].join("-");
    hub(&home, &login);
    // A test credential in a record, which is stored with its value's digest.
    let test_key = ["sk_", "test_", "Zq8Wx3Lm5Np7Rt2Vy4Bc6Df9"].concat();
    let record = home.join(".claude/projects/p/s.jsonl");
    std::fs::create_dir_all(record.parent().unwrap()).unwrap();
    private(&record, &format!("{{\"out\":\"{test_key}\"}}\n"));
    SEEN.lock().unwrap().clear();
    ch_set_event_handler(Some(seen));
    let scanned = ask(&app, "start_scan", "{}");
    ch_set_event_handler(None);
    let events = std::mem::take(&mut *SEEN.lock().unwrap());
    let review = ask(&app, "pending_review", "{}");
    let status = ask(&app, "monitor_status", "{}");
    let state = app.store.as_ref().unwrap().read().unwrap();
    let saved = std::fs::read_to_string(home.join(review::STATE_DIR).join("state.json")).unwrap();
    drop(app);
    std::fs::remove_dir_all(home).unwrap();

    // The record's test key is found by two rules: two items, one entry.
    assert_eq!(scanned["ok"]["stored"], 3);
    assert_eq!(state.stored.items.len(), 3);
    let kept: Vec<String> = state
        .stored
        .items
        .iter()
        .flat_map(|i| [i.secret.clone(), i.fingerprint.clone(), i.scope.clone()])
        .flatten()
        .collect();
    assert!(state.stored.items.iter().any(|i| i.secret.is_some()));
    let window = [
        scanned.to_string(),
        review.to_string(),
        status.to_string(),
        serde_json::to_string(&events).unwrap(),
    ];
    for text in &window {
        for digest in &kept {
            assert!(
                !text.contains(digest.as_str()),
                "a stored sign-in's digest reached the window"
            );
        }
    }
    let items = review["ok"]["items"].as_array().unwrap();
    assert_eq!(items.iter().filter(|i| i["kind"] == "inventory").count(), 2);
    for item in items {
        assert!(item["secret"].is_null() && item["fingerprint"].is_null());
        assert!(item.get("scope").is_none() && item.get("mount").is_none());
    }
    for text in window.iter().chain([&saved]) {
        for value in [&login, &test_key] {
            for piece in [value.as_str(), &value[..12], &value[value.len() - 12..]] {
                assert!(
                    !text.contains(piece),
                    "a stored sign-in's value left the engine"
                );
            }
        }
    }
}
