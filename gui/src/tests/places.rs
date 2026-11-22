use super::*;

#[test]
fn delayed_scope_read_cannot_widen_a_scan_when_the_store_is_unreadable() {
    use std::os::unix::fs::PermissionsExt;
    let _alone = one_scan();
    let (home, app) = engine("delayed-scope");
    let folder = home.join("Documents");
    std::fs::create_dir(&folder).unwrap();
    std::fs::write(
        folder.join("export.csv"),
        "url,username,password\nhttps://fixture.invalid,fixture,synthetic\n",
    )
    .unwrap();
    assert_eq!(ask(&app, "start_scan", "{}")["ok"]["review"], 1);
    let (generation, old) = app.store.as_ref().unwrap().read_versioned().unwrap();
    assert_eq!(ask(&app, "skip_folder", r#"{"id":1}"#), json!({"ok":null}));
    assert_eq!(
        ask(&app, "pending_review", "{}")["ok"]["skipped"],
        json!(["~/Documents"])
    );
    app.remember_state(generation, old);

    let state = home.join(review::STATE_DIR).join("state.json");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644)).unwrap();
    let scan = ask(&app, "start_scan", "{}");
    let excluded = app
        .report
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .report
        .coverage
        .excluded_by_user
        .clone();
    std::fs::remove_dir_all(home).unwrap();
    assert_eq!(scan["ok"]["review"], 0, "{scan}");
    assert_eq!(excluded, ["~/Documents"]);
}

#[test]
fn consecutive_include_actions_use_the_same_displayed_list() {
    let (home, app) = engine("include-two");
    let left = ["~/One", "~/Two", "~/Three"];
    update_state(&app, |state| {
        state.skipped.extend(left.map(|path| review::Skip {
            path: path.into(),
            added: report::utc_now(),
        }));
    })
    .unwrap();
    for (index, shown) in left[..2].iter().enumerate() {
        let args = json!({"index": index, "shown": shown});
        assert_eq!(
            ask(&app, "unskip_folder", &args.to_string()),
            json!({"ok":null})
        );
    }
    let remaining = ask(&app, "pending_review", "{}")["ok"]["skipped"].clone();
    std::fs::remove_dir_all(home).unwrap();
    assert_eq!(remaining, json!([left[2]]));
}

#[test]
fn consecutive_removals_use_the_same_displayed_list() {
    let (home, app) = engine("remove-two");
    let paths = ["One", "Two", "Three"].map(|name| home.join(name));
    for path in &paths {
        add_place(&app, path).unwrap();
    }
    let first = json!({"index": 0, "shown": show(&paths[0])});
    let second = json!({"index": 1, "shown": show(&paths[1])});
    assert_eq!(
        ask(&app, "remove_place", &first.to_string())["ok"]["extra"],
        json!([show(&paths[1]), show(&paths[2])])
    );
    let left = ask(&app, "remove_place", &second.to_string());
    std::fs::remove_dir_all(home).unwrap();
    assert_eq!(left["ok"]["extra"], json!([show(&paths[2])]));
}

#[test]
fn unknown_scope_blocks_preparation_and_scan_until_the_state_reads_again() {
    let _alone = one_scan();
    let (home, writer) = engine("unreadable-from-start");
    update_state(&writer, |state| {
        state.skipped.push(review::Skip {
            path: "~/Documents".into(),
            added: report::utc_now(),
        });
    })
    .unwrap();
    let state = home.join(review::STATE_DIR).join("state.json");
    let saved = std::fs::read(&state).unwrap();
    std::fs::write(&state, "{damaged").unwrap();
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

    SEEN.lock().unwrap().clear();
    ch_set_event_handler(Some(seen));
    let access = ask(&app, "prepare_access", r#"{"index":1}"#);
    let scan = ask(&app, "start_scan", "{}");
    ch_set_event_handler(None);

    let events = std::mem::take(&mut *SEEN.lock().unwrap());
    let retained = std::fs::read_to_string(&state).unwrap();
    let report = app.report.lock().unwrap().is_some();

    std::fs::write(&state, saved).unwrap();
    let scan_after_recovery = ask(&app, "start_scan", "{}");
    let after = ask(&app, "pending_review", "{}")["ok"]["error"].clone();
    std::fs::remove_dir_all(home).unwrap();
    assert!(
        access["error"].is_string(),
        "unknown scope allowed a folder access probe: {access}"
    );
    assert!(
        scan["error"].is_string(),
        "unknown scope allowed a scan: {scan}"
    );
    assert!(events.is_empty(), "blocked scan sent events: {events:?}");
    assert!(!report, "blocked scan created a report");
    assert_eq!(retained, "{damaged", "the scan saved over the state");
    assert_eq!(
        scan_after_recovery["ok"]["review"], 0,
        "{scan_after_recovery}"
    );
    assert_eq!(after, Value::Null, "no scan results were lost");
}

#[test]
fn unchecked_places_count_the_union_before_limiting_each_reason() {
    let (home, app) = engine("unequal-coverage");
    let manual_path = |n| format!("~/manual-{n:02}");
    update_state(&app, |state| {
        let mut saved = serde_json::to_value(&state.agent).unwrap();
        saved["unread_places"] = json!({
            "places": [
                [manual_path(0), "unreadable"],
                [manual_path(21), "unreadable"],
                [manual_path(21), "permission-denied"],
                ["~/automatic", "unreadable"],
                ["~/manual-\u{e9}", "unreadable"],
                [r"~/manual-\u{e9}", "unreadable"],
            ],
            "truncated": true,
        });
        state.agent = serde_json::from_value(saved).unwrap();
    })
    .unwrap();
    let report = Report {
        schema: "loose-keys/report/1",
        tool_version: "0.1.0",
        generated_at: report::utc_now(),
        status: "partial",
        context: "user",
        coverage: report::Coverage::default(),
        findings: Vec::new(),
        not_checked: (0..22)
            .map(|i| report::NotChecked {
                path: manual_path(i),
                reason: "unreadable",
            })
            .collect(),
    };
    *app.report.lock().unwrap() = Some(ManualReport { id: 1, report });
    let answer = ask(&app, "automatic_coverage", "{}");
    std::fs::remove_dir_all(home).unwrap();

    let groups = answer["ok"]["unread_gaps"].as_array().unwrap();
    let unreadable = groups
        .iter()
        .find(|group| group["label"] == "Couldn't Be Read")
        .unwrap();
    assert_eq!(unreadable["count"], 25, "{answer}");
    assert_eq!(
        unreadable["paths"].as_array().unwrap().len(),
        20,
        "{answer}"
    );
    assert_eq!(unreadable["paths"][0], manual_path(0));
    let denied = groups
        .iter()
        .find(|group| group["label"] == "No Access")
        .unwrap();
    assert_eq!(denied["paths"], json!([manual_path(21)]));
    assert_eq!(answer["ok"]["unread_truncated"], true);
}
