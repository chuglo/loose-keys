use super::tests::{ask, engine, one_scan};
use super::{review, scan};
use serde_json::json;
use std::fs;
use std::sync::{atomic::AtomicBool, Arc};
use std::time::Duration;

#[test]
fn saved_folder_scope_uses_the_spelling_on_disk() {
    let _alone = one_scan();
    let (home, app) = engine("folder-spelling");
    let folder = home.join("Invoices");
    fs::create_dir(&folder).unwrap();
    let csv = b"url,username,password\nhttps://example.invalid,a,synthetic\n";
    fs::write(folder.join("old.csv"), csv).unwrap();
    let initial = ask(&app, "start_scan", "{}");
    assert_eq!(initial["ok"]["review"], 1);
    assert_eq!(ask(&app, "skip_folder", r#"{"id":1}"#), json!({"ok":null}));
    let renamed = home.join("INVOICES");
    fs::rename(&folder, &renamed).unwrap();
    let same_directory = fs::symlink_metadata(&folder).is_ok();
    fs::write(renamed.join("new.csv"), csv).unwrap();
    let alias = home.join("invoices");
    // Also covers a folder saved by an earlier app with the spelling from its panel.
    app.store
        .as_ref()
        .unwrap()
        .update(|state| {
            state.selected_places.push(alias.clone());
            if same_directory {
                state.items[0].path = "~/INVOICES/old.csv".into();
            }
            Ok(())
        })
        .unwrap();
    if same_directory {
        // The merge must leave this item alone even though its old file is gone.
        fs::remove_file(renamed.join("old.csv")).unwrap();
    }
    let manual = ask(&app, "start_scan", "{}");
    let saved = app.store.as_ref().unwrap().read().unwrap();
    let report = app.report.lock().unwrap();
    let coverage = &report.as_ref().unwrap().report.coverage;
    if same_directory {
        assert_eq!(
            manual["ok"]["review"], 0,
            "the manual scan entered the skipped folder"
        );
        assert_eq!(coverage.roots, ["~/"]);
        assert_eq!(coverage.excluded_by_user, ["~/INVOICES"]);
        assert!(saved.items.iter().all(|i| !i.resolved));
    } else {
        assert_eq!(manual["ok"]["review"], 2);
        assert_eq!(coverage.excluded_by_user, ["~/Invoices"]);
    }
    drop(report);
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn automatic_checks_respect_a_saved_skip_after_a_case_only_rename() {
    let (home, _app) = engine("automatic-folder-spelling");
    let folder = home.join("Work");
    fs::create_dir(&folder).unwrap();
    let renamed = home.join("WORK");
    fs::rename(&folder, &renamed).unwrap();
    let same_directory = fs::symlink_metadata(&folder).is_ok();
    let path = renamed.join("export.csv");
    fs::write(
        &path,
        b"url,username,password\nhttps://example.invalid,a,synthetic\n",
    )
    .unwrap();
    let skip = [folder.clone()];
    let limits = scan::Limits {
        entries: 20_000,
        time: Duration::from_secs(5),
    };
    let cancel = || Arc::new(AtomicBool::new(false));
    let digest = |_: &str, _: &[u8], _: bool| String::new();
    let (changed, _) = scan::Scan::changed(&home, &skip, &[path], limits, cancel(), digest);
    let (sweep, _) = scan::Scan::sweep(&home, &skip, None, limits, cancel(), digest);
    // Work queued before the rename can retain the folder's original spelling.
    let pending = Some(vec![scan::Step::Folder(folder, 1)]);
    let (resumed, _) = scan::Scan::sweep(&home, &skip, pending, limits, cancel(), digest);
    assert_eq!(changed.findings.is_empty(), same_directory);
    assert_eq!(sweep.findings.is_empty(), same_directory);
    assert!(
        resumed.findings.is_empty(),
        "resumed pass entered the skipped folder"
    );
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn automatic_coverage_reports_overflow_in_a_single_slice() {
    let (home, _app) = engine("automatic-gaps-full");
    let dir = home.join("states");
    fs::create_dir(&dir).unwrap();
    for n in 0..4100 {
        fs::write(dir.join(format!("{n:04}.tfstate")), b"{").unwrap();
    }
    let mut places = review::UnreadPlaces::default();
    let limits = scan::Limits {
        entries: 20_000,
        time: Duration::from_secs(30),
    };
    let (report, pending, omitted) = scan::Scan::sweep_with_coverage(
        &home,
        &[],
        None,
        limits,
        Arc::new(AtomicBool::new(false)),
        |_, _, _| String::new(),
    );
    assert!(pending.is_empty());
    places.record(&report, omitted);
    assert!(places.places.len() <= review::MAX_UNREAD);
    assert!(
        places.truncated,
        "the scanner omitted unread paths before the helper recorded them"
    );
    fs::remove_dir_all(home).unwrap();
}
