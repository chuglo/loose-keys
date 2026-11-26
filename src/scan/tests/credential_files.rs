use super::*;

#[test]
fn terraform_sensitive_collections_are_detected_and_fingerprinted() {
    let f = Fixture::new("terraform-sensitive-collections");
    let state = |serial: u32, value: &str| {
        serde_json::json!({
            "terraform_version": "1.9.0", "serial": serial,
            "outputs": {
                "scalar": {"sensitive": true, "value": "synthetic-scalar-secret"},
                "collection": {"sensitive": true, "value": [{"nested": [value]}]},
                "public": {"sensitive": false, "value": [format!("synthetic-public-{serial}")]}
            },
            "resources": [{"type": "fixture", "name": "resource", "instances": [{
                "attributes": {"data": [{"nested": {"key": value}}]},
                "sensitive_attributes": [[{"type": "get_attr", "value": "data"}]]
            }]}]
        })
        .to_string()
    };
    let file = state(1, "synthetic-collection-secret");
    put(&f.0, "terraform.tfstate", file.as_bytes());
    let scan = Scan::run(&f.0, std::slice::from_ref(&f.0));
    let mut subjects: Vec<_> = scan
        .findings
        .iter()
        .filter_map(|f| f.subject.as_deref())
        .collect();
    subjects.sort_unstable();
    assert_eq!(
        subjects,
        ["fixture.resource", "output.collection", "output.scalar"]
    );
    assert!(scan.not_checked.is_empty());
    let material = |serial, value| {
        crate::rules::material(
            "dev.terraform.state-secret",
            state(serial, value).as_bytes(),
        )
    };
    assert!(material(1, "synthetic-first-value") == material(2, "synthetic-first-value"));
    assert!(material(1, "synthetic-first-value") != material(1, "synthetic-second-value"));
    let report = serde_json::to_string(&scan.into_report(std::slice::from_ref(&f.0))).unwrap();
    assert!(!report.contains("synthetic-collection-secret"));
    assert!(!report.contains("synthetic-scalar-secret"));
}

#[test]
fn json_that_only_looks_like_a_kubeconfig_is_not_a_gap() {
    let f = Fixture::new("kube-audit-log");
    // Kubernetes audit events, one JSON object per line.
    let event = r#"{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","stage":"ResponseComplete","verb":"get"}"#;
    put(
        &f.0,
        "Downloads/audit.log",
        format!("{event}\n").repeat(3).as_bytes(),
    );
    // Where kubectl reads, a damaged file is still one that couldn't be read.
    put(
        &f.0,
        ".kube/config",
        br#"{"apiVersion":"v1","kind":"Config","#,
    );
    let s = Scan::run(&f.0, std::slice::from_ref(&f.0));
    assert!(s.findings.is_empty());
    let gaps: Vec<_> = s
        .not_checked
        .iter()
        .map(|g| (g.path.as_str(), g.reason))
        .collect();
    assert_eq!(gaps, [("~/.kube/config", "unreadable")]);
}

#[test]
fn discovery_never_reads_presence_only_wallets_and_sessions() {
    let f = Fixture::new("presence-only-discovery");
    let export = b"url,username,password\nhttps://example.invalid,fixture,synthetic-only\n";
    let wallet = ".electrum/wallets";
    let extension = "Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn";
    let telegram = "Library/Application Support/Telegram Desktop/tdata";
    let adjacent = "adjacent.csv";
    for path in [
        format!("{wallet}/export.csv"),
        format!("{extension}/export.csv"),
        format!("{telegram}/key_datas"),
        format!("{telegram}/session"),
        "Library/Application Support/Bitcoin/wallet.dat".into(),
        adjacent.into(),
    ] {
        put(&f.0, &path, export);
    }
    let report = Scan::report_excluding(&f.0, &[f.0.join(wallet), f.0.join(extension)], &[]);
    let exports = |report: &crate::report::Report| {
        report
            .findings
            .iter()
            .filter(|f| f.rule == "export.password-csv")
            .map(|f| f.path.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(exports(&report), ["~/adjacent.csv"]);
    let cancel = Arc::new(AtomicBool::new(false));
    let paths = [
        f.0.join(format!("{wallet}/export.csv")),
        f.0.join(extension),
        f.0.join(telegram),
        f.0.join(adjacent),
    ];
    let changed = Scan::changed(&f.0, &[], &paths, limits(1000), cancel, digest).0;
    assert_eq!(exports(&changed), ["~/adjacent.csv"]);
    assert_eq!(
        recheck(
            "export.password-csv",
            &f.0.join(format!("{wallet}/export.csv")),
            &f.0,
            None
        ),
        None
    );
}

#[test]
fn presence_only_symlink_destinations_stay_unopened() {
    if is_root() {
        return;
    }
    let f = Fixture::new("presence-only-aliases");
    let export = b"url,username,password\nhttps://example.invalid,fixture,synthetic-only\n";
    let browser = "Library/Application Support/Google/Chrome";
    let settings = "Sync/profile/Local Extension Settings";
    let id = "nkbihfbeogaeaoehlefnkodbefgpgknn";
    for path in [
        "Sync/wallet/export.csv",
        "Sync/app/export.csv",
        "Sync/profile/neighbor.csv",
    ] {
        put(&f.0, path, export);
    }
    for dir in [
        ".electrum",
        "Library/Application Support/Google",
        "Sync/browser",
        settings,
    ] {
        fs::create_dir_all(f.0.join(dir)).unwrap();
    }
    for (to, at) in [
        ("Sync/wallet", ".electrum/wallets".to_string()),
        ("Sync/browser", browser.to_string()),
        ("Sync/profile", "Sync/browser/Default".to_string()),
        ("Sync/app", format!("{settings}/{id}")),
    ] {
        std::os::unix::fs::symlink(f.0.join(to), f.0.join(at)).unwrap();
    }
    let rules_at = |report: &crate::report::Report| {
        let mut results: Vec<_> = report
            .findings
            .iter()
            .map(|f| (f.rule, f.path.clone()))
            .collect();
        results.sort_unstable();
        results
    };
    let expected = [
        (
            "export.password-csv",
            "~/Sync/profile/neighbor.csv".to_string(),
        ),
        ("wallet.desktop.data", "~/Sync/wallet".to_string()),
        ("wallet.extension.vault", "~/Sync/app".to_string()),
    ];
    let report = Scan::report_excluding(&f.0, &[f.0.join("Sync/app")], &[]);
    assert_eq!(rules_at(&report), expected);
    let skipped = [f.0.join("Sync")];
    let report = Scan::report_excluding(&f.0, &[f.0.join("Sync/app")], &skipped);
    assert_eq!(rules_at(&report), expected[1..]);
    let (report, pending) = Scan::sweep(
        &f.0,
        &[],
        None,
        limits(1000),
        Arc::new(AtomicBool::new(false)),
        digest,
    );
    assert!(pending.is_empty());
    assert_eq!(rules_at(&report), expected);
    let paths = [
        "Sync/wallet/export.csv",
        "Sync/app/export.csv",
        "Sync/profile/neighbor.csv",
    ]
    .map(|path| f.0.join(path));
    let cancel = Arc::new(AtomicBool::new(false));
    let report = Scan::changed(&f.0, &[], &paths, limits(1000), cancel, digest).0;
    assert_eq!(rules_at(&report), expected);
    let cancel = Arc::new(AtomicBool::new(false));
    let report = Scan::changed(&f.0, &skipped, &paths, limits(1000), cancel, digest).0;
    assert!(report.findings.is_empty());
    assert_eq!(recheck("export.password-csv", &paths[1], &f.0, None), None);
    assert_eq!(
        recheck("wallet.extension.vault", &f.0.join("Sync/app"), &f.0, None),
        Some(vec![Some("MetaMask".to_string())])
    );
}

#[test]
fn a_removed_sidecar_for_a_linked_database_refreshes_its_count() {
    if is_root() {
        return;
    }
    let f = Fixture::new("sqlite-linked-sidecar");
    let browser = f.0.join("Library/Application Support/Google/Chrome");
    fs::create_dir_all(browser.join("Default")).unwrap();
    let real = "Sync/browser.db";
    let data = crate::rules::fixture_body::Body::Sqlite {
        sqlite: "logins".into(),
        rows: 1,
    }
    .bytes()
    .unwrap();
    put(&f.0, real, &data);
    std::os::unix::fs::symlink(f.0.join(real), browser.join("Default/Login Data")).unwrap();
    let sidecar = f.0.join(format!("{real}-wal"));
    let cancel = Arc::new(AtomicBool::new(false));
    let (report, left) = Scan::changed(&f.0, &[], &[sidecar], limits(1000), cancel, digest);
    assert_eq!(left, Unreached::default());
    assert!(report.not_checked.is_empty());
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].rule, "browser.chromium.saved-logins");
    assert_eq!(report.findings[0].path, "~/Sync/browser.db");
}

#[test]
fn differently_cased_extension_ids_are_still_presence_only() {
    let f = Fixture::new("presence-extension-case");
    let settings = "Library/Application Support/Google/Chrome/Default/Local Extension Settings";
    let id = "nkbihfbeogaeaoehlefnkodbefgpgknn";
    let body = b"url,username,password\nhttps://example.invalid,fixture,synthetic-only\n";
    let upper = id.to_ascii_uppercase();
    put(&f.0, &format!("{settings}/{upper}/export.csv"), body);
    let named = f.0.join(settings).join(id);
    if std::fs::symlink_metadata(named).is_err() {
        return; // A different extension name on a case-sensitive volume.
    }
    let mixed = f.0.join(settings).join("Nkbihfbeogaeaoehlefnkodbefgpgknn");
    let report = Scan::report_excluding(&f.0, std::slice::from_ref(&mixed), &[]);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].rule, "wallet.extension.vault");
    let (changed, pending) = Scan::changed(
        &f.0,
        &[],
        &[mixed.join("export.csv")],
        limits(1000),
        Arc::new(AtomicBool::new(false)),
        digest,
    );
    assert_eq!(pending, Unreached::default());
    assert_eq!(changed.findings.len(), 1);
    assert_eq!(changed.findings[0].rule, "wallet.extension.vault");
    assert_eq!(
        recheck("export.password-csv", &mixed.join("export.csv"), &f.0, None),
        None
    );
}

#[test]
fn cancelled_rechecks_do_not_start_a_file_read() {
    let f = Fixture::new("cancelled-recheck-file");
    let name = "export.csv";
    put(
        &f.0,
        name,
        b"url,username,password\nhttps://example.invalid,fixture,synthetic-only\n",
    );
    assert_eq!(
        recheck_identities(
            "export.password-csv",
            &f.0.join(name),
            &f.0,
            None,
            &digest,
            Want::Review,
            &|| true
        ),
        None,
    );
}
