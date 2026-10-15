#[path = "support/sqlite.rs"]
mod sqlite_fixture;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);
const EXCLUDED: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".cache",
    "Library/Caches",
    ".bun/install/cache",
    ".npm/_cacache",
    ".cargo/registry",
    ".rustup/toolchains",
    "vendor",
    "Library/Application Support/dev.loosekeys.desktop",
    "Library/Calendars",
    "Library/Application Support/AddressBook",
    "Library/Reminders",
    "Library/Photos",
    "Photos Library.photoslibrary",
];
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let base = std::env::var_os("TMPDIR").expect("set TMPDIR to a scratch directory");
        let path = PathBuf::from(base).join(format!(
            "credential-scope-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(path.join("home")).unwrap();
        Self(path)
    }
    fn home(&self) -> PathBuf {
        self.0.join("home")
    }
    fn csv(&self, path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            "url,username,password\nhttps://example.invalid,fixture,synthetic-only\n",
        )
        .unwrap();
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_loose-keys"))
            .env("HOME", self.home())
            .arg("scan")
            .args(args)
            .output()
            .unwrap()
    }
    fn json(&self, args: &[&str]) -> serde_json::Value {
        let mut args = args.to_vec();
        args.extend(["--export", "-"]);
        let out = self.run(&args);
        assert!(matches!(out.status.code(), Some(0 | 1 | 3)), "{:?}", out);
        serde_json::from_slice(&out.stdout).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn per_file_match_limits_keep_findings_and_make_the_scan_partial() {
    for (name, limit) in [(".env", 100), ("passwords.txt", 20)] {
        let f = Fixture::new();
        for count in [limit - 1, limit, limit + 1] {
            let body: String = (0..count)
                .map(|i| {
                    if name == ".env" {
                        format!("SERVICE_{i}_TOKEN=synthetic-value-{i}\n")
                    } else {
                        format!("service {i} password: synthetic-value-{i}\n")
                    }
                })
                .collect();
            fs::write(f.home().join(name), body).unwrap();
            let output = f.run(&["--export", "-"]);
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                report["findings"].as_array().unwrap().len(),
                count.min(limit)
            );
            assert!(!output.stdout.windows(15).any(|w| w == b"synthetic-value"));
            let limited = count > limit;
            assert_eq!(
                output.status.code(),
                Some(i32::from(limited)),
                "{name}: {count}"
            );
            assert_eq!(
                report["status"],
                if limited { "partial" } else { "complete" }
            );
            let expected = if limited {
                serde_json::json!([{"path": format!("~/{name}"), "reason": "scan-limit"}])
            } else {
                serde_json::json!([])
            };
            assert_eq!(report["not_checked"], expected);
        }
    }
}

#[test]
fn malformed_firefox_logins_are_reported_as_unreadable() {
    let f = Fixture::new();
    let relative = "Library/Application Support/Firefox/Profiles/fixture/logins.json";
    let path = f.home().join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    for body in ["{}", "null", "[]", r#"{"logins":null}"#, r#"{"logins":{}}"#] {
        fs::write(&path, body).unwrap();
        let output = f.run(&["--export", "-"]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "invalid login structure: {body}"
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(report["not_checked"].as_array().unwrap().iter().any(|gap| {
            gap["path"] == format!("~/{relative}") && gap["reason"] == "unreadable"
        }));
    }
    // An explicitly empty login list is valid evidence of zero saved logins.
    fs::write(path, r#"{"logins":[]}"#).unwrap();
    assert_eq!(f.run(&["--export", "-"]).status.code(), Some(0));
}

#[test]
fn help_works_without_a_home_or_a_scan() {
    for args in [
        vec![],
        vec!["--help"],
        vec!["scan", "--help"],
        vec!["scan", "-h"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_loose-keys"))
            .env_remove("HOME")
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("--feedback"));
    }
}

#[test]
fn compact_xml_passwords_are_found_without_exporting_values() {
    let f = Fixture::new();
    let values = [
        "synthetic-maven-private-value",
        "c3ludGhldGljLWZpbGV6aWxsYQ==",
    ];
    for (path, xml) in [
        (".m2/settings.xml", format!("<settings><servers><server><id>fixture-repository</id><password>{}<!-- note --></password></server></servers></settings>", values[0])),
        (".config/filezilla/sitemanager.xml", format!("<FileZilla3><Servers><Server><Host>fixture-host.invalid</Host><Pass encoding=\"base64\">{}<!-- note --></Pass></Server></Servers></FileZilla3>", values[1])),
    ] {
        let path = f.home().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, xml).unwrap();
    }
    let report = f.json(&[]);
    for rule in [
        "dev.maven.settings-password",
        "app.filezilla.saved-password",
    ] {
        let hits: Vec<_> = report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|hit| hit["rule"] == rule)
            .collect();
        assert_eq!(hits.len(), 1, "{rule}");
        assert_eq!(hits[0]["line"], 1);
    }
    for args in [vec![], vec!["--export", "-"]] {
        let output = f.run(&args);
        assert_eq!(output.status.code(), Some(0));
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            for value in values {
                for fragment in [value, &value[..10], &value[value.len() - 10..]] {
                    assert!(!text.contains(fragment), "XML value appeared in output");
                }
            }
            for label in ["fixture-repository", "fixture-host.invalid"] {
                if args.contains(&"--export") {
                    assert!(!text.contains(label), "subject appeared in JSON output");
                }
            }
        }
    }
}

#[test]
fn a_netrc_password_with_words_in_it_is_found_and_no_part_of_it_is_shown() {
    let f = Fixture::new();
    // One password in quotes, which curl and Python read as one value.
    let inner = "sensitive-inner-fragment";
    let quoted = format!("prefix machine {inner} password suffix-of-value");
    let plain = "second-private-value";
    fs::write(
        f.home().join(".netrc"),
        format!("machine fixture-host.invalid login fixture password \"{quoted}\"\nmachine second-host.invalid\n  login fixture\n  password {plain}\n"),
    )
    .unwrap();
    for args in [vec![], vec!["--export", "-"]] {
        let output = f.run(&args);
        assert_eq!(output.status.code(), Some(0));
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            for value in [quoted.as_str(), inner, plain] {
                for fragment in [value, &value[..10], &value[value.len() - 10..]] {
                    assert!(!text.contains(fragment), "netrc value appeared in output");
                }
            }
            for label in ["fixture-host.invalid", "second-host.invalid"] {
                if args.contains(&"--export") {
                    assert!(!text.contains(label), "subject appeared in JSON output");
                }
            }
        }
        // The hosts, and nothing else, name the two entries on the Mac.
        if args.is_empty() {
            let text = String::from_utf8_lossy(&output.stdout);
            for label in ["fixture-host.invalid", "second-host.invalid"] {
                assert!(text.contains(label), "{label} is not named");
            }
        }
    }
    let report = f.json(&[]);
    let lines: Vec<_> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|hit| hit["rule"] == "dev.netrc.inline-password")
        .map(|hit| hit["line"].as_u64().unwrap())
        .collect();
    assert_eq!(lines, [1, 4]);
}

#[test]
fn a_netrc_file_out_of_step_with_its_format_is_never_reported_as_checked() {
    let (one, two) = ("first-private-value", "second-private-value");
    for file in [
        // Two passwords that each open with a quote and close none.
        format!("machine fixture-host.invalid login fixture password \"{one}\nmachine second-host.invalid login fixture password \"{two}\n"),
        // A login with no value, so that `password` is taken for it.
        format!("machine fixture-host.invalid\n  login\n  password {one}\nmachine second-host.invalid login fixture password {two}\n"),
        format!("machine fixture-host.invalid login password {one}\n"),
        // A backslash at a line's end, which takes in the next line's `machine`.
        format!("machine fixture-host.invalid password {one}\\\nmachine second-host.invalid password {two}\n"),
        // A quote left open in a macro, which runs to the quote that opens a password.
        format!("macdef init\necho \"{one}\n\nmachine second-host.invalid login fixture password \"{two}\n"),
        // A password with blanks and no quotes.
        format!("machine fixture-host.invalid login fixture password {one} {two}\n"),
        // A quote that never closes.
        format!("machine fixture-host.invalid login fixture password \"{one}\nmachine second-host.invalid login fixture password {two}\n"),
    ] {
        let f = Fixture::new();
        fs::write(f.home().join(".netrc"), &file).unwrap();
        for args in [vec![], vec!["--export", "-"]] {
            let output = f.run(&args);
            // Not 0, which says that all in scope was checked.
            assert_eq!(output.status.code(), Some(1), "{file}");
            for bytes in [&output.stdout, &output.stderr] {
                let text = String::from_utf8_lossy(bytes);
                for value in [one, two] {
                    for fragment in [value, &value[..10], &value[value.len() - 10..]] {
                        assert!(!text.contains(fragment), "netrc value appeared in output");
                    }
                }
                // No host is a guess, on the Mac or in the report.
                for label in ["fixture-host.invalid", "second-host.invalid"] {
                    assert!(!text.contains(label), "{label} is named: {file}");
                }
            }
        }
        let report = f.json(&[]);
        assert_eq!(report["status"], "partial", "{file}");
        let gaps: Vec<_> = report["not_checked"]
            .as_array()
            .unwrap()
            .iter()
            .map(|gap| (gap["path"].as_str().unwrap(), gap["reason"].as_str().unwrap()))
            .collect();
        assert_eq!(gaps, [("~/.netrc", "unreadable")], "{file}");
        // Nothing found there is taken to be all there is.
        assert_eq!(report["findings"].as_array().unwrap().len(), 0, "{file}");
    }
}

#[test]
fn feedback_contains_only_fixed_metadata_and_counts() {
    let f = Fixture::new();
    f.csv(&f.home().join("private-account-name.csv"));
    fs::write(f.home().join("private-invalid.json"), r#"{"encrypted":"#).unwrap();
    let missing = f.0.join("private-selected-location");
    let output = f.run(&["--select", missing.to_str().unwrap(), "--feedback", "-"]);
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    for private in [
        "private-account",
        "private-invalid",
        "private-selected",
        "synthetic-only",
        "example.invalid",
        "fixture",
        "~/",
    ] {
        assert!(!text.contains(private), "leaked {private}: {text}");
    }
    let feedback: serde_json::Value = serde_json::from_str(&text).unwrap();
    let mut keys: Vec<_> = feedback
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "architecture",
            "context",
            "excluded_by_user",
            "findings_by_rule",
            "findings_by_severity",
            "findings_by_token_type",
            "not_checked_by_reason",
            "platform",
            "requested_roots",
            "review",
            "schema",
            "status",
            "tool_version"
        ]
    );
    assert_eq!(feedback["schema"], "loose-keys/feedback/1");
    assert_eq!(feedback["status"], "partial");
    assert_eq!(feedback["requested_roots"], 2);
    assert_eq!(feedback["excluded_by_user"], 0);
    let full = f.json(&["--select", missing.to_str().unwrap()]);
    let mut expected = serde_json::Map::new();
    for finding in full["findings"].as_array().unwrap() {
        let rule = finding["rule"].as_str().unwrap().to_owned();
        let count = expected.get(&rule).and_then(|v| v.as_u64()).unwrap_or(0);
        expected.insert(rule, (count + 1).into());
    }
    assert!(!expected.is_empty());
    assert_eq!(
        feedback["findings_by_rule"],
        serde_json::Value::Object(expected)
    );
    assert_eq!(feedback["not_checked_by_reason"]["unreadable"], 2);
    // Every level is there, so a reader of the counts needs no special cases.
    let review = &full["findings"].as_array().unwrap();
    for level in ["high", "medium", "low"] {
        let open = review
            .iter()
            .filter(|f| f["kind"] == "review" && f["severity"] == level)
            .count();
        assert_eq!(feedback["review"][level]["open"], open);
        let by_rule = feedback["review"][level]["open_by_rule"]
            .as_object()
            .unwrap();
        assert_eq!(
            by_rule.values().map(|n| n.as_u64().unwrap()).sum::<u64>(),
            open as u64
        );
    }
    assert!(feedback["review"]["high"]["open"].as_u64().unwrap() > 0);
}

#[test]
fn a_device_name_and_the_time_are_in_the_counts_only_when_the_caller_asks() {
    let f = Fixture::new();
    f.csv(&f.home().join("export.csv"));
    let run = |args: &[&str]| f.run(args);
    let output = run(&["--feedback", "-", "--device-id", "C02-FIXTURE.01"]);
    assert_eq!(output.status.code(), Some(0));
    let counts: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(counts["schema"], "loose-keys/device-counts/1");
    assert_eq!(counts["device_id"], "C02-FIXTURE.01");
    let time = counts["generated_at"].as_str().unwrap();
    assert!(time.len() == 20 && time.ends_with('Z'));
    // Everything else is the feedback a tester would send, which has neither.
    let mut plain: serde_json::Value =
        serde_json::from_slice(&run(&["--feedback", "-"]).stdout).unwrap();
    let mut named = counts.clone();
    for key in ["schema", "device_id", "generated_at"] {
        named.as_object_mut().unwrap().remove(key);
        assert!(plain.as_object_mut().unwrap().remove(key).is_none() || key == "schema");
    }
    assert_eq!(named, plain);
    // The name is the caller's, so its shape is fixed; and it means nothing
    // on a report that already names every file.
    let long = "x".repeat(65);
    for name in ["", "two words", "a/b", "caf\u{e9}", "a\nb", long.as_str()] {
        let refused = run(&["--feedback", "-", "--device-id", name]);
        assert_eq!(refused.status.code(), Some(2), "accepted {name:?}");
        assert!(refused.stdout.is_empty());
    }
    for args in [
        vec!["--device-id", "mac-1"],
        vec!["--export", "-", "--device-id", "mac-1"],
        vec![
            "--feedback",
            "-",
            "--device-id",
            "mac-1",
            "--device-id",
            "mac-2",
        ],
    ] {
        assert_eq!(run(&args).status.code(), Some(2), "accepted {args:?}");
    }
}

#[test]
fn feedback_export_is_private_create_only_and_exclusive_with_full_export() {
    use std::os::unix::fs::{symlink, MetadataExt};
    let f = Fixture::new();
    let destination = f.0.join("feedback.json");
    let path = destination.to_str().unwrap();
    assert!(f.run(&["--feedback", path]).status.success());
    assert_eq!(fs::metadata(&destination).unwrap().mode() & 0o777, 0o600);
    let original = fs::read(&destination).unwrap();
    assert_eq!(f.run(&["--feedback", path]).status.code(), Some(2));
    assert_eq!(fs::read(&destination).unwrap(), original);
    let link = f.0.join("feedback-link.json");
    symlink(&destination, &link).unwrap();
    assert_eq!(
        f.run(&["--feedback", link.to_str().unwrap()]).status.code(),
        Some(2)
    );
    assert_eq!(fs::read(&destination).unwrap(), original);
    let absent = f.0.join("feedback-absent-target.json");
    let dangling = f.0.join("feedback-dangling.json");
    symlink(&absent, &dangling).unwrap();
    assert_eq!(
        f.run(&["--feedback", dangling.to_str().unwrap()])
            .status
            .code(),
        Some(2)
    );
    assert!(fs::symlink_metadata(&absent).is_err());
    for args in [
        ["--export", "-", "--feedback", "-"],
        ["--feedback", "-", "--export", "-"],
        ["--feedback", "-", "--feedback", "-"],
    ] {
        let output = f.run(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn findings_distinguish_indicators_from_actual_access_or_revocation() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    fs::write(f.home().join("empty.csv"), "url,username,password\n").unwrap();
    fs::create_dir(f.home().join(".ssh")).unwrap();
    fs::write(
        f.home().join(".ssh/key"),
        "-----BEGIN RSA PRIVATE KEY-----\nsynthetic-only\n",
    )
    .unwrap();
    fs::set_permissions(f.home().join(".ssh/key"), fs::Permissions::from_mode(0o644)).unwrap();
    let r = f.json(&[]);
    let findings = r["findings"].as_array().unwrap();
    let export = findings
        .iter()
        .find(|x| x["rule"] == "export.password-csv")
        .unwrap();
    assert!(export["title"].as_str().unwrap().contains("Possible"));
    assert!(export["explanation"]
        .as_str()
        .unwrap()
        .contains("does not prove"));
    assert!(export["next_step"]
        .as_str()
        .unwrap()
        .contains("does not revoke"));
    let key = findings
        .iter()
        .find(|x| x["rule"] == "key.ssh.private")
        .unwrap();
    let reason = key["reason"].as_str().unwrap();
    assert!(
        reason.contains("authorization") && reason.contains("mode bits") && reason.contains("ACL")
    );
    assert!(!r.to_string().contains("works immediately"));
}

#[test]
fn discovery_uses_headers_not_filenames_across_recursive_roots() {
    let f = Fixture::new();
    f.csv(&f.home().join("Documents/renamed.backup"));
    let selected = f.0.join("external");
    f.csv(&selected.join("nested/no-extension"));
    for root in [f.home(), selected.clone()] {
        fs::create_dir_all(root.join("deep/keys")).unwrap();
        fs::write(
            root.join("deep/keys/misnamed.pub"),
            "-----BEGIN PRIVATE KEY-----\nsynthetic-only\n",
        )
        .unwrap();
    }
    let r = f.json(&[
        "--select",
        selected.to_str().unwrap(),
        "--select",
        f.home().join("deep").to_str().unwrap(),
    ]);
    assert_eq!(r["findings"].as_array().unwrap().len(), 4);
    assert_eq!(r["status"], "complete");
    assert!(!r.to_string().contains("synthetic-only"));
}

#[test]
fn discovers_structural_plaintext_bitwarden_exports_without_leaking_fields() {
    let f = Fixture::new();
    let export = serde_json::json!({
        "encrypted": false, "folders": [], "items": [{
            "id": "synthetic-account-id", "name": "synthetic-site-name", "type": 1,
            "login": {"username": "synthetic-user", "password": "synthetic-only"}
        }]
    });
    let selected = f.0.join("external");
    fs::create_dir(&selected).unwrap();
    for path in [
        f.home().join("renamed.backup"),
        selected.join("export.json"),
    ] {
        fs::write(path, serde_json::to_vec(&export).unwrap()).unwrap();
    }
    let r = f.json(&["--select", selected.to_str().unwrap()]);
    assert_eq!(r["findings"].as_array().unwrap().len(), 2);
    assert_eq!(r["findings"][0]["rule"], "export.password-bitwarden-json");
    assert_eq!(r["status"], "complete");
    for private in [
        "synthetic-account-id",
        "synthetic-site-name",
        "synthetic-user",
        "synthetic-only",
    ] {
        assert!(!r.to_string().contains(private));
    }
}

#[test]
fn git_plaintext_credentials_are_detected_without_reporting_accounts() {
    let f = Fixture::new();
    fs::write(f.home().join(".git-credentials"), "# synthetic fixture\nhttps://synthetic-account:synthetic-only@example.invalid\nhttps://user:${TOKEN}@example.invalid\nhttps://user@example.invalid\n").unwrap();
    let r = f.json(&[]);
    assert_eq!(r["findings"].as_array().unwrap().len(), 1);
    assert_eq!(r["findings"][0]["rule"], "dev.git.inline-credentials");
    assert_eq!(r["findings"][0]["line"], 2);
    for value in ["synthetic-account", "synthetic-only", "example.invalid"] {
        assert!(!r.to_string().contains(value));
    }
}

#[test]
fn repository_configs_are_read_for_url_credentials_and_nothing_else_in_git_is() {
    let f = Fixture::new();
    let repo = f.home().join("work/project");
    fs::create_dir_all(repo.join(".git/hooks")).unwrap();
    let token = format!("gh{}_{}", "p", "0123456789abcdefghijABCDEFGHIJ012345");
    let config = |host: &str| {
        format!(
            "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = https://synthetic-account:synthetic-only@{host}/team/project.git\n[remote \"mirror\"]\n\turl = https://{token}@{host}/team/project.git\n[remote \"ssh\"]\n\turl = git@{host}:team/project.git\n"
        )
    };
    fs::write(repo.join(".git/config"), config("git.example.invalid")).unwrap();
    // The rest of the folder stays unread.
    f.csv(&repo.join(".git/export.csv"));
    f.csv(&repo.join(".git/hooks/export.csv"));
    // A worktree or submodule keeps .git as a file that points elsewhere, and
    // .git can be a link. Neither is followed.
    let elsewhere = f.0.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    fs::write(elsewhere.join("config"), config("other.example.invalid")).unwrap();
    for name in ["pointer", "link"] {
        fs::create_dir_all(f.home().join("work").join(name)).unwrap();
    }
    fs::write(
        f.home().join("work/pointer/.git"),
        format!("gitdir: {}\n", elsewhere.display()),
    )
    .unwrap();
    std::os::unix::fs::symlink(&elsewhere, f.home().join("work/link/.git")).unwrap();

    let r = f.json(&[]);
    let found: Vec<_> = r["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["rule"].as_str().unwrap(),
                x["path"].as_str().unwrap(),
                x["line"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        found,
        [
            ("dev.url.inline-password", "~/work/project/.git/config", 4),
            ("secret.service-token", "~/work/project/.git/config", 6),
        ]
    );
    assert_eq!(r["status"], "complete");
    for value in [
        "synthetic-account",
        "synthetic-only",
        "example.invalid",
        &token,
    ] {
        assert!(!r.to_string().contains(value));
    }
    // The folder is still listed as excluded, and the limits say what is read in it.
    assert!(r["coverage"]["excluded_directories"]
        .as_array()
        .unwrap()
        .contains(&".git".into()));
    assert!(r["coverage"]["limitations"]
        .as_str()
        .unwrap()
        .contains(".git"));

    // A repository the person asked not to be checked is left unread.
    let r = f.json(&["--exclude", repo.to_str().unwrap()]);
    assert_eq!(r["findings"].as_array().unwrap().len(), 0);
}

#[test]
fn github_cli_detects_inline_host_and_user_tokens_not_references() {
    let f = Fixture::new();
    fs::create_dir_all(f.home().join(".config/gh")).unwrap();
    fs::write(f.home().join(".config/gh/hosts.yml"), "example.invalid:\n  oauth_token: synthetic-only # local fixture\n  users:\n    synthetic-account:\n      oauth_token: 'synthetic-user-token'\nother.invalid:\n  oauth_token: ${GH_TOKEN}\n  notes: |\n    oauth_token: not-a-token\nref.invalid:\n  oauth_token: *reference\nempty.invalid:\n  oauth_token: null\n").unwrap();
    let r = f.json(&[]);
    let findings = r["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|x| x["rule"] == "dev.gh.inline-token"));
    assert_eq!(findings[0]["line"], 2);
    assert_eq!(findings[1]["line"], 5);
    for value in [
        "synthetic-only",
        "synthetic-account",
        "synthetic-user-token",
        "example.invalid",
    ] {
        assert!(!r.to_string().contains(value));
    }
}

#[test]
fn npm_detects_inline_auth_fields_not_environment_or_helpers() {
    let f = Fixture::new();
    fs::write(f.home().join(".npmrc"), "; fixture\n//registry.example.invalid/:_authToken=synthetic-token\n_auth = \"c3ludGhldGljOm9ubHk=\"\n//registry.example.invalid/:_password=c3ludGhldGlj\n//other.invalid/:_authToken=${NPM_TOKEN}\ncredential_helper=synthetic-helper\n# _authToken=comment-only\nusername=synthetic-account\npassword=\n").unwrap();
    let r = f.json(&[]);
    let findings = r["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 3);
    assert!(findings
        .iter()
        .all(|x| x["rule"] == "dev.npm.inline-credentials"));
    assert_eq!(findings[0]["line"], 2);
    assert_eq!(findings[2]["line"], 4);
    for value in [
        "synthetic-token",
        "c3ludGhldGlj",
        "synthetic-account",
        "registry.example.invalid",
    ] {
        assert!(!r.to_string().contains(value));
    }
}

#[test]
fn config_references_and_helpers_are_not_inline_secrets() {
    let f = Fixture::new();
    fs::create_dir_all(f.home().join(".docker")).unwrap();
    fs::create_dir_all(f.home().join(".aws")).unwrap();
    fs::create_dir_all(f.home().join(".config/gh")).unwrap();
    fs::write(
        f.home().join(".docker/config.json"),
        r#"{"credsStore":"osxkeychain","auths":{"fixture":{"auth":"${DOCKER_AUTH}"}}}"#,
    )
    .unwrap();
    fs::write(
        f.home().join(".aws/credentials"),
        "[fixture]\naws_secret_access_key=${AWS_SECRET}\ncredential_process=never-execute-me\n",
    )
    .unwrap();
    fs::write(
        f.home().join(".git-credentials"),
        "https://user:${TOKEN}@example.invalid\n",
    )
    .unwrap();
    fs::write(f.home().join(".npmrc"), "_authToken=${NPM_TOKEN}\n_auth=\"\"\npassword=env:PASSWORD\ncredential_helper=never-execute-me\n").unwrap();
    fs::write(
        f.home().join(".config/gh/hosts.yml"),
        "example.invalid:\n  oauth_token: *reference\n  credential_helper: never-execute-me\n",
    )
    .unwrap();
    let r = f.json(&[]);
    assert_eq!(r["findings"].as_array().unwrap().len(), 0);
    assert_eq!(r["status"], "complete");
}

#[test]
fn json_and_targeted_config_reads_have_explicit_size_and_parse_gaps() {
    let f = Fixture::new();
    let mut export = serde_json::to_vec(&serde_json::json!({
        "encrypted": false, "folders": [], "items": [
            {"id": "synthetic-id", "name": "fixture", "type": 1, "login": {"password": "synthetic-only"}}
        ]
    })).unwrap();
    export.resize(1024 * 1024, b' ');
    fs::write(f.home().join("exact-limit.json"), &export).unwrap();
    export.push(b' ');
    fs::write(f.home().join("over-limit.json"), &export).unwrap();
    fs::write(
        f.home().join("malformed.json"),
        r#"{"encrypted": false, not JSON"#,
    )
    .unwrap();
    fs::write(f.home().join("other-malformed.json"), "{not valid JSON").unwrap();
    for name in [
        ".docker/config.json",
        ".aws/credentials",
        ".git-credentials",
        ".config/gh/hosts.yml",
        ".npmrc",
    ] {
        let path = f.home().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, &export).unwrap();
    }
    let r = f.json(&[]);
    assert_eq!(r["findings"].as_array().unwrap().len(), 1);
    assert_eq!(r["findings"][0]["path"], "~/exact-limit.json");
    assert_eq!(r["status"], "partial");
    let gaps = r["not_checked"].as_array().unwrap();
    for name in [
        "over-limit.json",
        ".docker/config.json",
        ".aws/credentials",
        ".git-credentials",
        ".config/gh/hosts.yml",
        ".npmrc",
    ] {
        assert!(gaps
            .iter()
            .any(|g| g["path"] == format!("~/{name}") && g["reason"] == "too-large"));
    }
    assert!(gaps
        .iter()
        .any(|g| g["path"] == "~/malformed.json" && g["reason"] == "unreadable"));
    assert!(
        !gaps.iter().any(|g| g["path"] == "~/other-malformed.json"),
        "JSON without an encrypted key is not a Bitwarden candidate"
    );
}

#[test]
fn discovery_does_not_read_headers_beyond_four_kib() {
    let f = Fixture::new();
    let mut bytes = vec![b' '; 4096];
    bytes.extend_from_slice(b"-----BEGIN PRIVATE KEY-----\nsynthetic-only\n");
    fs::write(f.home().join("late-key"), &bytes).unwrap();
    fs::write(
        f.home().join("unrelated.json"),
        r#"{"password":"synthetic-only"}"#,
    )
    .unwrap();
    let r = f.json(&[]);
    assert_eq!(r["findings"].as_array().unwrap().len(), 0);
    assert_eq!(r["status"], "complete");
}

#[test]
fn report_export_remains_owner_only_and_create_only() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    f.csv(&f.home().join("export.csv"));
    let destination = f.0.join("report.json");
    let out = f.run(&["--export", destination.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let original = fs::read(&destination).unwrap();
    let second = f.run(&["--export", destination.to_str().unwrap()]);
    assert_eq!(second.status.code(), Some(2));
    assert_eq!(fs::read(&destination).unwrap(), original);
}

#[test]
fn discovers_nested_exports_across_home() {
    let f = Fixture::new();
    for name in [
        "Documents/backups/passwords.CSV",
        ".private/archive/export.csv",
        "Downloads/nested/export.csv",
    ] {
        f.csv(&f.home().join(name));
    }
    let r = f.json(&[]);
    assert_eq!(r["findings"].as_array().unwrap().len(), 3);
    assert_eq!(r["status"], "complete");
}

/// macOS asks the person for their contacts when a program opens this one
/// settings file, so discovery passes it and reads the files beside it.
#[test]
fn the_contacts_settings_file_is_not_opened() {
    let f = Fixture::new();
    let settings = f.home().join("Library/Preferences");
    f.csv(&settings.join("com.apple.AddressBook.plist"));
    f.csv(&settings.join("com.example.plist"));
    let r = f.json(&[]);
    let found: Vec<_> = r["findings"].as_array().unwrap().iter().collect();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["path"], "~/Library/Preferences/com.example.plist");
    assert!(r["coverage"]["limitations"]
        .as_str()
        .unwrap()
        .contains("Contacts settings"));
}

#[test]
fn exclusions_and_detection_boundaries_are_visible() {
    let f = Fixture::new();
    for name in EXCLUDED {
        f.csv(&f.home().join(name).join("export.csv"));
    }
    f.csv(&f.home().join("Documents/keep/export.csv"));
    let r = f.json(&[]);
    assert_eq!(r["findings"].as_array().unwrap().len(), 1);
    assert_eq!(r["coverage"]["roots"], serde_json::json!(["~/"]));
    assert_eq!(
        r["coverage"]["excluded_directories"],
        serde_json::json!(EXCLUDED)
    );
    assert!(r["coverage"]["limitations"]
        .as_str()
        .unwrap()
        .contains("CSV"));
    let out = f.run(&[]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("node_modules") && text.contains("--limits"));
    assert!(!text.contains("No archives"), "limits are opt-in: {text}");
    let out = f.run(&["--limits"]);
    let text = String::from_utf8(out.stdout).unwrap();
    let words = text.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(words.contains("LIMITS") && words.contains("No archives"));
    assert!(
        text.lines().all(|l| l.len() <= 78),
        "lines must wrap: {text}"
    );
    let coverage = r["coverage"]["limitations"].as_str().unwrap();
    for detail in [
        "regardless of extension",
        "Bitwarden",
        "private-key",
        "1 MiB",
        "per root",
        "~/.git-credentials",
        "~/.config/gh/hosts.yml",
        "~/.npmrc",
        "No archives",
        "not revoke",
    ] {
        assert!(coverage.contains(detail), "missing {detail}");
    }
    assert!(coverage.len() <= 2000, "must fit report schema");
}

#[test]
fn selected_roots_are_additive_deduplicated_and_can_override_exclusions() {
    let f = Fixture::new();
    f.csv(&f.home().join("Documents/export.csv"));
    let backup = f.0.join("external backup");
    f.csv(&backup.join("nested/export.csv"));
    let excluded = f.home().join("target");
    f.csv(&excluded.join("export.csv"));
    let r = f.json(&[
        "--select",
        backup.to_str().unwrap(),
        "--select",
        excluded.to_str().unwrap(),
        "--select",
        backup.to_str().unwrap(),
        "--select",
        f.home().join("Documents").to_str().unwrap(),
    ]);
    assert_eq!(r["findings"].as_array().unwrap().len(), 3);
    assert_eq!(r["coverage"]["roots"].as_array().unwrap().len(), 4);
}

#[test]
fn never_reads_through_symlinked_parent_directories() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let outside = f.0.join("outside");
    f.csv(&outside.join("nested/export.csv"));
    fs::write(
        outside.join("credentials"),
        "[fixture]\naws_secret_access_key = synthetic-only\n",
    )
    .unwrap();
    symlink(&outside, f.home().join(".aws")).unwrap();
    symlink(&outside, f.home().join("link")).unwrap();
    let r = f.json(&["--select", f.home().join("link/nested").to_str().unwrap()]);
    assert_eq!(r["findings"].as_array().unwrap().len(), 0);
    // The known location behind a link out of the home is a gap, not silence.
    assert_eq!(r["status"], "partial");
    assert!(r["not_checked"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["path"] == "~/.aws/credentials" && g["reason"] == "symlink"));
}

#[test]
fn known_locations_linked_inside_home_are_checked_at_their_real_path() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let f = Fixture::new();
    let dotfiles = f.home().join("dotfiles");
    fs::create_dir_all(dotfiles.join("aws")).unwrap();
    fs::create_dir_all(dotfiles.join("ssh")).unwrap();
    fs::write(dotfiles.join("npmrc"), "_authToken=synthetic-only\n").unwrap();
    fs::write(
        dotfiles.join("aws/credentials"),
        "[fixture]\naws_secret_access_key = synthetic-only\n",
    )
    .unwrap();
    fs::write(
        dotfiles.join("ssh/id_fixture"),
        "-----BEGIN RSA PRIVATE KEY-----\nsynthetic-only\n",
    )
    .unwrap();
    for name in ["npmrc", "aws/credentials", "ssh/id_fixture"] {
        fs::set_permissions(dotfiles.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    // A linked file, a linked folder, and a folder of linked files.
    symlink(dotfiles.join("npmrc"), f.home().join(".npmrc")).unwrap();
    symlink(dotfiles.join("aws"), f.home().join(".aws")).unwrap();
    fs::create_dir(f.home().join(".ssh")).unwrap();
    symlink(
        dotfiles.join("ssh/id_fixture"),
        f.home().join(".ssh/id_fixture"),
    )
    .unwrap();

    let r = f.json(&[]);
    assert_eq!(r["status"], "complete", "{}", r["not_checked"]);
    let mut found: Vec<_> = r["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| (x["rule"].as_str().unwrap(), x["path"].as_str().unwrap()))
        .collect();
    found.sort_unstable();
    assert_eq!(
        found,
        [
            ("dev.aws.inline-credentials", "~/dotfiles/aws/credentials"),
            ("dev.npm.inline-credentials", "~/dotfiles/npmrc"),
            ("key.ssh.private", "~/dotfiles/ssh/id_fixture"),
        ]
    );

    // A home folder that is itself reached through a link is scanned as usual.
    symlink(f.home(), f.0.join("home-link")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_loose-keys"))
        .env("HOME", f.0.join("home-link"))
        .args(["scan", "--export", "-"])
        .output()
        .unwrap();
    let linked: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(linked["findings"], r["findings"]);
    assert_eq!(linked["coverage"]["roots"], serde_json::json!(["~/"]));
}

#[test]
fn unavailable_requested_roots_are_not_reported_complete() {
    let f = Fixture::new();
    let missing = f.0.join("missing");
    let out = f.run(&["--select", missing.to_str().unwrap(), "--export", "-"]);
    assert_eq!(out.status.code(), Some(1));
    let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["status"], "partial");
    assert_eq!(r["not_checked"][0]["path"], missing.to_str().unwrap());
}

#[test]
fn permission_denials_are_reported_without_hiding_other_findings() {
    use std::os::unix::fs::PermissionsExt;
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "run this test as an ordinary user"
    );
    let f = Fixture::new();
    let denied = f.home().join("denied");
    f.csv(&denied.join("export.csv"));
    f.csv(&f.home().join("Documents/export.csv"));
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o0)).unwrap();
    let out = f.run(&["--export", "-"]);
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(out.status.code(), Some(1));
    let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["findings"].as_array().unwrap().len(), 1);
    assert_eq!(r["not_checked"][0]["reason"], "permission-denied");
}

#[test]
fn special_files_links_and_large_headers_do_not_break_discovery() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let large = f.home().join("large.csv");
    f.csv(&large);
    fs::OpenOptions::new()
        .write(true)
        .open(&large)
        .unwrap()
        .set_len(1 << 30)
        .unwrap();
    symlink(&large, f.home().join("linked.csv")).unwrap();
    symlink(f.home(), f.home().join("loop")).unwrap();
    let fifo =
        std::ffi::CString::new(f.home().join("pipe.csv").as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let hostile = f.home().join("nested/escape\u{1b}\n.csv");
    f.csv(&hostile);
    let out = f.run(&["--export", "-"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(!out.stdout.contains(&0x1b));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("synthetic-only"));
    let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["findings"].as_array().unwrap().len(), 2);
}

#[test]
fn invalid_cli_options_fail_before_scanning() {
    let f = Fixture::new();
    for args in [
        &["--select"][..],
        &["--export"],
        &["--export", "-", "--export", "-"],
        &["--select", ""],
        &["--select", "../somewhere"],
        &["--unknown", "x"],
    ] {
        assert_eq!(f.run(args).status.code(), Some(2));
    }
}

#[test]
fn export_refuses_symlinked_parent_directories() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let outside = f.0.join("outside");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, f.0.join("link")).unwrap();
    let out = f.run(&["--export", f.0.join("link/report.json").to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(!outside.join("report.json").exists());
}

#[test]
fn deep_trees_stop_with_an_explicit_coverage_gap() {
    let f = Fixture::new();
    let mut deep = f.home();
    for _ in 0..65 {
        deep.push("d");
    }
    f.csv(&deep.join("export.csv"));
    let r = f.json(&[]);
    assert_eq!(r["status"], "partial");
    assert_eq!(r["not_checked"][0]["reason"], "scan-limit");
    assert_eq!(r["findings"].as_array().unwrap().len(), 0);
}

#[test]
fn an_agent_folder_deeper_than_its_limit_is_an_explicit_gap() {
    let f = Fixture::new();
    let mut deep = f.home().join(".claude");
    for _ in 0..17 {
        deep.push("d");
    }
    fs::create_dir_all(&deep).unwrap();
    // A second folder past the limit: the tree still gets one gap, not one each.
    fs::create_dir_all(deep.with_file_name("e")).unwrap();
    // Past the first 4 KiB, so only a full read of the record finds it.
    let token = format!("gh{}_{}", "p", "0123456789abcdefghijABCDEFGHIJ012345");
    fs::write(
        deep.join("record.jsonl"),
        format!(
            "{}{{\"out\":\"{token}\"}}\n",
            "{\"type\":\"filler\"}\n".repeat(400)
        ),
    )
    .unwrap();
    let r = f.json(&[]);
    assert_eq!(r["findings"].as_array().unwrap().len(), 0);
    assert_eq!(r["status"], "partial");
    let gaps = r["not_checked"].as_array().unwrap();
    assert_eq!(gaps.len(), 1, "{gaps:?}");
    assert_eq!(gaps[0]["reason"], "scan-limit");
    assert!(gaps[0]["path"]
        .as_str()
        .unwrap()
        .starts_with("~/.claude/d/"));
}

#[test]
fn a_wallet_extension_in_a_browser_with_one_top_level_profile_is_found() {
    // Opera keeps its profile in the browser's own folder, not in a subfolder.
    let f = Fixture::new();
    let opera = "Library/Application Support/com.operasoftware.Opera";
    let store = format!("{opera}/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn");
    fs::create_dir_all(f.home().join(&store)).unwrap();
    fs::write(f.home().join(&store).join("000003.log"), b"x").unwrap();
    let r = f.json(&[]);
    let found: Vec<_> = r["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| (x["rule"].as_str().unwrap(), x["path"].as_str().unwrap()))
        .collect();
    assert_eq!(
        found,
        [("wallet.extension.vault", format!("~/{store}").as_str())]
    );
}

#[test]
fn wide_trees_stop_with_an_explicit_coverage_gap() {
    let f = Fixture::new();
    for i in 0..10_001 {
        f.csv(&f.home().join(format!("file-{i}.csv")));
    }
    let r = f.json(&[]);
    assert_eq!(r["status"], "partial");
    assert_eq!(r["not_checked"][0]["reason"], "scan-limit");
    assert_eq!(r["findings"].as_array().unwrap().len(), 10_000);
}

#[test]
fn total_discovery_work_is_bounded_across_directories() {
    let f = Fixture::new();
    for dir in 0..11 {
        let path = f.home().join(format!("dir-{dir:02}"));
        fs::create_dir(&path).unwrap();
        for i in 0..10_000 {
            if dir == 9 || (dir == 10 && i == 0) {
                f.csv(&path.join(format!("file-{i}.csv")));
            } else {
                fs::write(path.join(format!("file-{i}")), "").unwrap();
            }
        }
    }
    let outside = f.0.join("selected");
    f.csv(&outside.join("export.csv"));
    let r = f.json(&[
        "--select",
        f.home().join("dir-09").to_str().unwrap(),
        "--select",
        f.home().join("dir-10").to_str().unwrap(),
        "--select",
        outside.to_str().unwrap(),
    ]);
    assert_eq!(r["findings"].as_array().unwrap().len(), 10_002);
    assert_eq!(r["status"], "partial");
    assert!(r["not_checked"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["reason"] == "scan-limit"));
}

/// A home holding the kinds of files infostealers and supply-chain malware
/// collect. Token-shaped strings are assembled here so this file holds none.
#[test]
fn stealer_targets_are_found_with_fixes_and_without_values() {
    let f = Fixture::new();
    let home = f.home();
    let put = |path: &str, content: &[u8]| {
        let path = home.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    };
    let github = format!("gh{}_{}", "p", "0123456789abcdefghijABCDEFGHIJ012345");
    let secret = "synthetic-only-value";
    put(
        "work/app/.env.local",
        format!("PORT=8080\nGITHUB_TOKEN={github}\nDATABASE_PASSWORD={secret}\n").as_bytes(),
    );
    put(
        ".zsh_history",
        format!(": 1700000000:0;ls\n: 1700000001:0;export DEPLOY_API_KEY={secret}\n").as_bytes(),
    );
    put(
        "notes/todo.txt",
        format!("rotate {github} soon\n").as_bytes(),
    );
    put(
        "Downloads/project-1234.json",
        format!(r#"{{"type": "service_account", "client_email": "deploy@fixture-project.iam.gserviceaccount.com", "private_key": "{secret}"}}"#).as_bytes(),
    );
    put(
        ".kube/config",
        format!("users:\n- name: fixture\n  user:\n    token: {secret}\n").as_bytes(),
    );
    put(
        ".config/gcloud/application_default_credentials.json",
        format!(r#"{{"type": "authorized_user", "refresh_token": "{secret}"}}"#).as_bytes(),
    );
    put(
        ".azure/msal_token_cache.json",
        format!(r#"{{"RefreshToken": {{"k": {{"secret": "{secret}"}}}}}}"#).as_bytes(),
    );
    put(
        ".terraform.d/credentials.tfrc.json",
        format!(r#"{{"credentials": {{"tf.example.invalid": {{"token": "{secret}"}}}}}}"#)
            .as_bytes(),
    );
    put(".vault-token", format!("{secret}\n").as_bytes());
    put(
        ".pypirc",
        format!("[pypi]\nusername = __token__\npassword = {secret}\n").as_bytes(),
    );
    put(
        ".cargo/credentials.toml",
        format!("[registry]\ntoken = \"{secret}\"\n").as_bytes(),
    );
    put(
        ".gem/credentials",
        format!("---\n:rubygems_api_key: {secret}\n").as_bytes(),
    );
    put(
        ".netrc",
        format!("machine api.example.invalid login fixture password {secret}\n").as_bytes(),
    );
    put(
        ".cursor/mcp.json",
        format!(r#"{{"mcpServers": {{"tracker": {{"command": "npx", "env": {{"TRACKER_API_KEY": "{secret}"}}}}}}}}"#).as_bytes(),
    );
    put(
        ".codex/auth.json",
        format!(r#"{{"tokens": {{"refresh_token": "{secret}"}}}}"#).as_bytes(),
    );
    let db = sqlite_fixture::table("logins", 4);
    put(
        "Library/Application Support/Google/Chrome/Default/Login Data",
        &db,
    );
    put(
        "Library/Application Support/Firefox/Profiles/abc.default/logins.json",
        br#"{"nextId": 3, "logins": [{"id": 1}, {"id": 2}]}"#,
    );

    let r = f.json(&[]);
    assert_eq!(r["status"], "complete", "{}", r["not_checked"]);
    let findings = r["findings"].as_array().unwrap();
    let count = |rule: &str| findings.iter().filter(|x| x["rule"] == rule).count();
    for (rule, want) in [
        ("secret.service-token", 2),
        ("secret.env-assignment", 2),
        ("dev.gcp.service-account-key", 1),
        ("dev.kube.inline-credentials", 1),
        ("dev.gcloud.stored-login", 1),
        ("dev.azure.stored-login", 1),
        ("dev.terraform.inline-token", 1),
        ("dev.vault.token", 1),
        ("dev.pypi.inline-credentials", 1),
        ("dev.cargo.inline-token", 1),
        ("dev.rubygems.inline-key", 1),
        ("dev.netrc.inline-password", 1),
        ("dev.mcp.inline-secret", 1),
        ("dev.ai.stored-login", 1),
        ("browser.chromium.saved-logins", 1),
        ("browser.firefox.saved-logins", 1),
    ] {
        assert_eq!(count(rule), want, "{rule}");
    }
    assert_eq!(findings.len(), 18);

    // Highest severity first, and every review finding says how to fix it.
    assert_eq!(findings[0]["severity"], "high");
    for x in findings {
        if x["kind"] == "review" {
            assert!(!x["steps"].as_array().unwrap().is_empty(), "{}", x["rule"]);
        }
    }
    let token = findings
        .iter()
        .find(|x| x["rule"] == "secret.service-token")
        .unwrap();
    assert_eq!(token["link"], "https://github.com/settings/tokens");
    assert_eq!(token["token_type"], "GitHub personal access token");
    // Only token findings carry a type, and the counts-only output totals them.
    assert_eq!(
        findings
            .iter()
            .filter(|x| !x["token_type"].is_null())
            .count(),
        2
    );
    let feedback: serde_json::Value =
        serde_json::from_slice(&f.run(&["--feedback", "-"]).stdout).unwrap();
    assert_eq!(
        feedback["findings_by_token_type"],
        serde_json::json!({"GitHub personal access token": 2})
    );

    // The export holds no values, hosts or account names.
    let export = r.to_string();
    for private in [
        secret,
        github.as_str(),
        "example.invalid",
        "fixture-project",
        "tracker",
        "DEPLOY_API_KEY",
    ] {
        assert!(!export.contains(private), "export leaked {private}");
    }

    // The local summary names what each finding concerns, never its value.
    let text = String::from_utf8(f.run(&[]).stdout).unwrap();
    for shown in [
        "(GitHub personal access token)",
        "(DATABASE_PASSWORD)",
        "(deploy@fixture-project.iam.gserviceaccount.com)",
        "(api.example.invalid)",
        "(server tracker)",
        "(4 saved logins)",
        "(2 saved logins)",
        "Where: https://github.com/settings/tokens",
    ] {
        assert!(text.contains(shown), "summary lacks {shown}:\n{text}");
    }
    assert!(!text.contains(secret) && !text.contains(&github));
}

/// What consumer infostealers take, and what AI agents leave behind.
#[test]
fn wallets_app_sessions_notes_and_agent_records_are_found() {
    let f = Fixture::new();
    let home = f.home();
    let put = |path: &str, content: &[u8]| {
        let path = home.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    };
    let chrome = "Library/Application Support/Google/Chrome/Profile 1";
    // A wallet extension's storage folder, and one that is not a wallet.
    put(
        &format!("{chrome}/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log"),
        b"x",
    );
    put(
        &format!("{chrome}/Local Extension Settings/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/000003.log"),
        b"x",
    );
    // Saved payment cards in a complete synthetic SQLite database.
    let db = sqlite_fixture::table("credit_cards", 2);
    put(&format!("{chrome}/Web Data"), &db);
    // Opera keeps a profile at the top of its folder.
    let logins = sqlite_fixture::table("logins", 5);
    put(
        "Library/Application Support/com.operasoftware.Opera/Login Data",
        &logins,
    );
    put(
        "Library/Application Support/Exodus/exodus.wallet/seed.seco",
        b"synthetic",
    );
    put(
        "Library/Application Support/Telegram Desktop/tdata/key_datas",
        b"synthetic",
    );
    put(
        "Desktop/seed.txt",
        concat!(
            "velvet winner thank year wave sausage ",
            "worth useful legal winner thank yellow\n"
        )
        .as_bytes(),
    );
    put(
        "Desktop/logins.txt",
        b"router admin password: synthetic-value-9\n",
    );
    put(
        "Documents/vault.kdbx",
        b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5synthetic",
    );
    put(
        ".config/filezilla/sitemanager.xml",
        b"<Server>\n<Host>ftp.example.invalid</Host>\n<Pass encoding=\"base64\">c3ludGhldGlj</Pass>\n</Server>\n",
    );
    // A token 3 MB into an agent session record, far past any header read.
    let token = format!("gh{}_{}", "p", "0123456789abcdefghijABCDEFGHIJ012345");
    let filler =
        "{\"type\":\"assistant\",\"text\":\"ordinary synthetic session content\"}\n".repeat(50_000);
    let record = format!("{filler}{{\"type\":\"tool_use\",\"command\":\"curl -H 'Authorization: Bearer {token}'\"}}\n{filler}");
    // The same token again later, and a second, different token of the same kind.
    let other = format!("gh{}_{}", "p", "ZYXWVUTSRQzyxwvutsrq9876543210987654");
    let record = format!("{record}{{\"output\":\"{token}\"}}\n{{\"output\":\"{other}\"}}\n");
    put(".claude/projects/-work-app/3f2a.jsonl", record.as_bytes());
    put(
        ".claude/plugins/cache/tool.js",
        format!("const t = '{token}';\n").as_bytes(),
    );

    let r = f.json(&[]);
    let findings = r["findings"].as_array().unwrap();
    let path_of = |rule: &str| -> Vec<&str> {
        findings
            .iter()
            .filter(|x| x["rule"] == rule)
            .map(|x| x["path"].as_str().unwrap())
            .collect()
    };
    assert_eq!(
        path_of("wallet.extension.vault"),
        [format!(
            "~/{chrome}/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"
        )]
    );
    assert_eq!(
        path_of("browser.chromium.saved-cards"),
        [format!("~/{chrome}/Web Data")]
    );
    assert_eq!(
        path_of("browser.chromium.saved-logins"),
        ["~/Library/Application Support/com.operasoftware.Opera/Login Data"]
    );
    assert_eq!(
        path_of("wallet.desktop.data"),
        ["~/Library/Application Support/Exodus/exodus.wallet"]
    );
    assert_eq!(
        path_of("app.telegram.session"),
        ["~/Library/Application Support/Telegram Desktop/tdata/key_datas"]
    );
    assert_eq!(path_of("wallet.recovery-phrase"), ["~/Desktop/seed.txt"]);
    assert_eq!(path_of("export.password-note"), ["~/Desktop/logins.txt"]);
    assert_eq!(
        path_of("export.keepass-database"),
        ["~/Documents/vault.kdbx"]
    );
    assert_eq!(
        path_of("app.filezilla.saved-password"),
        ["~/.config/filezilla/sitemanager.xml"]
    );
    // The record is found with its line; the tool's plugin folder is not read.
    let record = findings
        .iter()
        .find(|x| x["rule"] == "secret.agent-record")
        .unwrap();
    assert_eq!(record["path"], "~/.claude/projects/-work-app/3f2a.jsonl");
    assert_eq!(record["line"], 50_001);
    assert_eq!(record["token_type"], "GitHub personal access token");
    assert_eq!(record["link"], "https://github.com/settings/tokens");
    assert!(record["steps"][1]
        .as_str()
        .unwrap()
        .contains("Delete this file"));
    // One finding per distinct token, not per appearance.
    let lines: Vec<_> = findings
        .iter()
        .filter(|x| x["rule"] == "secret.agent-record")
        .map(|x| x["line"].as_u64().unwrap())
        .collect();
    assert_eq!(lines, [50_001, 100_003]);
    assert!(!r.to_string().contains(&other));

    let text = String::from_utf8(f.run(&[]).stdout).unwrap();
    for shown in [
        "(MetaMask)",
        "(2 saved cards)",
        "(5 saved logins)",
        "(Exodus)",
        "(Telegram Desktop)",
        "(ftp.example.invalid)",
    ] {
        assert!(text.contains(shown), "summary lacks {shown}");
    }
    assert!(!r.to_string().contains(&token) && !text.contains(&token));
}

#[test]
fn a_skipped_folder_is_not_read_and_is_always_listed() {
    let f = Fixture::new();
    f.csv(&f.home().join("corpus/samples/export.csv"));
    f.csv(&f.home().join("Documents/export.csv"));
    fs::create_dir(f.home().join(".aws")).unwrap();
    fs::write(
        f.home().join(".aws/credentials"),
        "[fixture]\naws_secret_access_key = synthetic-only\n",
    )
    .unwrap();
    let corpus = f.home().join("corpus");
    let r = f.json(&["--exclude", corpus.to_str().unwrap()]);
    let paths: Vec<_> = r["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["~/.aws/credentials", "~/Documents/export.csv"]);
    // A skip is intentional, so the scan is still complete, but it is stated.
    assert_eq!(r["status"], "complete");
    assert_eq!(
        r["coverage"]["excluded_by_user"],
        serde_json::json!(["~/corpus"])
    );
    let text = String::from_utf8(f.run(&["--exclude", corpus.to_str().unwrap()]).stdout).unwrap();
    assert!(text.contains("Not checked at your request: \"~/corpus\""));
    // The counts say that a folder was skipped, and not which.
    let counts = f.run(&["--exclude", corpus.to_str().unwrap(), "--feedback", "-"]);
    let counts = String::from_utf8(counts.stdout).unwrap();
    assert!(!counts.contains("corpus"), "{counts}");
    let counts: serde_json::Value = serde_json::from_str(&counts).unwrap();
    assert_eq!(counts["excluded_by_user"], 1);

    // Known sign-in files are checked even inside a skipped folder, and the
    // home folder itself cannot be skipped.
    let aws = f.home().join(".aws");
    let r = f.json(&["--exclude", aws.to_str().unwrap()]);
    assert!(r["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["path"] == "~/.aws/credentials"));
    let out = f.run(&["--exclude", f.home().to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    let out = f.run(&["--exclude", f.0.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn fail_on_open_changes_only_the_exit_status_and_only_when_asked() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    // One medium finding, and a key with a passphrase, which is not for review.
    fs::create_dir(f.home().join(".docker")).unwrap();
    fs::write(
        f.home().join(".docker/config.json"),
        r#"{"auths":{"registry.example.invalid":{"auth":"c3ludGhldGljOm9ubHk="}}}"#,
    )
    .unwrap();
    fs::write(
        f.home().join("key.pem"),
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nsynthetic\n",
    )
    .unwrap();
    for name in [".docker/config.json", "key.pem"] {
        fs::set_permissions(f.home().join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(f.run(&[]).status.code(), Some(0));
    assert_eq!(f.run(&["--fail-on-open", "high"]).status.code(), Some(0));
    assert_eq!(f.run(&["--fail-on-open", "medium"]).status.code(), Some(3));
    assert_eq!(f.run(&["--fail-on-open", "low"]).status.code(), Some(3));
    assert_eq!(f.run(&["--fail-on-open", "urgent"]).status.code(), Some(2));
    // The counts explain the status: what is open at each level, without the
    // stored key that the totals by risk level also count.
    let gated = f.run(&["--feedback", "-", "--fail-on-open", "medium"]);
    assert_eq!(gated.status.code(), Some(3));
    let counts: serde_json::Value = serde_json::from_slice(&gated.stdout).unwrap();
    assert_eq!(
        counts["review"],
        serde_json::json!({
            "high": { "open": 0, "open_by_rule": {} },
            "medium": { "open": 1, "open_by_rule": { "dev.docker.inline-auth": 1 } },
            "low": { "open": 0, "open_by_rule": {} },
        })
    );
    let all: u64 = counts["findings_by_severity"]
        .as_object()
        .unwrap()
        .values()
        .map(|n| n.as_u64().unwrap())
        .sum();
    assert_eq!(all, 2);
    // The report is the same either way.
    let plain = f.json(&[]);
    let mut gated = f.json(&["--fail-on-open", "medium"]);
    gated["generated_at"] = plain["generated_at"].clone();
    assert_eq!(plain, gated);
}
