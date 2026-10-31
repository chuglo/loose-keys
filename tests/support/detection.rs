//! Shared, independent expected results for the CLI process and GUI dispatcher.
//! Fixture contents and reports are never printed, including on failure.
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::fixture_body::Body;

/// One entry in `tests/detection-corpus.json`. `rule`, `kind`, `severity` and
/// `target` select exactly one registered implementation; several cases may
/// cover one. `path` is relative to the synthetic home, with normal components
/// only. `negative_path` puts the negative control at a similar location the
/// rule does not support. A case expects one finding at `~/` plus `path`; an
/// omitted `line` or `token_type` must be absent from it. `extra` lists further
/// expected findings; repeat a row to expect that finding more than once.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub name: String,
    rule: String,
    kind: String,
    severity: String,
    target: String,
    path: String,
    positive: Body,
    negative: Body,
    negative_path: Option<String>,
    line: Option<usize>,
    token_type: Option<String>,
    #[serde(default)]
    extra: Vec<Expected>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct Expected {
    rule: String,
    path: String,
    kind: String,
    severity: String,
    line: Option<usize>,
    token_type: Option<String>,
}

pub fn cases() -> Vec<Case> {
    let cases: Vec<Case> = serde_json::from_str(include_str!("../detection-corpus.json"))
        .expect("invalid detection manifest");
    let mut names = std::collections::BTreeSet::new();
    for case in &cases {
        assert!(case
            .name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-'));
        assert!(
            !case.name.is_empty() && names.insert(&case.name),
            "duplicate case name"
        );
        assert!(!case.target.is_empty(), "missing target for {}", case.name);
        for path in [
            &case.path,
            case.negative_path.as_ref().unwrap_or(&case.path),
        ] {
            assert!(
                !path.is_empty()
                    && Path::new(path)
                        .components()
                        .all(|c| matches!(c, Component::Normal(_))),
                "fixture path must stay under synthetic home"
            );
        }
    }
    assert!(!cases.is_empty(), "empty detection manifest");
    cases
}

impl Body {
    fn write(&self, path: &Path) {
        let Some(bytes) = self.bytes() else {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)
                .unwrap();
            return;
        };
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path.parent().unwrap())
            .unwrap();
        use std::io::Write;
        private_file(path).write_all(&bytes).unwrap();
    }
}

fn private_file(path: &Path) -> File {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
}

pub struct Fixture {
    pub root: PathBuf,
    pub home: PathBuf,
}

impl Fixture {
    pub fn new(case: &Case, positive: bool) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let base =
            PathBuf::from(std::env::var_os("TMPDIR").expect("set TMPDIR to a real scratch folder"));
        assert_eq!(
            fs::canonicalize(&base).unwrap(),
            base,
            "TMPDIR must have no symlinks"
        );
        let root = base.join(format!(
            "credential-detection-{}-{}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
            case.name,
            if positive { "positive" } else { "negative" }
        ));
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        let home = root.join("home");
        DirBuilder::new().mode(0o700).create(&home).unwrap();
        let (path, body) = if positive {
            (&case.path, &case.positive)
        } else {
            (
                case.negative_path.as_ref().unwrap_or(&case.path),
                &case.negative,
            )
        };
        body.write(&home.join(path));
        Self { root, home }
    }

    pub fn cli(&self, binary: &Path, case: &Case, positive: bool) -> Value {
        let stdout = self.root.join("cli.stdout");
        let stderr = self.root.join("cli.stderr");
        let mut child = Command::new(binary)
            .env("HOME", &self.home)
            .args(["scan", "--export", "-"])
            .stdin(Stdio::null())
            .stdout(private_file(&stdout))
            .stderr(private_file(&stderr))
            .spawn()
            .expect("could not start fixture CLI");
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("CLI timed out for {}", case.name);
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(
            status.code(),
            Some(0),
            "CLI exit for {} ({positive})",
            case.name
        );
        assert_no_values(&fs::read(&stderr).unwrap());
        case.check(&fs::read(&stdout).unwrap(), positive)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("synthetic detection home cleanup failed");
    }
}

pub fn assert_no_values(bytes: &[u8]) {
    // Values used by this corpus, including interior fragments. Add a new
    // case's secret markers here. Never print a rejected value or the output
    // that contained it.
    for value in [
        "synthetic-only-value",
        "synthetic,first-value",
        "synthetic-second-value",
        "synthetic-access-id",
        "c3ludGhldGlj",
        "0123456789abcdefghijABCDEFGHIJ012345",
    ] {
        for fragment in value.as_bytes().windows(10) {
            assert!(
                !bytes.windows(fragment.len()).any(|w| w == fragment),
                "fixture value or fragment exposed"
            );
        }
    }
    for start in [
        "velvet winner thank year wave sausage ",
        "legal winner thank year wave sausage ",
        "letter advice cage absurd amount doctor ",
    ] {
        assert!(
            !bytes.windows(start.len()).any(|w| w == start.as_bytes()),
            "fixture phrase exposed"
        );
    }
}

impl Case {
    pub fn check(&self, bytes: &[u8], positive: bool) -> Value {
        assert_no_values(bytes);
        assert!(bytes.is_ascii(), "report must be ASCII for {}", self.name);
        let report: Value = serde_json::from_slice(bytes).expect("invalid corpus report JSON");
        assert_eq!(report["schema"], "loose-keys/report/1");
        assert_eq!(
            report["status"], "complete",
            "unexpected gap in {} ({positive})",
            self.name
        );
        assert_eq!(
            report["not_checked"],
            json!([]),
            "unexpected gaps in {}",
            self.name
        );
        assert_eq!(report["coverage"]["roots"], json!(["~/"]));
        let actual: Vec<Expected> = report["findings"]
            .as_array()
            .expect("findings array")
            .iter()
            .map(|finding| Expected {
                rule: finding["rule"].as_str().expect("rule").to_owned(),
                path: finding["path"].as_str().expect("path").to_owned(),
                kind: finding["kind"].as_str().expect("kind").to_owned(),
                severity: finding["severity"].as_str().expect("severity").to_owned(),
                line: finding
                    .get("line")
                    .map(|v| usize::try_from(v.as_u64().expect("line")).expect("line")),
                token_type: finding
                    .get("token_type")
                    .map(|v| v.as_str().expect("token_type").to_owned()),
            })
            .collect();
        assert!(
            self.matches(&actual, positive),
            "wrong findings for {} ({positive}): {actual:?}",
            self.name
        );
        report
    }

    fn matches(&self, actual: &[Expected], positive: bool) -> bool {
        let mut expected = if positive {
            let mut expected = self.extra.clone();
            expected.push(Expected {
                rule: self.rule.clone(),
                path: format!("~/{}", self.path),
                kind: self.kind.clone(),
                severity: self.severity.clone(),
                line: self.line,
                token_type: self.token_type.clone(),
            });
            expected
        } else {
            Vec::new()
        };
        let mut actual = actual.to_vec();
        expected.sort();
        actual.sort();
        actual == expected
    }
}

pub fn compare_reports(mut cli: Value, mut engine: Value, name: &str) {
    for report in [&mut cli, &mut engine] {
        report.as_object_mut().unwrap().remove("generated_at");
        report["findings"]
            .as_array_mut()
            .unwrap()
            .sort_by_key(Value::to_string);
    }
    assert!(cli == engine, "CLI and engine exports differ for {name}");
}

#[test]
fn oracle_rejects_missing_extra_duplicate_and_misclassified_findings() {
    let case = &cases()[0];
    let expected = Expected {
        rule: case.rule.clone(),
        path: format!("~/{}", case.path),
        kind: case.kind.clone(),
        severity: case.severity.clone(),
        line: case.line,
        token_type: case.token_type.clone(),
    };
    assert!(case.matches(std::slice::from_ref(&expected), true));
    assert!(!case.matches(&[], true));
    assert!(!case.matches(&[expected.clone(), expected.clone()], true));
    assert!(!case.matches(std::slice::from_ref(&expected), false));
    for field in ["rule", "path", "kind", "severity", "line", "token_type"] {
        let mut wrong = expected.clone();
        match field {
            "rule" => wrong.rule = "other.rule".into(),
            "path" => wrong.path = "~/elsewhere".into(),
            "kind" => wrong.kind = "inventory".into(),
            "severity" => wrong.severity = "low".into(),
            "line" => wrong.line = Some(42),
            "token_type" => wrong.token_type = Some("unexpected".into()),
            _ => unreachable!(),
        }
        assert!(!case.matches(&[wrong], true), "oracle ignored {field}");
    }
    // Comparison removes only timestamp and finding order, not other report fields.
    let a = json!({"generated_at":"first", "findings":[], "status":"complete"});
    let b = json!({"generated_at":"second", "findings":[], "status":"complete"});
    compare_reports(a, b, "oracle-control");
}
