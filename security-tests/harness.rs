//! Test-only security harness. It is never built into either shipped scanner.
mod fixtures;
mod gates;
mod helper;
mod network;
mod platform;
mod reference;
mod synthetic_home;
mod validator;

use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, String>;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = dispatch(&args);
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("ERROR {error}");
            std::process::exit(2);
        }
    }
}

fn dispatch(args: &[String]) -> Result<i32> {
    match args.first().map(String::as_str) {
        None | Some("--self-tests") | Some("--nocapture") => {
            validator::self_tests()?;
            network::self_tests()?;
            gates::self_tests()?;
            helper::self_tests()?;
            println!("PASS: security harness regression tests");
            Ok(0)
        }
        Some("generate") => {
            fixtures::generate(
                &PathBuf::from(required(args, "--out")?),
                number(args, "--large-file-mib", 1024.)? as usize,
                number(args, "--bomb-mib", 256.)? as usize,
            )?;
            Ok(0)
        }
        Some("helper-check") => helper::run(args),
        Some("helper-self-tests") => {
            helper::self_tests()?;
            Ok(0)
        }
        Some("check") => check(args),
        Some("validate") => {
            let path = args.get(1).ok_or("missing report")?;
            let raw = fs::read(path).map_err(|_| "cannot read report")?;
            let manifest = option(args, "--manifest")
                .map(|p| load(Path::new(p)))
                .transpose()?;
            let errors = validator::validate(&raw, manifest.as_ref())?;
            for error in &errors {
                println!("INVALID {error}");
            }
            println!(
                "{}",
                if errors.is_empty() {
                    "VALID"
                } else {
                    "INVALID"
                }
            );
            Ok(i32::from(!errors.is_empty()))
        }
        Some("platform") => {
            platform::run(args)?;
            Ok(0)
        }
        Some("selftest") => reference::selftest(args),
        Some("generate-home") => {
            synthetic_home::generate(args)?;
            Ok(0)
        }
        Some("careful") | Some("naive") => reference::scan(args),
        _ => Err(
            "expected generate, generate-home, check, validate, platform, selftest or --self-tests"
                .into(),
        ),
    }
}

fn option<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|s| s == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}
fn required<'a>(args: &'a [String], name: &str) -> Result<&'a str> {
    option(args, name).ok_or_else(|| format!("missing {name}"))
}
fn number(args: &[String], name: &str, default: f64) -> Result<f64> {
    let value = option(args, name)
        .map(|s| s.parse::<f64>())
        .transpose()
        .map_err(|_| format!("bad {name}"))?
        .unwrap_or(default);
    if !value.is_finite() || value <= 0. {
        return Err(format!("bad {name}"));
    }
    Ok(value)
}
fn load(path: &Path) -> Result<Value> {
    serde_json::from_slice(&fs::read(path).map_err(|_| "cannot read harness JSON")?)
        .map_err(|_| "invalid harness JSON".into())
}
fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|e| e.to_string())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
}
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(data).map_err(|e| e.to_string())
}
fn save(path: &Path, value: &Value) -> Result<()> {
    write_private(
        path,
        &serde_json::to_vec_pretty(value).map_err(|_| "cannot encode harness evidence")?,
    )
}
fn random_hex() -> Result<String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| e.to_string())?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn scratch(name: &str) -> Result<PathBuf> {
    let base =
        std::env::var_os("TMPDIR").ok_or("TMPDIR must name a symlink-free scratch directory")?;
    let base = PathBuf::from(base);
    if fs::canonicalize(&base).map_err(|e| e.to_string())? != base {
        return Err("TMPDIR must have no symbolic link in its path".into());
    }
    let path = base.join(format!(
        "loose-keys-{name}-{}-{}",
        std::process::id(),
        random_hex()?
    ));
    fs::create_dir(&path).map_err(|e| e.to_string())?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    Ok(path)
}
fn files_under(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for item in fs::read_dir(path).map_err(|e| e.to_string())? {
        let path = item.map_err(|e| e.to_string())?.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if meta.is_dir() {
            files_under(&path, out)?;
        } else if meta.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

pub(crate) struct Captured {
    pub status: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub rss_mib: f64,
}

fn run_capture(command: &mut Command, work: &Path, timeout: Duration) -> Result<Captured> {
    let stdout = work.join(format!("stdout-{}", random_hex()?));
    let stderr = work.join(format!("stderr-{}", random_hex()?));
    command.stdout(Stdio::from(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stdout)
            .map_err(|e| e.to_string())?,
    ));
    command.stderr(Stdio::from(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stderr)
            .map_err(|e| e.to_string())?,
    ));
    command.process_group(0);
    let mut child = command
        .spawn()
        .map_err(|e| format!("could not be run ({e})"))?;
    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            // SAFETY: the child was started in its own process group; its live pid identifies that group.
            unsafe {
                libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
            }
            break child.wait().map_err(|e| e.to_string())?;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // SAFETY: zeroed rusage is valid storage and getrusage fills it for this process's children.
    let rss = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage) == 0 {
            usage.ru_maxrss as f64
        } else {
            return Err("cannot measure child RSS".into());
        }
    };
    let output = Captured {
        status: status.code(),
        signal: status.signal(),
        timed_out,
        stdout: fs::read(&stdout).map_err(|e| e.to_string())?,
        stderr: fs::read(&stderr).map_err(|e| e.to_string())?,
        rss_mib: rss / 1048576.,
    };
    fs::remove_file(stdout).map_err(|e| e.to_string())?;
    fs::remove_file(stderr).map_err(|e| e.to_string())?;
    Ok(output)
}

fn record(
    results: &mut Vec<Value>,
    check: &str,
    problems: Vec<String>,
    ok: &str,
    status: Option<&str>,
) {
    results.push(json!({"check":check,"status":status.unwrap_or(if problems.is_empty(){"pass"}else{"fail"}),
        "detail":if problems.is_empty(){ok.to_owned()}else{problems.into_iter().take(6).collect::<Vec<_>>().join("; ")}}));
}
fn contains(data: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && data.windows(needle.len()).any(|s| s == needle)
}

fn check(args: &[String]) -> Result<i32> {
    let fx = fs::canonicalize(required(args, "--fixtures")?).map_err(|e| e.to_string())?;
    let manifest = load(&fx.join("manifest.json"))?;
    let lay = &manifest["layout"];
    let path = |name: &str| -> Result<PathBuf> {
        lay[name]
            .as_str()
            .map(PathBuf::from)
            .ok_or_else(|| format!("missing fixture layout {name}"))
    };
    let trees = vec![path("scan_root")?, path("outside")?];
    let before = load(&fx.join("snapshot.json"))?;
    if before != fixtures::snapshot(&trees)?
        || fs::read_dir(path("sentinels")?)
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
    {
        return Err("fixtures were modified by an earlier run; regenerate them".into());
    }
    let run = fx.join("runs").join(format!("run-{}", random_hex()?));
    let artifacts = run.join("artifacts");
    let tmp = run.join("tmp");
    let capture = run.join("captured");
    for p in [&artifacts, &tmp, &capture] {
        private_dir(p)?;
    }
    let report = artifacts.join("report.json");
    let symlink_mode = option(args, "--report-mode") == Some("symlink");
    if symlink_mode {
        std::os::unix::fs::symlink(path("outside")?.join("clobber-target.txt"), &report)
            .map_err(|e| e.to_string())?;
    }
    let command_start = args
        .iter()
        .position(|s| s == "--")
        .ok_or("missing scanner command after --")?
        + 1;
    let home = path("home")?;
    let argv: Vec<String> = args[command_start..]
        .iter()
        .map(|a| {
            a.replace("{home}", &home.to_string_lossy())
                .replace("{projects}", &home.join("Projects").to_string_lossy())
                .replace("{report}", &report.to_string_lossy())
        })
        .collect();
    if argv.is_empty() {
        return Err("missing scanner command".into());
    }
    let tag = format!("LOOSE-KEYS-NET-{}", random_hex()?);
    let mut command = Command::new("sandbox-exec");
    command.args(["-p",&format!("(version 1)(allow default)(deny network* (with send-signal SIGKILL) (with message \"{tag}\"))(allow network-outbound (literal \"/private/var/run/syslog\"))")]);
    command.arg(&argv[0]);
    command
        .args(&argv[1..])
        .env("HOME", &home)
        .env("TMPDIR", &tmp)
        .env(
            "PATH",
            format!(
                "{}:{}",
                path("bin_hijack")?.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .current_dir(&run);
    let since = network::log_start()?;
    let started = Instant::now();
    let output = run_capture(
        &mut command,
        &capture,
        Duration::from_secs_f64(number(args, "--timeout", 300.)?),
    )?;
    write_private(&capture.join("stdout"), &output.stdout)?;
    write_private(&capture.join("stderr"), &output.stderr)?;
    let mut results = vec![];
    let mut health = vec![];
    let allowed: Vec<i32> = option(args, "--allowed-exit")
        .unwrap_or("0")
        .split(',')
        .map(|s| s.parse().map_err(|_| "bad allowed exit"))
        .collect::<std::result::Result<_, _>>()?;
    if output.timed_out {
        health.push("timed out".into());
    } else if let Some(signal) = output.signal {
        health.push(format!("killed by signal {signal}"));
    } else if !allowed.contains(&output.status.unwrap_or(-1)) {
        health.push(format!("unexpected exit {:?}", output.status));
    }
    if output.rss_mib > number(args, "--max-rss-mib", 1024.)? {
        health.push("peak RSS over budget".into());
    }
    record(
        &mut results,
        "health",
        health,
        &format!(
            "exit {:?} in {:.1}s, peak RSS {:.0} MiB",
            output.status,
            started.elapsed().as_secs_f64(),
            output.rss_mib
        ),
        None,
    );
    let kept = run.join("network-log");
    let behind = network::caught_up(&kept, Duration::from_secs(120), None, None)?;
    let (mut status, mut problems) = network::check(&tag, &since, &kept, None)?;
    if status == "pass" {
        if let Some(reason) = behind {
            status = "inconclusive".into();
            problems = vec![format!("network attempts cannot be ruled out: {reason}")];
        }
    }
    record(
        &mut results,
        "network",
        problems,
        "no network attempts",
        Some(&status),
    );
    let fired = fs::read_dir(path("sentinels")?)
        .map_err(|e| e.to_string())?
        .map(|e| {
            e.map(|e| format!("probe fired: {}", e.file_name().to_string_lossy()))
                .map_err(|e| e.to_string())
        })
        .collect::<Result<Vec<_>>>()?;
    record(&mut results, "execution", fired, "no probe fired", None);
    let after = fixtures::snapshot(&trees)?;
    record(
        &mut results,
        "tree",
        if after == before {
            vec![]
        } else {
            vec!["scanned or outside tree changed".into()]
        },
        "unchanged",
        None,
    );
    let mut outputs = vec![];
    for p in [&artifacts, &tmp, &capture] {
        files_under(p, &mut outputs)?;
    }
    let strings = |name: &str| -> Result<Vec<&str>> {
        manifest["forbidden"][name]
            .as_array()
            .ok_or("missing forbidden list")?
            .iter()
            .map(|v| v.as_str().ok_or_else(|| "bad forbidden string".into()))
            .collect()
    };
    let secrets = strings("secrets")?;
    let fragment_sources = strings("fragment_sources")?;
    let scope_tokens = strings("scope_tokens")?;
    let win = manifest["forbidden"]["fragment_window"]
        .as_u64()
        .ok_or("bad fragment window")? as usize;
    if win == 0 {
        return Err("bad fragment window".into());
    }
    let mut leak = vec![];
    let mut scope = vec![];
    let mut encoding = vec![];
    let mut loose = vec![];
    for file in &outputs {
        let data = fs::read(file).map_err(|e| e.to_string())?;
        let name = file
            .strip_prefix(&run)
            .map_err(|e| e.to_string())?
            .display()
            .to_string();
        if secrets.iter().any(|s| contains(&data, s.as_bytes()))
            || fragment_sources
                .iter()
                .any(|s| s.as_bytes().windows(win).any(|w| contains(&data, w)))
        {
            leak.push(format!("secret or fragment in {name}"));
        }
        if scope_tokens.iter().any(|s| contains(&data, s.as_bytes())) {
            scope.push(format!("out-of-scope token in {name}"));
        }
        if data.iter().any(|b| matches!(b,0..=8|11|12|14..=31|127))
            || data.windows(3).any(|w| {
                w[0] == 0xe2
                    && ((w[1] == 0x80 && (0xaa..=0xae).contains(&w[2]))
                        || (w[1] == 0x81 && (0xa6..=0xa9).contains(&w[2])))
            })
        {
            encoding.push(format!("raw control/bidi character in {name}"));
        }
        if let Some(forged) = manifest["forged_line_token"].as_str() {
            if !forged.is_empty()
                && data.split(|b| *b == b'\n').any(|line| {
                    line.iter()
                        .copied()
                        .skip_while(u8::is_ascii_whitespace)
                        .collect::<Vec<_>>()
                        .starts_with(forged.as_bytes())
                })
            {
                encoding.push(format!("forged line in {name}"));
            }
        }
        if file.starts_with(&artifacts)
            && fs::symlink_metadata(file)
                .map_err(|e| e.to_string())?
                .permissions()
                .mode()
                & 0o077
                != 0
        {
            loose.push(format!("export permissions in {name}"));
        }
    }
    record(
        &mut results,
        "leak",
        leak,
        &format!("none in {} outputs", outputs.len()),
        None,
    );
    record(&mut results, "scope", scope, "nothing out of scope", None);
    record(&mut results, "encoding", encoding, "escaped", None);
    record(
        &mut results,
        "permissions",
        loose,
        "exports are owner-only",
        None,
    );
    if args.iter().any(|s| s == "--validate-report") {
        let meta = fs::symlink_metadata(&report).ok();
        let problems = if meta.is_some_and(|m| m.is_file()) {
            validator::validate(
                &fs::read(&report).map_err(|e| e.to_string())?,
                Some(&manifest),
            )?
        } else if symlink_mode {
            vec![]
        } else {
            vec!["no report written".into()]
        };
        record(
            &mut results,
            "schema",
            problems,
            "valid or export refused",
            None,
        );
    }
    save(
        &run.join("results.json"),
        &json!({"argv":argv,"exit_code":output.status.unwrap_or(-output.signal.unwrap_or(1)),"results":results}),
    )?;
    for r in &results {
        println!(
            "{:<12} {:<11} {}",
            r["status"].as_str().unwrap_or("").to_uppercase(),
            r["check"].as_str().unwrap_or(""),
            r["detail"].as_str().unwrap_or("")
        );
    }
    println!("results: {}", run.join("results.json").display());
    Ok(i32::from(results.iter().any(|r| {
        r["status"] == "fail" || r["status"] == "inconclusive"
    })))
}
