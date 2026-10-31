//! Independent safe reference and deliberately unsafe scanners, test-only.
use super::*;
use std::os::unix::fs::OpenOptionsExt;

fn walk(path: &Path, follow: bool, depth: usize, files: &mut Vec<PathBuf>) -> Result<()> {
    if depth > 4 {
        return Ok(());
    }
    for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        let meta = if follow {
            fs::metadata(&path)
        } else {
            fs::symlink_metadata(&path)
        }
        .map_err(|e| e.to_string())?;
        if meta.is_dir() {
            if path.file_name().is_some_and(|n| n == ".git") {
                continue;
            }
            walk(&path, follow, depth + 1, files)?;
        } else if follow || meta.is_file() {
            files.push(path);
        }
    }
    Ok(())
}
fn head(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "reference read refused")?;
    if !file
        .metadata()
        .map_err(|_| "reference metadata failed")?
        .is_file()
    {
        return Err("reference refused special file".into());
    }
    let mut bytes = vec![];
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| "reference read failed")?;
    Ok(bytes)
}
fn finding(rule: &str, path: &Path, home: &Path, kind: &str, category: &str) -> Result<Value> {
    let relative = path
        .strip_prefix(home)
        .map_err(|_| "reference path escaped synthetic home")?;
    let mut f = json!({"rule":rule,"category":category,"kind":kind,"title":"Synthetic reference finding","explanation":"Independent security harness reference scanner","path":format!("~/{}",relative.display())});
    if kind == "review" {
        f["reason"] = json!("Synthetic material requires review");
    }
    Ok(f)
}
pub(crate) fn scan(args: &[String]) -> Result<i32> {
    let home = PathBuf::from(args.get(1).ok_or("missing synthetic home")?);
    let report_path = PathBuf::from(args.get(2).ok_or("missing reference report")?);
    if args[0] == "naive" {
        return naive(
            &home,
            &report_path,
            args.iter().any(|s| s == "--open-fifos"),
        );
    }
    let mut files = vec![];
    walk(&home, false, 0, &mut files)?;
    let mut findings = vec![];
    for path in files {
        let rel = path
            .strip_prefix(&home)
            .map_err(|_| "reference path outside home")?
            .to_string_lossy();
        if rel.starts_with("Downloads/") {
            let data = head(&path, 4096)?;
            let first = String::from_utf8_lossy(&data)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_lowercase();
            if first == "name,url,username,password" {
                findings.push(finding(
                    "export.browser-csv",
                    &path,
                    &home,
                    "review",
                    "password-export",
                )?);
            }
        } else if rel == ".aws/credentials" || rel == ".aws/config" {
            let data = head(&path, 65536)?;
            let text = String::from_utf8_lossy(&data);
            let mut section_line = 0;
            let mut found = false;
            for (index, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.starts_with('[') && line.ends_with(']') {
                    section_line = index + 1;
                    found = false;
                } else if !found
                    && section_line > 0
                    && line.split('=').next().is_some_and(|key| {
                        key.trim()
                            == if rel == ".aws/config" {
                                "credential_process"
                            } else {
                                "aws_secret_access_key"
                            }
                    })
                {
                    let rule = if rel == ".aws/config" {
                        "dev.aws.credential-process"
                    } else {
                        "dev.aws.inline-credentials"
                    };
                    let mut f = finding(rule, &path, &home, "inventory", "developer-cloud")?;
                    f["line"] = json!(section_line);
                    findings.push(f);
                    found = true;
                }
            }
        } else if rel == ".kube/config" {
            let data = head(&path, 65536)?;
            if let Some((index, _)) = String::from_utf8_lossy(&data)
                .lines()
                .enumerate()
                .find(|(_, line)| line.trim() == "exec:")
            {
                let mut f = finding(
                    "dev.kube.exec-plugin",
                    &path,
                    &home,
                    "inventory",
                    "developer-cloud",
                )?;
                f["line"] = json!(index + 1);
                findings.push(f);
            }
        } else if rel == ".docker/config.json" {
            let data = head(&path, 262144)?;
            let config: Value =
                serde_json::from_slice(&data).map_err(|_| "invalid reference docker fixture")?;
            if config["auths"].as_object().is_some_and(|a| {
                a.values()
                    .any(|v| v["auth"].as_str().is_some_and(|s| !s.is_empty()))
            }) {
                findings.push(finding(
                    "dev.docker.inline-auth",
                    &path,
                    &home,
                    "review",
                    "developer-cloud",
                )?);
            }
        } else if rel.starts_with(".ssh/") && !rel.ends_with(".pub") {
            let data = head(&path, 512)?;
            if contains(&data, b"PRIVATE KEY-----") {
                let protected = ssh_protected(&data).unwrap_or(true);
                findings.push(finding(
                    "key.ssh.private",
                    &path,
                    &home,
                    if protected { "inventory" } else { "review" },
                    "private-key",
                )?);
            }
        }
    }
    let report = json!({"schema":"loose-keys/report/1","tool_version":"0.0.0-selftest","generated_at":"2026-01-01T00:00:00Z","status":"complete","context":"user","findings":findings,"not_checked":[]});
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&report_path);
    let mut file = match file {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            eprintln!("refusing to export: destination already exists (possibly a symlink)");
            return Ok(3);
        }
        Err(_) => return Err("reference export failed".into()),
    };
    file.write_all(&ascii_json(&report)?)
        .map_err(|_| "reference export failed")?;
    println!("status=complete findings={}", findings.len());
    if args.iter().any(|s| s == "--partial-redaction") {
        let data = head(&home.join(".aws/credentials"), 65536)?;
        for line in String::from_utf8_lossy(&data).lines() {
            if line.starts_with("aws_secret_access_key") {
                if let Some((_, value)) = line.split_once('=') {
                    println!(
                        "aws secret: {}****",
                        value.trim().chars().take(12).collect::<String>()
                    );
                }
            }
        }
    }
    Ok(0)
}

fn ssh_protected(data: &[u8]) -> Option<bool> {
    let encoded: Vec<u8> = data
        .split(|b| *b == b'\n')
        .skip(1)
        .filter(|line| !line.starts_with(b"-----"))
        .flatten()
        .copied()
        .collect();
    let mut decoded = Vec::new();
    for chunk in encoded.as_chunks::<4>().0 {
        let mut value = 0u32;
        let mut padding = 0;
        for byte in chunk {
            let digit = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => {
                    padding += 1;
                    0
                }
                _ => return None,
            };
            value = (value << 6) | u32::from(digit);
        }
        decoded.push(((value >> 16) & 0xff) as u8);
        if padding < 2 {
            decoded.push(((value >> 8) & 0xff) as u8);
        }
        if padding < 1 {
            decoded.push((value & 0xff) as u8);
        }
    }
    if !decoded.starts_with(b"openssh-key-v1\0") {
        return None;
    }
    let size = u32::from_be_bytes(decoded.get(15..19)?.try_into().ok()?) as usize;
    Some(decoded.get(19..19usize.checked_add(size)?)? != b"none")
}
pub(crate) fn ascii_json(value: &Value) -> Result<Vec<u8>> {
    let json = serde_json::to_string_pretty(value).map_err(|_| "cannot encode reference report")?;
    let mut out = String::new();
    for c in json.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    Ok(out.into_bytes())
}
fn naive(home: &Path, report: &Path, open_fifos: bool) -> Result<i32> {
    let _ = Command::new("/usr/bin/nc")
        .args(["-z", "-w", "1", "k8s.invalid", "443"])
        .env("HOME", home)
        .status();
    let _ = Command::new("sh")
        .args(["-c", "git --version"])
        .env("HOME", home)
        .output();
    let config =
        fs::read_to_string(home.join(".aws/config")).map_err(|_| "naive config unavailable")?;
    for line in config.lines() {
        if let Some(command) = line.strip_prefix("credential_process = ") {
            let _ = Command::new("sh")
                .args(["-c", command])
                .env("HOME", home)
                .output();
        }
    }
    let mut files = vec![];
    walk(home, true, 0, &mut files)?;
    let mut found = vec![];
    for path in files {
        let meta = fs::metadata(&path).map_err(|_| "naive metadata unavailable")?;
        if (!meta.is_file() && !open_fifos) || (meta.is_file() && meta.len() > 16 * 1024 * 1024) {
            continue;
        }
        if let Ok(data) = fs::read(&path) {
            for line in String::from_utf8_lossy(&data).lines() {
                let lower = line.to_lowercase();
                if ["password", "secret", "token", "bearer", "auth"]
                    .iter()
                    .any(|key| lower.contains(key))
                {
                    println!("{}: {}", path.display(), line.trim());
                    found.push(path.clone());
                }
            }
        }
    }
    if let Ok(file) = File::open(home.join("Downloads/passwords-export.zip")) {
        if let Ok(mut archive) = zip::ZipArchive::new(file) {
            for i in 0..archive.len() {
                if let Ok(member) = archive.by_index(i) {
                    if let Ok(name) = member.name() {
                        println!("archive member: {name}");
                    }
                }
            }
        }
    }
    fs::write(
        report,
        serde_json::to_vec(&json!({"findings":found})).map_err(|_| "encode naive report")?,
    )
    .map_err(|_| "naive export failed")?;
    fs::set_permissions(report, fs::Permissions::from_mode(0o644))
        .map_err(|_| "naive permissions failed")?;
    let mut csv = File::create(
        report
            .parent()
            .ok_or("naive missing report parent")?
            .join("findings.csv"),
    )
    .map_err(|_| "naive CSV failed")?;
    for path in found {
        writeln!(
            csv,
            "{}",
            path.file_name()
                .ok_or("naive missing filename")?
                .to_string_lossy()
        )
        .map_err(|_| "naive CSV failed")?;
    }
    println!("done");
    Ok(0)
}

pub(crate) fn selftest(args: &[String]) -> Result<i32> {
    let work = PathBuf::from(required(args, "--work")?);
    private_dir(&work)?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    type Scenario<'a> = (
        &'a str,
        &'a str,
        &'a [&'a str],
        &'a [&'a str],
        &'a [&'a str],
    );
    let scenarios: [Scenario<'_>; 7] = [
        ("careful-fresh", "careful", &["--validate-report"], &[], &[]),
        (
            "careful-symlink-report",
            "careful",
            &[
                "--report-mode",
                "symlink",
                "--allowed-exit",
                "3",
                "--validate-report",
            ],
            &[],
            &[],
        ),
        (
            "naive-fresh",
            "naive",
            &[],
            &[],
            &[
                "leak",
                "execution",
                "scope",
                "encoding",
                "permissions",
                "network",
            ],
        ),
        (
            "naive-report-format",
            "naive",
            &["--validate-report"],
            &[],
            &["schema", "network"],
        ),
        (
            "naive-symlink-report",
            "naive",
            &["--report-mode", "symlink"],
            &[],
            &["tree", "network"],
        ),
        (
            "naive-fifo-hang",
            "naive",
            &["--timeout", "20"],
            &["--open-fifos"],
            &["health", "network"],
        ),
        (
            "careful-partial-redaction",
            "careful",
            &[],
            &["--partial-redaction"],
            &["leak"],
        ),
    ];
    let mut problems = vec![];
    for (name, scanner, hargs, sargs, expected) in scenarios {
        let fx = work.join(name);
        fixtures::generate(&fx, 64, 16)?;
        let mut command = Command::new(&exe);
        command
            .args(["check", "--fixtures"])
            .arg(&fx)
            .args(hargs)
            .arg("--")
            .arg(&exe)
            .args([scanner, "{home}", "{report}"])
            .args(sargs);
        let captured = run_capture(&mut command, &work, Duration::from_secs(420))?;
        let run = fs::read_dir(fx.join("runs"))
            .map_err(|e| e.to_string())?
            .next()
            .ok_or("selftest missing run")?
            .map_err(|e| e.to_string())?
            .path();
        let results = load(&run.join("results.json"))?;
        let checks = results["results"]
            .as_array()
            .ok_or("selftest missing results")?;
        let failed: Vec<&str> = checks
            .iter()
            .filter(|r| r["status"] == "fail")
            .filter_map(|r| r["check"].as_str())
            .collect();
        let unsure: Vec<&str> = checks
            .iter()
            .filter(|r| r["status"] == "inconclusive")
            .filter_map(|r| r["check"].as_str())
            .collect();
        println!(
            "== {name} (harness exit {:?}) failed={failed:?} inconclusive={unsure:?}",
            captured.status
        );
        if expected.is_empty()
            && (captured.status != Some(0) || !failed.is_empty() || !unsure.is_empty())
        {
            problems.push(format!("{name}: expected every check to pass"));
        }
        for check in expected {
            if !failed.contains(check) {
                problems.push(format!("{name}: harness did NOT catch {check}"));
                if *check == "network" {
                    explain_network_miss(&run)?;
                }
            }
        }
        if !expected.is_empty() && captured.status == Some(0) {
            problems.push(format!("{name}: unsafe scanner passed"));
        }
    }
    validator::self_tests()?;
    network::integration_self_tests(&work)?;
    if !problems.is_empty() {
        for problem in problems {
            println!("SELFTEST FAILED: {problem}");
        }
        return Ok(1);
    }
    println!("SELFTEST PASSED: 7 harness scenarios, 5 validator mutations");
    Ok(0)
}
fn explain_network_miss(run: &Path) -> Result<()> {
    let kept = run.join("network-log");
    println!("network miss evidence kept in {}", kept.display());
    let query = load(&kept.join("query.json"))?;
    println!(
        "network query status={}, entries={}, denials={}",
        query["tagged"]["exit_status"], query["entries_with_tag"], query["denials_with_tag"]
    );
    std::thread::sleep(Duration::from_secs(10));
    let (status, problems) = network::check(
        query["tag"].as_str().ok_or("missing tag")?,
        query["since"].as_str().ok_or("missing query time")?,
        &kept.join("late"),
        None,
    )?;
    println!(
        "network miss, 10 seconds later: {status}; {}",
        problems.join("; ")
    );
    Ok(())
}
