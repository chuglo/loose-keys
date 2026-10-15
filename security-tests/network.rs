//! macOS unified-log checks, including the deliberate denial barrier.
use super::*;

const LOG_TIMEOUT: u64 = 120;
const EVIDENCE_LIMIT: usize = 4 * 1024 * 1024;

pub(crate) fn log_start() -> Result<String> {
    timestamp(-60, "%Y-%m-%d %H:%M:%S")
}

fn timestamp(offset: i64, format: &str) -> Result<String> {
    let format = std::ffi::CString::new(format).map_err(|_| "invalid time format")?;
    let mut buffer = [0u8; 128];
    // SAFETY: time writes no pointer, localtime_r receives valid time and tm storage,
    // and strftime receives a writable buffer with its actual size and a terminated format.
    let count = unsafe {
        let now = libc::time(std::ptr::null_mut()) + offset as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() {
            return Err("cannot read local time".into());
        }
        libc::strftime(
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            format.as_ptr(),
            &tm,
        )
    };
    if count == 0 {
        return Err("cannot format local time".into());
    }
    String::from_utf8(buffer[..count].to_vec()).map_err(|_| "invalid formatted time".into())
}

fn log_show(since: &str, predicate: &str, info: bool, work: &Path, tool: Option<&Path>) -> Value {
    let mut argv = vec!["show".into(), "--style".into(), "json".into()];
    if info {
        argv.push("--info".into());
    }
    argv.extend([
        "--start".into(),
        since.into(),
        "--predicate".into(),
        predicate.into(),
    ]);
    let executable = tool.unwrap_or_else(|| Path::new("log"));
    let result = run_capture(
        Command::new(executable).args(&argv),
        work,
        Duration::from_secs(LOG_TIMEOUT),
    );
    let mut full = vec![executable.to_string_lossy().into_owned()];
    full.extend(argv);
    match result {
        Ok(out) => {
            json!({"argv":full,"exit_status":out.status,"error":if out.timed_out {Some(format!("did not finish in {LOG_TIMEOUT}s"))} else {None},"stdout":String::from_utf8_lossy(&out.stdout),"stderr":String::from_utf8_lossy(&out.stderr)})
        }
        Err(error) => json!({"argv":full,"exit_status":null,"error":error,"stdout":"","stderr":""}),
    }
}

fn entries(query: &Value) -> (Option<Vec<Value>>, Option<String>) {
    let parsed = serde_json::from_str::<Value>(query["stdout"].as_str().unwrap_or(""))
        .ok()
        .and_then(|v| v.as_array().cloned());
    let error = if let Some(error) = query["error"].as_str() {
        Some(format!("`log show` {error}"))
    } else if query["exit_status"] != 0 {
        Some(format!(
            "`log show` exited {}: {}",
            query["exit_status"],
            query["stderr"]
                .as_str()
                .unwrap_or("")
                .lines()
                .next()
                .unwrap_or("no message")
                .chars()
                .take(200)
                .collect::<String>()
        ))
    } else if parsed.is_none() {
        Some(format!(
            "`log show` printed {} instead of a JSON list",
            if query["stdout"].as_str().unwrap_or("").trim().is_empty() {
                "nothing"
            } else {
                "something"
            }
        ))
    } else {
        None
    };
    (parsed, error)
}
fn denials(entries: Option<&[Value]>, tag: &str) -> Vec<String> {
    entries
        .unwrap_or(&[])
        .iter()
        .filter_map(|e| e["eventMessage"].as_str())
        .filter(|m| m.contains("deny"))
        .map(|m| m.replace(tag, "").trim().to_owned())
        .collect()
}
fn marker_denial(marker: &str, work: &Path) {
    let _ = run_capture(
        Command::new("sandbox-exec").args([
            "-p",
            &format!("(version 1)(allow default)(deny network* (with message \"{marker}\"))"),
            "/usr/bin/nc",
            "-z",
            "-w",
            "1",
            "marker.invalid",
            "9",
        ]),
        work,
        Duration::from_secs(30),
    );
}

pub(crate) fn caught_up(
    evidence: &Path,
    timeout: Duration,
    tool: Option<&Path>,
    fixed_marker: Option<&str>,
) -> Result<Option<String>> {
    private_dir(evidence)?;
    let marker = fixed_marker
        .map(str::to_owned)
        .unwrap_or(format!("CREDHYG-MARK-{}", random_hex()?));
    let since = log_start()?;
    let made_at = timestamp(0, "%Y-%m-%dT%H:%M:%S")?;
    let started = Instant::now();
    if fixed_marker.is_none() {
        marker_denial(&marker, evidence);
    }
    let mut queries = 0;
    let (last, parsed, reason) = loop {
        let query = log_show(
            &since,
            &format!("eventMessage CONTAINS \"{marker}\""),
            false,
            evidence,
            tool,
        );
        queries += 1;
        let (parsed, reason) = entries(&query);
        if reason.is_some() || !denials(parsed.as_deref(), &marker).is_empty() {
            break (query, parsed, reason);
        }
        if started.elapsed() >= timeout {
            break (
                query,
                parsed,
                Some(format!(
                    "the log did not show a denial made on purpose {:.0}s earlier",
                    started.elapsed().as_secs_f64()
                )),
            );
        }
        std::thread::sleep(Duration::from_millis(if fixed_marker.is_some() {
            20
        } else {
            2000
        }));
    };
    let stamped = parsed
        .as_ref()
        .and_then(|v| {
            v.iter().find(|e| {
                e["eventMessage"]
                    .as_str()
                    .is_some_and(|s| s.contains("deny"))
            })
        })
        .map(|e| e["timestamp"].clone());
    let mut last = last;
    last.as_object_mut()
        .ok_or("invalid log evidence")?
        .remove("stdout");
    save(
        &evidence.join("caught-up.json"),
        &json!({"marker":marker,"since":since,"made_at":made_at,"stamped":stamped,"queries":queries,"waited_seconds":started.elapsed().as_secs_f64(),"reason":reason,"last_query":last}),
    )?;
    Ok(reason)
}

pub(crate) fn check(
    tag: &str,
    since: &str,
    evidence: &Path,
    tool: Option<&Path>,
) -> Result<(String, Vec<String>)> {
    private_dir(evidence)?;
    let tagged = log_show(
        since,
        &format!("eventMessage CONTAINS \"{tag}\""),
        false,
        evidence,
        tool,
    );
    let (parsed, unread) = entries(&tagged);
    let denied = denials(parsed.as_deref(), tag);
    let (status, problems) = if !denied.is_empty() {
        ("fail", denied.clone())
    } else if let Some(reason) = unread {
        (
            "inconclusive",
            vec![format!("network attempts cannot be ruled out: {reason}")],
        )
    } else {
        ("pass", vec![])
    };
    let untagged = log_show(
        since,
        "(process == \"kernel\" AND sender == \"Sandbox\") OR process == \"sandboxd\"",
        true,
        evidence,
        tool,
    );
    let mut summary = json!({"tag":tag,"since":since,"queried_at":timestamp(0,"%Y-%m-%dT%H:%M:%S")?,"status":status,"problems":problems,"entries_with_tag":parsed.as_ref().map(Vec::len),"denials_with_tag":denied.len()});
    for (name, mut query) in [("tagged", tagged), ("sandbox", untagged)] {
        let raw = query["stdout"].as_str().unwrap_or("").as_bytes();
        write_private(
            &evidence.join(format!("{name}.out")),
            &raw[..raw.len().min(EVIDENCE_LIMIT)],
        )?;
        let bytes = raw.len();
        query
            .as_object_mut()
            .ok_or("invalid log query")?
            .remove("stdout");
        query["stdout_bytes"] = json!(bytes);
        query["stdout_saved_as"] = json!(format!("{name}.out"));
        query["truncated"] = json!(bytes > EVIDENCE_LIMIT);
        summary[name] = query;
    }
    save(&evidence.join("query.json"), &summary)?;
    Ok((status.into(), problems))
}

pub(crate) fn self_tests() -> Result<()> {
    let work = scratch("network-tests")?;
    let cases = [
        (64, "", "log: simulated failure\n", "inconclusive"),
        (0, "", "", "inconclusive"),
        (0, "not json\n", "", "inconclusive"),
        (0, "{}", "", "inconclusive"),
        (0, "[]", "", "pass"),
        (0, "[{\"eventMessage\":\"log invocation TAG\"}]", "", "pass"),
        (0, "[{\"eventMessage\":\"deny network TAG\"}]", "", "fail"),
        (
            1,
            "[{\"eventMessage\":\"deny network TAG\"}]",
            "bad",
            "fail",
        ),
    ];
    for (index, (code, out, err, expected)) in cases.iter().enumerate() {
        let root = work.join(format!("case-{index}"));
        private_dir(&root)?;
        let tool = fake_log(&root, *code, out, err)?;
        let evidence = root.join("evidence");
        let (status, _) = check("TAG", "2026-01-01 00:00:00", &evidence, Some(&tool))?;
        if status != *expected {
            return Err(format!(
                "network regression {index}: expected {expected}, got {status}"
            ));
        }
        if fs::read(evidence.join("tagged.out")).map_err(|e| e.to_string())? != out.as_bytes() {
            return Err("network raw evidence mismatch".into());
        }
        if fs::symlink_metadata(&evidence)
            .map_err(|e| e.to_string())?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err("network evidence not private".into());
        }
    }
    let root = work.join("barrier");
    private_dir(&root)?;
    let tool = fake_log(&root, 0, "[{\"eventMessage\":\"deny network MARK\"}]", "")?;
    if caught_up(
        &root.join("caught"),
        Duration::from_millis(40),
        Some(&tool),
        Some("MARK"),
    )?
    .is_some()
    {
        return Err("barrier rejected denial".into());
    }
    let barrier = load(&root.join("caught/caught-up.json"))?;
    if barrier["since"].as_str().ok_or("missing barrier clock")?
        > timestamp(-30, "%Y-%m-%d %H:%M:%S")?.as_str()
    {
        return Err("log query lost its clock margin".into());
    }
    for (index, out) in ["[]", "[{\"eventMessage\":\"log invocation MARK\"}]"]
        .iter()
        .enumerate()
    {
        let root = work.join(format!("missing-{index}"));
        private_dir(&root)?;
        let tool = fake_log(&root, 0, out, "")?;
        if caught_up(
            &root.join("caught"),
            Duration::from_secs(1),
            Some(&tool),
            Some("MARK"),
        )?
        .is_none()
        {
            return Err("barrier trusted missing denial".into());
        }
        let kept = load(&root.join("caught/caught-up.json"))?;
        if kept["queries"].as_u64().unwrap_or(0) <= 1 {
            return Err("barrier did not retry".into());
        }
    }
    let root = work.join("unreadable");
    private_dir(&root)?;
    let tool = fake_log(&root, 64, "", "log: simulated failure\n")?;
    if caught_up(
        &root.join("caught"),
        Duration::from_secs(600),
        Some(&tool),
        Some("MARK"),
    )?
    .is_none()
    {
        return Err("barrier trusted unreadable log".into());
    }
    if load(&root.join("caught/caught-up.json"))?["queries"] != 1 {
        return Err("unreadable log was waited for".into());
    }
    let (status, _) = check(
        "TAG",
        "2026-01-01 00:00:00",
        &work.join("missing-tool"),
        Some(&work.join("nonexistent")),
    )?;
    if status != "inconclusive" {
        return Err("missing log tool passed".into());
    }
    fs::remove_dir_all(&work).map_err(|e| e.to_string())?;
    Ok(())
}

pub(crate) fn integration_self_tests(work: &Path) -> Result<()> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    for (name, broken) in [("broken-log", true), ("real-log", false)] {
        let root = work.join(name);
        private_dir(&root)?;
        let fx = root.join("fixtures");
        fixtures::generate(&fx, 1, 1)?;
        let mut command = Command::new(&exe);
        command
            .args(["check", "--fixtures"])
            .arg(&fx)
            .args(["--", "/usr/bin/true"]);
        if broken {
            let bin = root.join("bin");
            private_dir(&bin)?;
            fake_log(&bin, 64, "", "log: simulated failure\n")?;
            command.env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            );
        }
        let captured = run_capture(&mut command, &root, Duration::from_secs(300))?;
        let run = fs::read_dir(fx.join("runs"))
            .map_err(|e| e.to_string())?
            .next()
            .ok_or("missing network test run")?
            .map_err(|e| e.to_string())?
            .path();
        let results = load(&run.join("results.json"))?;
        for check in results["results"]
            .as_array()
            .ok_or("missing network test checks")?
        {
            let expected = if broken && check["check"] == "network" {
                "inconclusive"
            } else {
                "pass"
            };
            if check["status"] != expected {
                return Err(format!("{name}: unexpected {} status", check["check"]));
            }
        }
        if captured.status != Some(i32::from(broken)) {
            return Err(format!("{name}: network gate exit mismatch"));
        }
        let query = load(&run.join("network-log/query.json"))?;
        if broken {
            if query["tagged"]["exit_status"] != 64 {
                return Err("failing log evidence lost".into());
            }
        } else {
            let barrier = load(&run.join("network-log/caught-up.json"))?;
            if !barrier["reason"].is_null()
                || !barrier["marker"]
                    .as_str()
                    .is_some_and(|s| s.starts_with("CREDHYG-MARK-"))
            {
                return Err("clean run passed without denial barrier".into());
            }
            for name in ["tagged", "sandbox"] {
                let argv = query[name]["argv"].as_array().ok_or("missing log argv")?;
                let index = argv
                    .iter()
                    .position(|v| v == "--start")
                    .ok_or("missing log start")?;
                if argv
                    .get(index + 1)
                    .and_then(Value::as_str)
                    .ok_or("missing log start time")?
                    > timestamp(-30, "%Y-%m-%d %H:%M:%S")?.as_str()
                {
                    return Err("scanner log query lost clock margin".into());
                }
            }
        }
        println!("PASS network integration control: {name}");
    }
    Ok(())
}
fn fake_log(root: &Path, code: i32, out: &str, err: &str) -> Result<PathBuf> {
    write_private(&root.join("stdout"), out.as_bytes())?;
    write_private(&root.join("stderr"), err.as_bytes())?;
    let tool = root.join("log");
    let script = format!(
        "#!/bin/sh\n/bin/cat '{}'\n/bin/cat '{}' >&2\nexit {code}\n",
        root.join("stdout").display(),
        root.join("stderr").display()
    );
    write_private(&tool, script.as_bytes())?;
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    Ok(tool)
}
