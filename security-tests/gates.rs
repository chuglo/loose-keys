//! Shell gates must require both successful completion and real work.
use super::*;
pub(crate) fn self_tests() -> Result<()> {
    let work = scratch("gate-tests")?;
    let bin = work.join("bin");
    private_dir(&bin)?;
    let cargo = bin.join("cargo");
    write_private(&cargo,b"#!/bin/sh\nif [ -n \"${LOOSE_KEYS_DETECTION_CLI:-}\" ]; then\n if [ \"$FAKE_MARKER\" = yes ]; then\n echo 'PASS: CLI and engine detection parity'\n fi\n exit \"$FAKE_STATUS\"\nfi\nexit 0\n")?;
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    for mode in ["standalone", "workspace"] {
        for (index, (marker, status, expected)) in
            [("no", "0", 1), ("yes", "7", 7), ("yes", "0", 0)]
                .iter()
                .enumerate()
        {
            let tmp = work.join(format!("detection-{mode}-{index}"));
            private_dir(&tmp)?;
            let out = run_capture(
                Command::new("sh")
                    .arg(
                        Path::new(env!("CARGO_MANIFEST_DIR"))
                            .join("security-tests/check_detection.sh"),
                    )
                    .args(if mode == "workspace" {
                        vec!["--workspace"]
                    } else {
                        vec![]
                    })
                    .env(
                        "PATH",
                        format!(
                            "{}:{}",
                            bin.display(),
                            std::env::var("PATH").unwrap_or_default()
                        ),
                    )
                    .env("TMPDIR", &tmp)
                    .env("FAKE_MARKER", marker)
                    .env("FAKE_STATUS", status)
                    .env_remove("LOOSE_KEYS_DETECTION_CLI"),
                &tmp,
                Duration::from_secs(10),
            )?;
            if *expected == 1 {
                if out.status == Some(0) {
                    return Err("zero comparisons passed parity gate".into());
                }
            } else if out.status != Some(*expected) {
                return Err(format!("parity gate exit mismatch in case {index}"));
            }
        }
    }
    fs::remove_file(&cargo).map_err(|e| e.to_string())?;
    write_private(&cargo, b"#!/bin/sh\nexit 7\n")?;
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let output = work.join("output");
    private_dir(&output)?;
    write_private(&output.join("keep.txt"), b"existing workspace")?;
    let out = run_capture(
        Command::new("sh")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("security-tests/check_scanner.sh"))
            .arg(&output)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            ),
        &work,
        Duration::from_secs(10),
    )?;
    if out.status != Some(7)
        || fs::read(output.join("keep.txt")).map_err(|_| "gate deleted supplied workspace")?
            != b"existing workspace"
    {
        return Err("release gate failed preservation control".into());
    }
    runner_self_test(&work)?;
    fs::remove_dir_all(&work).map_err(|e| e.to_string())?;
    Ok(())
}

fn runner_self_test(work: &Path) -> Result<()> {
    let root = work.join("runner");
    let bin = root.join("bin");
    private_dir(&bin)?;
    // Every build, GUI and network command is replaced. Only the runner's
    // sequencing, timing and status handling execute for real.
    let stub = b"#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CALLS\"\ncase \"$*\" in *check_detection.sh*) exit \"$TEST_STATUS\";; esac\nexit 0\n";
    for name in ["cargo", "node", "sh", "python3"] {
        let file = bin.join(name);
        write_private(&file, stub)?;
        fs::set_permissions(file, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    let audit = root.join("cargo-audit/bin");
    private_dir(&audit)?;
    let tool = audit.join("cargo-audit");
    write_private(&tool, stub)?;
    fs::set_permissions(tool, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    for status in ["0", "7"] {
        let calls = root.join(format!("calls-{status}"));
        let out = run_capture(
            Command::new("/bin/sh")
                .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/check-all.sh"))
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .env("TMPDIR", &root)
                .env(
                    "PATH",
                    format!(
                        "{}:{}",
                        bin.display(),
                        std::env::var("PATH").unwrap_or_default()
                    ),
                )
                .env("CALLS", &calls)
                .env("TEST_STATUS", status),
            &root,
            Duration::from_secs(10),
        )?;
        let calls = fs::read_to_string(calls).map_err(|e| e.to_string())?;
        let summary = std::str::from_utf8(&out.stdout).map_err(|_| "invalid runner summary")?;
        if !summary.contains(&format!("test-and-detection: exit {status} ("))
            || !summary
                .lines()
                .filter(|line| line.contains(": exit "))
                .all(|line| line.ends_with("s)"))
            || out.status != Some(if status == "0" { 0 } else { 1 })
            || calls
                .lines()
                .filter(|line| line.contains("check_detection.sh"))
                .count()
                != 1
            || !calls.contains("check_detection.sh --workspace")
            || calls
                .lines()
                .filter(|line| line.contains("check-window-guest.sh"))
                .count()
                != 1
            || calls
                .lines()
                .filter(|line| line.contains("check-window-guest.py"))
                .count()
                != 1
            || calls.contains("test --locked --workspace")
            || !calls.lines().last().unwrap_or("").starts_with("audit --db")
        {
            return Err("full runner lost coverage, repeated tests or hid a failure".into());
        }
    }
    Ok(())
}
