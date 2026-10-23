//! Shell gates must require both successful completion and real work.
use super::*;
pub(crate) fn self_tests() -> Result<()> {
    let work = scratch("gate-tests")?;
    let bin = work.join("bin");
    private_dir(&bin)?;
    let cargo = bin.join("cargo");
    write_private(&cargo,b"#!/bin/sh\nif [ -n \"${LOOSE_KEYS_DETECTION_CLI:-}\" ]; then\n if [ \"$FAKE_MARKER\" = yes ]; then\n echo 'PASS: CLI and engine detection parity'\n fi\n exit \"$FAKE_STATUS\"\nfi\nexit 0\n")?;
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    for (index, (marker, status, expected)) in [("no", "0", 1), ("yes", "7", 7), ("yes", "0", 0)]
        .iter()
        .enumerate()
    {
        let tmp = work.join(format!("detection-{index}"));
        private_dir(&tmp)?;
        let out = run_capture(
            Command::new("sh")
                .arg(
                    Path::new(env!("CARGO_MANIFEST_DIR")).join("security-tests/check_detection.sh"),
                )
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
    fs::remove_dir_all(&work).map_err(|e| e.to_string())?;
    Ok(())
}
