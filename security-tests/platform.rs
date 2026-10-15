//! Synthetic layout, injected denial and directory replacement races.
use super::*;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
const HEADER: &str =
    "url,username,password\nhttps://fixture.invalid,fixture,synthetic-password-only\n";
fn put(path: &Path) -> Result<()> {
    private_dir(path.parent().ok_or("missing parent")?)?;
    write_private(path, HEADER.as_bytes())
}
fn scan(binary: &Path, home: &Path, work: &Path, profile: Option<&str>) -> Result<Value> {
    let mut command = if let Some(profile) = profile {
        let mut c = Command::new("sandbox-exec");
        c.args(["-p", profile]).arg(binary);
        c
    } else {
        Command::new(binary)
    };
    let out = run_capture(
        command.args(["scan", "--export", "-"]).env("HOME", home),
        work,
        Duration::from_secs(20),
    )?;
    if out.timed_out || !matches!(out.status, Some(0 | 1)) {
        return Err("scanner failed during controlled platform test".into());
    }
    if contains(&out.stdout, b"synthetic-password-only")
        || contains(&out.stderr, b"synthetic-password-only")
    {
        return Err("platform fixture value leaked".into());
    }
    let report: Value =
        serde_json::from_slice(&out.stdout).map_err(|_| "platform report invalid")?;
    if out.status
        != Some(i32::from(
            !report["not_checked"]
                .as_array()
                .ok_or("missing gaps")?
                .is_empty(),
        ))
    {
        return Err("gap/exit mismatch".into());
    }
    Ok(report)
}
pub(crate) fn run(args: &[String]) -> Result<()> {
    let binary = fs::canonicalize(required(args, "--binary")?).map_err(|e| e.to_string())?;
    let base = PathBuf::from(required(args, "--work")?);
    private_dir(&base)?;
    let root = base.join(format!("platform-{}-{}", std::process::id(), random_hex()?));
    private_dir(&root)?;
    let home = root.join("home");
    private_dir(&home)?;
    put(&home.join("Documents/archive/export.csv"))?;
    for i in 0..25 {
        for j in 0..64 {
            let file = home.join(format!("Projects/project-{i:02}/source/file-{j:03}.txt"));
            private_dir(file.parent().ok_or("missing parent")?)?;
            write_private(&file, b"ordinary synthetic document\n")?;
        }
    }
    let started = Instant::now();
    let report = scan(&binary, &home, &root, None)?;
    if report["findings"]
        .as_array()
        .ok_or("missing findings")?
        .len()
        != 1
        || !report["not_checked"]
            .as_array()
            .ok_or("missing gaps")?
            .is_empty()
    {
        return Err("layout detection failed".into());
    }
    println!(
        "PASS synthetic nested layout: 1600 decoys, one export; {:.2}s",
        started.elapsed().as_secs_f64()
    );
    let blocked = home.join("blocked");
    put(&blocked.join("export.csv"))?;
    let profile = format!(
        "(version 1)(allow default)(deny file-read-data (subpath {}))",
        serde_json::to_string(&blocked).map_err(|_| "encode denial path")?
    );
    let report = scan(&binary, &home, &root, Some(&profile))?;
    if !report["not_checked"]
        .as_array()
        .ok_or("missing gaps")?
        .iter()
        .any(|g| g["path"] == "~/blocked" && g["reason"] == "permission-denied")
    {
        return Err("denied directory not reported".into());
    }
    if !report["findings"]
        .as_array()
        .ok_or("missing findings")?
        .iter()
        .any(|f| f["path"] == "~/Documents/archive/export.csv")
    {
        return Err("denial hid unrelated finding".into());
    }
    println!("PASS sandbox-injected directory denial (not a real TCC approval test)");
    let race = root.join("race-home");
    private_dir(&race)?;
    let live = race.join("moving");
    let parked = root.join("parked");
    let outside = root.join("outside");
    put(&live.join("inside.csv"))?;
    put(&outside.join("OUTSIDE-CANARY.csv"))?;
    let stop = Arc::new(AtomicBool::new(false));
    let swaps = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = std::sync::mpsc::channel();
    let worker_stop = stop.clone();
    let worker_swaps = swaps.clone();
    let worker = std::thread::spawn(move || {
        let result = (|| -> Result<()> {
            while !worker_stop.load(Ordering::Relaxed) {
                fs::rename(&live, &parked).map_err(|e| e.to_string())?;
                std::os::unix::fs::symlink(&outside, &live).map_err(|e| e.to_string())?;
                std::thread::sleep(Duration::from_millis(1));
                fs::remove_file(&live).map_err(|e| e.to_string())?;
                fs::rename(&parked, &live).map_err(|e| e.to_string())?;
                worker_swaps.fetch_add(1, Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(())
        })();
        if fs::symlink_metadata(&live).is_ok_and(|m| m.file_type().is_symlink()) {
            let _ = fs::remove_file(&live);
        }
        if fs::symlink_metadata(&parked).is_ok() && fs::symlink_metadata(&live).is_err() {
            let _ = fs::rename(&parked, &live);
        }
        let _ = tx.send(result);
    });
    let result = (|| -> Result<()> {
        for _ in 0..20 {
            let report = scan(&binary, &race, &root, None)?;
            if report["findings"]
                .as_array()
                .ok_or("missing findings")?
                .iter()
                .any(|f| {
                    f["path"]
                        .as_str()
                        .is_some_and(|p| p.contains("OUTSIDE-CANARY"))
                })
            {
                return Err("scanner traversed swapped symlink".into());
            }
        }
        Ok(())
    })();
    stop.store(true, Ordering::Relaxed);
    rx.recv_timeout(Duration::from_secs(5))
        .map_err(|_| "race fixture thread failed to stop in 5s")??;
    worker.join().map_err(|_| "race fixture thread panicked")?;
    result?;
    let count = swaps.load(Ordering::Relaxed);
    if count == 0 {
        return Err("race fixture did not swap".into());
    }
    println!("PASS 20 scans during {count} directory/symlink swaps; no outside finding");
    println!("UNVERIFIED: real TCC prompts, provider-backed dataless files/directories, EDR behavior, signing/notarization");
    fs::remove_dir_all(&root).map_err(|e| e.to_string())?;
    Ok(())
}
