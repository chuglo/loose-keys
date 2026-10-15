//! Complete synthetic databases made by the system SQLite, independently of
//! the scanner's reader. No scanned file is opened by SQLite in the product.
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub fn database(sql: &str) -> Vec<u8> {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "loose-keys-sqlite-{}-{}-{}",
        module_path!().replace("::", "-"),
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let cleanup = Cleanup(dir);
    let path = cleanup.0.join("fixture.db");
    let mut child = Command::new("/usr/bin/sqlite3")
        .arg(&path)
        .arg(sql)
        .env("HOME", &cleanup.0)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the system SQLite fixture writer");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "SQLite fixture creation failed");
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("SQLite fixture creation timed out");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    fs::read(path).unwrap()
}

pub fn table(name: &str, rows: u8) -> Vec<u8> {
    assert!(matches!(name, "logins" | "credit_cards" | "credentials"));
    let mut sql = format!("PRAGMA page_size=512; CREATE TABLE {name}(value TEXT);");
    for _ in 0..rows {
        sql.push_str(&format!("INSERT INTO {name} VALUES ('synthetic');"));
    }
    database(&sql)
}
