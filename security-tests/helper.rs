//! Native helper acceptance. Test-only; never linked into the product.
use super::*;
use std::ffi::CStr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};

const STAGES: [&str; 8] = [
    "preflight",
    "enable-baseline",
    "event-create",
    "event-rotate",
    "event-delete",
    "restart-replay",
    "disable",
    "cleanup",
];
const DRIVER: &str = include_str!("../gui/tests/helper-control.swift");
const LIMIT: u64 = 8 * 1024 * 1024;
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

struct Failure {
    blocked: bool,
    reason: String,
}
type Check<T> = std::result::Result<T, Failure>;
impl From<String> for Failure {
    fn from(reason: String) -> Self {
        Self {
            blocked: false,
            reason,
        }
    }
}
fn fail(reason: &str) -> Failure {
    reason.to_owned().into()
}
fn blocked(reason: &str) -> Failure {
    Failure {
        blocked: true,
        reason: reason.into(),
    }
}
fn require(yes: bool, reason: &str) -> Check<()> {
    if yes {
        Ok(())
    } else {
        Err(fail(reason))
    }
}

extern "C" fn interrupt(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}
struct Signals(libc::sighandler_t, libc::sighandler_t);
impl Signals {
    fn install() -> Check<Self> {
        INTERRUPTED.store(false, Ordering::SeqCst);
        // SAFETY: the C callback only stores an atomic flag and lives for the process.
        let (int, term) = unsafe {
            (
                libc::signal(libc::SIGINT, interrupt as *const () as libc::sighandler_t),
                libc::signal(libc::SIGTERM, interrupt as *const () as libc::sighandler_t),
            )
        };
        require(
            int != libc::SIG_ERR && term != libc::SIG_ERR,
            "cannot install cleanup signal handlers",
        )?;
        Ok(Self(int, term))
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        // SAFETY: restores the valid previous handlers returned by signal.
        unsafe {
            libc::signal(libc::SIGINT, self.0);
            libc::signal(libc::SIGTERM, self.1);
        }
    }
}

fn wait_for<T>(
    name: &str,
    seconds: u64,
    mut condition: impl FnMut() -> Check<Option<T>>,
) -> Check<T> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline {
        require(!INTERRUPTED.load(Ordering::SeqCst), "interrupted")?;
        if let Some(value) = condition()? {
            return Ok(value);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(fail(&format!("deadline: {name}")))
}

fn event_observed(before: &Value, after: &Value) -> bool {
    let (old, new) = (&before["agent"], &after["agent"]);
    old["baseline"].is_string()
        && old["baseline"] == new["baseline"]
        && new["event_id"]
            .as_u64()
            .zip(old["event_id"].as_u64())
            .is_some_and(|(n, o)| n > o)
        && new["changes"]
            .as_u64()
            .zip(old["changes"].as_u64())
            .is_some_and(|(n, o)| n > o)
}
fn rotation_observed(old: &Value, current: &[&Value]) -> bool {
    let field = if old["secret"].as_str().is_some_and(|s| !s.is_empty()) {
        "secret"
    } else {
        "fingerprint"
    };
    current.len() == 1
        && old[field].as_str().is_some_and(|s| !s.is_empty())
        && current[0][field].as_str().is_some_and(|s| !s.is_empty())
        && current[0][field] != old[field]
        && current[0]["revision"]
            .as_u64()
            .zip(old["revision"].as_u64())
            .is_some_and(|(n, o)| n > o)
}
fn has_leak(data: &[u8], values: &[String]) -> bool {
    values.iter().any(|s| {
        let b = s.as_bytes();
        contains(data, b)
            || contains(data, &b[..b.len().min(10)])
            || contains(data, &b[b.len().saturating_sub(10)..])
    })
}
fn findings(state: &Value) -> Check<Vec<&Value>> {
    Ok(state["items"]
        .as_array()
        .ok_or_else(|| fail("review items missing"))?
        .iter()
        .filter(|i| {
            i["path"] == "~/.aws/credentials"
                && i["rule"] == "dev.aws.inline-credentials"
                && i["resolved"] == false
        })
        .collect())
}
fn observation(state: &Value) -> Check<Value> {
    let a = &state["agent"];
    Ok(
        json!({"pid":a["pid"],"event_id":a["event_id"],"changes":a["changes"],
              "baseline":a["baseline"],"open_fixture_findings":findings(state)?.len()}),
    )
}
fn pid(state: &Value) -> Check<u32> {
    let value = state["agent"]["pid"]
        .as_u64()
        .and_then(|p| u32::try_from(p).ok());
    value
        .filter(|p| *p > 1 && *p <= i32::MAX as u32)
        .ok_or_else(|| fail("invalid helper PID"))
}
fn absent(path: &Path) -> Check<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(_) => Err(blocked("cannot inspect prior product state")),
    }
}
fn account_home() -> Check<PathBuf> {
    // SAFETY: getuid has no preconditions; getpwuid's borrowed result is copied
    // before any other password-database call, on this single harness thread.
    unsafe {
        let account = libc::getpwuid(libc::getuid());
        if account.is_null() || (*account).pw_dir.is_null() {
            return Err(blocked("cannot identify account home"));
        }
        Ok(PathBuf::from(
            CStr::from_ptr((*account).pw_dir)
                .to_str()
                .map_err(|_| blocked("account home is not UTF-8"))?,
        ))
    }
}
fn hardware() -> Check<String> {
    let mut bytes = [0u8; 256];
    let mut len = bytes.len();
    // SAFETY: name is NUL-terminated, output has len bytes, no new value is supplied.
    let code = unsafe {
        libc::sysctlbyname(
            c"hw.model".as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    require(code == 0 && len <= bytes.len(), "cannot identify hardware")?;
    Ok(String::from_utf8_lossy(&bytes[..len])
        .trim_end_matches('\0')
        .to_owned())
}

struct Run {
    home: PathBuf,
    bundle: PathBuf,
    work: PathBuf,
    expected: String,
    app: Option<Child>,
    owned: Vec<PathBuf>,
    values: Vec<String>,
    report: Value,
    original: Value,
    omit: bool,
}
impl Run {
    fn new(home: PathBuf, bundle: PathBuf, work: PathBuf, expected: String, omit: bool) -> Self {
        let cases: serde_json::Map<String, Value> = STAGES
            .iter()
            .map(|n| ((*n).into(), json!({"status":"NOT RUN"})))
            .collect();
        Self {
            home,
            bundle,
            work,
            expected,
            app: None,
            owned: vec![],
            values: vec![],
            original: Value::Null,
            omit,
            report: json!({"cases":cases, "commands":[], "not_covered":["login/reboot","notifications",
                "sleep/wake/power","linked targets","browser sidecars","failed-save retry","UI refresh"]}),
        }
    }
    fn exe(&self) -> PathBuf {
        self.bundle.join("Contents/MacOS/loose-keys-gui")
    }
    fn store(&self) -> PathBuf {
        self.home
            .join("Library/Application Support/dev.loosekeys.desktop")
    }
    fn fixture(&self) -> PathBuf {
        self.home.join(".aws/credentials")
    }
    fn service(&self) -> String {
        // SAFETY: getuid has no preconditions.
        format!("gui/{}/dev.loosekeys.agent", unsafe { libc::getuid() })
    }
    fn save(&self) -> Check<()> {
        let temporary = self.work.join("results.tmp");
        super::save(&temporary, &self.report)?;
        fs::rename(temporary, self.work.join("results.json"))
            .map_err(|_| fail("cannot save helper receipt"))
    }
    fn invoke(&mut self, label: &str, command: &mut Command, seconds: u64) -> Check<Captured> {
        require(!INTERRUPTED.load(Ordering::SeqCst), "interrupted")?;
        let argv: Vec<String> = std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        let result = run_capture(command, &self.work, Duration::from_secs(seconds))?;
        let notes: Vec<&str> = std::str::from_utf8(&result.stdout)
            .unwrap_or("")
            .lines()
            .filter(|s| {
                ["PASS:", "FAIL:", "BLOCKED:", "NOTE:"]
                    .iter()
                    .any(|p| s.starts_with(p))
            })
            .collect();
        self.report["commands"]
            .as_array_mut()
            .ok_or_else(|| fail("receipt invariant"))?
            .push(
                json!({"stage":label,"argv":argv,"exit_status":result.status,"signal":result.signal,
                         "timed_out":result.timed_out,"driver_result":notes}),
            );
        require(!result.timed_out, "command deadline exceeded")?;
        Ok(result)
    }
    fn hash(&mut self, path: &Path) -> Check<String> {
        let out = self.invoke(
            "hash",
            Command::new("/usr/bin/shasum")
                .args(["-a", "256"])
                .arg(path),
            30,
        )?;
        require(out.status == Some(0), "cannot hash candidate")?;
        let text = std::str::from_utf8(&out.stdout).map_err(|_| fail("invalid hash output"))?;
        let hash = text.split_whitespace().next().unwrap_or("");
        require(
            hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid digest",
        )?;
        Ok(hash.to_owned())
    }
    fn registered(&mut self) -> Check<bool> {
        let service = self.service();
        // Frequent polling is not a new test stage; its final outcome is in the receipt.
        let out = run_capture(
            Command::new("/bin/launchctl").args(["print", &service]),
            &self.work,
            Duration::from_secs(30),
        )?;
        require(
            !out.timed_out && matches!(out.status, Some(0 | 113)),
            "launchctl lookup failed",
        )?;
        Ok(out.status == Some(0))
    }
    fn stopped(&mut self, process: u32) -> Check<bool> {
        // SAFETY: positive pid, signal zero only queries existence and sends no signal.
        let result = unsafe { libc::kill(process as i32, 0) };
        if result == 0 {
            return Ok(false);
        }
        require(
            std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
            "cannot query helper process",
        )?;
        Ok(!self.registered()?)
    }
    fn state(&self) -> Check<Value> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.store().join("state.json"))
            .map_err(|_| fail("cannot read review state"))?;
        let m = file
            .metadata()
            .map_err(|_| fail("cannot inspect review state"))?;
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        require(
            m.is_file()
                && m.len() <= LIMIT
                && m.uid() == uid
                && m.mode() & 0o077 == 0
                && m.nlink() == 1,
            "unsafe review state",
        )?;
        let mut data = vec![];
        file.take(LIMIT + 1)
            .read_to_end(&mut data)
            .map_err(|_| fail("cannot read review state"))?;
        require(
            data.len() as u64 <= LIMIT && !has_leak(&data, &self.values),
            "oversized or leaking review state",
        )?;
        serde_json::from_slice(&data).map_err(|_| fail("invalid review JSON"))
    }
    fn control(&mut self, action: &str) -> Check<()> {
        let app = self.app.as_mut().ok_or_else(|| fail("test app missing"))?;
        require(
            app.try_wait()
                .map_err(|_| fail("cannot query test app"))?
                .is_none(),
            "test app exited",
        )?;
        let app_pid = app.id().to_string();
        let driver = self.work.join("helper-control");
        let out = self.invoke(action, Command::new(driver).args([&app_pid, action]), 30)?;
        if out.status == Some(2) {
            return Err(blocked(
                "guest Accessibility or Login Items approval required",
            ));
        }
        require(
            out.status == Some(0),
            &format!("Settings driver failed: {action}"),
        )
    }
    fn helper_identity(&mut self, state: &Value) -> Check<()> {
        let process = pid(state)?;
        {
            let mut path = [0u8; 4096];
            // SAFETY: buffer is writable for the supplied length; proc_pidpath
            // reads process metadata for a positive pid, never dereferences it.
            let length = unsafe {
                libc::proc_pidpath(process as i32, path.as_mut_ptr().cast(), path.len() as u32)
            };
            require(length > 0, "helper executable identity unavailable")?;
            let end = path
                .iter()
                .position(|b| *b == 0)
                .ok_or_else(|| fail("invalid helper path"))?;
            require(
                std::str::from_utf8(&path[..end]).ok() == self.exe().to_str(),
                "helper executable mismatch",
            )?;
        }
        let out = self.invoke(
            "helper-identity",
            Command::new("/bin/ps").args(["-ww", "-p", &process.to_string(), "-o", "command="]),
            30,
        )?;
        let text = String::from_utf8_lossy(&out.stdout);
        require(
            out.status == Some(0)
                && (text.trim() == "loose-keys-gui --agent"
                    || text.trim() == format!("{} --agent", self.exe().display())),
            "helper arguments mismatch",
        )
    }
    fn preflight(&mut self) -> Check<Value> {
        let sip = self.invoke("sip", Command::new("/usr/bin/csrutil").arg("status"), 30)?;
        if sip.status != Some(0)
            || !String::from_utf8_lossy(&sip.stdout)
                .trim()
                .ends_with("enabled.")
        {
            return Err(blocked("SIP must be enabled"));
        }
        let gate = self.invoke(
            "gatekeeper",
            Command::new("/usr/sbin/spctl").arg("--status"),
            30,
        )?;
        if gate.status != Some(0) || !contains(&gate.stdout, b"assessments enabled") {
            return Err(blocked("Gatekeeper must be enabled"));
        }
        self.bundle = fs::canonicalize(&self.bundle).map_err(|_| blocked("candidate absent"))?;
        if self.hash(&self.exe())? != self.expected {
            return Err(blocked("candidate executable digest does not match"));
        }
        if !absent(&self.store())?
            || !absent(&self.home.join(".loose-keys-review"))?
            || !absent(&self.home.join(".aws"))?
            || self.registered()?
        {
            return Err(blocked(
                "existing product state or registered helper; reset guest first",
            ));
        }
        let processes = self.invoke(
            "prior-processes",
            Command::new("/usr/bin/pgrep").args(["-x", "loose-keys-gui"]),
            30,
        )?;
        if processes.status != Some(1) {
            return Err(blocked("product process already running or lookup failed"));
        }
        let source = self.work.join("helper-control.swift");
        write_private(&source, DRIVER.as_bytes())?;
        let driver = self.work.join("helper-control");
        let build = self.invoke(
            "driver-build",
            Command::new("/usr/bin/swiftc")
                .arg(&source)
                .arg("-o")
                .arg(&driver)
                .args(["-framework", "AppKit", "-framework", "ApplicationServices"]),
            120,
        )?;
        write_private(
            &self.work.join("driver-build.log"),
            &[build.stdout, build.stderr].concat(),
        )?;
        if build.status != Some(0) {
            return Err(blocked("Settings driver did not compile"));
        }
        let trust = self.invoke("accessibility", Command::new(&driver).arg("preflight"), 30)?;
        if trust.status != Some(0) {
            return Err(blocked("guest Settings driver requires Accessibility"));
        }
        let harness = std::env::current_exe().map_err(|_| fail("cannot identify harness"))?;
        let module = self.work.join("helper-source.rs");
        write_private(&module, include_bytes!("helper.rs"))?;
        self.report["candidate"] = json!({"executable_sha256":self.expected,
            "harness_sha256":self.hash(&harness)?, "runner_source_sha256":self.hash(&module)?,
            "driver_source_sha256":self.hash(&source)?,
            "plist_sha256":self.hash(&self.bundle.join("Contents/Library/LaunchAgents/dev.loosekeys.agent.plist"))?});
        let os = self.invoke("os", &mut Command::new("/usr/bin/sw_vers"), 30)?;
        let swift = self.invoke(
            "swift",
            Command::new("/usr/bin/swiftc").arg("--version"),
            30,
        )?;
        require(
            os.status == Some(0) && swift.status == Some(0),
            "cannot record environment",
        )?;
        self.report["environment"] = json!({"model":hardware()?.trim(),"architecture":std::env::consts::ARCH,
            "os":String::from_utf8_lossy(&os.stdout).trim(),"swift":String::from_utf8_lossy(&swift.stdout).trim()});
        Ok(json!(
            "guest, permissions, clean product state and candidate identity checked"
        ))
    }
    fn enable(&mut self) -> Check<Value> {
        let mut skipped = vec![];
        for entry in
            fs::read_dir(&self.home).map_err(|_| fail("cannot list synthetic guest home"))?
        {
            let entry = entry.map_err(|_| fail("cannot inspect guest directory"))?;
            if entry
                .file_type()
                .map_err(|_| fail("cannot inspect guest directory"))?
                .is_dir()
            {
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| blocked("guest directory name not UTF-8"))?;
                skipped.push(json!({"path":format!("~/{name}"),"added":""}));
            }
        }
        for path in [self.store(), self.home.join(".aws")] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .map_err(|_| fail("cannot create owned fixture directory"))?;
            self.owned.push(path);
        }
        super::save(
            &self.store().join("state.json"),
            &json!({"items":[],"skipped":skipped}),
        )?;
        self.report["fixture"] = json!({"preexisting_guest_directories_skipped":skipped.len()});
        let log = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(self.work.join("app.log"))
            .map_err(|_| fail("cannot create app log"))?;
        let stderr = log.try_clone().map_err(|_| fail("cannot clone app log"))?;
        self.app = Some(
            Command::new(self.exe())
                .env("HOME", &self.home)
                .stdout(log)
                .stderr(stderr)
                .spawn()
                .map_err(|_| fail("cannot launch test app"))?,
        );
        self.control("enable-overview")?;
        let state = wait_for("helper baseline", 90, || {
            let state = self.state()?;
            Ok((state["monitoring"] == true
                && state["agent"]["baseline"].is_string()
                && pid(&state).is_ok())
            .then_some(state))
        })?;
        require(self.registered()?, "helper not registered after consent")?;
        self.helper_identity(&state)?;
        observation(&state)
    }
    fn write_fixture(&mut self) -> Check<()> {
        let access = format!("{}{}{}", "AK", "IA", random_hex()?[..16].to_uppercase());
        let secret = format!("{}{}", random_hex()?, &random_hex()?[..8]);
        let body = format!(
            "[helper-check]\naws_access_key_id = {access}\naws_secret_access_key = {secret}\n"
        );
        self.values.extend([access, secret]);
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.fixture())
            .map_err(|_| fail("cannot write synthetic fixture"))?;
        file.write_all(body.as_bytes())
            .map_err(|_| fail("cannot write synthetic fixture"))
    }
    fn event(
        &mut self,
        before: &Value,
        mut predicate: impl FnMut(&Value) -> Check<bool>,
    ) -> Check<Value> {
        wait_for("native event and persisted fixture transition", 90, || {
            let state = self.state()?;
            let expected = predicate(&state)?;
            self.report["last_event_observation"] = json!({"before":observation(before)?,"after":observation(&state)?,
                "expected_transition":expected,"event_observed":event_observed(before,&state)});
            Ok((expected && event_observed(before, &state)).then_some(state))
        })
    }
    fn create(&mut self) -> Check<Value> {
        let before = self.state()?;
        if !self.omit {
            self.write_fixture()?;
        }
        let state = self.event(&before, |s| Ok(findings(s)?.len() == 1))?;
        self.original = findings(&state)?[0].clone();
        observation(&state)
    }
    fn rotate(&mut self) -> Check<Value> {
        let before = self.state()?;
        let old = self.original.clone();
        self.write_fixture()?;
        let state = self.event(&before, |s| Ok(rotation_observed(&old, &findings(s)?)))?;
        observation(&state)
    }
    fn delete(&mut self) -> Check<Value> {
        let before = self.state()?;
        fs::remove_file(self.fixture()).map_err(|_| fail("cannot delete owned fixture"))?;
        let state = self.event(&before, |s| Ok(findings(s)?.is_empty()))?;
        observation(&state)
    }
    fn restart(&mut self) -> Check<Value> {
        let before = self.state()?;
        let old_pid = pid(&before)?;
        self.control("stop")?;
        wait_for("helper unregister and process exit", 20, || {
            Ok(self.stopped(old_pid)?.then_some(()))
        })?;
        self.write_fixture()?;
        self.control("start")?;
        let state = wait_for("restart and real FSEvents history replay", 90, || {
            let state = self.state()?;
            let a = &state["agent"];
            let replayed = pid(&state)? != old_pid
                && a["baseline"] == before["agent"]["baseline"]
                && a["event_id"]
                    .as_u64()
                    .zip(before["agent"]["event_id"].as_u64())
                    .is_some_and(|(n, o)| n > o)
                && a["changes"].as_u64().is_some_and(|n| n > 0)
                && findings(&state)?.len() == 1;
            Ok(replayed.then_some(state))
        })?;
        self.helper_identity(&state)?;
        observation(&state)
    }
    fn disable(&mut self) -> Check<Value> {
        let process = pid(&self.state()?)?;
        self.control("disable")?;
        wait_for("helper disabled and process exited", 20, || {
            Ok(self.stopped(process)?.then_some(()))
        })?;
        let before = self.state()?;
        require(
            before["monitoring"] == false,
            "monitoring consent not withdrawn",
        )?;
        self.write_fixture()?;
        let end = Instant::now() + Duration::from_secs(12);
        while Instant::now() < end {
            require(!INTERRUPTED.load(Ordering::SeqCst), "interrupted")?;
            require(
                !self.registered()? && self.state()? == before,
                "helper or state changed while disabled",
            )?;
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(json!(
            "unregistered, consent off, no state changes during 12-second observation"
        ))
    }
    fn cleanup(&mut self) -> Check<Value> {
        if self.owned.is_empty() {
            return Ok(json!("no product state created; no cleanup actions needed"));
        }
        let process = pid(&self.state()?).ok();
        if self
            .app
            .as_mut()
            .is_some_and(|p| p.try_wait().ok().flatten().is_none())
        {
            self.control("disable")?;
            wait_for("cleanup unregister and process exit", 20, || {
                Ok(if let Some(p) = process {
                    self.stopped(p)?
                } else {
                    !self.registered()?
                }
                .then_some(()))
            })?;
            let app = self.app.as_mut().ok_or_else(|| fail("test app missing"))?;
            // SAFETY: the Child is still running and unreaped; this pid belongs to our app.
            let code = unsafe { libc::kill(app.id() as i32, libc::SIGTERM) };
            require(code == 0, "cannot stop test app")?;
            wait_for("test app exit", 10, || {
                app.try_wait().map_err(|_| fail("cannot wait for test app"))
            })?;
        }
        require(
            !self.registered()?,
            "cleanup refused: helper still registered; stop guest",
        )?;
        if let Some(p) = process {
            require(
                self.stopped(p)?,
                "cleanup refused: helper still running; stop guest",
            )?;
        }
        for path in self.owned.iter().rev() {
            fs::remove_dir_all(path).map_err(|_| fail("cannot remove owned fixture"))?;
        }
        let mut data = vec![];
        File::open(self.work.join("app.log"))
            .map_err(|_| fail("cannot read app log"))?
            .take(LIMIT + 1)
            .read_to_end(&mut data)
            .map_err(|_| fail("cannot read app log"))?;
        require(
            data.len() as u64 <= LIMIT && !has_leak(&data, &self.values),
            "oversized or leaking app log",
        )?;
        Ok(json!(
            "owned fixtures/state removed; helper unregistered; test app stopped"
        ))
    }
    fn stage(&mut self, name: &str, action: fn(&mut Self) -> Check<Value>) -> Check<()> {
        let start = Instant::now();
        let result = action(self);
        self.report["cases"][name] = match &result {
            Ok(evidence) => json!({"status":"PASS","evidence":evidence}),
            Err(error) => {
                json!({"status":if error.blocked {"BLOCKED"} else {"FAIL"},"reason":error.reason})
            }
        };
        self.report["cases"][name]["seconds"] = json!(start.elapsed().as_secs_f64());
        self.save()?;
        println!(
            "{name}: {}",
            self.report["cases"][name]["status"]
                .as_str()
                .unwrap_or("FAIL")
        );
        result.map(|_| ())
    }
    fn execute(&mut self) -> Check<i32> {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&self.work)
            .map_err(|_| blocked("work directory must be new, with an existing parent"))?;
        let mut status = 0;
        let actions: [fn(&mut Self) -> Check<Value>; 7] = [
            Self::preflight,
            Self::enable,
            Self::create,
            Self::rotate,
            Self::delete,
            Self::restart,
            Self::disable,
        ];
        for (name, action) in STAGES.iter().zip(actions) {
            if let Err(error) = self.stage(name, action) {
                status = if error.blocked { 2 } else { 1 };
                break;
            }
        }
        // A first interrupt requests cleanup, not an immediate abort. A second
        // interrupt may fail cleanup; the receipt must then remain a failure.
        if INTERRUPTED.swap(false, Ordering::SeqCst) {
            status = 1;
        }
        if self.stage("cleanup", Self::cleanup).is_err() {
            status = 1;
        }
        self.report["exit_status"] = json!(status);
        self.save()?;
        Ok(status)
    }
}

pub(crate) fn run(args: &[String]) -> Result<i32> {
    let result = (|| -> Check<i32> {
        if std::env::var("CREDHYG_HELPER_CHECK").as_deref() != Ok("disposable-guest") {
            return Err(blocked("guest-only opt-in required"));
        }
        let model = hardware()?;
        let home = PathBuf::from(required(args, "--guest-home").map_err(|e| blocked(&e))?);
        let account = account_home()?;
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        let console = fs::metadata("/dev/console")
            .map_err(|_| blocked("guest console user required"))?
            .uid();
        if !context_allowed(
            &model,
            uid,
            console,
            home.to_str().unwrap_or(""),
            account.to_str().unwrap_or(""),
        ) {
            return Err(blocked(
                "requires a disposable macOS guest and its non-root console account home",
            ));
        }
        if std::env::var_os("HOME").as_deref() != Some(account.as_os_str())
            || fs::canonicalize(&home).ok().as_ref() != Some(&home)
        {
            return Err(blocked("HOME must be the canonical guest account home"));
        }
        let expected = required(args, "--sha256")
            .map_err(|e| blocked(&e))?
            .to_owned();
        if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(blocked(
                "expected executable SHA-256 must be 64 hex characters",
            ));
        }
        let work = PathBuf::from(required(args, "--work").map_err(|e| blocked(&e))?);
        let bundle = PathBuf::from(required(args, "--bundle").map_err(|e| blocked(&e))?);
        let _signals = Signals::install()?;
        Run::new(
            home,
            bundle,
            work,
            expected,
            args.iter().any(|a| a == "--omit-create"),
        )
        .execute()
    })();
    match result {
        Ok(code) => Ok(code),
        Err(e) => {
            println!(
                "{}: {}",
                if e.blocked { "BLOCKED" } else { "FAIL" },
                e.reason
            );
            Ok(if e.blocked { 2 } else { 1 })
        }
    }
}

fn context_allowed(
    model: &str,
    uid: u32,
    console_uid: u32,
    home: &str,
    account_home: &str,
) -> bool {
    model.starts_with("VirtualMac") && uid != 0 && uid == console_uid && home == account_home
}

pub(crate) fn self_tests() -> Result<()> {
    if !context_allowed("VirtualMac2,1", 501, 501, "/Users/test", "/Users/test") {
        return Err("approved synthetic guest should pass context gate".into());
    }
    for (model, uid, console, home) in [
        ("Mac16,1", 501, 501, "/Users/test"),
        ("VirtualMac2,1", 0, 0, "/Users/test"),
        ("VirtualMac2,1", 501, 502, "/Users/test"),
        ("VirtualMac2,1", 501, 501, "/substitute/home"),
    ] {
        if context_allowed(model, uid, console, home, "/Users/test") {
            return Err("unsafe native helper context accepted".into());
        }
    }
    let before = json!({"agent":{"baseline":"first","event_id":20,"changes":2}});
    let after = json!({"agent":{"baseline":"first","event_id":21,"changes":3}});
    if !event_observed(&before, &after) {
        return Err("native event evidence rejected".into());
    }
    for (field, value) in [
        ("baseline", json!("second")),
        ("event_id", json!(20)),
        ("changes", json!(2)),
    ] {
        let mut bad = after.clone();
        bad["agent"][field] = value;
        if event_observed(&before, &bad) {
            return Err("stale or full-pass event evidence accepted".into());
        }
    }
    if event_observed(&json!({}), &json!({})) {
        return Err("missing event evidence accepted".into());
    }
    for field in ["secret", "fingerprint"] {
        let mut old = json!({"id":1,"revision":1});
        old[field] = json!("old-digest");
        let mut new = json!({"id":1,"revision":2});
        new[field] = json!("new-digest");
        if !rotation_observed(&old, &[&new]) {
            return Err("valid same-id rotation rejected".into());
        }
        if rotation_observed(&old, &[]) || rotation_observed(&old, &[&old, &new]) {
            return Err("invalid rotation cardinality accepted".into());
        }
        for (key, value) in [
            ("revision", json!(1)),
            (field, Value::Null),
            (field, json!("old-digest")),
        ] {
            let mut bad = new.clone();
            bad[key] = value;
            if rotation_observed(&old, &[&bad]) {
                return Err("unchanged rotation accepted".into());
            }
        }
    }
    let value = "synthetic-first-synthetic-last".to_owned();
    for piece in [&value[..], &value[..10], &value[value.len() - 10..]] {
        if !has_leak(piece.as_bytes(), std::slice::from_ref(&value)) {
            return Err("fixture leak missed".into());
        }
    }
    if has_leak(b"ordinary diagnostic", &[value]) {
        return Err("false leak match".into());
    }
    if wait_for::<()>("self-test", 0, || Ok(None)).is_ok() {
        return Err("expired deadline passed".into());
    }
    interrupt(0);
    let cancelled = wait_for("self-test", 1, || Ok(Some(()))).is_err();
    INTERRUPTED.store(false, Ordering::SeqCst);
    if !cancelled {
        return Err("interrupt did not fail wait".into());
    }
    for bad in [0, 1, i32::MAX as u64 + 1] {
        if pid(&json!({"agent":{"pid":bad}})).is_ok() {
            return Err("unsafe process id accepted".into());
        }
    }
    let observed = observation(&json!({"items":[],"key":[1],"agent":{"pid":4,"event_id":2,"changes":1,"baseline":"first","volume":"private"}}))
        .map_err(|e| e.reason)?;
    if observed.as_object().map(|m| m.len()) != Some(5)
        || observed.get("key").is_some()
        || observed.get("volume").is_some()
    {
        return Err("raw review fields leaked into observation".into());
    }
    let root = scratch("helper-selftests")?;
    let home = root.join("home");
    private_dir(&home)?;
    for (index, is_blocked) in [false, true].into_iter().enumerate() {
        let work = root.join(format!("receipt-{index}"));
        private_dir(&work)?;
        let mut test = Run::new(
            home.clone(),
            root.clone(),
            work.clone(),
            String::new(),
            false,
        );
        let action: fn(&mut Run) -> Check<Value> = if is_blocked {
            |_| Err(blocked("self-test prerequisite"))
        } else {
            |_| Err(fail("self-test assertion"))
        };
        if test.stage("preflight", action).is_ok() {
            return Err("failed stage passed".into());
        }
        test.stage("cleanup", Run::cleanup).map_err(|e| e.reason)?;
        let receipt = load(&work.join("results.json"))?;
        if receipt["cases"]["preflight"]["status"] != if is_blocked { "BLOCKED" } else { "FAIL" }
            || receipt["cases"]["event-create"]["status"] != "NOT RUN"
            || receipt["cases"]["cleanup"]["status"] != "PASS"
        {
            return Err("failed-stage receipt lost status or ran later work".into());
        }
    }
    let out = run_capture(
        Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
            .arg("helper-check")
            .env_remove("CREDHYG_HELPER_CHECK"),
        &root,
        Duration::from_secs(5),
    )?;
    if out.status != Some(2) || !contains(&out.stdout, b"BLOCKED: guest-only opt-in required") {
        return Err("helper command did not refuse absent opt-in".into());
    }
    let malformed = run_capture(
        Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
            .arg("helper-check")
            .env("CREDHYG_HELPER_CHECK", "disposable-guest"),
        &root,
        Duration::from_secs(5),
    )?;
    if malformed.status != Some(2) {
        return Err("missing helper arguments must be blocked, not a product failure".into());
    }
    fs::remove_dir_all(root).map_err(|e| e.to_string())?;
    println!("PASS: native helper runner self-tests");
    Ok(())
}
