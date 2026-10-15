//! Synthetic hostile trees; secrets live only in private generated files.
use super::*;
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::{symlink, MetadataExt};

pub(crate) fn snapshot(roots: &[PathBuf]) -> Result<Value> {
    let mut entries = serde_json::Map::new();
    for root in roots {
        snap(root, &mut entries)?;
    }
    Ok(Value::Object(entries))
}
fn snap(path: &Path, entries: &mut serde_json::Map<String, Value>) -> Result<()> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    let mut record = json!({"mode":meta.mode(),"size":meta.size(),"mtime_ns":(meta.mtime() as i128)*1_000_000_000+meta.mtime_nsec() as i128});
    if meta.file_type().is_symlink() {
        record["link"] = json!(fs::read_link(path)
            .map_err(|e| e.to_string())?
            .to_string_lossy());
    } else if meta.is_file() && meta.len() <= 64 * 1024 * 1024 {
        let mut command = Command::new("/usr/bin/shasum");
        command.args(["-a", "256"]);
        let input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| e.to_string())?;
        let output = command
            .stdin(Stdio::from(input))
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err("snapshot SHA-256 failed".into());
        }
        let digest = std::str::from_utf8(&output.stdout)
            .map_err(|_| "invalid SHA-256 output")?
            .split_whitespace()
            .next()
            .ok_or("missing SHA-256 digest")?;
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid SHA-256 digest".into());
        }
        record["sha256"] = json!(digest);
    }
    entries.insert(path.to_string_lossy().into_owned(), record);
    if meta.is_dir() {
        for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
            snap(&entry.map_err(|e| e.to_string())?.path(), entries)?;
        }
    }
    Ok(())
}

pub(crate) fn random(alphabet: &str, length: usize) -> Result<String> {
    let bytes = alphabet.as_bytes();
    if bytes.is_empty() {
        return Err("empty random alphabet".into());
    }
    let mut source = File::open("/dev/urandom").map_err(|e| e.to_string())?;
    let mut result = String::new();
    while result.len() < length {
        let mut byte = [0u8; 1];
        source.read_exact(&mut byte).map_err(|e| e.to_string())?;
        let cutoff = 256 - (256 % bytes.len());
        if (byte[0] as usize) < cutoff {
            result.push(bytes[byte[0] as usize % bytes.len()] as char);
        }
    }
    Ok(result)
}
const ALNUM: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
pub(crate) fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        out.push(TABLE[(n >> 18) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}
struct Builder {
    out: PathBuf,
    home: PathBuf,
    outside: PathBuf,
    sentinels: PathBuf,
    hijack: PathBuf,
    fixtures: Vec<Value>,
    secrets: Vec<String>,
    fragments: Vec<String>,
    scope: Vec<String>,
    skipped: Vec<String>,
}
impl Builder {
    fn write(&self, rel: &str, data: impl AsRef<[u8]>) -> Result<PathBuf> {
        self.write_at(&self.home, rel, data, 0o600)
    }
    fn write_at(
        &self,
        base: &Path,
        rel: &str,
        data: impl AsRef<[u8]>,
        mode: u32,
    ) -> Result<PathBuf> {
        let path = base.join(rel);
        private_dir(path.parent().ok_or("missing parent")?)?;
        write_private(&path, data.as_ref())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())?;
        Ok(path)
    }
    fn secret(&mut self, value: String, prefix: usize) -> String {
        self.fragments.push(value[prefix..].into());
        self.secrets.push(value.clone());
        value
    }
    fn add(
        &mut self,
        id: &str,
        invariants: &[&str],
        path: &str,
        description: &str,
        category: &str,
    ) {
        self.fixtures.push(json!({"id":id,"invariants":invariants,"path":path,"description":description,"expectation":"Preserve the named security invariants","category":category}));
    }
    fn probe(&self, name: &str) -> Result<PathBuf> {
        self.write_at(
            &self.out,
            &format!("exec-probes/{name}"),
            format!(
                "#!/bin/sh\n: > '{}'\nexit 1\n",
                self.sentinels.join(name).display()
            ),
            0o755,
        )
    }
}
pub(crate) fn generate(out: &Path, large_mib: usize, bomb_mib: usize) -> Result<Value> {
    if let Ok(meta) = fs::symlink_metadata(out) {
        if !meta.is_dir()
            || fs::read_dir(out)
                .map_err(|e| e.to_string())?
                .next()
                .is_some()
        {
            return Err("refusing to write into non-empty directory".into());
        }
    }
    private_dir(out)?;
    let out = fs::canonicalize(out).map_err(|e| e.to_string())?;
    let mut b = Builder {
        home: out.join("scan-root/home"),
        outside: out.join("outside"),
        sentinels: out.join("sentinels"),
        hijack: out.join("bin-hijack"),
        out,
        fixtures: vec![],
        secrets: vec![],
        fragments: vec![],
        scope: vec![],
        skipped: vec![],
    };
    for p in [&b.home, &b.outside, &b.sentinels, &b.hijack] {
        private_dir(p)?;
    }
    let mut rows = String::from("name,url,username,password\n");
    for i in 0..3 {
        let pw = b.secret(
            format!("PWEXPORT-{}{}", random_hex()?, random(ALNUM, 12)?),
            9,
        );
        rows.push_str(&format!(
            "site{i},https://site{i}.example,user{i}@example.com,{pw}\n"
        ));
    }
    b.write("Downloads/Chrome Passwords.csv", rows)?;
    b.add(
        "export-browser-csv",
        &["I2", "I6"],
        "Downloads/Chrome Passwords.csv",
        "Browser password export with generated passwords",
        "password-export",
    );
    b.write(
        "Downloads/contacts.csv",
        "name,url,username,notes\nalice,https://a.example,alice,met at conference\n",
    )?;
    b.add(
        "export-decoy-csv",
        &["I8"],
        "Downloads/contacts.csv",
        "Header without password column",
        "false-positive-control",
    );
    let mut aws = String::new();
    for profile in ["default", "declared-canary"] {
        let key = format!("AKIA{}", random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)?);
        let secret = b.secret(random(ALNUM, 40)?, 0);
        aws.push_str(&format!(
            "[{profile}]\naws_access_key_id = {key}\naws_secret_access_key = {secret}\n\n"
        ));
    }
    b.write(".aws/credentials", aws)?;
    b.add(
        "aws-inline-credentials",
        &["I2", "I6"],
        ".aws/credentials",
        "Ordinary and declared-canary AWS profiles",
        "developer-cloud",
    );
    let probe = b.probe("aws-credential-process")?;
    b.write(
        ".aws/config",
        format!(
            "[profile proc]\ncredential_process = {} --profile proc\n",
            probe.display()
        ),
    )?;
    b.add(
        "aws-credential-process",
        &["I3"],
        ".aws/config",
        "External credential command probe",
        "developer-cloud",
    );
    let probe = b.probe("kubeconfig-exec")?;
    b.write(".kube/config",format!("apiVersion: v1\nkind: Config\nclusters:\n- name: c\n  cluster:\n    server: https://k8s.invalid\ncontexts:\n- name: c\n  context: {{cluster: c, user: u}}\ncurrent-context: c\nusers:\n- name: u\n  user:\n    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: {}\n",probe.display()))?;
    b.add(
        "kubeconfig-exec",
        &["I3", "I5"],
        ".kube/config",
        "Credential plugin command and unreachable cluster",
        "developer-cloud",
    );
    let pw = b.secret(random(ALNUM, 24)?, 0);
    let auth = base64(format!("ci-bot:{pw}").as_bytes());
    b.secrets.push(auth.clone());
    b.fragments.push(auth[12..].into());
    b.write(
        ".docker/config.json",
        serde_json::to_vec(&json!({"auths":{"registry.invalid":{"auth":auth}}}))
            .map_err(|_| "encode docker fixture")?,
    )?;
    b.add(
        "docker-inline-auth",
        &["I6"],
        ".docker/config.json",
        "Encoded password and decoded password both forbidden",
        "developer-cloud",
    );
    let repo = b.home.join("Projects/evil-repo");
    private_dir(&repo)?;
    match Command::new("git")
        .args(["init", "-q"])
        .arg(&repo)
        .env("HOME", &b.home)
        .status()
    {
        Ok(status) if status.success() => {}
        _ => {
            b.skipped
                .push("git-real-repo: git unavailable; created bare config only".into());
            private_dir(&repo.join(".git"))?;
        }
    }
    let fsmon = b.probe("git-fsmonitor")?;
    let helper = b.probe("git-credential-helper")?;
    let mut config = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(repo.join(".git/config"))
        .map_err(|e| e.to_string())?;
    writeln!(
        config,
        "[core]\n\tfsmonitor = {}\n[credential]\n\thelper = !{}",
        fsmon.display(),
        helper.display()
    )
    .map_err(|e| e.to_string())?;
    let env_secret = b.secret(format!("DOTENV-{}{}", random_hex()?, random(ALNUM, 16)?), 7);
    b.write(
        "Projects/evil-repo/.env",
        format!("DATABASE_URL=postgres://app:{env_secret}@db.invalid/app\n"),
    )?;
    b.add(
        "git-malicious-config",
        &["I3"],
        "Projects/evil-repo/.git/config",
        "Git helper and fsmonitor execution probes",
        "hostile-config",
    );
    b.add(
        "dotenv-in-project",
        &["I6"],
        "Projects/evil-repo/.env",
        "Inline database password",
        "unexpected-copy",
    );
    let token = b.secret(format!("{}{}", concat!("gh", "p_"), random(ALNUM, 36)?), 4);
    b.write(
        "Library/Logs/SomeApp/debug.log",
        format!("2026-10-07 INFO request\n2026-10-07 DEBUG Authorization: Bearer {token}\n"),
    )?;
    b.add(
        "token-in-log",
        &["I6"],
        "Library/Logs/SomeApp/debug.log",
        "Bearer token in log",
        "unexpected-copy",
    );
    private_dir(&b.home.join(".ssh"))?;
    for (name, protected) in [("id_ed25519", false), ("id_ed25519_protected", true)] {
        let pass = if protected {
            b.secret(random(ALNUM, 20)?, 0)
        } else {
            String::new()
        };
        let target = b.home.join(".ssh").join(name);
        match Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", &pass, "-C", "fixture", "-f"])
            .arg(&target)
            .env("HOME", &b.home)
            .status()
        {
            Ok(status) if status.success() => {}
            _ => {
                b.skipped
                    .push("private-keys: ssh-keygen unavailable".into());
                break;
            }
        }
        let body = fs::read_to_string(&target)
            .map_err(|e| e.to_string())?
            .lines()
            .filter(|s| !s.is_empty() && !s.starts_with("-----"))
            .map(str::to_owned)
            .collect::<Vec<_>>();
        b.secrets
            .extend(body.iter().filter(|s| s.len() >= 16).cloned());
        b.fragments.extend(body.iter().skip(1).cloned());
        b.add(
            &format!("ssh-{name}"),
            &["I2", "I6"],
            &format!(".ssh/{name}"),
            "Generated OpenSSH private key",
            "private-key",
        );
        b.fixtures.last_mut().ok_or("missing key fixture")?["protected"] = json!(protected);
    }
    let file_token = format!("SCOPE-FILE-{}", random_hex()?);
    b.scope.push(file_token.clone());
    b.write_at(
        &b.outside,
        "secret-outside.txt",
        format!("aws_secret_access_key = {file_token}\n"),
        0o600,
    )?;
    private_dir(&b.home.join("Documents"))?;
    symlink(
        b.outside.join("secret-outside.txt"),
        b.home.join("Documents/notes.txt"),
    )
    .map_err(|e| e.to_string())?;
    b.add(
        "symlink-escape-file",
        &["I1", "I2"],
        "Documents/notes.txt",
        "Out-of-scope file link",
        "scope",
    );
    let dir_token = format!("SCOPE-DIR-{}", random_hex()?);
    b.scope.push(dir_token.clone());
    b.write_at(
        &b.outside,
        &format!("private-dir/{dir_token}.pem"),
        "not a key\n",
        0o600,
    )?;
    symlink(
        b.outside.join("private-dir"),
        b.home.join("Documents/archive"),
    )
    .map_err(|e| e.to_string())?;
    b.add(
        "symlink-escape-dir",
        &["I1", "I2"],
        "Documents/archive",
        "Out-of-scope folder link",
        "scope",
    );
    symlink("..", b.home.join("Documents/loop")).map_err(|e| e.to_string())?;
    b.add(
        "symlink-cycle",
        &["I4"],
        "Documents/loop",
        "Directory link cycle",
        "robustness",
    );
    let clobber = b.write_at(
        &b.outside,
        "clobber-target.txt",
        "ORIGINAL CONTENT - must not change\n",
        0o600,
    )?;
    b.add(
        "report-clobber-target",
        &["I1", "I6"],
        "../outside/clobber-target.txt",
        "Preplaced export link target",
        "scope",
    );
    b.fixtures.last_mut().ok_or("missing clobber fixture")?["absolute"] = json!(clobber);
    let forged = format!("FORGED-{}", random_hex()?);
    let osc = format!("OSC-{}", random_hex()?);
    for (id, name) in [
        ("osc-escape", format!("\x1b]0;{osc}\x07Passwords.csv")),
        (
            "newline-forgery",
            format!("Passwords\n{forged} finding resolved.csv"),
        ),
        ("bidi-override", "Passwords-\u{202e}vsc.exe".into()),
    ] {
        let pw = b.secret(random(ALNUM, 24)?, 0);
        let rel = format!("Downloads/{name}");
        b.write(
            &rel,
            format!("name,url,username,password\nx,https://x.example,x,{pw}\n"),
        )?;
        b.add(
            &format!("filename-{id}"),
            &["I4"],
            &rel,
            "Hostile filename containing controls or bidi",
            "output-encoding",
        );
    }
    let fifo = std::ffi::CString::new(
        b.home
            .join("Downloads/Bitwarden export.csv")
            .as_os_str()
            .as_encoded_bytes(),
    )
    .map_err(|_| "bad FIFO path")?;
    // SAFETY: fifo is a valid terminated path in the synthetic tree; mode is owner-only.
    if unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) } != 0 {
        return Err("cannot make FIFO fixture".into());
    }
    b.add(
        "fifo-export-name",
        &["I4"],
        "Downloads/Bitwarden export.csv",
        "FIFO must not stall scan",
        "robustness",
    );
    let mut sparse = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(b.home.join("Downloads/vault-backup.json"))
        .map_err(|e| e.to_string())?;
    sparse
        .write_all(b"{\"encrypted\": false, \"items\": [")
        .map_err(|e| e.to_string())?;
    sparse
        .seek(SeekFrom::Start((large_mib as u64) * 1024 * 1024))
        .map_err(|e| e.to_string())?;
    sparse.write_all(b"]}\n").map_err(|e| e.to_string())?;
    b.add(
        "sparse-large-file",
        &["I4"],
        "Downloads/vault-backup.json",
        "Sparse oversized file",
        "robustness",
    );
    b.write(
        "Downloads/bitwarden_export_20260101.json",
        format!(
            "{{\"encrypted\": false, \"items\": {}\n",
            "[".repeat(200000)
        ),
    )?;
    b.add(
        "deep-nesting-json",
        &["I4"],
        "Downloads/bitwarden_export_20260101.json",
        "200000 nested arrays",
        "robustness",
    );
    b.write(
        "Downloads/backup.txt",
        format!("password={}!\n", "a".repeat(8 * 1024 * 1024)),
    )?;
    b.add(
        "long-line-redos",
        &["I4"],
        "Downloads/backup.txt",
        "8 MiB credential-like line",
        "robustness",
    );
    let member = format!("ARCHIVE-{}", random_hex()?);
    let slip = format!("ZIPSLIP-{}", random_hex()?);
    b.scope.extend([member.clone(), slip.clone()]);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let mut inner = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    inner
        .start_file(format!("zeros-{member}.bin"), options)
        .map_err(|e| e.to_string())?;
    let chunk = vec![0u8; 1024 * 1024];
    for _ in 0..bomb_mib {
        inner.write_all(&chunk).map_err(|e| e.to_string())?;
    }
    let inner = inner.finish().map_err(|e| e.to_string())?.into_inner();
    let mut outer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    outer
        .start_file(format!("nested-{member}.zip"), options)
        .map_err(|e| e.to_string())?;
    outer.write_all(&inner).map_err(|e| e.to_string())?;
    outer
        .start_file(format!("../../{slip}.txt"), options)
        .map_err(|e| e.to_string())?;
    outer.write_all(b"zip slip\n").map_err(|e| e.to_string())?;
    outer
        .start_file(format!("Chrome Passwords {member}.csv"), options)
        .map_err(|e| e.to_string())?;
    let pw = b.secret(random(ALNUM, 24)?, 0);
    outer
        .write_all(format!("name,url,username,password\nx,https://x.example,x,{pw}\n").as_bytes())
        .map_err(|e| e.to_string())?;
    b.write(
        "Downloads/passwords-export.zip",
        outer.finish().map_err(|e| e.to_string())?.into_inner(),
    )?;
    b.add(
        "archive-bomb-slip",
        &["I4", "I6"],
        "Downloads/passwords-export.zip",
        "Nested compressed ZIP bomb and zip-slip members",
        "robustness",
    );
    for name in [
        "git",
        "trufflehog",
        "gitleaks",
        "aws",
        "kubectl",
        "gcloud",
        "az",
        "docker",
        "security",
        "ssh-keygen",
        "op",
        "bw",
    ] {
        b.write_at(
            &b.hijack,
            name,
            format!(
                "#!/bin/sh\n: > '{}'\nexit 1\n",
                b.sentinels.join(format!("path-hijack-{name}")).display()
            ),
            0o755,
        )?;
    }
    b.add(
        "path-hijack",
        &["I1", "I3"],
        "../bin-hijack/",
        "Fake command binaries on scanner PATH",
        "execution",
    );
    b.secrets.sort();
    b.secrets.dedup();
    b.fragments.retain(|s| s.len() >= 10);
    b.fragments.sort();
    b.fragments.dedup();
    let manifest = json!({"schema":"loose-keys-security-fixtures/1","warning":"Contains synthetic secrets. Never pass this file to the scanner.","layout":{"scan_root":b.out.join("scan-root"),"home":b.home,"outside":b.outside,"sentinels":b.sentinels,"bin_hijack":b.hijack},"fixtures":b.fixtures,"forbidden":{"secrets":b.secrets,"fragment_sources":b.fragments,"fragment_window":10,"scope_tokens":b.scope},"forged_line_token":forged,"skipped":b.skipped});
    save(&b.out.join("manifest.json"), &manifest)?;
    save(
        &b.out.join("snapshot.json"),
        &snapshot(&[b.out.join("scan-root"), b.out.join("outside")])?,
    )?;
    println!(
        "fixtures: {} forbidden strings: {} skipped: {}",
        manifest["fixtures"].as_array().map_or(0, Vec::len),
        manifest["forbidden"]["secrets"]
            .as_array()
            .map_or(0, Vec::len),
        manifest["skipped"].as_array().map_or(0, Vec::len)
    );
    Ok(manifest)
}
