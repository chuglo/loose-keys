//! Synthetic home generation for manual checks, compiled only in the test harness.
use super::*;
const ALNUM: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
struct Builder {
    home: PathBuf,
    seed: u64,
    state: u64,
    targets: Vec<Value>,
    decoys: Vec<Value>,
    secrets: Vec<String>,
}
impl Builder {
    fn rand(&mut self, n: usize, alphabet: &str) -> String {
        let bytes = alphabet.as_bytes();
        (0..n)
            .map(|_| {
                self.state ^= self.state << 13;
                self.state ^= self.state >> 7;
                self.state ^= self.state << 17;
                bytes[(self.state % bytes.len() as u64) as usize] as char
            })
            .collect()
    }
    fn random(&mut self, n: usize) -> String {
        self.rand(n, ALNUM)
    }
    fn secret(&mut self, s: String) -> String {
        self.secrets.push(s.clone());
        s
    }
    fn value(&mut self, n: usize) -> String {
        let s = self.random(n);
        self.secret(s)
    }
    fn token(&mut self, prefix: &str, n: usize) -> String {
        let suffix = self.random(n);
        self.secret(format!("{prefix}{suffix}"))
    }
    fn github(&mut self) -> String {
        self.token(concat!("gh", "p_"), 36)
    }
    fn stripe(&mut self) -> String {
        self.token(concat!("sk", "_live_"), 48)
    }
    fn anthropic(&mut self) -> String {
        let body = self.random(93);
        self.secret(format!("{}{body}AA", concat!("sk-", "ant-api03-")))
    }
    fn openai(&mut self) -> String {
        let a = self.random(74);
        let b = self.random(74);
        self.secret(format!(
            "{}{}{}{}",
            concat!("sk-", "proj-"),
            a,
            concat!("T3Blbk", "FJ"),
            b
        ))
    }
    fn slack(&mut self) -> String {
        let a = self.rand(12, "0123456789");
        let b = self.rand(13, "0123456789");
        let c = self.random(24);
        self.secret(format!("{}-{a}-{b}-{c}", concat!("xox", "b")))
    }
    fn put(&self, rel: &str, data: impl AsRef<[u8]>, mode: u32) -> Result<PathBuf> {
        let path = self.home.join(rel);
        private_dir(path.parent().ok_or("synthetic home missing parent")?)?;
        write_private(&path, data.as_ref())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())?;
        Ok(path)
    }
    fn json(&self, rel: &str, value: Value, mode: u32) -> Result<()> {
        self.put(
            rel,
            serde_json::to_vec_pretty(&value).map_err(|_| "synthetic home JSON encoding")?,
            mode,
        )?;
        Ok(())
    }
    fn target(&mut self, id: &str, category: &str, what: &str, rel: &str, also: &[&str]) {
        let mut paths = vec![rel];
        paths.extend(also);
        self.targets
            .push(json!({"id":id,"category":category,"what":what,"paths":paths}));
    }
    fn decoy(&mut self, id: &str, what: &str, rel: &str) {
        self.decoys.push(json!({"id":id,"what":what,"paths":[rel]}));
    }
    fn run(&self, program: &str, args: &[&str]) -> Result<()> {
        let out = Command::new(program)
            .args(args)
            .env("HOME", &self.home)
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!("synthetic home fixture program {program} failed"));
        }
        Ok(())
    }
    fn sql(&self, rel: &str, sql: &str) -> Result<()> {
        let path = self.home.join(rel);
        private_dir(path.parent().ok_or("SQL missing parent")?)?;
        self.run("sqlite3", &[path.to_str().ok_or("SQL path encoding")?, sql])
    }
    fn pem(&self) -> Result<String> {
        let out = Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ])
            .env("HOME", &self.home)
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err("synthetic home RSA generation failed".into());
        }
        String::from_utf8(out.stdout).map_err(|_| "synthetic home PEM encoding".into())
    }
    fn noise(&self, n: usize) -> Result<Vec<u8>> {
        let mut data = vec![0; n];
        File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut data))
            .map_err(|e| e.to_string())?;
        Ok(data)
    }
}
pub(crate) fn generate(args: &[String]) -> Result<()> {
    let out = PathBuf::from(args.get(1).ok_or("synthetic home output required")?);
    let seed = option(args, "--seed")
        .unwrap_or("20261010")
        .parse::<u64>()
        .map_err(|_| "bad synthetic home seed")?;
    if fs::symlink_metadata(out.join("home")).is_ok() {
        return Err("synthetic home home already exists; choose a new output directory".into());
    }
    private_dir(&out)?;
    let out = fs::canonicalize(out).map_err(|e| e.to_string())?;
    let home = out.join("home");
    private_dir(&home)?;
    let mut b = Builder {
        home,
        seed,
        state: if seed == 0 { 0x9e3779b97f4a7c15 } else { seed },
        targets: vec![],
        decoys: vec![],
        secrets: vec![],
    };
    let chrome = "Library/Application Support/Google/Chrome/Default";
    b.sql(&format!("{chrome}/Login Data"),"CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR); CREATE TABLE logins(origin_url VARCHAR NOT NULL,username_value VARCHAR,password_value BLOB,signon_realm VARCHAR NOT NULL,date_created INTEGER NOT NULL,id INTEGER PRIMARY KEY AUTOINCREMENT); INSERT INTO logins(origin_url,username_value,password_value,signon_realm,date_created) VALUES ('https://mail.example.invalid','dana@example.invalid',x'763130a1b2c3d4e5f60718293a4b5c6d','https://mail.example.invalid',1),('https://bank.example.invalid','dana',x'7631300102030405060708090a0b0c0d','https://bank.example.invalid',2),('https://shop.example.invalid','dana@example.invalid',x'763130ffeeddccbbaa99887766554433','https://shop.example.invalid',3);")?;
    b.target(
        "browser-chrome-logins",
        "browser",
        "Passwords saved in Chrome (3 logins)",
        &format!("{chrome}/Login Data"),
        &[],
    );
    b.sql(&format!("{chrome}/Cookies"),"CREATE TABLE cookies(host_key TEXT,name TEXT,encrypted_value BLOB,expires_utc INTEGER); INSERT INTO cookies VALUES('.example.invalid','session',x'763130112233445566778899aabbccdd',99999999999999999);")?;
    b.target(
        "browser-chrome-cookies",
        "browser",
        "Chrome session cookies",
        &format!("{chrome}/Cookies"),
        &[],
    );
    let firefox = "Library/Application Support/Firefox/Profiles/x1y2z3.default-release";
    let user1 = b.random(40);
    let pw1 = b.random(40);
    let user2 = b.random(40);
    let pw2 = b.random(40);
    b.json(&format!("{firefox}/logins.json"),json!({"nextId":3,"logins":[{"id":1,"hostname":"https://mail.example.invalid","encryptedUsername":user1,"encryptedPassword":pw1},{"id":2,"hostname":"https://forum.example.invalid","encryptedUsername":user2,"encryptedPassword":pw2}]}),0o600)?;
    b.target(
        "browser-firefox-logins",
        "browser",
        "Passwords saved in Firefox (2 logins)",
        &format!("{firefox}/logins.json"),
        &[],
    );
    let mut rows = String::from("name,url,username,password\n");
    for i in 0..3 {
        rows.push_str(&format!(
            "site{i},https://site{i}.example.invalid,dana,{}\n",
            b.value(14)
        ));
    }
    b.put("Downloads/Chrome Passwords.csv", rows, 0o644)?;
    b.target(
        "export-csv",
        "password-export",
        "Browser password export left in Downloads",
        "Downloads/Chrome Passwords.csv",
        &[],
    );
    let pw = b.value(16);
    b.json("Documents/bitwarden_export_20260901.json",json!({"encrypted":false,"folders":[],"items":[{"id":"a1","name":"Mail","type":1,"login":{"username":"dana","password":pw}}]}),0o644)?;
    b.target(
        "export-bitwarden",
        "password-export",
        "Plaintext Bitwarden export",
        "Documents/bitwarden_export_20260901.json",
        &[],
    );
    let content = format!(
        "wifi: {}\nbank login dana / {}\nrouter admin password: {}\n",
        b.value(12),
        b.value(14),
        b.value(10)
    );
    b.put("Desktop/passwords.txt", content, 0o644)?;
    b.target(
        "notes-passwords",
        "password-export",
        "Passwords kept in a text note",
        "Desktop/passwords.txt",
        &[],
    );
    private_dir(&b.home.join(".ssh"))?;
    for (name, pass, id, what) in [
        (
            "id_ed25519",
            "",
            "ssh-key-plain",
            "SSH key with no passphrase",
        ),
        (
            "id_work",
            "synthetic-passphrase",
            "ssh-key-protected",
            "SSH key with a passphrase (lower risk; should be told apart)",
        ),
    ] {
        let path = b.home.join(format!(".ssh/{name}"));
        b.run(
            "ssh-keygen",
            &[
                "-q",
                "-t",
                "ed25519",
                "-N",
                pass,
                "-C",
                "fixture",
                "-f",
                path.to_str().ok_or("SSH path")?,
            ],
        )?;
        b.target(id, "private-key", what, &format!(".ssh/{name}"), &[]);
    }
    b.decoy("ssh-public-key", "SSH public key", ".ssh/id_ed25519.pub");
    fs::remove_file(b.home.join(".ssh/id_work.pub")).map_err(|e| e.to_string())?;
    let pem_path = b.home.join("Downloads/prod-server.pem");
    b.run(
        "openssl",
        &[
            "genrsa",
            "-out",
            pem_path.to_str().ok_or("PEM path")?,
            "2048",
        ],
    )?;
    b.target(
        "pem-key",
        "private-key",
        "TLS/RSA private key left in Downloads",
        "Downloads/prod-server.pem",
        &[],
    );
    let id = b.rand(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
    let id = b.secret(format!("AKIA{id}"));
    let pw = b.rand(40, &format!("{ALNUM}+ /").replace(' ', ""));
    let pw = b.secret(pw);
    b.put(
        ".aws/credentials",
        format!("[default]\naws_access_key_id = {id}\naws_secret_access_key = {pw}\n"),
        0o600,
    )?;
    b.target(
        "aws-static-keys",
        "cloud",
        "AWS static access keys",
        ".aws/credentials",
        &[],
    );
    b.put(".aws/config","[profile work]\nsso_start_url = https://example.invalid/start\nsso_region = us-east-1\nregion = us-east-1\n",0o600)?;
    b.decoy(
        "aws-sso-config",
        "AWS config using SSO only (no secret)",
        ".aws/config",
    );
    let client = b.value(24);
    let refresh = b.rand(100, &format!("{ALNUM}-_"));
    let refresh = b.secret(format!("1//0{refresh}"));
    b.json(".config/gcloud/application_default_credentials.json",json!({"type":"authorized_user","client_id":"123456789012-fixture.apps.googleusercontent.com","client_secret":client,"refresh_token":refresh}),0o600)?;
    b.target(
        "gcloud-login",
        "cloud",
        "gcloud stored sign-in (refresh token)",
        ".config/gcloud/application_default_credentials.json",
        &[],
    );
    let pem = b.pem()?;
    let keyid = b.rand(40, "0123456789abcdef");
    let clientid = b.rand(21, "0123456789");
    b.json("Downloads/acme-prod-4f1c2d.json",json!({"type":"service_account","project_id":"acme-prod","private_key_id":keyid,"private_key":pem,"client_email":"deploy@acme-prod.iam.gserviceaccount.com","client_id":clientid,"token_uri":"https://oauth2.googleapis.com/token"}),0o644)?;
    b.target(
        "gcp-service-account",
        "cloud",
        "Google service-account key left in Downloads",
        "Downloads/acme-prod-4f1c2d.json",
        &[],
    );
    let secret = b.rand(400, &format!("{ALNUM}-_"));
    let secret = b.secret(format!("0.{secret}"));
    b.json(".azure/msal_token_cache.json",json!({"RefreshToken":{"k":{"credential_type":"RefreshToken","secret":secret}},"Account":{}}),0o600)?;
    b.target(
        "azure-login",
        "cloud",
        "Azure CLI stored sign-in",
        ".azure/msal_token_cache.json",
        &[],
    );
    let secret = b.value(64);
    b.put(".kube/config",format!("apiVersion: v1\nkind: Config\nusers:\n- name: prod-admin\n  user:\n    token: {secret}\n"),0o600)?;
    b.target(
        "kube-token",
        "cloud",
        "Kubernetes token in kubeconfig",
        ".kube/config",
        &[],
    );
    let secret = format!("{}.atlasv1.{}", b.random(14), b.random(67));
    let secret = b.secret(secret);
    b.json(
        ".terraform.d/credentials.tfrc.json",
        json!({"credentials":{"app.terraform.io":{"token":secret}}}),
        0o600,
    )?;
    b.target(
        "terraform-token",
        "cloud",
        "Terraform Cloud token",
        ".terraform.d/credentials.tfrc.json",
        &[],
    );
    let secret = b.token("hvs.", 90);
    b.put(".vault-token", format!("{secret}\n"), 0o600)?;
    b.target("vault-token", "cloud", "Vault token", ".vault-token", &[]);
    b.put(".gitconfig","[user]\n\tname = Dana Fixture\n\temail = dana@example.invalid\n[credential]\n\thelper = store\n",0o644)?;
    let secret = b.github();
    b.put(
        ".git-credentials",
        format!("https://dana:{secret}@github.com\n"),
        0o600,
    )?;
    b.target(
        "git-credentials",
        "developer",
        "Git plaintext credential store",
        ".git-credentials",
        &[".gitconfig"],
    );
    let secret = b.token(concat!("gh", "o_"), 36);
    b.put(
        ".config/gh/hosts.yml",
        format!(
            "github.com:\n    user: dana\n    oauth_token: {secret}\n    git_protocol: https\n"
        ),
        0o600,
    )?;
    b.target(
        "gh-cli-token",
        "developer",
        "GitHub CLI token in plain text",
        ".config/gh/hosts.yml",
        &[],
    );
    let secret = b.token(concat!("npm", "_"), 36);
    b.put(
        ".npmrc",
        format!("//registry.npmjs.org/:_authToken={secret}\n"),
        0o600,
    )?;
    b.target("npm-token", "developer", "npm publish token", ".npmrc", &[]);
    let secret = b.token(concat!("pypi-", "AgEIcHlwaS5vcmc"), 120);
    b.put(
        ".pypirc",
        format!("[pypi]\nusername = __token__\npassword = {secret}\n"),
        0o600,
    )?;
    b.target(
        "pypi-token",
        "developer",
        "PyPI upload token",
        ".pypirc",
        &[],
    );
    let secret = b.token("cio", 32);
    b.put(
        ".cargo/credentials.toml",
        format!("[registry]\ntoken = \"{secret}\"\n"),
        0o600,
    )?;
    b.target(
        "cargo-token",
        "developer",
        "crates.io token",
        ".cargo/credentials.toml",
        &[],
    );
    let suffix = b.rand(48, "0123456789abcdef");
    let secret = b.secret(format!("rubygems_{suffix}"));
    b.put(
        ".gem/credentials",
        format!("---\n:rubygems_api_key: {secret}\n"),
        0o600,
    )?;
    b.target(
        "rubygems-key",
        "developer",
        "RubyGems API key",
        ".gem/credentials",
        &[],
    );
    let secret = b.value(24);
    b.put(
        ".netrc",
        format!("machine api.example.invalid\n  login dana\n  password {secret}\n"),
        0o600,
    )?;
    b.target(
        "netrc-password",
        "developer",
        "Password in .netrc",
        ".netrc",
        &[],
    );
    let raw = b.random(20);
    let secret = b.secret(fixtures::base64(format!("dana:{raw}").as_bytes()));
    b.json(
        ".docker/config.json",
        json!({"auths":{"https://index.docker.io/v1/":{"auth":secret}}}),
        0o600,
    )?;
    b.target(
        "docker-auth",
        "developer",
        "Docker registry password in config",
        ".docker/config.json",
        &[],
    );
    let id = b.rand(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
    let id = b.secret(format!("AKIA{id}"));
    let pw = b.rand(40, &format!("{ALNUM}+ /").replace(' ', ""));
    let pw = b.secret(pw);
    let stripe = b.stripe();
    let password = b.value(20);
    b.put("projects/shop/.env",format!("PORT=8080\nAWS_ACCESS_KEY_ID={id}\nAWS_SECRET_ACCESS_KEY={pw}\nSTRIPE_SECRET_KEY={stripe}\nDATABASE_PASSWORD={password}\n"),0o644)?;
    b.target(
        "dotenv",
        "secret-in-file",
        "Live keys in a project .env file",
        "projects/shop/.env",
        &[],
    );
    b.put("projects/shop/.env.example","PORT=8080\nAWS_ACCESS_KEY_ID=your-access-key-id\nAWS_SECRET_ACCESS_KEY=your-secret-access-key\nSTRIPE_SECRET_KEY=changeme\n",0o644)?;
    b.decoy(
        "dotenv-example",
        ".env.example with placeholders only",
        "projects/shop/.env.example",
    );
    let secret = b.github();
    b.put(".zsh_history",format!(": 1790000000:0;ls -la\n: 1790000100:0;export GITHUB_TOKEN={secret}\n: 1790000200:0;git push\n"),0o600)?;
    b.target(
        "shell-history",
        "secret-in-file",
        "Token typed into the shell (history file)",
        ".zsh_history",
        &[],
    );
    let secret = b.openai();
    b.put(
        ".zshrc",
        format!("export PATH=\"$HOME/bin:$PATH\"\nexport OPENAI_API_KEY=\"{secret}\"\n"),
        0o644,
    )?;
    b.target(
        "shell-rc",
        "secret-in-file",
        "API key exported from .zshrc",
        ".zshrc",
        &[],
    );
    let secret = b.slack();
    b.put(
        "Documents/notes/oncall.md",
        format!("# On-call\n\nSlack bot for alerts: {secret}\n"),
        0o644,
    )?;
    b.target(
        "token-in-notes",
        "secret-in-file",
        "Slack token pasted into notes",
        "Documents/notes/oncall.md",
        &[],
    );
    let mut filler = String::new();
    for i in 0..120 {
        filler.push_str(&format!(
            "// module {i}: {}\n",
            b.rand(60, "abcdefghijklmnopqrstuvwxyz ")
        ));
    }
    let secret = b.stripe();
    b.put(
        "projects/shop/src/billing.js",
        format!("{filler}const stripe = require(\"stripe\")(\"{secret}\");\n"),
        0o644,
    )?;
    b.target(
        "token-deep-in-file",
        "secret-in-file",
        "Token 8 KB into a source file",
        "projects/shop/src/billing.js",
        &[],
    );
    let secret = b.value(40);
    b.put(
        "projects/shop/config/settings.yaml",
        format!("service:\n  api_key: {secret}\n  timeout: 30\n"),
        0o644,
    )?;
    b.target(
        "generic-api-key",
        "secret-in-file",
        "API key with no recognizable vendor format",
        "projects/shop/config/settings.yaml",
        &[],
    );
    let secret = b.value(22);
    b.put("projects/shop/settings.py",format!("DATABASES = {{\"default\": \"postgres://shop:{secret}@db.example.invalid:5432/shop\"}}\n"),0o644)?;
    b.target(
        "database-url",
        "secret-in-file",
        "Database URL with an inline password",
        "projects/shop/settings.py",
        &[],
    );
    let repo = b.home.join("projects/api");
    private_dir(&repo.join("config"))?;
    let repo = repo.to_str().ok_or("git path")?.to_owned();
    b.run("git", &["init", "-q", &repo])?;
    let secret = b.github();
    b.put(
        "projects/api/config/deploy.yml",
        format!("deploy:\n  github_token: {secret}\n"),
        0o600,
    )?;
    let git = [
        "-C",
        &repo,
        "-c",
        "user.name=Dana Fixture",
        "-c",
        "user.email=dana@example.invalid",
        "-c",
        "commit.gpgsign=false",
    ];
    let mut args = git.to_vec();
    args.extend(["add", "."]);
    b.run("git", &args)?;
    let mut args = git.to_vec();
    args.extend(["commit", "-q", "-m", "add deploy config"]);
    b.run("git", &args)?;
    fs::write(
        b.home.join("projects/api/config/deploy.yml"),
        "deploy:\n  github_token: ${GITHUB_TOKEN}\n",
    )
    .map_err(|e| e.to_string())?;
    let mut args = git.to_vec();
    args.extend(["commit", "-q", "-am", "read token from environment"]);
    b.run("git", &args)?;
    b.target(
        "git-history",
        "secret-in-file",
        "Token removed from a repo but still in its git history",
        "projects/api/config/deploy.yml",
        &["projects/api/.git"],
    );
    let secret = b.value(40);
    b.json(".cursor/mcp.json",json!({"mcpServers":{"tracker":{"command":"npx","args":["-y","tracker-mcp"],"env":{"TRACKER_API_KEY":secret}}}}),0o644)?;
    b.target(
        "mcp-cursor",
        "ai-tool",
        "Secret in a Cursor MCP server config",
        ".cursor/mcp.json",
        &[],
    );
    let secret = b.github();
    b.json("Library/Application Support/Claude/claude_desktop_config.json",json!({"mcpServers":{"github":{"command":"npx","args":["-y","server-github"],"env":{"GITHUB_PERSONAL_ACCESS_TOKEN":secret}}}}),0o644)?;
    b.target(
        "mcp-claude-desktop",
        "ai-tool",
        "Token in the Claude desktop MCP config",
        "Library/Application Support/Claude/claude_desktop_config.json",
        &[],
    );
    let access = b.rand(200, &format!("{ALNUM}-_"));
    let access = b.secret(access);
    let refresh = b.token("rt_", 80);
    b.json(
        ".codex/auth.json",
        json!({"OPENAI_API_KEY":null,"tokens":{"access_token":access,"refresh_token":refresh}}),
        0o600,
    )?;
    b.target(
        "ai-cli-login",
        "ai-tool",
        "AI coding CLI stored sign-in",
        ".codex/auth.json",
        &[],
    );
    let secret = b.anthropic();
    b.put(
        "projects/shop/.anthropic",
        format!("ANTHROPIC_API_KEY={secret}\n"),
        0o644,
    )?;
    b.target(
        "ai-api-key",
        "ai-tool",
        "AI provider API key in a project file",
        "projects/shop/.anthropic",
        &[],
    );
    b.sql(&format!("{chrome}/Web Data"),"CREATE TABLE credit_cards(guid VARCHAR PRIMARY KEY,name_on_card VARCHAR,card_number_encrypted BLOB); INSERT INTO credit_cards VALUES('a1','Dana Fixture',x'763130aabbccddeeff00112233445566'),('b2','Dana Fixture',x'76313000112233445566778899aabbcc');")?;
    b.target(
        "browser-chrome-cards",
        "browser",
        "Payment cards saved in Chrome",
        &format!("{chrome}/Web Data"),
        &[],
    );
    let wallet = format!("{chrome}/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn");
    b.put(&format!("{wallet}/000003.log"), b.noise(256)?, 0o600)?;
    b.target(
        "wallet-extension",
        "wallet",
        "MetaMask extension vault in a Chrome profile",
        &wallet,
        &[],
    );
    b.put(
        "Library/Application Support/Exodus/exodus.wallet/seed.seco",
        b.noise(512)?,
        0o600,
    )?;
    b.target(
        "wallet-desktop",
        "wallet",
        "Exodus desktop wallet data",
        "Library/Application Support/Exodus/exodus.wallet",
        &[],
    );
    b.put(
        "Desktop/wallet backup.txt",
        concat!(
            "metamask\nvelvet winner thank year wave sausage ",
            "worth useful legal winner thank yellow\n"
        ),
        0o644,
    )?;
    b.target(
        "wallet-recovery-phrase",
        "wallet",
        "Wallet recovery phrase in a text file",
        "Desktop/wallet backup.txt",
        &[],
    );
    b.put(
        "Library/Application Support/Telegram Desktop/tdata/key_datas",
        b.noise(256)?,
        0o600,
    )?;
    b.target(
        "telegram-session",
        "app-session",
        "Telegram Desktop session",
        "Library/Application Support/Telegram Desktop/tdata/key_datas",
        &["Library/Application Support/Telegram Desktop/tdata"],
    );
    let mut keepass = vec![0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5];
    keepass.extend(b.noise(512)?);
    b.put("Documents/Passwords.kdbx", keepass, 0o600)?;
    b.target(
        "keepass-db",
        "password-export",
        "KeePass password database in Documents",
        "Documents/Passwords.kdbx",
        &[],
    );
    let raw = b.random(16);
    let secret = b.secret(fixtures::base64(raw.as_bytes()));
    b.put(".config/filezilla/sitemanager.xml",format!("<?xml version=\"1.0\"?>\n<FileZilla3><Servers><Server>\n<Host>ftp.example.invalid</Host>\n<User>deploy</User>\n<Pass encoding=\"base64\">{secret}</Pass>\n</Server></Servers></FileZilla3>\n"),0o600)?;
    b.target(
        "filezilla",
        "app-session",
        "Server password saved by FileZilla",
        ".config/filezilla/sitemanager.xml",
        &[],
    );
    let pem = b.pem()?;
    b.put(
        "Downloads/work.ovpn",
        format!("client\nremote vpn.example.invalid 1194\n<key>\n{pem}</key>\n"),
        0o644,
    )?;
    b.target(
        "vpn-profile",
        "app-session",
        "VPN profile with an embedded private key",
        "Downloads/work.ovpn",
        &[],
    );
    b.put(
        "Library/Group Containers/group.com.apple.notes/NoteStore.sqlite",
        b.noise(4096)?,
        0o600,
    )?;
    b.target(
        "apple-notes",
        "other",
        "Apple Notes database",
        "Library/Group Containers/group.com.apple.notes/NoteStore.sqlite",
        &[],
    );
    b.put("Library/Keychains/login.keychain-db", b.noise(2048)?, 0o600)?;
    b.target(
        "keychain-db",
        "other",
        "Login keychain database",
        "Library/Keychains/login.keychain-db",
        &[],
    );
    let secret = b.github();
    b.put(
        "projects/api/.npmrc",
        format!("//npm.pkg.github.com/:_authToken={secret}\n"),
        0o644,
    )?;
    b.target(
        "project-npmrc",
        "developer",
        "Token in a project-level .npmrc",
        "projects/api/.npmrc",
        &[],
    );
    let secret = b.value(32);
    b.put(
        "projects/shop/.envrc",
        format!("export DEPLOY_API_KEY={secret}\n"),
        0o644,
    )?;
    b.target(
        "envrc",
        "secret-in-file",
        "Secret in a direnv .envrc",
        "projects/shop/.envrc",
        &[],
    );
    let secret = b.value(24);
    b.put(
        "projects/infra/terraform.tfvars",
        format!("db_password = \"{secret}\"\nregion = \"us-east-1\"\n"),
        0o644,
    )?;
    b.target(
        "tfvars",
        "secret-in-file",
        "Secret in terraform.tfvars",
        "projects/infra/terraform.tfvars",
        &[],
    );
    let secret = b.token(concat!("vc", "p_"), 56);
    b.put(".local/share/fish/fish_history",format!("- cmd: ls\n  when: 1790000000\n- cmd: set -gx VERCEL_TOKEN {secret}\n  when: 1790000100\n"),0o600)?;
    b.target(
        "fish-history",
        "secret-in-file",
        "Token typed into fish (history file)",
        ".local/share/fish/fish_history",
        &[],
    );
    let access = b.rand(120, &format!("{ALNUM}-_"));
    let access = b.secret(access);
    let refresh = b.rand(120, &format!("{ALNUM}-_"));
    let refresh = b.secret(refresh);
    b.json(".aws/sso/cache/3f1c9a.json",json!({"startUrl":"https://example.invalid/start","region":"us-east-1","accessToken":access,"refreshToken":refresh,"expiresAt":"2026-10-11T00:00:00Z"}),0o600)?;
    b.target(
        "aws-sso-cache",
        "cloud",
        "AWS single sign-on session cache",
        ".aws/sso/cache/3f1c9a.json",
        &[],
    );
    let secret = b.token("1//0", 90);
    b.sql(".config/gcloud/credentials.db",&format!("CREATE TABLE credentials(account_id TEXT PRIMARY KEY,value BLOB); INSERT INTO credentials VALUES('dana@example.invalid','{{\"refresh_token\": \"{secret}\"}}');"))?;
    b.target(
        "gcloud-store",
        "cloud",
        "gcloud's own sign-in database",
        ".config/gcloud/credentials.db",
        &[],
    );
    let secret = b.rand(40, &format!("{ALNUM}~._-"));
    let secret = b.secret(secret);
    b.json(
        ".azure/service_principal_entries.json",
        json!([{"client_id":"0f1e2d3c","tenant":"9a8b7c6d","client_secret":secret}]),
        0o600,
    )?;
    b.target(
        "azure-service-principal",
        "cloud",
        "Azure service principal secret",
        ".azure/service_principal_entries.json",
        &[],
    );
    let secret = b.token("glpat-", 20);
    b.put(
        "Library/Application Support/glab-cli/config.yml",
        format!("hosts:\n  gitlab.com:\n    token: {secret}\n    api_protocol: https\n"),
        0o600,
    )?;
    b.target(
        "glab-token",
        "developer",
        "GitLab CLI token in plain text",
        "Library/Application Support/glab-cli/config.yml",
        &[],
    );
    let secret = b.value(24);
    b.json(
        "Library/Application Support/com.vercel.cli/auth.json",
        json!({"token":secret}),
        0o600,
    )?;
    b.target(
        "vercel-login",
        "developer",
        "Vercel CLI stored sign-in",
        "Library/Application Support/com.vercel.cli/auth.json",
        &[],
    );
    let secret = b.value(20);
    b.put(
        ".pgpass",
        format!("db.example.invalid:5432:shop:shop_admin:{secret}\n"),
        0o600,
    )?;
    b.target(
        "pgpass",
        "developer",
        "Database password in .pgpass",
        ".pgpass",
        &[],
    );
    let secret = b.value(24);
    b.put(".m2/settings.xml",format!("<settings><servers><server>\n<id>releases</id>\n<username>deploy</username>\n<password>{secret}</password>\n</server></servers></settings>\n"),0o644)?;
    b.target(
        "maven-settings",
        "developer",
        "Repository password in Maven settings",
        ".m2/settings.xml",
        &[],
    );
    let secret = b.value(24);
    b.put(
        ".config/pip/pip.conf",
        format!("[global]\nindex-url = https://deploy:{secret}@pypi.example.invalid/simple\n"),
        0o644,
    )?;
    b.target(
        "pip-conf",
        "developer",
        "Password inside a URL in pip.conf",
        ".config/pip/pip.conf",
        &[],
    );
    let q = b.rand(64, "0123456789ABCDEF");
    let d = b.rand(64, "0123456789ABCDEF");
    let d = b.secret(d);
    b.put(
        ".gnupg/private-keys-v1.d/0A1B2C3D4E5F60718293A4B5C6D7E8F901234567.key",
        format!("Key: (private-key (ecc (curve Ed25519)(flags eddsa)(q #40{q}#)(d #{d}#)))\n"),
        0o600,
    )?;
    b.target(
        "gpg-key",
        "private-key",
        "GnuPG private key with no passphrase",
        ".gnupg/private-keys-v1.d/0A1B2C3D4E5F60718293A4B5C6D7E8F901234567.key",
        &[],
    );
    let secret = b.token(concat!("sk", "_test_"), 48);
    b.put(
        "projects/shop/.env.test",
        format!("STRIPE_SECRET_KEY={secret}\n"),
        0o644,
    )?;
    b.target(
        "stripe-test-key",
        "secret-in-file",
        "Stripe test-mode key (should be told apart from a live key)",
        "projects/shop/.env.test",
        &[],
    );
    let agent = b.github();
    let mut session = String::new();
    for _ in 0..4000 {
        let text = b.rand(60, "abcdefghijklmnopqrstuvwxyz ");
        session.push_str(&format!(
            "{}\n",
            json!({"type":"assistant","text":format!("ordinary session content {text}")})
        ));
    }
    let content = format!(
        "{session}{}\n{session}",
        json!({"type":"tool_use","name":"Bash","input":{"command":format!("curl -H 'Authorization: Bearer {agent}' https://api.example.invalid/repos")}})
    );
    b.put(
        ".claude/projects/-Users-dana-projects-api/7c1e0a52.jsonl",
        content,
        0o600,
    )?;
    b.target(
        "claude-session",
        "ai-agent-record",
        "Token inside a Claude Code session record (0.5 MB into a 1 MB file)",
        ".claude/projects/-Users-dana-projects-api/7c1e0a52.jsonl",
        &[],
    );
    let mut rollout = String::new();
    for _ in 0..2000 {
        let content = b.rand(80, "abcdefghijklmnopqrstuvwxyz ");
        rollout.push_str(&format!(
            "{}\n",
            json!({"type":"message","content":content})
        ));
    }
    let secret = b.stripe();
    rollout.push_str(&format!("{}\n",json!({"type":"exec_output","stdout":format!("AWS_SECRET loaded\nexport STRIPE_KEY={secret}")})));
    b.put(
        ".codex/sessions/2026/10/09/rollout-2026-10-09T10-00-00-abc.jsonl",
        rollout,
        0o600,
    )?;
    b.target(
        "codex-session",
        "ai-agent-record",
        "Token inside a Codex session record",
        ".codex/sessions/2026/10/09/rollout-2026-10-09T10-00-00-abc.jsonl",
        &[],
    );
    let secret = b.github();
    b.json("projects/api/.claude/settings.local.json",json!({"permissions":{"allow":[format!("Bash(curl -H 'Authorization: Bearer {secret}' https://api.github.com/user)")]}}),0o644)?;
    b.target(
        "claude-settings-local",
        "ai-agent-record",
        "Token recorded in an allowed-command entry",
        "projects/api/.claude/settings.local.json",
        &[],
    );
    let secret = b.anthropic();
    b.json(
        ".claude/settings.json",
        json!({"env":{"ANTHROPIC_API_KEY":secret}}),
        0o644,
    )?;
    b.target(
        "claude-settings-env",
        "ai-tool",
        "API key set in an AI tool's settings file",
        ".claude/settings.json",
        &[],
    );
    let key = b.value(48);
    let suffix = b.rand(64, "0123456789abcdef");
    let openrouter = b.secret(format!("{}{}", concat!("sk-or", "-v1-"), suffix));
    b.json(
        ".cline/data/secrets.json",
        json!({"apiKey":key,"openRouterApiKey":openrouter}),
        0o600,
    )?;
    b.target(
        "cline-secrets",
        "ai-tool",
        "AI extension's key store in a plain file",
        ".cline/data/secrets.json",
        &[],
    );
    let secret = b.slack();
    b.put("projects/shop/scripts/check_deploy.sh",format!("#!/bin/sh\n# one-off script written during a session\ncurl -s -H \"Authorization: Bearer {secret}\" https://slack.example.invalid/api/auth.test\n"),0o755)?;
    b.target(
        "agent-script",
        "ai-agent-record",
        "One-off script left with a token inline",
        "projects/shop/scripts/check_deploy.sh",
        &[],
    );
    b.put(
        "projects/shop/README.md",
        concat!(
            "## AWS setup\n\nUse keys like `AKIA",
            "IOSFODNN7EXAMPLE` and\n`wJalrXUtnFEMI/K7MDENG/bPxRfiCY",
            "EXAMPLEKEY` (AWS's documented samples).\n"
        ),
        0o644,
    )?;
    b.decoy(
        "docs-example-key",
        "AWS's documentation sample keys in a README",
        "projects/shop/README.md",
    );
    let mut packages = serde_json::Map::new();
    for i in 0..40 {
        let integrity = b.rand(86, &format!("{ALNUM}+ /").replace(' ', ""));
        packages.insert(
            format!("node_modules/pkg{i}"),
            json!({"version":"1.0.0","integrity":format!("sha512-{integrity}==")}),
        );
    }
    b.json(
        "projects/shop/package-lock.json",
        json!({"lockfileVersion":3,"packages":packages}),
        0o644,
    )?;
    b.decoy(
        "lockfile-hashes",
        "package-lock.json integrity hashes",
        "projects/shop/package-lock.json",
    );
    let mappings = b.random(400);
    b.json("projects/shop/dist/app.js.map",json!({"version":3,"names":["url","username","password","token","apiKey"],"mappings":mappings}),0o644)?;
    b.decoy(
        "source-map",
        "Source map naming url/username/password",
        "projects/shop/dist/app.js.map",
    );
    b.put(
        "Documents/contacts.csv",
        "name,email,notes\nSam,sam@example.invalid,met at conference\n",
        0o644,
    )?;
    b.decoy(
        "contacts-csv",
        "CSV that is not a password export",
        "Documents/contacts.csv",
    );
    let hash = b.rand(40, "0123456789abcdef");
    b.put(
        "projects/shop/test/fixtures.js",
        format!(
            "const fakeToken = \"{}{}\"; // placeholder\nconst commit = \"{hash}\";\n",
            concat!("gh", "p_"),
            "x".repeat(36)
        ),
        0o644,
    )?;
    b.decoy(
        "test-placeholder",
        "Placeholder token and a commit hash in a test file",
        "projects/shop/test/fixtures.js",
    );
    b.put("Documents/essay.txt","The actor was able to abandon the absurd abuse about an hour ago, and access to the account was above all an accident. Nobody could absorb such an abstract idea across the whole afternoon, again and again.\n",0o644)?;
    b.decoy(
        "prose-with-list-words",
        "Ordinary prose using words from the recovery-phrase list",
        "Documents/essay.txt",
    );
    let ordinary = format!("{chrome}/Local Extension Settings/cjpalhdlnbpafiamejdnhcphjbkeiagm");
    b.put(&format!("{ordinary}/000003.log"), b.noise(128)?, 0o600)?;
    b.decoy(
        "ordinary-extension",
        "A browser extension that is not a wallet",
        &ordinary,
    );
    b.put(
        "Documents/todo.txt",
        "Reminder: change my password: tomorrow\nAsk IT about the wifi password\n",
        0o644,
    )?;
    b.decoy(
        "note-about-passwords",
        "A note that mentions passwords but holds none",
        "Documents/todo.txt",
    );
    b.put(
        "projects/shop/docs/tokens.md",
        format!(
            "Tokens look like `{}{}` or `{}_live_...`.\n",
            concat!("gh", "p_"),
            "x".repeat(36),
            "sk"
        ),
        0o644,
    )?;
    b.decoy(
        "docs-token-shapes",
        "Documentation describing token formats",
        "projects/shop/docs/tokens.md",
    );
    let mut uuids = String::new();
    for _ in 0..30 {
        uuids.push_str(&format!(
            "{}-{}-4{}-a{}-{}\n",
            b.rand(8, "0123456789abcdef"),
            b.rand(4, "0123456789abcdef"),
            b.rand(3, "0123456789abcdef"),
            b.rand(3, "0123456789abcdef"),
            b.rand(12, "0123456789abcdef")
        ));
    }
    b.put("Documents/uuids.txt", uuids, 0o644)?;
    b.decoy("uuid-list", "List of UUIDs", "Documents/uuids.txt");
    b.json(
        ".docker/daemon.json",
        json!({"experimental":false,"builder":{"gc":{"enabled":true}}}),
        0o644,
    )?;
    b.decoy(
        "docker-daemon-config",
        "Docker config with no credentials",
        ".docker/daemon.json",
    );
    b.put(
        "projects/shop/settings.example.py",
        "DATABASES = {\"default\": \"postgres://user:password@localhost:5432/app\"}\n",
        0o644,
    )?;
    b.decoy(
        "placeholder-db-url",
        "Database URL with the literal word 'password'",
        "projects/shop/settings.example.py",
    );
    for dir in ["Documents/reports", "projects/shop/src/lib", "Pictures"] {
        for i in 0..60 {
            let text = b.rand(80, "abcdefghijklmnopqrstuvwxyz ");
            b.put(
                &format!("{dir}/file-{i:02}.txt"),
                format!("ordinary synthetic content {text}\n"),
                0o644,
            )?;
        }
    }
    let manifest = json!({"seed":b.seed,"targets":b.targets,"decoys":b.decoys,"secrets":b.secrets});
    save(&out.join("manifest.json"), &manifest)?;
    println!(
        "{} targets, {} decoys, {} planted values -> {}",
        b.targets.len(),
        b.decoys.len(),
        b.secrets.len(),
        b.home.display()
    );
    Ok(())
}
