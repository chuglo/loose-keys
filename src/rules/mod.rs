//! Detection rules, grouped by family. Each rule defines its report text,
//! targets, matcher and test samples. Scan scope and limits live in `scan.rs`
//! and `scan/`; scanned files are opened through `fsutil.rs`.

mod ai;
mod apps;
mod aws;
pub mod browser;
mod cloud;
mod docker;
mod env;
mod gh;
mod git;
mod logins;
mod npm;
mod password_export;
mod private_key;
mod registry;
mod sqlite;
mod token;
mod wallet;

#[cfg(test)]
#[path = "../../tests/support/detection_registry.rs"]
mod detection_registry;
#[cfg(test)]
#[path = "../../tests/support/fixture_body.rs"]
pub(crate) mod fixture_body;

use crate::fsutil::Gap;

/// Where a rule looks. Paths are relative to the home folder.
#[derive(Clone, Copy, PartialEq)]
pub enum Target {
    /// Every regular file under the scanned folders, by its first 4 KiB.
    Discovery,
    /// Each file directly in one folder, by its first 4 KiB.
    Dir(&'static str),
    /// One config file, read whole (1 MiB max).
    File(&'static str),
    /// The named file in each direct subfolder of a folder, read whole.
    Each(&'static str, &'static str),
    /// Discovered files with this name, read whole whatever their head holds.
    /// A leading or trailing `*` matches anything: ".env*", "*.tfvars".
    Name(&'static str),
    /// The named file in every profile of every Chromium-family browser.
    Profiles(&'static str),
    /// A browser extension's storage folder in any Chromium profile, by
    /// extension ID, and what the extension is.
    Extension(&'static str, &'static str),
    /// A file or folder whose presence is the finding, and what it is.
    Present(&'static str, &'static str),
    /// Every file under a folder, each read in full, up to 256 MiB. For the
    /// session records and logs AI agents keep, where a secret can be anywhere.
    Tree(&'static str),
    /// The named file in the `.git` folder of each repository discovery
    /// passes, read whole. Nothing else in that folder is read.
    Repo(&'static str),
}

impl Target {
    pub fn names(&self, file: &std::ffi::OsStr) -> bool {
        use std::os::unix::ffi::OsStrExt;
        let Target::Name(pattern) = self else {
            return false;
        };
        // By bytes: APFS takes only UTF-8 names, another volume may not
        // (unverified).
        let file = file.as_bytes();
        if let Some(suffix) = pattern.strip_prefix('*') {
            return file.ends_with(suffix.as_bytes()) && file.len() > suffix.len();
        }
        match pattern.strip_suffix('*') {
            Some(prefix) => file.starts_with(prefix.as_bytes()),
            None => file == pattern.as_bytes(),
        }
    }

    /// Named by a pattern, not an exact name: such files are common, so one
    /// too large to read whole is passed over, not reported as a gap.
    pub fn names_loosely(&self, file: &std::ffi::OsStr) -> bool {
        matches!(self, Target::Name(p) if p.starts_with('*')) && self.names(file)
    }
}

/// How to remove the exposure: ordered steps, and where the issuer revokes it.
#[derive(Clone, Copy, PartialEq)]
pub struct Advice {
    pub steps: &'static [&'static str],
    pub link: Option<&'static str>,
}

impl Advice {
    pub const NONE: Advice = Advice {
        steps: &[],
        link: None,
    };
}

/// What a finding says in place of its rule's text, where a match is a kind
/// the rule's own words don't fit. Its rule's id, kind and severity stay.
#[derive(Clone, Copy, PartialEq)]
pub struct Wording {
    pub explanation: &'static str,
    pub reason: Option<&'static str>,
    pub next_step: Option<&'static str>,
    pub advice: Advice,
}

/// One match. Never holds a secret value.
#[derive(Default)]
pub struct Hit {
    /// None for a whole-file match.
    pub line: Option<usize>,
    /// What the match concerns: a profile, host, variable name or token type.
    pub subject: Option<String>,
    /// Issuer-specific advice, when the match identifies its issuer.
    pub advice: Option<&'static Advice>,
    /// Text and advice in place of the rule's, for a match its words don't fit.
    pub wording: Option<&'static Wording>,
    /// The kind of token, from the scanner's fixed list. Unlike `subject`,
    /// this is never read from the file, so reports may include it.
    pub token_type: Option<&'static str>,
    /// The issuer's page, when the rule's own steps apply but the page differs.
    pub link: Option<&'static str>,
    /// Where the secret sits in the bytes that were tested: a position, not
    /// a value. Lets the scanner tell two different secrets apart.
    pub span: Option<std::ops::Range<usize>>,
    /// Registry key bytes used only for keyed place identity, never display.
    pub scope: Option<std::ops::Range<usize>>,
    /// A count or other detail that can change while the finding stays the
    /// same finding, such as how many logins a browser has saved. Shown, but
    /// not part of what identifies the finding.
    pub detail: Option<String>,
    /// A format its issuer declares to be for testing. Listed at low risk
    /// and never brought up for review on its own.
    pub low: bool,
}

impl Hit {
    pub fn file() -> Hit {
        Hit::default()
    }

    pub fn line(line: usize) -> Hit {
        Hit {
            line: Some(line),
            ..Hit::default()
        }
    }

    pub fn about(mut self, subject: &str) -> Hit {
        self.subject = label(subject);
        self
    }

    /// As `at`, but for a registry key that may itself hold credentials.
    pub fn scoped(mut self, text: &str, key: &str) -> Hit {
        self.scope = Hit::file().at(text, key).span;
        self
    }

    pub fn noting(mut self, detail: &str) -> Hit {
        self.detail = label(detail);
        self
    }

    /// Where the secret sits: `value` must be a piece of `text`, and `text`
    /// the file as it was read, so the position is one in the file.
    pub fn at(mut self, text: &str, value: &str) -> Hit {
        let start = (value.as_ptr() as usize).wrapping_sub(text.as_ptr() as usize);
        self.span = start
            .checked_add(value.len())
            .filter(|end| *end <= text.len())
            .map(|end| start..end);
        self
    }
}

/// Context that is safe to show: short and printable. Callers pass names and
/// hosts only, never a field that stores a secret.
pub fn label(s: &str) -> Option<String> {
    let s = s.trim();
    (!s.is_empty()
        && s.len() <= 80
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" ._-:/@".contains(&b)))
    .then(|| s.to_string())
}

/// A registry URL's host and optional port, or no label when an at-sign
/// after the authority could be unescaped userinfo. Never show URL tails.
/// This is conservative display extraction, not URL validation.
fn url_host(value: &str) -> &str {
    let value = value.strip_prefix("//").unwrap_or(value);
    let end = value.find(['/', '?', '#']).unwrap_or(value.len());
    if value[end..].contains('@') || value.contains('\\') {
        return "";
    }
    let authority = &value[..end];
    authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host)
}

/// Complete matches, or an incomplete check with any matches already found.
/// A capped matcher looks at one candidate past its cap, so filling the cap
/// exactly is complete and only an omitted match is `scan-limit`. A cap is not
/// resumable work: checking the same file again cannot get past it, so a
/// recheck never takes an incomplete result as evidence of removal.
pub type Hits = Result<Vec<Hit>, Incomplete>;

pub struct Incomplete {
    pub reason: Gap,
    pub hits: Vec<Hit>,
}

impl From<Gap> for Incomplete {
    fn from(reason: Gap) -> Self {
        Self {
            reason,
            hits: Vec::new(),
        }
    }
}

impl std::fmt::Debug for Incomplete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Match subjects can come from files. Debug exposes only fixed text and a count.
        f.debug_struct("Incomplete")
            .field("reason", &self.reason)
            .field("hits", &self.hits.len())
            .finish()
    }
}

/// Keep the existing match budget, and look for one more match before
/// declaring it incomplete. Exactly `max` matches is still a complete check.
fn capped_hits(hits: impl IntoIterator<Item = Hit>, max: usize) -> Hits {
    let mut hits = hits.into_iter();
    let kept = hits.by_ref().take(max).collect();
    if hits.next().is_some() {
        Err(Incomplete {
            reason: "scan-limit",
            hits: kept,
        })
    } else {
        Ok(kept)
    }
}

#[derive(Clone, Copy)]
pub enum Matcher {
    /// Tested on a file's first 4 KiB.
    Head(fn(&[u8]) -> bool),
    /// Tested on the whole file, which is read only if `candidate` accepts the head.
    Whole {
        candidate: fn(&[u8]) -> bool,
        test: fn(&[u8]) -> Hits,
    },
    /// Tested on consecutive pieces of a file of any size, split at line
    /// ends. Gets each piece and the line number it starts at.
    Stream(fn(&[u8], usize) -> Hits),
    /// Nothing is read: the target being there is the match.
    Present,
}

/// One thing the scanner looks for: what it reports, where it looks, how it
/// matches, and samples that exercise the matcher.
pub struct Rule {
    pub id: &'static str,
    pub category: &'static str,
    pub kind: &'static str,
    /// "high": works from any computer until revoked. "medium": needs more to
    /// use, or unlocks less. "low": protected or short-lived.
    pub severity: &'static str,
    pub title: &'static str,
    pub explanation: &'static str,
    pub reason: Option<&'static str>,
    pub next_step: Option<&'static str>,
    pub advice: Advice,
    pub targets: &'static [Target],
    pub matcher: Matcher,
    /// (file content, should match). Each rule needs at least one of each.
    pub samples: &'static [(&'static [u8], bool)],
}

/// Every rule, in the order each file is checked.
pub const RULES: &[Rule] = &[
    password_export::PASSWORD_EXPORT,
    private_key::SSH_KEY_NO_PASSPHRASE,
    private_key::SSH_KEY,
    password_export::BITWARDEN_EXPORT,
    password_export::ONEPASSWORD_EXPORT,
    password_export::ONEPASSWORD_1PIF_EXPORT,
    token::SERVICE_TOKEN,
    cloud::GCP_SERVICE_ACCOUNT,
    env::SHELL_SECRET,
    env::ENV_SECRET,
    docker::DOCKER_AUTH,
    aws::AWS_KEYS,
    git::GIT_CREDENTIALS,
    gh::GH_TOKEN,
    npm::NPM_CREDENTIALS,
    cloud::KUBE_CREDENTIALS,
    cloud::KUBE_ANYWHERE,
    cloud::TERRAFORM_STATE,
    cloud::GCLOUD_LOGIN,
    cloud::AZURE_LOGIN,
    cloud::AZURE_LEGACY_LOGIN,
    cloud::TERRAFORM_TOKEN,
    cloud::VAULT_TOKEN,
    registry::PYPI_PASSWORD,
    registry::CARGO_TOKEN,
    registry::GEM_KEY,
    logins::AZURE_SERVICE_PRINCIPAL,
    logins::AZURE_LEGACY_PRINCIPAL,
    logins::COMPOSER_AUTH,
    logins::MAVEN_PASSWORD,
    logins::BUNDLER_CREDENTIALS,
    logins::URL_PASSWORD,
    logins::CLI_LOGIN,
    logins::AWS_SESSION,
    cloud::GCLOUD_STORE,
    private_key::GPG_KEY_UNPROTECTED,
    private_key::GPG_KEY,
    apps::DBEAVER_PASSWORDS,
    registry::NETRC_PASSWORD,
    registry::PGPASS_PASSWORD,
    registry::MYCNF_PASSWORD,
    registry::WAREHOUSE_PASSWORD,
    ai::MCP_SECRET,
    ai::CODEX_MCP,
    ai::CONTINUE_YAML,
    ai::AI_TOOL_LOGIN,
    ai::OAUTH_TOKENS,
    browser::CHROMIUM_LOGINS,
    browser::CHROMIUM_CARDS,
    browser::FIREFOX_LOGINS,
    wallet::RECOVERY_PHRASE,
    wallet::WALLET_EXTENSION,
    wallet::DESKTOP_WALLET,
    wallet::HARDWARE_WALLET_APP,
    apps::TELEGRAM_SESSION,
    apps::FILEZILLA_PASSWORD,
    apps::RCLONE_SECRET,
    apps::RCLONE_LOGIN,
    apps::VPN_PROFILE_KEY,
    apps::WIREGUARD_KEY,
    apps::PASSWORD_NOTE,
    apps::KEEPASS_DATABASE,
    token::AGENT_RECORD,
];

/// What each rule looks for and where, for --list-rules.
pub fn rule_list() -> String {
    let mut s = String::new();
    let mut seen = Vec::new();
    for r in RULES {
        if seen.contains(&r.id) {
            continue;
        }
        seen.push(r.id);
        // Rules that share an id are one kind of finding in several places.
        let same = RULES.iter().filter(|other| other.id == r.id);
        let mut places: Vec<String> = same
            .flat_map(|other| other.targets)
            .map(|t| match t {
                Target::Discovery => "any file in the scanned folders".to_string(),
                Target::Dir(d) => format!("~/{d}/*"),
                Target::File(f) => format!("~/{f}"),
                Target::Each(d, f) => format!("~/{d}/*/{f}"),
                Target::Name(n) => format!("any file named {n}"),
                Target::Profiles(f) => format!("{f} in each Chromium-family browser profile"),
                Target::Extension(_, what) => format!("{what} extension storage"),
                Target::Present(p, _) => format!("~/{p}"),
                Target::Tree(d) => format!("every file under ~/{d}"),
                Target::Repo(f) => format!(".git/{f} in each repository"),
            })
            .collect();
        let mut listed = Vec::new();
        places.retain(|place| !listed.contains(place) && (listed.push(place.clone()), true).1);
        s.push_str(&format!(
            "{}\n   {}\n   Looks in: {}\n",
            r.id,
            r.title,
            places.join(", ")
        ));
    }
    s
}

/// Whether a link is one of the fixed issuer pages in the rules, so stored
/// state can never make the app open anything else.
pub fn known_link(url: &str) -> bool {
    RULES
        .iter()
        .filter_map(|r| r.advice.link)
        .chain(token::links())
        .chain(wordings().filter_map(|w| w.advice.link))
        .any(|link| link == url)
}

/// The text findings can give in place of their rule's.
pub fn wordings() -> impl Iterator<Item = &'static Wording> {
    [&aws::TEMPORARY_KEYS].into_iter()
}

/// The token providers' names, which token findings give as their subject.
pub fn token_names() -> impl Iterator<Item = &'static str> {
    token::names()
}

/// The rule for service tokens in any file, whose formats the rule for
/// agents' records also looks for.
pub const SERVICE_TOKEN_ID: &str = token::SERVICE_TOKEN.id;

/// Whether `rule` is one of the two that find a token in a known format in
/// any file: in files at large, or in an agent's records.
pub fn finds_tokens_anywhere(rule: &str) -> bool {
    rule == token::SERVICE_TOKEN.id || rule == token::AGENT_RECORD.id
}

/// The steps a token finding's advice gives, whichever provider issued it.
pub fn token_steps() -> &'static [&'static str] {
    token::STEPS
}

fn any(_: &[u8]) -> bool {
    true
}

/// Transient matched material for keyed GUI fingerprints. Never export this.
pub fn material(rule: &str, bytes: &[u8]) -> Vec<u8> {
    if rule == "dev.docker.inline-auth" {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) {
            let mut pairs: Vec<_> = v["auths"]
                .as_object()
                .into_iter()
                .flat_map(|a| a.iter())
                .flat_map(|(registry, auth)| {
                    docker::credentials(auth).map(move |(field, value)| {
                        if field == "auth" {
                            // Keep existing auth-only fingerprints unchanged.
                            vec![registry.as_str(), value]
                        } else {
                            // Distinguish tokens from auth and from each other.
                            vec![registry.as_str(), field, value]
                        }
                    })
                })
                .collect();
            pairs.sort();
            return serde_json::to_vec(&pairs).unwrap();
        }
    }
    if rule == "export.password-bitwarden-json" {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) {
            let mut logins: Vec<_> = v["items"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|i| i["type"].as_u64() == Some(1))
                .filter_map(|i| {
                    i["login"]["password"]
                        .as_str()
                        .filter(|p| !p.is_empty())
                        .map(|p| {
                            [
                                i["id"].as_str().unwrap_or(""),
                                i["login"]["username"].as_str().unwrap_or(""),
                                p,
                            ]
                        })
                })
                .collect();
            logins.sort();
            return serde_json::to_vec(&logins).unwrap();
        }
    }
    // Files that tools rewrite as they run: the secrets alone.
    let secrets = match rule {
        "dev.mcp.inline-secret" => ai::mcp_material(bytes),
        "dev.terraform.state-secret" => cloud::tfstate_material(bytes),
        "app.rclone.stored-secret" => apps::rclone_material(bytes, false),
        "app.rclone.stored-login" => apps::rclone_material(bytes, true),
        _ => None,
    };
    if let Some(secrets) = secrets {
        return secrets;
    }
    // Rules share an id where one kind of finding has files in more than one
    // format. The one that matches this file is the one that reported it.
    let mut tests = RULES
        .iter()
        .filter(|r| r.id == rule)
        .filter_map(|r| match r.matcher {
            Matcher::Whole { test, .. } => Some(test),
            _ => None,
        })
        .peekable();
    if tests.peek().is_some() {
        let mut matched =
            tests.map(|test| test(bytes).unwrap_or_else(|incomplete| incomplete.hits));
        let hits = matched.find(|hits| !hits.is_empty()).unwrap_or_default();
        let text = String::from_utf8_lossy(bytes);
        let lines: Vec<_> = text.lines().collect();
        let mut fields = Vec::new();
        // A count is a detail of the finding. The place identifies it, so
        // a browser saving one more login is not a change to report.
        if !hits.is_empty() && hits.iter().all(|h| h.line.is_none() && h.detail.is_some()) {
            return Vec::new();
        }
        if hits.iter().any(|h| h.line.is_none()) {
            return bytes.to_vec();
        }
        // The lines the hits are on, in the order of the file, each once: a
        // line can hold many hits, and is copied once for them all.
        let mut found: Vec<usize> = hits
            .into_iter()
            .filter_map(|h| {
                // A key in a .env file can run over several lines, each of
                // them part of it.
                let more = match (rule, &h.span) {
                    ("secret.env-assignment", Some(span)) => bytes
                        .get(span.clone())
                        .map_or(0, |value| value.iter().filter(|b| **b == b'\n').count()),
                    _ => 0,
                };
                Some(h.line?..=h.line?.checked_add(more)?)
            })
            .flatten()
            .collect();
        found.sort_unstable();
        found.dedup();
        for (nth, line) in found.iter().copied().enumerate() {
            let Some(raw) = lines.get(line.saturating_sub(1)) else {
                continue;
            };
            if rule == "dev.aws.inline-credentials" {
                for raw in lines
                    .iter()
                    .skip(line)
                    .take_while(|s| !s.trim().starts_with('['))
                {
                    if let Some((key, value)) = raw.split_once('=') {
                        let key = key.trim().to_ascii_lowercase();
                        if [
                            "aws_access_key_id",
                            "aws_secret_access_key",
                            "aws_session_token",
                        ]
                        .contains(&key.as_str())
                        {
                            if let Some(value) = scalar_literal_by(value, raw_literal) {
                                fields.push(vec![
                                    lines[line - 1].trim().to_string(),
                                    key,
                                    value.to_string(),
                                ]);
                            }
                        }
                    }
                }
            } else if rule == "app.openvpn.embedded-key" {
                // The hit is the line that opens the key; the key follows it,
                // up to the end of its block or the next key found, so no
                // line is taken for more than one key.
                let next = found.get(nth + 1).map_or(usize::MAX, |next| *next);
                let key = lines.iter().skip(line - 1).take(next.saturating_sub(line));
                fields.push(
                    key.take_while(|l| l.trim() != "</key>")
                        .map(|l| l.trim().to_string())
                        .collect(),
                );
            } else if let Some(close) = match rule {
                "dev.maven.settings-password" => Some("</password"),
                "app.filezilla.saved-password" => Some("</Pass"),
                _ => None,
            } {
                // The value may stand on lines of its own after the tag that
                // opens it: up to the tag that closes it, or the next hit.
                let next = found.get(nth + 1).map_or(usize::MAX, |next| *next);
                let lines = lines.iter().skip(line.saturating_sub(1));
                let mut value = Vec::new();
                for l in lines.take(next.saturating_sub(line).max(1)) {
                    value.push(l.trim().to_string());
                    if l.contains(close) {
                        break;
                    }
                }
                fields.push(value);
            } else if !matches!(rule, "dev.gh.inline-token" | "dev.npm.inline-credentials") {
                fields.push(vec![raw.trim().to_string()]);
            } else {
                // Yarn writes "npmAuthToken: value", .npmrc "name=value".
                let yarn = raw
                    .trim_start_matches('\u{feff}')
                    .trim_start()
                    .starts_with("npmAuth");
                let separator = if rule == "dev.gh.inline-token" || yarn {
                    ':'
                } else {
                    '='
                };
                // As the rules judge them: YAML for gh and Yarn, raw for .npmrc.
                let literal = if separator == ':' {
                    unexpanded_literal
                } else {
                    raw_literal
                };
                if let Some((key, value)) = raw.split_once(separator) {
                    if let Some(value) = scalar_literal_by(value, literal) {
                        fields.push(vec![key.trim().to_string(), value.to_string()]);
                    }
                }
            }
        }
        fields.sort();
        fields.dedup();
        return serde_json::to_vec(&fields).unwrap();
    }
    // CSV detection is header-only. Key and export file changes are conservative.
    bytes.to_vec()
}

fn json_hits(bytes: &[u8], test: fn(&serde_json::Value) -> bool) -> Hits {
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(v) if test(&v) => Ok(vec![Hit::file()]),
        Ok(_) => Ok(vec![]),
        Err(_) => Err("unreadable".into()),
    }
}

/// Line-based CLI configs must be UTF-8; anything else is a gap. So many
/// matches are listed, as `capped_hits` keeps them, so a planted file cannot
/// fill the findings one scan keeps.
fn utf8_lines(bytes: &[u8], parser: fn(&str) -> Vec<Hit>) -> Hits {
    utf8_text(bytes, |text| capped_hits(parser(text), 100))
}

/// A text config, which must be UTF-8: anything else is a gap. A byte order
/// mark is not part of the first line, so `parser` gets the text after it,
/// and the positions it gives are moved to be ones in the file.
fn utf8_text(bytes: &[u8], parser: impl FnOnce(&str) -> Hits) -> Hits {
    let text = std::str::from_utf8(bytes).map_err(|_| "unreadable")?;
    let body = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mark = text.len() - body.len();
    let in_file = |hits: Vec<Hit>| -> Vec<Hit> {
        let moved = |s: std::ops::Range<usize>| s.start + mark..s.end + mark;
        hits.into_iter()
            .map(|mut hit| {
                hit.span = hit.span.map(moved);
                hit.scope = hit.scope.map(moved);
                hit
            })
            .collect()
    };
    match parser(body) {
        Ok(hits) => Ok(in_file(hits)),
        Err(Incomplete { reason, hits }) => Err(Incomplete {
            reason,
            hits: in_file(hits),
        }),
    }
}

/// A stored value that is not an obvious placeholder or sample.
fn plausible(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let mut distinct: Vec<u8> = lower.bytes().collect();
    distinct.sort_unstable();
    distinct.dedup();
    distinct.len() >= 5
        && ![
            "example",
            "changeme",
            "placeholder",
            "your_",
            "your-",
            "xxxx",
            "dummy",
            "redacted",
        ]
        .iter()
        .any(|p| lower.contains(p))
}

/// A name, in capitals, for a key that is public by design: one half of a
/// key pair, or a publishable key a web page carries.
fn public_key_name(upper: &str) -> bool {
    [
        "PUBLIC_KEY",
        "PUBLICKEY",
        "PUB_KEY",
        "PUBKEY",
        "PUBLISHABLE_KEY",
        "PUBLISHABLEKEY",
    ]
    .iter()
    .any(|suffix| upper.ends_with(suffix))
}

/// Where a file is, not a secret: "~/.ssh/id_ed25519", "./server.key",
/// "$HOME/.ssh/id_rsa", a path from a folder at the root of a Mac, a name
/// with a key or credential file's extension, an SSH key's file name such as
/// "id_ed25519_work", or a path through folders in small letters, as in
/// "/app/.ssh/id_rsa", ".ssh/id_ed25519" or "keys/signing". A secret seldom
/// starts with "/" and is in small letters alone; a password can have a "/"
/// anywhere else.
fn path_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let key_file = [
        ".json",
        ".pem",
        ".key",
        ".p8",
        ".p12",
        ".pfx",
        ".crt",
        ".der",
        ".jks",
        ".keystore",
        ".gpg",
        ".asc",
    ]
    .iter()
    .any(|extension| lower.ends_with(extension));
    let small = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
    };
    let small_path = |path: &str| path.contains('/') && path.split('/').all(small);
    let rooted = value.strip_prefix('/').is_some_and(small_path);
    // From the current folder, a path needs more than small letters to tell
    // it from a password: a hidden folder, a folder keys are kept in, or an
    // SSH key's file name.
    let relative = small_path(value)
        && value.split('/').next().is_some_and(|first| {
            first.starts_with('.') || ["keys", "certs", "secrets", "ssl", "tls"].contains(&first)
        });
    let ssh_key_file = value.rsplit('/').next().is_some_and(|name| {
        small(name)
            && ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"]
                .iter()
                .any(|key| name.starts_with(key))
    }) && value.split('/').all(small);
    key_file
        || rooted
        || relative
        || ssh_key_file
        || [
            "~/",
            "./",
            "../",
            "$HOME/",
            "${HOME}/",
            "/Users/",
            "/Volumes/",
            "/private/",
            "/var/",
            "/tmp/",
            "/etc/",
            "/opt/",
            "/usr/",
            "/Library/",
            "/System/",
            "/home/",
            "/run/",
        ]
        .iter()
        .any(|start| value.starts_with(start))
}

/// Lines "name: value" or "name = value" with a literal value, where the name
/// is one of `keys` or says it holds a secret. Each hit is labelled with the name.
fn keyed_secret_lines(text: &str, keys: &[&str]) -> Vec<Hit> {
    text.lines()
        .enumerate()
        .filter_map(|(i, raw)| {
            let line = raw.trim().trim_start_matches("- ");
            if line.starts_with(['#', ';', '[']) {
                return None;
            }
            let (name, value) = line.split_once([':', '='])?;
            let name = name.trim().trim_matches(['"', '\'']);
            let lower = name.to_ascii_lowercase();
            let secret_name = ["key", "token", "secret", "password", "passwd"]
                .iter()
                .any(|word| lower.ends_with(word));
            let value = scalar_literal_by(value.trim().trim_end_matches(','), unexpanded_literal)?;
            ((keys.contains(&name) || secret_name) && value.len() >= 8 && plausible(value))
                .then(|| Hit::line(i + 1).about(name).at(text, value))
        })
        .collect()
}

/// Nonempty literal strings stored under any of `keys`, at any depth.
fn json_has_secret(v: &serde_json::Value, keys: &[&str]) -> bool {
    match v {
        serde_json::Value::Object(o) => o.iter().any(|(k, v)| {
            (keys.contains(&k.as_str())
                && v.as_str().is_some_and(|s| {
                    s.len() >= 16 && unexpanded_literal(s, Some('"')) && plausible(s)
                }))
                || json_has_secret(v, keys)
        }),
        serde_json::Value::Array(a) => a.iter().any(|v| json_has_secret(v, keys)),
        _ => false,
    }
}

/// Visit XML tags and their scalar text without expanding entities or loading
/// a DTD. This reads the scalar subset used by Maven and FileZilla, not all XML.
/// False when the text stops inside a tag, comment or declaration: what
/// follows that point was not visited.
fn xml_tags(text: &str, mut visit: impl FnMut(&str, &str, &str, usize)) -> bool {
    let mut rest = text;
    let mut line = 1;
    while let Some(start) = rest.find('<') {
        line += rest[..start].bytes().filter(|b| *b == b'\n').count();
        rest = &rest[start..];
        let skip = if rest.starts_with("<!--") {
            Some(("-->", 3))
        } else if rest.starts_with("<![CDATA[") {
            Some(("]]>", 3))
        } else if rest.starts_with("<?") {
            Some(("?>", 2))
        } else {
            None
        };
        if let Some((end, width)) = skip {
            let Some(end) = rest.find(end) else {
                return false;
            };
            let consumed = end + width;
            line += rest[..consumed].bytes().filter(|b| *b == b'\n').count();
            rest = &rest[consumed..];
            continue;
        }
        let mut quote = None;
        let mut brackets = 0usize;
        let declaration = rest.starts_with("<!");
        let mut end = 1;
        while end < rest.len() {
            // Declaration comments can contain brackets and apparent tags.
            if declaration && quote.is_none() && rest.as_bytes()[end..].starts_with(b"<!--") {
                let Some(width) = rest[end + 4..].find("-->") else {
                    return false;
                };
                end += 4 + width + 3;
                continue;
            }
            let c = rest.as_bytes()[end];
            match (quote, c) {
                (Some(q), c) if q == c => quote = None,
                (None, b'\'' | b'"') => quote = Some(c),
                (None, b'[') if declaration => brackets += 1,
                (None, b']') if declaration => brackets = brackets.saturating_sub(1),
                (None, b'>') if brackets == 0 => break,
                _ => {}
            }
            end += 1;
        }
        if end == rest.len() {
            return false;
        }
        let tag = rest[1..end].trim();
        let (name, attributes) = tag.split_once(char::is_whitespace).unwrap_or((tag, ""));
        let after = &rest[end + 1..];
        let mut closing = after;
        let mut value = std::borrow::Cow::Borrowed("");
        if !declaration {
            loop {
                let width = closing.find('<').unwrap_or(closing.len());
                let part = &closing[..width];
                if value.is_empty() {
                    value = std::borrow::Cow::Borrowed(part);
                } else if !part.is_empty() {
                    value.to_mut().push_str(part);
                }
                closing = &closing[width..];
                if !closing.starts_with("<!--") {
                    break;
                }
                let Some(end) = closing[4..].find("-->") else {
                    break;
                };
                closing = &closing[4 + end + 3..];
            }
        }
        // Only paired scalar elements have values; self-closing and nested
        // elements must not borrow text from a different element.
        let paired = closing
            .strip_prefix("</")
            .and_then(|s| s.strip_prefix(name))
            .is_some_and(|s| s.trim_start().starts_with('>'));
        if !declaration {
            visit(
                name,
                attributes,
                if paired { value.trim() } else { "" },
                line,
            );
        }
        line += rest[..end + 1].bytes().filter(|b| *b == b'\n').count();
        rest = after;
    }
    true
}

/// What an XML rule found, as `capped_hits` lists it, where `whole` says
/// whether `xml_tags` read the file to its end. One it did not is a gap,
/// with what was found before the point it stopped at.
fn xml_hits(hits: Vec<Hit>, whole: bool) -> Hits {
    let hits = capped_hits(hits, 100);
    if whole {
        return hits;
    }
    Err(Incomplete {
        reason: "unreadable",
        hits: hits.unwrap_or_else(|incomplete| incomplete.hits),
    })
}

fn xml_attribute<'a>(mut attributes: &'a str, wanted: &str) -> Option<&'a str> {
    while !attributes.trim_start().is_empty() {
        let (name, rest) = attributes.trim_start().split_once('=')?;
        let rest = rest.trim_start();
        let quote = rest.chars().next().filter(|c| matches!(c, '\'' | '"'))?;
        let end = rest[1..].find(quote)? + 1;
        if name.trim() == wanted {
            return Some(&rest[1..end]);
        }
        attributes = &rest[end + 1..];
    }
    None
}

/// A literal, single-line secret candidate, never a reference, in a format
/// that takes text as it is: one that expands no "$" or "`", and where a
/// leading "!" or "&" is not a YAML tag or anchor. A template's "${...}"
/// still stands in for a value there. The rules for shell files add their
/// own quoting rules to this (`env.rs`).
fn verbatim_literal(s: &str) -> bool {
    !s.is_empty()
        && !s.contains("${")
        && !s.chars().any(char::is_whitespace)
        && !s.starts_with(['<', '*'])
        // "op://" is a 1Password reference, which "op run" fills in, and
        // "ENC[" opens a value sops encrypted.
        && !["env:", "file:", "keychain:", "op://", "ENC["]
            .iter()
            .any(|prefix| s.starts_with(prefix))
}

/// As `verbatim_literal`, given the quote that held the value, in a format
/// that expands nothing, as JSON, TOML and YAML do. Only an unquoted YAML
/// value that opens with "!" or "&" is a tag or an anchor, not text.
fn unexpanded_literal(s: &str, quote: Option<char>) -> bool {
    verbatim_literal(s) && (quote.is_some() || !s.starts_with(['!', '&']))
}

/// As `verbatim_literal`, for a value `scalar_literal_by` read, quoted or
/// not, in a file read raw, as INI is: a leading "!" is text there.
fn raw_literal(s: &str, _quote: Option<char>) -> bool {
    verbatim_literal(s)
}

/// Parse the single-line scalar subset emitted by these CLI configs, with
/// `literal` judging the value, given the quote that held it, if any. No
/// YAML tags, aliases, collections, block scalars, interpolation or shell
/// execution.
fn scalar_literal_by(raw: &str, literal: fn(&str, Option<char>) -> bool) -> Option<&str> {
    let raw = raw.trim();
    if raw.starts_with(['#', ';']) {
        return None;
    }
    let quote = raw.chars().next().filter(|c| matches!(c, '\'' | '"'));
    let value = if let Some(quote) = quote {
        let end = raw[1..].find(quote)? + 1;
        let rest = raw[end + 1..].trim();
        if !rest.is_empty() && !rest.starts_with('#') {
            return None;
        }
        &raw[1..end]
    } else {
        raw.split_once(" #").map_or(raw, |(value, _)| value).trim()
    };
    (literal(value, quote)
        && !value.starts_with(['|', '>', '{', '['])
        && !matches!(value, "null" | "Null" | "NULL" | "~" | "true" | "false"))
    .then_some(value)
}

#[cfg(test)]
mod rule_samples {
    use super::*;

    #[test]
    fn registry_url_labels_omit_ambiguous_tails() {
        let mut unsafe_rules = Vec::new();
        for rule in [registry::GEM_KEY, logins::BUNDLER_CREDENTIALS] {
            let Matcher::Whole { test, .. } = rule.matcher else {
                unreachable!()
            };
            for (url, expected) in [
                (
                    "https://fixture:synthetic%2Fpass@registry.invalid/scope",
                    Some("registry.invalid"),
                ),
                (
                    "https://fixture:synthetic/pass@registry.invalid/scope",
                    None,
                ),
                ("https://registry.invalid/path@synthetic-tail", None),
                (
                    concat!("https://registry.invalid", "?query", "@synthetic-tail"),
                    None,
                ),
                (
                    concat!("https://registry.invalid", "#fragment", "@synthetic-tail"),
                    None,
                ),
                (
                    "https://registry.invalid:8443/scope",
                    Some("registry.invalid:8443"),
                ),
            ] {
                let body = if rule.id == "dev.rubygems.inline-key" {
                    format!("{url}: synthetic-stored-value\n")
                } else {
                    format!("BUNDLE_{url}: synthetic-stored-value\n")
                };
                let hits = test(body.as_bytes()).unwrap();
                assert_eq!(hits.len(), 1, "ambiguous labels must not remove findings");
                if hits[0].subject.as_deref() != expected {
                    unsafe_rules.push(rule.id);
                }
            }
        }
        assert!(
            unsafe_rules.is_empty(),
            "unsafe URL rules: {unsafe_rules:?}"
        );
    }

    #[test]
    fn incomplete_debug_excludes_match_labels() {
        let incomplete = Incomplete {
            reason: "scan-limit",
            hits: vec![Hit::file().about("synthetic-private-label")],
        };
        let shown = format!("{incomplete:?}");
        assert!(shown.contains("scan-limit"));
        assert!(!shown.contains("synthetic-private-label"));
    }

    fn xml_layout(rule: Rule, root: &str, entry: &str, name: &str, password: &str) {
        let Matcher::Whole { test, .. } = rule.matcher else {
            panic!("XML rules read whole files");
        };
        for separator in ["", "\n  "] {
            let xml = format!(
                    "<{root}><{entry}>{separator}<{name}>fixture.invalid</{name}>{separator}<{password}>synthetic-only</{password}></{entry}></{root}>"
                );
            let hits = test(xml.as_bytes()).unwrap();
            assert_eq!(hits.len(), 1, "{}: layout", rule.id);
            assert_eq!(hits[0].line, Some(if separator.is_empty() { 1 } else { 3 }));
            assert_eq!(hits[0].subject.as_deref(), Some("fixture.invalid"));
        }
        let xml = format!(
            "<{root}><{entry}><{name}>first.invalid</{name}><{password}>synthetic-first</{password}></{entry}><{entry}><{password}>synthetic-second</{password}></{entry}></{root}>"
        );
        let hits = test(xml.as_bytes()).unwrap();
        assert_eq!(hits.len(), 2, "{}: two entries", rule.id);
        assert_eq!(hits[0].subject.as_deref(), Some("first.invalid"));
        assert_eq!(hits[1].subject, None, "subject must not cross entries");
    }

    #[test]
    fn maven_xml_passwords_do_not_depend_on_line_layout() {
        xml_layout(
            logins::MAVEN_PASSWORD,
            "settings",
            "server",
            "id",
            "password",
        );
    }

    #[test]
    fn filezilla_xml_passwords_do_not_depend_on_line_layout() {
        xml_layout(
            apps::FILEZILLA_PASSWORD,
            "FileZilla3",
            "Server",
            "Host",
            "Pass",
        );
    }

    /// A file that stops inside a tag, a comment or a declaration was not
    /// read to its end: what is found before that point is kept, and the
    /// file is a gap, not a complete list.
    #[test]
    fn xml_that_stops_inside_a_tag_is_a_gap() {
        for (rule, entry, name, password) in [
            (logins::MAVEN_PASSWORD, "server", "id", "password"),
            (apps::FILEZILLA_PASSWORD, "Server", "Host", "Pass"),
        ] {
            let Matcher::Whole { test, .. } = rule.matcher else {
                panic!("XML rules read whole files");
            };
            let first = format!(
                "<{entry}><{name}>a.invalid</{name}><{password}>synthetic-one</{password}></{entry}>\n"
            );
            let second = format!("<{password}>synthetic-two</{password}></{entry}>\n");
            for stop in [
                format!("<{entry} note=\"unclosed>"),
                format!("<{entry} note='unclosed>"),
                "<!-- unclosed comment ".to_string(),
                "<![CDATA[ unclosed".to_string(),
                "<?xml unclosed".to_string(),
                "<!DOCTYPE x [<!-- unclosed ]>".to_string(),
            ] {
                // Also where nothing follows.
                for xml in [format!("{first}{stop}{second}"), format!("{first}{stop}")] {
                    let incomplete = test(xml.as_bytes()).err().expect(&stop);
                    assert_eq!(incomplete.reason, "unreadable", "{}: {stop}", rule.id);
                    let found: Vec<_> = incomplete
                        .hits
                        .iter()
                        .map(|h| (h.line, h.subject.as_deref()))
                        .collect();
                    assert_eq!(found, [(Some(1), Some("a.invalid"))], "{}: {stop}", rule.id);
                }
            }
            let xml = format!("{first}<{entry}");
            let incomplete = test(xml.as_bytes()).err().expect("a tag left open");
            assert_eq!(
                (incomplete.reason, incomplete.hits.len()),
                ("unreadable", 1)
            );
            // A quote inside a value or a closed attribute ends nothing.
            let xml = format!(
                "{first}<{entry} note=\"it's\"><{password}>synthetic-two'</{password}></{entry}>\n"
            );
            assert_eq!(test(xml.as_bytes()).unwrap().len(), 2, "{}", rule.id);
        }
    }

    /// A byte order mark is not part of the first line: it neither hides
    /// what the line holds nor joins its label, and the positions of values
    /// stay ones in the file.
    #[test]
    fn a_byte_order_mark_is_not_part_of_the_first_line() {
        for (rule, body) in [
            (
                git::GIT_CREDENTIALS,
                "https://fixture:synthetic-only@git.example.invalid\n",
            ),
            (
                registry::PYPI_PASSWORD,
                "[pypi]\npassword = synthetic-only\n",
            ),
            (
                registry::PYPI_PASSWORD,
                "[pypi-token]\nfixture-repo = \"synthetic-only\"\n",
            ),
            (
                registry::NETRC_PASSWORD,
                "machine fixture.invalid login fixture password synthetic-only\n",
            ),
            (
                apps::RCLONE_SECRET,
                "[fixture]\ntype = sftp\npass = c3ludGhldGljLW9ubHk\n",
            ),
            (
                registry::WAREHOUSE_PASSWORD,
                "[connections]\npassword = synthetic-only\n",
            ),
            (registry::GEM_KEY, ":rubygems_api_key: synthetic-only\n"),
            (cloud::KUBE_CREDENTIALS, "password: synthetic-only\n"),
            (
                gh::GH_TOKEN,
                "github.com:\n    oauth_token: synthetic-only\n",
            ),
        ] {
            let Matcher::Whole { test, .. } = rule.matcher else {
                panic!("{} reads whole files", rule.id);
            };
            let shown = |file: &str| -> Vec<_> {
                test(file.as_bytes())
                    .unwrap()
                    .into_iter()
                    .map(|h| {
                        let value = h.span.clone().map(|s| file[s].to_string());
                        let key = h.scope.clone().map(|s| file[s].to_string());
                        (h.line, h.subject, value, key)
                    })
                    .collect()
            };
            let plain = shown(body);
            assert_eq!(plain.len(), 1, "{}: {body}", rule.id);
            assert_eq!(shown(&format!("\u{feff}{body}")), plain, "{}", rule.id);
        }
    }

    #[test]
    fn maven_xml_comments_do_not_hide_scalar_text() {
        let Matcher::Whole { test, .. } = logins::MAVEN_PASSWORD.matcher else {
            panic!("XML rule reads whole files");
        };
        for value in [
            "synthetic-only<!-- note -->",
            "<!-- note -->synthetic-only",
            "synthetic-<!-- note -->only<!-- note -->",
        ] {
            let xml =
                format!("<settings><server>\n<password>{value}</password>\n</server></settings>");
            let hits = test(xml.as_bytes()).unwrap();
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].line, Some(2));
        }
        assert!(test(b"<password><!-- note --></password>")
            .unwrap()
            .is_empty());
        assert!(test(b"<password>$<!-- note -->{env.PASSWORD}</password>")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn filezilla_xml_comments_do_not_hide_scalar_text() {
        let Matcher::Whole { test, .. } = apps::FILEZILLA_PASSWORD.matcher else {
            panic!("XML rule reads whole files");
        };
        for value in [
            "synthetic-only<!-- note -->",
            "<!-- note -->synthetic-only",
            "synthetic-<!-- note -->only<!-- note -->",
        ] {
            let xml = format!("<FileZilla3><Server>\n<Pass>{value}</Pass>\n</Server></FileZilla3>");
            let hits = test(xml.as_bytes()).unwrap();
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].line, Some(2));
        }
        assert!(test(b"<Pass><!-- note --></Pass>").unwrap().is_empty());
        assert!(
            test(b"<Pass encoding='crypt'>synthetic-only<!-- note --></Pass>")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn xml_doctype_comments_do_not_expose_decoys() {
        for (rule, root, password) in [
            (logins::MAVEN_PASSWORD, "settings", "password"),
            (apps::FILEZILLA_PASSWORD, "FileZilla3", "Pass"),
        ] {
            let Matcher::Whole { test, .. } = rule.matcher else {
                panic!("XML rule reads whole files");
            };
            let declaration =
                format!("<!DOCTYPE {root} [<!-- ]> <{password}>synthetic-only</{password}> -->]>");
            let xml = format!("{declaration}<{root}/>");
            assert!(
                test(xml.as_bytes()).unwrap().is_empty(),
                "{}: DTD decoy",
                rule.id
            );
            let xml =
                format!("{declaration}\n<{root}><{password}>synthetic-only</{password}></{root}>");
            let hits = test(xml.as_bytes()).unwrap();
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].line, Some(2));
        }
    }

    #[test]
    fn xml_comments_have_bounded_read_cost() {
        let xml = format!(
            "<!DOCTYPE settings [{}]><password>{}</password>",
            "<!-- ]> <password>decoy</password> -->".repeat(10_000),
            "synthetic<!-- note -->".repeat(20_000)
        );
        assert!(xml.len() < 1024 * 1024);
        let started = std::time::Instant::now();
        let mut found = 0;
        xml_tags(&xml, |name, _, value, _| {
            if name == "password" {
                found += 1;
                assert_eq!(value.len(), "synthetic".len() * 20_000);
            }
        });
        assert_eq!(found, 1);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "XML comment read exceeded its deadline"
        );
    }

    #[test]
    fn xml_attributes_with_long_trailing_space_are_read_once() {
        let attributes = format!(
            "{}encoding='crypt'{}",
            "note='fixture' ".repeat(10_000),
            " ".repeat(800_000)
        );
        let started = std::time::Instant::now();
        assert_eq!(xml_attribute(&attributes, "encoding"), Some("crypt"));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "XML attribute read exceeded its deadline"
        );
    }

    /// The command's report shows the findings of one rule id and reason as
    /// one entry, with the first one's text. Rules that share an id and say
    /// different things must differ in their reason, or one file gets the
    /// other's advice.
    #[test]
    fn rules_shown_as_one_entry_say_the_same_thing() {
        let mut mixed: Vec<&str> = Vec::new();
        for a in RULES {
            for b in RULES
                .iter()
                .filter(|b| b.id == a.id && b.reason == a.reason)
            {
                let same = a.title == b.title
                    && a.explanation == b.explanation
                    && a.next_step == b.next_step
                    && a.advice.steps == b.advice.steps;
                if !same && !mixed.contains(&a.id) {
                    mixed.push(a.id);
                }
            }
        }
        assert_eq!(mixed, Vec::<&str>::new(), "two texts under one reason");
    }

    #[test]
    fn every_rule_matches_its_samples() {
        for rule in RULES {
            assert!(
                matches!(rule.matcher, Matcher::Present)
                    || (rule.samples.iter().any(|s| s.1) && rule.samples.iter().any(|s| !s.1)),
                "{} needs matching and non-matching samples",
                rule.id
            );
            for (bytes, want) in rule.samples {
                let got = match rule.matcher {
                    Matcher::Head(m) => m(bytes),
                    Matcher::Whole { candidate, test } => {
                        candidate(bytes) && test(bytes).is_ok_and(|hits| !hits.is_empty())
                    }
                    Matcher::Stream(m) => m(bytes, 1).is_ok_and(|hits| !hits.is_empty()),
                    Matcher::Present => true,
                };
                assert_eq!(
                    got,
                    *want,
                    "{}: {}",
                    rule.id,
                    String::from_utf8_lossy(bytes)
                );
            }
        }
    }

    #[test]
    fn material_changes_with_the_credential_and_not_with_a_count() {
        // Yarn's way of writing an npm token, alone, under a scope, and as
        // the base64 form that ends in "=", and after a byte order mark.
        for form in [
            "npmAuthToken: VALUE\n",
            "\u{feff}npmAuthToken: VALUE\n",
            "npmScopes:\n  fixture:\n    npmAuthToken: \"VALUE\"\n",
            "npmAuthIdent: VALUE==\n",
        ] {
            let of = |value: &str| {
                let file = form.replace("VALUE", value);
                material("dev.npm.inline-credentials", file.as_bytes())
            };
            assert_ne!(of("synthetic-first"), of("synthetic-second"), "{form}");
        }
        // A VPN profile issued again with a new key, and one only moved about.
        let profile = |key: &str, note: &str| {
            let file = format!(
                "client\n{note}<key>\n-----BEGIN {0}-----\n{key}\n-----END {0}-----\n</key>\n",
                "PRIVATE KEY"
            );
            material("app.openvpn.embedded-key", file.as_bytes())
        };
        assert_ne!(profile("MIIEfirst", ""), profile("MIIEsecond", ""));
        assert_eq!(profile("MIIEfirst", ""), profile("MIIEfirst", "verb 3\n"));
        // How many logins a browser has saved is a detail of one finding.
        let saved = |logins: &str| {
            let file = format!("{{\"nextId\": 9, \"logins\": [{logins}]}}");
            material("browser.firefox.saved-logins", file.as_bytes())
        };
        assert_eq!(saved("{\"id\": 1}"), saved("{\"id\": 1}, {\"id\": 2}"));
        // Other whole-file findings still follow the file.
        let composer = |token: &str| {
            let file = format!("{{\"github-oauth\": {{\"github.com\": \"{token}\"}}}}");
            material("dev.composer.auth", file.as_bytes())
        };
        assert_ne!(composer("synthetic-first"), composer("synthetic-second"));
    }

    /// A value found with "$" or a leading "!" in it is what the app
    /// fingerprints, so a changed value is a changed finding.
    #[test]
    fn material_keeps_values_the_rules_take_as_written() {
        for (rule, file) in [
            (
                "dev.aws.inline-credentials",
                "[default]\naws_secret_access_key = !Synth$tic-@\n",
            ),
            (
                "dev.gh.inline-token",
                "github.com:\n    oauth_token: Synth$tic-@\n",
            ),
            (
                "dev.npm.inline-credentials",
                "//registry.npmjs.org/:_authToken=!Synth$tic-@\n",
            ),
            ("dev.npm.inline-credentials", "npmAuthToken: Synth$tic-@\n"),
        ] {
            let of = |value: &str| material(rule, file.replace('@', value).as_bytes());
            assert_ne!(of("first"), of("second"), "{rule}: {file}");
        }
    }

    /// pip takes several URLs on a line, and each with a password is a hit.
    /// Copied once for each of them, a settings file of 1 MiB could take some
    /// 20 GB to fingerprint.
    #[test]
    fn material_copies_a_line_once_however_many_hits_are_on_it() {
        let line = "https://fixture:synthetic-only@host.invalid/simple ".repeat(4000);
        let file = format!("[global]\nextra-index-url = {line}\n");
        let peak = || {
            let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
            // SAFETY: `usage` is writable and the size getrusage fills.
            assert_eq!(
                unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
                0
            );
            // SAFETY: getrusage reported success, so it filled `usage`.
            unsafe { usage.assume_init() }.ru_maxrss
        };
        let before = peak();
        let material = material("dev.url.inline-password", file.as_bytes());
        // On macOS the peak is in bytes. Copied once per hit, it grows 800 MB.
        let grew = peak() - before;
        assert!(
            grew < 64 << 20,
            "fingerprinting {} bytes took {grew} more",
            file.len()
        );
        assert!(material.len() <= 2 * file.len());
    }

    /// Maven and FileZilla may write a password on lines of its own after
    /// the tag that opens it. With only the tag's line as material, a changed
    /// password would look like the same one.
    #[test]
    fn material_for_an_xml_password_follows_it_onto_its_own_lines() {
        for (rule, entry, password) in [
            ("dev.maven.settings-password", "server", "password"),
            ("app.filezilla.saved-password", "Server", "Pass"),
        ] {
            let of = |value: &str, around: &str| {
                let file = format!(
                    "<{entry}>\n<{password}>{around}{value}{around}</{password}>\n</{entry}>\n"
                );
                material(rule, file.as_bytes())
            };
            for around in ["", "\n", "\n  "] {
                assert_ne!(
                    of("synthetic-first", around),
                    of("synthetic-second", around),
                    "{rule}: {around:?}"
                );
            }
            // On one line.
            let file = format!("<{entry}>\n<{password}>synthetic-first</{password}>\n</{entry}>\n");
            let line = format!("<{password}>synthetic-first</{password}>");
            let expected = serde_json::to_vec(&[[line]]).unwrap();
            assert_eq!(material(rule, file.as_bytes()), expected, "{rule}");
        }
    }

    /// A key in a .env file can run over several lines inside quotes. The
    /// line that opens it is the same for every key, so it alone is not
    /// enough material.
    #[test]
    fn material_for_a_key_in_a_settings_file_takes_each_of_its_lines() {
        let of = |body: &str| {
            let file = format!(
                "PORT=8080\nTLS_KEY=\"-----BEGIN {0}-----\n{body}\n-----END {0}-----\"\n",
                "PRIVATE KEY"
            );
            material("secret.env-assignment", file.as_bytes())
        };
        assert_ne!(
            of("c3ludGhldGljLWZpcnN0LXZhbHVl"),
            of("c3ludGhldGljLXNlY29uZC12YWx1ZQ")
        );
    }

    #[test]
    fn a_maven_password_of_braces_is_read_once() {
        let Matcher::Whole { test, .. } = logins::MAVEN_PASSWORD.matcher else {
            panic!("the Maven rule reads whole files");
        };
        let hits = |value: &str| {
            let file = format!("<id>releases</id>\n<password>{value}</password>\n");
            test(file.as_bytes()).unwrap().len()
        };
        // Were each "{" to look for its "}" to the end of the line, and each
        // "{[" for its "]", a line of them would cost the square of its length.
        let long = 1000 * 1024;
        // Nor is what follows one "]" judged again for every "{[" before it.
        let shared = format!("{}]{}!}}", "{[".repeat(long / 4), "A".repeat(long / 2));
        // Also when a plain "{" stands between them.
        let apart = format!("{}]{}!}}", "{[{".repeat(long / 6), "A".repeat(long / 2));
        for value in [
            "{".repeat(long),
            format!("{}}}", "{[".repeat(long / 2)),
            shared,
            apart,
        ] {
            let started = std::time::Instant::now();
            // Not encrypted and not a reference: a literal.
            assert_eq!(hits(&value), 1);
            let took = started.elapsed();
            assert!(
                took < std::time::Duration::from_secs(10),
                "checking {} bytes took {took:?}",
                value.len()
            );
        }
        // What counts as encrypted: the first "}" after a "{", and the first
        // "]" after a "{[", wherever earlier ones stand.
        let encrypted = "c3ludGhldGljLW9ubHktdmFsdWU=";
        assert_eq!(hits(&format!("x}}{{{encrypted}}}")), 0);
        assert_eq!(hits(&format!("{{[a]{{{encrypted}}}")), 0);
        assert_eq!(hits(&format!("]{{[a]{encrypted}}}")), 0);
        assert_eq!(hits(&format!("]{{[{encrypted}}}")), 1);
        assert_eq!(hits(&format!("\\{{{encrypted}}}")), 1);
    }

    #[test]
    fn material_for_a_profile_takes_each_line_for_one_key() {
        let block = |keys: &[&str], rest: &str| {
            let key = |body: &&str| format!("-----BEGIN {0}-----\n{body}\n", "PRIVATE KEY");
            let keys: String = keys.iter().map(key).collect();
            let file = format!("client\n<key>\n{keys}{rest}</key>\n");
            (material("app.openvpn.embedded-key", file.as_bytes()), file)
        };
        // A planted profile: one block holding the line that opens a key
        // again and again. Were each of those lines to take every line after
        // it, the copy would grow with the square of the profile.
        let bodies: Vec<String> = (0..2000).map(|n| format!("synthetic{n}")).collect();
        let bodies: Vec<&str> = bodies.iter().map(String::as_str).collect();
        let (material, file) = block(&bodies, "");
        assert!(
            material.len() <= 2 * file.len(),
            "{} bytes of material for a profile of {}",
            material.len(),
            file.len()
        );
        // One profile cannot fill the findings a scan keeps: like other
        // rules, this one lists so many places in a file and no more.
        let Matcher::Whole { test, .. } = apps::VPN_PROFILE_KEY.matcher else {
            panic!("the VPN profile rule reads whole files");
        };
        let incomplete = test(file.as_bytes()).err().expect("match limit");
        assert_eq!(incomplete.reason, "scan-limit");
        assert_eq!(incomplete.hits.len(), 100);
        // Two keys in one block are two: a change to either shows.
        assert_ne!(
            block(&["first", "second"], ""),
            block(&["first", "third"], "")
        );
        assert_ne!(
            block(&["first", "second"], ""),
            block(&["other", "second"], "")
        );
        // What else the block holds after its one key is part of that key's
        // material, so an item for such a profile keeps its identity.
        let certificate = |body: &str| format!("-----BEGIN CERTIFICATE-----\n{body}\n");
        assert_ne!(
            block(&["first"], &certificate("MIIDfirst")).0,
            block(&["first"], &certificate("MIIDsecond")).0
        );
    }

    #[test]
    fn hits_name_what_they_are_about() {
        let subjects = |rule: &Rule, file: &str| -> Vec<Option<String>> {
            let Matcher::Whole { test, .. } = rule.matcher else {
                panic!("{} reads whole files", rule.id);
            };
            let hits = test(file.as_bytes()).unwrap();
            hits.into_iter().map(|hit| hit.subject).collect()
        };
        // Bundler: the host, with its dots and dashes back.
        assert_eq!(
            subjects(
                &logins::BUNDLER_CREDENTIALS,
                "---\nBUNDLE_GEM__FURY__IO: \"fixture:synthetic-only\"\nBUNDLE_GEMS__MY___COMPANY__INVALID: \"fixture:synthetic-only\"\n"
            ),
            [
                Some("gem.fury.io".to_string()),
                Some("gems.my-company.invalid".to_string())
            ]
        );
        // An unescaped slash makes userinfo ambiguous: omit its label, not
        // its finding. An encoded slash still permits the actual host label.
        assert_eq!(
            subjects(
                &logins::BUNDLER_CREDENTIALS,
                "---\nBUNDLE_HTTPS://FIXTUREUSER:SYNTHETIC/PASS@GEMS__EXAMPLE__INVALID/FIXTURE/: \"fixture:synthetic-only\"\nBUNDLE_HTTPS://FIXTUREUSER:SYNTHETIC%2FPASS@GEMS__EXAMPLE__INVALID/FIXTURE/: \"fixture:synthetic-only\"\nBUNDLE_HTTP://NEXUS:8081/REPOSITORY/GEMS/: \"fixture:synthetic-only\"\n"
            ),
            [
                None,
                Some("gems.example.invalid".to_string()),
                Some("nexus:8081".to_string())
            ]
        );
        // rclone: one hit for each remote, also where its name cannot be shown.
        let remotes = "[work+crypt]\ntype = crypt\npassword = c3ludGhldGljLW9uZQ\npassword2 = c3ludGhldGljLXR3bw\n[home+crypt]\ntype = crypt\npassword = c3ludGhldGljLXRocmVl\n";
        assert_eq!(subjects(&apps::RCLONE_SECRET, remotes), [None, None]);
        // Terraform: a credential that expires within minutes is listed, not flagged.
        let state = serde_json::json!({"version": 4, "terraform_version": "1.9.0", "resources": [
            {"mode": "data", "type": "aws_eks_cluster_auth", "name": "fixture",
             "instances": [{"attributes": {"token": "synthetic-only-value"}}]},
            {"mode": "managed", "type": "aws_db_instance", "name": "fixture",
             "instances": [{"attributes": {"password": "synthetic-only-value"}}]},
        ]});
        let Matcher::Whole { test, .. } = cloud::TERRAFORM_STATE.matcher else {
            unreachable!()
        };
        let low: Vec<bool> = test(state.to_string().as_bytes())
            .unwrap()
            .iter()
            .map(|hit| hit.low)
            .collect();
        assert_eq!(low, [true, false]);
        // Names too long to show share one hit, which is flagged if any of
        // what it stands for is: the scan keeps one finding without a name.
        let long = |name: char| name.to_string().repeat(90);
        let state = serde_json::json!({"version": 4, "terraform_version": "1.9.0", "resources": [
            {"mode": "data", "type": "aws_eks_cluster_auth", "name": long('a'),
             "instances": [{"attributes": {"token": "synthetic-only-value"}}]},
            {"mode": "managed", "type": "aws_db_instance", "name": long('b'),
             "instances": [{"attributes": {"password": "synthetic-only-value"}}]},
        ]});
        let hits = test(state.to_string().as_bytes()).unwrap();
        let shown: Vec<_> = hits
            .iter()
            .map(|hit| (hit.subject.is_some(), hit.low))
            .collect();
        assert_eq!(shown, [(false, false)]);
        // One resource that names an attribute many times is still one
        // holder with one secret, however long its name.
        let instance = serde_json::json!({"attributes": {"a": "synthetic-only-value"},
            "sensitive_attributes": vec![serde_json::json!([{"value": "a"}]); 100]});
        let state = serde_json::json!({"version": 4, "terraform_version": "1.9.0", "resources": [
            {"type": "fixture", "name": "n".repeat(4096), "instances": vec![instance; 40]},
        ]});
        let (held, limited) = cloud::state_secrets(&state);
        assert!(!limited);
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].secrets.len(), 1);
        // A long token is a token whatever letters it happens to have in it.
        let kube = |token: &str| {
            let file = format!("users:\n- name: fixture\n  user:\n    token: {token}\n");
            subjects(&cloud::KUBE_CREDENTIALS, &file).len()
        };
        let signed = format!(
            "synthetic.{}.{}",
            "abcDEF123".repeat(20),
            "dUmMyXxxx".repeat(20)
        );
        assert_eq!((kube(&signed), kube("your-token-here")), (1, 0));
        // A long placeholder is still a placeholder.
        let filler = "x".repeat(45);
        for sample in [
            filler.as_str(),
            "your-kubernetes-service-account-token-here",
        ] {
            assert_eq!(kube(sample), 0, "{sample}");
        }
    }

    #[test]
    fn material_is_each_secret_of_a_file_that_tools_rewrite() {
        // Terraform rewrites its state on every apply.
        let state = |serial: u32, password: &str| {
            let file = serde_json::json!({"version": 4, "terraform_version": "1.9.0", "serial": serial,
            "resources": [
                {"mode": "managed", "type": "aws_db_instance", "name": "fixture",
                 "instances": [{"attributes": {"password": password}}]},
                {"mode": "managed", "type": "aws_s3_bucket", "name": format!("bucket-{serial}"),
                 "instances": [{"attributes": {"bucket": "fixture"}}]},
            ]});
            material("dev.terraform.state-secret", file.to_string().as_bytes())
        };
        assert!(state(1, "synthetic-first-value") == state(2, "synthetic-first-value"));
        assert!(state(1, "synthetic-first-value") != state(1, "synthetic-second-value"));
        // A credential that lasts minutes is new on every apply, and no part
        // of what is fingerprinted.
        let cluster = |token: &str| {
            let file = serde_json::json!({"version": 4, "terraform_version": "1.9.0", "resources": [
                {"mode": "data", "type": "aws_eks_cluster_auth", "name": "fixture",
                 "instances": [{"attributes": {"token": token}}]},
                {"mode": "managed", "type": "aws_db_instance", "name": "fixture",
                 "instances": [{"attributes": {"password": "synthetic-only-value"}}]},
            ]});
            material("dev.terraform.state-secret", file.to_string().as_bytes())
        };
        assert!(cluster("synthetic-first-value") == cluster("synthetic-second-value"));
        // rclone refreshes the access token of a sign-in by itself.
        let drive = |access: &str, refresh: &str| {
            let file = format!("[drive]\ntype = drive\ntoken = {{\"access_token\":\"{access}\",\"refresh_token\":\"{refresh}\",\"expiry\":\"{access}\"}}\n");
            material("app.rclone.stored-login", file.as_bytes())
        };
        assert!(
            drive("synthetic-one", "synthetic-only") == drive("synthetic-two", "synthetic-only")
        );
        assert!(
            drive("synthetic-one", "synthetic-only") != drive("synthetic-one", "synthetic-other")
        );
        // rclone: every secret of a remote, not only its first.
        let remote = |second: &str| {
            let file = format!(
                "[fixture]\ntype = crypt\npassword = c3ludGhldGljLW9uZQ\npassword2 = {second}\n"
            );
            material("app.rclone.stored-secret", file.as_bytes())
        };
        assert!(remote("c3ludGhldGljLXR3bw") != remote("c3ludGhldGljLXRocmVl"));
    }

    #[test]
    fn rule_list_names_every_rule_once() {
        let list = rule_list();
        for rule in RULES {
            assert_eq!(list.matches(&format!("{}\n", rule.id)).count(), 1);
        }
    }
}
