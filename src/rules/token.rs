//! Service tokens recognizable by their issuer's prefix, wherever they are
//! stored. Prefix formats are the high-precision subset of what Gitleaks and
//! TruffleHog match; there is no entropy guessing here.

use super::*;

pub const SERVICE_TOKEN: Rule = Rule {
    id: "secret.service-token",
    category: "developer-cloud",
    kind: "review",
    severity: "high",
    title: "Service token stored in a file",
    explanation: "This file has text in the format of a service's access token. Loose Keys did not check whether it still works or what it can do.",
    reason: Some("A token like this usually works from any computer until it is revoked. Any program that can read this file can copy it."),
    next_step: Some("Revoke the token where it was issued, then remove it from this file. Deleting the text does not revoke the token."),
    advice: advice(None),
    targets: &[
        Target::Discovery,
        Target::Name(".env*"),
        Target::File(".zsh_history"),
        Target::File(".bash_history"),
        Target::File(".zshrc"),
        Target::File(".zshenv"),
        Target::File(".zprofile"),
        Target::File(".bashrc"),
        Target::File(".bash_profile"),
        Target::File(".profile"),
        Target::File(".zlogin"),
        Target::File(".bash_login"),
        Target::File(".sh_history"),
        Target::File(".config/fish/config.fish"),
        Target::File(".local/share/fish/fish_history"),
        // Terminal.app keeps a history file per window here.
        Target::Dir(".zsh_sessions"),
        Target::Dir(".bash_sessions"),
        // The name zsh's first-run setup suggests for its history.
        Target::File(".histfile"),
        // Other names tools use for a file of settings and secrets.
        Target::Name("*.env"),
        Target::Name(".dev.vars*"),
        Target::Name("secrets.toml"),
        // Database and language prompts keep what was typed, too.
        Target::File(".psql_history"),
        Target::File(".mysql_history"),
        Target::File(".rediscli_history"),
        Target::File(".python_history"),
        Target::File(".node_repl_history"),
        Target::File(".irb_history"),
        // Outside discovery, because .cache is a skipped folder.
        Target::File(".cache/huggingface/token"),
        Target::Name(".envrc"),
        Target::Name("*.tfvars"),
        // These settings files are read whole for assignments, including
        // tokens beyond the discovery head.
        Target::File(".gradle/gradle.properties"),
        Target::File(".codex/config.toml"),
        Target::File(".config/goose/secrets.yaml"),
        // Aider writes its chat history into the project folder.
        Target::Name(".aider.chat.history.md"),
        Target::Name(".aider.input.history"),
        // Outside discovery, because .git is a skipped folder.
        Target::Repo("config"),
    ],
    matcher: Matcher::Whole {
        candidate: has_token,
        test: token_hits,
    },
    samples: &[
        (concat!("export GITHUB_TOKEN=gh", "p_0123456789abcdefghijABCDEFGHIJ012345\n").as_bytes(), true),
        (concat!("key: sk-ant", "-api03-0123456789abcdefghijABCDEFGHIJ0123456789abcdefghijABCDEFGHIJ0123456789abcdefghijABCDEFGHIJ\n").as_bytes(), true),
        // AWS's documentation sample and an obvious placeholder.
        (concat!("aws_access_key_id = AKIA", "IOSFODNN7EXAMPLE\n").as_bytes(), false),
        (concat!("token = gh", "p_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n").as_bytes(), false),
        // A prefix inside a longer word is not a token.
        (concat!("class=\"task-gh", "p_0123456789abcdefghijABCDEFGHIJ012345\"\n").as_bytes(), false),
    ],
};

pub const AGENT_RECORD: Rule = Rule {
    id: "secret.agent-record",
    title: "Service token in an AI agent's records",
    explanation: "An AI coding agent's session record or log has text in the format of a service's access token. Agents save the commands they run and what those print, so a token used in a session stays on disk. Loose Keys did not check whether it still works.",
    reason: Some("These records are plain files that any program running as you can read, and they are kept long after the session ends."),
    next_step: Some("Revoke the token, then delete the session record that holds it. Deleting the record does not revoke the token."),
    advice: Advice {
        steps: &[
            "Revoke or replace the token where it was issued. Do this first: it keeps working until then.",
            "Delete this file if you no longer need the session record, using the tool's own delete option if it has one. Check for other copies and backups too.",
            "Keep credentials in the Keychain or a password manager and load them when needed. Do not paste them into prompts or commands, and make sure commands and debug logs do not print them.",
            "Shorten how long the tool keeps session records, if it has a setting for that.",
        ],
        link: None,
    },
    // The tools' own folders, read in full. Their layouts change between
    // versions, so whole folders are named, not individual files.
    targets: &[
        Target::Tree(".claude"),
        Target::Tree("Library/Caches/claude-cli-nodejs"),
        Target::Tree("Library/Logs/Claude"),
        Target::Tree("Library/Application Support/Claude/local-agent-mode-sessions"),
        Target::Tree(".codex"),
        Target::Tree(".gemini"),
        Target::Tree(".cursor/projects"),
        Target::Tree(".cursor/chats"),
        Target::Tree(".continue"),
        Target::Tree(".copilot"),
        Target::Tree(".cline/data"),
        Target::Tree(".codeium/windsurf/memories"),
        Target::Tree(".local/share/opencode"),
        Target::Tree(".local/share/goose"),
        Target::Tree("Library/Application Support/Code/User/workspaceStorage"),
        Target::Tree("Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev"),
        Target::Tree("Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline"),
    ],
    matcher: Matcher::Stream(record_hits),
    samples: &[
        (concat!("{\"type\":\"tool_use\",\"command\":\"curl -H 'Authorization: Bearer gh", "p_0123456789abcdefghijABCDEFGHIJ012345' https://api.example.invalid\"}\n").as_bytes(), true),
        // What a tool printed, with its line break as a record keeps it.
        (concat!("{\"type\":\"tool_result\",\"stdout\":\"Logged in. Token:\\nhf", "_abcdefghijABCDEFGHIJabcdefghijABCD\\n\"}\n").as_bytes(), true),
        (b"{\"type\":\"tool_use\",\"command\":\"curl -H \\\"Authorization: Bearer $GITHUB_TOKEN\\\" https://api.example.invalid\"}\n", false),
    ],
    ..SERVICE_TOKEN
};

/// Every token in one piece of a record, with where it sits so the scanner
/// can report each distinct one once. The rule's own steps apply (delete the
/// record), with the issuer's page for revoking.
fn record_hits(piece: &[u8], first_line: usize) -> Hits {
    let text = !piece.contains(&0);
    let (mut line, mut counted) = (first_line, 0);
    let (found, limited) = find(piece);
    let hits = found
        .into_iter()
        .map(|(at, p)| {
            line += piece[counted..at].iter().filter(|b| **b == b'\n').count();
            counted = at;
            let length = token_at(&piece[at..]).map_or(0, |(_, n)| n);
            Hit {
                line: text.then_some(line),
                subject: label(p.name),
                token_type: Some(p.name),
                link: p.advice.link,
                span: Some(at..at + length),
                low: p.test,
                ..Hit::default()
            }
        })
        .collect();
    if limited {
        Err(Incomplete {
            reason: "scan-limit",
            hits,
        })
    } else {
        Ok(hits)
    }
}

/// Hits reported per file, so a long shell history cannot flood the report:
/// this many, and after them only tokens not seen before, until this many
/// different ones have been seen in all.
const MAX_HITS: usize = 100;

/// The steps are the same for every issuer; only the page to do them on differs.
const fn advice(link: Option<&'static str>) -> Advice {
    Advice { steps: STEPS, link }
}

pub const STEPS: &[&str] = &[
    "Revoke or replace the token where it was issued. Do this first: until then, the old token keeps working wherever it was copied.",
    "If something still needs access, issue a replacement with the smallest permissions and the shortest expiry that work.",
    "Keep the replacement out of plain files. Store it in the macOS Keychain or a password manager and load it when needed.",
    "Remove the old value from this file. If it is a shell history file, delete that line.",
];

struct Provider {
    name: &'static str,
    prefix: &'static str,
    /// Characters allowed after the prefix, and how many of them.
    body: fn(u8) -> bool,
    min: usize,
    max: usize,
    /// Text the body must contain, for formats with a fixed marker inside.
    must: &'static str,
    /// A format the issuer declares to be for testing: listed, at low risk.
    test: bool,
    advice: Advice,
}

fn alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn dotted(b: u8) -> bool {
    word(b) || b == b'.' || b == b'='
}

fn base64ish(b: u8) -> bool {
    dotted(b) || b == b'+' || b == b'/' || b == b','
}

fn upper_base32(b: u8) -> bool {
    b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)
}

fn upper_alnum(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}

fn hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

fn hex_dashed(b: u8) -> bool {
    hex(b) || b == b'-'
}

const fn p(
    name: &'static str,
    prefix: &'static str,
    body: fn(u8) -> bool,
    min: usize,
    max: usize,
    link: Option<&'static str>,
) -> Provider {
    Provider {
        name,
        prefix,
        body,
        min,
        max,
        must: "",
        test: false,
        advice: advice(link),
    }
}

const fn containing(mut provider: Provider, must: &'static str) -> Provider {
    provider.must = must;
    provider
}

const fn test_mode(mut provider: Provider) -> Provider {
    provider.test = true;
    provider
}

const AWS: Option<&str> = Some("https://console.aws.amazon.com/iam/home#/security_credentials");
const GITHUB: Option<&str> = Some("https://github.com/settings/tokens");
const GITLAB: Option<&str> = Some("https://gitlab.com/-/user_settings/personal_access_tokens");
const OPENAI: Option<&str> = Some("https://platform.openai.com/api-keys");
const STRIPE: Option<&str> = Some("https://dashboard.stripe.com/apikeys");
const SLACK: Option<&str> = Some("https://api.slack.com/methods/auth.revoke");
const DIGITALOCEAN: Option<&str> = Some("https://cloud.digitalocean.com/account/api/tokens");
const VERCEL: Option<&str> = Some("https://vercel.com/account/tokens");
const CLOUDFLARE: Option<&str> = Some("https://dash.cloudflare.com/profile/api-tokens");
const TAILSCALE: Option<&str> = Some("https://login.tailscale.com/admin/settings/keys");

/// Formats as published in the Gitleaks, Betterleaks and TruffleHog rule sets
/// (checked 2026-10-10). Only formats with a fixed prefix and a length are
/// here; prefixes those projects flag as prone to false matches without more
/// context (Google `AIza`, Notion `secret_`, Twilio `SK`) are left out.
/// Checked in order, so longer prefixes come before the ones they contain.
#[rustfmt::skip]
const PROVIDERS: &[Provider] = &[
    p("AWS access key", "AKIA", upper_base32, 16, 16, AWS),
    p("AWS temporary access key", "ASIA", upper_base32, 16, 16, AWS),
    p("GitHub personal access token", "ghp_", alnum, 36, 255, GITHUB),
    p("GitHub OAuth token", "gho_", alnum, 36, 255, GITHUB),
    p("GitHub app token", "ghu_", alnum, 36, 255, GITHUB),
    p("GitHub app token", "ghs_", alnum, 36, 255, GITHUB),
    p("GitHub refresh token", "ghr_", alnum, 36, 255, GITHUB),
    p("GitHub fine-grained token", "github_pat_", word, 60, 255, GITHUB),
    p("GitLab personal access token", "glpat-", dotted, 20, 320, GITLAB),
    p("GitLab pipeline trigger token", "glptt-", hex, 40, 40, GITLAB),
    p("GitLab deploy token", "gldt-", word, 20, 60, GITLAB),
    p("GitLab runner token", "glrt-", word, 20, 60, GITLAB),
    p("GitLab feed token", "glft-", word, 20, 60, GITLAB),
    p("GitLab SCIM token", "glsoat-", word, 20, 60, GITLAB),
    p("GitLab OAuth app secret", "gloas-", word, 64, 64, GITLAB),
    p("GitLab agent token", "glagent-", word, 50, 60, GITLAB),
    p("Google OAuth client secret", "GOCSPX-", word, 28, 28, Some("https://console.cloud.google.com/apis/credentials")),
    p("Anthropic API key", "sk-ant-", word, 80, 255, Some("https://console.anthropic.com/settings/keys")),
    containing(p("OpenAI API key", "sk-proj-", word, 100, 255, OPENAI), "T3BlbkFJ"),
    containing(p("OpenAI API key", "sk-svcacct-", word, 100, 255, OPENAI), "T3BlbkFJ"),
    containing(p("OpenAI admin key", "sk-admin-", word, 100, 255, OPENAI), "T3BlbkFJ"),
    p("OpenRouter API key", "sk-or-v1-", hex, 64, 64, Some("https://openrouter.ai/settings/keys")),
    containing(p("OpenAI API key", "sk-", alnum, 48, 48, OPENAI), "T3BlbkFJ"),
    p("Stripe live secret key", "sk_live_", alnum, 20, 99, STRIPE),
    p("Stripe live restricted key", "rk_live_", alnum, 20, 99, STRIPE),
    test_mode(p("Stripe test secret key", "sk_test_", alnum, 20, 99, STRIPE)),
    test_mode(p("Stripe test restricted key", "rk_test_", alnum, 20, 99, STRIPE)),
    p("Slack token", "xox", dotted, 24, 255, SLACK),
    p("Slack app token", "xapp-", word, 40, 255, SLACK),
    p("npm access token", "npm_", alnum, 36, 36, Some("https://docs.npmjs.com/revoking-access-tokens")),
    p("PyPI API token", "pypi-AgEIcHlwaS5vcmc", word, 50, 1000, Some("https://pypi.org/manage/account/token/")),
    p("Test PyPI API token", "pypi-AgENdGVzdC5weXBpLm9yZw", word, 50, 1000, Some("https://test.pypi.org/manage/account/token/")),
    p("Hugging Face token", "hf_", alnum, 30, 40, Some("https://huggingface.co/settings/tokens")),
    p("DigitalOcean token", "dop_v1_", hex, 64, 64, DIGITALOCEAN),
    p("DigitalOcean OAuth token", "doo_v1_", hex, 64, 64, DIGITALOCEAN),
    p("DigitalOcean refresh token", "dor_v1_", hex, 64, 64, DIGITALOCEAN),
    containing(p("SendGrid API key", "SG.", dotted, 60, 72, Some("https://app.sendgrid.com/settings/api_keys")), "."),
    p("Shopify access token", "shpat_", hex, 32, 32, None),
    p("Shopify custom app token", "shpca_", hex, 32, 32, None),
    p("Shopify private app token", "shppa_", hex, 32, 32, None),
    p("Shopify shared secret", "shpss_", hex, 32, 32, None),
    p("Square access token", "sq0atp-", word, 22, 60, Some("https://developer.squareup.com/apps")),
    p("Square app secret", "sq0csp-", word, 40, 50, Some("https://developer.squareup.com/apps")),
    p("Supabase access token", "sbp_", alnum, 40, 40, Some("https://supabase.com/dashboard/account/tokens")),
    p("Supabase secret key", "sb_secret_", word, 20, 60, None),
    p("Fly.io token", "fo1_", base64ish, 43, 60, Some("https://fly.io/user/personal_access_tokens")),
    p("Fly.io token", "fm2_", base64ish, 100, 2000, Some("https://fly.io/user/personal_access_tokens")),
    p("Doppler personal token", "dp.pt.", alnum, 40, 44, None),
    p("Doppler CLI token", "dp.ct.", alnum, 40, 44, None),
    p("Doppler service account token", "dp.sa.", alnum, 40, 44, None),
    p("Linear API key", "lin_api_", alnum, 40, 40, Some("https://linear.app/settings/api")),
    p("Notion integration token", "ntn_", alnum, 46, 46, Some("https://www.notion.so/profile/integrations")),
    p("Atlassian API token", "ATATT3", base64ish, 150, 300, Some("https://id.atlassian.com/manage-profile/security/api-tokens")),
    p("Sentry user token", "sntryu_", hex, 64, 64, None),
    p("Sentry org token", "sntrys_", base64ish, 80, 400, None),
    p("Vault service token", "hvs.", word, 90, 120, None),
    p("Vault batch token", "hvb.", word, 138, 300, None),
    p("Pulumi access token", "pul-", hex, 40, 40, Some("https://app.pulumi.com/account/tokens")),
    p("Docker Hub access token", "dckr_pat_", word, 27, 27, Some("https://app.docker.com/settings/personal-access-tokens")),
    p("Docker Hub org token", "dckr_oat_", word, 32, 32, None),
    p("RubyGems API key", "rubygems_", hex, 48, 48, Some("https://rubygems.org/profile/api_keys")),
    p("Grafana service account token", "glsa_", word, 41, 41, None),
    p("Grafana Cloud token", "glc_", base64ish, 32, 400, None),
    p("Databricks token", "dapi", hex, 32, 32, None),
    p("PlanetScale token", "pscale_tkn_", dotted, 32, 64, None),
    p("PlanetScale password", "pscale_pw_", dotted, 32, 64, None),
    p("PlanetScale OAuth token", "pscale_oauth_", dotted, 32, 64, None),
    p("Postman API key", "PMAK-", hex_dashed, 59, 59, None),
    p("Tailscale auth key", "tskey-auth-", word, 20, 80, TAILSCALE),
    p("Tailscale API key", "tskey-api-", word, 20, 80, TAILSCALE),
    p("Tailscale OAuth client secret", "tskey-client-", word, 20, 80, TAILSCALE),
    p("Buildkite API token", "bkua_", alnum, 40, 40, None),
    p("Groq API key", "gsk_", alnum, 52, 52, Some("https://console.groq.com/keys")),
    p("Replicate API token", "r8_", alnum, 37, 37, Some("https://replicate.com/account/api-tokens")),
    p("xAI API key", "xai-", word, 70, 120, Some("https://console.x.ai")),
    p("age secret key", "AGE-SECRET-KEY-1", upper_alnum, 58, 58, None),
    p("Vercel token", "vcp_", word, 40, 70, VERCEL),
    p("Vercel token", "vci_", word, 40, 70, VERCEL),
    p("Vercel token", "vca_", word, 40, 70, VERCEL),
    p("Vercel token", "vcr_", word, 40, 70, VERCEL),
    p("Vercel token", "vck_", word, 40, 70, VERCEL),
    p("Cloudflare user API token", "cfut_", alnum, 48, 48, CLOUDFLARE),
    p("Cloudflare account API token", "cfat_", alnum, 48, 48, CLOUDFLARE),
    p("Cloudflare global API key", "cfk_", alnum, 48, 48, CLOUDFLARE),
    p("1Password service account token", "ops_eyJ", base64ish, 250, 2000, None),
    p("Heroku API key", "HRKU-AA", word, 58, 58, Some("https://dashboard.heroku.com/account/applications")),
    p("Perplexity API key", "pplx-", alnum, 48, 48, None),
    p("Neon API key", "napi_", alnum, 64, 64, None),
    p("Render API key", "rnd_", alnum, 28, 28, None),
    p("Together AI API key", "tgp_v1_", word, 43, 43, None),
];

/// Whether any prefix starts with this byte.
const STARTS: [bool; 256] = {
    let mut table = [false; 256];
    let mut i = 0;
    while i < PROVIDERS.len() {
        table[PROVIDERS[i].prefix.as_bytes()[0] as usize] = true;
        i += 1;
    }
    table
};

pub fn links() -> impl Iterator<Item = &'static str> {
    PROVIDERS.iter().filter_map(|p| p.advice.link)
}

pub fn names() -> impl Iterator<Item = &'static str> {
    PROVIDERS.iter().map(|p| p.name)
}

/// The token starting at `rest`, as (provider, length).
fn token_at(rest: &[u8]) -> Option<(&'static Provider, usize)> {
    PROVIDERS.iter().find_map(|p| {
        let body = rest.strip_prefix(p.prefix.as_bytes())?;
        // One past the longest allowed is already too long: counting further
        // would read a long run again from every place a token could start.
        let n = body
            .iter()
            .take(p.max + 1)
            .take_while(|b| (p.body)(**b))
            .count();
        // Databricks: the characters may be followed by "-" and one digit.
        let suffix = p.prefix == "dapi"
            && n == p.max
            && body.get(n) == Some(&b'-')
            && body.get(n + 1).is_some_and(u8::is_ascii_digit);
        let extra = if suffix { 2 } else { 0 };
        let ends = body.get(n + extra).is_none_or(|b| !word(*b));
        // Slack: a letter saying which kind of token, then "-" or ".".
        let slack = p.prefix != "xox"
            || (body.len() > 1 && b"bparsoecd".contains(&body[0]) && b"-.".contains(&body[1]));
        let text = std::str::from_utf8(&body[..n]).ok()?;
        (n >= p.min && n <= p.max && ends && slack && text.contains(p.must) && plausible(text))
            .then_some((p, p.prefix.len() + n + extra))
    })
}

/// Whether a token may start at `i`: not inside a longer word. In a JSON
/// string a line break or tab is written as a backslash and a letter, and a
/// terminal colour code ends in "m" ("[32m"), so neither letter makes a word
/// of what follows it.
fn starts_word(bytes: &[u8], i: usize) -> bool {
    if i == 0 || !word(bytes[i - 1]) {
        return true;
    }
    let before = &bytes[..i - 1];
    let digits = |b: &&u8| b.is_ascii_digit() || **b == b';';
    match bytes[i - 1] {
        b'n' | b'r' | b't' => before.last() == Some(&b'\\'),
        b'm' => {
            let code = before.iter().rev().take(8).take_while(digits).count();
            code > 0 && before.len() > code && before[before.len() - code - 1] == b'['
        }
        _ => false,
    }
}

/// (byte offset, provider) of each token, in file order. The first MAX_HITS
/// are all kept. After that only a value not seen before is, up to MAX_HITS
/// different values, so one token repeated often cannot hide another.
fn find(bytes: &[u8]) -> (Vec<(usize, &'static Provider)>, bool) {
    let mut out = Vec::new();
    let mut values = std::collections::HashSet::new();
    let mut i = 0;
    while i < bytes.len() {
        if STARTS[bytes[i] as usize] && starts_word(bytes, i) {
            if let Some((p, len)) = token_at(&bytes[i..]) {
                let value = &bytes[i..i + len];
                let new = !values.contains(value);
                if new && values.len() == MAX_HITS {
                    return (out, true);
                }
                if new {
                    values.insert(value);
                }
                if new || out.len() < MAX_HITS {
                    out.push((i, p));
                }
                i += len;
                continue;
            }
        }
        i += 1;
    }
    (out, false)
}

pub fn has_token(bytes: &[u8]) -> bool {
    !find(bytes).0.is_empty()
}

pub(super) fn is_token(bytes: &[u8]) -> bool {
    token_at(bytes).is_some_and(|(_, len)| len == bytes.len())
}

/// One hit per line, token type and value: a token repeated on its line is
/// one hit, and two different ones there are two. Binary files get a
/// whole-file hit for each different token.
fn token_hits(bytes: &[u8]) -> Hits {
    let text = std::str::from_utf8(bytes).is_ok();
    let mut hits: Vec<Hit> = Vec::new();
    let (mut line, mut counted) = (1, 0);
    let (found, limited) = find(bytes);
    for (at, p) in found {
        line += bytes[counted..at].iter().filter(|b| **b == b'\n').count();
        counted = at;
        let length = token_at(&bytes[at..]).map_or(0, |(_, n)| n);
        let hit = Hit {
            line: text.then_some(line),
            subject: label(p.name),
            advice: Some(&p.advice),
            token_type: Some(p.name),
            span: Some(at..at + length),
            low: p.test,
            ..Hit::default()
        };
        // Compared here, where the bytes are: a hit keeps only the position.
        let value = |h: &Hit| h.span.clone().and_then(|s| bytes.get(s));
        if !hits
            .iter()
            .any(|h| h.line == hit.line && h.subject == hit.subject && value(h) == value(&hit))
        {
            hits.push(hit);
        }
    }
    if limited {
        Err(Incomplete {
            reason: "scan-limit",
            hits,
        })
    } else {
        Ok(hits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Split so this source file never holds a complete token-shaped string.
    fn fake(prefix: &str, body: &str) -> String {
        format!("{prefix}{body}")
    }

    #[test]
    fn lines_and_types_are_reported_without_values() {
        let gh = fake("ghp_", "0123456789abcdefghijABCDEFGHIJ012345");
        let aws = fake("AKIA", "ABCDEFGHIJKLMNOP");
        let text = format!("# notes\nexport A={gh}\n\naws_access_key_id={aws}\nexport B={gh}\n");
        let hits = token_hits(text.as_bytes()).unwrap();
        assert_eq!(
            hits.iter().map(|h| h.line).collect::<Vec<_>>(),
            vec![Some(2), Some(4), Some(5)]
        );
        assert_eq!(
            hits[0].subject.as_deref(),
            Some("GitHub personal access token")
        );
        assert_eq!(hits[1].subject.as_deref(), Some("AWS access key"));
        assert_eq!(hits[1].token_type, Some("AWS access key"));
        assert!(hits[0].advice.unwrap().link.unwrap().contains("github.com"));
    }

    #[test]
    fn binary_files_get_one_whole_file_hit_per_type() {
        let gh = fake("gho_", "0123456789abcdefghijABCDEFGHIJ012345");
        let mut bytes = vec![0xff, 0x00, b'\n'];
        bytes.extend(gh.as_bytes());
        bytes.extend(b"\n\x00");
        bytes.extend(gh.as_bytes());
        let hits = token_hits(&bytes).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, None);
    }

    #[test]
    fn two_tokens_of_one_type_on_a_line_are_two_hits() {
        let one = fake("ghp_", "0123456789abcdefghijABCDEFGHIJ01234A");
        let two = fake("ghp_", "0123456789abcdefghijABCDEFGHIJ01234B");
        // Which value each hit is, by the letter it ends with, and its line.
        let ends = |bytes: &[u8]| -> Vec<(Option<usize>, char)> {
            let hits = token_hits(bytes).unwrap();
            hits.iter()
                .map(|h| {
                    let value = &bytes[h.span.clone().unwrap()];
                    assert_eq!(value.len(), one.len());
                    (h.line, value[value.len() - 1] as char)
                })
                .collect()
        };
        // Each different value is a hit, and one repeated on its line is not.
        let line = format!("{one} {two} {one}\n");
        assert_eq!(ends(line.as_bytes()), [(Some(1), 'A'), (Some(1), 'B')]);
        // The same in a file that is not text, where no hit has a line.
        let mut bytes = vec![0xff, 0x00];
        for token in [&one, &two, &one] {
            bytes.extend(token.as_bytes());
            bytes.push(0);
        }
        assert_eq!(ends(&bytes), [(None, 'A'), (None, 'B')]);
    }

    #[test]
    fn formats_are_strict() {
        for (prefix, body, want) in [
            (
                "xoxb-",
                "123456789012-123456789012-abcdefghijABCDEFGHIJ",
                true,
            ),
            (
                "xoxz-",
                "123456789012-123456789012-abcdefghijABCDEFGHIJ",
                false,
            ),
            (
                "sk-",
                "0123456789abcdefghijT3BlbkFJ0123456789abcdefghij",
                true,
            ),
            // Without OpenAI's marker, "sk-" plus 48 characters is not enough.
            (
                "sk-",
                "0123456789abcdefghijABCDEFGHIJ0123456789abcdefgh",
                false,
            ),
            (
                "xoxe.xoxp-",
                "1-ABCDEFGHIJ0123456789ABCDEFGHIJ0123456789",
                true,
            ),
            ("sk_test_", "0123456789abcdefghijABCDEF", true),
            (
                "vcp_",
                "0123456789abcdefghijABCDEFGHIJ0123456789abcdefghijABCDEF",
                true,
            ),
            (
                "cfut_",
                "0123456789abcdefghijABCDEFGHIJ01234567890123cdef",
                true,
            ),
            (
                "AGE-SECRET-KEY-1",
                "QQQQQQQQQQABCDEFGHJKLMNPQRSTUVWXYZ023456789ABCDEFGHJKLMNPQ",
                true,
            ),
            ("dapi", "0123456789abcdef0123456789abcdef", true),
            // Azure Databricks adds "-" and a digit.
            ("dapi", "0123456789abcdef0123456789abcdef-2", true),
            ("dapi", "0123456789abcdef0123456789abcdef-x", false),
            ("dapi", "0123456789abcdef", false),
            (
                "SG.",
                "0123456789abcdefghijAB.0123456789abcdefghijABCDEFGHIJ0123456789abc",
                true,
            ),
            (
                "sk-",
                "toggle-button-container-wrapper-element-12345678",
                false,
            ),
            ("npm_", "0123456789abcdefghijABCDEFGHIJ012345", true),
            ("npm_", "0123456789abcdefghij", false),
            ("hf_", "abcdefghijABCDEFGHIJabcdefghijABCD", true),
            (
                "dop_v1_",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                true,
            ),
        ] {
            assert_eq!(has_token(fake(prefix, body).as_bytes()), want, "{prefix}");
        }
    }

    #[test]
    fn a_repeated_token_does_not_hide_a_different_one_after_it() {
        let repeated = fake("ghp_", "0123456789abcdefghijABCDEFGHIJ012345");
        let other = fake("sk_live_", "0123456789abcdefghijABCD");
        let text = format!(
            "{}export B={other}\n",
            format!("use {repeated}\n").repeat(MAX_HITS + 50)
        );
        let stripe = |hits: &[Hit]| {
            hits.iter()
                .filter(|h| h.token_type == Some("Stripe live secret key"))
                .count()
        };
        // In a file read whole, and in one piece of an agent's record.
        assert_eq!(stripe(&token_hits(text.as_bytes()).unwrap()), 1);
        assert_eq!(stripe(&record_hits(text.as_bytes(), 1).unwrap()), 1);
        // Different tokens are bounded too: MAX_HITS of them, whatever
        // number of repeats came first.
        let different = |from: usize, count: usize| -> String {
            (from..from + count)
                .map(|n| format!("{}\n", fake("ghp_", &format!("abcdeABCDE{n:026}"))))
                .collect()
        };
        // Filling the distinct-value budget is complete if the rest only
        // repeats values already found.
        let exact = format!(
            "{}{}",
            different(0, MAX_HITS),
            different(MAX_HITS - 1, 1).repeat(20)
        );
        assert_eq!(token_hits(exact.as_bytes()).unwrap().len(), MAX_HITS);
        let many = different(0, 5 * MAX_HITS);
        let incomplete = token_hits(many.as_bytes()).err().expect("token limit");
        assert_eq!(incomplete.reason, "scan-limit");
        assert_eq!(incomplete.hits.len(), MAX_HITS);
        let after = format!(
            "{}{}",
            format!("use {repeated}\n").repeat(MAX_HITS + 50),
            different(0, MAX_HITS + 50)
        );
        let incomplete = token_hits(after.as_bytes())
            .err()
            .expect("token limit after repeats");
        assert_eq!(incomplete.reason, "scan-limit");
        assert_eq!(incomplete.hits.len(), 2 * MAX_HITS - 1);
    }

    #[test]
    fn a_token_after_an_escaped_line_break_is_found() {
        // What a tool printed is kept in a record as a JSON string, where a
        // line break or tab is a backslash and a letter.
        let token = fake("hf_", "abcdefghijABCDEFGHIJabcdefghijABCD");
        for escape in ["\\n", "\\r", "\\t"] {
            let line = format!("{{\"stdout\":\"Token:{escape}{token}{escape}\"}}\n");
            assert_eq!(
                record_hits(line.as_bytes(), 1).unwrap().len(),
                1,
                "{escape}"
            );
        }
        // So is a token a tool printed in colour, after the code for it.
        for colour in ["\u{1b}[32m", "\\u001b[1;32m", "\\x1b[0m"] {
            let line = format!("{{\"stdout\":\"Token: {colour}{token}\\u001b[0m\"}}\n");
            assert_eq!(
                record_hits(line.as_bytes(), 1).unwrap().len(),
                1,
                "{colour}"
            );
        }
        // A prefix inside a longer word is still not a token.
        for word in ["n", "\\x", "turn", "alarm", "item[m", "32m"] {
            assert!(!has_token(format!("{word}{token}").as_bytes()), "{word}");
        }
    }

    #[test]
    fn a_long_run_of_token_characters_is_not_read_again_from_every_start() {
        // Every "," starts a candidate, and "," is also one of the characters
        // this token may contain, so each candidate runs to the end. It has
        // too few different characters to be reported as a token anywhere.
        let run = format!(",{}", "ATATT3").repeat(256 * 1024 / 7);
        let started = std::time::Instant::now();
        assert!(!has_token(run.as_bytes()));
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_secs(10),
            "checking {} bytes took {took:?}",
            run.len()
        );
    }

    #[test]
    fn a_span_covers_the_whole_token() {
        // The span is what identifies a credential, so it ends where the token does.
        let token = fake("dapi", "0123456789abcdef0123456789abcdef-2");
        let text = format!("DATABRICKS_HOST_PAT={token}\n");
        let hits = token_hits(text.as_bytes()).unwrap();
        let span = hits[0].span.clone().unwrap();
        assert_eq!(span.len(), token.len());
        assert!(text[span].ends_with("-2"));
    }

    #[test]
    fn hits_per_file_are_bounded() {
        let line = format!("{}\n", fake("ghp_", "0123456789abcdefghijABCDEFGHIJ012345"));
        assert_eq!(
            token_hits(line.repeat(500).as_bytes()).unwrap().len(),
            MAX_HITS
        );
    }
}
