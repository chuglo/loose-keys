//! Sign-ins that command-line tools keep in plain files, in whatever format
//! each tool uses, and a few config files that hold passwords inline.
//! Locations were checked against each tool's documentation or source.

use super::*;

pub const CLI_LOGIN: Rule = Rule {
    id: "dev.cli.stored-login",
    category: "developer-cloud",
    kind: "inventory",
    severity: "medium",
    title: "Command-line tool sign-in stored in a file",
    explanation: "A command-line tool keeps its sign-in token in this file as plain text. This is how the tool stores it; validity and permissions were not checked.",
    reason: None,
    next_step: Some("Nothing to fix while you use the tool. Sign out of tools you have stopped using, which removes the stored token."),
    advice: Advice {
        steps: &[
            "For a tool you still use, leave this in place. If the tool can keep its token in the macOS Keychain instead, turn that on.",
            "For a tool you no longer use, run its sign-out command (most have 'logout'), then delete this file.",
            "If the token was created by hand in the service's settings, revoke it there too: signing out locally does not always do that.",
        ],
        link: None,
    },
    targets: &[
        Target::File("Library/Application Support/com.vercel.cli/auth.json"),
        Target::File("Library/Preferences/netlify/config.json"),
        Target::File("Library/Preferences/.wrangler/config/default.toml"),
        Target::File(".wrangler/config/default.toml"),
        Target::File(".fly/config.yml"),
        Target::File(".config/configstore/firebase-tools.json"),
        Target::File("Library/Application Support/doctl/config.yaml"),
        Target::File(".sentryclirc"),
        Target::File("Library/Application Support/ngrok/ngrok.yml"),
        Target::File(".pulumi/credentials.json"),
        Target::File(".supabase/access-token"),
        Target::File(".config/circleci/config.yml"),
        Target::File(".circleci/cli.yml"),
        Target::File(".config/stripe/config.toml"),
        Target::File(".config/stripe/credentials.json"),
        Target::File("Library/Application Support/glab-cli/config.yml"),
        Target::File(".config/glab-cli/config.yml"),
        Target::File(".config/hub"),
        Target::File(".cache/huggingface/stored_tokens"),
        Target::File(".terraformrc"),
        Target::Dir(".kube/cache/oidc-login"),
        Target::Dir(".kube/cache/kubelogin"),
        Target::Name(".aider.conf.yml"),
        Target::File(".expo/state.json"),
        Target::File(".local/share/uv/credentials/credentials.toml"),
        Target::File(".modal.toml"),
        Target::File(".kaggle/kaggle.json"),
        Target::File(".kaggle/access_token"),
    ],
    matcher: Matcher::Whole {
        candidate: any,
        test: stored_login_hits,
    },
    samples: &[
        (br#"{"token": "synthetic-only-value-1234"}"#, true),
        (b"access_token: synthetic-only-value-1234\nmetrics_token: \n", true),
        (b"[auth]\ntoken=synthetic-only-value-1234\n", true),
        (b"synthetic-only-value-1234567890\n", true),
        (b"version: 2\nupdate_check: false\n", false),
        (br#"{"telemetry": true, "token": ""}"#, false),
        // Signed out of Expo.
        (br#"{"auth": null, "uuid": "fixture"}"#, false),
    ],
};

const LOGIN_KEYS: &[&str] = &[
    "token",
    "access_token",
    "access-token",
    "accessToken",
    "oauth_token",
    "refresh_token",
    "refreshToken",
    "id_token",
    "authtoken",
    "api_key",
    "test_mode_api_key",
    "live_mode_api_key",
    "sessionSecret",
    "key",
];

/// A stored token in JSON, in "name: value" or "name = value" lines, in a
/// known issuer format, or as the file's only content.
fn stored_login_hits(bytes: &[u8]) -> Hits {
    let found = match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(v) => json_has_secret(&v, LOGIN_KEYS),
        Err(_) => {
            let text = String::from_utf8_lossy(bytes);
            let only = text.trim();
            !keyed_secret_lines(&text, LOGIN_KEYS).is_empty()
                || (only.len() >= 20 && inline_literal(only) && plausible(only))
        }
    };
    Ok((found || token::has_token(bytes))
        .then(Hit::file)
        .into_iter()
        .collect())
}

pub const AWS_SESSION: Rule = Rule {
    id: "dev.aws.session-cache",
    title: "AWS sign-in session stored by the AWS CLI",
    explanation: "The AWS CLI keeps single sign-on and temporary role credentials in this folder. They expire on their own, usually within hours; a refresh token here can last longer.",
    next_step: Some("Nothing to fix while you use AWS on this Mac. Sign out when you finish a piece of work, which removes the cached sessions."),
    advice: Advice {
        steps: &[
            "Sign out and clear the cache when you are done: aws sso logout",
            "Ask for short session lengths in IAM Identity Center, so a copied session stops working soon.",
        ],
        link: None,
    },
    targets: &[
        Target::Dir(".aws/sso/cache"),
        Target::Dir(".aws/cli/cache"),
        Target::Dir(".aws/login/cache"),
    ],
    matcher: Matcher::Whole {
        candidate: any,
        test: aws_session_hits,
    },
    samples: &[
        (br#"{"startUrl": "https://example.invalid/start", "accessToken": "synthetic-only-value-1234"}"#, true),
        (br#"{"Credentials": {"AccessKeyId": "x", "SecretAccessKey": "synthetic-only-value-1234"}}"#, true),
        (br#"{"startUrl": "https://example.invalid/start", "region": "us-east-1"}"#, false),
    ],
    ..CLI_LOGIN
};

fn aws_session_hits(bytes: &[u8]) -> Hits {
    json_hits(bytes, |v| {
        json_has_secret(
            v,
            &[
                "accessToken",
                "refreshToken",
                "clientSecret",
                "SecretAccessKey",
                "SessionToken",
            ],
        )
    })
}

pub const AZURE_SERVICE_PRINCIPAL: Rule = Rule {
    id: "dev.azure.service-principal",
    kind: "review",
    severity: "high",
    title: "Azure service principal secret stored in a file",
    explanation: "The Azure CLI keeps the secret of a service principal it signed in with in this file as plain text. Validity and permissions were not checked.",
    reason: Some("A service principal secret works from any computer until it expires or is rotated, and often has broad access to a subscription."),
    next_step: Some("Sign out, and rotate the secret in Microsoft Entra. Deleting the file does not revoke it."),
    advice: Advice {
        steps: &[
            "Sign out and clear the stored entries: az logout, then az account clear",
            "In Microsoft Entra, open App registrations, choose the app, and under Certificates & secrets delete this client secret and create a new one if still needed.",
            "For automation, prefer workload identity federation or a managed identity, which need no stored secret.",
        ],
        link: Some("https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade"),
    },
    targets: &[Target::File(".azure/service_principal_entries.json")],
    matcher: Matcher::Whole {
        candidate: any,
        test: azure_principal_hits,
    },
    samples: &[
        (br#"[{"client_id": "fixture", "tenant": "fixture", "client_secret": "synthetic-only-value-1234"}]"#, true),
        (br#"[{"client_id": "fixture", "tenant": "fixture", "certificate": "/path/to/cert.pem"}]"#, false),
    ],
    ..CLI_LOGIN
};

fn azure_principal_hits(bytes: &[u8]) -> Hits {
    json_hits(bytes, |v| json_has_secret(v, &["client_secret"]))
}

pub const COMPOSER_AUTH: Rule = Rule {
    id: "dev.composer.auth",
    kind: "review",
    severity: "high",
    title: "Tokens stored in Composer's auth file",
    explanation: "Composer keeps tokens and passwords for code hosts and package repositories in this file as plain text. Validity and permissions were not checked.",
    reason: Some("These are usually personal access tokens for GitHub or GitLab, which work from any computer until revoked."),
    next_step: Some("Revoke the tokens at each host and replace them with narrower ones. Removing an entry does not revoke it."),
    advice: Advice {
        steps: &[
            "At the host named here, revoke the token (GitHub: Settings > Developer settings > Personal access tokens).",
            "If Composer still needs access, create a fine-grained, read-only token with an expiry date.",
            "Remove entries for hosts you no longer use: composer config --global --unset github-oauth.<host>",
        ],
        link: None,
    },
    targets: &[
        Target::File(".composer/auth.json"),
        Target::File(".config/composer/auth.json"),
    ],
    matcher: Matcher::Whole {
        candidate: any,
        test: composer_hits,
    },
    samples: &[
        (br#"{"github-oauth": {"github.com": "synthetic-only-value"}}"#, true),
        (br#"{"http-basic": {"repo.example.invalid": {"username": "fixture", "password": "synthetic-only"}}}"#, true),
        (br#"{"github-oauth": {}, "http-basic": {}}"#, false),
    ],
    ..CLI_LOGIN
};

/// One hit per host that has any stored value.
fn composer_hits(bytes: &[u8]) -> Hits {
    fn holds_value(v: &serde_json::Value) -> bool {
        match v {
            serde_json::Value::String(s) => s.len() >= 8 && inline_literal(s) && plausible(s),
            serde_json::Value::Object(o) => {
                o.iter().any(|(k, v)| k != "username" && holds_value(v))
            }
            _ => false,
        }
    }
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| "unreadable")?;
    Ok([
        "github-oauth",
        "gitlab-oauth",
        "gitlab-token",
        "bitbucket-oauth",
        "bearer",
        "http-basic",
    ]
    .iter()
    .filter_map(|kind| v[kind].as_object())
    .flatten()
    .filter(|(_, stored)| holds_value(stored))
    .map(|(host, _)| Hit::file().about(host))
    .collect())
}

pub const MAVEN_PASSWORD: Rule = Rule {
    id: "dev.maven.settings-password",
    title: "Password stored in Maven settings",
    explanation: "A repository password or token is written in Maven's settings file as plain text. Validity and permissions were not checked.",
    reason: Some("Repository credentials can publish packages that other people's builds download."),
    next_step: Some("Change the password or revoke the token at the repository, and store the replacement encrypted or outside the file."),
    advice: Advice {
        steps: &[
            "At the repository manager, change this password or revoke this token.",
            "Reference an environment variable instead of the value: <password>${env.REPO_TOKEN}</password>, supplied when you build.",
            "Or use Maven's password encryption (mvn --encrypt-password), keeping the master password off this Mac's disk if you can.",
        ],
        link: None,
    },
    targets: &[Target::File(".m2/settings.xml")],
    matcher: Matcher::Whole {
        candidate: any,
        test: maven_hits,
    },
    samples: &[
        (b"<settings><servers><server><id>releases</id><password>synthetic-only</password></server></servers></settings>", true),
        (b"<settings>\n<server><password>\n synthetic-only\n</password></server>\n</settings>", true),
        (b"<settings><password></password><password>  </password><password/><password>${env.REPO_TOKEN}</password></settings>", false),
        (b"<settings><!-- <password>synthetic-only</password> --><note>&lt;password&gt;synthetic-only&lt;/password&gt;</note><passwordHint>synthetic-only</passwordHint></settings>", false),
        (b"<!DOCTYPE settings [<!ENTITY decoy '<password>synthetic-only</password>'>]><settings><note><![CDATA[<password>synthetic-only</password>]]></note></settings>", false),
        (b"<server>\n<id>releases</id>\n<password>synthetic-only</password>\n</server>\n", true),
        (b"<server>\n<id>releases</id>\n<password>Synth$tic-0nly</password>\n</server>\n", true),
        (b"<server>\n<id>releases</id>\n<password>Synth{tic}-0nly</password>\n</server>\n", true),
        // Encrypted as Maven 4 writes it, with what it was encrypted by.
        (b"<server>\n<id>releases</id>\n<password>{[name=master,cipher=AES/GCM/NoPadding,version=4.0]c3ludGhldGljLW9ubHktdmFsdWUtZm9yLXRlc3Q=}</password>\n</server>\n", false),
        (b"<server>\n<id>releases</id>\n<password>expires 2030:{c3ludGhldGljLW9ubHktdmFsdWU=}.</password>\n</server>\n", false),
        // Encrypted, with a note in front of it as Maven allows.
        (b"<server>\n<id>releases</id>\n<password>reset on 2009-03-11 {COQLCE6DU6GtcS5P0nlyFixture=}</password>\n</server>\n", false),
        (b"<server>\n<id>releases</id>\n<password>${env.REPO_TOKEN}</password>\n</server>\n", false),
        (b"<server>\n<id>releases</id>\n<password>{COQLCE6DU6GtcS5P=}</password>\n</server>\n", false),
    ],
    ..COMPOSER_AUTH
};

/// Whether a Maven password holds a part Maven encrypted: "{...}" with only
/// base64 inside, in Maven 4 after "[...]" saying how. A note may stand before
/// or after it, and "\{" is a brace, not the start.
fn maven_encrypted(value: &str) -> bool {
    let after = |from: usize, c: char| value[from..].find(c).map(|i| from + i);
    // The first "}" and the first "]" after the brace being looked at. Each
    // is looked for again only from a brace that lies past it, so the value
    // is read once however many braces it has.
    let (mut close, mut bracket) = (after(0, '}'), after(0, ']'));
    let base64 = |inner: &str| {
        inner.len() >= 16
            && inner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
    };
    // Where the part after a "]" began, and whether it was base64: several
    // "{[" before one "]" share what follows it. A part that begins right
    // after its "{" is judged each time: it ends at the next "{" at the
    // latest, so those are read once between them.
    let mut judged = None;
    for (at, _) in value.match_indices('{') {
        if close.is_some_and(|c| c < at) {
            close = after(at, '}');
        }
        // No "}" after this brace, so none after a later one either.
        let Some(end) = close else {
            return false;
        };
        let encrypted = if value[at + 1..end].starts_with('[') {
            if bracket.is_some_and(|b| b < at) {
                bracket = after(at, ']');
            }
            let from = bracket.filter(|b| *b < end).map_or(end, |b| b + 1);
            match judged {
                Some((begun, encrypted)) if begun == from => encrypted,
                _ => {
                    let encrypted = base64(&value[from..end]);
                    judged = Some((from, encrypted));
                    encrypted
                }
            }
        } else {
            base64(&value[at + 1..end])
        };
        if encrypted && !value[..at].ends_with('\\') {
            return true;
        }
    }
    false
}

/// <password> elements holding a literal: not `${...}` and not `{encrypted}`.
/// Nothing else in a value is a reference here, so a "$" alone is part of it.
fn maven_hits(bytes: &[u8]) -> Hits {
    utf8_lines(bytes, |text| {
        let mut server = String::new();
        let mut out = Vec::new();
        xml_tags(text, |name, _, value, line| {
            if matches!(name, "server" | "/server" | "proxy" | "/proxy") {
                server.clear();
            } else if name == "id" {
                server = value.to_owned();
            } else if name == "password" {
                let encrypted = maven_encrypted(value);
                let reference = value.contains("${") || value.starts_with('<');
                if !value.trim().is_empty() && !reference && !encrypted {
                    out.push(Hit::line(line).about(&server));
                }
            }
        });
        out
    })
}

pub const BUNDLER_CREDENTIALS: Rule = Rule {
    id: "dev.bundler.inline-credentials",
    title: "Gem server credentials stored by Bundler",
    explanation: "Bundler keeps a user name and password or token for a gem server in this file as plain text. Validity and permissions were not checked.",
    reason: Some("These credentials let anything running as you download, and often publish, private gems."),
    next_step: Some("Change the password or revoke the token at the gem server, then supply the replacement from the environment."),
    advice: Advice {
        steps: &[
            "At the gem server named here, change the password or revoke the token.",
            "Remove the stored entry: bundle config unset --global <host>",
            "Supply the credential when needed through the matching BUNDLE_ environment variable, set from a password manager.",
        ],
        link: None,
    },
    targets: &[Target::File(".bundle/config")],
    matcher: Matcher::Whole {
        candidate: any,
        test: bundler_hits,
    },
    samples: &[
        (b"---\nBUNDLE_GEMS__EXAMPLE__INVALID: \"fixture:synthetic-only\"\n", true),
        // A gem server whose name starts like one of Bundler's own settings,
        // and one with a "-" in its name, which Bundler writes as "___".
        (b"---\nBUNDLE_GEM__FURY__IO: \"fixture:synthetic-only\"\n", true),
        (b"---\nBUNDLE_GEM__COOP: \"fixture:synthetic-only\"\n", true),
        // Stored under the server's URL, also one with no dot in it.
        (b"---\nBUNDLE_HTTP://NEXUS:8081/REPOSITORY/GEMS/: \"fixture:synthetic-only\"\n", true),
        (b"---\nBUNDLE_MIRROR__HTTP://NEXUS:8081/: \"http://mirror.example.invalid/\"\n", false),
        // Stored under the server's URL, not its host name.
        (b"---\nBUNDLE_HTTPS://GEMS__EXAMPLE__INVALID/FIXTURE/: \"fixture:synthetic-only\"\n", true),
        // A mirror is a URL, whatever the server it stands in for is called.
        (b"---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: \"https://mirror.example.invalid/\"\nBUNDLE_MIRROR__RUBYGEMS__ORG: \"https://mirror.example.invalid/\"\n", false),
        (b"---\nBUNDLE_BUILD__INVALID: \"fixture:synthetic-only\"\n", true),
        (b"---\nBUNDLE_GEMS__MY___COMPANY__INVALID: \"fixture:synthetic-only\"\n", true),
        (b"---\nBUNDLE_BUILD__RUBY___PROF: \"--with-fixture-flags\"\nBUNDLE_GEM__GITHUB_USERNAME: \"fixture-user\"\n", false),
        (b"---\nBUNDLE_PATH: \"vendor/bundle\"\nBUNDLE_JOBS: \"4\"\n", false),
        // Settings with a dot in their name that are not hosts.
        (b"---\nBUNDLE_BUILD__NOKOGIRI: \"--use-system-libraries\"\nBUNDLE_LOCAL__RACK: \"/work/src/rack\"\nBUNDLE_GEM__TEST: \"minitest\"\n", false),
    ],
    ..COMPOSER_AUTH
};

/// Host settings are the keys with "__": Bundler writes a "." in a name that
/// way, and a "-" as "___". A key that is the server's whole URL is one too.
/// Some of its own settings have a dot too: the "gem.<name>" ones listed
/// here, "build.<gem>" and "local.<gem>", whose values are build flags and
/// paths, and "mirror.<server>", whose value is a URL.
/// Bundler's settings for `bundle gem`, as its settings list names them.
const GEM_SETTINGS: &[&str] = &[
    "BUNDLE",
    "CHANGELOG",
    "CI",
    "COC",
    "GITHUB_USERNAME",
    "LINTER",
    "MIT",
    "PUSH_KEY",
    "RUBOCOP",
    "TEST",
];

fn bundler_hits(bytes: &[u8]) -> Hits {
    utf8_lines(bytes, |text| {
        text.lines()
            .enumerate()
            .filter_map(|(i, raw)| {
                // At the colon with a blank after it: a key can be a URL.
                let (key, value) = raw.trim().split_once(": ")?;
                let name = key.strip_prefix("BUNDLE_")?.replace("___", "-");
                let value = scalar_literal(value).filter(|v| v.len() >= 8)?;
                // A key that is a URL is a server, with or without a dot.
                let url = name.contains("://") && !name.starts_with("MIRROR__");
                let own = !url
                    && match name.split_once("__")? {
                        ("GEM", setting) => GEM_SETTINGS.contains(&setting),
                        ("BUILD" | "LOCAL", gem) => {
                            !gem.contains("__") && value.starts_with(['-', '/', '~', '.'])
                        }
                        // A mirror is the URL of another server.
                        ("MIRROR", _) => value.starts_with("http") && !value.contains('@'),
                        _ => false,
                    };
                // Of a URL only the host is shown: it can carry a password.
                let shown = match name.split_once("://") {
                    Some((_, rest)) => {
                        let host = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
                        host.split(['/', '?', '#']).next().unwrap_or("")
                    }
                    None => &name,
                };
                (!own)
                    .then(|| Hit::line(i + 1).about(&shown.replace("__", ".").to_ascii_lowercase()))
            })
            .collect()
    })
}

pub const URL_PASSWORD: Rule = Rule {
    id: "dev.url.inline-password",
    title: "Password written inside a URL in a config file",
    explanation: "A URL in this config file carries a user name and password or token in the form https://user:password@host. Validity and permissions were not checked.",
    reason: Some("The credential is plain text, and tools print these URLs in logs and error messages."),
    next_step: Some("Change the password or revoke the token at the host named here, and take it out of the URL."),
    advice: Advice {
        steps: &[
            "At the host named here, change the password or revoke the token.",
            "Remove the user and password from the URL in this file.",
            "Let the tool fetch the credential instead: Git with 'git config --global credential.helper osxkeychain', pip with the 'keyring' package.",
        ],
        link: None,
    },
    targets: &[
        Target::File(".gitconfig"),
        Target::File(".config/git/config"),
        Target::File(".config/pip/pip.conf"),
        Target::File("Library/Application Support/pip/pip.conf"),
        Target::File(".pip/pip.conf"),
        Target::File(".curlrc"),
        // A remote added with its token in the URL, in any repository.
        Target::Repo("config"),
    ],
    matcher: Matcher::Whole {
        candidate: any,
        test: url_password_hits,
    },
    samples: &[
        (b"[global]\nindex-url = https://fixture:synthetic-only@pypi.example.invalid/simple\n", true),
        (b"[url \"https://fixture:synthetic-only@git.example.invalid/\"]\n\tinsteadOf = https://git.example.invalid/\n", true),
        (b"[global]\nindex-url = https://pypi.example.invalid/simple\n", false),
        (b"[global]\nindex-url = https://fixture:${PIP_PASSWORD}@pypi.example.invalid/simple\n", false),
    ],
    ..COMPOSER_AUTH
};

fn url_password_hits(bytes: &[u8]) -> Hits {
    utf8_lines(bytes, |text| {
        text.lines()
            .enumerate()
            .filter(|(_, l)| !l.trim_start().starts_with(['#', ';']))
            .filter_map(|(i, line)| {
                let rest = line.split_once("://")?.1;
                let authority = rest.split(['/', '?', '#', '"', '\'', ' ']).next()?;
                let (userinfo, host) = authority.rsplit_once('@')?;
                let (user, password) = userinfo.split_once(':')?;
                (!host.is_empty()
                    && !user.is_empty()
                    && inline_literal(password)
                    && plausible(password))
                .then(|| Hit::line(i + 1).about(host).at(text, password))
            })
            .collect()
    })
}
