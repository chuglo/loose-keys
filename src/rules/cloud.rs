//! Cloud and infrastructure CLI credentials: Kubernetes, Google Cloud, Azure,
//! Terraform and Vault.

use super::*;

pub const GCP_SERVICE_ACCOUNT: Rule = Rule {
    id: "dev.gcp.service-account-key",
    category: "developer-cloud",
    kind: "review",
    severity: "high",
    title: "Google Cloud service account key file",
    explanation: "This JSON file holds a service account's private key. Loose Keys did not check whether the key still works or what it can access.",
    reason: Some("A service account key does not expire by default and works from any computer. These files are often left in Downloads after being created."),
    next_step: Some("Delete the key in Google Cloud, not just this file. Use sign-in or impersonation instead of a downloaded key."),
    advice: Advice {
        steps: &[
            "In the Google Cloud console, open IAM & Admin > Service Accounts, choose the account named here, and open its Keys tab.",
            "If something still uses the key, first switch it to 'gcloud auth application-default login' with service account impersonation, or to workload identity. Then delete the key.",
            "Delete this file and empty the Trash. Look for other copies in Downloads and project folders.",
        ],
        link: Some("https://console.cloud.google.com/iam-admin/serviceaccounts"),
    },
    targets: &[
        Target::Discovery,
        Target::File(".config/gcloud/application_default_credentials.json"),
    ],
    matcher: Matcher::Whole {
        candidate: service_account_candidate,
        test: service_account_hits,
    },
    samples: &[
        (
            br#"{"type": "service_account", "client_email": "fixture@example-project.iam.gserviceaccount.com", "private_key": "synthetic-only"}"#,
            true,
        ),
        (br#"{"type": "service_account", "private_key": ""}"#, false),
        (br#"{"type": "authorized_user", "refresh_token": "synthetic-only-value"}"#, false),
    ],
};

/// Only JSON that names the type in its head gets a full read or a parse gap.
fn service_account_candidate(head: &[u8]) -> bool {
    head.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{')
        && head.windows(17).any(|w| w == b"\"service_account\"")
}

fn service_account_hits(bytes: &[u8]) -> Hits {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| "unreadable")?;
    let key =
        v["type"] == "service_account" && v["private_key"].as_str().is_some_and(|k| !k.is_empty());
    Ok(key
        .then(|| Hit::file().about(v["client_email"].as_str().unwrap_or("")))
        .into_iter()
        .collect())
}

pub const KUBE_CREDENTIALS: Rule = Rule {
    id: "dev.kube.inline-credentials",
    category: "developer-cloud",
    kind: "review",
    severity: "high",
    title: "Kubernetes credential stored in kubeconfig",
    explanation: "A token, password or client key is written directly in the kubeconfig file. Loose Keys did not check whether it still works, or on which cluster.",
    reason: Some("Credentials written into a kubeconfig last a long time and work from any computer that can reach the cluster."),
    next_step: Some("Replace them with a sign-in plugin that fetches short-lived credentials. Removing the entry does not revoke it on the cluster."),
    advice: Advice {
        steps: &[
            "See which users have credentials stored in the file: kubectl config view (values are hidden unless you add --raw).",
            "Recreate each entry with the provider's sign-in plugin, which stores no secret: 'aws eks update-kubeconfig', 'gcloud container clusters get-credentials' or 'az aks get-credentials' with kubelogin.",
            "Remove users you no longer need: kubectl config delete-user <name>",
            "On the cluster, delete the service account token or rotate the client certificate that was stored here.",
        ],
        link: None,
    },
    // Every file directly in ~/.kube: people keep one per cluster.
    targets: &[Target::File(".kube/config"), Target::Dir(".kube")],
    matcher: Matcher::Whole {
        candidate: any,
        test: kube_hits,
    },
    samples: &[
        (b"users:\n- name: fixture\n  user:\n    token: synthetic-only\n", true),
        (b"users:\n- name: fixture\n  user:\n    client-key-data: c3ludGhldGlj\n", true),
        (b"users:\n- name: fixture\n  user:\n    exec:\n      command: aws\n", false),
        (b"users:\n- name: fixture\n  user:\n    client-key: /path/to/key.pem\n    token: #none\n", false),
        // What "kubectl config view" prints in place of the values.
        (b"users:\n- name: fixture\n  user:\n    client-key-data: DATA+OMITTED\n    token: REDACTED\n", false),
        (b"users:\n- name: fixture\n  user:\n    token: your-token-here\n", false),
    ],
};

fn kube_hits(bytes: &[u8]) -> Hits {
    utf8_lines(bytes, |text| {
        text.lines()
            .enumerate()
            .filter_map(|(i, raw)| {
                let (key, value) = raw.trim().trim_start_matches("- ").split_once(':')?;
                let (key, value) = (key.trim(), scalar_literal(value)?);
                // What "kubectl config view" prints in place of a value, and
                // the token of a sample file.
                // A signed token (three parts with dots between) is one
                // whatever letters happen to be in it.
                let part = |part: &str| {
                    !part.is_empty()
                        && part
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                };
                let signed = value.len() >= 40
                    && value.split('.').count() == 3
                    && value.split('.').all(part);
                let shown = !matches!(value, "REDACTED" | "DATA+OMITTED")
                    && (key != "token" || signed || plausible(value));
                (matches!(key, "token" | "password" | "client-key-data") && shown)
                    .then(|| Hit::line(i + 1))
            })
            .collect()
    })
}

pub const GCLOUD_LOGIN: Rule = Rule {
    id: "dev.gcloud.stored-login",
    category: "developer-cloud",
    kind: "inventory",
    severity: "medium",
    title: "Google Cloud sign-in stored by gcloud",
    explanation: "gcloud keeps a refresh token for application-default sign-in in this file. That is normal for gcloud. Loose Keys did not check whether the token still works or what it can access.",
    reason: None,
    next_step: Some("Sign out when you stop using gcloud, which revokes the token."),
    advice: Advice {
        steps: &[
            "When you no longer need it, revoke the stored sign-in: gcloud auth application-default revoke",
            "To sign out of gcloud itself as well: gcloud auth revoke --all",
        ],
        link: None,
    },
    targets: &[
        Target::File(".config/gcloud/application_default_credentials.json"),
        Target::Each(".config/gcloud/legacy_credentials", "adc.json"),
    ],
    matcher: Matcher::Whole {
        candidate: any,
        test: gcloud_hits,
    },
    samples: &[
        (br#"{"type": "authorized_user", "refresh_token": "synthetic-only-value"}"#, true),
        (br#"{"type": "authorized_user", "refresh_token": ""}"#, false),
        // Signed in as a service account through a user's own sign-in.
        (br#"{"type": "impersonated_service_account", "service_account_impersonation_url": "https://example.invalid", "source_credentials": {"type": "authorized_user", "refresh_token": "synthetic-only-value"}}"#, true),
        (br#"{"type": "external_account", "audience": "fixture", "credential_source": {"file": "/path/to/token"}}"#, false),
    ],
};

fn gcloud_hits(bytes: &[u8]) -> Hits {
    // A user's own sign-in, alone or as what a service account is reached
    // through. The refresh token is then one level down.
    const USER: &[&str] = &[
        "authorized_user",
        "impersonated_service_account",
        "external_account_authorized_user",
    ];
    json_hits(bytes, |v| {
        v["type"].as_str().is_some_and(|t| USER.contains(&t))
            && json_has_secret(v, &["refresh_token"])
    })
}

/// gcloud's own sign-ins, in a small database with one row per account.
pub const GCLOUD_STORE: Rule = Rule {
    targets: &[Target::File(".config/gcloud/credentials.db")],
    matcher: Matcher::Whole {
        candidate: any,
        test: gcloud_store_hits,
    },
    samples: &[(&GCLOUD_ONE, true), (&GCLOUD_NONE, false)],
    ..GCLOUD_LOGIN
};

const GCLOUD_SCHEMA: &[u8] = b"credentials";
const GCLOUD_ONE: [u8; 1024] = browser::sqlite_sample_of(GCLOUD_SCHEMA, 1);
const GCLOUD_NONE: [u8; 1024] = browser::sqlite_sample_of(GCLOUD_SCHEMA, 0);

fn gcloud_store_hits(bytes: &[u8]) -> Hits {
    let rows = browser::sqlite_table_rows(bytes, b"credentials").ok_or("unreadable")?;
    Ok((rows != browser::Rows::Exactly(0))
        .then(Hit::file)
        .into_iter()
        .collect())
}

pub const AZURE_LOGIN: Rule = Rule {
    id: "dev.azure.stored-login",
    title: "Azure sign-in stored by the Azure CLI",
    explanation: "On macOS the Azure CLI keeps its refresh tokens in this file as plain text. That is normal for the Azure CLI. Loose Keys did not check whether the tokens still work or what they can access.",
    next_step: Some("Sign out when you stop using the Azure CLI."),
    advice: Advice {
        steps: &[
            "When you no longer need it, sign out and clear the stored tokens: az logout, then az account clear",
        ],
        link: None,
    },
    targets: &[Target::File(".azure/msal_token_cache.json")],
    matcher: Matcher::Whole {
        candidate: any,
        test: azure_hits,
    },
    samples: &[
        (br#"{"RefreshToken": {"fixture": {"secret": "synthetic-only-value"}}}"#, true),
        (br#"{"RefreshToken": {}, "Account": {}}"#, false),
    ],
    ..GCLOUD_LOGIN
};

fn azure_hits(bytes: &[u8]) -> Hits {
    json_hits(bytes, |v| json_has_secret(&v["RefreshToken"], &["secret"]))
}

pub const TERRAFORM_TOKEN: Rule = Rule {
    id: "dev.terraform.inline-token",
    title: "Terraform Cloud token stored in a file",
    explanation: "Terraform keeps its API token for HCP Terraform or Terraform Enterprise in this file as plain text. Loose Keys did not check whether it still works or what it can access.",
    reason: Some("A Terraform user token does not expire by default and can run plans that change infrastructure."),
    next_step: Some("Sign out to remove the token, and revoke it in your Terraform account. Deleting the file does not revoke it."),
    advice: Advice {
        steps: &[
            "Remove the stored token: terraform logout",
            "In HCP Terraform, open User Settings > Tokens and delete the token, since removing the file does not revoke it.",
            "When you next need it, 'terraform login' creates a new token. Give it an expiry date.",
        ],
        link: Some("https://app.terraform.io/app/settings/tokens"),
    },
    targets: &[Target::File(".terraform.d/credentials.tfrc.json")],
    matcher: Matcher::Whole {
        candidate: any,
        test: terraform_hits,
    },
    samples: &[
        (br#"{"credentials": {"app.terraform.io": {"token": "synthetic-only-value"}}}"#, true),
        (br#"{"credentials": {}}"#, false),
    ],
    ..KUBE_CREDENTIALS
};

fn terraform_hits(bytes: &[u8]) -> Hits {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| "unreadable")?;
    Ok(v["credentials"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, c)| json_has_secret(c, &["token"]))
        .map(|(host, _)| Hit::file().about(host))
        .collect())
}

pub const VAULT_TOKEN: Rule = Rule {
    id: "dev.vault.token",
    severity: "medium",
    title: "Vault token stored in a file",
    explanation: "The Vault CLI keeps its current token in this file as plain text. Loose Keys did not check whether it still works or what it can access.",
    reason: Some("A Vault token can read whatever secrets its policies allow until it expires or is revoked."),
    next_step: Some("Revoke the token when you are done with Vault. Deleting the file does not revoke it."),
    advice: Advice {
        steps: &[
            "Revoke the stored token: vault token revoke -self",
            "Delete ~/.vault-token.",
            "Ask your Vault administrator for short token lifetimes, so a copied token stops working soon.",
        ],
        link: None,
    },
    targets: &[Target::File(".vault-token")],
    matcher: Matcher::Whole {
        candidate: any,
        test: vault_hits,
    },
    samples: &[(b"hvs.synthetic-only-value\n", true), (b"\n", false)],
    ..KUBE_CREDENTIALS
};

fn vault_hits(bytes: &[u8]) -> Hits {
    utf8_lines(bytes, |text| {
        inline_literal(text.trim())
            .then(Hit::file)
            .into_iter()
            .collect()
    })
}

/// A kubeconfig saved anywhere else: a download, a project folder.
pub const KUBE_ANYWHERE: Rule = Rule {
    targets: &[Target::Discovery],
    matcher: Matcher::Whole {
        candidate: kubeconfig_head,
        test: kube_hits,
    },
    samples: &[
        (b"apiVersion: v1\nclusters:\n- cluster:\n    server: https://k8s.example.invalid\n  name: fixture\nkind: Config\nusers:\n- name: fixture\n  user:\n    token: synthetic-only\n", true),
        (b"apiVersion: v1\nclusters:\n- cluster:\n    server: https://k8s.example.invalid\n  name: fixture\nkind: Config\nusers:\n- name: fixture\n  user:\n    exec:\n      command: aws\n", false),
        (b"apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers: []\n      token: synthetic-only\n", false),
    ],
    ..KUBE_CREDENTIALS
};

/// kubectl writes keys in alphabetical order, so a large certificate can
/// push "server:" past the head; the certificate's own key stands in for it.
fn kubeconfig_head(head: &[u8]) -> bool {
    let has = |needle: &[u8]| head.windows(needle.len()).any(|w| w == needle);
    has(b"apiVersion:") && has(b"clusters:") && (has(b"server:") || has(b"certificate-authority"))
}

pub const TERRAFORM_STATE: Rule = Rule {
    id: "dev.terraform.state-secret",
    title: "Secret stored in a Terraform state file",
    explanation: "Terraform keeps what it created in this state file as plain JSON, including passwords and keys that providers return. Loose Keys only checked that the values are not empty or placeholders.",
    reason: Some("State files hold working database passwords and cloud keys, and they stay in project folders long after the work is done."),
    next_step: Some("Change the passwords and keys in the state, and move the state to a remote backend. Deleting the file does not revoke anything."),
    advice: Advice {
        steps: &[
            "For each resource named here, change its password or key at the service.",
            "Store state remotely (HCP Terraform, or an encrypted bucket with locking) so no copy stays on this Mac: add a backend block and run 'terraform init -migrate-state'.",
            "Delete the local state file and its .backup copy once the remote state works.",
        ],
        link: None,
    },
    targets: &[Target::Name("terraform.tfstate*"), Target::Name("*.tfstate")],
    matcher: Matcher::Whole {
        candidate: any,
        test: tfstate_hits,
    },
    samples: &[
        (br#"{"version":4,"terraform_version":"1.9.0","resources":[{"mode":"managed","type":"aws_db_instance","name":"fixture","instances":[{"attributes":{"password":"synthetic-only-value"}}]}]}"#, true),
        (br#"{"version":4,"terraform_version":"1.9.0","resources":[{"mode":"managed","type":"fixture_thing","name":"fixture","instances":[{"attributes":{"connection":"synthetic-only-value"},"sensitive_attributes":[[{"type":"get_attr","value":"connection"}]]}]}]}"#, true),
        (br#"{"version":4,"terraform_version":"1.9.0","outputs":{"db_password":{"value":"synthetic-only-value","type":"string","sensitive":true}},"resources":[]}"#, true),
        (br#"{"version":3,"terraform_version":"1.9.0","backend":{"type":"s3","config":{"bucket":"fixture","access_key":null,"secret_key":"synthetic-only-value"}}}"#, true),
        (br#"{"version":4,"terraform_version":"1.9.0","resources":[{"mode":"managed","type":"aws_db_instance","name":"fixture","instances":[{"attributes":{"password":null,"username":"fixture-user-name"}}]}]}"#, false),
        (br#"{"version":4,"terraform_version":"1.9.0","resources":[]}"#, false),
        // "result" is a secret for a generated password, not for a name suffix.
        (br#"{"version":4,"terraform_version":"1.9.0","resources":[{"mode":"managed","type":"random_password","name":"fixture","instances":[{"attributes":{"result":"synthetic-only-value"}}]}]}"#, true),
        (br#"{"version":4,"terraform_version":"1.9.0","resources":[{"mode":"managed","type":"random_string","name":"suffix","instances":[{"attributes":{"result":"k3v9x2qa","length":8}}]}]}"#, false),
        (br#"{"password":"synthetic-only-value"}"#, false),
        (b"", false),
    ],
    ..KUBE_CREDENTIALS
};

/// Attribute names providers use for secrets they write to state.
const STATE_SECRETS: &[&str] = &[
    "password",
    "master_password",
    "secret",
    "secret_key",
    "ses_smtp_password_v4",
    "client_secret",
    "token",
    "private_key",
    "private_key_pem",
];

/// One hit for each resource, sensitive output and backend that holds a
/// literal secret, named for it.
fn tfstate_hits(bytes: &[u8]) -> Hits {
    // Terraform leaves an empty file behind in some workflows.
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(vec![]);
    }
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| "unreadable")?;
    // By the name as it will be shown: the scan keeps one finding for a
    // name, and one for all the holders whose names cannot be shown.
    let mut out: Vec<Hit> = Vec::new();
    let (held, mut limited) = state_secrets(&v);
    for held in held {
        let subject = label(&held.shown());
        if let Some(hit) = out.iter_mut().find(|hit| hit.subject == subject) {
            // Listed at low risk only if all it holds is short-lived.
            hit.low &= held.low;
        } else if out.len() < 100 {
            out.push(Hit {
                subject,
                low: held.low,
                ..Hit::file()
            });
        } else {
            limited = true;
        }
    }
    if limited {
        Err(Incomplete {
            reason: "scan-limit",
            hits: out,
        })
    } else {
        Ok(out)
    }
}

/// What the app fingerprints for this rule: the secrets, not the rest of a
/// file that every `terraform apply` rewrites. Never export this.
pub(super) fn tfstate_material(bytes: &[u8]) -> Option<Vec<u8>> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    // Not the credentials that last minutes: each apply fetches new ones,
    // and they are listed, never brought up for review.
    let mut held: Vec<_> = state_secrets(&v)
        .0
        .into_iter()
        .filter(|held| !held.low)
        .map(|held| (held.holder, held.secrets))
        .collect();
    held.sort();
    serde_json::to_vec(&held).ok()
}

/// What holds secrets in a state file: a resource by its type and name, an
/// output, or the backend. Everything is borrowed from the file as parsed,
/// so the work stays in proportion to the file whatever it repeats.
pub(super) struct Held<'a> {
    holder: (&'a str, &'a str),
    /// Each attribute that is a literal secret, and its value.
    pub(super) secrets: Vec<(&'a str, &'a str)>,
    /// All of it is credentials that last minutes or hours.
    low: bool,
}

impl Held<'_> {
    fn shown(&self) -> String {
        match self.holder {
            ("", name) => name.to_string(),
            (kind, name) => format!("{kind}.{name}"),
        }
    }
}

pub(super) fn state_secrets(v: &serde_json::Value) -> (Vec<Held<'_>>, bool) {
    let mut out = Vec::new();
    let mut limited = false;
    if !v["terraform_version"].is_string() {
        return (out, limited);
    }
    fn stored(v: &serde_json::Value) -> Option<&str> {
        v.as_str()
            .filter(|s| s.len() >= 8 && !s.starts_with('$') && plausible(s))
    }
    for resource in v["resources"].as_array().into_iter().flatten() {
        let kind = resource["type"].as_str().unwrap_or("");
        // "result" is what was generated: a secret only for a password.
        let generated = (kind == "random_password").then_some("result");
        let mut secrets = Vec::new();
        let instances = resource["instances"].as_array().into_iter().flatten();
        limited |= instances.clone().nth(1000).is_some();
        for instance in instances.take(1000) {
            // What Terraform itself marked sensitive, then the usual names.
            let marked = instance["sensitive_attributes"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|path| path[0]["value"].as_str());
            let usual = STATE_SECRETS.iter().copied().chain(generated);
            limited |= marked.clone().nth(100).is_some();
            let mut names: Vec<&str> = marked.take(100).chain(usual).collect();
            names.sort_unstable();
            names.dedup();
            for name in names {
                if let Some(value) = stored(&instance["attributes"][name]) {
                    secrets.push((name, value));
                }
            }
        }
        secrets.sort_unstable();
        secrets.dedup();
        if !secrets.is_empty() {
            out.push(Held {
                holder: (kind, resource["name"].as_str().unwrap_or("")),
                secrets,
                low: matches!(kind, "aws_eks_cluster_auth" | "aws_ecr_authorization_token"),
            });
        }
    }
    for (name, output) in v["outputs"].as_object().into_iter().flatten() {
        if let Some(value) = stored(&output["value"]).filter(|_| output["sensitive"] == true) {
            out.push(Held {
                holder: ("output", name),
                secrets: vec![("value", value)],
                low: false,
            });
        }
    }
    // The backend settings Terraform copies into .terraform/terraform.tfstate.
    let backend = ["access_key", "secret_key", "password", "token", "sas_token"];
    let secrets: Vec<_> = backend
        .iter()
        .filter_map(|name| Some((*name, stored(&v["backend"]["config"][*name])?)))
        .collect();
    if !secrets.is_empty() {
        out.push(Held {
            holder: ("", "backend"),
            secrets,
            low: false,
        });
    }
    (out, limited)
}
