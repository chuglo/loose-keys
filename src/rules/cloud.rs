//! Cloud and infrastructure CLI credentials: Kubernetes, Google Cloud, Azure,
//! Terraform and Vault.

use super::*;

mod tfstate;
#[cfg(test)]
pub(super) use tfstate::state_secrets;
use tfstate::tfstate_hits;
pub(super) use tfstate::tfstate_material;

pub const GCP_SERVICE_ACCOUNT: Rule = Rule {
    id: "dev.gcp.service-account-key",
    category: "developer-cloud",
    kind: "review",
    severity: "high",
    title: "Google Cloud service account key file",
    explanation: "This JSON file holds a service account's private key. Loose Keys didn't check whether the key still works or what it can access.",
    reason: Some("A service account key doesn't expire by default and works from any computer. These files are often left in Downloads after being created."),
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
    explanation: "A token, password or client key is written directly in the kubeconfig file. Loose Keys didn't check whether it still works, or on which cluster.",
    reason: Some("Credentials written into a kubeconfig last a long time and work from any computer that can reach the cluster."),
    next_step: Some("Replace them with a sign-in plugin that fetches short-lived credentials. Removing the entry doesn't revoke it on the cluster."),
    advice: Advice {
        steps: &[
            "See which users have credentials stored in the file. This command hides their values: kubectl config view",
            "Recreate each entry with the provider's sign-in plugin, which stores no secret: 'aws eks update-kubeconfig', 'gcloud container clusters get-credentials' or 'az aks get-credentials' with kubelogin.",
            "Remove users you no longer need: kubectl config delete-user <name>",
            "On the cluster, delete the service account token that was stored here.",
            "If a client certificate was stored here, ask the cluster's admin to remove what it can access. Kubernetes can't revoke a certificate before it expires.",
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
        // What an OpenID Connect sign-in leaves, as kubectl writes it.
        (b"users:\n- name: fixture\n  user:\n    auth-provider:\n      config:\n        client-id: fixture\n        refresh-token: synthetic-only-value\n      name: oidc\n", true),
        (b"users:\n- name: fixture\n  user:\n    auth-provider:\n      config:\n        client-secret: synthetic-only-value\n      name: oidc\n", true),
        (b"users:\n- name: fixture\n  user:\n    exec:\n      command: aws\n", false),
        (b"users:\n- name: fixture\n  user:\n    client-key: /path/to/key.pem\n    token: #none\n", false),
        // What "kubectl config view" prints in place of the values.
        (b"users:\n- name: fixture\n  user:\n    client-key-data: DATA+OMITTED\n    token: REDACTED\n", false),
        (b"users:\n- name: fixture\n  user:\n    token: your-token-here\n", false),
        // YAML expands no "$", but an unquoted "&" or "!" opens an anchor or a tag.
        (b"users:\n- name: fixture\n  user:\n    password: Synth$tic-0nly-value\n", true),
        (b"users:\n- name: fixture\n  user:\n    password: '!synthetic-only-value'\n", true),
        (b"users:\n- name: fixture\n  user:\n    password: &synthetic-only-value\n", false),
    ],
};

fn kube_hits(bytes: &[u8]) -> Hits {
    if json_object(bytes) {
        let config = serde_json::from_slice(bytes).map_err(|_| "unreadable")?;
        let mut secrets = kube_json_secrets(&config);
        // JSON may spell several credentials on one line, with escaping.
        // Report the file once and fingerprint the decoded values.
        return Ok(secrets.next().map(|_| Hit::file()).into_iter().collect());
    }
    utf8_lines(bytes, |text| {
        text.lines()
            .enumerate()
            .filter_map(|(i, raw)| {
                let (key, value) = raw.trim().trim_start_matches("- ").split_once(':')?;
                let (key, value) = (key.trim(), scalar_literal_by(value, unexpanded_literal)?);
                // An OpenID Connect sign-in keeps its refresh token and
                // client secret under the user's auth-provider config.
                let named = matches!(
                    key,
                    "token" | "password" | "client-key-data" | "refresh-token" | "client-secret"
                );
                (named && kube_literal(key, value)).then(|| Hit::line(i + 1).at(text, value))
            })
            .collect()
    })
}

fn json_object(bytes: &[u8]) -> bool {
    bytes.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{')
}

fn kube_literal(key: &str, value: &str) -> bool {
    if value.trim().is_empty() || matches!(value, "REDACTED" | "DATA+OMITTED") {
        return false;
    }
    // A signed token has three base64url parts, whatever letters it uses.
    let part = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    let signed = value.len() >= 40 && value.split('.').count() == 3 && value.split('.').all(part);
    key != "token" || signed || plausible(value)
}

fn kube_json_secrets(config: &serde_json::Value) -> impl Iterator<Item = (&str, &str)> {
    let users = config["users"]
        .as_array()
        .filter(|_| config["apiVersion"] == "v1" && config["kind"] == "Config");
    users.into_iter().flatten().flat_map(|user| {
        let auth = &user["user"];
        let inline = ["token", "password", "client-key-data"].map(|key| (key, &auth[key]));
        let provider = &auth["auth-provider"]["config"];
        let provider = ["refresh-token", "client-secret"].map(|key| (key, &provider[key]));
        inline
            .into_iter()
            .chain(provider)
            .filter_map(|(key, value)| {
                let value = value.as_str()?;
                kube_literal(key, value).then_some((key, value))
            })
    })
}

pub(super) fn kube_material(bytes: &[u8]) -> Option<Vec<u8>> {
    if !json_object(bytes) {
        return None;
    }
    let config = serde_json::from_slice(bytes).ok()?;
    let mut secrets: Vec<_> = kube_json_secrets(&config).collect();
    secrets.sort_unstable();
    secrets.dedup();
    serde_json::to_vec(&secrets).ok()
}

pub const GCLOUD_LOGIN: Rule = Rule {
    id: "dev.gcloud.stored-login",
    category: "developer-cloud",
    kind: "inventory",
    severity: "medium",
    title: "Google Cloud sign-in stored by gcloud",
    explanation: "gcloud keeps a refresh token for your Google sign-in in this file. That's normal for gcloud. Loose Keys didn't check whether the token still works or what it can access.",
    reason: None,
    next_step: Some("Sign out when you stop using gcloud, which revokes the token."),
    advice: Advice {
        steps: &[
            "When you no longer need it, sign out of gcloud, which revokes its tokens: gcloud auth revoke --all",
            "If this file is application_default_credentials.json, revoke that sign-in too: gcloud auth application-default revoke",
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

pub(crate) const GCLOUD_DATABASE: &str = ".config/gcloud/credentials.db";

/// gcloud's own sign-ins, in a small database with one row per account.
pub const GCLOUD_STORE: Rule = Rule {
    targets: &[Target::File(GCLOUD_DATABASE)],
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
    let rows = sqlite::table_rows(bytes, b"credentials").ok_or("unreadable")?;
    Ok((rows != browser::Rows::Exactly(0))
        .then(Hit::file)
        .into_iter()
        .collect())
}

pub const AZURE_LOGIN: Rule = Rule {
    id: "dev.azure.stored-login",
    title: "Azure sign-in stored by the Azure CLI",
    explanation: "On macOS the Azure CLI keeps its refresh tokens in this file as plain text. That's normal for the Azure CLI. Loose Keys didn't check whether the tokens still work or what they can access.",
    next_step: Some("Sign out when you stop using the Azure CLI."),
    advice: Advice {
        steps: &[
            "When you no longer need it, sign out and clear the stored tokens: run 'az logout', then 'az account clear'.",
            "If the file may have been copied, ask your Azure admin to revoke your sessions. 'az logout' clears only this Mac.",
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

/// The Azure CLI before 2.30 kept its tokens in accessTokens.json: one
/// entry per sign-in. A user's entry holds its refresh and access tokens.
pub const AZURE_LEGACY_LOGIN: Rule = Rule {
    explanation: "Older versions of the Azure CLI kept sign-in tokens in this file as plain text. Loose Keys didn't check whether the tokens still work or what they can access.",
    // Not the current file's: the report shows one rule's findings with
    // the same reason as one entry, in the first one's words.
    reason: Some("Refresh tokens in this file may work from another computer until they expire or are revoked. Current versions of the Azure CLI don't remove the file when you sign out."),
    next_step: Some("Delete this file, which current versions of the Azure CLI don't use."),
    advice: Advice {
        steps: &[
            "Delete this file, then empty the Trash. Current versions of the Azure CLI don't use it.",
            "If the file may have been copied, ask your Azure admin to revoke your sessions. Deleting the file clears only this Mac.",
        ],
        link: None,
    },
    targets: &[Target::File(".azure/accessTokens.json")],
    matcher: Matcher::Whole {
        candidate: any,
        test: |bytes| azure_legacy_hits(bytes, false),
    },
    samples: &[
        (br#"[{"tokenType": "Bearer", "userId": "fixture@example.invalid", "refreshToken": "synthetic-only-value"}]"#, true),
        (br#"[{"servicePrincipalId": "fixture", "servicePrincipalTenant": "fixture", "accessToken": "synthetic-only-value"}]"#, false),
        (br#"[]"#, false),
    ],
    ..AZURE_LOGIN
};

/// Whether accessTokens.json holds a service principal's secret when
/// `principals`, or a user's sign-in tokens otherwise.
pub(super) fn azure_legacy_hits(bytes: &[u8], principals: bool) -> Hits {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| "unreadable")?;
    Ok(azure_legacy_entries(&v, principals)
        .then(Hit::file)
        .into_iter()
        .collect())
}

fn azure_legacy_entries(v: &serde_json::Value, principals: bool) -> bool {
    v.as_array().into_iter().flatten().any(|entry| {
        let principal = entry["servicePrincipalId"].is_string();
        if principals {
            principal && json_has_secret(entry, &["accessToken"])
        } else {
            !principal && json_has_secret(entry, &["refreshToken", "accessToken"])
        }
    })
}

pub const TERRAFORM_TOKEN: Rule = Rule {
    id: "dev.terraform.inline-token",
    title: "Terraform token stored in a file",
    explanation: "Terraform keeps its API token for HCP Terraform or Terraform Enterprise in this file as plain text. Loose Keys didn't check whether it still works or what it can access.",
    reason: Some("A Terraform user token doesn't expire by default and can run plans that change infrastructure."),
    next_step: Some("Sign out to remove the token, and revoke it in your Terraform account. Deleting the file doesn't revoke it."),
    advice: Advice {
        steps: &[
            "Remove the stored token: terraform logout",
            "In HCP Terraform, open User Settings > Tokens and delete the token.",
            "When you next need it, run 'terraform login' to create a new token, and give it an expiry date.",
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
    explanation: "The Vault CLI keeps its current token in this file as plain text. Loose Keys didn't check whether it still works or what it can access.",
    reason: Some("A Vault token can read whatever secrets its policies allow until it expires or is revoked."),
    next_step: Some("Revoke the token when you're done with Vault. Deleting the file doesn't revoke it."),
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
    samples: &[
        (b"hvs.synthetic-only-value\n", true),
        // The CLI reads the file as it is.
        (b"hvs.Synth$tic-0nly-value\n", true),
        (b"\n", false),
    ],
    ..KUBE_CREDENTIALS
};

fn vault_hits(bytes: &[u8]) -> Hits {
    utf8_lines(bytes, |text| {
        let token = text.trim();
        verbatim_literal(token)
            .then(|| Hit::file().at(text, token))
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
    if json_object(head) {
        has(b"\"apiVersion\"") && (has(b"\"kind\"") || has(b"\"clusters\""))
    } else {
        has(b"apiVersion:")
            && has(b"clusters:")
            && (has(b"server:") || has(b"certificate-authority"))
    }
}

pub const TERRAFORM_STATE: Rule = Rule {
    id: "dev.terraform.state-secret",
    title: "Secret stored in a Terraform state file",
    explanation: "Terraform keeps what it created in this state file as plain JSON, including passwords and keys that providers return. Loose Keys only checked that the values aren't empty or placeholders.",
    reason: Some("State files often hold working database passwords and cloud keys, and they stay in project folders long after the work is done."),
    next_step: Some("Change the passwords and keys in the state, and move the state to a remote backend. Deleting the file doesn't revoke anything."),
    advice: Advice {
        steps: &[
            "For each resource named here, change its password or key at the service.",
            "Store state remotely, in HCP Terraform or an encrypted bucket with locking, so no copy stays on this Mac. Add a backend block, then run 'terraform init -migrate-state'.",
            "Once the remote state works, delete the local state file and its .backup copy.",
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
        // Version 3, as Terraform 0.11 and earlier wrote it.
        (br#"{"version":3,"terraform_version":"0.11.14","modules":[{"path":["root"],"outputs":{},"resources":{"aws_db_instance.fixture":{"type":"aws_db_instance","primary":{"id":"fixture","attributes":{"password":"synthetic-only-value","username":"fixture-user-name"}}}}}]}"#, true),
        (br#"{"version":3,"terraform_version":"0.11.14","modules":[{"path":["root"],"outputs":{"db_password":{"sensitive":true,"type":"string","value":"synthetic-only-value"}},"resources":{}}]}"#, true),
        (br#"{"version":3,"terraform_version":"0.11.14","modules":[{"path":["root"],"outputs":{"name":{"sensitive":false,"type":"string","value":"synthetic-only-value"}},"resources":{"aws_db_instance.fixture":{"type":"aws_db_instance","primary":{"id":"fixture","attributes":{"username":"fixture-user-name"}}}}}]}"#, false),
        (br#"{"version":4,"terraform_version":"1.9.0","resources":[{"mode":"managed","type":"aws_db_instance","name":"fixture","instances":[{"attributes":{"password":null,"username":"fixture-user-name"}}]}]}"#, false),
        (br#"{"version":4,"terraform_version":"1.9.0","resources":[]}"#, false),
        // "result" is a secret for a generated password, not for a name suffix.
        (br#"{"version":4,"terraform_version":"1.9.0","resources":[{"mode":"managed","type":"random_password","name":"fixture","instances":[{"attributes":{"result":"synthetic-only-value"}}]}]}"#, true),
        (br#"{"version":4,"terraform_version":"1.9.0","resources":[{"mode":"managed","type":"random_string","name":"suffix","instances":[{"attributes":{"result":"k3v9x2qa","length":8}}]}]}"#, false),
        // A map Terraform marked sensitive as a whole.
        (br#"{"version":4,"terraform_version":"1.9.0","resources":[{"mode":"managed","type":"kubernetes_secret","name":"fixture","instances":[{"attributes":{"data":{"credentials":"synthetic-only-value"}},"sensitive_attributes":[[{"type":"get_attr","value":"data"}]]}]}]}"#, true),
        (br#"{"password":"synthetic-only-value"}"#, false),
        (b"", false),
    ],
    ..KUBE_CREDENTIALS
};
