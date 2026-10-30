//! Browser and password-manager CSV exports, and plaintext Bitwarden JSON exports.

use super::*;

pub const PASSWORD_EXPORT: Rule = Rule {
    id: "export.password-csv",
    category: "password-export",
    kind: "review",
    severity: "high",
    title: "Possible password export file",
    explanation: "The first line of this CSV file looks like a browser or password manager export. That does not prove the file holds passwords. Loose Keys read only that line.",
    reason: Some("If it holds passwords, any program that can read the file can read them too."),
    next_step: Some("Delete exports you no longer need, including copies in the Trash and in synced folders. Deleting a file does not revoke the passwords in it, so change any that were exposed."),
    advice: Advice {
        steps: &[
            "Open the file's folder and confirm it is a password export you made.",
            "If you still need these passwords, import the file into a password manager first.",
            "Delete the file, then empty the Trash. Look for other copies in Downloads, Desktop and iCloud Drive.",
            "If the file sat in a shared or synced folder, or you think this Mac had malware, change the passwords for your email and bank accounts first, then the rest.",
        ],
        link: None,
    },
    targets: &[Target::Discovery],
    matcher: Matcher::Head(is_password_export),
    samples: &[
        (b"name,url,username,password\nx,y,z,w\n", true),
        (b"\xef\xbb\xbfurl,username,password\n", true),
        (b"name,url,username,notes\n", false),
        // Minified source maps hold the same words on one line.
        (br#"{"version":3,"names":["url","username","password"]}"#, false),
    ],
};

pub const BITWARDEN_EXPORT: Rule = Rule {
    id: "export.password-bitwarden-json",
    title: "Possible unencrypted Bitwarden export",
    explanation: "This file looks like an unencrypted Bitwarden export, and at least one login in it has a password. Loose Keys did not check whether the passwords still work.",
    matcher: Matcher::Whole {
        candidate: is_bitwarden_candidate,
        test: bitwarden_hits,
    },
    samples: &[
        (
            br#"{"encrypted": false, "folders": [], "items": [{"id": "s", "name": "s", "type": 1, "login": {"password": "synthetic"}}]}"#,
            true,
        ),
        (br#"{"encrypted": true, "folders": [], "items": []}"#, false),
        (br#"{"lockfileVersion": 1, "password": "synthetic"}"#, false),
    ],
    ..PASSWORD_EXPORT
};

/// 1Password's own export: a ZIP whose export.data holds every item
/// unencrypted. Named by its extension and recognised by the ZIP signature;
/// nothing inside is opened.
pub const ONEPASSWORD_EXPORT: Rule = Rule {
    id: "export.password-1pux",
    title: "1Password export file",
    explanation: "This file has the name and format of a 1Password export (1PUX). These exports hold every item unencrypted. Loose Keys did not read the items inside.",
    targets: &[Target::Name("*.1pux")],
    matcher: Matcher::Head(is_zip),
    samples: &[
        (b"PK\x03\x04\x14\x00\x00\x00\x08\x00synthetic", true),
        (b"not an archive", false),
    ],
    ..PASSWORD_EXPORT
};

fn is_zip(head: &[u8]) -> bool {
    head.starts_with(b"PK\x03\x04")
}

fn bitwarden_hits(bytes: &[u8]) -> Hits {
    json_hits(bytes, is_bitwarden_export)
}

/// Deliberately limited to plaintext personal exports, not arbitrary password
/// fields, encrypted exports, organization exports or other JSON formats.
fn is_bitwarden_export(v: &serde_json::Value) -> bool {
    v["encrypted"].as_bool() == Some(false)
        && v["folders"].is_array()
        && v["items"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item["type"].as_u64() == Some(1)
                    && item["id"].as_str().is_some_and(|s| !s.is_empty())
                    && item["name"].is_string()
                    && item["login"]["password"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty())
            })
        })
}

/// A CSV header with URL, username and password columns, as written by
/// Chrome, Firefox, Safari, Bitwarden, 1Password and others.
pub fn is_password_export(head: &[u8]) -> bool {
    let text = String::from_utf8_lossy(head);
    let first = text
        .trim_start_matches('\u{feff}')
        .lines()
        .next()
        .unwrap_or("")
        .trim_start();
    // Minified JSON (source maps, bundles) can hold the same words in one line.
    if first.starts_with(['{', '[']) {
        return false;
    }
    let cols: Vec<String> = first
        .split(',')
        .map(|c| c.trim().trim_matches('"').to_ascii_lowercase())
        .collect();
    let has = |names: &[&str]| cols.iter().any(|c| names.contains(&c.as_str()));
    has(&["password", "login_password"])
        && has(&["url", "login_uri", "website", "web site", "origin"])
        && has(&["username", "login_username", "user name", "email"])
}

/// Bitwarden writes "encrypted" first, so lockfiles, source maps and other
/// JSON never get a full read or a parse gap.
pub fn is_bitwarden_candidate(head: &[u8]) -> bool {
    head.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{')
        && head.windows(11).any(|w| w == b"\"encrypted\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitwarden_requires_the_plaintext_personal_login_structure() {
        let valid = serde_json::json!({"encrypted": false, "folders": [], "items": [
            {"id": "synthetic-id", "name": "fixture", "type": 1, "login": {"password": "synthetic-only"}}
        ]});
        assert!(is_bitwarden_export(&valid));
        for field in ["encrypted", "folders", "items"] {
            let mut value = valid.clone();
            value.as_object_mut().unwrap().remove(field);
            assert!(!is_bitwarden_export(&value));
        }
        for replacement in [serde_json::json!(true), serde_json::json!("false")] {
            let mut value = valid.clone();
            value["encrypted"] = replacement;
            assert!(!is_bitwarden_export(&value));
        }
        for password in [
            serde_json::json!(""),
            serde_json::Value::Null,
            serde_json::json!(123),
        ] {
            let mut value = valid.clone();
            value["items"][0]["login"]["password"] = password;
            assert!(!is_bitwarden_export(&value));
        }
        for field in ["id", "name", "type", "login"] {
            let mut value = valid.clone();
            value["items"][0].as_object_mut().unwrap().remove(field);
            assert!(!is_bitwarden_export(&value));
        }
        assert!(!is_bitwarden_export(
            &serde_json::json!({"password": "synthetic-only"})
        ));
        assert!(!is_bitwarden_export(
            &serde_json::json!({"encrypted": false, "folders": [], "items": []})
        ));
    }

    #[test]
    fn export_headers() {
        assert!(is_password_export(b"name,url,username,password\nx,y,z,w"));
        assert!(is_password_export(
            b"\xef\xbb\xbf\"url\",\"username\",\"password\",\"httpRealm\""
        ));
        assert!(is_password_export(
            b"Title,URL,Username,Password,Notes,OTPAuth"
        ));
        assert!(is_password_export(b"folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp"));
        assert!(!is_password_export(b"name,url,username,notes"));
        assert!(!is_password_export(b"password,reset,date"));
        assert!(!is_password_export(
            br#"{"version":3,"names":["url","username","password","token"]}"#
        ));
        assert!(!is_password_export(br#"["url","username","password"]"#));
    }

    #[test]
    fn bitwarden_candidates_need_the_encrypted_key_in_the_head() {
        assert!(is_bitwarden_candidate(b"\n  {\n  \"encrypted\": false,"));
        assert!(!is_bitwarden_candidate(
            b"{\"lockfileVersion\": 1, \"packages\": {"
        ));
        assert!(!is_bitwarden_candidate(b"[{\"encrypted\": false}]"));
    }
}
