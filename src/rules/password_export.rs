//! Browser and password-manager CSV exports, plaintext Bitwarden JSON exports
//! and 1Password export files.

use super::*;

pub const PASSWORD_EXPORT: Rule = Rule {
    id: "export.password-csv",
    category: "password-export",
    kind: "review",
    severity: "high",
    title: "Possible password export file",
    explanation: "The first line of this CSV file looks like a browser or password manager export. That doesn't prove the file holds passwords. Loose Keys read only that line.",
    reason: Some("If it holds passwords, any program that can read the file can read them too."),
    next_step: Some("Delete exports you no longer need, including copies in the Trash and in synced folders. Deleting a file doesn't revoke the passwords in it, so change any that were exposed."),
    advice: Advice {
        steps: &[
            "Open the file's folder and confirm it's a password export you made.",
            "If you still need these passwords, import the file into a password manager first.",
            "Delete the file, then empty the Trash. Look for other copies in Downloads, Desktop and iCloud Drive.",
            "If the file was in a shared or synced folder, or you think this Mac had malware, change your email and bank passwords first, then the rest.",
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
    explanation: "This file looks like an unencrypted Bitwarden export, and at least one login in it has a password. Loose Keys didn't check whether the passwords still work.",
    reason: Some("Any program that can read the file can read the passwords in it."),
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
    explanation: "This file has the name and format of a 1Password export (1PUX). These exports hold every item unencrypted. Loose Keys didn't read the items inside.",
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

/// The export of 1Password 7 and earlier: a folder named *.1pif whose
/// data.1pif holds one unencrypted JSON item per line. Named by its extension
/// and recognised by its first item.
pub const ONEPASSWORD_1PIF_EXPORT: Rule = Rule {
    id: "export.password-1pif",
    title: "1Password export file",
    explanation: "This file has the name and format of a 1Password export (1PIF). These exports hold every item unencrypted. Loose Keys checked only the start of the file.",
    targets: &[Target::Name("*.1pif")],
    matcher: Matcher::Head(is_1pif),
    samples: &[
        (br#"{"uuid":"FIXTURE","title":"fixture","secureContents":{"fields":[]},"typeName":"webforms.WebForm"}"#, true),
        (b"***5642bee8-a5ff-11dc-8314-0800200c9a66***\n", false),
        (br#"{"uuid":"FIXTURE","title":"fixture"}"#, false),
    ],
    ..PASSWORD_EXPORT
};

/// A JSON item as 1Password writes it, with a uuid and its contents or type.
fn is_1pif(head: &[u8]) -> bool {
    let has = |key: &[u8]| head.windows(key.len()).any(|w| w == key);
    let start = head.strip_prefix(b"\xef\xbb\xbf").unwrap_or(head);
    start.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{')
        && has(b"\"uuid\"")
        && (has(b"\"secureContents\"") || has(b"\"typeName\""))
}

fn bitwarden_hits(bytes: &[u8]) -> Hits {
    json_hits(bytes, is_bitwarden_export)
}

/// Deliberately limited to plaintext exports of a personal vault, which list
/// folders, or of an organization, which list collections: not arbitrary
/// password fields, encrypted exports or other JSON formats.
fn is_bitwarden_export(v: &serde_json::Value) -> bool {
    v["encrypted"].as_bool() == Some(false)
        && (v["folders"].is_array() || v["collections"].is_array())
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
/// Chrome, Firefox, Safari, Bitwarden, 1Password, RoboForm and others.
pub fn is_password_export(head: &[u8]) -> bool {
    // Only the first line can be the header, so only it is made text, not
    // a binary head to its end.
    let line = head.split_inclusive(|b| *b == b'\n').next();
    let text = String::from_utf8_lossy(line.unwrap_or_default());
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
    has(&["password", "login_password", "pwd"])
        && has(&["url", "login_uri", "website", "web site", "origin"])
        && has(&["username", "login_username", "user name", "email", "login"])
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
    fn bitwarden_organization_exports_have_collections_in_place_of_folders() {
        let organization = serde_json::json!({"encrypted": false, "collections": [], "items": [
            {"id": "synthetic-id", "name": "fixture", "type": 1, "collectionIds": [], "login": {"password": "synthetic-only"}}
        ]});
        assert!(is_bitwarden_export(&organization));
        let mut value = organization.clone();
        value["collections"] = serde_json::json!({});
        assert!(!is_bitwarden_export(&value));
    }

    #[test]
    fn export_header_byte_boundaries_do_not_change_detection() {
        for header in [
            &b"url,username,password\r\n\xff\x00"[..],
            &b"\xef\xbb\xbfurl,username,password\n\xff"[..],
            &b"url,username,password"[..],
        ] {
            assert!(is_password_export(header));
        }
        for other in [
            &b"\nurl,username,password\n"[..],
            &b"\r\nurl,username,password\n"[..],
            &b"\xff\nurl,username,password\n"[..],
            &b""[..],
        ] {
            assert!(!is_password_export(other));
        }
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
        // RoboForm, from its browser extension and from its app.
        assert!(is_password_export(
            b"Name,Url,MatchUrl,Login,Pwd,Note,Folder,RfFieldsV2"
        ));
        assert!(is_password_export(
            b"Name,URL,MatchUrl,Login,Password,Note,Folder,RfFieldsV2"
        ));
        assert!(!is_password_export(b"name,url,login,notes"));
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
