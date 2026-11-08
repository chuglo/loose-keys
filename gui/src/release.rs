//! Whether GitHub's latest release is newer than this app. The window
//! fetches the reply (`gui/app/Updates.swift`); this reads it. The reply is
//! outside input: it is size-capped, only three fields are read, and no part
//! of it reaches an error.

use serde::Serialize;

/// The most of a reply that is read. GitHub's is a few KiB.
pub(crate) const MAX_BODY: usize = 1_048_576;

pub(crate) const NOT_EXPECTED: &str =
    "Loose Keys couldn't read GitHub's response. Try again later.";

#[derive(Serialize)]
pub(crate) struct ReleaseView {
    /// The release's version, only when it is newer than this app's.
    pub newer: Option<String>,
    pub current: String,
}

/// What a reply from GitHub's latest-release API says, against `current`.
pub(crate) fn check(body: &str, current: &str) -> Result<ReleaseView, String> {
    if body.len() > MAX_BODY {
        return Err(NOT_EXPECTED.into());
    }
    let reply: serde_json::Value =
        serde_json::from_str(body).map_err(|_| NOT_EXPECTED.to_string())?;
    let tag = reply
        .get("tag_name")
        .and_then(serde_json::Value::as_str)
        .ok_or(NOT_EXPECTED)?;
    let flag = |name: &str| reply.get(name).and_then(serde_json::Value::as_bool);
    let release = tag.strip_prefix('v').and_then(parts).ok_or(NOT_EXPECTED)?;
    // A test build's version goes on past "x.y.z": "-beta.1" makes it come
    // before that release, and "+local" changes nothing.
    let (core, suffix) = current
        .find(['-', '+'])
        .map_or((current, ""), |at| current.split_at(at));
    let own = parts(core).ok_or(NOT_EXPECTED)?;
    let unreleased = flag("draft") == Some(true) || flag("prerelease") == Some(true);
    let ahead = release > own || (release == own && suffix.starts_with('-'));
    let newer =
        (!unreleased && ahead).then(|| format!("{}.{}.{}", release[0], release[1], release[2]));
    Ok(ReleaseView {
        newer,
        current: format!("{}.{}.{}{suffix}", own[0], own[1], own[2]),
    })
}

/// "x.y.z", each part 1 to 9 ASCII digits, so it fits a `u32`.
fn parts(text: &str) -> Option<[u32; 3]> {
    let mut out = [0u32; 3];
    let mut pieces = text.split('.');
    for slot in &mut out {
        let piece = pieces.next()?;
        if piece.is_empty() || piece.len() > 9 || !piece.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *slot = piece.parse().ok()?;
    }
    pieces.next().is_none().then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::Path;

    /// Names that mark network code, kept in pieces so that this file holds
    /// none of them whole.
    const SWIFT_WORDS: &[&str] = &[
        concat!("URL", "Session"),
        concat!("URL", "Request"),
        concat!("NW", "Connection"),
        concat!("import ", "Network"),
        concat!("CF", "Stream"),
        concat!("CF", "Socket"),
        concat!("CFRead", "Stream"),
        concat!("CFWrite", "Stream"),
        concat!("sock", "et("),
        concat!("getStreams", "ToHost"),
        concat!("NSURL", "Connection"),
        concat!("getaddr", "info"),
        concat!("Data(contents", "Of:"),
        concat!("String(contents", "Of:"),
        concat!("XMLParser(contents", "Of:"),
        concat!("WK", "WebView"),
    ];
    const OBJC_WORDS: &[&str] = &[
        concat!("NSURL", "Session"),
        concat!("NSURL", "Connection"),
        concat!("CF", "Stream"),
        concat!("CF", "Socket"),
        concat!("sock", "et("),
        concat!("nw_", "connection"),
        concat!("CFRead", "Stream"),
        concat!("CFWrite", "Stream"),
        concat!("getaddr", "info"),
        concat!("dataWithContents", "OfURL"),
        concat!("stringWithContents", "OfURL"),
        concat!("initWithContents", "OfURL"),
        concat!("WK", "WebView"),
    ];
    /// Readers of a URL on a file the code itself made, each with the
    /// expression around it, so that no other use passes.
    const LOCAL_READS: &[(&str, &str)] = &[(
        "app/Preview.swift",
        concat!("String(contents", "Of: old, encoding: .utf8)"),
    )];
    const RUST_WORDS: &[&str] = &[
        concat!("std", "::net"),
        concat!("Tcp", "Stream"),
        concat!("Tcp", "Listener"),
        concat!("Udp", "Socket"),
        concat!("libc::", "socket"),
        concat!("libc::", "connect"),
        concat!("getaddr", "info"),
    ];

    fn network_words<'a>(text: &str, words: &[&'a str]) -> Vec<&'a str> {
        words.iter().copied().filter(|w| text.contains(w)).collect()
    }

    #[test]
    fn the_guard_finds_a_planted_word() {
        let swift = format!("let session = {}.shared", SWIFT_WORDS[0]);
        assert_eq!(network_words(&swift, SWIFT_WORDS), [SWIFT_WORDS[0]]);
        let rust = format!("use {}::*;", RUST_WORDS[0]);
        assert_eq!(network_words(&rust, RUST_WORDS), [RUST_WORDS[0]]);
        assert!(network_words("let session = Session.shared", SWIFT_WORDS).is_empty());
    }

    #[test]
    fn the_guard_knows_lower_level_routes() {
        let socket = format!(
            "let fd = unsafe {{ {}(2, 1, 0) }};",
            concat!("libc::", "socket")
        );
        assert!(
            !network_words(&socket, RUST_WORDS).is_empty(),
            "a raw socket"
        );
        let lookup = format!("{}(host, port, hints, out)", concat!("getaddr", "info"));
        assert!(
            !network_words(&lookup, RUST_WORDS).is_empty(),
            "a name lookup"
        );
        let stream = format!(
            "Stream.{}(withName: host, port: 443)",
            concat!("getStreams", "ToHost")
        );
        assert!(
            !network_words(&stream, SWIFT_WORDS).is_empty(),
            "a Foundation stream"
        );
        let old = format!(
            "{}(request: request, delegate: self)",
            concat!("NSURL", "Connection")
        );
        assert!(
            !network_words(&old, SWIFT_WORDS).is_empty(),
            "NSURLConnection from Swift"
        );
    }

    /// Readers that take a URL fetch a remote one as readily as a file, and
    /// a web view loads whatever it is given.
    #[test]
    fn the_guard_knows_readers_that_take_a_url() {
        for swift in [
            format!("let reply = try {}url)", concat!("Data(contents", "Of: ")),
            format!("let reply = try {}url)", concat!("NSData(contents", "Of: ")),
            format!(
                "let page = try {}url, encoding: .utf8)",
                concat!("String(contents", "Of: ")
            ),
            format!("let parser = {}url)", concat!("XMLParser(contents", "Of: ")),
            format!("let view = {}()", concat!("WK", "WebView")),
        ] {
            assert!(!network_words(&swift, SWIFT_WORDS).is_empty(), "{swift}");
        }
        for objc in [
            format!("[NSData {}url]", concat!("dataWithContents", "OfURL:")),
            format!("[NSString {}url]", concat!("stringWithContents", "OfURL:")),
            format!(
                "[[NSXMLParser alloc] {}url]",
                concat!("initWithContents", "OfURL:")
            ),
            format!("[[{} alloc] init]", concat!("WK", "WebView")),
        ] {
            assert!(!network_words(&objc, OBJC_WORDS).is_empty(), "{objc}");
        }
        // A file read by its path is no network code.
        let log = concat!("String(contents", "OfFile: log, encoding: .utf8)");
        assert!(network_words(log, SWIFT_WORDS).is_empty());
    }

    /// The window's update check is the only code that goes online. The
    /// scanner, the engine and its C bridge, and the rest of the window
    /// name no network API.
    #[test]
    fn network_code_lives_only_in_updates_swift() {
        let gui = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut problems = Vec::new();
        let mut updates = None;
        let mut stack = vec![gui.join("app"), gui.join("src"), gui.join("../src")];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if entry.file_type().unwrap().is_dir() {
                    stack.push(path);
                    continue;
                }
                let words = match path.extension().and_then(|e| e.to_str()) {
                    Some("swift") => SWIFT_WORDS,
                    Some("m" | "h") => OBJC_WORDS,
                    Some("rs") => RUST_WORDS,
                    _ => continue,
                };
                let mut text = std::fs::read_to_string(&path).unwrap();
                if path == gui.join("app/Updates.swift") {
                    updates = Some(text);
                    continue;
                }
                for (file, read) in LOCAL_READS {
                    if path == gui.join(file) {
                        if !text.contains(read) {
                            problems.push(format!("{}: no longer has {read}", path.display()));
                        }
                        text = text.replace(read, "");
                    }
                }
                for word in network_words(&text, words) {
                    problems.push(format!("{}: {word}", path.display()));
                }
            }
        }
        let updates = updates.expect("gui/app/Updates.swift holds the update check");
        assert!(
            updates.contains(SWIFT_WORDS[0]),
            "the walk reached Updates.swift but found no network code in it"
        );
        assert!(
            problems.is_empty(),
            "network code outside gui/app/Updates.swift:\n{}",
            problems.join("\n")
        );
    }

    fn reply(tag: &str) -> String {
        json!({"tag_name": tag, "draft": false, "prerelease": false}).to_string()
    }

    #[test]
    fn a_newer_release_is_offered() {
        let answer = check(&reply("v0.7.0"), "0.6.0").unwrap();
        assert_eq!(answer.newer.as_deref(), Some("0.7.0"));
        assert_eq!(answer.current, "0.6.0");
    }

    #[test]
    fn the_same_or_an_older_release_is_not_offered() {
        for tag in ["v0.6.0", "v0.5.9"] {
            assert_eq!(check(&reply(tag), "0.6.0").unwrap().newer, None, "{tag}");
        }
    }

    #[test]
    fn own_newer_build_is_not_offered_an_older_release() {
        assert_eq!(check(&reply("v0.6.0"), "0.7.0").unwrap().newer, None);
    }

    #[test]
    fn versions_compare_as_numbers() {
        for (tag, current, newer) in [
            ("v0.10.0", "0.9.0", "0.10.0"),
            ("v1.0.0", "0.6.0", "1.0.0"),
            ("v0.07.0", "0.6.0", "0.7.0"),
        ] {
            assert_eq!(
                check(&reply(tag), current).unwrap().newer.as_deref(),
                Some(newer),
                "{tag} against {current}"
            );
        }
    }

    /// A test build of this app has a version such as "0.10.0-beta.1". It
    /// was refused as a reply that could not be read, so every check failed.
    #[test]
    fn a_prerelease_of_this_app_is_offered_its_release() {
        let answer = check(&reply("v0.10.0"), "0.10.0-beta.1").unwrap();
        assert_eq!(answer.newer.as_deref(), Some("0.10.0"));
        assert_eq!(answer.current, "0.10.0-beta.1");
        for (tag, current) in [("v0.9.0", "0.10.0-beta.1"), ("v0.10.0", "0.10.0+local")] {
            let answer = check(&reply(tag), current).unwrap();
            assert_eq!(answer.newer, None, "{tag} against {current}");
            assert_eq!(answer.current, current);
        }
        assert_eq!(
            check(&reply("v0.11.0"), "0.10.0-beta.1")
                .unwrap()
                .newer
                .as_deref(),
            Some("0.11.0")
        );
    }

    #[test]
    fn drafts_and_prereleases_are_not_offered() {
        for field in ["draft", "prerelease"] {
            let mut body = json!({"tag_name": "v9.0.0", "draft": false, "prerelease": false});
            body[field] = json!(true);
            assert_eq!(
                check(&body.to_string(), "0.6.0").unwrap().newer,
                None,
                "{field}"
            );
        }
    }

    #[test]
    fn malformed_tags_are_refused() {
        for tag in [
            "0.7.0",
            "v0.7",
            "v0.7.0.1",
            "v0.7.0-beta",
            "v+0.7.0",
            " v0.7.0",
            "v0..0",
            "v1234567890.0.0",
            "",
            "v\u{0660}.7.0",
        ] {
            assert_eq!(
                check(&reply(tag), "0.6.0").err().as_deref(),
                Some(NOT_EXPECTED),
                "{tag:?}"
            );
        }
    }

    #[test]
    fn replies_that_are_not_a_release_are_refused() {
        for body in [
            "not json",
            "[]",
            "{}",
            r#"{"tag_name": 7}"#,
            "<html><body>Sign in to this network</body></html>",
        ] {
            assert_eq!(
                check(body, "0.6.0").err().as_deref(),
                Some(NOT_EXPECTED),
                "{body}"
            );
        }
    }

    #[test]
    fn an_oversized_reply_is_refused_before_parsing() {
        let valid = reply("v0.7.0");
        let at_cap = format!("{valid}{}", " ".repeat(MAX_BODY - valid.len()));
        assert_eq!(at_cap.len(), MAX_BODY);
        assert!(check(&at_cap, "0.6.0").is_ok());
        let past_cap = format!("{at_cap} ");
        assert_eq!(
            check(&past_cap, "0.6.0").err().as_deref(),
            Some(NOT_EXPECTED)
        );
    }

    #[test]
    fn errors_never_echo_the_reply() {
        for body in [
            reply("v1.2.3-planted-marker"),
            "planted-marker, not json".to_string(),
        ] {
            let error = check(&body, "0.6.0").err().expect("the reply is refused");
            assert!(!error.contains("planted"), "{error}");
        }
    }
}
