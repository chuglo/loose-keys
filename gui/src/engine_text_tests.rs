//! The engine and scanner text the window shows, against its Spanish.
//!
//! The window translates what the engine sends when it shows it, by looking
//! up the engine's exact English in `gui/macos/es.lproj/Engine.strings`, with
//! `gui/macos/es-419.lproj/Engine.strings` laid over it for Latin America.
//! The engine and the saved review list stay English. A key may be a
//! template with one `%@` (any text) or `%lld` (digits). A missing key shows
//! English and a stale one is never used, so this lists the English the
//! window can be given and compares both tables with it.

use loose_keys::{report, rules};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const ES: &str = "gui/macos/es.lproj/Engine.strings";
const ES_419: &str = "gui/macos/es-419.lproj/Engine.strings";

/// The files text is read from, as they were when this test was built.
const SOURCES: &[(&str, &str)] = &[
    ("gui/src/lib.rs", include_str!("lib.rs")),
    ("gui/src/review.rs", include_str!("review.rs")),
    ("gui/src/agent.rs", include_str!("agent.rs")),
    ("gui/src/monitor.rs", include_str!("monitor.rs")),
    ("src/scan.rs", include_str!("../../src/scan.rs")),
    ("src/fsutil.rs", include_str!("../../src/fsutil.rs")),
    ("src/rules/ai.rs", include_str!("../../src/rules/ai.rs")),
    ("src/rules/aws.rs", include_str!("../../src/rules/aws.rs")),
    (
        "src/rules/browser.rs",
        include_str!("../../src/rules/browser.rs"),
    ),
    (
        "schema/report-1.schema.json",
        include_str!("../../schema/report-1.schema.json"),
    ),
];

fn source(name: &str) -> &'static str {
    SOURCES
        .iter()
        .find(|(file, _)| *file == name)
        .map(|(_, text)| *text)
        .unwrap_or_else(|| panic!("no source named {name}"))
}

/// The engine's files. A sentence in their code outside tests is a message
/// the window can be given.
const ENGINE: &[&str] = &[
    "gui/src/lib.rs",
    "gui/src/review.rs",
    "gui/src/agent.rs",
    "gui/src/monitor.rs",
];

/// A gap id that `fsutil::open_directory` returns and the window is given.
const GAP_ID: &str = "a gap id from fsutil::open_directory: the whole error when the review \
     store cannot open the home folder, and inside \"export directory: %@\" and \"Could not \
     open the folder (%@).\"";

/// What the window can be given that is not a sentence in the engine's
/// code: whole errors that are not sentences, and the scanner's words that
/// engine messages wrap. Each must still be in its file's code outside
/// tests. Not here: "file already exists", which save_report replaces with
/// its own sentence, and error text from the system or serde_json, which no
/// table can match.
const EXTRA: &[(&str, &str, &str)] = &[
    (
        "HOME is not set to an absolute path",
        "src/scan.rs",
        "a whole error from skip_folder and the review store, the folder list's home \
         error, and inside \"Cannot scan: %@.\"",
    ),
    (
        "could not resolve selected path",
        "src/scan.rs",
        "inside \"Cannot add that folder: %@.\" and \"Cannot skip: %@.\"",
    ),
    (
        "selected paths must not contain '..'",
        "src/scan.rs",
        "inside \"Cannot add that folder: %@.\" and \"Cannot skip: %@.\"",
    ),
    (
        "the home folder, or a folder above it, cannot be skipped",
        "src/scan.rs",
        "inside \"Cannot skip: %@.\"",
    ),
    (
        "export needs a filename",
        "src/fsutil.rs",
        "inside \"Could not save: %@.\"",
    ),
    (
        "export directory: %@",
        "src/fsutil.rs",
        "inside \"Could not save: %@.\", around a gap id",
    ),
    (
        "invalid export filename",
        "src/fsutil.rs",
        "inside \"Could not save: %@.\"",
    ),
    (
        "as root, the export directory must be root-owned and not writable by others",
        "src/fsutil.rs",
        "inside \"Could not save: %@.\"",
    ),
    ("unreadable", "src/fsutil.rs", GAP_ID),
    ("permission-denied", "src/fsutil.rs", GAP_ID),
    // open_path returns it for a folder whose contents are only in the cloud.
    ("cloud-only-file", "src/fsutil.rs", GAP_ID),
    (
        "no folder",
        "gui/src/lib.rs",
        "item_path's whole error for a path with no folder above it",
    ),
];

/// What scan.rs adds to a finding's reason when others may read its file:
/// after the rule's reason, or alone when the rule has none.
const MODE_NOTE: &str = "Group/other read mode bits are set; effective access is unknown \
     because parent directories and ACLs were not assessed.";

/// Text the scanner builds as it runs, as the window receives it, and the
/// code in that file that builds it, exactly as it is written there. Each
/// place in the scanner's code that gives a finding a subject or detail
/// made from fixed text must be here or in `OTHER_SUBJECTS`.
fn built() -> Vec<(String, &'static str, String)> {
    let row = |key: &str, file: &'static str, code: &str| (key.to_string(), file, code.to_string());
    vec![
        row(
            "1 saved login",
            "src/rules/browser.rs",
            r#"Hit::file().noting("1 saved login")"#,
        ),
        row(
            "%lld saved logins",
            "src/rules/browser.rs",
            r#"Hit::file().noting(&format!("{n} saved logins"))"#,
        ),
        row(
            "many saved logins",
            "src/rules/browser.rs",
            r#"Hit::file().noting("many saved logins")"#,
        ),
        row(
            "1 saved card",
            "src/rules/browser.rs",
            r#"Hit::file().noting("1 saved card")"#,
        ),
        row(
            "%lld saved cards",
            "src/rules/browser.rs",
            r#"Hit::file().noting(&format!("{n} saved cards"))"#,
        ),
        row(
            "many saved cards",
            "src/rules/browser.rs",
            r#"Hit::file().noting("many saved cards")"#,
        ),
        row(
            "profile %@",
            "src/rules/aws.rs",
            r#".about(&format!("profile {profile}"))"#,
        ),
        row(
            "server %@",
            "src/rules/ai.rs",
            r#".about(&format!("server {name}"))"#,
        ),
        row(
            MODE_NOTE,
            "src/scan.rs",
            &format!("let mode_note = \"{MODE_NOTE}\";"),
        ),
        row(MODE_NOTE, "src/scan.rs", "None => mode_note.to_string()"),
        row(
            &format!("%@ {MODE_NOTE}"),
            "src/scan.rs",
            r#"Some(r) => format!("{r} {mode_note}")"#,
        ),
    ]
}

/// Places in the scanner's code that give a finding a subject or detail
/// from code holding a string literal, but whose text is the file's own, so
/// no table can match it. The code is as it is written there; each must
/// still be such a place, so the list cannot outlive the code.
const OTHER_SUBJECTS: &[(&str, &str, &str)] = &[
    (
        "src/rules/cloud.rs",
        r#".about(v["client_email"].as_str().unwrap_or(""))"#,
        "a service account's email address, as the key file has it",
    ),
    (
        "src/rules/logins.rs",
        r#".about(&shown.replace("__", ".").to_ascii_lowercase())"#,
        "a Bundler setting's name or a server's host name, as the file has it",
    ),
];

/// The repository, which holds the gui crate.
fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("gui is inside the repository")
}

/// The scanner's files that give findings their subject and detail, as
/// they are now: src/scan.rs and every file in src/rules, so a new rule
/// file is read too.
fn scanner_files() -> Result<Vec<(String, String)>, String> {
    let rules = root().join("src/rules");
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&rules).map_err(|e| format!("cannot list src/rules: {e}"))? {
        let entry = entry.map_err(|e| format!("cannot list src/rules: {e}"))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or("src/rules holds a file whose name is not UTF-8")?;
        if name.ends_with(".rs") {
            names.push(format!("src/rules/{name}"));
        }
    }
    names.sort();
    names.insert(0, "src/scan.rs".to_string());
    names
        .into_iter()
        .map(|name| match std::fs::read_to_string(root().join(&name)) {
            Ok(text) => Ok((name, text)),
            Err(e) => Err(format!("cannot read {name}: {e}")),
        })
        .collect()
}

/// What is wrong with `text` as a finding's reason, if anything. The review
/// list gives the window each reason through report::escape (shown() in
/// gui/src/lib.rs) and the results list does not, so both look up the same
/// key only when escaping leaves the reason as it is.
fn escaped(text: &str, origin: &str) -> Option<String> {
    let escaped = report::escape(text);
    (escaped != text).then(|| {
        format!(
            "{origin}: the review list gives the window a finding's reason through \
             report::escape (shown() in gui/src/lib.rs), which turns {} into {}, so the \
             review inspector would show it in English. Keep the reason printable ASCII \
             with no quotes or backslashes, or require its escaped form as a key too.",
            quoted(text),
            quoted(&escaped)
        )
    })
}

/// One text the window can be given, and where it comes from.
#[derive(Clone)]
struct Required {
    key: String,
    origin: String,
}

fn need(key: &str, origin: &str) -> Required {
    Required {
        key: key.to_string(),
        origin: origin.to_string(),
    }
}

/// The English the window can be given, and what is wrong with the code it
/// was read from.
fn required() -> (Vec<Required>, Vec<String>) {
    let mut problems = Vec::new();

    let mut rule_text = Vec::new();
    for rule in rules::RULES {
        let origin = format!("rule {}", rule.id);
        if let Some(reason) = rule.reason {
            problems.extend(escaped(reason, &origin));
        }
        let fields = [
            Some(rule.title),
            Some(rule.explanation),
            rule.reason,
            rule.next_step,
        ];
        for text in fields
            .into_iter()
            .flatten()
            .chain(rule.advice.steps.iter().copied())
        {
            rule_text.push(need(text, &origin));
        }
    }

    // A token finding's subject is its provider's name, and its steps are
    // the providers' shared ones.
    let mut tokens: Vec<Required> = rules::token_names()
        .map(|name| need(name, "token provider: a token finding's subject"))
        .collect();
    tokens.extend(
        rules::token_steps()
            .iter()
            .map(|step| need(step, "token provider: a token finding's steps")),
    );

    let built = built();
    let mut scanner_built = Vec::new();
    for (key, file, code) in &built {
        if source(file).contains(code.as_str()) {
            scanner_built.push(need(key, file));
        } else {
            problems.push(format!(
                "{file} no longer has `{code}`. If the scanner builds {key:?} another way \
                 now, change built() in gui/src/engine_text_tests.rs to match."
            ));
        }
    }
    for form in [MODE_NOTE.to_string(), format!("%@ {MODE_NOTE}")] {
        problems.extend(escaped(
            &form,
            "src/scan.rs, the note that others may read the file",
        ));
    }
    match scanner_files() {
        Ok(files) => problems.extend(subject_problems(&files, &built, OTHER_SUBJECTS)),
        Err(e) => problems.push(e),
    }

    let mut gaps = Vec::new();
    let schema: serde_json::Value =
        serde_json::from_str(source("schema/report-1.schema.json")).expect("the schema is JSON");
    let pointer = "/properties/not_checked/items/properties/reason/enum";
    match schema.pointer(pointer).and_then(|v| v.as_array()) {
        None => problems.push(format!(
            "schema/report-1.schema.json has no list of not_checked reasons at {pointer}"
        )),
        Some(reasons) => {
            for reason in reasons {
                let Some(reason) = reason.as_str() else {
                    problems.push(format!("a not_checked reason is not text: {reason}"));
                    continue;
                };
                let (label, help) = crate::gap_text(reason.to_string().leak());
                if label == reason {
                    problems.push(format!(
                        "gap_text in gui/src/lib.rs has no label for the not_checked reason {reason:?}"
                    ));
                    continue;
                }
                let origin = format!("not_checked reason {reason}: label, then any help");
                gaps.push(need(label, &origin));
                // The window shows no help when there is none.
                if !help.is_empty() {
                    gaps.push(need(help, &origin));
                }
            }
        }
    }

    let mut parsed = BTreeMap::new();
    let files = ENGINE.iter().chain(EXTRA.iter().map(|(_, file, _)| file));
    for file in files {
        if !parsed.contains_key(file) {
            match literals(source(file)) {
                Ok(found) => {
                    parsed.insert(*file, found);
                }
                Err(e) => problems.push(format!("{file}: {e}")),
            }
        }
    }
    let mut messages = Vec::new();
    for file in ENGINE {
        for literal in parsed.get(file).into_iter().flatten() {
            if !sentence(&literal.text) {
                continue;
            }
            if !literal.format && literal.text.contains(['{', '}']) {
                problems.push(format!(
                    "{file}:{}: cannot tell whether {:?} is a format string. If it is, add \
                     its macro to FORMATTING in gui/src/engine_text_tests.rs.",
                    literal.line, literal.text
                ));
            }
            messages.push(need(&literal.text, &format!("{file}:{}", literal.line)));
        }
    }
    for (text, file, why) in EXTRA {
        let mut found = parsed.get(file).into_iter().flatten();
        if found.any(|l| l.text == *text) {
            messages.push(need(text, &format!("{file}: {why}")));
        } else {
            problems.push(format!(
                "EXTRA in gui/src/engine_text_tests.rs names {text:?}, which is no longer in \
                 the code of {file} ({why}). Find what the window is given instead."
            ));
        }
    }

    let all = [rule_text, tokens, scanner_built, gaps, messages].concat();
    (all, problems)
}

/// Whether a literal reads as a sentence: it starts with a capital letter,
/// or with "macOS", which is written with a small m, and it has a space and
/// ends with a full stop.
fn sentence(text: &str) -> bool {
    (text.starts_with(|c: char| c.is_ascii_uppercase()) || text.starts_with("macOS "))
        && text.contains(' ')
        && text.ends_with('.')
}

// ---- Reading Rust source ----

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Ident(String),
    Punct(char),
    /// A string literal's value and the line it starts on. Byte and C
    /// strings are `Other`: the engine never shows one.
    Str(String, usize),
    Other,
}

/// Rust source as tokens, with comments left out.
fn tokens(src: &str) -> Result<Vec<Token>, String> {
    let c: Vec<char> = src.chars().collect();
    let at = |i: usize| c.get(i).copied();
    let word_char = |ch: char| ch.is_alphanumeric() || ch == '_';
    let mut out = Vec::new();
    let (mut i, mut line) = (0, 1);
    while let Some(ch) = at(i) {
        if ch == '\n' {
            line += 1;
            i += 1;
        } else if ch.is_whitespace() {
            i += 1;
        } else if ch == '/' && at(i + 1) == Some('/') {
            while at(i).is_some_and(|ch| ch != '\n') {
                i += 1;
            }
        } else if ch == '/' && at(i + 1) == Some('*') {
            let mut depth = 0;
            loop {
                match (at(i), at(i + 1)) {
                    (None, _) => return Err(format!("line {line}: a comment does not end")),
                    (Some('/'), Some('*')) => {
                        depth += 1;
                        i += 2;
                    }
                    (Some('*'), Some('/')) => {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    }
                    (Some(ch), _) => {
                        line += usize::from(ch == '\n');
                        i += 1;
                    }
                }
            }
        } else if ch.is_alphabetic() || ch == '_' {
            let start = i;
            while at(i).is_some_and(word_char) {
                i += 1;
            }
            let word: String = c[start..i].iter().collect();
            let hashes = c[i..].iter().take_while(|ch| **ch == '#').count();
            match (word.as_str(), at(i)) {
                ("r" | "br" | "cr", Some('"' | '#')) if at(i + hashes) == Some('"') => {
                    let first = line;
                    let close: Vec<char> = std::iter::once('"')
                        .chain(std::iter::repeat_n('#', hashes))
                        .collect();
                    i += hashes + 1;
                    let start = i;
                    while !c[i..].starts_with(&close) {
                        match at(i) {
                            None => return Err(format!("line {first}: a raw string does not end")),
                            Some(ch) => line += usize::from(ch == '\n'),
                        }
                        i += 1;
                    }
                    let text: String = c[start..i].iter().collect();
                    i += close.len();
                    out.push(if word == "r" {
                        Token::Str(text, first)
                    } else {
                        Token::Other
                    });
                }
                // A raw identifier, such as r#type.
                ("r", Some('#')) if at(i + 1).is_some_and(word_char) => {
                    i += 1;
                    let start = i;
                    while at(i).is_some_and(word_char) {
                        i += 1;
                    }
                    out.push(Token::Ident(c[start..i].iter().collect()));
                }
                ("b" | "c", Some('"')) => {
                    cooked(&c, &mut i, &mut line)?;
                    out.push(Token::Other);
                }
                ("b", Some('\'')) => {
                    i = char_end(&c, i, line)?;
                    out.push(Token::Other);
                }
                _ => out.push(Token::Ident(word)),
            }
        } else if ch.is_ascii_digit() {
            while at(i).is_some_and(word_char) {
                i += 1;
            }
            out.push(Token::Other);
        } else if ch == '"' {
            let first = line;
            let text = cooked(&c, &mut i, &mut line)?;
            out.push(Token::Str(text, first));
        } else if ch == '\'' {
            if at(i + 1) == Some('\\') || at(i + 2) == Some('\'') {
                i = char_end(&c, i, line)?;
            } else {
                // A lifetime or a loop label.
                i += 1;
                while at(i).is_some_and(word_char) {
                    i += 1;
                }
            }
            out.push(Token::Other);
        } else {
            out.push(Token::Punct(ch));
            i += 1;
        }
    }
    Ok(out)
}

/// Past the end of the character literal whose opening quote is at `i`.
fn char_end(c: &[char], i: usize, line: usize) -> Result<usize, String> {
    let mut j = i + 1;
    if c.get(j) == Some(&'\\') {
        j += 1;
    }
    j += 1;
    while c.get(j).is_some_and(|ch| *ch != '\'' && *ch != '\n') {
        j += 1;
    }
    match c.get(j) {
        Some('\'') => Ok(j + 1),
        _ => Err(format!("line {line}: a character literal does not end")),
    }
}

/// The value of the string literal whose opening quote is at `i`, with its
/// escapes read. Leaves `i` past its end and `line` on the line it ends on.
fn cooked(c: &[char], i: &mut usize, line: &mut usize) -> Result<String, String> {
    let first = *line;
    let unended = || format!("line {first}: a string does not end");
    let mut text = String::new();
    *i += 1;
    loop {
        let ch = *c.get(*i).ok_or_else(unended)?;
        *i += 1;
        match ch {
            '"' => return Ok(text),
            '\n' => {
                *line += 1;
                text.push('\n');
            }
            '\\' => {
                let escape = *c.get(*i).ok_or_else(unended)?;
                *i += 1;
                match escape {
                    'n' => text.push('\n'),
                    'r' => text.push('\r'),
                    't' => text.push('\t'),
                    '0' => text.push('\0'),
                    '\\' | '\'' | '"' => text.push(escape),
                    'x' => {
                        let hex: String = c.get(*i..*i + 2).ok_or_else(unended)?.iter().collect();
                        *i += 2;
                        let byte = u8::from_str_radix(&hex, 16)
                            .map_err(|_| format!("line {line}: a bad \\x escape"))?;
                        text.push(char::from(byte));
                    }
                    'u' => {
                        let end = *i
                            + c[*i..]
                                .iter()
                                .position(|ch| *ch == '}')
                                .ok_or_else(unended)?;
                        let hex: String = c[*i + 1..end].iter().filter(|ch| **ch != '_').collect();
                        *i = end + 1;
                        let scalar = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32);
                        text.push(scalar.ok_or_else(|| format!("line {line}: a bad \\u escape"))?);
                    }
                    // A line continuation: the line end and the spaces after it are dropped.
                    '\n' => {
                        *line += 1;
                        while let Some(space) = c.get(*i).filter(|ch| ch.is_whitespace()) {
                            *line += usize::from(*space == '\n');
                            *i += 1;
                        }
                    }
                    other => return Err(format!("line {line}: an unknown escape \\{other}")),
                }
            }
            ch => text.push(ch),
        }
    }
}

/// Past the end of the attribute whose `#` is at `i`, if one starts there.
fn attribute_end(tokens: &[Token], i: usize) -> Option<usize> {
    let mut j = i + 1;
    if tokens.get(j) == Some(&Token::Punct('!')) {
        j += 1;
    }
    if tokens.get(j) != Some(&Token::Punct('[')) {
        return None;
    }
    let mut depth = 0;
    for (k, token) in tokens.iter().enumerate().skip(j) {
        match token {
            Token::Punct('[') => depth += 1,
            Token::Punct(']') => {
                depth -= 1;
                if depth == 0 {
                    return Some(k + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// Past the end of the item that follows its first attribute at `i`: the
/// `;` or the closing brace that ends it. Anything else, such as a field
/// or a match arm marked for tests, is refused rather than guessed at.
fn item_end(tokens: &[Token], mut i: usize) -> Result<usize, String> {
    let unknown = |i: usize| {
        let item = &tokens[i.min(tokens.len())..(i + 8).min(tokens.len())];
        format!("this check cannot find the end of a test item that starts {item:?}")
    };
    let start = i;
    while tokens.get(i) == Some(&Token::Punct('#')) {
        i = attribute_end(tokens, i).ok_or_else(|| unknown(start))?;
    }
    let (mut depth, mut braced) = (0usize, false);
    while let Some(token) = tokens.get(i) {
        i += 1;
        match token {
            Token::Punct('(' | '[') => depth += 1,
            Token::Punct('{') => {
                braced |= depth == 0;
                depth += 1;
            }
            Token::Punct(')' | ']' | '}') => {
                depth = depth.checked_sub(1).ok_or_else(|| unknown(start))?;
                if depth == 0 && braced && *token == Token::Punct('}') {
                    if tokens.get(i) == Some(&Token::Punct(';')) {
                        i += 1;
                    }
                    return Ok(i);
                }
            }
            Token::Punct(';') if depth == 0 => return Ok(i),
            _ => {}
        }
    }
    Err(unknown(start))
}

/// The tokens outside test code: items marked #[cfg(test)] or #[test] are
/// left out. Any other attribute that names `test` is refused, so test code
/// marked a way this does not know cannot pass for code that runs.
fn without_test_code(tokens: &[Token]) -> Result<Vec<Token>, String> {
    let marks_test = |attribute: &[Token]| {
        let forms: [&[&str]; 2] = [
            &["#", "[", "cfg", "(", "test", ")", "]"],
            &["#", "[", "test", "]"],
        ];
        forms.iter().any(|form| {
            form.len() == attribute.len()
                && form.iter().zip(attribute).all(|(word, token)| match token {
                    Token::Ident(ident) => ident == word,
                    Token::Punct(c) => word.len() == 1 && word.starts_with(*c),
                    _ => false,
                })
        })
    };
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i] == Token::Punct('#') {
            if let Some(end) = attribute_end(tokens, i) {
                let attribute = &tokens[i..end];
                if marks_test(attribute) {
                    i = item_end(tokens, end)?;
                    continue;
                }
                if attribute.contains(&Token::Ident("test".into())) {
                    return Err(format!(
                        "an attribute names test in a way gui/src/engine_text_tests.rs does \
                         not know: {attribute:?}"
                    ));
                }
            }
        }
        out.push(tokens[i].clone());
        i += 1;
    }
    Ok(out)
}

/// A string literal in code outside tests, as the program has it.
struct Literal {
    /// As the window would be given it: in a format string each `{...}` is
    /// `%@`, and `{{` and `}}` are braces.
    text: String,
    line: usize,
    /// Whether it is the format string of one of `FORMATTING`.
    format: bool,
}

/// Macros whose first argument is a format string.
const FORMATTING: &[&str] = &[
    "format",
    "format_args",
    "panic",
    "print",
    "println",
    "eprint",
    "eprintln",
];

fn literals(src: &str) -> Result<Vec<Literal>, String> {
    let tokens = without_test_code(&tokens(src)?)?;
    let mut out = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        let Token::Str(text, line) = token else {
            continue;
        };
        let format = i >= 3
            && matches!(
                &tokens[i - 3..i],
                [Token::Ident(m), Token::Punct('!'), Token::Punct('(')]
                    if FORMATTING.contains(&m.as_str())
            );
        let text = if format {
            as_received(text).map_err(|e| format!("line {line}: {e}"))?
        } else {
            text.clone()
        };
        out.push(Literal {
            text,
            line: *line,
            format,
        });
    }
    Ok(out)
}

/// A format string as its output reads, with `%@` for each argument.
fn as_received(format: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut chars = format.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' | '}' if chars.peek() == Some(&c) => {
                chars.next();
                out.push(c);
            }
            '{' => {
                if !chars.by_ref().any(|c| c == '}') {
                    return Err(format!("an unclosed {{ in {format:?}"));
                }
                out.push_str("%@");
            }
            '}' => return Err(format!("a }} with no {{ in {format:?}")),
            c => out.push(c),
        }
    }
    Ok(out)
}

/// A place in code outside tests that gives a finding a subject or detail
/// from code holding a string literal: the line of its first literal, and
/// the code from the method or field name to the end of its argument.
struct Site {
    line: usize,
    code: Vec<Token>,
}

/// Each `.about(...)` and `.noting(...)` call, and each `subject` or
/// `detail` field set with `:` or `=`, whose argument holds a string literal.
fn fixed_subjects(src: &str) -> Result<Vec<Site>, String> {
    let tokens = without_test_code(&tokens(src)?)?;
    let mut out = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        let Token::Ident(name) = token else {
            continue;
        };
        let after = |n: usize| tokens.get(i + n);
        let called = i > 0 && tokens[i - 1] == Token::Punct('.');
        let end = match (name.as_str(), after(1), after(2)) {
            ("about" | "noting", Some(Token::Punct('(')), _) if called => {
                let close = expression_end(&tokens, i + 2);
                (close + 1).min(tokens.len())
            }
            ("subject" | "detail", Some(Token::Punct(':')), next)
                if next != Some(&Token::Punct(':')) =>
            {
                expression_end(&tokens, i + 2)
            }
            ("subject" | "detail", Some(Token::Punct('=')), next)
                if !matches!(next, Some(Token::Punct('=' | '>'))) =>
            {
                expression_end(&tokens, i + 2)
            }
            _ => continue,
        };
        let code = &tokens[i..end];
        if let Some(line) = code.iter().find_map(|t| match t {
            Token::Str(_, line) => Some(*line),
            _ => None,
        }) {
            out.push(Site {
                line,
                code: bare(code),
            });
        }
    }
    Ok(out)
}

/// Where the expression that starts at `j` ends: at the bracket that closes
/// the one it is in, or at a `,` or `;` outside brackets.
fn expression_end(tokens: &[Token], j: usize) -> usize {
    let mut depth = 0usize;
    for (k, token) in tokens.iter().enumerate().skip(j) {
        match token {
            Token::Punct('(' | '[' | '{') => depth += 1,
            Token::Punct(')' | ']' | '}') => match depth.checked_sub(1) {
                Some(d) => depth = d,
                None => return k,
            },
            Token::Punct(',' | ';') if depth == 0 => return k,
            _ => {}
        }
    }
    tokens.len()
}

/// Tokens without the lines their literals are on, to compare code.
fn bare(tokens: &[Token]) -> Vec<Token> {
    tokens
        .iter()
        .map(|t| match t {
            Token::Str(text, _) => Token::Str(text.clone(), 0),
            t => t.clone(),
        })
        .collect()
}

/// What is wrong with the subjects and details made from fixed text in
/// `files`: each must be in the code of a `built` row or of `others` for
/// its file, and each of `others` must still be such a place.
fn subject_problems(
    files: &[(String, String)],
    built: &[(String, &str, String)],
    others: &[(&str, &str, &str)],
) -> Vec<String> {
    let mut problems = Vec::new();
    // The built rows, then the others, each as its file and its code.
    let rows = built
        .iter()
        .map(|(_, file, code)| (*file, code.as_str()))
        .chain(others.iter().map(|(file, code, _)| (*file, *code)));
    let mut listed = Vec::new();
    for (file, code) in rows {
        let code = tokens(code).unwrap_or_else(|e| {
            problems.push(format!("cannot read `{code}`: {e}"));
            Vec::new()
        });
        listed.push((file, bare(&code)));
    }
    let mut used = vec![false; listed.len()];
    for (file, text) in files {
        let sites = match fixed_subjects(text) {
            Ok(sites) => sites,
            Err(e) => {
                problems.push(format!("{file}: {e}"));
                continue;
            }
        };
        for site in sites {
            let mut known = false;
            for (k, (listed_file, code)) in listed.iter().enumerate() {
                if listed_file == file && code.windows(site.code.len()).any(|w| w == site.code) {
                    (known, used[k]) = (true, true);
                }
            }
            if !known {
                let line = text.lines().nth(site.line - 1).unwrap_or("").trim();
                problems.push(format!(
                    "{file}:{}: `{line}` gives a finding fixed text as its subject or detail, \
                     which the window shows. If it is English, add it to built() in \
                     gui/src/engine_text_tests.rs with the text the window is given; if it is \
                     the file's own text, add it to OTHER_SUBJECTS with why.",
                    site.line
                ));
            }
        }
    }
    for ((file, code, why), used) in others.iter().zip(&used[built.len()..]) {
        if !used {
            problems.push(format!(
                "OTHER_SUBJECTS in gui/src/engine_text_tests.rs names `{code}` in {file} \
                 ({why}), which no longer gives a finding a subject or detail there. Remove \
                 it from the list."
            ));
        }
    }
    problems
}

// ---- Reading and comparing the tables ----

/// The table at `path`, read by plutil as the build reads it. Repeated keys
/// and entry layout are checked by gui/tests/bundle-contract.test.js.
fn read_table(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let shown = path.display();
    let out = std::process::Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-"])
        .arg(path)
        .output()
        .map_err(|e| format!("cannot run /usr/bin/plutil: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{shown}: /usr/bin/plutil cannot read it ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let json: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("{shown}: plutil did not give a JSON object: {e}"))?;
    let mut entries = BTreeMap::new();
    for (key, value) in json {
        let value = value
            .as_str()
            .ok_or_else(|| format!("{shown}: the value of {key:?} is not text"))?;
        entries.insert(key, value.to_string());
    }
    Ok(entries)
}

/// The placeholders in a key or value, in order, or None where a `%` is
/// not the start of one.
fn placeholders(text: &str) -> Option<Vec<&'static str>> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find('%') {
        rest = &rest[at..];
        let placeholder = ["%@", "%lld"].into_iter().find(|p| rest.starts_with(p))?;
        found.push(placeholder);
        rest = &rest[placeholder.len()..];
    }
    Some(found)
}

/// At most one placeholder, `%@` or `%lld`, and no other `%`.
fn key_ok(key: &str) -> bool {
    placeholders(key).is_some_and(|found| found.len() <= 1)
}

/// The key's placeholder exactly once, or none if the key has none.
fn value_ok(key: &str, value: &str) -> bool {
    key_ok(key) && placeholders(value) == placeholders(key)
}

/// The words of a key that are code, paths or addresses, which the Spanish
/// must keep exactly.
fn code_words(key: &str) -> Vec<&str> {
    key.split_whitespace()
        .filter(|word| {
            word.starts_with("~/")
                || word.starts_with("--")
                || ["://", "${", "{{"].iter().any(|mark| word.contains(mark))
        })
        .map(|word| word.trim_end_matches(['.', ',', ';', ':', ')', '"', '\'']))
        .filter(|word| !word.is_empty())
        .collect()
}

/// Text as a .strings file quotes it.
fn quoted(text: &str) -> String {
    let mut out = String::from('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn entry(key: &str, value: &str) -> String {
    format!("{} = {};", quoted(key), quoted(value))
}

/// Every way the tables fail the required text, as one message: empty when
/// they do not.
fn compare(
    required: &[Required],
    es: &BTreeMap<String, String>,
    es419: &BTreeMap<String, String>,
) -> String {
    let mut sections = Vec::new();
    let mut add = |title: String, entries: Vec<String>| {
        if !entries.is_empty() {
            sections.push(format!(
                "{title} ({}):\n{}",
                entries.len(),
                entries.join("\n")
            ));
        }
    };

    let mut keys = BTreeSet::new();
    let unique: Vec<&Required> = required
        .iter()
        .filter(|r| keys.insert(r.key.as_str()))
        .collect();

    add(
        "REQUIRED TEXT THAT CANNOT BE A KEY: a key has at most one placeholder, %@ or %lld, \
         and no other %"
            .into(),
        unique
            .iter()
            .filter(|r| !key_ok(&r.key))
            .map(|r| format!("{} from {}", quoted(&r.key), r.origin))
            .collect(),
    );

    let mut missing = Vec::new();
    let mut origin = "";
    for r in unique.iter().filter(|r| !es.contains_key(&r.key)) {
        let line = entry(&r.key, "");
        if r.origin == origin {
            missing.push(line);
        } else {
            origin = &r.origin;
            missing.push(format!("/* {} */\n{line}", origin.replace("*/", "* /")));
        }
    }
    add(format!("MISSING from {ES}, ready to paste"), missing);

    add(
        format!(
            "STALE in {ES}: the window is never given this English. Remove it, or move its \
             Spanish to the key that replaced it"
        ),
        es.iter()
            .filter(|(key, _)| !keys.contains(key.as_str()))
            .map(|(key, value)| entry(key, value))
            .collect(),
    );

    for (name, table) in [(ES, es), (ES_419, es419)] {
        add(
            format!("UNTRANSLATED in {name}: the value is empty or the same as its key"),
            table
                .iter()
                .filter(|(key, value)| value.is_empty() || key == value)
                .map(|(key, value)| entry(key, value))
                .collect(),
        );
        add(
            format!(
                "PLACEHOLDERS in {name}: a key has at most one, %@ or %lld, its value has \
                 the same one exactly once, and neither has any other %"
            ),
            table
                .iter()
                .filter(|(key, value)| !value_ok(key, value))
                .map(|(key, value)| entry(key, value))
                .collect(),
        );
        add(
            format!("CODE NOT KEPT in {name}: copy these words of the key into its value exactly"),
            table
                .iter()
                .filter_map(|(key, value)| {
                    let lost: Vec<&str> = code_words(key)
                        .into_iter()
                        .filter(|word| !value.contains(word))
                        .collect();
                    (!lost.is_empty())
                        .then(|| format!("keep {} in: {}", lost.join(" "), entry(key, value)))
                })
                .collect(),
        );
    }

    sections.join("\n\n")
}

#[test]
fn engine_strings_translate_what_the_window_shows() {
    let (all, mut problems) = required();
    let distinct = all.iter().map(|r| &r.key).collect::<BTreeSet<_>>().len();
    match (
        read_table(&root().join(ES)),
        read_table(&root().join(ES_419)),
    ) {
        (Ok(es), Ok(es419)) => {
            let found = compare(&all, &es, &es419);
            if !found.is_empty() {
                problems.push(found);
            }
        }
        (es, es419) => problems.extend([es.err(), es419.err()].into_iter().flatten()),
    }
    assert!(
        problems.is_empty(),
        "{ES} and its overrides in {ES_419} do not match the English the window can be \
         given. The window looks each key up by the engine's exact English. A key may hold \
         one %@ (any text) or %lld (digits), and its Spanish keeps the same one, once.\n\
         Required: {} keys in all.\n\n{}",
        distinct,
        problems.join("\n\n")
    );
}

// ---- The checks themselves: each must be able to fail ----

fn table(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn needs(keys: &[&str]) -> Vec<Required> {
    keys.iter().map(|key| need(key, "a test")).collect()
}

/// The count in the heading of the section that starts with `title`.
fn count(message: &str, title: &str) -> Option<usize> {
    let heading = message
        .split("\n\n")
        .filter_map(|section| section.lines().next())
        .find(|heading| heading.starts_with(title))?;
    heading
        .strip_suffix("):")?
        .rsplit_once(" (")?
        .1
        .parse()
        .ok()
}

fn sections(message: &str) -> usize {
    message.split("\n\n").filter(|s| !s.is_empty()).count()
}

#[test]
fn compare_accepts_tables_that_match() {
    let required = needs(&[
        "Could not be read",
        "Cannot skip: %@.",
        "%lld saved logins",
        "Open ~/.aws/config, or run aws sso login --profile <name>.",
    ]);
    let es = table(&[
        ("Could not be read", "No se pudo leer"),
        ("Cannot skip: %@.", "No se puede omitir: %@."),
        ("%lld saved logins", "%lld inicios de sesi\u{f3}n guardados"),
        (
            "Open ~/.aws/config, or run aws sso login --profile <name>.",
            "Abra ~/.aws/config o ejecute aws sso login --profile <nombre>.",
        ),
    ]);
    let es419 = table(&[("Could not be read", "No se logr\u{f3} leer")]);
    assert_eq!(compare(&required, &es, &es419), "");
}

#[test]
fn compare_lists_a_missing_key_ready_to_paste() {
    let message = compare(&needs(&["Set \"credsStore\"."]), &table(&[]), &table(&[]));
    assert_eq!(
        count(&message, &format!("MISSING from {ES}")),
        Some(1),
        "{message}"
    );
    assert_eq!(sections(&message), 1, "{message}");
    assert!(
        message.contains("/* a test */\n\"Set \\\"credsStore\\\".\" = \"\";"),
        "{message}"
    );
}

#[test]
fn compare_lists_a_stale_key() {
    let es = table(&[("Old wording.", "Texto anterior.")]);
    let message = compare(&needs(&[]), &es, &table(&[]));
    assert_eq!(
        count(&message, &format!("STALE in {ES}")),
        Some(1),
        "{message}"
    );
    assert_eq!(sections(&message), 1, "{message}");
    assert!(
        message.contains("\"Old wording.\" = \"Texto anterior.\";"),
        "{message}"
    );
}

#[test]
fn compare_lists_an_untranslated_value() {
    let required = needs(&["Could not be read", "Too large to check"]);
    let es = table(&[
        ("Could not be read", "Could not be read"),
        ("Too large to check", ""),
    ]);
    let message = compare(&required, &es, &table(&[]));
    assert_eq!(
        count(&message, &format!("UNTRANSLATED in {ES}")),
        Some(2),
        "{message}"
    );
    assert_eq!(sections(&message), 1, "{message}");
}

#[test]
fn compare_lists_each_placeholder_mismatch() {
    let required = needs(&[
        "Cannot skip: %@.",
        "%lld saved cards",
        "Done.",
        "Could not save: %@.",
    ]);
    let es = table(&[
        ("Cannot skip: %@.", "No se puede omitir."),
        ("%lld saved cards", "%@ tarjetas guardadas"),
        ("Done.", "Hecho al 100%."),
        ("Could not save: %@.", "No se pudo guardar: %@ (%@)."),
    ]);
    let message = compare(&required, &es, &table(&[]));
    assert_eq!(
        count(&message, &format!("PLACEHOLDERS in {ES}")),
        Some(4),
        "{message}"
    );
    assert_eq!(sections(&message), 1, "{message}");
}

#[test]
fn compare_lists_required_text_that_cannot_be_a_key() {
    let message = compare(
        &needs(&["Moved %@ to %@.", "Half 50% done."]),
        &table(&[]),
        &table(&[]),
    );
    assert_eq!(
        count(&message, "REQUIRED TEXT THAT CANNOT BE A KEY"),
        Some(2),
        "{message}"
    );
    assert!(
        message.contains("\"Moved %@ to %@.\" from a test"),
        "{message}"
    );
    assert!(
        message.contains("\"Half 50% done.\" from a test"),
        "{message}"
    );
}

#[test]
fn compare_lists_a_dropped_code_word() {
    let key = "Set \"credsStore\": \"osxkeychain\" in ~/.docker/config.json, or open \
               chrome://settings/payments, or use ${env.REPO_TOKEN}.";
    let es = table(&[(
        key,
        "Defina \"credsStore\": \"osxkeychain\" en la configuraci\u{f3}n de Docker, o abra \
         chrome://settings/payments, o use la variable.",
    )]);
    let message = compare(&needs(&[key]), &es, &table(&[]));
    assert_eq!(
        count(&message, &format!("CODE NOT KEPT in {ES}")),
        Some(1),
        "{message}"
    );
    assert_eq!(sections(&message), 1, "{message}");
    assert!(
        message.contains("keep ~/.docker/config.json ${env.REPO_TOKEN} in:"),
        "{message}"
    );
}

#[test]
fn compare_checks_the_overrides() {
    let required = needs(&["Cannot skip: %@."]);
    let es = table(&[("Cannot skip: %@.", "No se puede omitir: %@.")]);
    let es419 = table(&[("Cannot skip: %@.", "No se puede omitir.")]);
    let message = compare(&required, &es, &es419);
    assert_eq!(
        count(&message, &format!("PLACEHOLDERS in {ES_419}")),
        Some(1),
        "{message}"
    );
}

#[test]
fn literals_are_read_as_the_program_has_them() {
    let src = r####"
// "A line comment."
/* "A block /* nested */ comment." */
fn a<'a>(x: &'a str) -> char { let _ = ('"', '\'', b'"', "Plain \"quoted\" text."); 'x' }
fn b(e: &str) -> String { format!("Cannot {e}: {{x}} {:?} {0}.", r#"Raw "text"."#, b"Bytes.") }
#[cfg(test)]
#[derive(Debug)]
enum C { A }
#[cfg(test)]
fn c() { let _ = "Only in a test."; }
#[cfg(test)]
mod tests { fn d() { let _ = "Also in a test."; } }
#[test]
fn e() { let _ = "A test."; }
fn f() { let _ = ("Line \
    continued.", r#type, c"C text.", "\u{e9}\x41"); }
"####;
    let found: Vec<(String, usize, bool)> = literals(src)
        .unwrap()
        .into_iter()
        .map(|l| (l.text, l.line, l.format))
        .collect();
    let expected = [
        ("Plain \"quoted\" text.", 4, false),
        ("Cannot %@: {x} %@ %@.", 5, true),
        ("Raw \"text\".", 5, false),
        ("Line continued.", 15, false),
        ("\u{e9}A", 16, false),
    ]
    .map(|(text, line, format)| (text.to_string(), line, format));
    assert_eq!(found, expected);
}

#[test]
fn test_code_marked_another_way_is_refused() {
    for src in [
        "#[cfg(not(test))]\nfn a() {}\n",
        "#[cfg_attr(test, derive(Debug))]\nstruct A;\n",
        "#![cfg(test)]\nfn a() {}\n",
        "#[cfg(any(test, feature = \"x\"))]\nfn a() {}\n",
        "struct S {\n    #[cfg(test)]\n    a: u8,\n    b: u8,\n}\n",
    ] {
        assert!(literals(src).is_err(), "{src}");
    }
    assert!(literals("fn a() -> String { format!(\"a } b\") }").is_err());
}

#[test]
fn a_reason_escaping_changes_is_refused() {
    assert_eq!(escaped("Others may read it.", "a test"), None);
    for text in ["Set \"credsStore\".", "Use C:\\keys.", "Caf\u{e9} keys."] {
        let found = escaped(text, "a test").unwrap_or_default();
        assert!(
            found.starts_with("a test: the review list"),
            "{text:?}: {found}"
        );
    }
}

#[test]
fn fixed_subjects_must_be_built_or_listed() {
    let src = r####"
fn a(n: usize, name: &str) -> Vec<Hit> {
    vec![
        Hit::file().noting("1 saved login"),
        Hit::file().noting("2 saved passkeys"),
        Hit::line(1).about(name),
        Hit::file().about(&format!("vault {name}")),
        Hit { subject: label("fixed"), ..Hit::file() },
        Hit { subject: label(name), ..Hit::file() },
        Hit::file().about(&name.replace("__", ".")),
    ]
}
fn b(hit: &mut Hit, n: usize) {
    hit.detail = label(&format!("{n} keys"));
    if hit.subject == label("x") {}
}
#[cfg(test)]
mod tests { fn c() { let _ = Hit::file().noting("Only in a test."); } }
"####;
    let file = "src/rules/x.rs";
    let files = [(file.to_string(), src.to_string())];
    let built = [(
        "1 saved login".to_string(),
        file,
        r#"Hit::file().noting("1 saved login")"#.to_string(),
    )];
    let others = [
        (
            file,
            r#".about(&name.replace("__", "."))"#,
            "the file's name",
        ),
        (file, r#".about("gone")"#, "no longer there"),
    ];
    let problems = subject_problems(&files, &built, &others);
    for line in [5, 7, 8, 14] {
        let at = format!("{file}:{line}: ");
        assert_eq!(
            problems.iter().filter(|p| p.starts_with(&at)).count(),
            1,
            "{line}: {problems:#?}"
        );
    }
    let stale = problems
        .iter()
        .filter(|p| p.starts_with("OTHER_SUBJECTS") && p.contains(r#"`.about("gone")`"#))
        .count();
    assert_eq!(stale, 1, "{problems:#?}");
    assert_eq!(problems.len(), 5, "{problems:#?}");

    let everything_listed = [
        (file, r#".noting("2 saved passkeys")"#, "a test"),
        (file, r#".about(&format!("vault {name}"))"#, "a test"),
        (file, r#"subject: label("fixed")"#, "a test"),
        (file, r#"detail = label(&format!("{n} keys"))"#, "a test"),
        (file, r#".about(&name.replace("__", "."))"#, "a test"),
    ];
    let problems = subject_problems(&files, &built, &everything_listed);
    assert!(problems.is_empty(), "{problems:#?}");
}
