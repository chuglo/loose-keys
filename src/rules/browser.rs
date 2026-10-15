//! Passwords saved in browsers: the first thing an infostealer collects.
//! Only the number of saved logins is read. Nothing is decrypted.

use super::*;

/// Chromium-family browsers, as folders under the home that hold profiles.
/// Names from published stealer analyses; a browser that is not installed
/// costs one failed lookup.
pub const CHROMIUM: &[&str] = &[
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Google/Chrome Beta",
    "Library/Application Support/Google/Chrome Canary",
    "Library/Application Support/BraveSoftware/Brave-Browser",
    "Library/Application Support/Microsoft Edge",
    "Library/Application Support/Arc/User Data",
    "Library/Application Support/Chromium",
    "Library/Application Support/Vivaldi",
    "Library/Application Support/com.operasoftware.Opera",
    "Library/Application Support/com.operasoftware.OperaGX",
    "Library/Application Support/Yandex/YandexBrowser",
];

pub const CHROMIUM_LOGINS: Rule = Rule {
    id: "browser.chromium.saved-logins",
    category: "browser",
    kind: "review",
    severity: "medium",
    title: "Passwords saved in a browser",
    explanation: "This browser profile has saved passwords. They are encrypted with a key in your login keychain, so reading them needs your Mac password. Only the number of saved logins was read.",
    reason: Some("Infostealers such as Atomic (AMOS) show a fake system prompt to get the Mac password, then decrypt every password saved in the browser at once."),
    next_step: Some("Move saved passwords to a password manager and clear them from the browser. Deleting them here does not change the passwords themselves."),
    advice: Advice {
        steps: &[
            "Choose where passwords will live instead: the Passwords app built into macOS, or a password manager such as 1Password or Bitwarden. Both keep items locked until you unlock them.",
            "In the browser, open the password settings (chrome://password-manager/settings in Chrome, Brave, Edge and Arc) and export your passwords.",
            "Import the exported file into the password manager, check that the logins arrived, then delete the exported file and empty the Trash.",
            "Back in the browser's password settings, delete all saved passwords and turn off 'Offer to save passwords'.",
            "Stealers copy signed-in sessions too, which skip passwords and two-step codes. Sign out of bank and email sites when you finish, and after any infection use each site's 'sign out everywhere'.",
            "Never type your Mac password into a prompt that appears right after you open a download or paste a command into Terminal.",
        ],
        link: None,
    },
    targets: &[Target::Profiles("Login Data")],
    matcher: Matcher::Whole {
        candidate: any,
        test: chromium_hits,
    },
    samples: &[(&WITH_LOGINS, true), (&NO_LOGINS, false)],
};

const WITH_LOGINS: [u8; 1024] = sqlite_sample(3);
const NO_LOGINS: [u8; 1024] = sqlite_sample(0);

/// A two-page database whose `logins` table has `rows` rows.
const fn sqlite_sample(rows: u8) -> [u8; 1024] {
    sqlite_sample_of(b"logins", rows)
}

/// Complete small sample database: one ordinary table of NULL values. The
/// tests also use independent databases created by the system SQLite.
pub(super) const fn sqlite_sample_of(table: &[u8], rows: u8) -> [u8; 1024] {
    assert!(table.len() <= 20 && rows <= 84);
    let mut b = [0u8; 1024];
    let magic = b"SQLite format 3\0";
    let mut i = 0;
    while i < magic.len() {
        b[i] = magic[i];
        i += 1;
    }
    b[16] = 2; // 512-byte pages.
    b[18] = 1;
    b[19] = 1;
    b[21] = 64;
    b[22] = 32;
    b[23] = 32;
    b[27] = 1;
    b[31] = 2;
    b[43] = 1;
    b[47] = 4;
    b[59] = 1;
    b[95] = 1;
    let sql_prefix = b"CREATE TABLE ";
    let sql_suffix = b"(value TEXT)";
    let sql_len = sql_prefix.len() + table.len() + sql_suffix.len();
    let payload_len = 6 + 5 + table.len() * 2 + 1 + sql_len;
    let cell = 512 - payload_len - 2;
    b[100] = 13;
    b[104] = 1;
    b[105] = (cell >> 8) as u8;
    b[106] = cell as u8;
    b[108] = (cell >> 8) as u8;
    b[109] = cell as u8;
    b[cell] = payload_len as u8;
    b[cell + 1] = 1;
    b[cell + 2] = 6; // Record header: five serial types.
    b[cell + 3] = 23; // Text "table".
    b[cell + 4] = 13 + table.len() as u8 * 2;
    b[cell + 5] = 13 + table.len() as u8 * 2;
    b[cell + 6] = 1; // Root page, one-byte integer.
    b[cell + 7] = 13 + sql_len as u8 * 2;
    let mut at = cell + 8;
    let parts: [&[u8]; 7] = [
        b"table", table, table, b"\x02", sql_prefix, table, sql_suffix,
    ];
    let mut part = 0;
    while part < parts.len() {
        i = 0;
        while i < parts[part].len() {
            b[at] = parts[part][i];
            at += 1;
            i += 1;
        }
        part += 1;
    }
    b[512] = 13;
    b[516] = rows;
    let content = 512 - rows as usize * 4;
    b[517] = (content >> 8) as u8;
    b[518] = content as u8;
    i = 0;
    while i < rows as usize {
        let cell = 512 - (i + 1) * 4;
        b[520 + i * 2] = (cell >> 8) as u8;
        b[521 + i * 2] = cell as u8;
        b[512 + cell] = 2;
        b[513 + cell] = i as u8 + 1;
        b[514 + cell] = 2;
        i += 1;
    }
    b
}

fn chromium_hits(bytes: &[u8]) -> Hits {
    let rows = sqlite_table_rows(bytes, b"logins").ok_or("unreadable")?;
    Ok(saved_logins(rows))
}

fn saved_logins(rows: Rows) -> Vec<Hit> {
    match rows {
        Rows::Exactly(0) => vec![],
        Rows::Exactly(1) => vec![Hit::file().noting("1 saved login")],
        Rows::Exactly(n) => vec![Hit::file().noting(&format!("{n} saved logins"))],
        Rows::Many => vec![Hit::file().noting("many saved logins")],
    }
}

#[derive(Debug, PartialEq)]
pub(super) enum Rows {
    Exactly(usize),
    /// The table spans several pages.
    Many,
}

/// Whether a file is an SQLite database, by how it begins. What such a file
/// holds may be unsettled while a write-ahead log or rollback journal holds
/// anything: the scan checks both before trusting a count from the file.
pub fn is_sqlite(file: &[u8]) -> bool {
    file.starts_with(b"SQLite format 3\0")
}

/// Count only rows reachable through the live schema and table b-trees.
pub(super) fn sqlite_table_rows(db: &[u8], table: &[u8]) -> Option<Rows> {
    super::sqlite::table_rows(db, table)
}

pub const CHROMIUM_CARDS: Rule = Rule {
    id: "browser.chromium.saved-cards",
    title: "Payment cards saved in a browser",
    explanation: "This browser profile has saved payment cards. The card numbers are encrypted with a key in your login keychain, so reading them needs your Mac password. Only the number of saved cards was read.",
    reason: Some("Infostealers get the Mac password with a fake system prompt, then decrypt every card saved in the browser."),
    next_step: Some("Remove saved cards from the browser and pay with Apple Pay or a password manager instead."),
    advice: Advice {
        steps: &[
            "In the browser, open the payment settings (chrome://settings/payments in Chrome, Brave, Edge and Arc) and remove each saved card.",
            "Turn off 'Save and fill payment methods'.",
            "Pay with Apple Pay where you can, or keep cards in a password manager, which stays locked until you unlock it.",
        ],
        link: None,
    },
    targets: &[Target::Profiles("Web Data")],
    matcher: Matcher::Whole {
        candidate: any,
        test: card_hits,
    },
    samples: &[(&WITH_CARDS, true), (&NO_CARDS, false)],
    ..CHROMIUM_LOGINS
};

const WITH_CARDS: [u8; 1024] = sqlite_sample_of(b"credit_cards", 2);
const NO_CARDS: [u8; 1024] = sqlite_sample_of(b"credit_cards", 0);

fn card_hits(bytes: &[u8]) -> Hits {
    Ok(
        match sqlite_table_rows(bytes, b"credit_cards").ok_or("unreadable")? {
            Rows::Exactly(0) => vec![],
            Rows::Exactly(1) => vec![Hit::file().noting("1 saved card")],
            Rows::Exactly(n) => vec![Hit::file().noting(&format!("{n} saved cards"))],
            Rows::Many => vec![Hit::file().noting("many saved cards")],
        },
    )
}

pub const FIREFOX_LOGINS: Rule = Rule {
    id: "browser.firefox.saved-logins",
    explanation: "This Firefox profile has saved passwords. Unless a primary password is set, the key that decrypts them is stored next to them in the same folder. Only the number of saved logins was read.",
    reason: Some("Without a primary password, any program able to read the profile folder can decrypt every saved password. Infostealers collect this folder."),
    advice: Advice {
        steps: &[
            "Choose where passwords will live instead: the Passwords app built into macOS, or a password manager such as 1Password or Bitwarden.",
            "In Firefox, open about:logins, choose the menu (three dots) > Export Passwords, and import the file into the password manager.",
            "Check that the logins arrived, then delete the exported file and empty the Trash.",
            "In about:logins, choose the menu > Remove All Passwords, and in Settings > Privacy & Security turn off 'Ask to save passwords'.",
            "If you keep passwords in Firefox, set a primary password in Settings > Privacy & Security so they cannot be decrypted without it.",
        ],
        link: None,
    },
    targets: &[
        Target::Each("Library/Application Support/Firefox/Profiles", "logins.json"),
        Target::Each("Library/Application Support/Waterfox/Profiles", "logins.json"),
        Target::Each("Library/Application Support/librewolf/Profiles", "logins.json"),
        Target::Each("Library/Application Support/zen/Profiles", "logins.json"),
    ],
    matcher: Matcher::Whole {
        candidate: any,
        test: firefox_hits,
    },
    samples: &[
        (br#"{"nextId": 2, "logins": [{"id": 1, "hostname": "https://example.invalid"}]}"#, true),
        (br#"{"nextId": 1, "logins": []}"#, false),
    ],
    ..CHROMIUM_LOGINS
};

fn firefox_hits(bytes: &[u8]) -> Hits {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| "unreadable")?;
    let logins = v["logins"].as_array().ok_or("unreadable")?;
    Ok(saved_logins(Rows::Exactly(logins.len())))
}

#[cfg(test)]
mod tests {
    use super::super::fixture_body::sqlite_fixture;
    use super::*;

    #[test]
    fn schema_text_in_unused_bytes_is_not_a_table() {
        let mut db = sqlite_fixture::table("credentials", 1);
        let fake = b"tableloginslogins\x02CREATE TABLE logins (";
        db[200..200 + fake.len()].copy_from_slice(fake);
        assert_eq!(sqlite_table_rows(&db, b"logins"), None);
    }

    #[test]
    fn truncated_database_is_not_an_empty_table() {
        let mut db = sqlite_fixture::table("logins", 0);
        db.truncate(520);
        assert_eq!(sqlite_table_rows(&db, b"logins"), None);
    }

    #[test]
    fn quoted_schema_and_multiple_pages_are_read_from_live_cells() {
        let db = sqlite_fixture::database(
            "PRAGMA page_size=512; CREATE TABLE \"logins\"(value TEXT); \
             WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100) \
             INSERT INTO logins SELECT printf('%080d', x) FROM n;",
        );
        assert_eq!(sqlite_table_rows(&db, b"logins"), Some(Rows::Many));
    }

    #[test]
    fn schema_pages_and_large_page_sizes_use_the_same_reader() {
        for size in [512, 4096, 65536] {
            let mut sql = format!("PRAGMA page_size={size};");
            for i in 0..(if size == 65536 { 12 } else { 30 }) {
                sql.push_str(&format!("CREATE TABLE filler_{i}(value TEXT);"));
            }
            sql.push_str(
                "CREATE TABLE logins(value TEXT); INSERT INTO logins VALUES ('synthetic');",
            );
            let db = sqlite_fixture::database(&sql);
            assert_eq!(sqlite_table_rows(&db, b"logins"), Some(Rows::Exactly(1)));
        }
    }

    #[test]
    fn malformed_cells_and_cycles_are_unknown_not_counts() {
        let original = sqlite_fixture::table("logins", 3);
        for (offset, value) in [(520, 0), (521, 0), (516, 255), (517, 255), (518, 255)] {
            let mut db = original.clone();
            db[offset] = value;
            assert_eq!(sqlite_table_rows(&db, b"logins"), None, "offset {offset}");
        }
        let mut db = sqlite_fixture::database(
            "PRAGMA page_size=512; CREATE TABLE logins(value TEXT); \
             WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100) \
             INSERT INTO logins SELECT printf('%080d', x) FROM n;",
        );
        // Root's rightmost child points back to itself.
        db[520..524].copy_from_slice(&2u32.to_be_bytes());
        assert_eq!(sqlite_table_rows(&db, b"logins"), None);
    }

    #[test]
    fn unsupported_layouts_produce_no_count() {
        for sql in [
            "PRAGMA encoding='UTF-16'; CREATE TABLE logins(value TEXT);",
            "CREATE TABLE logins(value TEXT PRIMARY KEY) WITHOUT ROWID;",
            "PRAGMA page_size=512; CREATE TABLE logins(value TEXT); INSERT INTO logins VALUES(zeroblob(2000));",
        ] {
            assert_eq!(sqlite_table_rows(&sqlite_fixture::database(sql), b"logins"), None);
        }
    }

    #[test]
    fn row_counts_require_valid_live_cells() {
        assert_eq!(
            sqlite_table_rows(&sqlite_sample(0), b"logins"),
            Some(Rows::Exactly(0))
        );
        assert_eq!(
            sqlite_table_rows(&sqlite_sample(7), b"logins"),
            Some(Rows::Exactly(7))
        );
        let mut interior = sqlite_sample(0);
        interior[512] = 0x05;
        // A changed page tag alone does not make a valid interior tree.
        assert_eq!(sqlite_table_rows(&interior, b"logins"), None);
        // Not a database, no such table, or a root page past the end.
        assert_eq!(sqlite_table_rows(b"plain text", b"logins"), None);
        assert_eq!(sqlite_table_rows(&sqlite_sample(1), b"cookies"), None);
        let mut truncated = sqlite_sample(1).to_vec();
        truncated.truncate(400);
        assert_eq!(sqlite_table_rows(&truncated, b"logins"), None);
    }

    #[test]
    fn counts_are_a_detail_not_part_of_the_finding() {
        let one = &chromium_hits(&sqlite_sample(1)).unwrap()[0];
        assert_eq!(one.detail.as_deref(), Some("1 saved login"));
        let three = &chromium_hits(&sqlite_sample(3)).unwrap()[0];
        assert_eq!(three.detail.as_deref(), Some("3 saved logins"));
        // Saving another password must not make it a different finding.
        assert_eq!(one.subject, three.subject);
    }
}
