#[path = "sqlite.rs"]
pub(crate) mod sqlite_fixture;

use serde::Deserialize;

/// Recipes are independent of the production matchers and their samples:
/// text, `parts` joined at run time so no token-shaped string is in the file
/// (`padding_lines` puts a token past the 4 KiB head), raw `bytes`, a
/// `sqlite` table of `rows` made by the system `sqlite3`, or an empty
/// `directory`.
#[derive(Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Body {
    Text(String),
    Parts {
        parts: Vec<String>,
        #[serde(default)]
        padding_lines: usize,
    },
    Bytes {
        bytes: Vec<u8>,
    },
    Sqlite {
        sqlite: String,
        rows: u8,
    },
    Directory {
        directory: bool,
    },
}

impl Body {
    /// None means an empty directory, not an absent fixture.
    pub fn bytes(&self) -> Option<Vec<u8>> {
        Some(match self {
            Self::Text(text) => text.as_bytes().to_vec(),
            Self::Parts {
                parts,
                padding_lines,
            } => {
                assert!(*padding_lines <= 1000, "fixture padding is bounded");
                let mut bytes =
                    b"{\"message\":\"ordinary synthetic record\"}\n".repeat(*padding_lines);
                bytes.extend(parts.concat().as_bytes());
                bytes
            }
            Self::Bytes { bytes } => bytes.clone(),
            Self::Sqlite { sqlite, rows } => sqlite_fixture::table(sqlite, *rows),
            Self::Directory { directory } => {
                assert!(directory, "directory recipe must be true");
                return None;
            }
        })
    }
}
