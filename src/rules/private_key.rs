//! PEM and OpenSSH private keys, split by whether the header shows a passphrase.

use super::*;

pub const SSH_KEY: Rule = Rule {
    id: "key.ssh.private",
    category: "private-key",
    kind: "inventory",
    severity: "low",
    title: "Possible private key",
    explanation: "A private-key header was found. The key has not been validated or tested for access; a passphrase can make a copied key harder to use.",
    reason: None,
    next_step: None,
    advice: Advice::NONE,
    targets: &[Target::Discovery, Target::Dir(".ssh")],
    matcher: Matcher::Head(other_key),
    samples: &[
        (concat!("-----BEGIN ENCRYPTED ", "PRIVATE KEY-----\nsynthetic\n").as_bytes(), true),
        (b"ssh-ed25519 AAAA synthetic public key\n", false),
    ],
};

pub const SSH_KEY_NO_PASSPHRASE: Rule = Rule {
    kind: "review",
    severity: "high",
    reason: Some("The key has no passphrase, so a copy of this file works as it is. The header does not show that the key is valid or has current authorization."),
    next_step: Some("Add a passphrase. Deleting a copy or adding a passphrase does not revoke access the key already has."),
    advice: Advice {
        steps: &[
            "If this is an SSH key you use, add a passphrase: ssh-keygen -p -f <key file> (for a PuTTY .ppk file, set one in PuTTYgen instead).",
            "Let macOS remember the passphrase so you are not asked each time: ssh-add --apple-use-keychain <key file>",
            "If you do not recognize the key or no longer use it, remove its public key from the servers and services that trust it (GitHub: Settings > SSH and GPG keys), then delete the file.",
            "If the key may have been copied, replace it: create a new key, install it, and remove the old public key everywhere.",
        ],
        link: None,
    },
    matcher: Matcher::Head(unprotected_key),
    samples: &[
        (concat!("-----BEGIN RSA ", "PRIVATE KEY-----\nsynthetic\n").as_bytes(), true),
        (concat!("-----BEGIN ENCRYPTED ", "PRIVATE KEY-----\nsynthetic\n").as_bytes(), false),
    ],
    ..SSH_KEY
};

/// GnuPG keeps each private key in its own file. An unprotected one starts
/// "(private-key"; one with a passphrase, "(protected-private-key"; a stub
/// for a key on a smartcard, "(shadowed-private-key".
pub const GPG_KEY_UNPROTECTED: Rule = Rule {
    id: "key.gpg.private",
    title: "GnuPG private key with no passphrase",
    explanation: "This GnuPG private key is stored without a passphrase. It was not tested or used.",
    reason: Some("A copy of this file can sign and decrypt as you. Keys used to sign commits or releases are a target of supply-chain malware."),
    next_step: Some("Add a passphrase. If the key may have been copied, revoke it and publish the revocation."),
    advice: Advice {
        steps: &[
            "Find the key: gpg --list-secret-keys --keyid-format long",
            "Add a passphrase: gpg --edit-key <key id>, then 'passwd', then 'save'.",
            "If the key may have been copied, generate a revocation certificate (gpg --gen-revoke <key id>), import it, publish it to the keyservers and to GitHub or GitLab, then create a new key.",
        ],
        link: None,
    },
    targets: &[Target::Dir(".gnupg/private-keys-v1.d")],
    matcher: Matcher::Head(gpg_unprotected),
    samples: &[
        (b"Key: (private-key (ecc (curve Ed25519)(q #00#)(d #00#)))\n", true),
        (b"(11:private-key(3:ecc(5:curve7:Ed25519)))", true),
        (b"Key: (protected-private-key (ecc (curve Ed25519)))\n", false),
        (b"Key: (shadowed-private-key (ecc (curve Ed25519)))\n", false),
    ],
    ..SSH_KEY_NO_PASSPHRASE
};

pub const GPG_KEY: Rule = Rule {
    id: "key.gpg.private",
    title: "GnuPG private key",
    explanation: "A GnuPG private key protected by a passphrase. It was not tested or used.",
    targets: &[Target::Dir(".gnupg/private-keys-v1.d")],
    matcher: Matcher::Head(gpg_protected),
    samples: &[
        (
            b"Key: (protected-private-key (ecc (curve Ed25519)))\n",
            true,
        ),
        (
            b"Key: (private-key (ecc (curve Ed25519)(q #00#)(d #00#)))\n",
            false,
        ),
    ],
    ..SSH_KEY
};

fn has(head: &[u8], needle: &[u8]) -> bool {
    head.windows(needle.len()).any(|w| w == needle)
}

fn gpg_protected(head: &[u8]) -> bool {
    has(head, b"protected-private-key")
}

fn gpg_unprotected(head: &[u8]) -> bool {
    has(head, b"private-key") && !gpg_protected(head) && !has(head, b"shadowed-private-key")
}

fn unprotected_key(head: &[u8]) -> bool {
    key_protection(head) == KeyState::Unprotected
}

fn other_key(head: &[u8]) -> bool {
    matches!(
        key_protection(head),
        KeyState::Protected | KeyState::Unknown
    )
}

#[derive(Debug, PartialEq)]
pub enum KeyState {
    NotAKey,
    Protected,
    Unprotected,
    Unknown,
}

const PGP: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----";

pub fn key_protection(head: &[u8]) -> KeyState {
    let text = String::from_utf8_lossy(head);
    // PuTTY's own format: a version line, then "Encryption: none" or a cipher.
    if text.starts_with("PuTTY-User-Key-File-") {
        let encryption = text.lines().nth(1).map(str::trim);
        return match encryption.and_then(|l| l.strip_prefix("Encryption: ")) {
            Some("none") => KeyState::Unprotected,
            Some(_) => KeyState::Protected,
            None => KeyState::NotAKey,
        };
    }
    let Some((at, first)) = key_header(&text) else {
        return KeyState::NotAKey;
    };
    // An exported PGP key may or may not have a passphrase; the armor does not say.
    if first == PGP {
        return KeyState::Unknown;
    }
    if first.contains("ENCRYPTED") || text.contains("Proc-Type: 4,ENCRYPTED") {
        return KeyState::Protected;
    }
    if first != "-----BEGIN OPENSSH PRIVATE KEY-----" {
        return KeyState::Unprotected; // PEM/PKCS#8 without encryption markers
    }
    // openssh-key-v1: magic "openssh-key-v1\0", then a length-prefixed cipher name.
    let b64: String = text
        .lines()
        .skip(at + 1)
        .take_while(|l| !l.starts_with("-----"))
        .flat_map(str::chars)
        .take(64)
        .collect();
    let blob = base64_decode(&b64);
    if blob.len() < 19 || &blob[..15] != b"openssh-key-v1\0" {
        return KeyState::Unknown;
    }
    let n = u32::from_be_bytes([blob[15], blob[16], blob[17], blob[18]]) as usize;
    match blob.get(19..19 + n) {
        Some(b"none") => KeyState::Unprotected,
        Some(_) => KeyState::Protected,
        None => KeyState::Unknown,
    }
}

/// The line that opens a private key, and which line it is, when nothing
/// comes before it but what tools write there: blank lines, other PEM blocks
/// (a certificate, or the key's parameters), and the attributes that
/// `openssl pkcs12` prints. Prose or code before it means the file is about
/// keys, not a key.
fn key_header(text: &str) -> Option<(usize, &str)> {
    let (mut block, mut bag) = (false, false);
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim_start_matches('\u{feff}').trim();
        if block {
            block = !line.starts_with("-----END ");
        } else if line == PGP
            || (line.starts_with("-----BEGIN ") && line.ends_with("PRIVATE KEY-----"))
        {
            return Some((i, line));
        } else if line.starts_with("-----BEGIN ") {
            block = true;
        } else if line.starts_with("Bag Attributes") || line.starts_with("Key Attributes") {
            bag = true;
        } else if !(line.is_empty()
            || (bag && raw.starts_with(' '))
            || line.starts_with("subject=")
            || line.starts_with("issuer="))
        {
            return None;
        }
    }
    None
}

fn base64_decode(s: &str) -> Vec<u8> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for v in s.bytes().filter_map(val) {
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_states() {
        // openssh-key-v1 headers: cipher "none" vs "aes256-ctr" (first 64 base64 chars suffice).
        let none = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----\n";
        let aes = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBnQb\n-----END OPENSSH PRIVATE KEY-----\n";
        assert_eq!(key_protection(none.as_bytes()), KeyState::Unprotected);
        assert_eq!(key_protection(aes.as_bytes()), KeyState::Protected);
        assert_eq!(
            key_protection(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"),
            KeyState::Protected
        );
        assert_eq!(
            key_protection(b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"),
            KeyState::Protected
        );
        assert_eq!(
            key_protection(b"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n"),
            KeyState::Unprotected
        );
        assert_eq!(
            key_protection(b"ssh-ed25519 AAAA user@host"),
            KeyState::NotAKey
        );
        assert_eq!(
            key_protection(b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBF\n"),
            KeyState::Unknown
        );
        assert_eq!(
            key_protection(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"),
            KeyState::NotAKey
        );
    }

    #[test]
    fn a_key_after_what_openssl_writes_before_it_is_found() {
        let key = |kind: &str| format!("-----BEGIN {kind}PRIVATE KEY-----\nMHcC\n");
        // "openssl ecparam -genkey" writes the curve first.
        let ec = format!(
            "-----BEGIN EC PARAMETERS-----\nBggq\n-----END EC PARAMETERS-----\n{}",
            key("EC ")
        );
        assert_eq!(key_protection(ec.as_bytes()), KeyState::Unprotected);
        // "openssl pkcs12 -nodes" writes attributes first.
        let bag = format!(
            "Bag Attributes\n    friendlyName: fixture\nKey Attributes: <No Attributes>\n{}",
            key("")
        );
        assert_eq!(key_protection(bag.as_bytes()), KeyState::Unprotected);
        // A certificate and its key in one file, with and without a passphrase.
        let certificate = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        let bundle = format!("{certificate}{}", key("RSA "));
        assert_eq!(key_protection(bundle.as_bytes()), KeyState::Unprotected);
        let locked = format!("{certificate}{}", key("ENCRYPTED "));
        assert_eq!(key_protection(locked.as_bytes()), KeyState::Protected);
        assert_eq!(key_protection(certificate.as_bytes()), KeyState::NotAKey);
        // A key quoted in a document is not a key file.
        let prose = format!("How to make a key\n\n{}", key("RSA "));
        assert_eq!(key_protection(prose.as_bytes()), KeyState::NotAKey);
    }

    #[test]
    fn a_key_after_openssl_or_certificate_preamble_and_a_ppk_key() {
        // `openssl pkcs12 -nodes` prints bag attributes before each PEM block.
        let bag = concat!(
            "Bag Attributes\n    friendlyName: fixture\n    localKeyID: 01 02 03 04\nKey Attributes: <No Attributes>\n-----BEGIN ",
            "PRIVATE KEY-----\nsynthetic\n"
        );
        assert_eq!(key_protection(bag.as_bytes()), KeyState::Unprotected);
        let bag_encrypted = concat!(
            "Bag Attributes\n    friendlyName: fixture\nKey Attributes: <No Attributes>\n-----BEGIN ENCRYPTED ",
            "PRIVATE KEY-----\nsynthetic\n"
        );
        assert_eq!(
            key_protection(bag_encrypted.as_bytes()),
            KeyState::Protected
        );
        // A certificate, then its key, in one file.
        let bundle = concat!(
            "Bag Attributes\n    localKeyID: 01 02 03 04\nsubject=CN = fixture\nissuer=CN = fixture\n-----BEGIN CERTIFICATE-----\nc3ludGhldGlj\n-----END CERTIFICATE-----\n-----BEGIN RSA ",
            "PRIVATE KEY-----\nsynthetic\n"
        );
        assert_eq!(key_protection(bundle.as_bytes()), KeyState::Unprotected);
        let blank = concat!("\r\n\n-----BEGIN EC ", "PRIVATE KEY-----\nsynthetic\n");
        assert_eq!(key_protection(blank.as_bytes()), KeyState::Unprotected);
        // An OpenSSH key after a preamble still has its cipher read.
        let openssh = concat!(
            "\n-----BEGIN OPENSSH ",
            "PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBnQb\n"
        );
        assert_eq!(key_protection(openssh.as_bytes()), KeyState::Protected);
        // PuTTY's format has no PEM header.
        assert_eq!(
            key_protection(b"PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: fixture\nPublic-Lines: 2\n"),
            KeyState::Unprotected
        );
        assert_eq!(
            key_protection(
                b"PuTTY-User-Key-File-2: ssh-rsa\r\nEncryption: aes256-cbc\r\nComment: fixture\r\n"
            ),
            KeyState::Protected
        );
        // Prose or code before a header is not a key file.
        let prose = concat!(
            "Here is what a key looks like:\n-----BEGIN RSA ",
            "PRIVATE KEY-----\n"
        );
        assert_eq!(key_protection(prose.as_bytes()), KeyState::NotAKey);
        let code = concat!("const KEY = `\n-----BEGIN ", "PRIVATE KEY-----\n");
        assert_eq!(key_protection(code.as_bytes()), KeyState::NotAKey);
        assert_eq!(
            key_protection(b"PuTTY-User-Key-File-3 is the header of a .ppk file\n"),
            KeyState::NotAKey
        );
    }
}
