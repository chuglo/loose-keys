//! PEM and OpenSSH private keys, split by whether the header shows a passphrase.

use super::*;

pub const SSH_KEY: Rule = Rule {
    id: "key.ssh.private",
    category: "private-key",
    kind: "inventory",
    severity: "low",
    title: "Possible private key",
    explanation: "The start of this file looks like a private key. Loose Keys did not check whether the key works anywhere.",
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
    title: "Private key with no passphrase",
    reason: Some("The key has no passphrase, so anyone with a copy of this file can use it. Loose Keys did not check whether the key is still trusted anywhere."),
    next_step: Some("If this key has only ever been in ~/.ssh on this Mac, adding a passphrase protects it from now on. If it has ever been anywhere else (a synced folder, a repository, an email, a backup), or you are not sure, replace it. Create a new key with a passphrase, add it wherever the old one is trusted, then remove the old one from those places. Deleting the file or adding a passphrase does not stop a copy made earlier from working."),
    advice: Advice {
        steps: &[
            "If it is an SSH key you use, add a passphrase: ssh-keygen -p -f <key file>. Don't run this on a key another program reads, such as a web server's HTTPS key: it rewrites the file in SSH's own format.",
            "To avoid typing the passphrase each time, run ssh-add --apple-use-keychain <key file>, and put UseKeychain yes at the top of ~/.ssh/config so SSH still finds it after a restart.",
            "If a script or server signs in with this key unattended, a passphrase will stop it. Leave the key without one and limit what it can do where it's trusted, for example as a read-only deploy key.",
            "If you don't use it, remove it where it's trusted, then delete the file and its .pub. ssh-keygen -lf <key file> prints its fingerprint, which GitHub (Settings > SSH and GPG keys) and similar services show beside each key.",
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
    explanation: "This GnuPG private key has no passphrase. Loose Keys did not test it.",
    reason: Some("A copy of this file can sign and decrypt as you. Malware that spreads through packages goes after keys used to sign commits or releases."),
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
    explanation: "This GnuPG private key is protected by a passphrase. Loose Keys did not test it.",
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
    let mut rest = text.as_ref();
    let mut state = KeyState::NotAKey;
    while let Some((at, first)) = key_header(rest) {
        let start: usize = rest.split_inclusive('\n').take(at).map(str::len).sum();
        let block = &rest[start..];
        let mut end = 0;
        let mut closed = false;
        for line in block.split_inclusive('\n') {
            end += line.len();
            if line.trim().starts_with("-----END ") {
                closed = true;
                break;
            }
        }
        match key_block_protection(&block[..end], first) {
            KeyState::Unprotected => return KeyState::Unprotected,
            KeyState::Unknown => state = KeyState::Unknown,
            KeyState::Protected if state == KeyState::NotAKey => state = KeyState::Protected,
            _ => {}
        }
        if !closed {
            break;
        }
        rest = &block[end..];
    }
    state
}

fn key_block_protection(text: &str, first: &str) -> KeyState {
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
        .skip(1)
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
            out.push(((acc >> bits) & 0xff) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_encrypted_key_does_not_hide_an_unprotected_key_in_the_same_file() {
        let plain = concat!(
            "-----BEGIN RSA ",
            "PRIVATE KEY-----\nsynthetic\n-----END RSA ",
            "PRIVATE KEY-----\n"
        );
        let encrypted = concat!(
            "-----BEGIN RSA ",
            "PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nsynthetic\n-----END RSA ",
            "PRIVATE KEY-----\n"
        );
        for bundle in [format!("{plain}{encrypted}"), format!("{encrypted}{plain}")] {
            assert_eq!(key_protection(bundle.as_bytes()), KeyState::Unprotected);
        }
    }

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
