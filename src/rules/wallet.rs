//! Crypto wallets: browser-extension vaults, desktop wallet folders, and
//! recovery phrases written into files. Stealers copy all three; the vault's
//! password is then guessed offline, and a recovery phrase needs no guessing.

use super::*;

pub const WALLET_EXTENSION: Rule = Rule {
    id: "wallet.extension.vault",
    category: "wallet",
    kind: "review",
    severity: "medium",
    title: "Crypto wallet extension in a browser",
    explanation: "A crypto wallet extension keeps its encrypted vault in this browser profile. Loose Keys found the folder but did not open it.",
    reason: Some("Malware can copy wallet extension data and try to guess its password offline, or use a fake prompt to steal the password."),
    next_step: Some("Keep only small amounts in a browser wallet, and never keep its recovery phrase on this Mac."),
    advice: Advice {
        steps: &[
            "For funds you want to keep safe, create a new wallet on a hardware device and move the funds to it. Do not import the old recovery phrase into it: that phrase may already be copied.",
            "Give the extension a long password used nowhere else. If the vault is copied, that password is all that protects it.",
            "Check that the recovery phrase is not saved in a note, a text file or a screenshot on this Mac.",
            "If you no longer use this wallet, remove the extension after confirming you hold the recovery phrase offline.",
            "Never type a recovery phrase into a prompt you did not expect. If you are restoring a wallet yourself, follow the wallet maker's instructions on a device you trust.",
        ],
        link: None,
    },
    // IDs confirmed in published analyses of Atomic and Banshee stealer.
    targets: &[
        Target::Extension("nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask"),
        Target::Extension("ejbalbakoplchlghecdalmeeeajnimhm", "MetaMask"),
        Target::Extension("bfnaelmomeimhlpmgjnjophhpkkoljpa", "Phantom"),
        Target::Extension("hnfanknocfeofbddgcijnmhnfnkdnaad", "Coinbase Wallet"),
        Target::Extension("egjidjbpglichdcondbcbdnbeeppgdph", "Trust Wallet"),
        Target::Extension("ibnejdfjmmkpcnlpebklmnkoeoihofec", "TronLink"),
        Target::Extension("aholpfdialjgjfhomihkjbmgjidlcdno", "Exodus Web3"),
        Target::Extension("dmkamcknogkgcdfhhbddcghachkejeap", "Keplr"),
        Target::Extension("fnjhmkhhmkbjkkabndcnnogagogbneec", "Ronin"),
        Target::Extension("acmacodkjbdgmoleebolmdjonilkdbch", "Rabby"),
        Target::Extension("bhhhlbepdkbapadjdnnojkbgioiodbic", "Solflare"),
        Target::Extension("ffnbelfdoeiohenkjibnmadjiehjhajb", "Yoroi"),
        Target::Extension("fhbohimaelbohpjbbldcngcnapndodjp", "BNB Chain Wallet"),
        Target::Extension("hpglfhgfnhbgpjdenjgmdgoeiappafln", "Guarda"),
        Target::Extension("nphplpgoakhhjchkkhmiggakijnkhfnd", "TON Wallet"),
    ],
    matcher: Matcher::Present,
    samples: &[],
};

pub const RECOVERY_PHRASE: Rule = Rule {
    id: "wallet.recovery-phrase",
    category: "wallet",
    kind: "review",
    severity: "high",
    title: "Possible wallet recovery phrase in a file",
    explanation: "This file starts with 12 or more words from the list wallets use for recovery phrases. Loose Keys did not check whether they make a valid phrase or a wallet with funds.",
    reason: Some("A valid recovery phrase can restore a wallet and spend from it. Some wallets also need a separate passphrase, which Loose Keys does not look for."),
    next_step: Some("Treat the phrase as exposed if this Mac could have had malware. Otherwise move it off the Mac now."),
    advice: Advice {
        steps: &[
            "Write the phrase on paper, or stamp it in metal, and store it somewhere safe away from the computer.",
            "Delete this file and empty the Trash. Check Notes, Photos and cloud folders for other copies, including screenshots.",
            "If this Mac may have been infected, or the file was in a synced or shared folder, create a new wallet with a new phrase and move the funds to it. Deleting the file does not help once it has been copied.",
        ],
        link: None,
    },
    targets: &[Target::Discovery],
    matcher: Matcher::Head(has_recovery_phrase),
    samples: &[
        (concat!("wallet backup\n1. velvet 2. winner 3. thank 4. year 5. wave 6. sausage\n", "7. worth 8. useful 9. legal 10. winner 11. thank 12. yellow\n").as_bytes(), true),
        (concat!("velvet winner thank year wave sausage ", "worth useful legal winner thank yellow").as_bytes(), true),
        // Ordinary prose uses the same common words, but not twelve in a row.
        (b"The actor was able to act about the absurd abuse, and the access was an accident above all.", false),
        (b"legal winner thank year wave sausage worth useful legal winner thank", false),
        // Source code runs list words together with its own punctuation.
        (b"void test_open_file(void *data, short index);\nvoid test_close_file(void *data, short index);\n", false),
        // The word list itself, and a common public development phrase.
        (b"abandon ability able about above absent absorb abstract absurd abuse access accident", false),
        (b"test test test test test test test test test test test junk", false),
    ],
};

// BIP-39 English word list; source and license are in THIRD_PARTY_NOTICES.
const WORDS: &str = include_str!("bip39-english.txt");

/// Twelve consecutive words from the BIP-39 English list, written the way a
/// person writes a phrase down. On a developer's Mac the common words in the
/// list (test, file, open, void) sit twelve in a row in ordinary source files,
/// so the gaps between the words and the words themselves both have to fit.
fn has_recovery_phrase(head: &[u8]) -> bool {
    static LIST: std::sync::OnceLock<Vec<&str>> = std::sync::OnceLock::new();
    let list = LIST.get_or_init(|| WORDS.lines().collect());
    // The current run, as positions in the list, and what came before its next word.
    let mut run: Vec<usize> = Vec::new();
    let mut gap: &[u8] = &[];
    for chunk in head.chunk_by(|a, b| a.is_ascii_alphabetic() == b.is_ascii_alphabetic()) {
        if !chunk[0].is_ascii_alphabetic() {
            gap = chunk;
            continue;
        }
        // Words are 3 to 8 letters; anything else ends a run without a lookup.
        let mut lower = [0u8; 8];
        let known = (3..=8).contains(&chunk.len()).then(|| {
            lower[..chunk.len()].copy_from_slice(chunk);
            lower[..chunk.len()].make_ascii_lowercase();
            list.binary_search_by(|w| w.as_bytes().cmp(&lower[..chunk.len()]))
                .ok()
        });
        let Some(Some(position)) = known else {
            run.clear();
            continue;
        };
        if !plain_gap(gap) {
            run.clear();
        }
        run.push(position);
        if run.len() >= 12 {
            let candidate = &run[run.len() - 12..];
            if looks_random(candidate) && !public_example(candidate, list) {
                return true;
            }
        }
    }
    false
}

/// What a person puts between the words of a phrase: spaces, line breaks,
/// commas, list numbers ("3.", "3)", "3:") and a bullet at the start of a line.
fn plain_gap(gap: &[u8]) -> bool {
    gap.iter().enumerate().all(|(i, b)| match b {
        b' ' | b'\t' | b'\r' | b'\n' | b',' | b'0'..=b'9' => true,
        b'.' | b')' | b':' => i > 0 && gap[i - 1].is_ascii_digit(),
        b'-' | b'*' => i > 0 && gap[i - 1] == b'\n' && gap.get(i + 1) == Some(&b' '),
        _ => false,
    })
}

/// A wallet picks the words at random, so twelve of them almost never hold
/// fewer than nine different words and are almost never in list order.
fn looks_random(words: &[usize]) -> bool {
    let mut different = words.to_vec();
    different.sort_unstable();
    different.dedup();
    different.len() >= 9 && !words.is_sorted()
}

/// These two public 12-word BIP-39 vectors otherwise pass the randomness
/// heuristic. Compare normalized words, never exempt their containing file.
/// Source: https://github.com/trezor/python-mnemonic/blob/master/vectors.json
fn public_example(words: &[usize], list: &[&str]) -> bool {
    [
        concat!(
            "legal winner thank year wave sausage ",
            "worth useful legal winner thank yellow"
        ),
        concat!(
            "letter advice cage absurd amount doctor ",
            "acoustic avoid letter advice cage above"
        ),
    ]
    .iter()
    .any(|example| {
        words
            .iter()
            .map(|&i| list[i])
            .eq(example.split_ascii_whitespace())
    })
}

pub const DESKTOP_WALLET: Rule = Rule {
    id: "wallet.desktop.data",
    title: "Desktop crypto wallet data",
    explanation: "A desktop crypto wallet keeps its data here. Loose Keys found it but did not open it.",
    reason: Some("Password-stealing malware copies desktop wallet folders and guesses the password offline. Some versions also replace the wallet app with a fake that asks for the recovery phrase."),
    next_step: Some("Use a hardware wallet for funds you cannot afford to lose, and never type a recovery phrase into an app on this Mac."),
    advice: Advice {
        steps: &[
            "Move funds you cannot afford to lose to a hardware wallet.",
            "Give this wallet a long password used nowhere else, and make sure its recovery phrase is not stored on this Mac.",
            "Install and update the wallet app only from its official site or the App Store. If it asks for your recovery phrase out of the blue, stop and find out why.",
            "If you no longer use this wallet, move any funds out, then delete the app and this data.",
        ],
        link: None,
    },
    // Locations from stealer code quoted in published analyses, and vendor docs.
    targets: &[
        Target::Present("Library/Application Support/Exodus/exodus.wallet", "Exodus"),
        Target::Present(".electrum/wallets", "Electrum"),
        Target::Present("Library/Application Support/Coinomi/wallets", "Coinomi"),
        Target::Present("Library/Application Support/atomic/Local Storage/leveldb", "Atomic Wallet"),
        Target::Present("Library/Application Support/Guarda/Local Storage/leveldb", "Guarda"),
        Target::Present(".walletwasabi/client/Wallets", "Wasabi"),
        Target::Present("Library/Application Support/Binance/app-store.json", "Binance"),
        Target::Present("Library/Application Support/Bitcoin/wallet.dat", "Bitcoin Core"),
        Target::Present("Library/Application Support/Bitcoin/wallets", "Bitcoin Core"),
        Target::Present("Library/Application Support/Bitcoin/wallets", "Bitcoin Core"),
        Target::Present("Library/Application Support/Ledger Live", "Ledger Wallet"),
        Target::Present("Library/Application Support/@trezor/suite-desktop", "Trezor Suite"),
        Target::Present("Library/Application Support/@tonkeeper/desktop", "Tonkeeper"),
        Target::Present(".sparrow/wallets", "Sparrow"),
        Target::Present("Monero/wallets", "Monero"),
    ],
    ..WALLET_EXTENSION
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_word_list_is_the_standard_one() {
        let list: Vec<&str> = WORDS.lines().collect();
        assert_eq!(list.len(), 2048);
        assert_eq!((list[0], list[2047]), ("abandon", "zoo"));
        assert!(list.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn public_bip39_examples_are_not_wallet_backups() {
        let examples = [
            concat!(
                "legal winner thank year wave sausage ",
                "worth useful legal winner thank yellow"
            ),
            concat!(
                "letter advice cage absurd amount doctor ",
                "acoustic avoid letter advice cage above"
            ),
        ];
        for example in examples {
            assert!(!has_recovery_phrase(example.as_bytes()));
            assert!(!has_recovery_phrase(example.to_uppercase().as_bytes()));
            let numbered = example
                .split_whitespace()
                .enumerate()
                .map(|(i, word)| format!("{}. {word}\n", i + 1))
                .collect::<String>();
            assert!(!has_recovery_phrase(numbered.as_bytes()));
            let (_, rest) = example.split_once(' ').unwrap();
            assert!(has_recovery_phrase(format!("velvet {rest}").as_bytes()));
        }
        // Synthetic source-history content, containing both public vectors.
        let history = format!(
            "{{\n  \"example-one\": \"{}\",\n  \"example-two\": \"{}\"\n}}",
            examples[0], examples[1]
        );
        assert!(!has_recovery_phrase(history.as_bytes()));
        // An example must not silence a different candidate in the same file.
        let candidate = examples[0].replacen("legal", "velvet", 1);
        assert!(has_recovery_phrase(
            format!("{history}\n{candidate}").as_bytes()
        ));
        assert!(has_recovery_phrase(
            format!("{candidate}\n{history}").as_bytes()
        ));
    }

    #[test]
    fn phrases_are_found_however_they_are_laid_out() {
        let words = concat!(
            "velvet winner thank year wave sausage ",
            "worth useful legal winner thank yellow"
        );
        assert!(has_recovery_phrase(words.replace(' ', "\n").as_bytes()));
        assert!(has_recovery_phrase(words.to_uppercase().as_bytes()));
        assert!(has_recovery_phrase(
            format!("my seed:\n{}", words.replace(' ', ", ")).as_bytes()
        ));
        // Eleven words, or twelve with another word between them, are not enough.
        let eleven = words.rsplit_once(' ').unwrap().0;
        assert!(!has_recovery_phrase(eleven.as_bytes()));
        assert!(!has_recovery_phrase(
            words.replacen("wave", "wave the", 1).as_bytes()
        ));
        // A bulleted list is a phrase; the same words as code are not.
        assert!(has_recovery_phrase(
            format!("- {}", words.replace(' ', "\n- ")).as_bytes()
        ));
        for code in ["_", "(", " = ", ": ", "-", "\", \""] {
            assert!(!has_recovery_phrase(words.replace(' ', code).as_bytes()));
        }
    }

    #[test]
    fn a_phrase_is_found_after_words_that_do_not_belong_to_it() {
        // "seed" and "phrase" are list words too, and a label ends with a colon.
        let words = concat!(
            "velvet winner thank year wave sausage ",
            "worth useful legal winner thank yellow"
        );
        assert!(has_recovery_phrase(
            format!("seed phrase: {words}").as_bytes()
        ));
        // A phrase that follows the sorted word list in the same file.
        let list: String = WORDS.lines().take(40).collect::<Vec<_>>().join("\n");
        assert!(!has_recovery_phrase(list.as_bytes()));
        assert!(has_recovery_phrase(format!("{list}\n{words}").as_bytes()));
    }
}
