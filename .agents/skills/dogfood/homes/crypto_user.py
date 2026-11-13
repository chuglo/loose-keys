"""A home Mac user who holds crypto, the usual victim of the macOS
infostealers of 2025 and 2026 (AMOS, MacSync, SHub, AmnesiaStealer): browser
stores, wallet apps and extensions, and passwords and recovery phrases kept
in Desktop, Documents and Downloads. No developer tooling."""

from .lib import HIDDEN, STORED, WORTH

METAMASK = "nkbihfbeogaeaoehlefnkodbefgpgknn"
PHANTOM = "bfnaelmomeimhlpmgjnjophhpkkoljpa"


def build(h):
    browsers(h)
    wallets(h)
    notes_and_exports(h)
    lookalikes(h)
    bulk(h)


def browsers(h):
    chrome = h.browser("Default", logins=5, cards=1)
    h.expect(f"{chrome}/Login Data", "passwords saved in Chrome", STORED, "the browser's own store; every stealer takes it")
    h.expect(f"{chrome}/Web Data", "payment card saved in Chrome", STORED, "the browser's own store")
    h.expect(f"{chrome}/Cookies", "Chrome's cookies", HIDDEN, "the usage guide says cookies are not covered")
    second = h.browser("Profile 1", logins=2, cards=0)
    h.expect(f"{second}/Login Data", "passwords saved in a second Chrome profile", STORED, "the browser's own store")
    for profile, extension, name in (("Default", METAMASK, "MetaMask"), ("Profile 1", PHANTOM, "Phantom")):
        folder = f"Library/Application Support/Google/Chrome/{profile}/Local Extension Settings/{extension}"
        h.put(f"{folder}/000003.log", h.rng.randbytes(600), 0o600)
        h.put(f"{folder}/MANIFEST-000001", h.rng.randbytes(60), 0o600)
        h.expect(folder, f"{name} wallet extension's vault", STORED, "the wallet's own encrypted storage")
    firefox = "Library/Application Support/Firefox/Profiles/x1y2.default-release"
    h.json(f"{firefox}/logins.json", {"nextId": 3, "logins": [
        {"id": n, "hostname": f"https://site{n}.example.invalid", "encryptedUsername": h.chars(40),
         "encryptedPassword": h.chars(40)} for n in (1, 2)]}, mode=0o600)
    h.put(f"{firefox}/key4.db", h.rng.randbytes(2000), 0o600)
    h.expect(f"{firefox}/logins.json", "passwords saved in Firefox", STORED, "the browser's own store")


def wallets(h):
    h.put("Library/Application Support/Exodus/exodus.wallet/seed.seco", h.rng.randbytes(512), 0o600)
    h.expect("Library/Application Support/Exodus/exodus.wallet", "Exodus desktop wallet", STORED, "the wallet's own storage")
    h.json(".electrum/wallets/default_wallet", {
        "use_encryption": False, "wallet_type": "standard",
        "keystore": {"type": "bip32", "seed": h.phrase(12), "xpub": "xpub" + h.chars(107)}}, mode=0o600)
    h.expect(".electrum/wallets/default_wallet", "Electrum wallet with no password: its recovery phrase is in plain text",
             WORTH, "the phrase can be read straight from the file")
    h.json(".electrum/wallets/watch_only", {"wallet_type": "standard", "keystore": {"type": "bip32", "xpub": "xpub" + h.chars(107)}})
    h.expect(".electrum/wallets/watch_only", "Electrum watch-only wallet", HIDDEN, "holds a public key only")
    h.json("Library/Application Support/Ledger Live/app.json", {"data": {"settings": {"currency": "USD"}}})
    h.expect("Library/Application Support/Ledger Live", "Ledger's desktop app", STORED,
             "the keys are on the hardware; stealers replace this app to phish the phrase")
    h.put("Library/Application Support/Telegram Desktop/tdata/key_datas", h.rng.randbytes(300), 0o600)
    h.put("Library/Application Support/Telegram Desktop/tdata/D877F783D5D3EF8Cs", h.rng.randbytes(300), 0o600)
    h.expect("Library/Application Support/Telegram Desktop/tdata/key_datas", "Telegram Desktop session", STORED,
             "the session Telegram keeps for itself")


def notes_and_exports(h):
    h.plant("Documents/seed phrase.txt", h.phrase(12) + "\n", "12-word recovery phrase in a text file", WORTH,
            "whoever reads it owns the wallet")
    numbered = "".join(f"{n}. {word}\\\n" for n, word in enumerate(h.phrase(24).split(), 1))
    h.plant("Desktop/wallet backup.rtf", "{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Helvetica;}}\\f0\\fs24\nLedger\\\n" + numbered + "}\n",
            "24-word recovery phrase, numbered, in an RTF note", WORTH, "whoever reads it owns the wallet")
    h.json("Downloads/bitwarden_export_20260301.json", {"encrypted": False, "folders": [], "items": [
        {"id": f"i{n}", "name": f"Site {n}", "type": 1, "login": {"username": "sam", "password": h.password()}} for n in range(6)]})
    h.expect("Downloads/bitwarden_export_20260301.json", "unencrypted Bitwarden export left in Downloads", WORTH,
             "every password in plain text")
    h.plant("Downloads/Chrome Passwords.csv",
            "name,url,username,password,note\n" + "".join(
                f"site{n},https://site{n}.example.invalid,sam,{h.password()},\n" for n in range(8)),
            "Chrome password export left in Downloads", WORTH, "every password in plain text")
    h.plant("Documents/passwords.txt",
            f"bank: {h.password(12)}\nemail password: {h.password(12)}\nexchange login sam / {h.password(12)}\n"
            f"router password: {h.password(10)}\n",
            "passwords kept in a text note", WORTH, "real passwords in plain text")
    h.plant("Documents/Passwords.kdbx", b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5\x01\x00\x04\x00" + h.rng.randbytes(4000),
            "KeePass database", STORED, "an encrypted password database")
    h.plant("Pictures/seed.png", b"\x89PNG\r\n\x1a\n" + h.rng.randbytes(9000),
            "screenshot of a recovery phrase", WORTH, "stealers take images; the usage guide says images are not covered")
    h.plant("Documents/Exchange API.txt", f"Exchange\nAPI Key: {h.chars(64)}\nSecret: {h.chars(64)}\n",
            "exchange API key and secret in a text note", WORTH, "can trade or withdraw")
    h.plant("Documents/Google backup codes.txt",
            "Google backup codes\n" + "".join(f"{h.chars(4, '0123456789')} {h.chars(4, '0123456789')}\n" for _ in range(10)),
            "two-step backup codes in a text note", WORTH, "each code stands in for the second factor")


def lookalikes(h):
    h.plant("Documents/bip39-english.txt", "\n".join(sorted(h.phrase(400).split())) + "\n",
            "sorted list of recovery-phrase words", HIDDEN, "a word list, not a phrase")
    h.plant("Documents/crypto-tax-2025.csv",
            "Date,Asset,TxHash,Address\n" + "".join(
                f"2025-0{n % 9 + 1}-11,ETH,0x{h.chars(64, '0123456789abcdef')},0x{h.chars(40, '0123456789abcdef')}\n"
                for n in range(60)),
            "transaction history with public addresses and hashes", HIDDEN, "public values")
    h.plant("Documents/house.txt", "Plumber comes Tuesday.\nThe Wi-Fi password is on the fridge.\n",
            "note that mentions a password but holds none", HIDDEN, "no secret")
    h.plant("Documents/tutorial-notes.txt",
            "From the wallet tutorial, the sample phrase everyone uses:\n"
            + " ".join(["abandon"] * 11) + " about\n",
            "the published sample recovery phrase", HIDDEN, "a public test value")
    h.plant("Documents/recipes.txt",
            "Soup: carrot, onion, garlic, potato, butter, salt, pepper, cream, bread, olive, lemon, basil, tomato\n",
            "a recipe whose words are on the phrase list", HIDDEN, "ordinary text")
    h.json("Documents/contacts-export.json", {"contacts": [{"name": f"Person {n}", "phone": "555-01" + str(10 + n)} for n in range(30)]})


def bulk(h):
    h.documents("Documents/Taxes", 300)
    h.documents("Documents/Work", 900)
    h.documents("Pictures/2025", 1500)
    h.documents("Downloads", 600)
    h.documents("Desktop", 60)
    h.tree("Library/Application Support/Google/Chrome/Default/Extensions", 1500, (".js", ".json"), 4)
    h.tree("Library/Application Support/Steam/steamapps", 1200, (".acf", ".vdf"), 3, 4)
    h.tree("Library/Caches/com.spotify.client", 1500, (".file",), 2, 3)
    h.tree("Library/Application Support/discord/Cache", 800, (".bin",), 2, 3)
