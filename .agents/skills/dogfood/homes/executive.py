"""A crypto or venture executive who takes meetings from strangers, the
target of the fake-meeting-app campaigns of 2025 and 2026: Telegram, wallet
apps, password-manager exports, and credentials kept in notes."""

from .lib import HIDDEN, STORED, WORTH

EXTENSIONS = (("aeblfdkhhhdcdjpifhhbdiojplfjncoa", "1Password"), ("hnfanknocfeofbddgcijnmhnfnkdnaad", "Coinbase Wallet"),
              ("nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask"))


def build(h):
    chrome = h.browser("Default", logins=8, cards=2)
    h.expect(f"{chrome}/Login Data", "passwords saved in Chrome", STORED, "the browser's own store")
    h.expect(f"{chrome}/Web Data", "payment cards saved in Chrome", STORED, "the browser's own store")
    for extension, name in EXTENSIONS:
        folder = f"{chrome}/Local Extension Settings/{extension}"
        h.put(f"{folder}/000003.log", h.rng.randbytes(600), 0o600)
        expect = HIDDEN if name == "1Password" else STORED
        why = "a password manager's own encrypted storage" if name == "1Password" else "the wallet's own encrypted storage"
        h.expect(folder, f"{name} extension's storage", expect, why)
    h.put("Library/Application Support/Telegram Desktop/tdata/key_datas", h.rng.randbytes(300), 0o600)
    h.expect("Library/Application Support/Telegram Desktop/tdata/key_datas", "Telegram Desktop session", STORED,
             "the session Telegram keeps for itself")
    h.json("Library/Application Support/Ledger Live/app.json", {"data": {"settings": {"currency": "USD"}}})
    h.expect("Library/Application Support/Ledger Live", "Ledger's desktop app", STORED, "the keys are on the hardware")
    h.put("Library/Application Support/Exodus/exodus.wallet/seed.seco", h.rng.randbytes(512), 0o600)
    h.expect("Library/Application Support/Exodus/exodus.wallet", "Exodus desktop wallet", STORED, "the wallet's own storage")

    h.plant("Documents/Exchange API.txt", f"Exchange (trading desk)\nAPI Key: {h.chars(64)}\nSecret: {h.chars(64)}\n",
            "exchange API key and secret in a note", WORTH, "can trade or withdraw")
    h.plant("Documents/Google backup codes.txt",
            "Google backup codes\n" + "".join(f"{h.chars(4, '0123456789')} {h.chars(4, '0123456789')}\n" for _ in range(10)),
            "two-step backup codes in a note", WORTH, "each code stands in for the second factor")
    h.plant("Downloads/1PasswordExport-AB12CD34EF.1pux", b"PK\x03\x04" + h.rng.randbytes(3000),
            "1Password export left in Downloads", WORTH, "every password in plain text inside")
    numbered = "".join(f"{n}. {word}\n" for n, word in enumerate(h.phrase(24).split(), 1))
    h.plant("Documents/Ledger recovery.txt", "Ledger Nano (office safe copy)\n" + numbered,
            "24-word recovery phrase, numbered, in a note", WORTH, "whoever reads it owns the wallet")
    h.plant("Library/Logs/sam_auth.log", f"auth ok user=sam password={h.password(14)}\n",
            "the Mac's login password, left in a log by a fake meeting app", WORTH, "the account password in plain text")
    h.plant(".pwd", h.password(14) + "\n", "the Mac's login password, left in a file by a stealer", WORTH,
            "the account password in plain text")
    h.json(".openai/config.json", {"api_key": h.token("openai"), "organization": "org-sample"})
    h.expect(".openai/config.json", "OpenAI API key in a config file", WORTH, "a real key in plain text")
    h.plant("Library/Application Support/AnyDesk/service.conf", f"ad.anynet.pwd_hash={h.chars(64, '0123456789abcdef')}\nad.anynet.id=123456789\n",
            "AnyDesk settings with a password hash", HIDDEN, "a hash, not the password")
    h.sqlite("Library/Application Support/Slack/Cookies",
             "CREATE TABLE cookies(host_key TEXT,name TEXT,encrypted_value BLOB);"
             "INSERT INTO cookies VALUES('.slack.example.invalid','d',x'763130" + h.chars(26, "0123456789abcdef") + "');")
    h.expect("Library/Application Support/Slack/Cookies", "Slack's session cookie", HIDDEN,
             "the usage guide says cookies are not covered")
    h.plant("Downloads/Zoom SDK Update.scpt", "-- update\ndo shell script \"echo updating\"\n",
            "the script a fake meeting invite asks the person to run", HIDDEN, "no credential in it")
    h.plant("Documents/Board/investor-update.txt", "Q3 update\nRunway: 22 months\nNew password policy rolls out in January.\n",
            "note that mentions a password policy", HIDDEN, "no secret")
    h.documents("Documents/Board", 250)
    h.documents("Documents/Deals", 900)
    h.documents("Downloads", 500)
    h.documents("Desktop", 40)
    h.tree("Library/Application Support/Slack/Cache", 1500, (".bin",), 2, 3)
    h.tree("Library/Application Support/zoom.us/data", 600, (".db", ".log"), 2, 3)
    h.tree("Library/Caches/com.tinyspeck.slackmacgap", 1200, (".file",), 2, 3)
