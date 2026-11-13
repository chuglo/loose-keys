"""What every synthetic developer home is built from: files, a manifest of
what was planted, token-shaped values made at run time, and filler trees."""

import base64
import json
import os
import random
import sqlite3
import string
import subprocess
from pathlib import Path

BIP39 = Path(__file__).resolve().parents[4] / "src/rules/bip39-english.txt"

WORTH = "Worth Reviewing"
STORED = "Stored Sign-ins"
HIDDEN = "not shown"
DEBATABLE = "debatable"

ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
UPPER32 = string.ascii_uppercase + "234567"

WORDS = (
    "account adapter batch buffer cache client config cursor decode driver "
    "encode engine event fetch filter format handler header index layout "
    "listener loader logger mapper metric middleware module parser payload "
    "queue reader registry render request resolver response router runner "
    "schema server service session signal socket stream table task timer "
    "tracker transform utils validator worker writer"
).split()


class Home:
    """A home folder under `out/home`, and the manifest of what is in it."""

    def __init__(self, out, seed):
        self.root = Path(out) / "home"
        self.rng = random.Random(seed)
        self.items = []
        self.files = 0

    def put(self, rel, data, mode=0o644):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, str):
            data = data.encode()
        with open(path, "wb") as handle:
            handle.write(data)
        os.chmod(path, mode)
        self.files += 1
        return path

    def plant(self, rel, data, what, expect, why, group=None, mode=0o644):
        """A file the app's result is judged on."""
        self.put(rel, data, mode)
        self.expect(rel, what, expect, why, group)

    def expect(self, rel, what, expect, why, group=None):
        """Another thing to judge in a file already written. `group` names
        one credential kept in several files, which should be one item."""
        item = {"path": rel, "what": what, "expect": expect, "why": why}
        if group:
            item["group"] = group
        self.items.append(item)

    def json(self, rel, value, mode=0o644):
        return self.put(rel, json.dumps(value, indent=2) + "\n", mode)

    # Values. Each is made here, from pieces, so no complete token-shaped
    # string is in this repository.

    def chars(self, n, alphabet=ALNUM):
        return "".join(self.rng.choice(alphabet) for _ in range(n))

    def password(self, n=18):
        return self.chars(4, string.ascii_uppercase) + self.chars(n - 6) + self.chars(2, string.digits)

    def token(self, kind):
        c = self.chars
        made = {
            "github": lambda: "gh" + "p_" + c(36),
            "github-app": lambda: "gh" + "s_" + c(36),
            "gitlab": lambda: "gl" + "pat-" + c(20),
            "aws-id": lambda: "AK" + "IA" + c(16, UPPER32),
            "anthropic": lambda: "sk-" + "ant-" + "api03-" + c(93) + "AA",
            "openai": lambda: "sk-" + "proj-" + c(60) + "T3Blbk" + "FJ" + c(60),
            "stripe": lambda: "sk_" + "live_" + c(40),
            "stripe-test": lambda: "sk_" + "test_" + c(40),
            "slack": lambda: "xo" + "xb-" + c(12, string.digits) + "-" + c(13, string.digits) + "-" + c(24),
            "slack-hook": lambda: "https://hooks.slack" + ".com/services/T" + c(8, string.ascii_uppercase)
            + "/B" + c(10, string.ascii_uppercase) + "/" + c(24),
            "npm": lambda: "np" + "m_" + c(36),
            "huggingface": lambda: "h" + "f_" + c(34),
            "sendgrid": lambda: "S" + "G." + c(22) + "." + c(43),
            "databricks": lambda: "da" + "pi" + c(32, HEX),
            "linear": lambda: "lin_" + "api_" + c(40),
            "pinecone": lambda: "pc" + "sk_" + c(5) + "_" + c(63),
            "langsmith": lambda: "lsv2_" + "pt_" + c(32, HEX) + "_" + c(10, HEX),
            "age": lambda: "AGE-" + "SECRET-KEY-1" + c(58, string.ascii_uppercase + string.digits),
            "digitalocean": lambda: "do" + "p_v1_" + c(64, HEX),
            "bedrock": lambda: "AB" + "SK" + c(120),
            # No prefix that names the issuer: found only under a secret name.
            "google": lambda: "AI" + "za" + c(35),
            "hex32": lambda: c(32, HEX),
            "hex40": lambda: c(40, HEX),
            "jwt": lambda: ".".join(
                base64.urlsafe_b64encode(self.rng.randbytes(n)).decode().rstrip("=") for n in (27, 120, 32)
            ),
        }
        return made[kind]()

    def pem(self, label="RSA", lines=26, encrypted=False):
        """Text with a private key's armor. The body is random, not a key:
        the scanner reads the header alone."""
        kind = ("ENCRYPTED " if encrypted else "") + (label + " " if label else "") + "PRIVATE " + "KEY"
        body = "\n".join(base64.b64encode(self.rng.randbytes(48)).decode() for _ in range(lines))
        return "-----BEGIN " + kind + "-----\n" + body + "\n-----END " + kind + "-----\n"

    def certificate(self):
        body = "\n".join(base64.b64encode(self.rng.randbytes(48)).decode() for _ in range(18))
        return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n"

    def ssh_key(self, rel, passphrase=""):
        """A real OpenSSH key pair: the scanner reads the cipher inside it."""
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", passphrase, "-C", "dev@example.invalid", "-f", str(path)],
            check=True,
        )
        self.files += 2

    def phrase(self, words=12):
        """Words from the recovery-phrase list. Not a wallet's phrase: the
        checksum a real one carries is not made."""
        return " ".join(self.rng.sample(BIP39.read_text().split(), words))

    def sqlite(self, rel, script, mode=0o600):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as db:
            db.executescript(script)
        db.close()
        os.chmod(path, mode)
        self.files += 1

    def browser(self, profile="Default", logins=5, cards=1):
        """A Chrome profile's saved passwords, cards and cookies, as opaque
        bytes in the tables Chrome keeps them in."""
        base = f"Library/Application Support/Google/Chrome/{profile}"
        value = lambda: "x'763130" + self.chars(26, HEX) + "'"
        rows = ",".join(
            f"('https://site{n}.example.invalid','user{n}',{value()},'https://site{n}.example.invalid',{n})"
            for n in range(logins))
        self.sqlite(f"{base}/Login Data",
                    "CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);"
                    "CREATE TABLE logins(origin_url VARCHAR NOT NULL,username_value VARCHAR,password_value BLOB,"
                    "signon_realm VARCHAR NOT NULL,date_created INTEGER NOT NULL,id INTEGER PRIMARY KEY AUTOINCREMENT);"
                    f"INSERT INTO logins(origin_url,username_value,password_value,signon_realm,date_created) VALUES {rows};")
        cards = ",".join(f"('c{n}','Sample Person',{value()})" for n in range(cards))
        self.sqlite(f"{base}/Web Data",
                    "CREATE TABLE credit_cards(guid VARCHAR PRIMARY KEY,name_on_card VARCHAR,card_number_encrypted BLOB);"
                    + (f"INSERT INTO credit_cards VALUES {cards};" if cards else ""))
        self.sqlite(f"{base}/Cookies",
                    "CREATE TABLE cookies(host_key TEXT,name TEXT,encrypted_value BLOB,expires_utc INTEGER);"
                    f"INSERT INTO cookies VALUES('.example.invalid','session',{value()},99999999999999999);")
        return base

    def documents(self, rel, files):
        """Ordinary office files: invoices, photos, letters."""
        for n in range(files):
            kind = self.rng.choice((".pdf", ".docx", ".xlsx", ".jpg", ".png", ".pages"))
            self.put(f"{rel}/{self.rng.choice(WORDS)}-{self.rng.choice(WORDS)}-{n}{kind}", self.rng.randbytes(1500))

    # Filler: the bulk of a home, which holds nothing to find.

    def source(self, lines=30):
        rng = self.rng
        out = []
        for _ in range(lines):
            a, b, c = (rng.choice(WORDS) for _ in range(3))
            out.append(f"export function {a}{b.title()}({c}) {{ return {c}.{a}({rng.randint(1, 999)}); }}")
        return "\n".join(out) + "\n"

    def tree(self, rel, files, suffixes=(".js",), depth=3, lines=12):
        """About `files` small files below `rel`, in folders `depth` deep."""
        rng = self.rng
        for n in range(files):
            parts = [rng.choice(WORDS) for _ in range(rng.randint(1, depth))]
            name = f"{rng.choice(WORDS)}-{n}{rng.choice(suffixes)}"
            self.put("/".join([rel, *parts, name]), self.source(lines))

    def blobs(self, rel, files, size=600):
        """Files named by a hash, as content-addressed stores keep them."""
        for _ in range(files):
            name = self.chars(62, HEX)
            self.put(f"{rel}/{name[:2]}/{name[2:]}", self.source(size // 80))

    def node_modules(self, rel, packages):
        """An installed dependency tree. Some packages ship test keys and
        sample settings, as real ones do."""
        for n in range(packages):
            pkg = f"{rel}/node_modules/{self.rng.choice(WORDS)}-{self.rng.choice(WORDS)}-{n}"
            self.json(f"{pkg}/package.json", {"name": pkg.rsplit("/", 1)[1], "version": "1.0.0"})
            self.put(f"{pkg}/README.md", "# package\n\nUsage: see index.js\n")
            for part in ("index.js", "lib/main.js", "lib/util.js", "dist/index.cjs", "dist/index.mjs"):
                self.put(f"{pkg}/{part}", self.source(8))
            if n % 40 == 0:
                self.put(f"{pkg}/test/fixtures/server.key", self.pem())
                self.put(f"{pkg}/.env.example", "API_KEY=" + self.chars(24) + "\n")

    def repo(self, rel, remote):
        """The parts of a Git repository a scan can meet."""
        self.put(f"{rel}/.git/HEAD", "ref: refs/heads/main\n")
        self.put(
            f"{rel}/.git/config",
            "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
            f'[remote "origin"]\n\turl = {remote}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n',
        )
        for _ in range(12):
            name = self.chars(40, HEX)
            self.put(f"{rel}/.git/objects/{name[:2]}/{name[2:]}", self.rng.randbytes(180))
        self.put(f"{rel}/.gitignore", ".env\n.env.*\n!.env.example\nnode_modules/\ndist/\n")
        self.put(f"{rel}/README.md", f"# {rel.rsplit('/', 1)[-1]}\n\nSee docs/ for setup.\n")
