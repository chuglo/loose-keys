"""A careful developer, whose Worth Reviewing should be almost empty: keys
with passphrases or on a security key, credential helpers, references to a
secret manager, encrypted files, and example files with placeholders."""

import base64
import struct

from .lib import DEBATABLE, HIDDEN, STORED, WORTH

REPOS = ["billing", "gateway", "infra-live", "docs", "mobile", "tools", "website", "wordle-clone"]


def security_key_handle(h):
    """An OpenSSH key file for a FIDO security key, as `ssh-keygen -t
    ed25519-sk` writes one with no passphrase: the file holds a handle, and
    the private key stays on the hardware."""
    def text(value):
        return struct.pack(">I", len(value)) + value
    kind = b"sk-ssh-ed25519@openssh.com"
    public = text(kind) + text(h.rng.randbytes(32)) + text(b"ssh:")
    private = h.rng.randbytes(8) + public + text(h.rng.randbytes(96)) + text(b"dev@example.invalid")
    blob = b"openssh-key-v1\0" + text(b"none") + text(b"none") + text(b"") + struct.pack(">I", 1) + text(public) + text(private)
    body = base64.b64encode(blob).decode()
    lines = "\n".join(body[i:i + 70] for i in range(0, len(body), 70))
    return "-----BEGIN OPENSSH PRIVATE " + "KEY-----\n" + lines + "\n-----END OPENSSH PRIVATE " + "KEY-----\n"


def build(h):
    keys_and_helpers(h)
    repositories(h)
    encrypted(h)
    samples_and_tests(h)
    shell(h)
    bulk(h)


def keys_and_helpers(h):
    h.ssh_key(".ssh/id_ed25519", "synthetic passphrase")
    h.expect(".ssh/id_ed25519", "SSH key with a passphrase", STORED, "protected by its passphrase")
    h.plant(".ssh/id_ed25519_sk", security_key_handle(h), "SSH key kept on a hardware security key", HIDDEN,
            "the file is a handle; the key cannot leave the hardware", mode=0o600)
    h.put(".ssh/id_ed25519_sk.pub", f"sk-ssh-ed25519@openssh.com AAAA{h.chars(80)} dev@example.invalid\n")
    h.put(".ssh/config", 'Host *\n  IdentityAgent "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"\n  UseKeychain yes\n')
    h.put(".ssh/work_1password.pub", f"ssh-ed25519 AAAA{h.chars(64)} work\n")
    h.expect(".ssh/work_1password.pub", "public half of a key kept in 1Password", HIDDEN, "public by design")
    h.plant(".gitconfig",
            "[user]\n\tname = Dev\n\temail = dev@example.invalid\n\tsigningkey = ~/.ssh/work_1password.pub\n"
            "[credential]\n\thelper = osxkeychain\n[gpg]\n\tformat = ssh\n",
            "Git config that uses the Keychain helper", HIDDEN, "stores no credential")
    h.plant(".aws/config",
            "[profile dev]\nsso_session = corp\nsso_account_id = 123456789012\nsso_role_name = Developer\n\n"
            "[sso-session corp]\nsso_start_url = https://corp.example.invalid/start\nsso_region = us-east-1\n\n"
            "[profile prod]\ncredential_process = aws-vault exec prod --json\n",
            "AWS config with SSO and aws-vault", HIDDEN, "stores no credential")
    cached = ".aws/sso/cache/" + h.chars(40, "0123456789abcdef") + ".json"
    h.json(cached, {"startUrl": "https://corp.example.invalid/start", "region": "us-east-1",
                    "accessToken": h.chars(400), "expiresAt": "2026-11-12T08:00:00Z"}, mode=0o600)
    h.expect(cached, "AWS single sign-on session", STORED, "short-lived, kept by the CLI")
    h.json(".docker/config.json", {"auths": {"ghcr.io": {}, "https://index.docker.io/v1/": {}}, "credsStore": "osxkeychain"})
    h.expect(".docker/config.json", "Docker config that uses the Keychain", HIDDEN, "stores no credential")
    h.plant(".npmrc", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\nfund=false\n",
            "~/.npmrc that reads the token from the environment", HIDDEN, "a reference, not a value")
    h.plant(".config/gh/hosts.yml", "github.com:\n    git_protocol: ssh\n    users:\n        dev:\n    user: dev\n",
            "GitHub CLI config with its token in the Keychain", HIDDEN, "stores no credential")
    h.plant(".kube/config",
            "apiVersion: v1\nkind: Config\nusers:\n- name: eks\n  user:\n    exec:\n"
            "      apiVersion: client.authentication.k8s.io/v1beta1\n      command: aws\n      args: [eks, get-token, --cluster-name, prod]\n",
            "kubeconfig that runs 'aws eks get-token'", HIDDEN, "stores no credential", mode=0o600)
    h.plant(".pypirc", "[distutils]\nindex-servers = pypi\n\n[pypi]\nusername = __token__\n",
            ".pypirc with no password (keyring)", HIDDEN, "stores no credential")
    h.plant(".cargo/config.toml", '[registry]\nglobal-credential-providers = ["cargo:macos-keychain"]\n',
            "Cargo config that uses the Keychain", HIDDEN, "stores no credential")
    h.json(".config/gcloud/application_default_credentials.json",
           {"type": "authorized_user", "client_id": "764086051850.apps.googleusercontent.com",
            "client_secret": h.chars(24), "refresh_token": "1//" + h.chars(60)}, mode=0o600)
    h.expect(".config/gcloud/application_default_credentials.json", "gcloud's stored sign-in", STORED,
             "the sign-in gcloud keeps for itself")
    h.plant(".gnupg/private-keys-v1.d/" + h.chars(40, "0123456789ABCDEF") + ".key",
            "Created: 20260101T000000\nKey: (protected-private-key (ecc (curve Ed25519)(q #" + h.chars(64, "0123456789ABCDEF")
            + "#)(protected openpgp-s2k3-ocb-aes ((sha1 #00# \"1\")#00#)#" + h.chars(96, "0123456789ABCDEF") + "#)))\n",
            "GnuPG key with a passphrase", STORED, "protected by its passphrase", mode=0o600)
    h.plant(".config/sops/age/keys.txt",
            "# created: 2026-03-01T10:00:00Z\n# public key: age1" + h.chars(58, "abcdefghijklmnopqrstuvwxyz0123456789")
            + "\n" + h.token("age") + "\n",
            "age private key that decrypts the team's sops files", WORTH, "an unprotected key, the one real exposure here",
            mode=0o600)
    for name in ("personal/github.gpg", "work/vpn.gpg", "work/db-prod.gpg"):
        h.plant(f".password-store/{name}", h.rng.randbytes(420), "entry of the pass password store", HIDDEN, "encrypted")
    h.plant("Sync/Passwords.kdbx", b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5\x01\x00\x04\x00" + h.rng.randbytes(4000),
            "KeePass database", STORED, "an encrypted password database")


def repositories(h):
    for name in REPOS:
        h.repo(f"work/{name}", f"git@github.com:corp/{name}.git")
        h.tree(f"work/{name}/src", 180, (".rs", ".go", ".ts"), 4)
        h.tree(f"work/{name}/target/release/deps", 300, (".d", ".rlib"), 2, 3)
    h.plant("work/billing/.env",
            'DATABASE_URL="op://Engineering/billing-db/url"\nSTRIPE_SECRET_KEY="op://Engineering/stripe/secret-key"\n'
            "API_TOKEN=${API_TOKEN}\nAWS_PROFILE=dev\nLOG_LEVEL=info\n",
            ".env that holds 1Password references", HIDDEN, "references, not values")
    h.plant("work/billing/.env.example",
            "DATABASE_URL=postgres://user:password@localhost:5432/billing\nSTRIPE_SECRET_KEY=sk_test_your_key_here\n"
            "API_TOKEN=your-api-token\nJWT_SECRET=changeme\nADMIN_PASSWORD=<set me>\n",
            ".env.example with placeholders", HIDDEN, "placeholders only")
    h.plant("work/gateway/.env.example",
            "DB_PASSWORD=password\nPOSTGRES_PASSWORD=postgres\nJWT_SECRET=dev-secret-not-for-production\n"
            "MINIO_ROOT_PASSWORD=minioadmin\nSECRET_KEY=django-insecure-" + h.chars(50) + "\nREDIS_PASSWORD=\n",
            ".env.example with well-known defaults", HIDDEN, "sample values in a committed example file")
    h.plant("work/gateway/.env.development",
            "DATABASE_URL=postgres://postgres:postgres@localhost:5432/gateway_dev\nREDIS_URL=redis://localhost:6379\n"
            "SESSION_SECRET=development-only-secret\n",
            "defaults for local development", HIDDEN, "values for services on localhost")
    h.plant("work/gateway/.env.test", "API_KEY=test-key-not-real-0000\nDB_PASSWORD=testpass123\n",
            "values for the test suite", HIDDEN, "named as test values")
    h.plant("work/infra-live/.envrc",
            'export AWS_PROFILE=prod\nexport VAULT_ADDR=https://vault.example.invalid\n'
            'export DATABASE_PASSWORD="$(op read op://Engineering/db/password)"\ndotenv_if_exists\n',
            ".envrc that reads from 1Password", HIDDEN, "a reference, not a value")
    h.plant("work/infra-live/prod.tfvars", 'region = "us-east-1"\ninstance_count = 3\ndb_password_secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:db"\n',
            ".tfvars that names a secret's ARN", HIDDEN, "a reference, not a value")
    h.plant("work/mobile/.env", "EXPO_PUBLIC_API_URL=https://api.example.invalid\nSENTRY_AUTH_TOKEN=${SENTRY_AUTH_TOKEN}\n",
            ".env with a reference", HIDDEN, "a reference, not a value")


def encrypted(h):
    enc = lambda: f"ENC[AES256_GCM,data:{h.chars(28)},iv:{h.chars(16)},tag:{h.chars(22)},type:str]"
    h.plant("work/infra-live/secrets/prod.enc.yaml",
            f"db_password: {enc()}\napi_token: {enc()}\nsops:\n  age:\n  - recipient: age1"
            + h.chars(58, "abcdefghijklmnopqrstuvwxyz0123456789") + "\n",
            "sops-encrypted YAML", HIDDEN, "encrypted")
    h.plant("work/infra-live/secrets/prod.enc.env",
            f"DB_PASSWORD={enc()}\nAPI_TOKEN={enc()}\nsops_version=3.9.0\n",
            "sops-encrypted .env file", HIDDEN, "encrypted")
    h.plant("work/infra-live/ansible/vault.yml",
            "$ANSIBLE_VAULT;1.1;AES256\n" + "\n".join(h.chars(80, "0123456789abcdef") for _ in range(10)) + "\n",
            "Ansible Vault file", HIDDEN, "encrypted")
    h.plant("work/gateway/certs/server.key", h.pem("", encrypted=True), "TLS key encrypted with a passphrase", STORED,
            "protected by its passphrase")
    h.plant("work/gateway/certs/server.crt", h.certificate(), "TLS certificate", HIDDEN, "public by design")
    h.plant("work/gateway/certs/jwt-public.pem",
            "-----BEGIN PUBLIC KEY-----\n" + h.chars(64) + "\n-----END PUBLIC KEY-----\n",
            "public key", HIDDEN, "public by design")


def samples_and_tests(h):
    h.plant("work/gateway/tests/fixtures/test_key.pem", h.pem("RSA"),
            "private key among a repository's test fixtures", DEBATABLE, "looks real, sits in tests/")
    h.plant("work/billing/testdata/fake_service_account.json",
            '{\n  "type": "service_account",\n  "project_id": "test",\n  "private_key": "'
            + h.pem("", 6).replace("\n", "\\n") + '",\n  "client_email": "test@test.iam.gserviceaccount.com"\n}\n',
            "service account file among test data", DEBATABLE, "looks real, sits in testdata/")
    h.plant("work/docs/security.md",
            "# Handling keys\n\nNever commit a file that starts like this:\n\n    -----BEGIN OPENSSH PRIVATE " + "KEY-----\n\n"
            "Use `op read` instead of exporting tokens.\n",
            "documentation that quotes a key's first line", HIDDEN, "prose about keys")
    h.plant("work/docs/payments.md",
            "# Payments\n\nUse Stripe's published test key while developing:\n\n    export STRIPE_KEY=" + h.token("stripe-test") + "\n",
            "Stripe test-mode key in documentation", HIDDEN, "a test-only key in a guide")
    h.plant("work/tools/third_party/httpd/conf/server.key", h.pem("RSA"),
            "sample key inside a vendored third-party package", HIDDEN, "published with the package")
    for rel in ("go/pkg/mod/github.com/golang-jwt/jwt/v5@v5.2.1/test/sample_key",
                "go/pkg/mod/google.golang.org/grpc@v1.64.0/testdata/x509/server1_key.pem"):
        h.plant(rel, h.pem("RSA"), "test key shipped inside a downloaded package", HIDDEN,
                "published with the package; the developer never made or used it", mode=0o444)
    words = ("apple river stone cloud table chair light music paper water green house bread smile "
             "plant horse train window garden letter market silver winter summer").split()
    h.rng.shuffle(words)
    h.plant("work/wordle-clone/words.txt", "\n".join(words) + "\n", "word list of a word game", HIDDEN, "ordinary words")


def shell(h):
    h.plant(".zshrc",
            'export GITHUB_TOKEN="$(op read op://Private/GitHub/token)"\nexport AWS_VAULT_BACKEND=keychain\n'
            'eval "$(op completion zsh)"\nHISTCONTROL=ignorespace\n',
            "startup file that reads a token from 1Password", HIDDEN, "a reference, not a value")
    h.plant(".zsh_history",
            ": 1790000000:0;op run --env-file=.env -- cargo run\n"
            ": 1790000100:0;aws-vault exec prod -- terraform plan\n"
            ": 1790000200:0;export API_TOKEN=$(pass show work/api)\n"
            ": 1790000300:0;PGPASSWORD=$(op read op://Engineering/db/password) psql -h db.example.invalid\n"
            ': 1790000400:0;curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.example.invalid/user\n'
            ": 1790000500:0;sops -d secrets/prod.enc.yaml | less\n: 1790000600:0;ssh-add --apple-use-keychain ~/.ssh/id_ed25519\n",
            "shell history with references only", HIDDEN, "no value was typed", mode=0o600)


def bulk(h):
    h.tree("go/pkg/mod/github.com", 2500, (".go", ".mod"), 5)
    h.tree(".cargo/registry/src/index.crates.io-6f17d22bba15001f", 3000, (".rs",), 4)
    h.tree(".rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/src", 2500, (".rs",), 5)
    h.tree("Library/Caches/Homebrew/downloads", 300, (".tar.gz",), 1, 30)
    h.tree("Library/Application Support/Code/User/workspaceStorage", 500, (".json",), 2, 5)
    h.tree(".vscode/extensions/rust-lang.rust-analyzer-0.3.2000/out", 600, (".js",), 3)
    h.tree("work/website/dist", 400, (".html", ".js"), 3, 20)
    h.node_modules("work/website", 400)
