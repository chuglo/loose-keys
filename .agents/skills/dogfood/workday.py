#!/usr/bin/env python3
"""One step of a developer's ordinary work, done in a guest's home, to see
which changes Loose Keys alerts about while it scans automatically.

    python3 workday.py <step>      (in the guest; `python3 workday.py list` names the steps)

Each step says whether an alert for it would be worth the interruption.
Values are made here, from pieces: no complete token-shaped string is in
this file.
"""

import base64
import os
import random
import string
import sys
from pathlib import Path

HOME = Path.home()
ALNUM = string.ascii_letters + string.digits
rng = random.Random()


def chars(n, alphabet=ALNUM):
    return "".join(rng.choice(alphabet) for _ in range(n))


def put(rel, text, mode=0o644):
    path = HOME / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    os.chmod(path, mode)


def key():
    armor = "RSA PRIVATE " + "KEY"
    body = "\n".join(base64.b64encode(rng.randbytes(48)).decode() for _ in range(20))
    return f"-----BEGIN {armor}-----\n{body}\n-----END {armor}-----\n"


def github():
    return "gh" + "p_" + chars(36)


def source(n):
    for i in range(n):
        yield f"file-{i}.js", f"export const value{i} = {rng.randint(1, 9999)};\n"


def clone():
    """Clone a repository with no secret in it. An alert would be noise."""
    put("src/new-service/.git/HEAD", "ref: refs/heads/main\n")
    put("src/new-service/.git/config", '[remote "origin"]\n\turl = git@github.com:corp/new-service.git\n')
    for name, text in source(200):
        put(f"src/new-service/src/{name}", text)


def install():
    """Install dependencies: thousands of files in node_modules, some with
    test keys. An alert would be noise."""
    for n in range(300):
        for name, text in source(10):
            put(f"src/new-service/node_modules/pkg-{n}/{name}", text)
        if n % 50 == 0:
            put(f"src/new-service/node_modules/pkg-{n}/test/server.key", key())


def go_get():
    """Download a new version of a Go module that ships test keys. An alert
    would be noise."""
    base = "go/pkg/mod/google.golang.org/grpc@v1.65.0"
    for name, text in source(150):
        put(f"{base}/internal/{name}", text)
    put(f"{base}/testdata/x509/server1_key.pem", key(), 0o444)
    put(f"{base}/testdata/x509/client1_key.pem", key(), 0o444)


def pnpm_install():
    """pnpm adds packages to its store, each file under a hash, test keys
    included. An alert would be noise."""
    for n in range(300):
        name = chars(62, "0123456789abcdef")
        put(f"Library/pnpm/store/v3/files/{name[:2]}/{name[2:]}", key() if n % 100 == 0 else f"module.exports = {n};\n")


def python_install():
    """Install a new Python version, whose own test suite ships keys. An
    alert would be noise."""
    base = ".pyenv/versions/3.13.0/lib/python3.13/test/certdata"
    for name in ("keycert.pem", "ssl_key.pem", "keycert2.pem"):
        put(f"{base}/{name}", key(), 0o444)


def env_token():
    """Paste a real token into a new .env file. An alert is worth it."""
    put("src/new-service/.env", f"GITHUB_TOKEN={github()}\nPORT=8080\n")


def env_example():
    """Add the project's committed .env.example. An alert would be noise."""
    put("src/new-service/.env.example",
        "GITHUB_TOKEN=\nDATABASE_URL=postgres://user:password@localhost:5432/app\nJWT_SECRET=changeme\n")


def agent_log():
    """An AI agent's session record keeps a token a command printed. An
    alert is worth it."""
    line = '{"type":"user","message":{"content":[{"type":"tool_result","content":"TOKEN=' + github() + '"}]}}\n'
    put(".claude/projects/-Users-admin-src-new-service/" + chars(12, "0123456789abcdef") + ".jsonl",
        '{"type":"assistant","message":{"content":"ok"}}\n' * 50 + line)


def shell_snapshot():
    """An agent starts a session and saves the shell's environment, which
    repeats a token ~/.zshrc exports. The token is already listed, so an
    alert would be noise."""
    exports = [line for line in (HOME / ".zshrc").read_text().splitlines() if line.startswith("export ")]
    put(f".claude/shell-snapshots/snapshot-zsh-{rng.randint(10**9, 10**10)}-{chars(6)}.sh",
        "# Snapshot file\n" + "\n".join(exports) + "\n")


def rotate_key():
    """Replace an SSH key with a new one, again without a passphrase. An
    alert is debatable: the exposure is the same kind as before."""
    put(".ssh/id_rsa_prod_bastion", key(), 0o600)


def aws_session():
    """The AWS CLI caches new temporary credentials, as it does at each
    sign-in. An alert would be noise."""
    upper32 = string.ascii_uppercase + "234567"
    put(".aws/cli/cache/" + chars(40, "0123456789abcdef") + ".json",
        '{"Credentials": {"AccessKeyId": "' + "AS" + "IA" + chars(16, upper32) + '", "SecretAccessKey": "'
        + chars(40) + '", "SessionToken": "' + chars(400) + '", "Expiration": "2026-11-13T08:00:00Z"}}\n', 0o600)


def local_cluster():
    """minikube makes new keys for its local cluster. An alert would be noise."""
    put(".minikube/profiles/minikube/client.key", key(), 0o600)


def yaml_password():
    """Write a production password into a YAML config, and a token far down
    a script. The usage guide says neither is found; an alert would be
    worth it."""
    put("src/new-service/config/production.yml", "database:\n  username: app\n  password: " + chars(20) + "\n")
    put("src/new-service/scripts/release.py", "".join(text for _, text in source(200)) + f'TOKEN = "{github()}"\n')


STEPS = [clone, install, go_get, pnpm_install, python_install, env_token, env_example, agent_log, shell_snapshot,
         rotate_key, aws_session,
         local_cluster, yaml_password]

if __name__ == "__main__":
    names = {step.__name__: step for step in STEPS}
    if len(sys.argv) != 2 or sys.argv[1] not in names:
        for step in STEPS:
            print(f"{step.__name__}: {' '.join(step.__doc__.split())}")
        sys.exit(0 if sys.argv[1:] == ["list"] else 2)
    names[sys.argv[1]]()
    print(f"did {sys.argv[1]}")
