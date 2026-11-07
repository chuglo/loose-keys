#!/usr/bin/env python3
"""Offline regressions for check_refs.py.

Usage: python3 -I .agents/skills/documentation/check_refs_test.py

Builds a small repository under TMPDIR with one planted problem of each kind
and one correct reference of each kind, then checks that exactly the planted
problems are reported.
"""

import os
import shutil
import subprocess
import sys
import tempfile

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check_refs.py")

FILES = {
    "src/main.rs": 'const USAGE: &str = "  --limits  also print limits";\n'
                   "fn real_fn() {}\nstruct ReadTurns;\n"
                   'const SKIPPED: &str = ".cache/tool";\nconst GAP: &str = "scan-limit";\n',
    "tools/run.sh": '#!/bin/sh\ncase "$1" in --work) ;; esac\n',
    "tools/parse.rs": 'if arg == "--binary" {}\n',
    "gui/AGENTS.md": "Engine code is in `src/engine.rs`; `src/missing.rs` is not.\n",
    "gui/src/engine.rs": "fn engine() {}\n",
    "docs/a.md": "# Page A\n\n## Real Heading\n\n## Real Heading\n\n```sh\n# Not A Heading\n```\n",
    ".gitignore": "/target\n/out/\n",
}

# Each planted problem is on its own line of README.md: (line, kind).
README = """\
# Readme

[good](docs/a.md#real-heading) and [second](docs/a.md#real-heading-1)
[missing file](docs/missing.md)
[missing heading](docs/a.md#not-a-heading)
[same page](#readme) and [web](https://example.com/x.md)
Code lives in `src/main.rs`, `docs/*.md` and `out/report.json`; skips `.cache/tool`.
Gone: `src/gone.rs` and `src/old.rs`.
No match: `docs/*.txt`.
`real_fn`, `ReadTurns`, `scan-limit`, `std::thread` and `is_char_boundary` hold.
`old_fn` and `old-name` were removed.
Not checked: `$TMPDIR/vm/x` and `target/release/x` and `~/docs/x`.
A span `real_fn
` across lines holds.

```sh
loose-keys scan --limits
loose-keys scan --nope
sh tools/run.sh --work x
tools/run.sh --binary y
sh tools/run.sh --bad
cargo test --locked  # not ours
cat src/nothere.rs
```

```text
[inside a fence](nowhere.md)
```
Alone: `scan --limits` holds and `scan --gone` does not.
[Deleted](docs/old.md) but not committed.
"""

EXPECTED = [
    ("README.md", 4, "link"),
    ("README.md", 5, "anchor"),
    ("README.md", 8, "path"),
    ("README.md", 8, "path"),
    ("README.md", 9, "path"),
    ("README.md", 11, "name"),
    ("README.md", 11, "name"),
    ("README.md", 18, "flag"),
    ("README.md", 21, "flag"),
    ("README.md", 23, "path"),
    ("README.md", 29, "flag"),
    ("README.md", 30, "link"),
    ("gui/AGENTS.md", 1, "path"),
]


def run(cwd, *args):
    return subprocess.run(["git", "-C", cwd, *args], check=True, capture_output=True)


def write(root, files):
    for rel, text in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)


def commit(root, message):
    run(root, "add", "-A")
    run(root, "-c", "user.name=test", "-c", "user.email=test@invalid",
        "-c", "commit.gpgsign=false", "commit", "-q", "-m", message)


def make_repo(root):
    run(root, "init", "-q")
    write(root, {"src/old.rs": 'fn old_fn() {}\nconst N: &str = "old-name";\n'})
    commit(root, "Add old names")
    os.remove(os.path.join(root, "src/old.rs"))
    write(root, FILES)
    write(root, {"README.md": README, "docs/old.md": "# Old\n"})
    commit(root, "Remove old names")
    os.remove(os.path.join(root, "docs/old.md"))


def check(root):
    out = subprocess.run([sys.executable, "-I", SCRIPT], cwd=root,
                         capture_output=True, text=True)
    found = []
    for line in out.stdout.splitlines():
        rel, number, kind, _ = line.split(":", 3)
        found.append((rel, int(number), kind.strip()))
    return out, found


def main():
    base = os.environ.get("TMPDIR") or sys.exit("set TMPDIR to a scratch folder")
    root = tempfile.mkdtemp(prefix=f"check-refs-test-{os.getpid()}-", dir=base)
    failures = []
    try:
        make_repo(root)
        out, found = check(root)
        if out.returncode != 1:
            failures.append(f"planted problems: exit {out.returncode}, want 1\n{out.stderr}")
        if sorted(found) != sorted(EXPECTED):
            failures.append("planted problems: got\n  " + "\n  ".join(out.stdout.splitlines())
                            + "\nmissing " + str(sorted(set(EXPECTED) - set(found)))
                            + "\nunexpected " + str(sorted(set(found) - set(EXPECTED))))
        if "old_fn: gone from the code since " not in out.stdout \
                or "Remove old names" not in out.stdout:
            failures.append("a removed name should name the commit that removed it")
        if "src/old.rs: no such file or folder (last in " not in out.stdout:
            failures.append("a deleted path should name the commit that last had it")
        if "docs/old.md: no such file (deleted, not committed)" not in out.stdout:
            failures.append("a deletion not yet committed should say so")

        write(root, {"README.md": "# Readme\n\nSee [A](docs/a.md#page-a) and `src/main.rs`.\n",
                     "gui/AGENTS.md": "See `src/engine.rs`.\n"})
        out, _ = check(root)
        if out.returncode != 0 or out.stdout:
            failures.append(f"clean pages: exit {out.returncode}, want 0\n{out.stdout}")

        out = subprocess.run([sys.executable, "-I", SCRIPT, "no-such.md"], cwd=root,
                             capture_output=True, text=True)
        if out.returncode != 2:
            failures.append(f"missing argument file: exit {out.returncode}, want 2")
    finally:
        shutil.rmtree(root)
    for failure in failures:
        print(f"FAIL: {failure}")
    print("ok" if not failures else f"{len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
