#!/usr/bin/env python3
"""Offline regressions for check_prose.py.

Usage: python3 -I .agents/skills/documentation/check_prose_test.py

Builds a small repository under TMPDIR with one planted finding of each kind
next to text that must not be reported, then checks that exactly the planted
findings are reported.
"""

import os
import shutil
import subprocess
import sys
import tempfile

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check_prose.py")

FENCE = "```"
PAGES = {
    "docs/a.md": f"""\
# Page A

The scanner is robust.
A quoted "seamless" word and `robust` code are fine.
Ask the owner first; the owner-only file is fine.
Done ✅
Checked on 2026-10-27: a candidate passed.
Approved on 2026-10-13.
Both came from an older worktree.
Every finding names the file, the rule and the first step to take today.

{FENCE}sh
seamless robust
{FENCE}
See [the guide](robust.md).
""",
    "docs/b.md": "# Page B\n\nAs the overview says, every finding names the file, "
                 "the rule and the first step to take today.\n",
    "docs/design-notes.md": "# Notes\n\nPlain text.\n",
    "docs/clean.md": "# Clean\n\nPlain words here.\n",
    "docs/usage.md": f"""\
# Usage

Short one. This sentence keeps going and going because it wants to list a
great many separate things, which a person could do, one after another, until
the reader has long since forgotten how it began, e.g. right here at the end.
Loose Keys skips the Trash, but `a, b, c, d.` stays, and it also skips caches,
and it reports gaps; you decide, then you act.
It works with Chrome, Brave, Edge, Arc, Safari, Firefox, Opera.
- A link-only item follows.
- [The detection guide](detection.md)

| Cell | Long row |
|---|---|
| a | this table row goes on and on and on and on and on and on and on and on and on and on and on and on and on and on and on and on and on and on and on and on, yes, yes, yes, yes |
""",
    "docs/testing/x.md": "# X\n\nHere is a different sentence which rambles on while it names "
                         "an enormous number of unrelated tasks that somebody might attempt, "
                         "first this, then that, until nobody can recall its opening words, "
                         "so, yes, again, and again.\n",
}

EXPECTED = [
    ("docs/a.md", 3, "filler"),
    ("docs/a.md", 5, "owner"),
    ("docs/a.md", 6, "emoji"),
    ("docs/a.md", 7, "record"),
    ("docs/a.md", 9, "history"),
    ("docs/b.md", 3, "repeat"),
    ("docs/design-notes.md", 1, "plan"),
    ("docs/usage.md", 3, "long-sentence"),
    ("docs/usage.md", 3, "stacked-clauses"),
    ("docs/usage.md", 6, "stacked-clauses"),
]


def make_repo(root):
    for rel, text in PAGES.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
    subprocess.run(["git", "-C", root, "init", "-q"], check=True)


def check(root, *pages):
    out = subprocess.run([sys.executable, "-I", SCRIPT, *pages], cwd=root,
                         capture_output=True, text=True)
    found = []
    for line in out.stdout.splitlines():
        rel, number, kind, _ = line.split(":", 3)
        found.append((rel, int(number), kind.strip()))
    return out, found


def main():
    base = os.environ.get("TMPDIR") or sys.exit("set TMPDIR to a scratch folder")
    root = tempfile.mkdtemp(prefix=f"check-prose-test-{os.getpid()}-", dir=base)
    failures = []
    try:
        make_repo(root)
        out, found = check(root)
        if out.returncode != 1:
            failures.append(f"planted findings: exit {out.returncode}, want 1\n{out.stderr}")
        if sorted(found) != sorted(EXPECTED):
            failures.append("planted findings: got\n  " + "\n  ".join(out.stdout.splitlines())
                            + "\nmissing " + str(sorted(set(EXPECTED) - set(found)))
                            + "\nunexpected " + str(sorted(set(found) - set(EXPECTED))))
        if "14 words also at docs/a.md:10" not in out.stdout:
            failures.append("a repeat should give its length and the other copy")

        out, found = check(root, "docs/a.md")
        if ("docs/a.md", 10, "repeat") not in found:
            failures.append("a repeat whose other copy is out of scope should be "
                            f"reported on the page in scope\n{out.stdout}")

        out, _ = check(root, "docs/clean.md")
        if out.returncode != 0 or out.stdout:
            failures.append(f"clean page: exit {out.returncode}, want 0\n{out.stdout}")

        out, _ = check(root, "no-such.md")
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
