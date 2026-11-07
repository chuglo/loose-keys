"""Reading the repository's Markdown, shared by check_refs.py and
check_prose.py."""

import os
import re
import subprocess
import sys
from bisect import bisect_right

FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
CODE_SPAN = re.compile(r"(`+)((?:(?!\1)[^\n]|\n(?!\s*\n))+?)\1")
TEXT_LIMIT = 2 * 1024 * 1024


class GitError(Exception):
    pass


def git(root, *args):
    out = subprocess.run(["git", "-C", root, *args], capture_output=True)
    if out.returncode != 0:
        raise GitError(f"git {args[0]} failed: "
                       f"{out.stderr.decode(errors='replace').strip()}")
    return out.stdout.decode()


def listed_files(root):
    """Tracked files, and new ones git does not ignore, that exist."""
    listed = git(root, "ls-files", "-z", "--cached", "--others",
                 "--exclude-standard").split("\0")
    return sorted(p for p in set(listed)
                  if p and os.path.lexists(os.path.join(root, p)))


def read(root, rel):
    path = os.path.join(root, rel)
    if not os.path.isfile(path) or os.path.getsize(path) > TEXT_LIMIT:
        return ""
    with open(path, "rb") as f:
        return f.read().decode("utf-8", errors="replace")


def blank_fences(text):
    """Split a page into its prose, with fenced blocks blanked, and the
    fenced lines as (line number, text)."""
    prose, fenced, fence = [], [], None
    for number, line in enumerate(text.split("\n"), 1):
        match = FENCE.match(line)
        if fence is None and match:
            fence = match.group(1)
            prose.append("")
        elif fence is not None:
            if match and match.group(1)[0] == fence[0] \
                    and len(match.group(1)) >= len(fence) \
                    and not line.strip()[len(match.group(1)):].strip():
                fence = None
            else:
                fenced.append((number, line))
            prose.append("")
        else:
            prose.append(line)
    return "\n".join(prose), fenced


def blank(pattern, text):
    """The text with every match of pattern blanked, keeping line breaks."""
    return pattern.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


class Lines:
    """Line numbers for offsets into a text."""

    def __init__(self, text):
        self.breaks = [i for i, c in enumerate(text) if c == "\n"]

    def at(self, offset):
        return bisect_right(self.breaks, offset - 1) + 1


def run(check):
    """Call check(root, files, names) for the Markdown files named on the
    command line, or all of them, print what it finds and return the exit
    status: 0 for nothing, 1 for findings, 2 when it cannot run."""
    tool = os.path.basename(sys.argv[0])
    try:
        root = git(os.getcwd(), "rev-parse", "--show-toplevel").strip()
        files = listed_files(root)
        if sys.argv[1:]:
            names = [os.path.relpath(os.path.abspath(a), root) for a in sys.argv[1:]]
            missing = [n for n in names if not os.path.isfile(os.path.join(root, n))]
            if missing:
                print(f"{tool}: no such file: {', '.join(missing)}", file=sys.stderr)
                return 2
        else:
            names = [f for f in files if f.endswith(".md")]
        found = sorted(check(root, files, names))
    except GitError as err:
        print(f"{tool}: {err}", file=sys.stderr)
        return 2
    for rel, line, kind, detail in found:
        print(f"{rel}:{line}: {kind}: {detail}")
    return 1 if found else 0
