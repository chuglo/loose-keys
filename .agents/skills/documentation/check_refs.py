#!/usr/bin/env python3
"""Find references in the repository's Markdown that no longer hold.

Usage, from the repository or worktree root:
    python3 -I .agents/skills/documentation/check_refs.py [FILE.md ...]

With no files it reads every tracked or new Markdown file. It prints one
"path:line: kind: detail" line per problem and exits 0 when there are none,
1 when there are some and 2 when it cannot run. Kinds:

  link    a relative link whose file is missing
  anchor  a #fragment with no matching heading in its page
  path    a repository path in code that matches no file and that no file
          outside Markdown names; on a nested AGENTS.md, a path starting
          with ../ or with a folder beside the page is read from the page's
          folder, any other from the root
  flag    an option given to loose-keys or a repository script that its
          source never mentions, or an option alone in inline code that
          files outside Markdown once had and no longer do
  name    a code name or hyphenated name in inline code that files outside
          Markdown once had and no longer do

A name or lone option the code never had, such as a standard library item, a
lint, an Apple constant or another tool's option, is not reported: read those
yourself. One whose removal is not yet committed says so.
"""

import fnmatch
import os
import re
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mdpages  # noqa: E402

HEADING = re.compile(r"^ {0,3}(#{1,6})[ \t]+(.*?)[ \t]*#*[ \t]*$")
LINK = re.compile(r"!?\[(?:[^\]\\\n]|\\.)*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
REF_DEF = re.compile(r"^ {0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s|$)", re.M)
HTML_ID = re.compile(r"<a\s[^>]*(?:id|name)=\"([^\"]+)\"")
PATHLIKE = re.compile(r"(?<![\w.$~/@-])([\w.-]+(?:/[\w.*-]*)+)")
IDENT = re.compile(r"(?:[A-Za-z_]\w*::)*([A-Za-z_]\w*)(?:\(\))?")
CAMEL = re.compile(r"[A-Za-z][a-z0-9]+[A-Z]")
KEBAB = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)+")
SCRIPT_EXT = (".sh", ".py", ".js")
FLAG = re.compile(r"(?<![\w-])(--[a-z][a-z0-9-]*)")
LONE_FLAG = re.compile(r"(--[a-z][a-z0-9-]*)(?:[ =]\S+)?")


class Repo:
    def __init__(self, root, files):
        self.root, self.files = root, files
        self.known = set(files)
        for f in files:
            parts = f.split("/")
            for i in range(1, len(parts)):
                self.known.add("/".join(parts[:i]))
        self.top_dirs = {f.split("/")[0] for f in files if "/" in f}
        self.deleted = set(mdpages.git(root, "ls-files", "-z", "--deleted").split("\0"))
        self._words = None
        self._source = None
        self._anchors = {}

    def exists(self, rel):
        rel = os.path.normpath(rel).replace(os.sep, "/")
        if rel in self.known:
            return True
        # A tracked symbolic link to a folder hides the files under it.
        real = os.path.realpath(os.path.join(self.root, rel))
        inside = os.path.relpath(real, os.path.realpath(self.root))
        return not inside.startswith("..") and inside in self.known

    def glob(self, pattern):
        return any(fnmatch.fnmatchcase(f, pattern) for f in self.known)

    def read(self, rel):
        return mdpages.read(self.root, rel)

    def source(self):
        """The text of every file that is not Markdown, joined."""
        if self._source is None:
            self._source = "\n".join(self.read(f) for f in self.files
                                     if not f.endswith(".md"))
            self._words = set(re.findall(r"\w+", self._source))
        return self._source

    def has_word(self, word):
        self.source()
        return word in self._words

    def anchors(self, rel):
        if rel not in self._anchors:
            self._anchors[rel] = page_anchors(self.read(rel))
        return self._anchors[rel]

    def ignored(self, rel):
        return subprocess.run(["git", "-C", self.root, "check-ignore", "-q",
                               "--no-index", rel]).returncode == 0

    def last_change(self, *args):
        """The newest commit matching a `git log` filter, as "hash subject",
        or "" when none does."""
        return mdpages.git(self.root, "log", "-1", "--format=%h %s", *args).strip()

    def gone(self, rel):
        """Where a missing file went, for a finding's detail."""
        rel = os.path.normpath(rel)
        if rel in self.deleted:
            return " (deleted, not committed)"
        last = self.last_change("--", rel)
        return f" (last in {last})" if last else ""

    def removed(self, name, word):
        """Where a name the code no longer has went, for a finding's detail,
        or "" when the code never had it."""
        # Attached, so a name starting with -- is not read as an option.
        last = self.last_change(f"-S{name}", "--", ".", ":(exclude)*.md")
        if not last:
            return ""
        # While HEAD still has it, the newest match is the commit that added it.
        grep = ["git", "-C", self.root, "grep", "-q", "-F", *(["-w"] if word else []),
                "-e", name, "HEAD", "--", ".", ":(exclude)*.md"]
        if subprocess.run(grep).returncode == 0:
            return " (removed, not committed)"
        return f" since {last}"


def slug(heading):
    text = re.sub(r"`([^`]*)`", r"\1", heading)
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[^\w\- ]", "", text.strip().lower())
    return text.replace(" ", "-")


def page_anchors(text):
    prose, _ = mdpages.blank_fences(text)
    seen, found = {}, set(HTML_ID.findall(prose))
    for line in prose.split("\n"):
        match = HEADING.match(line)
        if not match:
            continue
        base = slug(match.group(2))
        count = seen.get(base, 0)
        seen[base] = count + 1
        found.add(base if count == 0 else f"{base}-{count}")
    return found


class Page:
    def __init__(self, repo, rel):
        self.repo, self.rel = repo, rel
        self.dir = os.path.dirname(rel)
        # Only an AGENTS.md writes paths from its own folder.
        self.local = self.dir if os.path.basename(rel) == "AGENTS.md" else ""
        self.prose, self.fenced = mdpages.blank_fences(repo.read(rel))
        self.lines = mdpages.Lines(self.prose)
        self.spans = [(self.lines.at(m.start(2)), m.group(2))
                      for m in mdpages.CODE_SPAN.finditer(self.prose)]
        self.problems = []

    def report(self, line, kind, detail):
        self.problems.append((self.rel, line, kind, detail))

    def code(self):
        """Every piece of code on the page, spans and fenced lines."""
        return self.spans + self.fenced

    def check_links(self):
        no_code = mdpages.blank(mdpages.CODE_SPAN, self.prose)
        targets = [(m.start(1), m.group(1)) for m in LINK.finditer(no_code)]
        targets += [(m.start(1), m.group(1)) for m in REF_DEF.finditer(no_code)]
        for offset, target in targets:
            if re.match(r"[a-z][a-z0-9+.-]*:", target, re.I):
                continue
            self.check_link(self.lines.at(offset), target)

    def check_link(self, line, target):
        target = target.split("?")[0]
        path, _, fragment = target.partition("#")
        path = path.replace("%20", " ")
        if not path:
            rel = self.rel
        elif path.startswith("/"):
            rel = os.path.normpath(path.lstrip("/"))
        else:
            rel = os.path.normpath(os.path.join(self.dir, path))
        if rel.startswith(".."):
            self.report(line, "link", f"{target} leaves the repository")
        elif not self.repo.exists(rel):
            self.report(line, "link", f"{target}: no such file{self.repo.gone(rel)}")
        elif fragment and rel.endswith(".md") \
                and fragment.lower() not in self.repo.anchors(rel):
            self.report(line, "anchor", f"{target}: no such heading in {rel}")

    def check_paths(self):
        for line, text in self.code():
            for match in PATHLIKE.finditer(text):
                token = match.group(1).rstrip(".,:;")
                rel = self.resolve(token.rstrip("/"))
                if rel is not None and not self.path_holds(token, rel):
                    self.report(line, "path", f"{token}: no such file or folder"
                                + self.repo.gone(rel))

    def resolve(self, bare):
        """The repository path a path in code means, or None when it is not
        one to check."""
        first = bare.split("/")[0]
        if self.local and (first == ".."
                           or os.path.join(self.local, first) in self.repo.known):
            rel = os.path.normpath(os.path.join(self.local, bare))
            return None if rel == ".." or rel.startswith("../") else rel
        return bare if first in self.repo.top_dirs else None

    def path_holds(self, token, rel):
        if "*" in token:
            return self.repo.glob(rel)
        # A path git ignores is made at run time; one the code names, such
        # as a folder the scanner skips, is not a file of this repository.
        return (self.repo.exists(rel) or self.repo.ignored(rel)
                or rel in self.repo.source())

    def check_flags(self):
        for line, text in self.code():
            for command in re.split(r"\|\||&&|[|;]", text):
                self.check_command(line, command.split(" #")[0])

    def check_command(self, line, command):
        words = command.replace('"', " ").replace("'", " ").split()
        for i, word in enumerate(words):
            # The docs also write a command's subcommand alone: `scan --limits`.
            if word == "loose-keys" or word.endswith("/loose-keys") \
                    or (i == 0 and word == "scan"):
                sources = self.repo.read("src/main.rs")
            elif word.endswith(SCRIPT_EXT) and self.repo.exists(word):
                sources = self.script_sources(word)
            else:
                continue
            for flag in FLAG.findall(" ".join(words[i + 1:])):
                if flag not in sources:
                    self.report(line, "flag", f"{word} {flag}: not in its source")
            return

    def script_sources(self, script):
        """A script's text and that of the files beside it, which often
        parse the options the script passes on."""
        folder = os.path.dirname(script)
        return "\n".join(self.repo.read(f) for f in self.repo.files
                         if os.path.dirname(f) == folder and not f.endswith(".md"))

    def check_names(self):
        for line, text in self.spans:
            text = " ".join(text.split())
            ident = IDENT.fullmatch(text)
            lone = LONE_FLAG.fullmatch(text)
            kind, word = "name", False
            if ident and ("::" in text or "_" in text or text.endswith("()")
                          or CAMEL.match(ident.group(1))):
                name, word = ident.group(1), True
                if self.repo.has_word(name):
                    continue
            elif KEBAB.fullmatch(text) or lone:
                # A lone option's command is unknown, so like a name it holds
                # when any file outside Markdown has it.
                name = text
                if lone:
                    name, kind = lone.group(1), "flag"
                if name in self.repo.source():
                    continue
            else:
                continue
            removed = self.repo.removed(name, word)
            if removed:
                self.report(line, kind, f"{text}: gone from the code{removed}")

    def check(self):
        self.check_links()
        self.check_paths()
        self.check_flags()
        self.check_names()
        return self.problems


def check(root, files, names):
    repo = Repo(root, files)
    return [problem for name in names for problem in Page(repo, name).check()]


if __name__ == "__main__":
    sys.exit(mdpages.run(check))
