#!/usr/bin/env python3
"""Find references in the repository's Markdown that no longer hold.

Usage, from the repository or worktree root:
    python3 -I .agents/skills/documentation/check_refs.py [FILE.md ...]

With no files it reads every tracked or new Markdown file. It prints one
"path:line: kind: detail" line per problem and exits 0 when there are none,
1 when there are some and 2 when it cannot run. Kinds:

  link    a relative link whose file is missing
  anchor  a #fragment with no matching heading in its page
  path    a repository path in code that matches no file, from the root or
          from the page's folder, and that no file outside Markdown names
  flag    an option given to loose-keys or a repository script that its
          source never mentions
  name    a code name or hyphenated name in inline code that files outside
          Markdown once had and no longer do

A name the code never had, such as a standard library item, a lint or an
Apple constant, is not reported: read those yourself.
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
                first = token.split("/")[0]
                if first not in self.repo.top_dirs or re.search(r"[<>{}$]", token):
                    continue
                if not self.path_holds(token):
                    self.report(line, "path", f"{token}: no such file or folder"
                                + self.repo.gone(token.rstrip("/")))

    def path_holds(self, token):
        bare = token.rstrip("/")
        local = os.path.join(self.dir, bare) if self.dir else bare
        if "*" in token:
            return self.repo.glob(bare) or self.repo.glob(local)
        # A path git ignores is made at run time; one the code names, such
        # as a folder the scanner skips, is not a file of this repository.
        return (self.repo.exists(bare) or self.repo.exists(local)
                or self.repo.ignored(bare) or bare in self.repo.source())

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
            if ident and ("::" in text or "_" in text or text.endswith("()")
                          or CAMEL.match(ident.group(1))):
                name = ident.group(1)
                if self.repo.has_word(name):
                    continue
            elif KEBAB.fullmatch(text):
                name = text
                if name in self.repo.source():
                    continue
            else:
                continue
            removed = self.repo.last_change("-S", name, "--", ".", ":(exclude)*.md")
            if removed:
                self.report(line, "name", f"{text}: gone from the code since {removed}")

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
