#!/usr/bin/env python3
"""Find lines in the repository's Markdown that break the docs' prose rules.

Usage, from the repository or worktree root:
    python3 -I .agents/skills/documentation/check_prose.py [FILE.md ...]

With no files it reads every tracked or new Markdown file. Only prose is read:
fenced blocks, code spans, link targets and HTML comments are left out, and
quotations are left out of all but the repeat check. It
prints one "path:line: kind: detail" line per finding and exits 0 when there
are none, 1 when there are some and 2 when it cannot run. A finding is a line
to read, not a verdict. Kinds:

  filler   a filler or marketing word
  owner    "the owner", where the docs say "the person directing the session"
  emoji    an emoji
  record   a dated line that reports how a run went
  history  a phrase about what an earlier draft, worktree or session did
  repeat   a passage of at least REPEAT words that another page, or the same
           page, already says; compared against every page, reported once
  plan     a page whose name marks it as a spec, plan or design note
"""

import os
import re
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mdpages  # noqa: E402

REPEAT = 10

FILLER = re.compile(r"\b(?:" + "|".join([
    r"robust(?:ly|ness)?", r"seamless(?:ly)?", r"leverag(?:e|es|ed|ing)",
    r"comprehensive(?:ly)?", r"utili[sz](?:e|es|ed|ing|ation)", r"delv(?:e|es|ing)",
    r"streamlin(?:e|es|ed|ing)", r"cutting-edge", r"state-of-the-art",
    r"best-in-class", r"world-class", r"effortless(?:ly)?", r"game-chang(?:er|ing)",
    r"holistic(?:ally)?", r"plethora", r"myriad", r"empower(?:s|ed|ing)?",
    r"it(?:'|’| i)s worth (?:noting|mentioning)", r"needless to say",
    r"in today(?:'|’)s", r"fast-paced", r"rest assured", r"simply put",
]) + r")\b", re.I)
OWNER = re.compile(r"\bthe owner\b(?!-)", re.I)
EMOJI = re.compile("[\U0001F000-\U0001FAFF\u2600-\u27BF\u2B50\u2B55\uFE0F]")
DATE = re.compile(r"\b20\d\d-\d\d-\d\d\b")
RESULT = re.compile(r"\b(?:passed|failed|succeeded|green|candidate|exit(?:ed)? "
                    r"(?:with )?(?:0|1|2|status))\b", re.I)
HISTORY = re.compile(r"\b(?:" + "|".join([
    r"preserved from", r"already present", r"(?:earlier|previous|first|old) draft",
    r"(?:earlier|previous|older) (?:worktree|session)s?",
    r"(?:was|were) (?:dropped|preserved|kept from)", r"used to (?:be|say|have)",
    r"originally",
]) + r")\b", re.I)
PLAN_WORDS = {"spec", "specs", "plan", "plans", "proposal", "design", "rfc",
              "adr", "superpowers", "brainstorm"}
LINK_TARGET = re.compile(r"\]\([^)\n]*\)")
COMMENT = re.compile(r"<!--.*?-->", re.S)
QUOTED = re.compile(r"\"[^\"\n]*\"|“[^”\n]*”")
WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9'’-]*")


def prose(root, rel):
    """A page's prose, the same length and line count as the page."""
    text, _ = mdpages.blank_fences(mdpages.read(root, rel))
    for pattern in (COMMENT, mdpages.CODE_SPAN, LINK_TARGET):
        text = mdpages.blank(pattern, text)
    return text


def line_findings(rel, text):
    """Findings within single lines. A quotation is someone else's words,
    so its wording is not checked."""
    found = []
    for number, line in enumerate(mdpages.blank(QUOTED, text).split("\n"), 1):
        for match in FILLER.finditer(line):
            found.append((rel, number, "filler", f'"{match.group(0)}"'))
        if OWNER.search(line):
            found.append((rel, number, "owner",
                          'write "the person directing the session"'))
        if EMOJI.search(line):
            found.append((rel, number, "emoji", repr(EMOJI.search(line).group(0))))
        if DATE.search(line) and RESULT.search(line):
            found.append((rel, number, "record",
                          f"{DATE.search(line).group(0)} with "
                          f'"{RESULT.search(line).group(0)}"'))
        for match in HISTORY.finditer(line):
            found.append((rel, number, "history", f'"{match.group(0)}"'))
    return found


def plan_finding(rel):
    parts = set(re.split(r"[/._-]+", rel.lower()))
    if parts & PLAN_WORDS:
        return [(rel, 1, "plan", "specs and plans stay out of the repository")]
    return []


class Words:
    """Every page's prose as words with their line numbers, and where each
    run of REPEAT words occurs."""

    def __init__(self, texts):
        self.words, self.where = {}, {}
        for rel, text in texts.items():
            lines = mdpages.Lines(text)
            self.words[rel] = [(m.group(0).lower().strip("'’-"), lines.at(m.start()))
                               for m in WORD.finditer(text)]
            for i in range(len(self.words[rel]) - REPEAT + 1):
                self.where.setdefault(self.key(rel, i), []).append((rel, i))

    def key(self, rel, i):
        return " ".join(w for w, _ in self.words[rel][i:i + REPEAT])

    def elsewhere(self, rel, i):
        """The first other place with the run starting at word i."""
        for other, j in self.where.get(self.key(rel, i), []):
            if other != rel or abs(j - i) >= REPEAT:
                return other, j
        return None

    def repeats(self, rel, scope):
        found, i, count = [], 0, len(self.words[rel]) - REPEAT + 1
        while i < count:
            other = self.elsewhere(rel, i)
            if other is None:
                i += 1
                continue
            end = i
            while end + 1 < count and self.elsewhere(rel, end + 1):
                end += 1
            # Report a passage once: at its later copy, unless only this
            # copy is in scope.
            if (rel, i) > other or other[0] not in scope:
                line = self.words[rel][i][1]
                where = f"{other[0]}:{self.words[other[0]][other[1]][1]}"
                found.append((rel, line, "repeat",
                              f"{end - i + REPEAT} words also at {where}"))
            i = end + REPEAT
        return found


def check(root, files, names):
    texts = {f: prose(root, f) for f in files if f.endswith(".md")}
    for name in names:
        texts.setdefault(name, prose(root, name))
    words = Words(texts)
    scope = set(names)
    found = []
    for name in names:
        found += plan_finding(name)
        found += line_findings(name, texts[name])
        found += words.repeats(name, scope)
    return found


if __name__ == "__main__":
    sys.exit(mdpages.run(check))
