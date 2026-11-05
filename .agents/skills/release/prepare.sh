#!/bin/sh
# Check the release commit, then build its candidate: the checks for a push
# to main (tests/check-all.sh) on this worktree's HEAD, then candidate.sh from
# the same commit. One after the other: the release build's load made a
# timed check in check-all fail when they ran together. Each writes its own
# log; a failed check stops before the build, and the tree must still be
# clean afterwards.
# Usage, from the root of a worktree whose HEAD is the release commit:
#   sh .agents/skills/release/prepare.sh
set -u

fail() {
    printf 'FAILED: %s\n' "$*" >&2
    exit 1
}

[ -f gui/macos/Info.plist ] || fail 'run this from the repository root'
[ -f .git ] || fail 'run this in a git worktree'
: "${TMPDIR:?Set TMPDIR to a scratch folder with no symbolic link in its path}"
[ "$(cd "$TMPDIR" && pwd -P)" = "${TMPDIR%/}" ] || fail 'TMPDIR must have no symbolic link in its path'
[ -z "$(git status --porcelain)" ] || fail 'commit the release first; the checks run on the exact commit'
COMMIT=$(git rev-parse HEAD)
LOGS=$(mktemp -d "${TMPDIR%/}/prepare-$(git rev-parse --short HEAD).XXXXXX") || exit 1
unchanged() {
    [ "$(git rev-parse HEAD)" = "$COMMIT" ] || fail 'HEAD moved during the checks'
    [ -z "$(git status --porcelain)" ] || fail 'the tree changed during the checks'
}

printf 'Commit: %s\n' "$COMMIT"
printf '%s\n' 'window: the sample window check runs in a headless macOS guest'
if sh tests/check-all.sh > "$LOGS/check-all.log" 2>&1; then checks=0; else checks=$?; fi
grep -E '^[a-z0-9.-]+: (exit|skipped)' "$LOGS/check-all.log"
printf 'check-all: exit %s (%s)\n' "$checks" "$LOGS/check-all.log"
unchanged
[ "$checks" -eq 0 ] || fail 'a check failed, so no candidate was built'

if sh "$(dirname "$0")/candidate.sh" "$COMMIT" > "$LOGS/candidate.log" 2>&1; then build=0; else build=$?; fi
printf 'candidate: exit %s (%s)\n' "$build" "$LOGS/candidate.log"
unchanged
[ "$build" -eq 0 ] || fail 'the candidate build failed'
grep -E '^(Candidate|Commit|Disk image|Zip|SHA-256|DMG SHA-256):' "$LOGS/candidate.log"
