#!/bin/sh
# Publish a tested candidate, in one fixed order that stops at the first
# failure: push its commit to main, push its signed tag, publish both tested
# packages with the notes, then check everything again from GitHub and
# compare fresh downloads with the tested files. A step already done for the
# same commit is checked and skipped, so a run that stopped can be repeated.
# Usage, from the root of a worktree of this repository:
#   sh .agents/skills/release/publish.sh <candidate directory> <notes file>
set -eu

CAND=${1:?usage: publish.sh <candidate directory> <notes file>}
NOTES=${2:?usage: publish.sh <candidate directory> <notes file>}
. "$(dirname "$0")/guest-lib.sh"

[ -f gui/macos/Info.plist ] || fail 'run this from the repository root'
: "${TMPDIR:?Set TMPDIR to a scratch folder with no symbolic link in its path}"
step 'Candidate'
verify_candidate
TAG="v$VERSION"
[ -f "$NOTES" ] || fail "no notes file: $NOTES"
for package in "$ZIP" "$DMG"; do
    sum=$(cut -d ' ' -f 1 "$CAND/$package.sha256")
    grep -q -F "$package: $sum" "$NOTES" || fail "the notes do not give $package's checksum, $sum"
done
printf '%s %s\n' "$COMMIT" "$TAG"

step 'Repository'
[ "$(gh api 'repos/{owner}/{repo}/immutable-releases' --jq .enabled)" = true ] \
    || fail 'immutable releases are off; ask the person directing the session'
git fetch -q origin
git merge-base --is-ancestor origin/main "$COMMIT" || fail 'the tested commit does not fast-forward main'
local_tag=$(git rev-parse -q --verify "refs/tags/$TAG^{commit}" || true)
[ -z "$local_tag" ] || [ "$local_tag" = "$COMMIT" ] || fail "$TAG already names another commit"
remote_tag=$(git ls-remote origin "refs/tags/$TAG^{}" | cut -f 1)
[ -z "$remote_tag" ] || [ "$remote_tag" = "$COMMIT" ] || fail "$TAG on GitHub already names another commit"

step 'Push'
if [ "$(git rev-parse origin/main)" = "$COMMIT" ]; then
    printf 'main is already %s\n' "$COMMIT"
else
    git push origin "$COMMIT:refs/heads/main"
fi
[ -n "$local_tag" ] || git tag -s "$TAG" "$COMMIT" -m "Loose Keys $VERSION"
[ -n "$remote_tag" ] || git push origin "refs/tags/$TAG"

step 'Release'
if gh release view "$TAG" > /dev/null 2>&1; then
    printf '%s is already released; checking it\n' "$TAG"
else
    gh release create "$TAG" "$CAND/share/$ZIP" "$CAND/share/$DMG" \
        --verify-tag --title "Loose Keys $VERSION (beta)" --notes-file "$NOTES"
fi

step 'Verify'
[ "$(gh release view "$TAG" --json isImmutable --jq .isImmutable)" = true ] || fail "$TAG is not immutable"
gh release verify "$TAG"
gh release verify-asset "$TAG" "$CAND/share/$ZIP"
gh release verify-asset "$TAG" "$CAND/share/$DMG"
[ "$(gh api "repos/{owner}/{repo}/commits/$COMMIT" --jq .commit.verification.verified)" = true ] \
    || fail "GitHub does not verify the signature of $COMMIT"
tag_object=$(gh api "repos/{owner}/{repo}/git/refs/tags/$TAG" --jq .object.sha)
[ "$(gh api "repos/{owner}/{repo}/git/tags/$tag_object" --jq '"\(.object.sha) \(.verification.verified)"')" = "$COMMIT true" ] \
    || fail "GitHub does not verify $TAG as a signed tag of $COMMIT"
DOWNLOAD=$(mktemp -d "${TMPDIR%/}/release-download-$VERSION.XXXXXX")
gh release download "$TAG" --dir "$DOWNLOAD" --pattern "$ZIP" --pattern "$DMG"
for package in "$ZIP" "$DMG"; do
    [ "$(cd "$DOWNLOAD" && shasum -a 256 "$package")" = "$(cat "$CAND/$package.sha256")" ] \
        || fail "the published $package differs from the tested one"
done
printf '\nPublished %s: %s\n' "$TAG" "$(gh release view "$TAG" --json url --jq .url)"
