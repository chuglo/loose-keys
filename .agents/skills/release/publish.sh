#!/bin/sh
# Publish a tested candidate, in one fixed order that stops at the first
# failure: check that tests/check-all.sh passed on its commit and that the
# configured key signed it, push the commit to main, push its signed tag,
# publish both tested packages with the notes, then check everything again
# from GitHub and compare fresh downloads with the tested files. A step
# already done for the same commit is checked and skipped, so a run that
# stopped can be repeated.
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
[ "$(cat "$CAND/check-all" 2> /dev/null)" = "$COMMIT passed" ] \
    || fail "no passing tests/check-all.sh run is recorded for $COMMIT; build the candidate with prepare.sh"
TAG="v$VERSION"
[ -f "$NOTES" ] || fail "no notes file: $NOTES"
for package in "$ZIP" "$DMG"; do
    sum=$(cut -d ' ' -f 1 "$CAND/$package.sha256")
    grep -q -F "$package: $sum" "$NOTES" || fail "the notes do not give $package's checksum, $sum"
done
printf '%s %s\n' "$COMMIT" "$TAG"

# Checked here, before anything is pushed, against the key this repository
# signs with; GitHub's own check comes after publication.
step 'Signature'
[ "$(git config gpg.format)" = ssh ] || fail 'gpg.format is not ssh, so the commit signature cannot be checked'
key=$(git config user.signingkey) || fail 'no signing key is configured (user.signingkey)'
case "$key" in
    key::*) key=${key#key::} ;;
    ssh-* | ecdsa-* | sk-*) ;;
    *)
        case "$key" in "~/"*) key="$HOME/${key#"~/"}" ;; esac
        # A private key's path stands for the public key beside it.
        [ ! -f "$key.pub" ] || key="$key.pub"
        key=$(head -n 1 "$key") || fail "the signing key $key could not be read"
        ;;
esac
SIGNERS=$(mktemp "${TMPDIR%/}/release-signers.XXXXXX")
trap 'rm -f "$SIGNERS"' EXIT
printf '%s\n' "$key" | awk '{ print "* " $1 " " $2 }' > "$SIGNERS"
signed() { git -c gpg.ssh.allowedSignersFile="$SIGNERS" "$@" > "$SIGNERS.log" 2>&1; }
signed verify-commit "$COMMIT" || fail "$COMMIT is not signed by the configured signing key; see $SIGNERS.log"

step 'Repository'
[ "$(gh api 'repos/{owner}/{repo}/immutable-releases' --jq .enabled)" = true ] \
    || fail 'immutable releases are off; ask the person directing the session'
git fetch -q origin
git merge-base --is-ancestor origin/main "$COMMIT" || fail 'the tested commit does not fast-forward main'
# A tag left by an earlier run is used only if it is the one this run would
# make: annotated, naming the commit itself and signed by the configured key.
# Once pushed, a release would be published from it before GitHub's check.
local_tag=$(git rev-parse -q --verify "refs/tags/$TAG" || true)
if [ -n "$local_tag" ]; then
    [ "$(git rev-parse "refs/tags/$TAG^{commit}")" = "$COMMIT" ] || fail "$TAG already names another commit"
    [ "$(git for-each-ref --format='%(objecttype) %(*objectname)' "refs/tags/$TAG")" = "tag $COMMIT" ] \
        || fail "$TAG is not an annotated tag of $COMMIT; delete it with git tag -d $TAG"
    signed verify-tag "$TAG" || fail "$TAG is not signed by the configured signing key; see $SIGNERS.log"
fi
# A lightweight tag has no peeled ^{} line.
remote=$(git ls-remote origin "refs/tags/$TAG" "refs/tags/$TAG^{}")
remote_tag=$(printf '%s\n' "$remote" | awk -v ref="refs/tags/$TAG" '$2 == ref { print $1 }')
remote_commit=$(printf '%s\n' "$remote" | awk -v ref="refs/tags/$TAG^{}" '$2 == ref { print $1 }')
if [ -n "$remote_tag" ]; then
    [ "$remote_commit" = "$COMMIT" ] || fail "$TAG on GitHub is not an annotated tag of $COMMIT"
    [ -n "$local_tag" ] || fail "$TAG is on GitHub but not here; fetch it with git fetch origin tag $TAG"
    [ "$remote_tag" = "$local_tag" ] || fail "$TAG on GitHub is not the signed tag here"
fi
rm -f "$SIGNERS.log"

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
