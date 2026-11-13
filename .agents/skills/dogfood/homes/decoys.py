"""Where a developer would expect each decoy of `security-tests/harness.sh
generate-home`, which every guest's home also gets. Written from what the
harness says each one is, not from what the scanner does with it."""

from .lib import DEBATABLE, HIDDEN, STORED, WORTH

# By the id the harness gives a target. Anything not here is a credential in
# a plain file, expected in Worth Reviewing.
EXPECT = {
    "browser-chrome-logins": (STORED, "passwords a browser saved, as browsers do"),
    "browser-chrome-cards": (STORED, "cards a browser saved, as browsers do"),
    "browser-firefox-logins": (STORED, "passwords a browser saved, as browsers do"),
    "browser-chrome-cookies": (HIDDEN, "the usage guide says cookies are not covered"),
    "ssh-key-protected": (STORED, "the key has a passphrase"),
    "gcloud-login": (STORED, "the sign-in gcloud keeps for itself"),
    "gcloud-store": (STORED, "the sign-in gcloud keeps for itself"),
    "azure-login": (STORED, "the sign-in the Azure CLI keeps for itself"),
    "aws-sso-cache": (STORED, "a short-lived session the AWS CLI keeps"),
    "vercel-login": (STORED, "the sign-in the Vercel CLI keeps for itself"),
    "ai-cli-login": (STORED, "the sign-in an AI tool keeps for itself"),
    "cline-secrets": (STORED, "the key store an AI extension keeps for itself"),
    "wallet-extension": (STORED, "a wallet's own encrypted storage"),
    "wallet-desktop": (STORED, "a wallet's own storage"),
    "telegram-session": (STORED, "the session Telegram keeps for itself"),
    "keepass-db": (STORED, "an encrypted password database"),
    "apple-notes": (HIDDEN, "the usage guide says Notes is not covered"),
    "keychain-db": (HIDDEN, "the usage guide says the Keychain is not covered"),
    "stripe-test-key": (DEBATABLE, "a key its issuer marks as test-only"),
    "git-history": (DEBATABLE, "the token is only in the repository's history"),
}

# The vm skill leaves these out of a guest cloned from lk-sip-base.
NOT_IN_SIP_GUEST = ("Desktop/", "Documents/", "Downloads/", "Library/Group Containers/", "Library/Keychains/")


def items(manifest, taken):
    """Manifest entries for the decoys, without the paths a home wrote over."""
    out = []
    for target in manifest["targets"]:
        expect, why = EXPECT.get(target["id"], (WORTH, "a credential in a plain file"))
        out.append((target, expect, why))
    for decoy in manifest["decoys"]:
        out.append((decoy, HIDDEN, "holds no credential"))
    entries = []
    for source, expect, why in out:
        path = source["paths"][0]
        if path in taken:
            continue
        entry = {"path": path, "what": "decoy: " + source["what"], "expect": expect, "why": why}
        if path.startswith(NOT_IN_SIP_GUEST):
            entry["absent"] = "left out of a guest cloned from lk-sip-base"
        entries.append(entry)
    return entries
