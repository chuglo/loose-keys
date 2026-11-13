#!/usr/bin/env python3
"""Build one synthetic developer home and its manifest.

    python3 make_home.py <home> <new folder> <decoy manifest.json>

<home> is backend, javascript, ai, careful or web3 (developers), or
crypto_user, executive or freelancer (people the Mac infostealers of 2025
and 2026 robbed, who keep their files in Desktop, Documents and Downloads).

Writes <folder>/home, to pass to the vm skill as LOOSE_KEYS_EXTRA_HOME, and
<folder>/manifest.json: each planted item's path, what it is, and where a
developer would expect it, written before the app sees the home. The decoy
manifest is the one `security-tests/harness.sh generate-home` writes; its
paths are the same in every run, so the decoys the guest gets are listed too.
A home that is not a messy developer's has the decoys removed from its
guest before the first scan: <folder>/decoy-paths.txt lists what to remove.
The last three homes need a guest that lets its Desktop, Documents and
Downloads be written, which a clone of lk-sip-base refuses: open them with
LOOSE_KEYS_BASE set to the tahoe image.
"""

import json
import sys
from pathlib import Path

from homes import ai, backend, careful, crypto_user, decoys, executive, freelancer, javascript, web3
from homes.lib import Home

HOMES = {"backend": backend, "javascript": javascript, "ai": ai, "careful": careful, "web3": web3,
         "crypto_user": crypto_user, "executive": executive, "freelancer": freelancer}
WITHOUT_DECOYS = ("careful", "crypto_user", "executive", "freelancer")


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in HOMES:
        sys.exit(__doc__)
    kind, out, decoy_manifest = sys.argv[1], Path(sys.argv[2]), json.loads(Path(sys.argv[3]).read_text())
    out.mkdir(parents=True)
    home = Home(out, seed=kind)
    HOMES[kind].build(home)
    items = home.items
    if kind in WITHOUT_DECOYS:
        # Not a decoy this home wrote its own file over.
        paths = [path for entry in decoy_manifest["targets"] + decoy_manifest["decoys"] for path in entry["paths"]
                 if not (home.root / path).exists()]
        (out / "decoy-paths.txt").write_text("".join(path + "\n" for path in paths))
    else:
        items = items + decoys.items(decoy_manifest, {item["path"] for item in items})
    (out / "manifest.json").write_text(json.dumps({"home": kind, "files": home.files, "items": items}, indent=1) + "\n")
    print(f"{kind}: {home.files} files, {len(items)} manifest items -> {out}")


if __name__ == "__main__":
    main()
