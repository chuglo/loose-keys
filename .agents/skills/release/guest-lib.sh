# Shared by bundle-check.sh and helper-check.sh. Expects CAND, VM, WORK, S
# and TART to be set.

fail() {
    printf 'FAILED: %s\n' "$*" >&2
    exit 1
}
step() { printf '\n== %s\n' "$*"; }
guest() { "$TART" exec "$VM" "$@"; }

# Compare only fixed candidate paths, never paths read from a manifest.
# This detects accidental changes; the manifest is not a signature.
verify_candidate() {
    read -r COMMIT VERSION < "$CAND/commit" || fail 'candidate commit is missing'
    printf '%s\n' "$COMMIT" | grep -Eq '^[0-9a-f]{40}$' || fail 'invalid candidate commit'
    printf '%s\n' "$VERSION" | grep -Eq '^0\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' \
        || fail 'invalid candidate version'
    ZIP="Loose-Keys-$VERSION.zip"
    DMG="Loose-Keys-$VERSION.dmg"
    sums=$(cd "$CAND" && shasum -a 256 commit share/repo.tar share/security-harness "share/$ZIP" "share/$DMG") \
        || fail 'candidate files are missing'
    printf '%s\n' "$sums" | cmp -s - "$CAND/SHA256SUMS" || fail 'candidate changed; build a new candidate'
}

# Stop only the clone created by this invocation, even if startup or unpacking
# fails. A failed stop must not be reported as successful cleanup.
OWNED_VM=
cleanup_guest() {
    code=$?
    trap - EXIT HUP INT TERM
    if [ -n "$OWNED_VM" ]; then
        stop_guest || code=1
    fi
    exit "$code"
}
own_guest() {
    OWNED_VM=$VM
    trap cleanup_guest EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
}

# Clone $1 as $VM, start it headless with the candidate's share folder, and
# wait until it answers.
start_guest() {
    step "Starting a new VM, $VM, from $1"
    "$TART" clone "$1" "$VM" > "$WORK/clone.log" 2>&1 || fail "clone; see $WORK/clone.log"
    own_guest
    nohup "$TART" run "$VM" --no-graphics --dir="share:$CAND/share:ro" > "$WORK/run.log" 2>&1 &
    GUEST_PID=$!
    tries=0
    until guest test -f "$S/repo.tar" > /dev/null 2>&1; do
        kill -0 "$GUEST_PID" 2> /dev/null || fail "VM process exited; see $WORK/run.log"
        tries=$((tries + 1))
        [ "$tries" -lt 90 ] || fail "the VM did not answer within three minutes; see $WORK/run.log"
        sleep 2
    done
}

# Check the share by SHA-256, then unpack the source and the bundle under
# ~/work, where the guest checks expect them.
unpack_candidate() {
    step 'Copying the candidate in'
    for file in repo.tar security-harness "$ZIP"; do
        here=$(shasum -a 256 "$CAND/share/$file" | cut -d ' ' -f 1)
        there=$(guest shasum -a 256 "$S/$file" | cut -d ' ' -f 1)
        [ "$here" = "$there" ] || fail "$file differs in the guest"
    done
    guest sh -c 'mkdir -p ~/work/target/release/bundle/macos &&
        tar -xf "$1/repo.tar" -C ~/work &&
        ditto -x -k "$1/$2" ~/work/target/release/bundle/macos &&
        codesign --verify --deep --strict ~/work/target/release/bundle/macos/"Loose Keys.app"' \
        sh "$S" "$ZIP" > "$WORK/unpack.log" 2>&1 || fail "unpack; see $WORK/unpack.log"
}

# Flush the guest's disk before stopping it: a copy made just before a stop
# was lost once.
stop_guest() {
    guest sync || true
    if ! "$TART" stop "$VM" > /dev/null 2>&1; then
        if ! "$TART" list | awk -v vm="$VM" '$2 == vm && $NF == "stopped" { found = 1 } END { exit !found }'; then
            printf 'FAILED: could not stop %s; inspect it before continuing\n' "$VM" >&2
            return 1
        fi
    fi
    OWNED_VM=
}
