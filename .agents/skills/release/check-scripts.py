"""Offline regression checks for release preparation; never starts a VM."""
import os
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class ReleaseScripts(unittest.TestCase):
    def test_changed_candidate_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix=f"release-integrity-{os.getpid()}-") as folder:
            root = Path(folder)
            (root / "share").mkdir()
            (root / "commit").write_text("a" * 40 + " 0.3.0\n")
            names = ["commit", "share/repo.tar", "share/security-harness",
                     "share/Loose-Keys-0.3.0.zip", "share/Loose-Keys-0.3.0.dmg"]
            for name in names[1:]:
                (root / name).write_bytes(b"original")
            (root / "SHA256SUMS").write_text("".join(
                hashlib.sha256((root / name).read_bytes()).hexdigest() + "  " + name + "\n"
                for name in names))
            def verify():
                return subprocess.run(["sh", "-c", '. "$1"; verify_candidate',
                                       "check", str(HERE / "guest-lib.sh")],
                                      env=dict(os.environ, CAND=folder), capture_output=True)
            self.assertEqual(verify().returncode, 0)
            for name in names[-2:]:
                with self.subTest(package=name):
                    (root / name).write_bytes(b"changed")
                    self.assertNotEqual(verify().returncode, 0)
                    (root / name).write_bytes(b"original")
                    self.assertEqual(verify().returncode, 0)
            (root / names[-1]).unlink()
            self.assertNotEqual(verify().returncode, 0)

    def test_invalid_version_does_not_modify_files(self):
        with tempfile.TemporaryDirectory(prefix=f"release-version-{os.getpid()}-") as folder:
            root = Path(folder)
            (root / "gui/macos").mkdir(parents=True)
            original = 'version = "0.2.0"\n'
            for name in ("Cargo.toml", "gui/Cargo.toml"):
                (root / name).write_text(original)
            (root / "gui/macos/Info.plist").write_text('<string>0.2.0</string>\n')
            (root / "README.md").write_text('Version 0.2.0, MIT licensed.\n')
            (root / "cargo").write_text('#!/bin/sh\nexit 0\n')
            (root / "cargo").chmod(0o700)
            result = subprocess.run(["sh", str(HERE / "bump.sh"), "1.2"],
                                    cwd=root, capture_output=True,
                                    env=dict(os.environ, PATH=f"{root}:/usr/bin:/bin"))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((root / "Cargo.toml").read_text(), original)

    def test_bump_preserves_readme_version_line_format(self):
        # A UTF-8 locale sorts README.md after gui/, which C does not.
        for locale in ("C", "en_US.UTF-8"):
            with self.subTest(locale=locale), \
                    tempfile.TemporaryDirectory(prefix=f"release-readme-{os.getpid()}-") as folder:
                result, work = self.bump_fixture(Path(folder), locale, "0.2.1")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((work / "README.md").read_text(), "Version 0.2.1 · MIT licensed\n")

    def test_bump_requires_a_higher_version(self):
        # From 0.2.0; 0.10.0 is higher though it sorts lower as text.
        for new, higher in (("0.1.9", False), ("0.1.10", False), ("0.0.5", False),
                            ("0.2.0", False), ("0.10.0", True), ("0.2.1", True)):
            with self.subTest(new=new), \
                    tempfile.TemporaryDirectory(prefix=f"release-bump-{os.getpid()}-") as folder:
                result, work = self.bump_fixture(Path(folder), "C", new)
                self.assertEqual(result.returncode == 0, higher, result.stderr)
                if not higher:
                    self.assertIn('version = "0.2.0"', (work / "Cargo.toml").read_text())

    def bump_fixture(self, root, locale, new):
        repo = root / "repo"
        repo.mkdir()
        def run(*args, cwd=repo):
            return subprocess.run(args, cwd=cwd, check=True, capture_output=True)
        run("git", "init")
        (repo / "gui/macos").mkdir(parents=True)
        (repo / "src").mkdir()
        (repo / "gui/src").mkdir()
        (repo / "src/lib.rs").write_text("")
        (repo / "gui/src/lib.rs").write_text("")
        (repo / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["gui"]\n[package]\nname = "fixture"\nversion = "0.2.0"\nedition = "2021"\n')
        (repo / "gui/Cargo.toml").write_text(
            '[package]\nname = "fixture-gui"\nversion = "0.2.0"\nedition = "2021"\n')
        (repo / "README.md").write_text("Version 0.2.0 · MIT licensed\n")
        (repo / "gui/macos/Info.plist").write_text("<string>0.2.0</string>\n")
        run("cargo", "metadata", "--offline", "--format-version", "1")
        run("git", "add", ".")
        run("git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "-m", "Synthetic version fixture")
        work = root / "work"
        run("git", "worktree", "add", str(work))
        result = subprocess.run(["sh", str(HERE / "bump.sh"), new],
                                cwd=work, capture_output=True, text=True,
                                env=dict(os.environ, LC_ALL=locale))
        return result, work

    # publish.sh against stand-ins for git and gh that record each call, in a
    # local repository whose commit is signed with a key made for the test.
    # Only the signature check reaches the real git. Nothing here reaches
    # GitHub or changes a repository other than the fixture's.
    GIT_ENV = dict(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")

    def signed_repo(self, root, signer="configured"):
        repo = root / "repo"
        (repo / "gui/macos").mkdir(parents=True)
        (repo / "gui/macos/Info.plist").write_text("")
        env = dict(os.environ, **self.GIT_ENV)
        def run(*args):
            return subprocess.run(args, cwd=repo, env=env, check=True,
                                  capture_output=True, text=True).stdout.strip()
        for name in ("configured", "other"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "fixture",
                            "-f", str(root / f"{name}-key")], check=True, capture_output=True)
        run("git", "init", "-q")
        for key, value in (("user.name", "Fixture"), ("user.email", "fixture@example.invalid"),
                           ("gpg.format", "ssh"), ("commit.gpgsign", "false"),
                           ("user.signingkey", str(root / "configured-key"))):
            run("git", "config", key, value)
        run("git", "add", ".")
        if signer is None:
            run("git", "commit", "-q", "-m", "Synthetic release")
        else:
            run("git", "-c", f"user.signingkey={root / (signer + '-key')}",
                "commit", "-q", "-S", "-m", "Synthetic release")
        return repo, run("git", "rev-parse", "HEAD")

    def publish_fixture(self, root, notes_checksums=True, signer="configured", checked=True):
        repo, self.COMMIT = self.signed_repo(root, signer)
        cand = root / "candidate"
        (cand / "share").mkdir(parents=True)
        (cand / "commit").write_text(self.COMMIT + " 0.3.0\n")
        if checked:
            (cand / "check-all").write_text(self.COMMIT + " passed\n")
        names = ["commit", "share/repo.tar", "share/security-harness",
                 "share/Loose-Keys-0.3.0.zip", "share/Loose-Keys-0.3.0.dmg"]
        for name in names[1:]:
            (cand / name).write_bytes(name.encode())
        digest = {name: hashlib.sha256((cand / name).read_bytes()).hexdigest() for name in names}
        (cand / "SHA256SUMS").write_text("".join(f"{digest[n]}  {n}\n" for n in names))
        notes = root / "notes.md"
        lines = ["What's changed\n"]
        for package in ("Loose-Keys-0.3.0.zip", "Loose-Keys-0.3.0.dmg"):
            (cand / f"{package}.sha256").write_text(f"{digest['share/' + package]}  {package}\n")
            if notes_checksums:
                lines.append(f"{package}: {digest['share/' + package]}\n")
        notes.write_text("".join(lines))
        bin_dir = root / "bin"
        bin_dir.mkdir()
        # Tags are read from the fixture repository; GitHub's are the
        # "<sha>\t<ref>" lines in $REMOTE_REFS, matched by exact name as
        # ls-remote matches them.
        real_git = shutil.which("git")
        (bin_dir / "git").write_text(
            '#!/bin/sh\nprintf "git %s\\n" "$*" >> "$RECORD"\n'
            'case "$1" in\n'
            f'  config|-c|for-each-ref) exec "{real_git}" "$@";;\n'
            '  merge-base) exit "${FF_STATUS:-0}";;\n'
            f'  rev-parse) case "$*" in *refs/tags/*) exec "{real_git}" "$@";; esac; echo base;;\n'
            '  ls-remote) shift 2; for ref in "$@"; do\n'
            '    printf "%s" "${REMOTE_REFS:-}" | awk -F "\\t" -v ref="$ref" \'$2 == ref\'; done;;\n'
            'esac\nexit 0\n')
        (bin_dir / "gh").write_text(
            '#!/bin/sh\nprintf "gh %s\\n" "$*" >> "$RECORD"\n'
            'case "$1 $2" in\n'
            '  "api repos/{owner}/{repo}/immutable-releases") echo true;;\n'
            '  "api repos/{owner}/{repo}/commits/"*) echo true;;\n'
            '  "api repos/{owner}/{repo}/git/refs/tags/"*) echo tag-object;;\n'
            '  "api repos/{owner}/{repo}/git/tags/"*) echo "$COMMIT true";;\n'
            '  "release view") [ -f "$RELEASED" ] || exit 1\n'
            '    case "$*" in *isImmutable*) echo true;; *url*) echo https://example.invalid;; esac;;\n'
            '  "release create") : > "$RELEASED";;\n'
            '  "release download") while [ $# -gt 0 ]; do [ "$1" = --dir ] && dir=$2; shift; done\n'
            '    cp "$CAND/share/"Loose-Keys-0.3.0.* "$dir/";;\n'
            'esac\nexit 0\n')
        for tool in ("git", "gh"):
            (bin_dir / tool).chmod(0o700)
        record = root / "calls"
        env = dict(os.environ, PATH=f"{bin_dir}:/usr/bin:/bin", RECORD=str(record),
                   RELEASED=str(root / "released"), CAND=str(cand), COMMIT=self.COMMIT,
                   TMPDIR=str(root), **self.GIT_ENV)
        return cand, notes, repo, record, env

    def publish(self, cand, notes, repo, env):
        return subprocess.run(["sh", str(HERE / "publish.sh"), str(cand), str(notes)],
                              cwd=repo, env=env, capture_output=True, text=True)

    def test_publish_runs_each_step_in_order(self):
        with tempfile.TemporaryDirectory(prefix=f"release-publish-{os.getpid()}-") as folder:
            cand, notes, repo, record, env = self.publish_fixture(Path(folder))
            result = self.publish(cand, notes, repo, env)
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = record.read_text().splitlines()
            order = [f"git push origin {self.COMMIT}:refs/heads/main",
                     f"git tag -s v0.3.0 {self.COMMIT} -m Loose Keys 0.3.0",
                     "git push origin refs/tags/v0.3.0"]
            self.assertEqual([c for c in calls if c in order], order)
            create = next(i for i, c in enumerate(calls) if c.startswith("gh release create v0.3.0"))
            self.assertGreater(create, calls.index(order[-1]))
            for later in ("gh release verify v0.3.0", "gh release verify-asset v0.3.0", "gh release download v0.3.0"):
                self.assertTrue(any(c.startswith(later) for c in calls[create:]), later)

    # A v0.3.0 tag in the fixture repository, as an earlier run might leave.
    def tag(self, root, repo, *args, signer="configured"):
        env = dict(os.environ, **self.GIT_ENV)
        subprocess.run(["git", "-c", f"user.signingkey={root / (signer + '-key')}", "tag", *args,
                        "v0.3.0", self.COMMIT], cwd=repo, env=env, check=True, capture_output=True)
        return subprocess.run(["git", "rev-parse", "refs/tags/v0.3.0"], cwd=repo, env=env,
                              check=True, capture_output=True, text=True).stdout.strip()

    def test_publish_resumes_with_the_signed_tag_it_made(self):
        for on_github in (False, True):
            with self.subTest(on_github=on_github), \
                    tempfile.TemporaryDirectory(prefix=f"release-publish-{os.getpid()}-") as folder:
                root = Path(folder)
                cand, notes, repo, record, env = self.publish_fixture(root)
                tag = self.tag(root, repo, "-s", "-m", "Loose Keys 0.3.0")
                if on_github:
                    env["REMOTE_REFS"] = (f"{tag}\trefs/tags/v0.3.0\n"
                                          f"{self.COMMIT}\trefs/tags/v0.3.0^{{}}\n")
                result = self.publish(cand, notes, repo, env)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = record.read_text()
                self.assertNotIn("git tag -s", calls)
                self.assertEqual("git push origin refs/tags/v0.3.0" in calls, not on_github)
                self.assertIn("gh release create v0.3.0", calls)

    def test_publish_refuses_an_earlier_tag_it_did_not_sign(self):
        unsigned = "v0.3.0 is not signed by the configured signing key"
        for kind, args, signer, reason in (
                ("lightweight", [], "configured", "v0.3.0 is not an annotated tag"),
                ("unsigned", ["-a", "-m", "Loose Keys 0.3.0"], "configured", unsigned),
                ("other key", ["-s", "-m", "Loose Keys 0.3.0"], "other", unsigned)):
            with self.subTest(kind=kind), \
                    tempfile.TemporaryDirectory(prefix=f"release-publish-{os.getpid()}-") as folder:
                root = Path(folder)
                cand, notes, repo, record, env = self.publish_fixture(root)
                self.tag(root, repo, *args, signer=signer)
                result = self.publish(cand, notes, repo, env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(reason, result.stderr)
                calls = record.read_text()
                self.assertNotIn("git push", calls)
                self.assertNotIn("gh release create", calls)

    def test_publish_refuses_a_lightweight_tag_on_github(self):
        with tempfile.TemporaryDirectory(prefix=f"release-publish-{os.getpid()}-") as folder:
            cand, notes, repo, record, env = self.publish_fixture(Path(folder))
            env["REMOTE_REFS"] = f"{self.COMMIT}\trefs/tags/v0.3.0\n"
            result = self.publish(cand, notes, repo, env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("v0.3.0 on GitHub is not an annotated tag", result.stderr)
            calls = record.read_text()
            self.assertNotIn("git push", calls)
            self.assertNotIn("gh release create", calls)

    def test_publish_stops_before_pushing_when_main_moved(self):
        with tempfile.TemporaryDirectory(prefix=f"release-publish-{os.getpid()}-") as folder:
            cand, notes, repo, record, env = self.publish_fixture(Path(folder))
            result = self.publish(cand, notes, repo, dict(env, FF_STATUS="1"))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not fast-forward main", result.stderr)
            calls = record.read_text()
            self.assertNotIn("git push", calls)
            self.assertNotIn("gh release create", calls)

    def test_publish_refuses_notes_without_checksums(self):
        with tempfile.TemporaryDirectory(prefix=f"release-publish-{os.getpid()}-") as folder:
            cand, notes, repo, record, env = self.publish_fixture(Path(folder), notes_checksums=False)
            result = self.publish(cand, notes, repo, env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("checksum", result.stderr)
            self.assertFalse(record.exists(), "no git or gh call before the notes are checked")

    def test_publish_refuses_a_commit_not_signed_by_the_configured_key(self):
        for signer in (None, "other"):
            with self.subTest(signer=signer), \
                    tempfile.TemporaryDirectory(prefix=f"release-publish-{os.getpid()}-") as folder:
                cand, notes, repo, record, env = self.publish_fixture(Path(folder), signer=signer)
                result = self.publish(cand, notes, repo, env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("not signed by the configured signing key", result.stderr)
                calls = record.read_text()
                self.assertNotIn("git push", calls)
                self.assertNotIn("git fetch", calls)
                self.assertNotIn("gh ", calls)

    def test_publish_refuses_a_candidate_without_a_passing_check_all(self):
        for record_text in (None, "d" * 40 + " passed\n"):
            with self.subTest(record=record_text), \
                    tempfile.TemporaryDirectory(prefix=f"release-publish-{os.getpid()}-") as folder:
                cand, notes, repo, record, env = self.publish_fixture(Path(folder), checked=False)
                if record_text is not None:
                    (cand / "check-all").write_text(record_text)
                result = self.publish(cand, notes, repo, env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("check-all", result.stderr)
                self.assertFalse(record.exists(), "no git or gh call without a passing check-all")

    # prepare.sh copied beside a stand-in candidate.sh, in a worktree of a
    # fixture repository whose tests/check-all.sh exits with $CHECK_STATUS.
    def prepare(self, root, check_status):
        repo = root / "repo"
        (repo / "gui/macos").mkdir(parents=True)
        (repo / "tests").mkdir()
        (repo / "gui/macos/Info.plist").write_text("")
        (repo / "tests/check-all.sh").write_text('echo "fmt: exit $CHECK_STATUS"\nexit "$CHECK_STATUS"\n')
        env = dict(os.environ, **self.GIT_ENV, TMPDIR=str(root), CHECK_STATUS=str(check_status))
        def run(*args, cwd=repo):
            return subprocess.run(args, cwd=cwd, env=env, check=True,
                                  capture_output=True, text=True).stdout.strip()
        run("git", "init", "-q")
        run("git", "add", ".")
        run("git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "-q", "-m", "Synthetic release")
        work = root / "work"
        run("git", "worktree", "add", "-q", str(work))
        skill = root / "skill"
        skill.mkdir()
        shutil.copy(HERE / "prepare.sh", skill / "prepare.sh")
        (skill / "candidate.sh").write_text(
            'out="$TMPDIR/candidate"\nmkdir "$out"\n'
            'printf \'%s 0.3.0\\n\' "$1" > "$out/commit"\n'
            'printf \'Candidate: %s\\n\' "$out"\n')
        result = subprocess.run(["sh", str(skill / "prepare.sh")], cwd=work, env=env,
                                capture_output=True, text=True)
        return result, root / "candidate", run("git", "rev-parse", "HEAD")

    def test_prepare_records_a_passing_check_all_in_the_candidate(self):
        with tempfile.TemporaryDirectory(prefix=f"release-prepare-{os.getpid()}-") as folder:
            result, cand, commit = self.prepare(Path(folder), 0)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((cand / "check-all").read_text(), commit + " passed\n")
            self.assertIn("fmt: exit 0", (cand / "check-all.log").read_text())

    def test_prepare_builds_nothing_after_a_failed_check_all(self):
        with tempfile.TemporaryDirectory(prefix=f"release-prepare-{os.getpid()}-") as folder:
            result, cand, _ = self.prepare(Path(folder), 1)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(cand.exists())

    def test_failed_guest_setup_stops_owned_guest(self):
        with tempfile.TemporaryDirectory(prefix=f"release-cleanup-{os.getpid()}-") as folder:
            root = Path(folder)
            tart = root / "tart"
            record = root / "calls"
            tart.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$RECORD"\n'
                            'case "$1" in exec) exit 1;; esac\n')
            tart.chmod(0o700)
            script = '. "$1"\nstart_guest base\n'
            env = dict(os.environ, TART=str(tart), RECORD=str(record),
                       WORK=folder, CAND=folder, VM="test-owned", S="/share")
            # A failing startup must stop the VM, including failures before
            # unpacking. Stub sleep so the existing bounded wait is immediate.
            result = subprocess.run(["sh", "-c", 'sleep() { :; }; ' + script,
                                     "check", str(HERE / "guest-lib.sh")],
                                    env=env, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("stop test-owned", record.read_text())
            self.assertIn("VM process exited", result.stderr.decode())

    # A tart stand-in whose clone leaves an unfinished VM behind and fails.
    PARTIAL_CLONE_TART = ('#!/bin/sh\nprintf "%s\\n" "$*" >> "$RECORD"\n'
                          'case "$1" in\n'
                          '  list) echo "local lk-sip-base 50 33 today stopped"\n'
                          '    [ ! -f "$RECORD.partial" ] || echo "local $(cat "$RECORD.partial") 50 0 today stopped";;\n'
                          '  clone) printf "%s\\n" "$3" > "$RECORD.partial"; exit 1;;\n'
                          '  delete) rm -f "$RECORD.partial";;\n'
                          'esac\nexit 0\n')

    def test_failed_clone_is_deleted(self):
        with tempfile.TemporaryDirectory(prefix=f"release-cleanup-{os.getpid()}-") as folder:
            root = Path(folder)
            tart = root / "tart"
            record = root / "calls"
            tart.write_text(self.PARTIAL_CLONE_TART)
            tart.chmod(0o700)
            env = dict(os.environ, TART=str(tart), RECORD=str(record),
                       WORK=folder, CAND=folder, VM="test-owned", S="/share")
            result = subprocess.run(["sh", "-c", '. "$1"\nstart_guest base\n',
                                     "check", str(HERE / "guest-lib.sh")],
                                    env=env, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            calls = record.read_text().splitlines()
            self.assertIn("delete test-owned", calls)
            self.assertFalse(any(c.startswith("run ") for c in calls))

    # helper-check.sh against a tart stand-in whose guest answers each suite
    # run with the planted results.json and exit status.
    HELPER_TART = ('#!/bin/sh\nprintf "%s\\n" "$*" >> "$RECORD"\n'
                   'case "$1" in\n'
                   '  list) echo "local lk-sip-base 50 33 today stopped";;\n'
                   '  exec) shift 2; case "$1" in\n'
                   '    shasum) shasum -a 256 "$CAND/share/$(basename "$4")";;\n'
                   '    cat) case "$2" in *helper-negative*) cat "$RESULTS/negative.json";;\n'
                   '      *) cat "$RESULTS/positive.json";; esac;;\n'
                   '    sh) case "$*" in *helper-check*helper-negative*) exit 1;; esac;;\n'
                   '  esac;;\n'
                   'esac\nexit 0\n')
    STAGES = ["preflight", "enable-baseline", "event-create", "event-rotate", "event-delete",
              "restart-replay", "disable", "cleanup"]

    def helper_check(self, root, create_reason):
        cand = root / "candidate"
        (cand / "share").mkdir(parents=True)
        (cand / "commit").write_text("a" * 40 + " 0.3.0\n")
        names = ["commit", "share/repo.tar", "share/security-harness",
                 "share/Loose-Keys-0.3.0.zip", "share/Loose-Keys-0.3.0.dmg"]
        for name in names[1:]:
            (cand / name).write_bytes(name.encode())
        (cand / "SHA256SUMS").write_text("".join(
            hashlib.sha256((cand / name).read_bytes()).hexdigest() + "  " + name + "\n"
            for name in names))
        results = root / "results"
        results.mkdir()
        (results / "positive.json").write_text(json.dumps(
            {"cases": {stage: {"status": "PASS"} for stage in self.STAGES}}))
        negative = {stage: {"status": "NOT RUN"} for stage in self.STAGES}
        for stage in ("preflight", "enable-baseline", "cleanup"):
            negative[stage] = {"status": "PASS"}
        negative["event-create"] = {"status": "FAIL", "reason": create_reason}
        (results / "negative.json").write_text(json.dumps({"cases": negative}))
        bin_dir = root / "bin"
        bin_dir.mkdir()
        (bin_dir / "tart").write_text(self.HELPER_TART)
        (bin_dir / "tart").chmod(0o700)
        return subprocess.run(["sh", str(HERE / "helper-check.sh"), str(cand)],
                              env=dict(os.environ, PATH=f"{bin_dir}:/usr/bin:/bin",
                                       RECORD=str(root / "calls"), CAND=str(cand),
                                       RESULTS=str(results)),
                              capture_output=True, text=True)

    def test_helper_negative_control_must_fail_at_the_create_event(self):
        for reason, passes in (("deadline: native event and persisted fixture transition", True),
                               ("cannot write synthetic fixture", False)):
            with self.subTest(reason=reason), \
                    tempfile.TemporaryDirectory(prefix=f"release-helper-{os.getpid()}-") as folder:
                result = self.helper_check(Path(folder), reason)
                self.assertEqual(result.returncode == 0, passes, result.stdout + result.stderr)
                self.assertIn("Result:  PASS" if passes else "Result:  FAIL", result.stdout)

    def test_walkthrough_stops_when_the_decoy_archive_cannot_be_listed(self):
        with tempfile.TemporaryDirectory(prefix=f"release-walkthrough-{os.getpid()}-") as folder:
            root = Path(folder)
            cand = root / "candidate"
            (cand / "share").mkdir(parents=True)
            (cand / "commit").write_text("a" * 40 + " 0.3.0\n")
            (cand / "share/security-harness").write_text(
                '#!/bin/sh\nmkdir -p "$2/home" && echo synthetic > "$2/home/decoy"\n')
            (cand / "share/security-harness").chmod(0o700)
            names = ["commit", "share/repo.tar", "share/security-harness",
                     "share/Loose-Keys-0.3.0.zip", "share/Loose-Keys-0.3.0.dmg"]
            for name in names[3:] + names[1:2]:
                (cand / name).write_bytes(name.encode())
            (cand / "SHA256SUMS").write_text("".join(
                hashlib.sha256((cand / name).read_bytes()).hexdigest() + "  " + name + "\n"
                for name in names))
            bin_dir = root / "bin"
            bin_dir.mkdir()
            (bin_dir / "tart").write_text(self.PARTIAL_CLONE_TART)
            # Listing fails; creating and extracting use the real tar.
            (bin_dir / "tar").write_text(
                '#!/bin/sh\ncase "$1" in -t*) echo "tar: unreadable" >&2; exit 1;; esac\n'
                'exec /usr/bin/tar "$@"\n')
            for tool in ("tart", "tar"):
                (bin_dir / tool).chmod(0o700)
            record = root / "calls"
            result = subprocess.run(["sh", str(HERE / "walkthrough.sh"), str(cand)],
                                    env=dict(os.environ, PATH=f"{bin_dir}:/usr/bin:/bin",
                                             RECORD=str(record)),
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("decoy archive", result.stderr)
            self.assertNotIn("clone", record.read_text())


if __name__ == "__main__":
    unittest.main()
