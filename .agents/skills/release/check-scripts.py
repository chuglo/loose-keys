"""Offline regression checks for release preparation; never starts a VM."""
import os
import hashlib
from pathlib import Path
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
            with self.subTest(locale=locale):
                self.bump_fixture(locale)

    def bump_fixture(self, locale):
        with tempfile.TemporaryDirectory(prefix=f"release-readme-{os.getpid()}-") as folder:
            root = Path(folder)
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
            result = subprocess.run(["sh", str(HERE / "bump.sh"), "0.2.1"],
                                    cwd=work, capture_output=True, text=True,
                                    env=dict(os.environ, LC_ALL=locale))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((work / "README.md").read_text(), "Version 0.2.1 · MIT licensed\n")

    # publish.sh against stand-ins for git and gh that record each call.
    # Nothing here reaches GitHub or changes a repository.
    COMMIT = "c" * 40

    def publish_fixture(self, root, notes_checksums=True):
        cand = root / "candidate"
        (cand / "share").mkdir(parents=True)
        (cand / "commit").write_text(self.COMMIT + " 0.3.0\n")
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
        repo = root / "repo"
        (repo / "gui/macos").mkdir(parents=True)
        (repo / "gui/macos/Info.plist").write_text("")
        bin_dir = root / "bin"
        bin_dir.mkdir()
        (bin_dir / "git").write_text(
            '#!/bin/sh\nprintf "git %s\\n" "$*" >> "$RECORD"\n'
            'case "$1" in\n'
            '  merge-base) exit "${FF_STATUS:-0}";;\n'
            '  rev-parse) case "$*" in *refs/tags/*) exit 1;; esac; echo base;;\n'
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
                   TMPDIR=str(root))
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


if __name__ == "__main__":
    unittest.main()
