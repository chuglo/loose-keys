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
