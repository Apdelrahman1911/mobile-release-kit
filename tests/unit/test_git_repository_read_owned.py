"""Explicit, Root-approved disposable real-Git core fixtures.

Only new private temporary repos/home/config. Fixed /usr/bin/git, no remote,
provider, host home, global config, repository hook, download or credentials.
Every setup/read call uses the unchanged run_owned C/A/W lifecycle. This is
portable core semantics verification, NOT installed Mac/provider qualification.
"""
from __future__ import annotations

import math
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest

from mobile_release import git_repository_read as read
from mobile_release import git_service as core
from mobile_release.owned_process import ProcessError, run_owned


class OwnedReadTests(unittest.TestCase):
    def setUp(self):
        self.unknown = False
        self.calls = 0
        self.end = time.monotonic() + 120
        self.repositories = []
        self.base = Path(tempfile.mkdtemp(prefix="mrk-git-read-owned-"))
        self.base.chmod(0o700)
        self.home, self.root = self.base / "home", self.base / "repo"
        self.home.mkdir(mode=0o700); self.root.mkdir(mode=0o700)
        self.created = {path: self.identity(path.lstat())[:5] for path in (self.base, self.home, self.root)}
        self.inventory = None
        self.environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": str(self.home),
            "XDG_CONFIG_HOME": str(self.home / "xdg"), "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_ALLOW_PROTOCOL": "",
            "GIT_TERMINAL_PROMPT": "0", "GIT_ATTR_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0"}
        self.addCleanup(self.cleanup_fixture)
        self.remember_fixture()
        self.git("init", "--template=", "--initial-branch=main", ".")

    def reader(self):
        # A fresh owner/deadline for each genuinely distinct action, as in the
        # private worker. Never renew a running action or the enclosing budget.
        repository = read.GitReadRepository(self.root, git_executable=Path("/usr/bin/git"),
            work_end=min(self.end, time.monotonic() + 45), _run=self.owned)
        self.repositories.append(repository)
        return repository

    def cleanup_fixture(self):
        if self.unknown or any(repository._unknown for repository in self.repositories):
            # Never delete a fixture under a retained original process or an
            # ambiguous cleanup. Root must inspect that original, not retry it.
            raise AssertionError("Original Git fixture settlement unknown; owned temporary directory preserved")
        # Only positively returned commands can update this finite inventory.
        # A later extra entry/replacement is not adopted for blanket deletion.
        self.assertIsNotNone(self.inventory)
        self.assertEqual(self.read_inventory(), self.inventory, "Changed fixture preserved")
        for path, identity in tuple(self.inventory.items()):
            if stat.S_ISREG(identity[2]):
                self.assertEqual(self.identity(path.lstat()), identity, "Changed fixture file preserved")
                del self.inventory[path]  # One attempt, never retry an uncertain unlink.
                path.unlink()
        for path in sorted(tuple(self.inventory), key=lambda item: len(item.parts), reverse=True):
            self.assertEqual(self.identity(path.lstat())[:5], self.inventory[path][:5], "Changed fixture directory preserved")
            del self.inventory[path]
            path.rmdir()  # Unexpected contents are retained, never recursively removed.

    @staticmethod
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def read_inventory(self):
        for path, original in self.created.items():
            self.assertEqual(self.identity(path.lstat())[:5], original, "Original fixture directory changed")
        found, pending, total = {}, [self.base], 0
        while pending:
            path = pending.pop()
            info = path.lstat()
            self.assertEqual(info.st_uid, os.getuid())
            self.assertTrue(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), "Nonregular fixture entry preserved")
            found[path] = self.identity(info)
            self.assertLessEqual(len(found), 256)
            self.assertLessEqual(len(path.relative_to(self.base).parts), 12)
            if stat.S_ISDIR(info.st_mode):
                self.assertEqual(info.st_mode & 0o7022, 0)
                with os.scandir(path) as entries:
                    for entry in entries:
                        self.assertLess(len(found) + len(pending), 256)
                        pending.append(Path(entry.path))
            else:
                self.assertEqual(info.st_nlink, 1)
                self.assertLessEqual(info.st_size, 1024 * 1024)
                total += info.st_size
                self.assertLessEqual(total, 4 * 1024 * 1024)
        return found

    def remember_fixture(self):
        try:
            self.inventory = self.read_inventory()
        except BaseException:
            self.unknown = True
            raise

    def write_text(self, name, text):
        self.assertIn(name, ("selected.txt", "untracked.txt"))
        (self.root / name).write_text(text)
        self.remember_fixture()

    def owned(self, argv, **options):
        self.assertFalse(self.unknown)
        self.calls += 1
        self.assertLessEqual(self.calls, 160)
        remaining = math.floor(self.end - time.monotonic())
        self.assertGreaterEqual(remaining, 1)
        options["timeout"] = min(options.get("timeout", 5), 5, remaining)
        try:
            return run_owned(argv, **options)
        except BaseException as error:
            if not isinstance(error, ProcessError) or error.fatal:
                self.unknown = True
            raise

    def git(self, *args):
        result = self.owned(["/usr/bin/git", "--no-pager", "-c", "core.hooksPath=" + os.devnull,
            "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "gc.auto=0",
            "-c", "maintenance.auto=false", "-c", "protocol.allow=never",
            "-c", "user.name=GitReadFixture", "-c", "user.email=fixture@example.invalid", *args],
            cwd=self.root, environ=self.environment, timeout=5, output_limit=65536, capture=True, text=False)
        self.assertEqual(result.returncode, 0, "The bounded fixture Git setup did not succeed")
        self.remember_fixture()
        return result.stdout

    def commit_text(self, text):
        self.write_text("selected.txt", text)
        self.git("add", "--", "selected.txt")  # Never blanket stage, even fixtures.
        self.git("commit", "--no-gpg-sign", "-m", "Synthetic subject withheld from history")

    def test_real_local_tracking_worktree_diff_and_metadata_only_history(self):
        self.commit_text("one\n")
        self.git("branch", "upstream")
        self.commit_text("two\n")
        # A local upstream, NOT a configured remote/URL/server or fetch.
        self.git("config", "--local", "branch.main.remote", ".")
        self.git("config", "--local", "branch.main.merge", "refs/heads/upstream")
        self.write_text("selected.txt", "three\n")
        self.write_text("untracked.txt", "inert untracked text\n")
        observed = self.reader().observe()
        self.assertEqual(observed.observation.branch, "refs/heads/main")
        self.assertEqual(observed.observation.remotes, ())
        self.assertEqual((observed.tracking.state, observed.tracking.remote, observed.tracking.ahead, observed.tracking.behind),
                         ("complete", ".", 1, 0))
        self.assertEqual({row.path for row in observed.observation.changes}, {"selected.txt", "untracked.txt"})
        diff = self.reader().diff(["selected.txt"], staged=False, expected_revision=observed.observation.revision)
        self.assertIsNone(diff.withheld)
        self.assertIn("+three", diff.text)
        history = self.reader().history(expected_revision=observed.observation.revision)
        self.assertEqual(len(history.commits), 2)
        self.assertEqual(history.commits[0].oid, observed.observation.head)
        self.assertEqual(history.commits[0].parents, (history.commits[1].oid,))
        self.assertNotIn("Synthetic subject", repr(history.as_dict()))

    def test_real_unborn_detached_and_ref_change_preserve_core_revision_contract(self):
        unborn = self.reader().observe()
        self.assertTrue(unborn.observation.as_dict()["unborn"])
        self.assertEqual(unborn.tracking.state, "unborn")
        self.assertEqual(self.reader().history(expected_revision=unborn.observation.revision).commits, ())
        self.commit_text("one\n")
        self.git("branch", "upstream")
        self.commit_text("two\n")
        self.git("config", "--local", "branch.main.remote", ".")
        self.git("config", "--local", "branch.main.merge", "refs/heads/upstream")
        before = self.reader().observe()
        self.git("update-ref", "--no-deref", "refs/heads/upstream", before.observation.head, before.tracking.head)
        after = self.reader().observe()
        self.assertEqual(after.observation.revision, before.observation.revision)
        self.assertNotEqual(after.reference_revision, before.reference_revision)
        self.assertEqual((after.tracking.ahead, after.tracking.behind), (0, 0))
        self.git("checkout", "--detach", "--no-guess", before.observation.head)
        detached = self.reader().observe()
        self.assertEqual(detached.tracking.state, "detached")
        self.assertIsNone(detached.observation.branch)

    def test_real_config_policy_refusal_runs_only_safe_no_includes_census(self):
        self.git("config", "--local", "include.path", str(self.base / "absent-never-opened"))
        before = self.calls
        with self.assertRaises(core.GitError) as raised:
            self.reader().observe()
        self.assertEqual(raised.exception.reason, "unsupported-repository")
        self.assertEqual(self.calls - before, 1)
        self.assertFalse((self.base / "absent-never-opened").exists())
