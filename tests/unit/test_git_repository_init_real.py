"""Root-approved, nonroot Linux stock-Git initialization regressions.

Only a fresh private fixture is touched. Reuse the existing run_owned C/A/W
runner and finite cleanup, not another process harness. No remote, hook, shell,
project code or real credentials are used. The borrowed directories and inert
Candidate-ACK callback are test setup, NOT native Preparing/journal authority
or installed Mac qualification. An unknown original preserves its fixture.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from mobile_release import git_repository_init as init
from mobile_release import git_service as core
import test_git_repository_init as passive_fixture
import test_git_repository_read_owned as approved_fixture


@unittest.skipUnless(sys.platform == "linux" and os.getuid() != 0,
                     "The approved stock-Git fixture requires an ordinary Linux uid")
class RealInitTests(unittest.TestCase):
    # Helper composition only: never collect the older real-Git test classes.
    identity = staticmethod(approved_fixture.OwnedReadTests.identity)
    read_inventory = approved_fixture.OwnedReadTests.read_inventory
    remember_fixture = approved_fixture.OwnedReadTests.remember_fixture
    git = approved_fixture.OwnedReadTests.git

    def setUp(self):
        self.unknown, self.calls, self.returned_calls = False, 0, 0
        self.end = time.monotonic() + 120
        self.repositories, self.descriptors = [], []
        self.command_tail = self.uncertain_close = None
        self.base = Path(tempfile.mkdtemp(prefix="mrk-git-init-real-"))
        self.base.chmod(0o700)
        self.home, self.root = self.base / "home", self.base / "project"
        self.home.mkdir(mode=0o700); self.root.mkdir(mode=0o700)
        self.created = {path: self.identity(path.lstat())[:5]
                        for path in (self.base, self.home, self.root)}
        self.inventory = None
        self.environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
            "HOME": str(self.home), "XDG_CONFIG_HOME": str(self.home / "xdg"),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_ALLOW_PROTOCOL": "",
            "GIT_TERMINAL_PROMPT": "0", "GIT_ATTR_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0"}
        self.addCleanup(self.cleanup_originals)
        self.remember_fixture()
        (self.root / "source.txt").write_bytes(b"ordinary project text\n")
        (self.root / "nested").mkdir(mode=0o700)
        (self.root / "nested/keep").write_bytes(b"unchanged nested file\n")
        self.source = {path: (self.identity(path.lstat()), path.read_bytes())
                       for path in (self.root / "source.txt", self.root / "nested/keep")}
        self.remember_fixture()

        # The actual fixed installed binary, not a fake version/digest/provider.
        # Hold its original descriptor and compare it around every real call.
        self.tool = Path("/usr/bin/git")
        self.tool_fd = self.borrow(self.tool, directory=False)
        info = os.fstat(self.tool_fd)
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(info.st_uid, 0)
        self.assertEqual(info.st_mode & 0o022, 0)
        self.assertLessEqual(info.st_size, 16 * 1024 * 1024)
        self.tool_identity = self.identity(info)
        digest, size = hashlib.sha256(), 0
        while block := os.read(self.tool_fd, 65536):
            size += len(block)
            self.assertLessEqual(size, 16 * 1024 * 1024)
            digest.update(block)
        self.assertEqual(size, info.st_size)
        self.tool_digest = digest.hexdigest()
        self.check_tool()

    def borrow(self, path, *, directory=True):
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(path, flags | (os.O_DIRECTORY if directory else 0))
        self.descriptors.append((fd, None))  # Custody before inspection can fail.
        expected = self.identity(os.fstat(fd))[:5]
        self.descriptors[-1] = (fd, expected)
        self.assertEqual(self.identity(path.lstat())[:5], expected)
        return fd

    def check_tool(self):
        self.assertEqual(self.identity(os.fstat(self.tool_fd)), self.tool_identity)
        self.assertEqual(self.identity(self.tool.lstat()), self.tool_identity)

    def owned(self, argv, **options):
        self.check_tool()
        try:
            result = approved_fixture.OwnedReadTests.owned(self, argv, **options)
        except BaseException as error:
            self.command_tail = error  # Keep the original failure/cleanup facts.
            raise
        self.command_tail = result
        self.returned_calls += 1
        self.check_tool()
        return result

    def cleanup_originals(self):
        if self.unknown or any(repo._unknown or repo._active_sessions or repo._retained_sessions
                               or repo._retained for repo in self.repositories):
            self.unknown = True
            raise AssertionError("Original Init fixture is unresolved; descriptors and files preserved")
        try:
            while self.descriptors:
                fd, expected = self.descriptors[-1]
                self.assertIsNotNone(expected)
                self.assertEqual(self.identity(os.fstat(fd))[:5], expected)
                self.descriptors.pop()  # Retire this close route before its sole attempt.
                self.uncertain_close = (fd, expected)
                os.close(fd)
                self.uncertain_close = None
        except BaseException:
            self.unknown = True
            raise
        approved_fixture.OwnedReadTests.cleanup_fixture(self)

    def prepared(self):
        repository = init.GitInitRepository(self.root, git_executable=self.tool,
            work_end=min(self.end, time.monotonic() + 45), tool_digest=self.tool_digest, _run=self.owned)
        self.repositories.append(repository)
        review = repository.prepare_init()  # No Git or private candidate yet.
        self.assertEqual(self.calls, 0)
        outer = self.root / (init.PRIVATE_PREFIX + "a" * 32)
        paths = (outer, outer / "worktree", outer / "worktree/.git", outer / "empty-template")
        for path in paths:
            path.mkdir(mode=0o700)
        originals = []
        for path in (self.root, *paths):
            fd = self.borrow(path)
            originals.append(init.BorrowedDirectory(path, fd, init.directory(os.fstat(fd))))
        repository.candidate = init.BorrowedCandidate(*originals)
        self.remember_fixture()
        return repository, review, passive_fixture.Owner(self.root, review)

    def settled(self, repository):
        self.assertFalse(self.unknown or repository._unknown or repository._active_sessions
                         or repository._retained_sessions or repository._retained)
        self.assertEqual(self.calls, self.returned_calls)
        self.check_tool()
        # All real processes have returned with their original C/A/W cleanup;
        # only then adopt these fixture-created entries for finite test cleanup.
        self.remember_fixture()
        for path, (identity, body) in self.source.items():
            self.assertEqual(self.identity(path.lstat()), identity)
            self.assertEqual(path.read_bytes(), body)

    @staticmethod
    def apply(repository, review, owner):
        return repository.apply_init(review, owner, expected_digest=review.digest)

    def test_real_empty_template_init_relocates_without_ambient_config_or_staging(self):
        template = self.home / "unselected-template"
        template.mkdir(mode=0o700)
        (template / "description").write_bytes(b"inert template canary, never selected\n")
        config = self.home / ".gitconfig"
        config.write_text(f"[init]\n defaultBranch = unselected\n templateDir = {template}\n"
                          "[core]\n bare = true\n", encoding="utf-8")
        self.remember_fixture()
        repository, review, owner = self.prepared()
        candidate = repository.candidate
        (self.root / "later.txt").write_bytes(b"an edit made after review\n")
        self.remember_fixture()
        with patch.dict(os.environ, {"HOME": str(self.home), "GIT_CONFIG_GLOBAL": str(config),
                "GIT_TEMPLATE_DIR": str(template), "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "init.defaultBranch", "GIT_CONFIG_VALUE_0": "unselected"}):
            result = self.apply(repository, review, owner)
        self.settled(repository)
        self.assertEqual((result.state, result.settlement, result.reason, result.observation),
                         ("succeeded", "settled", None, None))
        self.assertEqual(self.calls, 2)  # Actual init, then actual bounded config query.
        self.assertEqual(owner.intents, [result.intent])
        transaction = repository._transaction
        self.assertTrue(transaction.acknowledged and transaction.returned and transaction.fsynced)
        published = init.manifest(candidate, published=True)
        self.assertEqual(published, transaction.captured)
        self.assertEqual(init.directory((self.root / ".git").lstat()), candidate.git.identity)
        self.assertFalse(candidate.git.path.exists())
        self.assertEqual(init.names(candidate.worktree.path), ())
        self.assertEqual((self.root / "later.txt").read_bytes(), b"an edit made after review\n")
        self.assertEqual(init.names(self.root / ".git"), ("HEAD", "config", "objects", "refs"))
        for leaf in ("objects/info", "objects/pack", "refs/heads", "refs/tags"):
            self.assertEqual(init.names(self.root / ".git" / leaf), ())
        self.assertEqual((self.root / ".git/HEAD").read_bytes(), b"ref: refs/heads/main\n")
        # Real stock Git recognizes the moved repository with no core.worktree
        # relocation trick, initial commit, index, hook or remote configuration.
        self.assertEqual(self.git("rev-parse", "--show-toplevel", "--show-object-format", "--is-bare-repository"),
                         os.fsencode(self.root) + b"\nsha1\nfalse\n")
        init.configuration(self.git("config", "--local", "--no-includes", "--null", "--list"))
        self.assertEqual(init.manifest(candidate, published=True), published)
        before = self.calls
        with self.assertRaises(core.GitError) as caught:
            self.apply(repository, review, owner)
        self.assertEqual(caught.exception.reason, "authorization")
        self.assertEqual(self.calls, before)  # No implicit second init/replay.
        self.settled(repository)

    def test_real_candidate_collision_before_publication_preserves_foreign_git(self):
        repository, review, owner = self.prepared()
        foreign = self.root / ".git"
        def collide(_intent):
            self.assertEqual(self.returned_calls, 2)
            foreign.mkdir(mode=0o700)
            (foreign / "keep").write_bytes(b"new external repository, not ours\n")
        owner.on_intent = collide
        with self.assertRaises(core.GitError) as caught:
            self.apply(repository, review, owner)
        self.assertEqual(caught.exception.reason, "git-already-present")
        self.settled(repository)
        self.assertEqual(self.calls, 2)
        self.assertFalse(repository._transaction.attempted)
        self.assertEqual((foreign / "keep").read_bytes(), b"new external repository, not ours\n")
        self.assertEqual(init.names(foreign), ("keep",))
        self.assertEqual(init.manifest(repository.candidate), repository._transaction.captured)

    def test_real_candidate_changed_after_ack_is_retained_without_publish_or_overwrite(self):
        repository, review, owner = self.prepared()
        config = repository.candidate.git.path / "config"
        changed = []
        def edit_candidate(_intent):
            self.assertEqual(self.returned_calls, 2)
            changed.append(config.read_bytes() + b"\n# intervening fixture-owned edit\n")
            config.write_bytes(changed[0])
        owner.on_intent = edit_candidate
        with self.assertRaises(core.GitError) as caught:
            self.apply(repository, review, owner)
        self.assertEqual(caught.exception.reason, "stale-observation")
        self.settled(repository)
        self.assertEqual(self.calls, 2)
        self.assertFalse(repository._transaction.attempted)
        self.assertFalse((self.root / ".git").exists())
        self.assertEqual(config.read_bytes(), changed[0])
        self.assertNotEqual(init.manifest(repository.candidate), repository._transaction.captured)
