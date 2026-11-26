"""PROPOSED exact four owned Git fixtures; DO NOT RUN before Root approval.

Reuse the reviewed nonroot public-source projection, original run_owned C/A/W,
0700 fixture/HOME/TMPDIR, fixed platform Git, no remotes/hooks/credentials. The
invocation selects umask022; production never changes the inherited mask.
Every fixture keeps the unchanged120s/160calls/5s ceilings, every action45s,
and the enclosing fail-fast run600s. Failed/unknown fixtures remain intact.
These are portable Git semantics, NOT native/Store/SourceBook qualification.
"""
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from mobile_release import git_repository_branches as branches
from mobile_release import git_repository_switch as switch
from mobile_release import git_service as core
import test_git_repository_read_owned as approved
import test_git_repository_local as passive


class OwnedSwitchTests(unittest.TestCase):
    identity = staticmethod(approved.OwnedReadTests.identity)
    read_inventory = approved.OwnedReadTests.read_inventory
    remember_fixture = approved.OwnedReadTests.remember_fixture
    write_text = approved.OwnedReadTests.write_text
    git = approved.OwnedReadTests.git
    commit_text = approved.OwnedReadTests.commit_text

    def setUp(self):
        self.assertNotEqual(os.getuid(), 0, "Only the reviewed nonroot projection may run these four cases")
        self.assertTrue(hasattr(branches, "_local_identity"), "Compose the exact reviewed one-file core hook first")
        self.case_returned = False
        self.checkout_calls = 0
        approved.OwnedReadTests.setUp(self)
        original = tempfile.mkdtemp
        def scratch(**kwargs):
            kwargs.setdefault("dir", self.base)
            self.assertTrue(Path(kwargs["dir"]).is_relative_to(self.base))
            return original(**kwargs)
        selected = patch.object(core.tempfile, "mkdtemp", side_effect=scratch)
        selected.start()
        self.addCleanup(selected.stop)
        self.git("config", "--local", "user.name", "Switch Fixture")
        self.git("config", "--local", "user.email", "fixture@example.invalid")

    def cleanup_fixture(self):
        if not self.case_returned:
            raise AssertionError("Nonpassing switch fixture preserved; inspect the original result")
        approved.OwnedReadTests.cleanup_fixture(self)

    def owned(self, argv, **options):
        if any(arg.startswith("--git-dir=") for arg in argv) and "switch" in argv:
            self.checkout_calls += 1
        return approved.OwnedReadTests.owned(self, argv, **options)

    def fixed_write(self, name, raw):
        self.assertIn(name, (".gitignore", "ignored.txt", ".git/refs/heads/next.lock"))
        with open(self.root / name, "xb") as stream:
            stream.write(raw)
        self.remember_fixture()

    def repo(self):
        repository = switch.GitSwitchRepository(self.root, git_executable=approved.GIT,
            work_end=min(self.end, time.monotonic() + 45), _run=self.owned)
        self.repositories.append(repository)
        return repository

    def closed(self, repository):
        self.assertFalse(repository._unknown or repository._retained or repository._active_sessions
                         or repository._retained_sessions, "Original operation did not positively retire")
        self.remember_fixture()

    def observed(self):
        observer = self.repo()
        observation = observer.observe()
        self.closed(observer)
        reader = self.repo()
        catalog = reader.branches(expected_revision=observation.revision)
        self.closed(reader)
        return catalog

    def prepared(self, catalog):
        repository = self.repo()  # One unchanged45s Prepare+fresh Apply, no reset.
        start, calls = time.monotonic(), self.calls
        review = repository.prepare_switch("next", expected_revision=catalog.revision,
            expected_reference_revision=catalog.reference_revision)
        self.closed(repository)
        return repository, review, start, calls

    def applied(self, prepared):
        repository, review, start, calls = prepared
        owner = passive.Owner(self.root, review.plan)  # Inert journal; never a NativeUse.
        result = repository.apply_switch(review, owner, expected_digest=review.digest)
        detail = f"reason={result.reason}; calls={self.calls-calls}; elapsed={time.monotonic()-start:.3f}s"
        self.assertEqual((result.state, result.settlement), ("succeeded", "settled"), detail)
        self.assertEqual(owner.intents, [result.intent])
        self.assertEqual(self.checkout_calls, 1)
        self.closed(repository)
        for name in ("HEAD.lock", "index.lock", "config.lock", "logs/HEAD.lock", "refs/heads/next.lock"):
            self.assertFalse((self.root / ".git" / name).exists())
        return result, repository

    def test_real_content_switch_preserves_ignored_and_untracked_bytes(self):
        self.fixed_write(".gitignore", b"ignored.txt\n")
        self.git("add", "--", ".gitignore")
        self.commit_text("before content\n")
        self.git("branch", "next")
        self.git("switch", "--no-guess", "--no-recurse-submodules", "--no-overwrite-ignore", "--", "next")
        self.commit_text("after content\n")
        target = self.git("rev-parse", "HEAD").strip().decode("ascii")
        self.git("switch", "--no-guess", "--no-recurse-submodules", "--no-overwrite-ignore", "--", "main")
        self.write_text("untracked.txt", "preserve unrelated untracked fixture\n")
        self.fixed_write("ignored.txt", b"preserve unrelated ignored fixture\n")
        preserved = {p: (self.root / p).read_bytes() for p in (".git/config", ".gitignore", "untracked.txt", "ignored.txt")}
        result, repository = self.applied(self.prepared(self.observed()))
        self.assertEqual((result.observation.head, result.observation.branch), (target, "refs/heads/next"))
        self.assertEqual((self.root / "selected.txt").read_bytes(), b"after content\n")
        self.assertEqual({p: (self.root / p).read_bytes() for p in preserved}, preserved)
        self.assertEqual([r.name for r in repository._transaction.metadata_returns], ["logs/HEAD", "HEAD", "index"])
        self.assertEqual(self.git("diff", "--no-ext-diff", "--no-textconv", "--name-only", "HEAD", "--"), b"")
        self.case_returned = True

    def test_real_dirty_and_staged_entries_refuse_without_checkout(self):
        self.commit_text("original\n")
        self.git("branch", "next")
        self.write_text("selected.txt", "uncommitted preserved bytes\n")
        for staged in (False, True):
            if staged:
                self.git("add", "--", "selected.txt")
            catalog = self.observed()
            before = {p: (self.root / p).read_bytes() for p in (".git/index", ".git/HEAD", "selected.txt")}
            repository = self.repo()
            with self.assertRaises(switch.SwitchError) as caught:
                repository.prepare_switch("next", expected_revision=catalog.revision,
                    expected_reference_revision=catalog.reference_revision)
            self.assertEqual(caught.exception.reason, "switch-dirty")
            self.closed(repository)
            self.assertEqual({p: (self.root / p).read_bytes() for p in before}, before)
        self.assertEqual(self.checkout_calls, 0)
        self.case_returned = True

    def test_real_stale_target_and_foreign_target_lock_never_checkout(self):
        self.commit_text("one\n")
        self.git("branch", "next")
        old = self.git("rev-parse", "HEAD").strip().decode("ascii")
        self.commit_text("two\n")
        catalog = self.observed()
        prepared = self.prepared(catalog)
        repository, review, _, _ = prepared
        self.git("update-ref", "--no-deref", "refs/heads/next", catalog.head, old)
        before = {p: (self.root / p).read_bytes() for p in (".git/index", ".git/HEAD", "selected.txt")}
        with self.assertRaises(core.GitError) as caught:
            repository.apply_switch(review, passive.Owner(self.root, review.plan), expected_digest=review.digest)
        self.assertEqual(caught.exception.reason, "stale-observation")
        self.closed(repository)
        prepared = self.prepared(self.observed())
        repository, review, _, _ = prepared
        self.fixed_write(".git/refs/heads/next.lock", b"foreign owned fixture lock\n")
        path = self.root / ".git/refs/heads/next.lock"
        original = self.identity(path.lstat())
        with self.assertRaises(core.GitError):
            repository.apply_switch(review, passive.Owner(self.root, review.plan), expected_digest=review.digest)
        self.closed(repository)
        self.assertEqual(self.identity(path.lstat()), original)
        self.assertEqual(path.read_bytes(), b"foreign owned fixture lock\n")
        self.assertEqual({p: (self.root / p).read_bytes() for p in before}, before)
        self.assertEqual(self.checkout_calls, 0)
        self.case_returned = True

    def test_real_same_tree_still_publishes_head_reflog_and_exact_candidate_index(self):
        self.commit_text("same tree\n")
        self.git("branch", "next")
        catalog = self.observed()
        prepared = self.prepared(catalog)
        self.assertEqual(prepared[1].plan.changed, ())
        prefix = (self.root / ".git/logs/HEAD").read_bytes()
        old_bytes = (self.root / ".git/index").read_bytes()
        with open(self.root / ".git/index", "rb") as old_index:
            old_identity = self.identity(os.fstat(old_index.fileno()))
            result, repository = self.applied(prepared)
            self.assertEqual(os.fstat(old_index.fileno()).st_ino, old_identity[1])
            self.assertEqual(os.fstat(old_index.fileno()).st_nlink, 0)
            self.assertEqual(old_index.read(), old_bytes)
        self.assertEqual((result.observation.head, result.observation.branch), (catalog.head, "refs/heads/next"))
        self.assertEqual((self.root / ".git/HEAD").read_bytes(), b"ref: refs/heads/next\n")
        raw = (self.root / ".git/logs/HEAD").read_bytes()
        self.assertTrue(raw.startswith(prefix))
        self.assertTrue(raw[len(prefix):].startswith((catalog.head + " " + catalog.head + " Switch Fixture <fixture@example.invalid> ").encode()))
        self.assertTrue(raw.endswith(b"\tMRK: switch to reviewed local branch\n"))
        self.assertEqual(core._digest((self.root / ".git/index").read_bytes()), result.intent.candidate_index)
        self.assertEqual([r.name for r in repository._transaction.metadata_returns], ["logs/HEAD", "HEAD", "index"])
        self.assertEqual(self.git("diff", "--no-ext-diff", "--no-textconv", "--name-only", "HEAD", "--"), b"")
        self.case_returned = True
