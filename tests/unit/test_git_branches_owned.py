"""PROPOSED four real-Git cases; Root must approve source before execution.

Only the previously approved nonroot public-source projection/private HOME and
TMPDIR recipe. Reuse original run_owned C/A/W, 120s/160calls per fixture, 5s per
command, one 45s Prepare+Apply. No native/Store qualification, user repository,
network/remotes, hooks, credentials or inherited test collections. Setup-only
Git branch/pack-refs/checkout calls below are fixed disposable fixture actions,
not additional product operations.
"""
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from mobile_release import git_repository_branches as branches
from mobile_release import git_service as core
import test_git_repository_read_owned as approved
import test_git_repository_local as passive


class OwnedBranchTests(unittest.TestCase):
    identity = staticmethod(approved.OwnedReadTests.identity)
    read_inventory = approved.OwnedReadTests.read_inventory
    remember_fixture = approved.OwnedReadTests.remember_fixture
    write_text = approved.OwnedReadTests.write_text
    git = approved.OwnedReadTests.git
    commit_text = approved.OwnedReadTests.commit_text

    def setUp(self):
        self.assertNotEqual(os.getuid(), 0, "Use only the reviewed nonroot fixture projection")
        self.case_returned = False
        self.race_oid = None
        self.create_calls = 0
        approved.OwnedReadTests.setUp(self)
        original = tempfile.mkdtemp
        def scratch(**kwargs):
            kwargs.setdefault("dir", self.base)
            self.assertTrue(Path(kwargs["dir"]).is_relative_to(self.base))
            return original(**kwargs)
        selected = patch.object(core.tempfile, "mkdtemp", side_effect=scratch)
        selected.start()
        self.addCleanup(selected.stop)
        self.git("config", "--local", "user.name", "Branch Fixture")
        self.git("config", "--local", "user.email", "fixture@example.invalid")

    def cleanup_fixture(self):
        if not self.case_returned:
            raise AssertionError("Nonpassing branch fixture preserved; inspect its original result")
        approved.OwnedReadTests.cleanup_fixture(self)

    def owned(self, argv, **options):
        primary_create = any(arg.startswith("--git-dir=") for arg in argv) and "update-ref" in argv
        if primary_create:
            self.create_calls += 1
            if self.race_oid is not None:
                # A separate, positively joined fixed fixture Git command
                # wins just before the product's single actual expected-zero
                # CAS. No overlapping helper, new deadline or timer owner.
                winner, self.race_oid = self.race_oid, None
                self.git("update-ref", "--no-deref", "refs/heads/next", winner, "0" * len(winner))
        return approved.OwnedReadTests.owned(self, argv, **options)

    def repo(self):
        repository = branches.GitBranchesRepository(self.root, git_executable=Path("/usr/bin/git"),
            work_end=min(self.end, time.monotonic() + 45), _run=self.owned)
        self.repositories.append(repository)
        return repository

    def closed(self, repository):
        self.assertFalse(repository._unknown or repository._retained or repository._active_sessions
                         or repository._retained_sessions)
        self.remember_fixture()

    def observed(self):
        observer = self.repo()
        observation = observer.observe()
        self.closed(observer)  # Complete distinct Observe before next action.
        reader = self.repo()
        catalog = reader.branches(expected_revision=observation.revision)
        self.closed(reader)  # Complete distinct branch read before Apply.
        return catalog

    def prepare_apply(self, catalog, *, race_oid=None):
        repository = self.repo()  # ONE unchanged 45s for fresh Prepare+Apply.
        started, calls = time.monotonic(), self.calls
        review = repository.prepare_branch("next", expected_revision=catalog.revision,
            expected_reference_revision=catalog.reference_revision)
        self.closed(repository)
        owner = passive.Owner(self.root, review.plan)  # Inert journal, NOT NativeUse.
        self.race_oid = race_oid
        result = repository.apply_branch(review, owner, expected_digest=review.digest)
        self.assertFalse(repository._unknown, "Actual original Git call did not settle")
        self.closed(repository)
        self.assertEqual(owner.intents, [result.intent])
        self.assertEqual(self.create_calls, 1)
        self.assertTrue(all(not (self.root / ".git" / leaf).exists() for leaf in ("HEAD.lock", "index.lock", "config.lock")))
        diagnostic = f"reason={result.reason}; calls={self.calls-calls}; elapsed={time.monotonic()-started:.3f}s"
        self.assertEqual(result.settlement, "settled", diagnostic)
        self.assertEqual(result.state, "recovery-required" if race_oid else "succeeded", diagnostic)
        return result, repository

    def test_real_list_includes_loose_and_packed_local_refs_only(self):
        self.commit_text("initial\n")
        self.git("branch", "packed-one")
        self.git("pack-refs", "--all", "--prune")
        self.git("branch", "loose-two")
        catalog = self.observed()
        self.assertEqual([row.ref for row in catalog.branches],
                         ["refs/heads/loose-two", "refs/heads/main", "refs/heads/packed-one"])
        self.assertTrue(all(row.oid == catalog.head for row in catalog.branches))
        self.assertEqual(catalog.branch, "refs/heads/main")
        self.assertEqual(catalog.as_dict()["basis"], "local-refs-no-fetch")
        self.assertEqual(self.create_calls, 0)
        self.case_returned = True

    def test_real_create_preserves_dirty_staged_index_head_config_and_worktree(self):
        self.commit_text("initial\n")
        self.write_text("selected.txt", "unstaged selected change\n")
        self.write_text("untracked.txt", "explicitly staged fixture change\n")
        self.git("add", "--", "untracked.txt")
        names = (".git/index", ".git/HEAD", ".git/config", "selected.txt", "untracked.txt")
        before = {name: (self.root / name).read_bytes() for name in names}
        catalog = self.observed()
        result, repository = self.prepare_apply(catalog)
        self.assertEqual({name: (self.root / name).read_bytes() for name in names}, before)
        self.assertEqual((self.root / ".git/refs/heads/next").read_bytes(), (catalog.head + "\n").encode())
        self.assertEqual(result.intent.candidate_ref_oid, catalog.head)
        self.assertIsNotNone(repository._transaction.branch_publication)
        self.case_returned = True

    def test_real_expected_absence_cas_preserves_separate_git_winner(self):
        self.commit_text("one\n")
        winner = self.git("rev-parse", "HEAD").strip().decode("ascii")
        self.commit_text("two\n")
        catalog = self.observed()
        self.assertNotEqual(winner, catalog.head)
        result, repository = self.prepare_apply(catalog, race_oid=winner)
        self.assertEqual((self.root / ".git/refs/heads/next").read_bytes(), (winner + "\n").encode())
        self.assertEqual((self.root / ".git/refs/heads/main").read_bytes(), (catalog.head + "\n").encode())
        self.assertEqual(result.intent.candidate_ref_oid, catalog.head)
        self.assertIsNone(repository._transaction.branch_publication)
        self.case_returned = True

    def test_real_unborn_refusal_then_detached_create_leaves_head_detached(self):
        unborn = self.observed()
        repository = self.repo()
        with self.assertRaises(branches.BranchError) as error:
            repository.prepare_branch("next", expected_revision=unborn.revision,
                expected_reference_revision=unborn.reference_revision)
        self.assertEqual(error.exception.reason, "unborn-head")
        self.closed(repository)
        self.assertEqual(self.create_calls, 0)
        self.commit_text("first commit\n")
        oid = self.git("rev-parse", "HEAD").strip().decode("ascii")
        self.git("checkout", "--detach", "--no-guess", oid)
        catalog = self.observed()
        self.assertIsNone(catalog.branch)
        self.prepare_apply(catalog)
        self.assertEqual((self.root / ".git/HEAD").read_bytes(), (oid + "\n").encode())
        self.assertEqual((self.root / ".git/refs/heads/next").read_bytes(), (oid + "\n").encode())
        self.case_returned = True
