"""PROPOSED real local Git fixtures. Execute only after Root source approval.

Reuses the already inspected disposable GitRead fixture's fixed /usr/bin/git,
private repo/HOME/config, original run_owned C/A/W, <=160 calls/120s per fixture,
<=5s each call, and exact finite cleanup. No user repo, remotes, credentials,
hooks, network, install, native source admission or installed Mac qualification.

The MutationOwner here is explicitly an inert test journal/currentness delegate,
NOT a native publisher/Store authority. Only actual Git/C/A/W semantics are tested.
The sole Root core hook is projected in memory until integrated, never on disk.
"""
from __future__ import annotations

from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from mobile_release import git_repository_local as local
from mobile_release import git_service as core
import test_git_repository_read_owned as approved_fixture
import test_git_repository_local as passive_fixture


class OwnedLocalTests(unittest.TestCase):
    # Reuse only fixture helpers, not inherited/imported TestCase collections.
    # Running this module cannot accidentally rerun the older read suite.
    cleanup_fixture = approved_fixture.OwnedReadTests.cleanup_fixture
    identity = staticmethod(approved_fixture.OwnedReadTests.identity)
    read_inventory = approved_fixture.OwnedReadTests.read_inventory
    remember_fixture = approved_fixture.OwnedReadTests.remember_fixture
    write_text = approved_fixture.OwnedReadTests.write_text
    owned = approved_fixture.OwnedReadTests.owned
    git = approved_fixture.OwnedReadTests.git

    def setUp(self):
        hook = passive_fixture.projected_hook()
        self.addCleanup(hook.close)
        approved_fixture.OwnedReadTests.setUp(self)
        original = tempfile.mkdtemp
        def scratch(**kwargs):
            if "dir" not in kwargs:
                kwargs["dir"] = self.base
            self.assertTrue(Path(kwargs["dir"]).is_relative_to(self.base))
            return original(**kwargs)
        scratch_patch = patch.object(core.tempfile, "mkdtemp", side_effect=scratch)
        scratch_patch.start()
        self.addCleanup(scratch_patch.stop)

    def initial_commit(self):
        self.write_text("selected.txt", "initial selected\n")
        self.write_text("untracked.txt", "initial second\n")
        self.git("add", "--", "selected.txt", "untracked.txt")
        self.git("commit", "--no-gpg-sign", "-m", "Inert local fixture initial commit")

    def local_apply(self, action, paths=()):
        repository = local.GitLocalRepository(self.root, git_executable=Path("/usr/bin/git"),
            work_end=min(self.end, time.monotonic() + 45), _run=self.owned)
        self.repositories.append(repository)
        observed = repository.observe()
        self.remember_fixture()  # Original read/scratch close returned.
        kwargs = {"paths": paths}
        if action == "commit":
            kwargs.update(message="Reviewed complete staged set", identity=core.CommitIdentity("Local Fixture", "fixture@example.invalid"))
        review = repository.prepare_local(action, expected_revision=observed.revision, **kwargs)
        self.remember_fixture()  # Real prepare and all its original commands returned.
        owner = passive_fixture.Owner(self.root, review.plan)
        result = repository.apply_review(review, owner, expected_digest=review.digest)
        self.assertEqual((result.state, result.settlement), ("succeeded", "settled"))
        self.assertFalse(repository._unknown)
        self.assertFalse(repository._retained)
        self.remember_fixture()  # Positive real apply + exact known cleanup only.
        self.assertEqual(owner.intents, [result.intent])
        self.assertFalse(any((self.root / ".git" / leaf).exists() for leaf in ("index.lock", "HEAD.lock", "config.lock")))
        return review, result

    def test_real_selected_stage_preserves_other_staged_entry_and_worktree(self):
        self.initial_commit()
        self.write_text("selected.txt", "selected change\n")
        self.write_text("untracked.txt", "staged outside MRK\n")
        self.git("add", "--", "untracked.txt")
        unrelated = self.git("ls-files", "--stage", "--", "untracked.txt")
        self.local_apply("stage", ("selected.txt",))
        self.assertEqual(self.git("ls-files", "--stage", "--", "untracked.txt"), unrelated)
        self.assertEqual((self.root / "untracked.txt").read_text(), "staged outside MRK\n")
        self.assertEqual(self.git("diff", "--cached", "--no-ext-diff", "--no-textconv", "--name-only", "--"),
                         b"selected.txt\nuntracked.txt\n")

    def test_real_selected_unstage_preserves_other_staged_entry(self):
        self.initial_commit()
        self.write_text("selected.txt", "selected change\n")
        self.write_text("untracked.txt", "staged outside MRK\n")
        self.git("add", "--", "selected.txt", "untracked.txt")
        unrelated = self.git("ls-files", "--stage", "--", "untracked.txt")
        self.local_apply("unstage", ("selected.txt",))
        self.assertEqual(self.git("ls-files", "--stage", "--", "untracked.txt"), unrelated)
        self.assertEqual(self.git("diff", "--cached", "--no-ext-diff", "--no-textconv", "--name-only", "--"), b"untracked.txt\n")
        self.assertEqual((self.root / "selected.txt").read_text(), "selected change\n")

    def test_real_attached_commit_includes_whole_reviewed_index_without_replacing_it(self):
        self.initial_commit()
        old_head = self.git("rev-parse", "HEAD").strip().decode()
        self.write_text("selected.txt", "selected change\n")
        self.write_text("untracked.txt", "staged outside MRK\n")
        self.git("add", "--", "selected.txt", "untracked.txt")
        old_index = (self.root / ".git/index").read_bytes()
        review, result = self.local_apply("commit")
        self.assertEqual(review.plan.paths, ("selected.txt", "untracked.txt"))
        self.assertEqual((self.root / ".git/index").read_bytes(), old_index)
        self.assertEqual(self.git("rev-list", "--parents", "--max-count=1", "HEAD").strip().decode().split(),
                         [result.intent.candidate_commit, old_head])
        self.assertEqual(self.git("diff", "--cached", "--no-ext-diff", "--no-textconv", "--name-only", "--"), b"")

    def test_real_unborn_commit_keeps_symbolic_head_and_has_no_parent(self):
        self.write_text("selected.txt", "initial selected\n")
        self.write_text("untracked.txt", "initial second\n")
        self.git("add", "--", "selected.txt", "untracked.txt")
        review, result = self.local_apply("commit")
        self.assertIsNone(review.plan._snapshot.public.head)
        self.assertEqual(review.plan.paths, ("selected.txt", "untracked.txt"))
        self.assertEqual(self.git("symbolic-ref", "--quiet", "HEAD"), b"refs/heads/main\n")
        self.assertEqual(self.git("rev-list", "--parents", "--max-count=1", "HEAD").strip().decode(), result.intent.candidate_commit)

