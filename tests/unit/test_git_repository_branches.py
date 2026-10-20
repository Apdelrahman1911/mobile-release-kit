"""Passive branch tests: only synthetic private files and inert Git replies.

No subprocess, actual Git, user repository, native receipt, Store or credentials.
The existing small inert Git fixture supplies unchanged observation responses;
the added fake models only fixed list/CAS replies, never native finality.
"""
from contextlib import ExitStack
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from mobile_release import git_repository_branches as branches
from mobile_release import git_repository_local as local
from mobile_release import git_service as core
from mobile_release.owned_process import ProcessCleanupError
import test_git_repository_local as fixture


class FakeBranches(fixture.FakeGit):
    def __init__(self, root):
        super().__init__(root)
        self.config.update({"user.name": (b"Fixture Name",), "user.email": (b"fixture@example.invalid",),
                            "core.logallrefupdates": (b"true",)})
        self.list_body = None

    def __call__(self, argv, **kwargs):
        marker = "--work-tree=" + str(self.root)
        args = argv[argv.index(marker) + 1:]
        if args != list(branches._LIST) and args[0] != "update-ref":
            return super().__call__(argv, **kwargs)
        directory = Path(next(value[10:] for value in argv if value.startswith("--git-dir=")))
        index = Path(kwargs["environ"]["GIT_INDEX_FILE"])
        self.calls.append((tuple(args), directory, dict(kwargs["environ"])))
        if self.before is not None:
            self.before(args, directory, index)
        code, raw = 0, b""
        if args == list(branches._LIST):
            if self.list_body is not None:
                raw = self.list_body
            else:
                # All paths below are this test's finite private fake refs.
                selected = sorted((directory / "refs/heads").glob("*"))
                raw = b"".join((str(p.relative_to(directory)) + "\0" + p.read_text().strip() + "\0\0\n").encode()
                               for p in selected if p.is_file())
        else:
            assert directory == self.root / ".git" and args[:4] == ["update-ref", "--no-deref", "-m", branches._MESSAGE]
            assert (directory / "index.lock").exists() and (directory / "config.lock").exists()
            assert not (directory / "HEAD.lock").exists()
            assert args[6] == "0" * len(args[5])
            target = directory / args[4]
            if target.exists() or target.with_name(target.name + ".lock").exists():
                code = 1
            else:
                temporary = target.with_name(target.name + ".lock")
                temporary.write_bytes((args[5] + "\n").encode())
                os.replace(temporary, target)
                if self.config.get("core.logallrefupdates", (b"true",)) == (b"true",):
                    identity = kwargs["environ"]["GIT_COMMITTER_NAME"] + " <" + kwargs["environ"]["GIT_COMMITTER_EMAIL"] + ">"
                    raw_log = args[6] + " " + args[5] + " " + identity + " 1700000000 +0000\t" + branches._MESSAGE + "\n"
                    (directory / "logs" / args[4]).write_text(raw_log)
        if self.after is not None:
            self.after(args, directory, index)
        return subprocess.CompletedProcess(argv, code, raw, b"")


class BranchTests(unittest.TestCase):
    release_fixture_descriptors = fixture.LocalFacetTests.release_fixture_descriptors

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mrk-git-branches-data-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "project"
        for name in ("", ".git", ".git/objects", ".git/objects/info", ".git/objects/pack", ".git/refs",
                     ".git/refs/heads", ".git/logs", ".git/logs/refs", ".git/logs/refs/heads"):
            (self.root / name).mkdir(mode=0o700)
        self.write(".git/HEAD", b"ref: refs/heads/main\n")
        self.write(".git/config", b"[core]\nbare=false\nrepositoryformatversion=0\nlogAllRefUpdates=true\n"
                                  b"[user]\nname=Fixture Name\nemail=fixture@example.invalid\n")
        self.write(".git/refs/heads/main", (fixture.HEAD + "\n").encode())
        self.write(".git/index", fixture.OLD_INDEX)
        self.write("a.txt", b"inert dirty a\n")
        self.write("b.txt", b"inert staged b\n")
        self.fake = FakeBranches(self.root)
        self.repositories = []
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError("No real processes in passive branch tests")))
        original = tempfile.mkdtemp
        def scratch(**kwargs):
            kwargs.setdefault("dir", self.base)
            self.assertTrue(Path(kwargs["dir"]).is_relative_to(self.base))
            return original(**kwargs)
        stack.enter_context(patch.object(core.tempfile, "mkdtemp", side_effect=scratch))
        self.addCleanup(self.release_fixture_descriptors)

    def write(self, name, body):
        (self.root / name).write_bytes(body)

    def repo(self):
        repository = branches.GitBranchesRepository(self.root, git_executable=Path("/never-run/git"),
            work_end=time.monotonic() + 45, _run=self.fake)
        self.repositories.append(repository)
        return repository

    def prepared(self, name="next"):
        repository = self.repo()
        observed = repository.observe()
        catalog = repository.branches(expected_revision=observed.revision)
        review = repository.prepare_branch(name, expected_revision=observed.revision,
            expected_reference_revision=catalog.reference_revision)
        return repository, review, fixture.Owner(self.root, review.plan)

    def apply(self, repository, review, owner):
        return repository.apply_branch(review, owner, expected_digest=review.digest)

    def writes(self):
        return [row for row in self.fake.calls if row[0][0] in ("add", "commit-tree", "write-tree", "update-ref", "restore")]

    def refusal(self, reason, callback):
        with self.assertRaises(core.GitError) as error:
            callback()
        self.assertEqual(error.exception.reason, reason)

    def test_names_are_fixed_subset_and_never_options_or_generic_refs(self):
        for name in ("topic", "Feature/topic-1", "fix.v2"):
            self.assertEqual(branches.branch_name(name), name)
        for name in ("", "-m", "foo//bar", "foo..bar", "../main", "foo.lock", "foo/../bar", "foo@{bar", "a\\b", "x\n", "refs/" + "x" * 255):
            self.refusal("invalid-input", lambda: branches.branch_name(name))

    def test_bounded_catalog_omits_private_fields_and_checks_frozen_currentness(self):
        repository = self.repo()
        observed = repository.observe()
        catalog = repository.branches(expected_revision=observed.revision)
        self.assertEqual(catalog.branches, (branches.Branch(fixture.BRANCH, fixture.HEAD),))
        self.assertEqual(set(catalog.as_dict()), {"revision", "referenceRevision", "head", "branch", "branches", "basis"})
        self.assertEqual(catalog.as_dict()["basis"], "local-refs-no-fetch")
        self.assertNotIn("Fixture Name", repr(catalog.as_dict()))
        calls = [call for call in self.fake.calls if call[0] == branches._LIST]
        self.assertEqual(len(calls), 1)
        self.assertNotEqual(calls[0][1], self.root / ".git")
        self.assertEqual(self.writes(), [])

    def test_symbolic_malformed_unsorted_and_over_limit_catalog_refuse(self):
        cases = (b"refs/heads/main\0" + fixture.HEAD.encode() + b"\0refs/heads/other\0\n",
                 b"refs/heads/main\0bad\0\0\n",
                 b"bad-ref\0" + fixture.HEAD.encode() + b"\0\0\n")
        for raw in cases:
            with self.assertRaises(core.GitError):
                branches._rows(raw)
        raw = b"".join((f"refs/heads/b{i:03d}\0{fixture.HEAD}\0\0\n").encode() for i in range(257))
        self.refusal("limit", lambda: branches._rows(raw))
        self.refusal("response-invalid", lambda: branches._rows(raw.splitlines(keepends=True)[1] + raw.splitlines(keepends=True)[0]))

    def test_create_is_one_absent_cas_preserving_dirty_staged_config_head_and_index(self):
        repository, review, owner = self.prepared()
        before = {name: (self.root / name).read_bytes() for name in (".git/HEAD", ".git/index", ".git/config", "a.txt", "b.txt")}
        result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.settlement), ("succeeded", "settled"))
        self.assertEqual({name: (self.root / name).read_bytes() for name in before}, before)
        self.assertEqual((self.root / ".git/refs/heads/next").read_bytes(), (fixture.HEAD + "\n").encode())
        self.assertEqual(owner.intents, [result.intent])
        self.assertEqual(len(self.writes()), 1)
        self.assertEqual(self.writes()[0][0], ("update-ref", "--no-deref", "-m", branches._MESSAGE,
                                             "refs/heads/next", fixture.HEAD, "0" * 40))
        self.assertEqual(self.writes()[0][2]["GIT_COMMITTER_NAME"], "Fixture Name")
        self.assertIsNotNone(repository._transaction.branch_publication)
        self.assertFalse(repository._unknown or repository._retained or repository._active_sessions)
        self.assertTrue(repository._transaction.config_lock.closed)
        self.assertEqual(repository._transaction.locks, [])
        self.refusal("already-used", lambda: self.apply(repository, review, owner))

    def test_missing_or_ambiguous_local_identity_refuses_without_guessed_default(self):
        for key, value in (("user.name", ()), ("user.email", (b"one@example.invalid", b"two@example.invalid")),
                           ("user.name", (b" padded ",)),
                           ("committer.name", (b"Another identity",))):
            saved = self.fake.config.copy()
            self.fake.config[key] = value
            self.refusal("branch-identity-required", self.prepared)
            self.fake.config = saved
        self.assertEqual(self.writes(), [])

    def test_catalog_cannot_hide_current_branch_or_expose_obvious_token_name(self):
        repository = self.repo()
        observed = repository.observe()
        self.fake.list_body = b""
        self.refusal("response-invalid", lambda: repository.branches(expected_revision=observed.revision))
        inert_token_shape = "ghp_" + "notarealtokenfixture" * 2
        raw = ("refs/heads/" + inert_token_shape + "\0" + fixture.HEAD + "\0\0\n").encode()
        self.refusal("sensitive-content", lambda: branches._rows(raw))
        self.refusal("sensitive-content", lambda: branches.branch_name(inert_token_shape))

    def test_existing_prefix_case_names_and_missing_namespace_refuse(self):
        for name in ("main", "MAIN", "main/topic"):
            self.refusal("branch-exists", lambda: self.prepared(name))
        self.refusal("branch-parent-missing", lambda: self.prepared("new/topic"))
        self.assertEqual(self.writes(), [])

    def test_empty_target_namespace_is_never_removed_or_published_over(self):
        target = self.root / ".git/refs/heads/next"
        target.mkdir(mode=0o700)
        identity = core._identity(target.lstat())
        for name in ("next", "NEXT"):
            self.refusal("branch-exists", lambda: self.prepared(name))
        self.assertEqual(core._identity(target.lstat()), identity)
        self.assertEqual(self.writes(), [])
        target.rmdir()
        repository, review, owner = self.prepared()
        target.mkdir(mode=0o700)
        identity = core._identity(target.lstat())
        result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.reason), ("failed", "stale-observation"))
        self.assertEqual(core._identity(target.lstat()), identity)
        self.assertEqual(owner.intents, [])
        self.assertEqual(self.writes(), [])

    def test_required_hooks_filters_and_signing_never_execute(self):
        for key, value, reason in (("core.hookspath", b"not-an-executable", "required-hooks"),
                ("commit.gpgsign", b"true", "required-signing"), ("filter.lfs.process", b"never-run", "unsupported-filter")):
            self.fake.config[key] = (value,)
            self.refusal(reason, self.prepared)
            del self.fake.config[key]
        self.assertEqual(self.writes(), [])

    def test_unborn_refuses_and_detached_create_never_attaches_head(self):
        (self.root / ".git/refs/heads/main").unlink()
        self.refusal("unborn-head", self.prepared)
        self.write(".git/HEAD", (fixture.HEAD + "\n").encode())
        repository, review, owner = self.prepared()
        self.assertIsNone(review.plan._snapshot.public.branch)
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "succeeded")
        self.assertEqual((self.root / ".git/HEAD").read_bytes(), (fixture.HEAD + "\n").encode())

    def test_stale_reference_revision_and_foreign_index_at_ack_prevent_cas(self):
        repository, review, owner = self.prepared()
        owner.on_intent = lambda _: self.write(".git/index", b"foreign index")
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "recovery-required")
        self.assertEqual((self.root / ".git/index").read_bytes(), b"foreign index")
        self.assertEqual(self.writes(), [])
        self.write(".git/index", fixture.OLD_INDEX)
        repository, review, owner = self.prepared()
        self.write(".git/refs/heads/foreign", (fixture.OTHER + "\n").encode())
        result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.reason), ("failed", "stale-observation"))
        self.assertEqual(self.writes(), [])

    def test_stop_after_candidate_ack_prevents_publication(self):
        repository, review, owner = self.prepared()
        owner.on_intent = lambda _: setattr(owner, "stopped", True)
        result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.reason), ("recovery-required", "authorization"))
        self.assertEqual(self.writes(), [])
        self.assertFalse((self.root / ".git/refs/heads/next").exists())

    def test_last_moment_target_conflict_is_not_overwritten_or_retried(self):
        repository, review, owner = self.prepared()
        def before(args, _, __):
            if args[0] == "update-ref":
                self.write(".git/refs/heads/next", (fixture.OTHER + "\n").encode())
        self.fake.before = before
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "recovery-required")
        self.assertEqual((self.root / ".git/refs/heads/next").read_bytes(), (fixture.OTHER + "\n").encode())
        self.assertEqual(len(self.writes()), 1)
        self.assertIsNone(repository._transaction.branch_publication)

    def test_foreign_source_head_at_send_never_redirects_branch_or_adopts_success(self):
        repository, review, owner = self.prepared()
        def before(args, _, __):
            if args[0] == "update-ref":
                self.write(".git/HEAD", (fixture.OTHER + "\n").encode())
        self.fake.before = before
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "recovery-required")
        self.assertEqual((self.root / ".git/refs/heads/next").read_bytes(), (fixture.HEAD + "\n").encode())
        self.assertEqual((self.root / ".git/HEAD").read_bytes(), (fixture.OTHER + "\n").encode())
        self.assertIsNone(repository._transaction.branch_publication)

    def test_unknown_sent_cas_matching_ref_has_no_positive_receipt_or_retry(self):
        repository, review, owner = self.prepared()
        def after(args, _, __):
            if args[0] == "update-ref":
                raise ProcessCleanupError("synthetic lost return", dispatched=True)
        self.fake.after = after
        result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.settlement), ("unknown", "unknown"))
        self.assertTrue(repository._unknown)
        self.assertEqual(len(self.writes()), 1)
        self.assertIsNone(repository._transaction.branch_publication)
        self.assertEqual((self.root / ".git/refs/heads/next").read_bytes(), (fixture.HEAD + "\n").encode())

    def test_reflog_symlink_parent_and_unexpected_contents_never_adopt(self):
        parent = self.root / ".git/logs/refs/heads"
        parent.rmdir()
        outside = self.base / "private-test-target"
        outside.mkdir(mode=0o700)
        parent.symlink_to(outside, target_is_directory=True)
        self.refusal("unsupported-repository", self.prepared)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(self.writes(), [])
        parent.unlink(); parent.mkdir(mode=0o700)
        repository, review, owner = self.prepared()
        def after(args, _, __):
            if args[0] == "update-ref":
                self.write(".git/logs/refs/heads/next", b"unreviewed replacement log\n")
        self.fake.after = after
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "recovery-required")
        self.assertIsNone(repository._transaction.branch_publication)
