"""Passive local-facet tests: synthetic private files and inert Git responses.

No Git/native executable, real command owner, credentials, remote or user repo.
Popen is forbidden. The tiny Root-only core hook is projected into two actual
methods in memory; no worktree/shared source file is modified. Simulated unknown
process outcomes are not native lifetime evidence.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack
import difflib
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from mobile_release import git_repository_local as local
from mobile_release import git_repository_read as read
from mobile_release import git_service as core
from mobile_release.owned_process import ProcessCleanupError

HEAD, BLOB, OTHER, TREE, COMMIT = (str(n) * 40 for n in range(1, 6))
BRANCH = "refs/heads/main"
OLD_INDEX, CANDIDATE_INDEX = b"inert original index", b"inert selected candidate index"


def entries(*rows):
    return b"".join(f"100644 {oid} 0\t{path}\0".encode() for path, oid in sorted(rows))


def projected_hook():
    source = Path(core.__file__).read_text()
    anchor = "    @_session_boundary\n    def apply(self, plan: GitPlan, owner: MutationOwner) -> MutationResult:\n"
    factory = ("    def _index_transaction(self, session: _Session, current: _Snapshot) -> _IndexTransaction:\n"
               "        # Internal closed facets may strengthen publication checks; ordinary\n"
               "        # GitRepository behavior and its original transaction stay unchanged.\n"
               "        return _IndexTransaction(session, current)\n\n")
    old, new = "        transaction = _IndexTransaction(session, current)\n", "        transaction = self._index_transaction(session, current)\n"
    # Once Root applies the same hook, test the actual integrated method instead
    # of projecting a different implementation over it.
    if hasattr(core.GitRepository, "_index_transaction"):
        assert factory in source and new in source and old not in source
        return ExitStack()
    assert source.count(anchor) == source.count(old) == 1
    amended = source.replace(anchor, factory + anchor).replace(old, new)
    artifact = Path(__file__).resolve().parents[2] / "docs/git-local-core-hook-2026-10-19.patch"
    expected = "".join(difflib.unified_diff(source.splitlines(True), amended.splitlines(True),
        fromfile="a/src/mobile_release/git_service.py", tofile="b/src/mobile_release/git_service.py"))
    assert artifact.read_text() == expected
    tree = ast.parse(amended)
    definition = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "GitRepository")
    nodes = [node for node in definition.body if isinstance(node, ast.FunctionDef) and node.name in ("apply", "_index_transaction")]
    namespace = dict(vars(core))
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<exact-root-git-core-hook>", "exec"), namespace)
    stack = ExitStack()
    for name in ("apply", "_index_transaction"):
        stack.enter_context(patch.object(core.GitRepository, name, namespace[name], create=True))
    return stack


class FakeGit:
    def __init__(self, root: Path):
        self.root, self.calls = root, []
        self.config = {"core.repositoryformatversion": (b"0",), "core.bare": (b"false",)}
        self.original_entries = entries(("a.txt", BLOB), ("b.txt", OTHER))
        self.candidate_entries = entries(("a.txt", OTHER), ("b.txt", OTHER))
        self.status = b" M a.txt\0M  b.txt\0"
        self.post_status = b"M  a.txt\0M  b.txt\0"
        self.before = self.after = None
        self.blob = b"inert public fixture blob\n"

    def object(self, oid):
        parent = self.root / ".git/objects" / oid[:2]
        parent.mkdir(mode=0o700, exist_ok=True)
        (parent / oid[2:]).write_bytes(b"inert object, not Git data")

    @staticmethod
    def head(directory):
        raw = (directory / "HEAD").read_bytes()
        if raw.startswith(b"ref: "):
            branch = raw[5:].rstrip(b"\n").decode()
            path = directory / branch
            return branch, path.read_bytes().rstrip(b"\n").decode() if path.exists() else None
        return None, raw.rstrip(b"\n").decode()

    def __call__(self, argv, **kwargs):
        marker = "--work-tree=" + str(self.root)
        args = argv[argv.index(marker) + 1:]
        directory = Path(next(value[10:] for value in argv if value.startswith("--git-dir=")))
        index = Path(kwargs["environ"]["GIT_INDEX_FILE"]) if "GIT_INDEX_FILE" in kwargs["environ"] else None
        self.calls.append((tuple(args), directory, dict(kwargs["environ"])))
        if self.before is not None:
            self.before(args, directory, index)
        code, out = 0, b""
        if args[0] == "config":
            assert args == ["config", "--file", str(directory / read._CONFIG_FILE), "--no-includes", "--null", "--list"]
            out = b"".join(name.encode() + b"\n" + value + b"\0" for name, values in self.config.items() for value in values)
        elif args == ["--version"]:
            out = b"git version 2.49.0 (Apple Git-154)\n"
        elif args == ["rev-parse", "--shared-index-path"]:
            pass
        elif args[:2] == ["symbolic-ref", "--quiet"]:
            branch, _ = self.head(directory)
            code, out = (0, (branch + "\n").encode()) if args[2] == "HEAD" and branch else (1, b"")
        elif args == ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"]:
            _, head = self.head(directory)
            code, out = (0, (head + "\n").encode()) if head else (1, b"")
        elif args[:3] == ["show-ref", "--verify", "--quiet"]:
            code = 0 if (directory / args[3]).exists() else 1
        elif args == ["ls-files", "--stage", "-z"]:
            out = self.candidate_entries if index and index.exists() and index.read_bytes() == CANDIDATE_INDEX else self.original_entries
        elif args[0] == "status":
            published = index and index.exists() and index.read_bytes() == CANDIDATE_INDEX
            out = b"" if self.head(directory)[1] == COMMIT else self.post_status if published else self.status
        elif args[0] == "check-attr":
            out = b"".join(path.encode() + b"\0filter\0unspecified\0" for path in args[4:])
        elif args[:2] == ["cat-file", "blob"]:
            out = self.blob
        elif args[0] in ("add", "restore", "update-index"):
            assert index is not None and index != self.root / ".git/index"
            index.write_bytes(CANDIDATE_INDEX)
            if args[0] == "add":
                self.object(OTHER)
        elif args == ["write-tree"]:
            self.object(TREE)
            out = (TREE + "\n").encode()
        elif args[0] == "commit-tree":
            self.object(COMMIT)
            out = (COMMIT + "\n").encode()
        elif args[0] == "update-ref":
            assert directory == self.root / ".git" and args[:4] == ["update-ref", "--no-deref", "-m", local._REF_MESSAGE]
            path = directory / args[4]
            old = path.read_bytes().rstrip(b"\n").decode() if path.exists() else "0" * 40
            if old != args[6] or path.with_name(path.name + ".lock").exists():
                code = 1
            else:
                temporary = path.with_name(path.name + ".lock")
                temporary.write_bytes((args[5] + "\n").encode())
                os.replace(temporary, path)
        elif args[0] == "diff":
            out = b"diff --git a/a.txt b/a.txt\n-old\n+new\n"
        else:
            raise AssertionError("unexpected inert local command")
        if self.after is not None:
            self.after(args, directory, index)
        return subprocess.CompletedProcess(argv, code, out, b"")


class Owner:
    """An inert test delegate, NOT a NativeUse or original invocation."""
    operation_id = "inert-local-operation"

    def __init__(self, root, plan):
        self.expected = root, plan.action, plan._snapshot.public.revision
        self.intents, self.checks = [], 0
        self.stopped = False
        self.on_intent = None

    def check_current(self, root, action, revision):
        assert (root, action, revision) == self.expected
        self.checks += 1
        if self.stopped:
            raise core.GitError("authorization")

    def record_intent(self, intent):
        assert not self.intents
        self.intents.append(intent)
        if self.on_intent is not None:
            self.on_intent(intent)


class LocalFacetTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mrk-git-local-data-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "project"
        for name in ("", ".git", ".git/objects", ".git/objects/info", ".git/objects/pack", ".git/refs", ".git/refs/heads"):
            (self.root / name).mkdir(mode=0o700)
        self.write(".git/HEAD", b"ref: refs/heads/main\n")
        self.write(".git/config", b"[core]\nbare = false\nrepositoryformatversion = 0\n")
        self.write(".git/refs/heads/main", (HEAD + "\n").encode())
        self.write(".git/index", OLD_INDEX)
        self.write("a.txt", b"edited a\n")
        self.write("b.txt", b"staged by someone else\n")
        self.fake = FakeGit(self.root)
        self.repositories = []
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError("no process allowed in passive DATA tests")))
        stack.enter_context(projected_hook())
        original_mkdtemp = tempfile.mkdtemp
        def scratch(**kwargs):
            if "dir" not in kwargs:
                kwargs["dir"] = self.base
            assert Path(kwargs["dir"]).is_relative_to(self.base)
            return original_mkdtemp(**kwargs)
        stack.enter_context(patch.object(core.tempfile, "mkdtemp", side_effect=scratch))
        self.addCleanup(self.release_fixture_descriptors)

    def release_fixture_descriptors(self):
        # Test teardown ONLY: every process was inert. Release exact test FDs
        # retained for synthetic unknown outcomes, without changing any result
        # or claiming an actual producer settled. Never touch a foreign FD.
        for repository in self.repositories:
            transaction = repository._transaction
            if transaction is None:
                continue
            routes = [*transaction.locks, *transaction.uncertain_closes]
            lock = transaction.config_lock
            if lock.fd is not None and not lock.closed and lock.identity is not None:
                routes.append((lock.path, lock.fd, lock.identity))
            for _, fd, expected in routes:
                try:
                    actual = core._identity(os.fstat(fd))
                except OSError:
                    continue
                if actual[:2] == expected[:2]:
                    os.close(fd)

    def write(self, path, value):
        (self.root / path).write_bytes(value)

    def repo(self):
        repository = local.GitLocalRepository(self.root, git_executable=Path("/never-executed/git"),
            work_end=time.monotonic() + 45, _run=self.fake)
        self.repositories.append(repository)
        return repository

    def prepared(self, action="stage", paths=("a.txt",)):
        repository = self.repo()
        observed = repository.observe()
        if action == "commit":
            review = repository.prepare_local(action, expected_revision=observed.revision,
                message="Review all staged changes", identity=core.CommitIdentity("Fixture Author", "fixture@example.invalid"))
        else:
            review = repository.prepare_local(action, expected_revision=observed.revision, paths=paths)
        return repository, review, Owner(self.root, review.plan)

    def apply(self, repository, review, owner):
        return repository.apply_review(review, owner, expected_digest=review.digest)

    def refused(self, reason, callback):
        with self.assertRaises(core.GitError) as error:
            callback()
        self.assertEqual(error.exception.reason, reason)

    def writes(self):
        return [row[0] for row in self.fake.calls if row[0][0] in ("add", "restore", "update-index", "write-tree", "commit-tree", "update-ref")]

    def test_resolved_head_reuses_no_commands_only_in_same_checked_session(self):
        repository = self.repo()
        session = repository._session()
        self.assertIsNone(session._resolved_head)
        before = len(self.fake.calls)
        self.assertEqual(session.head(), (HEAD, BRANCH))
        self.assertEqual(len(self.fake.calls) - before, 3)
        before = len(self.fake.calls)
        with patch.object(session, "check_original", wraps=session.check_original) as originals, \
                patch.object(session, "guard_current", wraps=session.guard_current) as current, \
                patch.object(session, "_check_frozen", wraps=session._check_frozen) as frozen:
            self.assertEqual(session.head(), (HEAD, BRANCH))
        self.assertEqual((originals.call_count, current.call_count, frozen.call_count), (2, 2, 2))
        self.assertEqual(len(self.fake.calls), before)
        self.assertTrue(repository._finish_sessions(False))
        before = len(self.fake.calls)
        self.refused("already-used", session.head)
        self.assertEqual(len(self.fake.calls), before)
        successor_session = repository._session()
        self.assertIsNone(successor_session._resolved_head)
        before = len(self.fake.calls)
        self.assertEqual(successor_session.head(), (HEAD, BRANCH))
        self.assertEqual(len(self.fake.calls) - before, 3)
        self.assertTrue(repository._finish_sessions(False))

    def test_resolved_head_reuse_refuses_unknown_original_or_scratch_even_without_drift(self):
        for target in ("repository", "frozen"):
            with self.subTest(target=target):
                repository = self.repo()
                session = repository._session()
                self.assertEqual(session.head(), (HEAD, BRANCH))
                before = len(self.fake.calls)
                if target == "repository":
                    repository._unknown = True
                else:
                    session.frozen.unknown = True
                self.refused("unknown", session.head)
                self.assertEqual(len(self.fake.calls), before)
                self.assertEqual(session._resolved_head, (HEAD, BRANCH))
                self.assertFalse(repository._finish_sessions(True))

    def test_resolved_head_reuse_cannot_hide_actual_ref_drift_or_unborn_addition(self):
        for unborn in (False, True):
            with self.subTest(unborn=unborn):
                path = self.root / ".git/refs/heads/main"
                if unborn:
                    path.unlink()
                repository = self.repo()
                session = repository._session()
                expected = (None if unborn else HEAD, BRANCH)
                self.assertEqual(session.head(), expected)
                before = len(self.fake.calls)
                path.write_bytes((OTHER + "\n").encode())
                self.refused("stale-observation", session.head)
                self.assertEqual(len(self.fake.calls), before)
                self.assertEqual(session._resolved_head, expected)
                self.assertTrue(repository._finish_sessions(False))

    def test_resolved_head_reuse_checks_exact_frozen_files_and_directory_roster(self):
        for change in ("HEAD", BRANCH, "extra-file", "extra-directory"):
            with self.subTest(change=change):
                repository = self.repo()
                session = repository._session()
                self.assertEqual(session.head(), (HEAD, BRANCH))
                before = len(self.fake.calls)
                if change == "extra-directory":
                    (session.frozen.root / "refs/heads/foreign").mkdir(mode=0o700)
                else:
                    path = session.frozen.root / ("refs/heads/foreign" if change == "extra-file" else change)
                    path.write_bytes((OTHER + "\n").encode())
                self.refused("stale-observation", session.head)
                self.assertEqual(len(self.fake.calls), before)
                self.assertEqual(session._resolved_head, (HEAD, BRANCH))
                # Exact original scratch cleanup refuses the altered fixture.
                # All producers are inert; only test TemporaryDirectory later
                # removes this synthetic data, never as a settlement receipt.
                self.assertFalse(repository._finish_sessions(False))
                self.assertTrue(repository._unknown)

    def test_resolved_head_reuse_rechecks_original_mutation_owner_stop(self):
        repository, review, owner = self.prepared()
        session = repository._session()
        self.assertEqual(session.head(), (HEAD, BRANCH))
        repository._active_plan, repository._active_owner = review.plan, owner
        owner.stopped = True
        before = len(self.fake.calls)
        self.refused("authorization", session.head)
        self.assertEqual(len(self.fake.calls), before)
        self.assertTrue(repository._finish_sessions(False))

    def test_failed_head_resolution_never_populates_session_cache(self):
        repository = self.repo()
        session = repository._session()
        def after(args, _, __):
            if args == ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"]:
                raise core.GitError("command-failed")
        self.fake.after = after
        self.refused("command-failed", session.head)
        self.assertIsNone(session._resolved_head)
        self.assertTrue(repository._finish_sessions(False))

    def test_positive_cas_invalidates_cache_before_frozen_successor_then_resolves_once(self):
        self.fake.status = b"M  a.txt\0M  b.txt\0"
        repository, review, owner = self.prepared("commit")
        captured = []
        original = core._FrozenGitDirectory.write
        def write(frozen, name, body):
            transaction = repository._transaction
            if transaction is not None and name == BRANCH:
                self.assertIs(frozen, transaction.session.frozen)
                self.assertIsNone(transaction.session._resolved_head)
                captured.append(body)
            return original(frozen, name, body)
        def before(args, _, __):
            if args[0] == "update-ref":
                self.assertEqual(repository._transaction.session._resolved_head, (HEAD, BRANCH))
        self.fake.before = before
        with patch.object(core._FrozenGitDirectory, "write", write):
            result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.settlement), ("succeeded", "settled"))
        self.assertEqual(captured, [(COMMIT + "\n").encode()])
        self.assertEqual(repository._transaction.session._resolved_head, (COMMIT, BRANCH))
        cas = next(i for i, (args, _, __) in enumerate(self.fake.calls) if args[0] == "update-ref")
        resolutions = [args for args, _, __ in self.fake.calls[cas + 1:]
                       if args == ("rev-parse", "--verify", "--quiet", "HEAD^{commit}")]
        self.assertEqual(len(resolutions), 1)

    def test_stage_only_selected_path_preserves_unrelated_index_and_worktree(self):
        repository, review, owner = self.prepared()
        before = (self.root / "b.txt").read_bytes()
        result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.settlement), ("succeeded", "settled"))
        self.assertEqual(self.writes(), [("add", "--all", "--", "a.txt")])
        self.assertEqual((self.root / ".git/index").read_bytes(), CANDIDATE_INDEX)
        self.assertEqual((self.root / "b.txt").read_bytes(), before)
        self.assertEqual(core._entries(self.fake.original_entries)["b.txt"], core._entries(self.fake.candidate_entries)["b.txt"])
        self.assertEqual(result.intent, owner.intents[0])
        self.assertEqual(result.intent.candidate_index, hashlib.sha256(CANDIDATE_INDEX).hexdigest())
        publication = repository._transaction.index_publication
        self.assertIs(publication.intent, owner.intents[0])
        self.assertEqual(publication.original, review.plan._snapshot.index_stamp)
        self.assertEqual(publication.successor, core._read(self.root / ".git/index", core.MAX_INDEX_BYTES)[0])
        self.assertFalse(any((self.root / ".git" / name).exists() for name in ("config.lock", "index.lock", "HEAD.lock")))

    def test_unstage_is_exact_paths_and_immutable_expected_head(self):
        self.fake.candidate_entries = entries(("a.txt", BLOB), ("b.txt", BLOB))
        repository, review, owner = self.prepared("unstage", ("b.txt",))
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "succeeded")
        self.assertEqual(self.writes(), [("restore", "--staged", "--source=" + HEAD, "--", "b.txt")])

    def test_unborn_unstage_removes_only_selected_index_entry(self):
        (self.root / ".git/refs/heads/main").unlink()
        self.fake.candidate_entries = entries(("a.txt", BLOB))
        repository, review, owner = self.prepared("unstage", ("b.txt",))
        self.assertEqual(self.apply(repository, review, owner).state, "succeeded")
        self.assertEqual(self.writes(), [("update-index", "--force-remove", "--", "b.txt")])

    def test_commit_reviews_whole_staged_set_and_refreshes_only_positive_frozen_successor(self):
        self.fake.status = b"M  a.txt\0M  b.txt\0"
        repository, review, owner = self.prepared("commit")
        self.assertEqual(review.plan.paths, ("a.txt", "b.txt"))
        self.assertTrue(review.as_dict()["wholeIndex"])
        self.assertNotIn("Fixture Author", json.dumps(review.as_dict()))
        self.assertNotIn("Review all staged", json.dumps(review.as_dict()))
        result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.settlement), ("succeeded", "settled"))
        self.assertEqual((result.observation.head, result.observation.branch), (COMMIT, BRANCH))
        self.assertEqual((self.root / ".git/index").read_bytes(), OLD_INDEX)
        self.assertEqual(self.writes()[-1], ("update-ref", "--no-deref", "-m", local._REF_MESSAGE, BRANCH, COMMIT, HEAD))
        self.assertFalse(any(args[0] in ("add", "commit") for args in self.writes()))
        self.assertEqual(repository._transaction.session.successor.oid, COMMIT)

    def test_unborn_commit_uses_exact_zero_old_ref_without_detaching_head(self):
        (self.root / ".git/refs/heads/main").unlink()
        self.fake.status = b"A  a.txt\0A  b.txt\0"
        repository, review, owner = self.prepared("commit")
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "succeeded")
        self.assertEqual(self.writes()[-1][-1], "0" * 40)
        self.assertNotIn("-p", next(args for args in self.writes() if args[0] == "commit-tree"))
        self.assertEqual((self.root / ".git/HEAD").read_bytes(), b"ref: refs/heads/main\n")
        self.assertEqual(repository._transaction.session._resolved_head, (COMMIT, BRANCH))

    def test_mutation_command_config_is_frozen_except_locked_original_ref_cas(self):
        self.fake.status = b"M  a.txt\0M  b.txt\0"
        repository, review, owner = self.prepared("commit")
        seen = []
        def before(args, directory, _):
            if args[0] == "update-ref":
                seen.append((self.root / ".git/config.lock").exists())
                self.assertFalse((self.root / ".git/HEAD.lock").exists())
                self.assertTrue((self.root / ".git/index.lock").exists())
        self.fake.before = before
        self.assertEqual(self.apply(repository, review, owner).state, "succeeded")
        self.assertEqual(seen, [True])
        for args, directory, env in self.fake.calls:
            self.assertEqual(directory == self.root / ".git", args[0] == "update-ref")
            self.assertEqual(env["GIT_CONFIG_GLOBAL"], os.devnull)
            self.assertEqual(env["GIT_CONFIG_SYSTEM"], os.devnull)
            self.assertEqual(env["GIT_ALLOW_PROTOCOL"], "")
            self.assertNotIn("SSH_AUTH_SOCK", env)

    def test_required_hooks_signing_and_filters_never_execute_or_mutate(self):
        for key, value, action, reason in (("core.hookspath", b"/inert/hooks", "stage", "required-hooks"),
                ("commit.gpgsign", b"true", "commit", "required-signing"),
                ("filter.custom.clean", b"never-execute", "stage", "unsupported-filter")):
            with self.subTest(key=key):
                self.fake.config[key] = (value,)
                self.refused(reason, lambda: self.prepared(action))
                self.assertEqual(self.writes(), [])
                del self.fake.config[key]
        hooks = self.root / ".git/hooks"
        hooks.mkdir(mode=0o700)
        path = hooks / "pre-commit"
        path.write_bytes(b"inert fixture, no shebang")
        path.chmod(0o700)
        self.refused("required-hooks", self.prepared)
        self.assertEqual(self.writes(), [])

    def test_foreign_config_index_and_head_locks_preserved_without_candidate_write(self):
        for leaf in ("config.lock", "index.lock", "HEAD.lock"):
            with self.subTest(leaf=leaf):
                repository, review, owner = self.prepared()
                self.write(".git/" + leaf, b"foreign inert lock")
                result = self.apply(repository, review, owner)
                self.assertEqual(result.reason, "locked")
                self.assertEqual((self.root / ".git" / leaf).read_bytes(), b"foreign inert lock")
                self.assertEqual(self.writes(), [])
                (self.root / ".git" / leaf).unlink()

    def test_real_ref_drift_is_not_hidden_by_frozen_head(self):
        self.fake.status = b"M  a.txt\0M  b.txt\0"
        repository, review, owner = self.prepared("commit")
        def after(args, _, __):
            if args[0] == "commit-tree":
                self.write(".git/refs/heads/main", (OTHER + "\n").encode())
        self.fake.after = after
        result = self.apply(repository, review, owner)
        self.assertNotEqual(result.state, "succeeded")
        self.assertFalse(any(args[0] == "update-ref" for args in self.writes()))
        self.assertEqual((self.root / ".git/refs/heads/main").read_bytes(), (OTHER + "\n").encode())

    def test_expected_old_cas_refuses_last_moment_branch_drift_without_rollback(self):
        self.fake.status = b"M  a.txt\0M  b.txt\0"
        repository, review, owner = self.prepared("commit")
        def before(args, _, __):
            if args[0] == "update-ref":
                self.write(".git/refs/heads/main", (OTHER + "\n").encode())
        self.fake.before = before
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "recovery-required")
        self.assertEqual((self.root / ".git/refs/heads/main").read_bytes(), (OTHER + "\n").encode())
        self.assertEqual(sum(args[0] == "update-ref" for args in self.writes()), 1)
        self.assertIsNone(repository._transaction.session.successor)
        self.assertEqual(repository._transaction.session._resolved_head, (HEAD, BRANCH))

    def test_head_switch_after_lock_release_keeps_candidate_and_reports_recovery(self):
        self.fake.status = b"M  a.txt\0M  b.txt\0"
        repository, review, owner = self.prepared("commit")
        def before(args, _, __):
            if args[0] == "update-ref":
                self.assertFalse((self.root / ".git/HEAD.lock").exists())
                self.write(".git/HEAD", (OTHER + "\n").encode())
        self.fake.before = before
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "recovery-required")
        self.assertEqual(result.intent.candidate_commit, COMMIT)
        self.assertEqual((self.root / ".git/refs/heads/main").read_bytes(), (COMMIT + "\n").encode())
        self.assertEqual((self.root / ".git/HEAD").read_bytes(), (OTHER + "\n").encode())
        self.assertIsNone(repository._transaction.session.successor)

    def test_external_index_drift_at_ack_preserves_foreign_index(self):
        repository, review, owner = self.prepared()
        owner.on_intent = lambda _: self.write(".git/index", b"foreign new index")
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "recovery-required")
        self.assertEqual((self.root / ".git/index").read_bytes(), b"foreign new index")
        self.assertFalse(repository._transaction.published)

    def test_stop_after_ack_at_index_fsync_prevents_publication(self):
        repository, review, owner = self.prepared()
        original = os.fsync
        def sync(fd):
            original(fd)
            transaction = repository._transaction
            if transaction is not None and transaction.locks and transaction.locks[0][1] == fd:
                owner.stopped = True
        with patch.object(local.os, "fsync", side_effect=sync):
            result = self.apply(repository, review, owner)
        self.assertEqual(len(owner.intents), 1)
        self.assertEqual(result.state, "recovery-required")
        self.assertFalse(repository._transaction.published)
        self.assertEqual((self.root / ".git/index").read_bytes(), OLD_INDEX)

    def test_changed_private_candidate_during_ack_cannot_publish_other_bytes(self):
        repository, review, owner = self.prepared()
        owner.on_intent = lambda _: repository._transaction.index.write_bytes(b"not the acknowledged candidate")
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "recovery-required")
        self.assertFalse(repository._transaction.published)
        self.assertEqual((self.root / ".git/index").read_bytes(), OLD_INDEX)

    def test_unknown_sent_ref_cas_never_consumes_matching_readback_as_success_or_retries(self):
        self.fake.status = b"M  a.txt\0M  b.txt\0"
        repository, review, owner = self.prepared("commit")
        def after(args, _, __):
            if args[0] == "update-ref":
                raise ProcessCleanupError("synthetic lost original return", dispatched=True)
        self.fake.after = after
        result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.settlement), ("unknown", "unknown"))
        self.assertEqual((self.root / ".git/refs/heads/main").read_bytes(), (COMMIT + "\n").encode())
        self.assertIsNone(repository._transaction.session.successor)
        self.assertEqual(repository._transaction.session._resolved_head, (HEAD, BRANCH))
        count = len(self.fake.calls)
        self.refused("already-used", lambda: self.apply(repository, review, owner))
        self.assertEqual(len(self.fake.calls), count)

    def test_lost_ack_baseexception_stays_latched_and_never_publishes(self):
        repository, review, owner = self.prepared()
        original = KeyboardInterrupt("synthetic ACK return lost")
        def lost(_):
            raise original
        owner.on_intent = lost
        with self.assertRaises(KeyboardInterrupt) as error:
            self.apply(repository, review, owner)
        self.assertIs(error.exception, original)
        self.assertTrue(repository._unknown)
        self.assertFalse(repository._transaction.published)
        self.assertFalse(repository._active_owner.acknowledged)
        self.assertEqual((self.root / ".git/index").read_bytes(), OLD_INDEX)
        self.refused("already-used", lambda: self.apply(repository, review, owner))

    def test_fanout_symlink_or_foreign_replacement_refuses_before_candidate_write(self):
        repository, review, owner = self.prepared()
        (self.root / ".git/objects/33").symlink_to(self.base, target_is_directory=True)
        self.refused("unsupported-repository", lambda: self.apply(repository, review, owner))
        self.assertEqual(self.writes(), [])
        self.assertFalse((self.root / ".git/index.lock").exists())

    def test_positive_object_additions_never_allow_replacing_an_existing_fanout(self):
        self.fake.status = b"M  a.txt\0M  b.txt\0"
        self.fake.object(TREE)
        repository, review, owner = self.prepared("commit")
        def after(args, _, __):
            if args[0] == "write-tree":
                parent = self.root / ".git/objects/44"
                parent.rename(self.root / ".git/objects/moved-inert-parent")
                parent.mkdir(mode=0o700)
        self.fake.after = after
        result = self.apply(repository, review, owner)
        self.assertNotEqual(result.state, "succeeded")
        self.assertFalse(any(args[0] in ("commit-tree", "update-ref") for args in self.writes()))

    def test_ignored_unobserved_and_sensitive_stage_targets_refuse_without_effect(self):
        self.write("hidden.txt", b"not in returned status")
        self.refused("unsupported-path", lambda: self.prepared(paths=("hidden.txt",)))
        self.write(".env", b"fixture=value\n")
        self.fake.status += b"?? .env\0"
        self.refused("sensitive-content", lambda: self.prepared(paths=(".env",)))
        self.assertEqual(self.writes(), [])

    def test_missing_nested_unborn_ref_parent_refuses_before_candidate_write(self):
        self.write(".git/HEAD", b"ref: refs/heads/missing/branch\n")
        self.fake.status = b"A  a.txt\0A  b.txt\0"
        self.refused("unsupported-repository", lambda: self.prepared("commit"))
        self.assertEqual(self.writes(), [])

    def test_review_digest_binds_author_message_index_and_selected_metadata(self):
        repository, review, owner = self.prepared()
        self.refused("stale-observation", lambda: repository.apply_review(review, owner, expected_digest="a" * 64))
        self.assertFalse(repository._apply_entered)
        self.fake.status = b"M  a.txt\0M  b.txt\0"
        repository, review, owner = self.prepared("commit")
        review.plan._message += " changed"
        self.refused("invalid-input", lambda: self.apply(repository, review, owner))
        self.assertEqual(self.writes(), [])

    def test_unknown_config_close_is_one_attempt_and_retains_repository(self):
        repository, review, owner = self.prepared()
        close, seen = os.close, []
        def interrupted(fd):
            transaction = repository._transaction
            if transaction is not None and fd == transaction.config_lock.fd:
                seen.append(fd)
                close(fd)
                raise KeyboardInterrupt("synthetic close return lost")
            return close(fd)
        with patch.object(local.os, "close", side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.apply(repository, review, owner)
            self.assertFalse(repository._transaction.config_lock.close())
        self.assertEqual(len(seen), 1)
        self.assertTrue(repository._unknown)
        self.assertTrue(repository._transaction.config_lock.unknown)
        self.assertTrue(repository._retained)

    def test_returned_unknown_config_cleanup_cannot_be_reported_as_settled(self):
        repository, review, owner = self.prepared()
        close = local._ConfigLock.close
        def unknown(lock):
            close(lock)  # Real fixture FD is closed; only its receipt is lost.
            lock.closed, lock.unknown = False, True
            return False
        with patch.object(local._ConfigLock, "close", unknown):
            result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.settlement, result.reason), ("unknown", "unknown", "unknown"))
        self.assertTrue(repository._unknown)
        self.assertTrue(repository._retained_sessions)

    def test_rename_without_directory_fsync_return_has_no_positive_publication_receipt(self):
        repository, review, owner = self.prepared()
        original = os.fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("synthetic directory fsync failure")
            return original(fd)
        with patch.object(local.os, "fsync", side_effect=fail_directory):
            with self.assertRaises(OSError):
                self.apply(repository, review, owner)
        self.assertTrue(repository._transaction.published)  # Base flag is early.
        self.assertIsNone(repository._transaction.index_publication)
        self.assertTrue(repository._unknown)
        self.assertEqual((self.root / ".git/index").read_bytes(), CANDIDATE_INDEX)

    def test_closed_mutation_syntax_never_accepts_remote_reset_or_blanket_stage(self):
        repository, review, _ = self.prepared()
        session = local._LocalSession(repository)
        session.git_dir = self.root / ".git"
        session.frozen = type("FrozenData", (), {"root": self.base / "inert-view"})()
        for args in (["fetch"], ["push", "--force"], ["reset", "--hard"], ["add", "--all"],
                     ["commit", "--", "a.txt"], ["update-ref", "HEAD", COMMIT], ["config", "--global", "x", "y"]):
            with self.subTest(args=args):
                self.refused("invalid-input", lambda: session.command_spec(args))
        self.assertEqual(self.writes(), [])
