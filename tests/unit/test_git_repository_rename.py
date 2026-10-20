"""Synthetic private files + inert Git responses only; no Git process/native.

The fixed private commands are modeled, not executed. Real Git/ref-log and
installed SourceBook/Store/C/A/W behavior need Root's separate native batch.
"""
from contextlib import ExitStack
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from mobile_release import git_repository_rename as rename
from mobile_release import git_rename_transaction as tx
from mobile_release import git_service as core
from mobile_release.owned_process import ProcessCleanupError
import test_git_repository_branches as branch_fixture
import test_git_repository_local as fixture


class FakeRename(branch_fixture.FakeBranches):
    def __init__(self, root):
        super().__init__(root)
        self.config.update({"branch.main.remote": (b"origin",), "branch.main.merge": (b"refs/heads/main",),
                            "branch.main.rebase": (b"true",)})
        self.rename_calls = 0

    @staticmethod
    def atomic(path, raw):
        temporary = path.with_name(path.name + ".lock")
        with open(temporary, "xb") as target:
            target.write(raw)
        os.replace(temporary, path)

    def __call__(self, argv, **kwargs):
        args = argv[argv.index("--work-tree=" + str(self.root)) + 1:]
        special = args[0] == "branch" or args[0] == "config" and Path(args[2]).name == "rename-config"
        if not special:
            return super().__call__(argv, **kwargs)
        directory = Path(next(a[10:] for a in argv if a.startswith("--git-dir=")))
        index = Path(kwargs["environ"]["GIT_INDEX_FILE"])
        assert directory != self.root / ".git" and index != self.root / ".git/index"
        for name in ("index.lock", "HEAD.lock", "config.lock", "refs/heads/main.lock", "refs/heads/next.lock"):
            assert (self.root / ".git" / name).is_file(), name
        self.calls.append((tuple(args), directory, dict(kwargs["environ"])))
        if self.before:
            self.before(args, directory, index)
        out = b""
        if args[0] == "branch":
            assert args == ["branch", "-m", "--", "main", "next"]
            self.rename_calls += 1
            assert (directory / "refs/heads/main").read_bytes() == (fixture.HEAD + "\n").encode()
            os.rename(directory / "refs/heads/main", directory / "refs/heads/next")
            self.atomic(directory / "HEAD", b"ref: refs/heads/next\n")
            config = (directory / "config").read_bytes()
            self.atomic(directory / "config", config.replace(b'[branch "main"]\n', b'[branch "next"]\n'))
            old_log, new_log = directory / "logs/refs/heads/main", directory / "logs/refs/heads/next"
            if old_log.exists():
                os.rename(old_log, new_log)
                identity = kwargs["environ"]["GIT_COMMITTER_NAME"] + " <" + kwargs["environ"]["GIT_COMMITTER_EMAIL"] + ">"
                tail = (fixture.HEAD + " " + fixture.HEAD + " " + identity
                        + " 1700000000 +0000\tBranch: renamed refs/heads/main to refs/heads/next\n").encode()
                self.atomic(new_log, new_log.read_bytes() + tail)
                head_log = directory / "logs/HEAD"
                self.atomic(head_log, head_log.read_bytes() + tail)
        elif "--rename-section" in args:
            assert args == ["config", "--file", str(directory / "rename-config"), "--no-includes",
                            "--rename-section", "branch.main", "branch.next"]
            old = (directory / "rename-config").read_bytes()
            self.atomic(directory / "rename-config", old.replace(b'[branch "main"]\n', b'[branch "next"]\n'))
        else:
            assert args == ["config", "--file", str(directory / "rename-config"), "--no-includes", "--null", "--list"]
            result = rename.renamed_config(self.config, "main", "next")
            out = b"".join(key.encode() + b"\n" + value + b"\0" for key, values in result.items() for value in values)
        if self.after:
            self.after(args, directory, index)
        return subprocess.CompletedProcess(argv, 0, out, b"")


class RenameTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mrk-rename-inert-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "project"
        for name in ("", ".git", ".git/objects", ".git/objects/info", ".git/objects/pack", ".git/refs",
                     ".git/refs/heads", ".git/logs", ".git/logs/refs", ".git/logs/refs/heads"):
            (self.root / name).mkdir(mode=0o700)
        self.write(".git/HEAD", b"ref: refs/heads/main\n")
        self.config = (b"[core]\nbare=false\nrepositoryformatversion=0\nlogAllRefUpdates=true\n"
                       b"[user]\nname=Fixture Name\nemail=fixture@example.invalid\n"
                       b'# private settings/comments preserved\n[branch "main"]\nremote=origin\nmerge=refs/heads/main\nrebase=true\n')
        self.write(".git/config", self.config)
        self.write(".git/index", fixture.OLD_INDEX)
        self.write(".git/refs/heads/main", (fixture.HEAD + "\n").encode())
        self.write(".git/logs/refs/heads/main", b"private branch log prefix\n")
        self.write(".git/logs/HEAD", b"private HEAD log prefix\n")
        self.write("a.txt", b"inert dirty a\n")
        self.write("b.txt", b"inert staged b\n")
        self.fake = FakeRename(self.root)
        self.repositories = []
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError("No real process in passive rename tests")))
        original = tempfile.mkdtemp
        def scratch(**kwargs):
            kwargs.setdefault("dir", self.base)
            self.assertTrue(Path(kwargs["dir"]).is_relative_to(self.base))
            return original(**kwargs)
        stack.enter_context(patch.object(core.tempfile, "mkdtemp", side_effect=scratch))
        self.addCleanup(self.close_inert_descriptors)

    def close_inert_descriptors(self):
        # Test-only exact-FD disposal after all modeled commands returned. This
        # does not turn an unknown production result into known settlement.
        for repo in self.repositories:
            routes = []
            transaction = repo._transaction
            if transaction is not None:
                routes.extend(transaction.locks + transaction.uncertain_closes)
                locks = [transaction.config_lock, *transaction.log_locks.values()]
            else:
                locks = []
            if type(repo._ref_locks) is tx.RefLocks:
                locks.extend(repo._ref_locks.locks)
            for lock in locks:
                if lock.fd is not None and not lock.closed and lock.identity is not None:
                    routes.append((lock.path, lock.fd, lock.identity))
            for _, fd, expected in routes:
                try:
                    actual = core._identity(os.fstat(fd))
                except OSError:
                    continue
                if actual[:2] == expected[:2]:
                    os.close(fd)

    def write(self, name, raw):
        (self.root / name).write_bytes(raw)

    def repo(self):
        repo = rename.GitRenameRepository(self.root, git_executable=Path("/never-run/git"),
                                          work_end=time.monotonic() + 45, _run=self.fake)
        self.repositories.append(repo)
        return repo

    def prepared(self, name="next"):
        repo = self.repo()
        observed = repo.observe()
        listed = repo.branches(expected_revision=observed.revision)
        review = repo.prepare_rename(name, expected_revision=observed.revision,
                                    expected_reference_revision=listed.reference_revision)
        return repo, review, fixture.Owner(self.root, review.plan)

    def apply(self, repo, review, owner):
        return repo.apply_rename(review, owner, expected_digest=review.digest)

    def refusal(self, reason, callback):
        with self.assertRaises(core.GitError) as raised:
            callback()
        self.assertEqual(raised.exception.reason, reason)

    def test_one_private_candidate_exact_rename_preserves_dirty_index_config_upstream_logs(self):
        repo, review, owner = self.prepared()
        index, a, b = [(self.root / n).read_bytes() for n in (".git/index", "a.txt", "b.txt")]
        result = self.apply(repo, review, owner)
        self.assertEqual((result.state, result.settlement, result.reason), ("succeeded", "settled", None))
        self.assertEqual((result.observation.head, result.observation.branch), (fixture.HEAD, "refs/heads/next"))
        self.assertEqual([(self.root / n).read_bytes() for n in (".git/index", "a.txt", "b.txt")], [index, a, b])
        self.assertEqual((self.root / ".git/config").read_bytes(), self.config.replace(b'[branch "main"]', b'[branch "next"]'))
        self.assertFalse((self.root / ".git/refs/heads/main").exists())
        self.assertEqual((self.root / ".git/refs/heads/next").read_bytes(), (fixture.HEAD + "\n").encode())
        self.assertFalse((self.root / ".git/logs/refs/heads/main").exists())
        self.assertTrue((self.root / ".git/logs/refs/heads/next").read_bytes().startswith(b"private branch log prefix\n"))
        self.assertTrue((self.root / ".git/logs/HEAD").read_bytes().startswith(b"private HEAD log prefix\n"))
        self.assertEqual(self.fake.rename_calls, 1)
        self.assertEqual(owner.intents, [result.intent])
        self.assertEqual(tuple(row.step for row in repo._transaction.returns), rename.steps(review.plan))
        self.assertTrue(repo._ref_locks.closed)
        self.assertFalse(repo._unknown or repo._retained)
        self.assertNotIn("Fixture Name", repr(review.as_dict()))
        self.assertNotIn("private", repr(result.intent.as_dict()))
        self.refusal("already-used", lambda: self.apply(repo, review, owner))

    def test_missing_old_config_section_is_no_rewrite_not_ambiguous(self):
        self.fake.config = {k: v for k, v in self.fake.config.items() if not k.startswith("branch.")}
        raw = self.config.split(b'[branch "main"]')[0]
        self.write(".git/config", raw)
        before = (self.root / ".git/config").stat().st_ino
        repo, review, owner = self.prepared()
        self.assertFalse(review.as_dict()["configMoved"])
        result = self.apply(repo, review, owner)
        self.assertEqual(result.state, "succeeded")
        self.assertEqual((self.root / ".git/config").read_bytes(), raw)
        self.assertEqual((self.root / ".git/config").stat().st_ino, before)
        self.assertNotIn("config", [r.step for r in repo._transaction.returns])

    def test_disabled_absent_logs_and_missing_section_publish_only_ref_and_head(self):
        self.fake.config = {k: v for k, v in self.fake.config.items() if not k.startswith("branch.")}
        self.fake.config["core.logallrefupdates"] = (b"false",)
        raw = self.config.split(b'[branch "main"]')[0].replace(b"logAllRefUpdates=true", b"logAllRefUpdates=false")
        self.write(".git/config", raw)
        for name in (".git/logs/HEAD", ".git/logs/refs/heads/main"):
            (self.root / name).unlink()
        original_config = (self.root / ".git/config").stat().st_ino
        repo, review, owner = self.prepared()
        self.assertFalse(review.as_dict()["logging"] or review.as_dict()["configMoved"])
        result = self.apply(repo, review, owner)
        self.assertEqual(result.state, "succeeded")
        self.assertEqual([r.step for r in repo._transaction.returns], ["ref", "head"])
        self.assertEqual((self.root / ".git/config").read_bytes(), raw)
        self.assertEqual((self.root / ".git/config").stat().st_ino, original_config)
        self.assertEqual(list((self.root / ".git/logs/refs/heads").iterdir()), [])
        self.assertFalse((self.root / ".git/logs/HEAD").exists())
        self.assertEqual(result.intent.original_log, core._ABSENT.digest)
        self.assertEqual(result.intent.candidate_log, core._ABSENT.digest)

    def test_config_growth_and_oversized_log_refuse_before_private_candidate(self):
        prefix = b'[branch "main"]\n'
        raw = prefix + b"#" + b"x" * (rename.MAX_CONFIG - len(prefix) - 2) + b"\n"
        self.assertEqual(len(raw), rename.MAX_CONFIG)
        self.refusal("rename-config", lambda: rename.config_move(raw, {"branch.main.remote": (b"origin",)}, "main", "longer"))
        self.write(".git/logs/HEAD", b"x" * rename.MAX_LOG + b"\n")
        with self.assertRaises(core.GitError):
            self.prepared()
        self.assertEqual(self.fake.rename_calls, 0)

    def test_unexpected_private_git_change_cannot_be_accepted_or_published(self):
        repo, review, owner = self.prepared()
        def altered(args, directory, index):
            if args[0] == "branch":
                with open(directory / "config", "ab") as output:
                    output.write(b"# unreviewed private change\n")
        self.fake.after = altered
        result = self.apply(repo, review, owner)
        self.assertNotEqual(result.state, "succeeded")
        self.assertEqual(owner.intents, [])
        self.assertEqual(repo._transaction.returns, [])
        self.assertEqual((self.root / ".git/config").read_bytes(), self.config)
        self.assertEqual((self.root / ".git/HEAD").read_bytes(), b"ref: refs/heads/main\n")
        self.assertFalse((self.root / ".git/refs/heads/next").exists())
        self.assertEqual(self.fake.rename_calls, 1)
        self.refusal("already-used", lambda: self.apply(repo, review, owner))

    def test_config_duplicate_alias_legacy_destination_and_extra_changes_refuse(self):
        cases = [self.config + b'[branch "main"]\n', self.config + b'[branch "next"]\n',
                 self.config.replace(b'[branch "main"]', b'[branch "Main"]'),
                 self.config.replace(b'[branch "main"]', b'[branch.main]')]
        for raw in cases:
            with self.subTest(raw=raw[-40:]):
                self.write(".git/config", raw)
                with self.assertRaises(core.GitError):
                    self.prepared()
        self.assertEqual(self.fake.rename_calls, 0)

    def test_target_existing_file_empty_dir_and_case_alias_refuse_before_candidates(self):
        for name, kind in (("next", "file"), ("next", "dir"), ("NEXT", "dir")):
            path = self.root / ".git/refs/heads" / name
            if kind == "file":
                path.write_bytes((fixture.HEAD + "\n").encode())
            else:
                path.mkdir(mode=0o700)
            self.refusal("rename-target", self.prepared)
            path.unlink() if kind == "file" else path.rmdir()
        self.assertEqual(self.fake.rename_calls, 0)

    def test_detached_packed_shadow_other_parent_and_missing_log_are_not_supported(self):
        self.write(".git/packed-refs", ("# pack-refs with: peeled\n" + fixture.HEAD + " refs/heads/main\n").encode())
        self.refusal("rename-packed", self.prepared)
        (self.root / ".git/packed-refs").unlink()
        self.refusal("rename-target", lambda: self.prepared("topic/next"))
        self.write(".git/HEAD", (fixture.HEAD + "\n").encode())
        self.refusal("rename-layout", self.prepared)
        self.write(".git/HEAD", b"ref: refs/heads/main\n")
        (self.root / ".git/logs/HEAD").unlink()
        self.refusal("rename-log", self.prepared)
        (self.root / ".git/logs/refs/heads/main").unlink()
        self.refusal("rename-log-missing", self.prepared)

    def test_stale_before_apply_and_stop_before_candidate_ack_never_publish(self):
        repo, review, owner = self.prepared()
        self.write(".git/config", self.config + b"# intervening edit\n")
        self.refusal("stale-observation", lambda: self.apply(repo, review, owner))
        self.assertEqual(owner.intents, [])
        self.assertEqual(self.fake.rename_calls, 0)
        self.write(".git/config", self.config)
        repo, review, owner = self.prepared()
        owner.stopped = True
        result = self.apply(repo, review, owner)
        self.assertEqual(result.state, "failed")
        self.assertEqual(owner.intents, [])
        self.assertEqual((self.root / ".git/HEAD").read_bytes(), b"ref: refs/heads/main\n")

    def test_ack_stop_and_lost_ack_never_publish_or_replay(self):
        repo, review, owner = self.prepared()
        owner.on_intent = lambda _: setattr(owner, "stopped", True)
        result = self.apply(repo, review, owner)
        self.assertNotEqual(result.state, "succeeded")
        self.assertEqual(repo._transaction.returns, [])
        self.assertEqual(len(owner.intents), 1)
        self.assertEqual((self.root / ".git/HEAD").read_bytes(), b"ref: refs/heads/main\n")
        self.refusal("already-used", lambda: self.apply(repo, review, owner))

    def test_foreign_destination_at_publication_is_preserved_and_not_retried(self):
        repo, review, owner = self.prepared()
        original = tx.RenameTransaction.publish
        def race(transaction, step):
            if step == "ref":
                self.write(".git/refs/heads/next", b"foreign contents\n")
            return original(transaction, step)
        with patch.object(tx.RenameTransaction, "publish", race):
            result = self.apply(repo, review, owner)
        self.assertNotEqual(result.state, "succeeded")
        self.assertEqual((self.root / ".git/refs/heads/next").read_bytes(), b"foreign contents\n")
        self.assertTrue((self.root / ".git/refs/heads/main").exists())
        self.assertEqual(self.fake.rename_calls, 1)

    def test_partial_positive_ref_then_stop_retains_exact_prefix_no_rollback(self):
        repo, review, owner = self.prepared()
        original = tx.RenameTransaction.publish
        def stop(transaction, step):
            value = original(transaction, step)
            if step == "ref":
                owner.stopped = True
            return value
        with patch.object(tx.RenameTransaction, "publish", stop):
            result = self.apply(repo, review, owner)
        self.assertNotEqual(result.state, "succeeded")
        self.assertEqual([row.step for row in repo._transaction.returns], ["new-log", "old-log", "ref"])
        self.assertEqual((self.root / ".git/HEAD").read_bytes(), b"ref: refs/heads/main\n")
        self.assertFalse((self.root / ".git/refs/heads/main").exists())
        self.assertEqual((self.root / ".git/refs/heads/next").read_bytes(), (fixture.HEAD + "\n").encode())
        self.assertTrue(repo._retained)


if __name__ == "__main__":
    unittest.main()
