"""Three Root-approved real-Git fixtures; source review precedes execution.

Reuse the existing nonroot public-source projection and OwnedReadTests helpers,
not its test collection. Actual run_owned C/A/W, fixed platform Git, private
0700 HOME/TMPDIR, umask022, 120s/160calls/5s ceilings, one45s Prepare+Apply and
the existing600s fail-fast outer bound. No user repository, network, credential,
hook or native/Store authority. Failed/unknown fixtures remain intact.

Only MutationOwner is inert: its ACK exercises portable transaction ordering,
not durable native journal admission or installed SourceBook finality.
"""
from contextlib import ExitStack
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from mobile_release import git_repository_rename as rename
from mobile_release import git_service as core
import test_git_repository_read_owned as approved
import test_git_repository_local as passive


class OwnedRenameTests(unittest.TestCase):
    identity = staticmethod(approved.OwnedReadTests.identity)
    read_inventory = approved.OwnedReadTests.read_inventory
    remember_fixture = approved.OwnedReadTests.remember_fixture
    write_text = approved.OwnedReadTests.write_text
    git = approved.OwnedReadTests.git
    commit_text = approved.OwnedReadTests.commit_text

    def setUp(self):
        self.assertNotEqual(os.getuid(), 0, "Only the approved nonroot projection may run these fixtures")
        self.case_returned = False
        self.private_commands = []
        approved.OwnedReadTests.setUp(self)
        original = tempfile.mkdtemp

        def scratch(**kwargs):
            kwargs.setdefault("dir", self.base)
            self.assertTrue(Path(kwargs["dir"]).is_relative_to(self.base))
            return original(**kwargs)

        selected = patch.object(core.tempfile, "mkdtemp", side_effect=scratch)
        selected.start()
        self.addCleanup(selected.stop)
        self.git("config", "--local", "user.name", "Rename Fixture")
        self.git("config", "--local", "user.email", "fixture@example.invalid")

    def cleanup_fixture(self):
        if not self.case_returned:
            raise AssertionError("Nonpassing rename fixture preserved; inspect its original result")
        approved.OwnedReadTests.cleanup_fixture(self)

    def owned(self, argv, **options):
        # Observe only the fixed production candidate commands, forwarding the
        # SAME argv/environment to the actual unchanged process owner below.
        marker = "--work-tree=" + str(self.root)
        args = argv[argv.index(marker) + 1:] if marker in argv else []
        candidate = bool(args and (args[0] == "branch" or args[0] == "config"
                         and len(args) > 2 and Path(args[2]).name == "rename-config"))
        if candidate:
            private = Path(next(arg[10:] for arg in argv if arg.startswith("--git-dir=")))
            index = Path(options["environ"]["GIT_INDEX_FILE"])
            self.assertNotEqual(private, self.root / ".git")
            self.assertNotEqual(index, self.root / ".git/index")
            self.assertTrue(private.is_relative_to(self.base) and index.is_relative_to(self.base))
            for leaf in ("HEAD.lock", "index.lock", "config.lock", "refs/heads/main.lock", "refs/heads/next.lock"):
                self.assertTrue((self.root / ".git" / leaf).is_file(), leaf)
            self.assertEqual((self.root / ".git/HEAD").read_bytes(), b"ref: refs/heads/main\n")
            self.assertTrue((self.root / ".git/refs/heads/main").is_file())
            self.assertFalse((self.root / ".git/refs/heads/next").exists())
            if args[0] == "branch":
                self.assertEqual(args, ["branch", "-m", "--", "main", "next"])
                self.assertEqual(options["environ"]["GIT_COMMITTER_NAME"], "Rename Fixture")
                self.assertEqual(options["environ"]["GIT_COMMITTER_EMAIL"], "fixture@example.invalid")
                name = "branch"
            elif "--rename-section" in args:
                self.assertEqual(args, ["config", "--file", str(private / "rename-config"), "--no-includes",
                                        "--rename-section", "branch.main", "branch.next"])
                name = "config"
            else:
                self.assertEqual(args, ["config", "--file", str(private / "rename-config"), "--no-includes", "--null", "--list"])
                name = "verify"
            self.private_commands.append(name)  # Count sends, not inferred success.
        return approved.OwnedReadTests.owned(self, argv, **options)

    def repo(self):
        repository = rename.GitRenameRepository(self.root, git_executable=approved.GIT,
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
        catalogue = reader.branches(expected_revision=observation.revision)
        self.closed(reader)
        return catalogue

    def prepared(self, catalogue):
        repository = self.repo()  # No renewal between this Prepare and Apply.
        started, calls = time.monotonic(), self.calls
        review = repository.prepare_rename("next", expected_revision=catalogue.revision,
            expected_reference_revision=catalogue.reference_revision)
        self.closed(repository)
        return repository, review, started, calls

    def applied(self, prepared):
        repository, review, started, calls = prepared
        owner = passive.Owner(self.root, review.plan)  # Explicitly inert journal.
        result = repository.apply_rename(review, owner, expected_digest=review.digest)
        detail = f"reason={result.reason}; calls={self.calls-calls}; elapsed={time.monotonic()-started:.3f}s"
        self.assertEqual((result.state, result.settlement), ("succeeded", "settled"), detail)
        self.assertEqual(owner.intents, [result.intent])
        self.closed(repository)
        self.assertTrue(repository._ref_locks.closed)
        for leaf in ("HEAD.lock", "index.lock", "config.lock", "refs/heads/main.lock", "refs/heads/next.lock",
                     "logs/refs/heads/next.lock", "logs/HEAD.lock"):
            self.assertFalse((self.root / ".git" / leaf).exists(), leaf)
        sent = self.calls
        with self.assertRaises(core.GitError) as error:
            repository.apply_rename(review, owner, expected_digest=review.digest)
        self.assertEqual(error.exception.reason, "already-used")
        self.assertEqual(self.calls, sent)
        self.closed(repository)
        return result, repository

    def test_real_private_rename_preserves_dirty_index_upstream_and_original_fds(self):
        self.commit_text("initial\n")
        self.git("branch", "upstream")
        self.git("config", "--local", "branch.main.remote", ".")
        self.git("config", "--local", "branch.main.merge", "refs/heads/upstream")
        self.git("config", "--local", "branch.main.rebase", "true")
        self.write_text("selected.txt", "unstaged preserved change\n")
        self.write_text("untracked.txt", "staged preserved change\n")
        self.git("add", "--", "untracked.txt")
        names = (".git/index", "selected.txt", "untracked.txt", ".git/refs/heads/upstream")
        unchanged = {name: (self.root / name).read_bytes() for name in names}
        original_config = (self.root / ".git/config").read_bytes()
        expected_config = original_config.replace(b'[branch "main"]\n', b'[branch "next"]\n')
        self.assertNotEqual(expected_config, original_config)
        prefixes = {name: (self.root / name).read_bytes() for name in (".git/logs/refs/heads/main", ".git/logs/HEAD")}
        catalogue = self.observed()
        prepared = self.prepared(catalogue)
        with ExitStack() as stack:
            paths = (".git/refs/heads/main", ".git/HEAD", ".git/config", ".git/logs/refs/heads/main", ".git/logs/HEAD", ".git/index")
            held = {name: stack.enter_context(open(self.root / name, "rb")) for name in paths}
            before = {name: (self.identity(os.fstat(stream.fileno())), stream.read()) for name, stream in held.items()}
            result, repository = self.applied(prepared)
            for name, stream in held.items():
                actual = os.fstat(stream.fileno())
                self.assertEqual((actual.st_dev, actual.st_ino), before[name][0][:2])
                self.assertEqual(actual.st_nlink, 1 if name in (".git/refs/heads/main", ".git/index") else 0)
                stream.seek(0)
                self.assertEqual(stream.read(), before[name][1])
            self.assertEqual(self.identity((self.root / ".git/refs/heads/next").lstat())[:2], before[".git/refs/heads/main"][0][:2])
            self.assertEqual(self.identity((self.root / ".git/index").lstat()), before[".git/index"][0])
        self.assertEqual((result.observation.head, result.observation.branch), (catalogue.head, "refs/heads/next"))
        self.assertEqual({name: (self.root / name).read_bytes() for name in names}, unchanged)
        self.assertEqual((self.root / ".git/config").read_bytes(), expected_config)
        self.assertFalse((self.root / ".git/refs/heads/main").exists())
        self.assertFalse((self.root / ".git/logs/refs/heads/main").exists())
        head, zero = catalogue.head.encode(), b"0" * len(catalogue.head)
        actor = b" Rename Fixture <fixture@example.invalid> "
        for old, new in ((".git/logs/refs/heads/main", ".git/logs/refs/heads/next"), (".git/logs/HEAD", ".git/logs/HEAD")):
            raw = (self.root / new).read_bytes()
            self.assertTrue(raw.startswith(prefixes[old]))
            lines = raw[len(prefixes[old]):].splitlines(keepends=True)
            transitions = [(head, zero), (zero, head)] if new == ".git/logs/HEAD" and len(lines) == 2 else [(head, head)]
            self.assertEqual(len(lines), len(transitions))
            suffixes = []
            for line, (before, after) in zip(lines, transitions):
                marker = before + b" " + after + actor
                self.assertTrue(line.startswith(marker))
                suffix = line[len(marker):]
                self.assertRegex(suffix, rb"^[0-9]{1,12} [+-][0-9]{4}\tBranch: renamed refs/heads/main to refs/heads/next\n$")
                suffixes.append(suffix)
            self.assertEqual(len(set(suffixes)), 1)
        self.assertEqual(self.private_commands, ["branch", "config", "verify"])
        self.assertEqual([row.step for row in repository._transaction.returns], ["new-log", "old-log", "ref", "head-log", "head", "config"])
        self.assertEqual(self.git("config", "--local", "--get", "branch.next.remote"), b".\n")
        self.assertEqual(self.git("config", "--local", "--get", "branch.next.merge"), b"refs/heads/upstream\n")
        self.assertEqual(self.git("diff", "--cached", "--no-ext-diff", "--no-textconv", "--name-only", "--"), b"untracked.txt\n")
        self.case_returned = True

    def test_real_missing_section_and_disabled_logs_do_not_rewrite_config(self):
        self.git("config", "--local", "core.logAllRefUpdates", "false")
        self.commit_text("original without logs\n")
        # The supported layout requires these existing empty log parents even
        # when logging is disabled. Create only fixed disposable fixture dirs.
        for leaf in ("logs", "logs/refs", "logs/refs/heads"):
            (self.root / ".git" / leaf).mkdir(mode=0o700)
        self.remember_fixture()
        path = self.root / ".git/config"
        before = self.identity(path.lstat()), path.read_bytes()
        catalogue = self.observed()
        prepared = self.prepared(catalogue)
        self.assertFalse(prepared[1].as_dict()["logging"] or prepared[1].as_dict()["configMoved"])
        result, repository = self.applied(prepared)
        self.assertEqual((self.identity(path.lstat()), path.read_bytes()), before)
        self.assertEqual((result.observation.head, result.observation.branch), (catalogue.head, "refs/heads/next"))
        self.assertEqual(self.private_commands, ["branch", "verify"])
        self.assertEqual([row.step for row in repository._transaction.returns], ["ref", "head"])
        self.assertEqual(list((self.root / ".git/logs/refs/heads").iterdir()), [])
        self.assertFalse((self.root / ".git/logs/HEAD").exists())
        self.case_returned = True

    def test_real_stale_and_foreign_target_lock_refuse_before_private_git(self):
        self.commit_text("original\n")
        prepared = self.prepared(self.observed())
        self.write_text("selected.txt", "intervening source edit stays\n")
        for phase in ("stale", "foreign-lock"):
            if phase == "foreign-lock":
                prepared = self.prepared(self.observed())
                lock = self.root / ".git/refs/heads/next.lock"
                with open(lock, "xb") as stream:
                    stream.write(b"foreign fixture lock stays\n")
                lock_before = self.identity(lock.lstat())
                self.remember_fixture()
            repository, review, _, _ = prepared
            owner = passive.Owner(self.root, review.plan)
            names = (".git/HEAD", ".git/index", ".git/config", ".git/refs/heads/main", "selected.txt")
            before = {name: (self.root / name).read_bytes() for name in names}
            with self.assertRaises(core.GitError) as error:
                repository.apply_rename(review, owner, expected_digest=review.digest)
            if phase == "stale":
                self.assertEqual(error.exception.reason, "stale-observation")
            self.closed(repository)
            self.assertEqual(owner.intents, [])
            self.assertEqual(self.private_commands, [])
            self.assertEqual({name: (self.root / name).read_bytes() for name in names}, before)
            sent = self.calls
            with self.assertRaises(core.GitError) as replay:
                repository.apply_rename(review, owner, expected_digest=review.digest)
            self.assertEqual(replay.exception.reason, "already-used")
            self.assertEqual(self.calls, sent)
            self.closed(repository)
        self.assertEqual(self.identity(lock.lstat()), lock_before)
        self.assertEqual(lock.read_bytes(), b"foreign fixture lock stays\n")
        self.assertFalse((self.root / ".git/refs/heads/main.lock").exists())
        self.case_returned = True
