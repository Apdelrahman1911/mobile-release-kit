"""Three scoped real-Git fixtures; source approval precedes execution.

Reuse OwnedReadTests/run_owned, not its test collection: nonroot, private
HOME/TMPDIR, fixed platform Git, no network/hooks/credentials, umask022,
120s/160calls/5s per fixture, ONE45s Prepare+Apply, existing600s outer bound.
MutationOwner alone is inert; no native/Store/SourceBook authority is asserted.

The last case deliberately retains a returned UNKNOWN core operation and its
private fixture. Every actual process caller has returned; process exit may
close retained descriptors but is NOT a protocol cleanup/finality receipt.
No reset, rollback, retry, descriptor repair or unknown-fixture deletion.
"""
from contextlib import ExitStack
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from mobile_release import git_repository_fast_forward as ff
from mobile_release import git_repository_read as read
from mobile_release import git_service as core
import test_git_repository_read_owned as approved
import test_git_repository_local as passive

TRACKING = "refs/remotes/origin/main"
BRANCH = "refs/heads/main"
COMPETING_MESSAGE = "fixture: competing expected-old ref write"
# Keep the one deliberately unresolved original reachable until this finite
# test process exits. This is not a native retirement or a reusable test owner.
_EXPECTED_UNKNOWN = []


class OwnedFastForwardTests(unittest.TestCase):
    identity = staticmethod(approved.OwnedReadTests.identity)
    read_inventory = approved.OwnedReadTests.read_inventory
    remember_fixture = approved.OwnedReadTests.remember_fixture
    write_text = approved.OwnedReadTests.write_text
    git = approved.OwnedReadTests.git
    commit_text = approved.OwnedReadTests.commit_text

    def setUp(self):
        self.assertNotEqual(os.getuid(), 0, "Use only the approved nonroot projection")
        self.case_returned = False
        self.expected_unknown = None
        self.returned_calls = 0
        self.checkout_calls = self.cas_calls = self.competing_calls = 0
        self.cas_results = []
        self.compete = False
        self.ack_index = None
        approved.OwnedReadTests.setUp(self)
        original = tempfile.mkdtemp

        def scratch(**kwargs):
            kwargs.setdefault("dir", self.base)
            self.assertTrue(Path(kwargs["dir"]).is_relative_to(self.base))
            return original(**kwargs)

        selected = patch.object(core.tempfile, "mkdtemp", side_effect=scratch)
        selected.start()
        self.addCleanup(selected.stop)
        self.git("config", "--local", "user.name", "FastForward Fixture")
        self.git("config", "--local", "user.email", "fixture@example.invalid")

    def cleanup_fixture(self):
        if not self.case_returned:
            raise AssertionError("Nonpassing fast-forward fixture preserved")
        self.assertFalse(self.unknown, "An actual process caller did not settle")
        self.assertEqual(self.calls, self.returned_calls)
        if self.expected_unknown is not None:
            self.assertTrue(self.expected_unknown._unknown and self.expected_unknown._retained)
            self.assertIs(_EXPECTED_UNKNOWN[0][1], self.expected_unknown)
            print("EXPECTED_UNKNOWN_FIXTURE_RETAINED=" + str(self.base), flush=True)
            return  # No adoption into the successful-cleanup inventory.
        approved.OwnedReadTests.cleanup_fixture(self)

    def owned(self, argv, **options):
        # Inspect the actual production sends, then pass the SAME arguments to
        # the unchanged C/A/W owner. No synthetic Git result or relaxed clock.
        marker = "--work-tree=" + str(self.root)
        args = argv[argv.index(marker) + 1:] if marker in argv else []
        is_cas = bool(args and args[0] == "update-ref")
        if args and args[0] == "read-tree":
            self.assertIn(args, (["read-tree", "-m", self.old, self.target],
                                 ["read-tree", "-m", "-u", self.old, self.target]))
            private = Path(next(arg[10:] for arg in argv if arg.startswith("--git-dir=")))
            index = Path(options["environ"]["GIT_INDEX_FILE"])
            self.assertNotEqual(private, self.root / ".git")
            self.assertNotEqual(index, self.root / ".git/index")
            self.assertTrue(private.is_relative_to(self.base) and index.is_relative_to(self.base))
            for leaf in ("HEAD.lock", "index.lock", "config.lock", TRACKING + ".lock"):
                self.assertTrue((self.root / ".git" / leaf).is_file(), leaf)
            self.assertEqual((self.root / ".git/index").read_bytes(), self.original_index)
            if "-u" in args:
                self.assertIsNotNone(self.ack_index)
                self.checkout_calls += 1
        if is_cas:
            self.assertEqual(args, ["update-ref", "--no-deref", "-m", ff.MESSAGE,
                                    BRANCH, self.target, self.old])
            self.assertIn("--git-dir=" + str(self.root / ".git"), argv)
            self.assertFalse((self.root / ".git/HEAD.lock").exists())
            self.assertTrue((self.root / ".git" / (TRACKING + ".lock")).is_file())
            self.assertEqual((self.root / ".git/index").read_bytes(), self.ack_index)
            self.cas_calls += 1
            if self.compete:
                self.compete = False
                # A distinct REAL competing writer wins after the production
                # precheck, before its unchanged expected-OLD CAS is sent.
                self.competing_calls += 1
                self.git("update-ref", "--no-deref", "-m", COMPETING_MESSAGE,
                         BRANCH, self.target, self.old)
                self.assertEqual((self.root / ".git" / BRANCH).read_bytes(), (self.target + "\n").encode())
        result = approved.OwnedReadTests.owned(self, argv, **options)
        self.returned_calls += 1
        if is_cas:
            self.cas_results.append(result.returncode)
        return result

    def fixed_write(self, name, raw):
        self.assertIn(name, (".gitignore", "ignored.txt", ".git/" + TRACKING + ".lock"))
        with open(self.root / name, "xb") as stream:
            stream.write(raw)
        self.remember_fixture()

    def history(self):
        self.fixed_write(".gitignore", b"ignored.txt\n")
        self.git("add", "--", ".gitignore")
        self.commit_text("before content\n")
        self.old = self.git("rev-parse", "HEAD").strip().decode("ascii")
        self.git("branch", "next")
        self.git("switch", "--no-guess", "--no-recurse-submodules", "--no-overwrite-ignore", "--", "next")
        self.commit_text("after content\n")
        self.target = self.git("rev-parse", "HEAD").strip().decode("ascii")
        self.git("switch", "--no-guess", "--no-recurse-submodules", "--no-overwrite-ignore", "--", "main")
        # Cached reference created locally. No fetch/remote action is run.
        self.git("update-ref", "--no-deref", TRACKING, self.target, "0" * len(self.target))
        for name, value in (("remote.origin.url", "https://example.invalid/fixture.git"),
                            ("remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"),
                            ("branch.main.remote", "origin"), ("branch.main.merge", BRANCH)):
            self.git("config", "--local", name, value)
        self.write_text("untracked.txt", "preserve unrelated untracked bytes\n")
        self.fixed_write("ignored.txt", b"preserve unrelated ignored bytes\n")

    def closed(self, repository):
        self.assertFalse(repository._unknown or repository._retained or repository._active_sessions
                         or repository._retained_sessions, "Original operation did not positively retire")
        self.remember_fixture()

    def prepared(self):
        observer = read.GitReadRepository(self.root, git_executable=approved.GIT,
            work_end=min(self.end, time.monotonic() + 45), _run=self.owned)
        self.repositories.append(observer)
        observed = observer.observe()
        self.closed(observer)  # Genuinely separate completed Observe, not a clock reset.
        self.assertEqual((observed.tracking.state, observed.tracking.local_ref, observed.tracking.head,
                          observed.tracking.ahead, observed.tracking.behind),
                         ("complete", TRACKING, self.target, 0, 1))
        repository = ff.GitFastForwardRepository(self.root, git_executable=approved.GIT,
            work_end=min(self.end, time.monotonic() + 45), _run=self.owned)
        self.repositories.append(repository)
        started, calls = time.monotonic(), self.calls
        review = repository.prepare_fast_forward(TRACKING, self.target,
            expected_revision=observed.observation.revision, expected_reference_revision=observed.reference_revision)
        self.closed(repository)
        self.original_index = (self.root / ".git/index").read_bytes()
        return repository, review, started, calls

    def apply(self, prepared):
        repository, review, started, calls = prepared
        owner = passive.Owner(self.root, review.plan)  # Inert journal only.

        def before_ack(intent):
            self.assertIsNone(self.ack_index)
            self.ack_index = repository._transaction.index.read_bytes()
            self.assertEqual(core._digest(self.ack_index), intent.candidate_index)
            self.assertEqual((self.root / ".git/index").read_bytes(), self.original_index)
            self.assertEqual((self.root / "selected.txt").read_bytes(), b"before content\n")
            self.assertEqual((self.root / ".git" / BRANCH).read_bytes(), (self.old + "\n").encode())

        owner.on_intent = before_ack
        result = repository.apply_fast_forward(review, owner, expected_digest=review.digest)
        detail = f"reason={result.reason}; calls={self.calls-calls}; elapsed={time.monotonic()-started:.3f}s"
        self.assertEqual(owner.intents, [result.intent], detail)
        return result, repository, owner, detail

    def no_replay(self, repository, review, owner):
        calls = self.calls
        with self.assertRaises(core.GitError) as caught:
            repository.apply_fast_forward(review, owner, expected_digest=review.digest)
        self.assertEqual(caught.exception.reason, "already-used")
        self.assertEqual(self.calls, calls)

    def test_real_01_default_reflogs_exact_index_and_untracked_preservation(self):
        self.history()
        stable = (".git/HEAD", ".git/config", ".git/" + TRACKING, ".gitignore", "untracked.txt", "ignored.txt")
        preserved = {name: (self.identity((self.root / name).lstat()), (self.root / name).read_bytes()) for name in stable}
        logs = (".git/logs/HEAD", ".git/logs/" + BRANCH)
        prefixes = {name: (self.root / name).read_bytes() for name in logs}
        prepared = self.prepared()
        with ExitStack() as stack:
            held = {name: stack.enter_context(open(self.root / name, "rb")) for name in (".git/index", *logs)}
            before = {name: self.identity(os.fstat(stream.fileno())) for name, stream in held.items()}
            result, repository, owner, detail = self.apply(prepared)
            self.assertEqual((result.state, result.settlement), ("succeeded", "settled"), detail)
            self.assertEqual((result.observation.head, result.observation.branch), (self.target, BRANCH))
            self.assertEqual((self.checkout_calls, self.cas_calls, self.cas_results), (1, 1, [0]))
            self.assertEqual(held[".git/index"].read(), self.original_index)
            for name, stream in held.items():
                current = os.fstat(stream.fileno())
                self.assertEqual((current.st_dev, current.st_ino), before[name][:2])
                self.assertEqual(current.st_nlink, 0 if name == ".git/index" else 1)
            self.closed(repository)
        self.assertEqual((self.root / ".git/index").read_bytes(), self.ack_index)
        self.assertEqual((self.root / "selected.txt").read_bytes(), b"after content\n")
        for name, expected in preserved.items():
            self.assertEqual((self.identity((self.root / name).lstat()), (self.root / name).read_bytes()), expected)
        for name in logs:
            raw = (self.root / name).read_bytes()
            self.assertTrue(raw.startswith(prefixes[name]))
            tail = raw[len(prefixes[name]):]
            prefix = (self.old + " " + self.target + " FastForward Fixture <fixture@example.invalid> ").encode()
            self.assertTrue(tail.startswith(prefix))
            self.assertRegex(tail[len(prefix):], rb"^[0-9]{1,12} [+-][0-9]{4}\tMRK: fast-forward to reviewed cached tracking commit\n$")
        self.assertIs(repository._transaction.publication.reference, repository._transaction.reference_return)
        for name in ("HEAD.lock", "index.lock", "config.lock", BRANCH + ".lock", TRACKING + ".lock"):
            self.assertFalse((self.root / ".git" / name).exists())
        self.no_replay(repository, prepared[1], owner)
        self.closed(repository)
        self.assertEqual(self.git("diff", "--no-ext-diff", "--no-textconv", "--name-only", "HEAD", "--"), b"")
        self.case_returned = True

    def test_real_02_stale_tracking_and_foreign_lock_refuse_before_checkout(self):
        self.history()
        prepared = self.prepared()
        self.git("update-ref", "--no-deref", TRACKING, self.old, self.target)
        for phase in ("stale", "foreign-lock"):
            if phase == "foreign-lock":
                self.git("update-ref", "--no-deref", TRACKING, self.target, self.old)
                prepared = self.prepared()
                self.fixed_write(".git/" + TRACKING + ".lock", b"foreign fixture lock stays\n")
                lock = self.root / ".git" / (TRACKING + ".lock")
                lock_before = self.identity(lock.lstat()), lock.read_bytes()
            repository, review, _, _ = prepared
            owner = passive.Owner(self.root, review.plan)
            names = (".git/HEAD", ".git/index", ".git/config", ".git/" + BRANCH,
                     "selected.txt", "untracked.txt", "ignored.txt")
            before = {name: (self.root / name).read_bytes() for name in names}
            with self.assertRaises(core.GitError) as caught:
                repository.apply_fast_forward(review, owner, expected_digest=review.digest)
            if phase == "stale":
                self.assertEqual(caught.exception.reason, "stale-observation")
            self.closed(repository)
            self.assertEqual(owner.intents, [])
            self.assertEqual((self.checkout_calls, self.cas_calls), (0, 0))
            self.assertEqual({name: (self.root / name).read_bytes() for name in names}, before)
            self.no_replay(repository, review, owner)
            self.closed(repository)
        self.assertEqual((self.identity(lock.lstat()), lock.read_bytes()), lock_before)
        self.case_returned = True

    def test_real_03_expected_old_refusal_retains_prior_files_index_and_unknown(self):
        self.history()
        prepared = self.prepared()
        self.compete = True
        result, repository, owner, detail = self.apply(prepared)
        self.assertEqual((result.state, result.settlement), ("unknown", "unknown"), detail)
        self.assertEqual((self.checkout_calls, self.cas_calls, self.competing_calls), (1, 1, 1))
        self.assertEqual(len(self.cas_results), 1)
        self.assertNotEqual(self.cas_results[0], 0)  # The unchanged production CAS really refused.
        self.assertEqual((self.root / "selected.txt").read_bytes(), b"after content\n")
        self.assertEqual((self.root / ".git/index").read_bytes(), self.ack_index)
        self.assertEqual((self.root / ".git/HEAD").read_bytes(), b"ref: refs/heads/main\n")
        self.assertEqual((self.root / ".git" / BRANCH).read_bytes(), (self.target + "\n").encode())
        for name in ("logs/HEAD", "logs/" + BRANCH):
            raw = (self.root / ".git" / name).read_bytes()
            self.assertTrue(raw.endswith(("\t" + COMPETING_MESSAGE + "\n").encode()))
            self.assertNotIn(ff.MESSAGE.encode(), raw)  # The winner was NOT this operation.
        transaction = repository._transaction
        self.assertIsNotNone(transaction.checkout_return)
        self.assertIsNotNone(transaction.index_publication)
        self.assertIsNone(transaction.reference_return)
        self.assertEqual(transaction.command_entered, "reference")
        self.assertIn(transaction, repository._retained)
        self.assertEqual(transaction.index.read_bytes(), self.ack_index)
        self.assertTrue(repository._unknown and repository._retained_sessions)
        self.assertFalse(repository._active_sessions or self.unknown)
        self.assertEqual(self.calls, self.returned_calls)
        self.no_replay(repository, prepared[1], owner)
        calls = self.calls
        with self.assertRaises(core.GitError):
            repository.prepare_fast_forward(TRACKING, self.target,
                expected_revision=prepared[1].plan._snapshot.public.revision,
                expected_reference_revision=prepared[1].plan.reference_revision)
        self.assertEqual(self.calls, calls)
        self.assertEqual(_EXPECTED_UNKNOWN, [])
        _EXPECTED_UNKNOWN.append((self.base, repository, owner))
        self.expected_unknown = repository
        self.case_returned = True
