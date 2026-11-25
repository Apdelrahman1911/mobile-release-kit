"""Private filesystem + deliberately inert Git replies. No process or native grant."""
from dataclasses import replace
import os
from pathlib import Path
import subprocess
import time
import unittest
from unittest.mock import patch

from mobile_release import git_repository_fast_forward as ff
from mobile_release import git_repository_read as read
from mobile_release import git_repository_switch as switch
from mobile_release import git_service as core
import test_git_repository_switch as fixture
import test_git_repository_local as local_fixture

HEAD, TARGET = fixture.HEAD, fixture.TARGET
REF = "refs/remotes/origin/main"


class FakeFastForward(fixture.FakeSwitch):
    def __init__(self, root):
        super().__init__(root)
        self.config.update({"branch.main.remote": (b"origin",), "branch.main.merge": (b"refs/heads/main",),
            "remote.origin.url": (b"https://example.invalid/public",),
            "remote.origin.fetch": (b"+refs/heads/*:refs/remotes/origin/*",)})
        self.ahead, self.behind = 0, 2
        self.cas_count = 0
        self.bad_log = False
        self.stat_cache = False

    def __call__(self, argv, **kwargs):
        args = argv[argv.index("--work-tree=" + str(self.root)) + 1:]
        custom = args[0] in ("read-tree", "update-ref", "rev-list")
        custom |= args[:2] == ["for-each-ref", "--count=1"]
        custom |= args[:5] == ["rev-parse", "--verify", "--quiet", "--end-of-options", REF + "^{commit}"]
        if not custom:
            return super().__call__(argv, **kwargs)
        directory = Path(next(a[10:] for a in argv if a.startswith("--git-dir=")))
        index = Path(kwargs["environ"]["GIT_INDEX_FILE"])
        self.calls.append((tuple(args), directory, dict(kwargs["environ"])))
        if self.before:
            self.before(args, directory, index)
        raw, code = b"", 0
        if args[0] == "for-each-ref":
            raw = ("refs/heads/main\0" + REF + "\0origin\0refs/heads/main\0\n").encode()
        elif args[0] == "rev-parse":
            raw = (directory / REF).read_bytes()
        elif args[0] == "rev-list":
            raw = f"{self.ahead}\t{self.behind}\n".encode()
        elif args[0] == "read-tree":
            assert directory != self.root / ".git" and index != self.root / ".git/index"
            for name in ("HEAD.lock", "index.lock", "config.lock", REF + ".lock"):
                assert (self.root / ".git" / name).is_file(), name
            assert (self.root / ".git/index").read_bytes() == fixture.INDEX
            assert (self.root / ".git/HEAD").read_bytes() == b"ref: refs/heads/main\n"
            if "-u" in args:
                self.checkout_count += 1
                assert index.read_bytes() == fixture.INDEX
                for name, body in self.after_files.items():
                    if body != self.before_files[name]:
                        self.atomic(self.root / name, body)
            self.atomic(index, fixture.CANDIDATE + (b"stat refresh" if "-u" in args and self.stat_cache else b""))
        else:
            self.cas_count += 1
            assert directory == self.root / ".git" and args == ["update-ref", "--no-deref", "-m", ff.MESSAGE,
                "refs/heads/main", TARGET, HEAD]
            assert not (directory / "HEAD.lock").exists()
            assert (directory / "index").read_bytes() == fixture.CANDIDATE
            assert (directory / (REF + ".lock")).is_file()
            if (directory / "refs/heads/main").read_text().strip() != HEAD:
                code = 1
            else:
                self.atomic(directory / "refs/heads/main", (TARGET + "\n").encode())
                identity = kwargs["environ"]["GIT_COMMITTER_NAME"] + " <" + kwargs["environ"]["GIT_COMMITTER_EMAIL"] + ">"
                for name in ("logs/HEAD", "logs/refs/heads/main"):
                    path = directory / name
                    if path.exists() or self.config["core.logallrefupdates"] == (b"true",):
                        tail = f"{HEAD} {TARGET} {identity} 1700000000 +0000\t{ff.MESSAGE}\n".encode()
                        with path.open("ab") as out:
                            out.write(b"bad\n" if self.bad_log else tail)
                        path.chmod(0o644)
        if self.after:
            self.after(args, directory, index)
        if self.refusal == args[0]:
            code = 1
        return subprocess.CompletedProcess(argv, code, raw, b"")


class FastForwardTests(unittest.TestCase):
    write = fixture.SwitchTests.write
    close_inert_descriptors = fixture.SwitchTests.close_inert_descriptors
    refusal = fixture.SwitchTests.refusal
    assert_no_checkout = fixture.SwitchTests.assert_no_checkout

    def setUp(self):
        fixture.SwitchTests.setUp(self)
        for name in (".git/refs/remotes", ".git/refs/remotes/origin", ".git/logs/refs", ".git/logs/refs/heads"):
            (self.root / name).mkdir(mode=0o700)
        self.write(REF.join((".git/", "")), (TARGET + "\n").encode())
        self.write(".git/logs/refs/heads/main", b"old branch prefix\n")
        self.fake = FakeFastForward(self.root)
        with (self.root / ".git/config").open("ab") as out:
            out.write(b'[branch "main"]\nremote=origin\nmerge=refs/heads/main\n[remote "origin"]\n'
                      b'url=https://example.invalid/public\nfetch=+refs/heads/*:refs/remotes/origin/*\n')

    def repo(self):
        value = ff.GitFastForwardRepository(self.root, git_executable=Path("/never-run/git"),
            work_end=time.monotonic() + 45, _run=self.fake)
        self.repositories.append(value)
        return value

    def prepared(self):
        repository = self.repo()
        observed = repository.observe()
        refs = repository.branches(expected_revision=observed.revision)
        review = repository.prepare_fast_forward(REF, TARGET, expected_revision=observed.revision,
                                                  expected_reference_revision=refs.reference_revision)
        return repository, review, local_fixture.Owner(self.root, review.plan)

    def apply(self, repository, review, owner):
        return repository.apply_fast_forward(review, owner, expected_digest=review.digest)

    def test_success_keeps_branch_tracking_unrelated_files_and_exact_pre_ack_index(self):
        repository, review, owner = self.prepared()
        unchanged = {n: (self.root / n).read_bytes() for n in
                     (".git/HEAD", ".git/" + REF, ".git/config", "b.txt", "loose.txt", "ignored.txt")}
        self.fake.stat_cache = True
        result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.settlement, result.reason), ("succeeded", "settled", None))
        self.assertEqual((result.observation.branch, result.observation.head), ("refs/heads/main", TARGET))
        self.assertEqual(len(owner.intents), 1)
        self.assertEqual((self.fake.checkout_count, self.fake.cas_count), (1, 1))
        self.assertEqual((self.root / ".git/index").read_bytes(), fixture.CANDIDATE)
        self.assertEqual(owner.intents[0].candidate_index, core._digest(fixture.CANDIDATE))
        for name, raw in unchanged.items():
            self.assertEqual((self.root / name).read_bytes(), raw)
        for name, prefix in (("logs/HEAD", b"old inert fixture log preserved byte-for-byte\n"),
                             ("logs/refs/heads/main", b"old branch prefix\n")):
            raw = (self.root / ".git" / name).read_bytes()
            self.assertTrue(raw.startswith(prefix))
            self.assertEqual(raw[len(prefix):].count(b"\n"), 1)
        self.assertFalse(repository._unknown or repository._retained or repository._active_sessions)

    def test_review_is_codes_and_paths_not_identity_or_remote_credentials(self):
        _, review, _ = self.prepared()
        value = review.as_dict()
        self.assertEqual(value["basis"], "local-refs-no-fetch")
        self.assertEqual((value["targetRef"], value["targetOid"], value["paths"]), (REF, TARGET, ["a.txt"]))
        for private in ("Fixture Name", "fixture@example", "https://", str(self.root), "public fixture"):
            self.assertNotIn(private, repr(value))
        self.assert_no_checkout()

    def test_divergent_equal_and_overbounded_walk_are_not_ancestor_authority(self):
        for ahead, behind in ((1, 2), (0, 0), (0, read.MAX_WALK + 1)):
            with self.subTest(ahead=ahead, behind=behind):
                self.fake.ahead, self.fake.behind = ahead, behind
                with self.assertRaises(core.GitError):
                    self.prepared()
                self.assert_no_checkout()

    def test_stale_tracking_or_dirty_original_never_enters_checkout(self):
        repository, review, owner = self.prepared()
        self.write(".git/" + REF, ("7" * 40 + "\n").encode())
        with self.assertRaises(core.GitError):
            self.apply(repository, review, owner)
        self.assert_no_checkout()
        self.write(".git/" + REF, (TARGET + "\n").encode())
        self.fake.status = b" M a.txt\0"
        self.refusal("switch-dirty", self.prepared)

    def test_lost_ack_retains_candidate_and_never_writes_worktree_or_replays(self):
        repository, review, owner = self.prepared()
        owner.on_intent = lambda _: (_ for _ in ()).throw(core.GitError("authorization"))
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "recovery-required")
        self.assertTrue(repository._retained)
        self.assert_no_checkout()
        with self.assertRaises(core.GitError):
            self.apply(repository, review, owner)

    def test_stop_after_checkout_preserves_known_partial_without_cas(self):
        repository, review, owner = self.prepared()
        self.fake.after = lambda args, *_: setattr(owner, "stopped", True) if args[:3] == ["read-tree", "-m", "-u"] else None
        result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.settlement), ("recovery-required", "settled"))
        self.assertEqual(self.fake.cas_count, 0)
        self.assertEqual((self.root / "a.txt").read_bytes(), self.fake.after_files["a.txt"])
        self.assertEqual((self.root / ".git/index").read_bytes(), fixture.INDEX)
        self.assertTrue(repository._retained)

    def test_returned_nonzero_or_bad_log_after_entered_cas_is_unknown_not_retry(self):
        repository, review, owner = self.prepared()
        self.fake.refusal = "update-ref"
        result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.settlement), ("unknown", "unknown"))
        self.assertTrue(repository._unknown and repository._retained)
        self.assertEqual(self.fake.cas_count, 1)

    def test_wrong_log_after_positive_cas_has_no_positive_receipt(self):
        repository, review, owner = self.prepared()
        self.fake.bad_log = True
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "unknown")
        self.assertIsNone(repository._transaction.reference_return)

    def test_disabled_absent_logs_stay_absent_no_policy_change(self):
        for name in ("logs/HEAD", "logs/refs/heads/main"):
            (self.root / ".git" / name).unlink()
        self.fake.config["core.logallrefupdates"] = (b"false",)
        path = self.root / ".git/config"
        path.write_bytes(path.read_bytes().replace(b"logAllRefUpdates=true", b"logAllRefUpdates=false"))
        repository, review, owner = self.prepared()
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "succeeded")
        self.assertFalse((self.root / ".git/logs/HEAD").exists())
        self.assertFalse((self.root / ".git/logs/refs/heads/main").exists())

    def test_selected_input_cannot_be_other_ref_or_arbitrary_command(self):
        for ref in ("refs/heads/next", "refs/remotes/origin/HEAD", "refs/remotes/a/../b", "--all"):
            self.assertFalse(ff.tracking_ref(ref))
        repository, review, _ = self.prepared()
        self.refusal("invalid-input", lambda: repository.prepare_local("commit"))
        with self.assertRaises(core.GitError):
            repository.apply_fast_forward(replace(review, digest="a" * 64), local_fixture.Owner(self.root, review.plan),
                                          expected_digest="a" * 64)


if __name__ == "__main__":
    unittest.main()
