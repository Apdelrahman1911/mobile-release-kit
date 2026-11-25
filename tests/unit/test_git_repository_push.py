"""Actual bounded core/private files, deliberately inert process/channel replies.

No Git child, HTTP, credential, native ACK or join is supplied. Reuses the same
existing local-facet fixture and its exact descriptor teardown for fake unknowns.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import subprocess
import time
import unittest

from mobile_release import git_repository_push as push
from mobile_release import git_repository_read as read
from mobile_release import git_push_transaction as txs
from mobile_release import git_push_body as bodies
from mobile_release import git_push_transport as transport
from mobile_release import git_push_wire as wire
from mobile_release import _git_push_private_protocol as private
from mobile_release import git_service as core
from mobile_release.owned_process import ProcessCleanupError
import test_git_repository_local as fixture
from test_git_push_wire import packet, pack


HEAD, OLD, BLOB = fixture.HEAD, "9" * 40, fixture.BLOB
BRANCH, TRACKING = fixture.BRANCH, "refs/remotes/origin/main"
SELECTED = wire.Selection(BRANCH, BRANCH, OLD, HEAD)
TARGET = transport.Target("fixture/relay", "chosen-user", "11", "22", SELECTED)
LAUNCH = txs.Launch(*(Path("/never-run") / name for name in ("python", "bootstrap", "core", "runtime")),
                    context=private.Clock("c" * 64, 145_000_000_000, 155_000_000_000))


class FakePush(fixture.FakeGit):
    def __init__(self, root):
        super().__init__(root)
        self.config.update({"branch.main.remote": (b"origin",), "branch.main.merge": (BRANCH.encode(),),
            "remote.origin.url": (b"https://github.com/fixture/relay.git",),
            "remote.origin.fetch": (b"+refs/heads/*:refs/remotes/origin/*",)})
        self.ahead, self.behind = 1, 0
        self.commits = (HEAD,)
        self.tree = f"100644 blob {BLOB}\ta.txt\0".encode()
        self.symbolic_tracking = False

    def __call__(self, argv, **options):
        args = argv[argv.index("--work-tree=" + str(self.root)) + 1:]
        special = args[0] in ("for-each-ref", "rev-list", "ls-tree") or args[-1] in (TRACKING, TRACKING + "^{commit}")
        if not special:
            return super().__call__(argv, **options)
        directory = Path(next(value[10:] for value in argv if value.startswith("--git-dir=")))
        self.calls.append((tuple(args), directory, dict(options["environ"])))
        code, raw = 0, b""
        if args[0] == "for-each-ref":
            raw = (BRANCH + "\0" + TRACKING + "\0origin\0" + BRANCH + "\0\n").encode()
        elif args[0] == "symbolic-ref":
            code, raw = (0, b"refs/remotes/origin/other\n") if self.symbolic_tracking else (1, b"")
        elif args[0] == "rev-parse":
            raw = (directory / TRACKING).read_bytes()
        elif args[:2] == ["rev-list", "--left-right"]:
            raw = f"{self.ahead}\t{self.behind}\n".encode()
        elif args[0] == "rev-list":
            raw = b"".join((oid + "\n").encode() for oid in self.commits)
        else:
            raw = self.tree
        return subprocess.CompletedProcess(argv, code, raw, b"")


class InertRemote:
    """No actual original channel/ACK: only a fake of its exact callbacks."""
    def __init__(self, test):
        self.test, self.repository = test, None
        self.calls, self.sent = [], 0
        self.before_hook = self.after_hook = self.after_send = self.after_receipt = None
        self.omit_hook = self.omit_return = self.foreign_body = False
        self.result = 0

    def __call__(self, argv, **options):
        test, tx = self.test, self.repository._transaction
        self.calls.append((tx.mode, tuple(argv), options["timeout"]))
        expected, env = tx.view.command()
        test.assertEqual(argv, expected)
        test.assertEqual(options["environ"], env)
        test.assertLessEqual(options["timeout"], 45)
        test.assertEqual(options["cwd"], tx.view.root)
        test.assertTrue(tx.running)
        if self.before_hook:
            self.before_hook(tx)
        if not self.omit_hook:
            tx.hook(txs.hook_line(SELECTED), txs.url(tx.plan), txs.url(tx.plan))
        if self.after_hook:
            self.after_hook(tx)
        if tx.mode == "apply" and not self.omit_hook:
            offered = wire.advertisement(packet(b"# service=git-receive-pack\n") + b"0000"
                + packet((OLD + " " + BRANCH).encode() + b"\0report-status\n") + b"0000", SELECTED)
            command = wire.command(packet((OLD + " " + HEAD + " " + BRANCH).encode()
                + b"\0 report-status") + b"0000", SELECTED, offered)
            stream = wire.PackStream(command, SELECTED, offered)
            raw = pack()
            stream.feed(raw)
            digest = stream.finish()
            path = tx.view.root / bodies.NAME
            if self.foreign_body:
                old = path.with_name("foreign-body")
                path.rename(old)  # Preserve real original, not unlink/recreate repair.
                path.write_bytes(b"")
                path.chmod(0o600)
            path.write_bytes(command.raw + raw)
            tx.consume_send(digest, bodies._stamp(path.lstat()))
            self.sent += 1
            if self.after_send:
                self.after_send(tx)
            raw_status = packet(b"unpack ok\n") + packet(("ok " + BRANCH + "\n").encode()) + b"0000"
            status = wire.status_response(raw_status, SELECTED, offered, command)
            tx.observe_status(status)
            value = txs.Returned("apply", SELECTED, hashlib.sha256(offered.raw).hexdigest(), digest, status, "b" * 64)
        else:
            value = txs.Returned("review", SELECTED, "a" * 64, None, None, None)
        if not self.omit_return and not self.omit_hook:
            tx.observe_return(value)
        if self.after_receipt:
            self.after_receipt(tx)
        return subprocess.CompletedProcess(argv, self.result, b"Done\n", b"")


class GitPushRepositoryTests(unittest.TestCase):
    write = fixture.LocalFacetTests.write
    release_fixture_descriptors = fixture.LocalFacetTests.release_fixture_descriptors

    def setUp(self):
        fixture.LocalFacetTests.setUp(self)
        for name in (".git/refs/remotes", ".git/refs/remotes/origin"):
            (self.root / name).mkdir(mode=0o700)
        self.write(".git/" + TRACKING, (OLD + "\n").encode())
        self.fake = FakePush(self.root)
        self.remote = InertRemote(self)

    def repo(self):
        value = push.GitPushRepository(self.root, git_executable=Path("/never-run/git"),
            work_end=time.monotonic() + 45, launch=LAUNCH, _run=self.fake, _remote=self.remote)
        self.repositories.append(value)
        self.remote.repository = value
        return value

    def prepare(self):
        repository = self.repo()
        observed = read.GitReadRepository(self.root, git_executable=Path("/never-run/git"),
            work_end=repository.work_end, _run=self.fake).observe()
        review = repository.prepare_push(TARGET, expected_revision=observed.observation.revision,
                                         expected_reference_revision=observed.reference_revision)
        return repository, review, fixture.Owner(self.root, review.plan)

    def apply(self, repository, review, owner):
        return repository.apply_push(review, owner, expected_digest=review.digest)

    def test_review_then_one_apply_keeps_every_original_dirty_index_ref_and_config_byte(self):
        originals = {name: (self.root / name).read_bytes() for name in
            (".git/HEAD", ".git/config", ".git/index", ".git/" + BRANCH, ".git/" + TRACKING, "a.txt", "b.txt")}
        repository, review, owner = self.prepare()
        self.assertEqual(owner.intents, [])
        self.assertEqual([mode for mode, _, _ in self.remote.calls], ["review"])
        self.assertIn("--dry-run", self.remote.calls[0][1])
        result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.settlement, result.reason), ("succeeded", "settled", None))
        self.assertEqual(len(owner.intents), 1)
        self.assertEqual(self.remote.sent, 1)
        self.assertNotIn("--dry-run", self.remote.calls[1][1])
        self.assertIsNone(result.observation)  # No manufactured refreshed tracking view.
        self.assertFalse(repository._unknown or repository._retained or repository._active_sessions)
        for name, raw in originals.items():
            self.assertEqual((self.root / name).read_bytes(), raw)
        self.assertFalse(any((self.root / ".git" / name).exists() for name in ("HEAD.lock", "index.lock", "config.lock")))

    def test_review_contains_complete_oids_but_no_message_author_path_or_credential(self):
        _, review, _ = self.prepare()
        value = review.as_dict()
        self.assertEqual(value["commits"], [HEAD])
        self.assertEqual(value["expectedRemoteOid"], OLD)
        for absent in ("edited a", "someone else", str(self.root), "Author", "password", "token"):
            self.assertNotIn(absent, repr(value))

    def test_private_command_has_only_exact_refspec_no_config_mapping_or_implicit_fetch(self):
        def check(tx):
            argv, env = tx.view.command()
            self.assertEqual(argv[-2:], [txs.url(tx.plan), BRANCH + ":" + BRANCH])
            config = (tx.view.root / "config").read_bytes()
            hook = (tx.view.root / "hooks/pre-push").read_bytes()
            self.assertIn(("push-hook review " + LAUNCH.context.digest + " " + tx.review_digest
                           + " 145000000000 155000000000").encode(), hook)
            self.assertNotIn(b"[remote", config)
            for flag in ("--force", "--force-with-lease", "--all", "--mirror", "--delete", "--set-upstream", "--no-verify"):
                self.assertNotIn(flag, argv)
            self.assertEqual(env["GIT_NO_LAZY_FETCH"], "1")
            self.assertEqual(env["GIT_OBJECT_DIRECTORY"], str(self.root / ".git/objects"))
            self.assertNotIn("GIT_CONFIG_PARAMETERS", env)
            self.assertEqual((tx.view.root / BRANCH).read_bytes(), (HEAD + "\n").encode())
        self.remote.before_hook = check
        self.prepare()

    def test_non_ancestor_equal_diverged_overbound_or_symbolic_tracking_never_runs_remote(self):
        for ahead, behind in ((0, 0), (1, 1), (65, 0)):
            self.fake.ahead, self.fake.behind = ahead, behind
            with self.subTest(ahead=ahead, behind=behind), self.assertRaises(core.GitError):
                self.prepare()
        self.fake.ahead, self.fake.behind, self.fake.symbolic_tracking = 1, 0, True
        with self.assertRaises(core.GitError):
            self.prepare()
        self.assertEqual(self.remote.calls, [])

    def test_incomplete_outgoing_oid_list_and_forbidden_committed_tree_are_not_authority(self):
        self.fake.ahead = 2
        with self.assertRaises(core.GitError):
            self.prepare()
        self.fake.ahead = 1
        for mode, path in (("160000", "child"), ("100644", ".gitattributes"), ("100644", "private.p12")):
            self.fake.tree = f"{mode} {'commit' if mode == '160000' else 'blob'} {BLOB}\t{path}\0".encode()
            with self.subTest(path=path), self.assertRaises(core.GitError):
                self.prepare()
        self.assertEqual(self.remote.calls, [])

    def test_existing_hook_and_required_push_configuration_are_refused_not_overwritten(self):
        for key, value in (("push.gpgsign", b"true"), ("push.pushoption", b"skip"),
                           ("remote.origin.pushurl", b"https://github.com/other/repo.git")):
            self.fake.config[key] = (value,)
            with self.subTest(key=key), self.assertRaises(core.GitError):
                self.prepare()
            del self.fake.config[key]
        (self.root / ".git/hooks").mkdir(mode=0o700)
        self.write(".git/hooks/pre-push", b"inert foreign policy")
        with self.assertRaises(core.GitError):
            self.prepare()
        self.assertEqual((self.root / ".git/hooks/pre-push").read_bytes(), b"inert foreign policy")
        self.assertEqual(self.remote.calls, [])

    def test_plain_successful_git_exit_without_original_hook_or_private_return_is_not_review(self):
        self.remote.omit_hook = True
        with self.assertRaises(core.GitError):
            self.prepare()
        self.assertEqual(self.remote.sent, 0)
        repository = self.repositories[-1]
        self.assertEqual(repository._retained, [repository._transaction])
        self.assertTrue(repository._transaction.view.retained)
        self.assertTrue(repository._transaction.view.root.is_dir())
        with self.assertRaises(core.GitError):
            repository.prepare_push(TARGET, expected_revision="0" * 64, expected_reference_revision="0" * 64)
        self.assertEqual(len(self.remote.calls), 1)

    def test_changed_original_after_review_refuses_once_without_second_remote_or_source_write(self):
        repository, review, owner = self.prepare()
        self.write("a.txt", b"new unrelated work")
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "failed")
        self.assertEqual(owner.intents, [])
        self.assertEqual(len(self.remote.calls), 1)
        with self.assertRaises(core.GitError):
            self.apply(repository, review, owner)

    def test_lost_candidate_ack_preserves_intent_no_send_and_no_replay(self):
        repository, review, owner = self.prepare()
        owner.on_intent = lambda _: (_ for _ in ()).throw(core.GitError("authorization"))
        result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.settlement), ("recovery-required", "settled"))
        self.assertTrue(repository._transaction.ack_entered)
        self.assertFalse(repository._transaction.acknowledged or repository._transaction.send_entered)
        self.assertTrue(repository._retained)
        self.assertEqual(self.remote.sent, 0)
        with self.assertRaises(core.GitError):
            self.apply(repository, review, owner)
        self.assertEqual(len(owner.intents), 1)

    def test_native_apply_local_reprepare_does_not_repeat_dry_run_and_does_not_accept_other_digest(self):
        _, previous, _ = self.prepare()
        self.assertEqual(len(self.remote.calls), 1)
        repository = self.repo()
        with self.assertRaises(core.GitError):
            repository.prepare_push_apply(TARGET, expected_revision=previous.plan._snapshot.public.revision,
                expected_reference_revision=previous.plan.reference_revision, expected_digest="0" * 64)
        self.assertEqual(len(self.remote.calls), 1)
        current = repository.prepare_push_apply(TARGET, expected_revision=previous.plan._snapshot.public.revision,
            expected_reference_revision=previous.plan.reference_revision, expected_digest=previous.digest)
        self.assertIsNot(current.plan._key, previous.plan._key)
        self.assertEqual(len(self.remote.calls), 1)
        result = self.apply(repository, current, fixture.Owner(self.root, current.plan))
        self.assertEqual(result.state, "succeeded")
        self.assertEqual([mode for mode, _, _ in self.remote.calls], ["review", "apply"])

    def test_late_stop_after_hook_does_not_turn_prior_ack_into_send_permission(self):
        repository, review, owner = self.prepare()
        self.remote.after_hook = lambda _: setattr(owner, "stopped", True)
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "recovery-required")
        self.assertTrue(repository._transaction.acknowledged)
        self.assertFalse(repository._transaction.send_consumed)
        self.assertEqual(self.remote.sent, 0)

    def test_equal_body_under_foreign_inode_cannot_consume_original_send(self):
        repository, review, owner = self.prepare()
        self.remote.foreign_body = True
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "recovery-required")
        self.assertTrue(repository._transaction.send_entered)
        self.assertFalse(repository._transaction.send_consumed)
        self.assertEqual(self.remote.sent, 0)

    def test_missing_return_after_send_keeps_remote_receipt_but_never_infers_success_from_git0(self):
        repository, review, owner = self.prepare()
        self.remote.omit_return = True
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "recovery-required")
        self.assertEqual(repository._transaction.remote_status.outcome, "ok")
        self.assertIsNone(repository._transaction.receipt)
        self.assertTrue(repository._retained)

    def test_unknown_original_close_after_positive_receipt_stays_unknown_and_retained(self):
        repository, review, owner = self.prepare()
        self.remote.after_receipt = lambda _: (_ for _ in ()).throw(ProcessCleanupError("inert lost close", dispatched=True))
        result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.settlement), ("unknown", "unknown"))
        self.assertEqual(repository._transaction.remote_status.outcome, "ok")
        self.assertIsNotNone(repository._transaction.receipt)
        self.assertTrue(repository._unknown and repository._retained)
        with self.assertRaises(core.GitError):
            self.apply(repository, review, owner)

    def test_same_send_and_private_receipt_are_consumed_once_and_wrong_review_cannot_apply(self):
        repository, review, owner = self.prepare()
        with self.assertRaises(core.GitError):
            repository.apply_push(replace(review, digest="f" * 64), owner, expected_digest="f" * 64)
        def duplicate(tx):
            with self.assertRaises(core.GitError):
                tx.consume_send(tx.body_digest, tx.view.body_current)
        self.remote.after_send = duplicate
        result = self.apply(repository, review, owner)
        self.assertEqual(result.state, "succeeded")
        self.assertEqual(self.remote.sent, 1)


if __name__ == "__main__":
    unittest.main()
