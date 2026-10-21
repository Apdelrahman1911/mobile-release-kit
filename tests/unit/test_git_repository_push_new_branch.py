"""Real bounded private/core files with fake fixed Git/channel returns only.

Reuses original LocalFacetTests custody/teardown. No actual Git child, HTTP,
native ACK, worker join or credential is supplied by these tests.
"""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import time
import unittest

from mobile_release import git_repository_push_new_branch as first
from mobile_release import git_push_new_branch as selection
from mobile_release import git_repository_push as push
from mobile_release import git_repository_read as read
from mobile_release import git_push_transaction as transaction
from mobile_release import git_push_body as bodies
from mobile_release import git_push_transport as transport
from mobile_release import git_push_wire as wire
from mobile_release import _desktop_git_push_protocol as protocol
from mobile_release import git_service as core
from mobile_release.owned_process import ProcessCleanupError
import test_git_repository_local as fixture
from test_git_repository_push import FakePush, HEAD, BLOB, LAUNCH
from test_git_push_wire import advertisement_raw, packet, pack, status
from test_desktop_git_push_protocol import fixture as request_fixture, frame


BRANCH = fixture.BRANCH
SELECTED = selection.Selection(BRANCH, BRANCH, selection.ZERO, HEAD)
TARGET = transport.Target("fixture/relay", "chosen-user", "11", "22", SELECTED)
ANCESTOR = "7" * 40


class FakeFirst(FakePush):
    def __init__(self, root):
        super().__init__(root)
        self.config = {name: values for name, values in self.config.items()
                       if not name.startswith(("branch.", "remote."))}
        self.commits = (ANCESTOR, HEAD)


class InertRemote:
    """Exact production callbacks; deliberately NOT an original FD8/ACK."""
    def __init__(self, test):
        self.test, self.repository = test, None
        self.calls, self.sent = [], 0
        self.after_hook = self.after_send = None

    def __call__(self, argv, **options):
        tx = self.repository._transaction
        self.calls.append((tx.mode, tuple(argv)))
        expected, environment = tx.view.command()
        self.test.assertEqual((argv, options["environ"]), (expected, environment))
        self.test.assertLessEqual(options["timeout"], 45)
        tx.hook(transaction.hook_line(SELECTED), transaction.url(tx.plan), transaction.url(tx.plan))
        if self.after_hook:
            self.after_hook(tx)
        if tx.mode == "review":
            returned = transaction.Returned("review", SELECTED, "a" * 64, None, None, None)
        else:
            ad = wire.advertisement(advertisement_raw(caps=b"report-status",
                refs=(("capabilities^{}", selection.ZERO),)), SELECTED)
            request = wire.command(packet((selection.ZERO + " " + HEAD + " " + BRANCH).encode()
                + b"\0 report-status") + b"0000", SELECTED, ad)
            stream = wire.PackStream(request, SELECTED, ad)
            opaque = pack(); stream.feed(opaque); digest = stream.finish()
            path = tx.view.root / bodies.NAME
            path.write_bytes(request.raw + opaque)
            tx.consume_send(digest, bodies._stamp(path.lstat()))
            self.sent += 1
            if self.after_send:
                self.after_send(tx)
            response = wire.status_response(status(b"unpack ok", ("ok " + BRANCH).encode(), sideband=False),
                                            SELECTED, ad, request)
            tx.observe_status(response)
            returned = transaction.Returned("apply", SELECTED, hashlib.sha256(ad.raw).hexdigest(),
                                             digest, response, "b" * 64)
        tx.observe_return(returned)
        return subprocess.CompletedProcess(argv, 0, b"Done\n", b"")


class GitPushNewBranchRepositoryTests(unittest.TestCase):
    write = fixture.LocalFacetTests.write
    release_fixture_descriptors = fixture.LocalFacetTests.release_fixture_descriptors

    def setUp(self):
        fixture.LocalFacetTests.setUp(self)
        self.fake, self.remote = FakeFirst(self.root), InertRemote(self)

    def repo(self):
        value = first.GitPushNewBranchRepository(self.root, git_executable=Path("/never-run/git"),
            work_end=time.monotonic() + 45, launch=LAUNCH, _run=self.fake, _remote=self.remote)
        self.repositories.append(value)
        self.remote.repository = value
        return value

    def prepare(self):
        repository = self.repo()
        observed = read.GitReadRepository(self.root, git_executable=Path("/never-run/git"),
            work_end=repository.work_end, _run=self.fake).observe()
        self.assertEqual(observed.tracking.state, "not-configured")
        review = repository.prepare_push(TARGET, expected_revision=observed.observation.revision,
                                         expected_reference_revision=observed.reference_revision)
        return repository, review, fixture.Owner(self.root, review.plan)

    def apply(self, repository, review, owner):
        return repository.apply_push(review, owner, expected_digest=review.digest)

    def test_complete_local_history_review_and_apply_preserve_dirty_index_untracked_and_config(self):
        self.write("unrelated.txt", b"untracked work left alone\n")
        original = {name: (self.root / name).read_bytes() for name in
                    (".git/HEAD", ".git/config", ".git/index", ".git/" + BRANCH, "a.txt", "b.txt", "unrelated.txt")}
        repository, review, owner = self.prepare()
        self.assertEqual(review.plan.commits, (ANCESTOR, HEAD))
        self.assertEqual(review.plan.public()["basis"], selection.BASIS)
        self.assertIsNone(review.plan.remote)
        self.assertIsNone(review.plan.public()["trackingRef"])
        outgoing = [args for args, _, _ in self.fake.calls if args[0] == "rev-list"]
        self.assertTrue(outgoing)
        self.assertTrue(all(args == ("rev-list", "--reverse", "--topo-order", "--max-count=65", HEAD, "--")
                            for args in outgoing))
        self.assertEqual(owner.intents, [])
        result = self.apply(repository, review, owner)
        self.assertEqual((result.action, result.state, result.settlement), (selection.KIND, "succeeded", "settled"))
        self.assertIs(type(result.intent), first.PushNewBranchIntent)
        self.assertEqual(result.intent.old_oid, selection.ZERO)
        self.assertEqual(len(owner.intents), 1)
        self.assertEqual(self.remote.sent, 1)
        for name, content in original.items():
            self.assertEqual((self.root / name).read_bytes(), content)
        self.assertFalse((self.root / ".git/refs/remotes").exists())
        self.assertFalse(any((self.root / ".git" / name).exists() for name in ("HEAD.lock", "index.lock", "config.lock")))
        self.assertFalse(repository._unknown or repository._retained or repository._active_sessions)

    def test_fixed_private_view_has_no_named_remote_or_upstream_and_only_create_hook(self):
        def checked(tx):
            argv, environment = tx.view.command()
            self.assertEqual(argv[-2:], [transaction.url(tx.plan), BRANCH + ":" + BRANCH])
            self.assertIn(b" push-new-branch-hook ", (tx.view.root / "hooks/pre-push").read_bytes())
            config = (tx.view.root / "config").read_bytes()
            self.assertNotIn(b"[remote", config)
            self.assertNotIn(b"[branch", config)
            for flag in ("--force", "--force-with-lease", "--mirror", "--all", "--delete", "--set-upstream", "-u", "--no-verify"):
                self.assertNotIn(flag, argv)
            self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
        self.remote.after_hook = checked
        self.prepare()

    def test_both_upstream_keys_must_be_absent_not_empty_partial_duplicate_or_configured(self):
        cases = ({"branch.main.remote": (b"origin",)}, {"branch.main.merge": (BRANCH.encode(),)},
                 {"branch.main.remote": (b"",)}, {"branch.main.merge": ()},
                 {"branch.main.remote": (b"origin", b"origin"), "branch.main.merge": (BRANCH.encode(),)},
                 {"branch.main.remote": (b"origin",), "branch.main.merge": (BRANCH.encode(),)})
        for changes in cases:
            config = dict(self.fake.config); config.update(changes)
            with self.subTest(keys=tuple(changes)), self.assertRaises(push.PushError):
                first.configuration(config, SELECTED)
        self.assertEqual(self.remote.calls, [])

    def test_partial_upstream_refuses_actual_capture_before_any_remote_call(self):
        self.fake.config["branch.main.remote"] = (b"origin",)
        repository = self.repo()
        observed = read.GitReadRepository(self.root, git_executable=Path("/never-run/git"),
            work_end=repository.work_end, _run=self.fake).observe()
        self.assertEqual(observed.tracking.state, "unsupported")
        with self.assertRaises(push.PushError):
            repository.prepare_push(TARGET, expected_revision=observed.observation.revision,
                                     expected_reference_revision=observed.reference_revision)
        self.assertEqual(self.remote.calls, [])

    def test_truncated_overbound_duplicate_unrelated_tip_or_forbidden_tree_never_reviews(self):
        for commits in ((), (ANCESTOR,), (HEAD, HEAD), tuple(f"{i:040x}" for i in range(1, 65)) + (HEAD,)):
            self.fake.commits = commits
            with self.subTest(count=len(commits)), self.assertRaises(core.GitError):
                self.prepare()
        self.fake.commits = (ANCESTOR, HEAD)
        for mode, name in (("160000", "child"), ("100644", ".gitattributes"), ("100644", "private.p12")):
            self.fake.tree = f"{mode} {'commit' if mode == '160000' else 'blob'} {BLOB}\t{name}\0".encode()
            with self.subTest(name=name), self.assertRaises(core.GitError):
                self.prepare()
        self.assertEqual(self.remote.calls, [])

    def test_new_and_existing_capture_types_cannot_reuse_one_another(self):
        repository, review, _ = self.prepare()
        ordinary_target = replace(TARGET, selected=wire.Selection(BRANCH, BRANCH, ANCESTOR, HEAD))
        fresh = self.repo()
        with self.assertRaises(core.GitError):
            fresh.prepare_push(ordinary_target, expected_revision=review.plan._snapshot.public.revision,
                               expected_reference_revision=review.plan.reference_revision)
        ordinary = push.GitPushRepository(self.root, git_executable=Path("/never-run/git"),
            work_end=time.monotonic() + 45, launch=LAUNCH, _run=self.fake, _remote=self.remote)
        self.repositories.append(ordinary)
        with self.assertRaises(core.GitError):
            ordinary.prepare_push(TARGET, expected_revision=review.plan._snapshot.public.revision,
                                  expected_reference_revision=review.plan.reference_revision)
        self.assertEqual(len(self.remote.calls), 1)

    def test_lost_candidate_ack_retains_new_kind_intent_and_refuses_retry_without_send(self):
        repository, review, owner = self.prepare()
        owner.on_intent = lambda _: (_ for _ in ()).throw(core.GitError("authorization"))
        result = self.apply(repository, review, owner)
        self.assertEqual((result.action, result.state, result.settlement), (selection.KIND, "recovery-required", "settled"))
        self.assertEqual(result.intent.action, selection.KIND)
        self.assertTrue(repository._transaction.ack_entered)
        self.assertFalse(repository._transaction.acknowledged)
        self.assertEqual(self.remote.sent, 0)
        self.assertTrue(repository._retained)
        with self.assertRaises(core.GitError):
            self.apply(repository, review, owner)
        self.assertEqual(len(owner.intents), 1)

    def test_unknown_after_send_keeps_exact_intent_and_body_no_regenerate_or_cleanup_credit(self):
        repository, review, owner = self.prepare()
        error = ProcessCleanupError("Synthetic original command close remained unknown")
        self.remote.after_send = lambda _: (_ for _ in ()).throw(error)
        result = self.apply(repository, review, owner)
        self.assertEqual((result.state, result.settlement), ("unknown", "unknown"))
        self.assertTrue(repository._unknown and repository._retained)
        self.assertEqual(self.remote.sent, 1)
        self.assertTrue((repository._transaction.view.root / bodies.NAME).exists())
        with self.assertRaises(core.GitError):
            self.apply(repository, review, owner)
        self.assertEqual(self.remote.sent, 1)

    def test_actual_review_candidate_and_retained_failure_terminal_keep_explicit_kind(self):
        repository, review, owner = self.prepare()
        row = request_fixture(phase="apply")
        row["id"] = owner.operation_id
        row["reviewDigest"] = review.digest
        row["action"].update(kind=selection.KIND, remote=None, localRef=BRANCH, remoteRef=BRANCH,
                             oldOid=selection.ZERO, newOid=HEAD,
                             expectedRevision=review.plan._snapshot.public.revision,
                             expectedReferenceRevision=review.plan.reference_revision)
        request = protocol.parse_request(frame(row))
        protocol.matches_review(request, review)
        owner.on_intent = lambda _: (_ for _ in ()).throw(core.GitError("authorization"))
        result = self.apply(repository, review, owner)
        candidate = protocol.candidate(request, review, result.intent)
        self.assertEqual(json.loads(candidate.raw)["intent"]["action"], selection.KIND)
        phase, paths = repository._transaction.diagnostics()
        raw = protocol.terminal(request, "ok", reason=None, result=result, effect_phase=phase, retained_paths=paths,
            first_failure_ns=request.work_end_ns - 5_000_000_000, cleanup_end_ns=request.work_end_ns + 5_000_000_000)
        decoded = json.loads(raw)
        self.assertEqual(decoded["action"], selection.KIND)
        self.assertEqual(decoded["result"]["action"], selection.KIND)
        self.assertEqual(decoded["result"]["intent"]["action"], selection.KIND)
        self.assertEqual(len(decoded["result"]["retainedPaths"]), 1)
        self.assertIsNone(decoded["transmission"])


if __name__ == "__main__":
    unittest.main()
