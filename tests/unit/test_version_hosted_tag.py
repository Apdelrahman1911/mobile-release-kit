"""Actual fixed binder/CI code on existing inert Git/HTTP fixtures, never live refs."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import subprocess
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mobile_release import version_allocation as a
from mobile_release import version_future_tag as tag
from mobile_release import version_hosted as host
from mobile_release import version_hosted_tag as bind
from mobile_release import version_ci as ci
from mobile_release import version_policy as p
from mobile_release import workflow
from mobile_release import _github_connection_transport as http
from mobile_release.github_preflight import HttpRequest
from test_version_ci import Fixture, NOW, BRANCH, oid, commit
from test_version_hosted import MemoryRepository, SourceData, StoreData, reply

TAG = "refs/tags/release-1.2"


class TaggedFixture(Fixture):
    def __init__(self, root, schema=2):
        super().__init__(root, schema)
        old = self.row
        self.request = replace(self.request, future_tag=TAG,
            version_policy=replace(self.request.version_policy, rules=(p.RefRule(TAG, "build"),)))
        self.ledger = a.Ledger(self.ledger.genesis).append(self.request, old.store_observations, now=NOW)
        self.row = self.ledger.reservations[-1]
        self.anchor = replace(self.anchor, head_sha256=self.ledger.head_sha256)
        self.settings = p.canonical({"schemaVersion": 1, "authority": self.authority.value(),
                                     "checkpoint": self.anchor.value()}).decode()
        self.message = (f"Save reserved version\n\n{ci.TRAILER}: {self.request.candidate_id} {self.row.sha256}\n").encode()
        self.final_raw = commit(self.after_tree, self.message, (self.before_commit,))
        self.final = oid("commit", self.final_raw)
        self.commits = {self.before_commit: self.before_commit_raw, self.final: self.final_raw}
        self.context = replace(self.context, authority={"headSha": self.final, "ref": BRANCH})
        self.intent = bind.Intent("both" if schema == 4 else self.platforms[0], self.request.candidate_id, self.row.sha256, self.final)
        source = SourceData(self)
        self.binding_context = replace(source.context, confirmation=self.intent.confirmation(),
            authority={**source.context.authority, "headSha": self.final})
        self.tooling = root / "tooling"; self.tooling.mkdir()
        self.ca = b"PUBLIC inert CA fixture; not TLS qualification"
        self.ca_oid = oid("blob", self.ca)

    def bind_git(self, argv, **kwargs):
        if Path(argv[argv.index("-C") + 1]) != self.tooling:
            return super().git(argv, **kwargs)
        args = argv[argv.index("-C") + 2:]
        self.git_calls.append((list(args), kwargs))
        assert kwargs["cancellation"] is not None and kwargs["text"] is False
        assert kwargs["environ"]["GIT_ALLOW_PROTOCOL"] == "" and "protocol.allow=never" in argv
        if args == ["rev-parse", "--verify", "HEAD"]:
            result = (self.binding_context.trusted_tooling_commit + "\n").encode()
        elif args == ["ls-tree", "-z", "--full-tree", self.binding_context.trusted_tooling_commit, "--", host.CA_PATH]:
            result = f"100644 blob {self.ca_oid}\t{host.CA_PATH}\0".encode()
        else:
            assert args == ["cat-file", "blob", self.ca_oid]
            result = self.ca
        return subprocess.CompletedProcess(argv, 0, result, b"")

    def json(self, receiver, endpoint, *, maximum, timeout):
        if endpoint.endswith("/git/ref/tags/" + TAG.removeprefix("refs/tags/")):
            self.http_calls.append((endpoint, maximum, timeout))
            if self.after_http: self.after_http(len(self.http_calls), receiver)
            return copy.deepcopy(self.tag_body)
        return super().json(receiver, endpoint, maximum=maximum, timeout=timeout)


class TagRepository(MemoryRepository):
    def __init__(self, fixture):
        super().__init__(fixture)
        self.ledger = fixture.ledger
        self.journal = b"retained opaque unrelated hosted/Play journal bytes"
        self.commits = {self.head: (self.ledger, self.journal)}
        self.context = fixture.binding_context
        self.source_commit = fixture.final
        self.tag = None
        self.claim_puts = self.tag_posts = 0
        self.after_response = None

    def send(self, role, request):
        if role in bind.ROLES or request.path.endswith("git/commits/" + self.fixture.final):
            self.calls.append((role, request))
            if self.before: self.before(role, request)
            if role == bind.READ:
                result = reply(status=404) if self.tag is None else reply(copy.deepcopy(self.tag))
            elif role == bind.CLAIM:
                self.claim_puts += 1
                body = json.loads(request.body)
                if self.fault == "claim-before": raise OSError("PRIVATE fake error")
                if body["sha"] != a.blob_sha(self.ledger.to_bytes()): return reply(status=409)
                after = a.Ledger.parse(base64.b64decode(body["content"], validate=True), self.fixture.authority)
                assert after.reservations == self.ledger.reservations and tag.preserves(self.ledger, after)
                assert len(after.tag_bindings) == len(self.ledger.tag_bindings) + 1
                self.ledger = after; self.advance()
                if self.fault == "claim-after": raise OSError("PRIVATE fake error")
                result = reply({"content": {"path": a.LEDGER_PATH, "sha": a.blob_sha(after.to_bytes())},
                                "commit": {"sha": self.head}})
            elif role == bind.CREATE:
                self.tag_posts += 1
                if self.fault == "post-before": raise OSError("PRIVATE fake error")
                if self.tag is not None: return reply(status=422)
                body = json.loads(request.body)
                assert set(body) == {"ref", "sha"} and body == {"ref": TAG, "sha": self.fixture.final}
                self.tag = {"ref": body["ref"], "object": {"type": "commit", "sha": body["sha"]}}
                if self.fault == "post-after": raise OSError("PRIVATE fake error")
                result = reply(copy.deepcopy(self.tag), 201)
            else:
                result = reply({"sha": self.fixture.final, "tree": {"sha": self.fixture.after_tree}})
        else:
            result = super().send(role, request)
        if self.after_response: self.after_response(role, request, result)
        return result


class HostedTagTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.fixture = TaggedFixture(Path(self.temp.name))
        self.repo = TagRepository(self.fixture)
        self.settings = ci.Settings(self.fixture.authority,
            a.Checkpoint(len(self.repo.ledger.reservations), self.repo.ledger.head_sha256, self.repo.head))

    def run_bind(self, *, context=None):
        f = self.fixture
        context = context or f.binding_context
        env = {"MOBILE_RELEASE_SELECTED_PLATFORM": context.platform, "MOBILE_RELEASE_OPERATION": "bind-version-tag",
               host.TOKEN_ENV: "INERT-not-a-token", ci.AUTHORITY_ENV: p.canonical({"schemaVersion": 1,
                   "authority": self.settings.authority.value(), "checkpoint": self.settings.checkpoint.value()}).decode()}
        for name in ("MOBILE_RELEASE_RECOVERY_RUN_ID", "MOBILE_RELEASE_RECOVERY_CONFIRMATION", "MOBILE_RELEASE_DESKTOP_REQUEST",
                     "MOBILE_RELEASE_DESKTOP_SOURCE_SHA", "MOBILE_RELEASE_DESKTOP_EXPECTED_REF"): env[name] = ""
        def factory(token, **kwargs):
            self.assertEqual(token, "INERT-not-a-token")
            self.assertEqual(kwargs["_profile"], http._ExchangeProfile.HOSTED_VERSION_TAG_BIND)
            self.assertEqual(kwargs["_hosted_ca_sha256"], hashlib.sha256(f.ca).hexdigest())
            self.assertEqual(kwargs["started"], f.clock)
            return lambda method, path, body, *, _role: self.repo.send(_role.value, HttpRequest(method, path, body))
        with patch.dict(os.environ, env), patch.object(workflow.Context, "current", return_value=context), \
             patch.object(ci, "run_owned", f.bind_git), patch.object(http, "_make_live_exchange", factory), \
             patch.object(ci.time, "monotonic", lambda: f.clock), patch("subprocess.Popen", side_effect=AssertionError("no child")), \
             patch.object(host, "_reserve", side_effect=AssertionError("no reservation/Store")):
            return bind.bind(f.root, f.tooling)

    def test_real_owner_fixed_ca_full_proof_claim_then_only_create_with_16_git_25_http(self):
        before = self.repo.ledger.to_bytes(); journal = self.repo.journal
        result = self.run_bind()
        self.assertEqual(result["status"], "bound")
        self.assertEqual((len(self.fixture.git_calls), len(self.repo.calls)), (16, 25))
        self.assertEqual((self.repo.claim_puts, self.repo.tag_posts, self.repo.journal_puts), (1, 1, 0))
        self.assertEqual([role for role, _ in self.repo.calls][12:20],
                         [bind.CLAIM, host.READ, host.READ, host.READ, bind.READ, host.READ, bind.CREATE, bind.READ])
        self.assertEqual(a.Ledger(self.repo.ledger.genesis, self.repo.ledger.reservations).to_bytes(), before)
        self.assertEqual(self.repo.journal, journal)
        self.assertEqual(result["futureTag"], TAG)
        self.assertEqual(result["sourceBranch"], BRANCH)
        self.assertFalse(result["tagTriggeredBuild"])
        self.assertEqual(result["store"], "not-entered")
        self.assertNotIn("INERT-not-a-token", str(result))

    def test_loaded_claim_is_read_only_observed_or_unresolved_never_another_post(self):
        self.run_bind()
        count = len(self.repo.calls)
        result = self.run_bind()
        self.assertEqual(result["status"], "observed")
        self.assertTrue(all(r.method == "GET" for _, r in self.repo.calls[count:]))
        self.repo.tag = None
        result = self.run_bind()
        self.assertEqual(result["status"], "unresolved")
        self.assertEqual((self.repo.claim_puts, self.repo.tag_posts), (1, 1))
        self.assertEqual(len(self.repo.ledger.tag_bindings), 1)

    def test_lost_claim_and_post_ack_preserve_claim_no_replay_or_false_created(self):
        for failure in ("claim-after", "post-before", "post-after"):
            with self.subTest(failure=failure):
                self.setUp(); self.repo.fault = failure
                with self.assertRaises(Exception): self.run_bind()
                original = self.repo.ledger.to_bytes()
                posts = self.repo.tag_posts; self.repo.fault = None
                result = self.run_bind()
                self.assertEqual(result["status"], "observed" if failure == "post-after" else "unresolved")
                self.assertEqual(self.repo.ledger.to_bytes(), original)
                self.assertEqual((self.repo.claim_puts, self.repo.tag_posts), (1, posts))

    def test_preexisting_even_exact_or_annotated_tag_refuses_before_claim(self):
        for kind, target in (("commit", self.fixture.before_commit), ("commit", self.fixture.final), ("tag", self.fixture.final)):
            with self.subTest(kind=kind, target=target):
                self.repo.tag = {"ref": TAG, "object": {"type": kind, "sha": target}}
                with self.assertRaises(host.Refused) as caught: self.run_bind()
                self.assertEqual(caught.exception.reason, "tag-exists")
                self.assertEqual((self.repo.claim_puts, self.repo.tag_posts), (0, 0))

    def test_changed_full_claim_final_is_not_a_new_candidate_or_once_key(self):
        self.run_bind()
        row = self.repo.ledger.tag_bindings[0]
        self.repo.ledger = replace(self.repo.ledger, tag_bindings=(replace(row, final_commit="9" * 40),))
        self.repo.advance()
        with self.assertRaises(ValueError): self.run_bind()
        self.assertEqual((self.repo.claim_puts, self.repo.tag_posts), (1, 1))

    def test_prepost_counter_drift_requires_exact_read_claim_commit_not_ancestor(self):
        def before(role, request):
            if len(self.repo.calls) == 18:
                self.repo.advance()  # Even same contents on an unread successor refuses.
        self.repo.before = before
        with self.assertRaises(host.Refused): self.run_bind()
        self.assertEqual((self.repo.claim_puts, self.repo.tag_posts), (1, 0))
        self.assertEqual(len(self.repo.ledger.tag_bindings), 1)

    def test_bad_claim_readback_late_original_return_or_terminal_read_cannot_create_success(self):
        for point, fault in ((14, "bad"), (14, "late"), (19, "late"), (23, "bad")):
            with self.subTest(point=point, fault=fault):
                self.setUp()
                def after(role, request, result):
                    if len(self.repo.calls) == point:
                        if fault == "late": self.fixture.clock += 61
                        else: result.observation["body"]["sha"] = "0" * 40
                self.repo.after_response = after
                with self.assertRaises(Exception): self.run_bind()
                self.assertEqual(self.repo.claim_puts, 1)
                self.assertEqual(self.repo.tag_posts, 0 if point == 14 else 1)
                self.assertIsNotNone(self.repo.ledger.tag_bindings[0])

    def test_branch_advance_or_any_extra_diff_or_wrong_parent_prevents_claim(self):
        for fault in ("branch", "diff", "parent"):
            with self.subTest(fault=fault):
                self.setUp()
                if fault == "branch": self.repo.source_commit = "9" * 40
                elif fault == "diff": self.fixture.delta += self.fixture.delta
                else:
                    raw = commit(self.fixture.after_tree, self.fixture.message, (self.fixture.before_commit, "d" * 40))
                    self.fixture.commits[self.fixture.final] = raw  # Also fails genuine object hash.
                with self.assertRaises(Exception): self.run_bind()
                self.assertEqual((self.repo.claim_puts, self.repo.tag_posts), (0, 0))

    def test_dispatch_context_sha_cannot_be_relabelled_and_no_store_secret_is_required(self):
        wrong = replace(self.fixture.binding_context, authority={**self.fixture.binding_context.authority, "headSha": "9" * 40})
        with self.assertRaises(host.Refused): self.run_bind(context=wrong)
        self.assertEqual(self.repo.calls, [])
        self.assertEqual(self.fixture.git_calls, [])
        with patch("mobile_release.version_hosted_store.Material", side_effect=AssertionError("no Store material")):
            self.assertEqual(self.run_bind()["status"], "bound")

    def test_closed_http_roles_and_original_budgets_do_not_authorize_generic_ref_changes(self):
        prefix = "/repos/" + self.fixture.authority.repository
        body = p.canonical({"ref": TAG, "sha": self.fixture.final})
        bind.validate_body(bind.CREATE, body, path=prefix + "/git/refs")
        for changed in ({"ref": BRANCH}, {"force": True}, {"ref": "refs/tags/../x"}, {"sha": "X" * 40}):
            with self.assertRaises(Exception):
                bind.validate_body(bind.CREATE, p.canonical({**json.loads(body), **changed}), path=prefix + "/git/refs")
        for method in ("PATCH", "PUT", "DELETE"):
            with self.assertRaises(host.Refused): bind.validate_endpoint(bind.CREATE, method, prefix + "/git/refs")
        for profile, count in ((http._ExchangeProfile.HOSTED_VERSION, 44),
                               (http._ExchangeProfile.HOSTED_VERSION_TAG_BIND, 25),
                               (http._ExchangeProfile.HOSTED_VERSION_TAG_RESERVE, 45)):
            budget = http._Budget(100, monotonic=lambda: 101, _profile=profile)
            self.assertEqual(budget.end, 160)
            for _ in range(count): budget.claim_request()
            with self.assertRaises(http.ReadFailure): budget.claim_request()
        for profile in (http._ExchangeProfile.HOSTED_VERSION, http._ExchangeProfile.HOSTED_VERSION_TAG_RESERVE):
            with self.assertRaises(ValueError): http._role_limits(profile, http._ResponseRole.HOSTED_VERSION_TAG_CREATE)
        self.assertEqual(ci.MAX_GIT_CALLS, 12)
        self.assertEqual(ci.MAX_HTTP_CALLS, 8)

    def test_branch_ci_requires_v5_binding_and_both_fresh_tag_reads_without_allocation(self):
        self.run_bind()
        f = self.fixture; f.ledger = self.repo.ledger
        f.tag_body = copy.deepcopy(self.repo.tag)
        f.git_calls.clear(); f.http_calls.clear()
        checked = f.run()
        self.assertEqual((checked.candidate_id, checked.source_commit), (f.request.candidate_id, f.final))
        self.assertEqual((len(f.git_calls), len(f.http_calls)), (10, 10))
        for fault in ("missing-claim", "annotation", "late-tag"):
            with self.subTest(fault=fault):
                f.ledger = self.repo.ledger; f.tag_body = copy.deepcopy(self.repo.tag)
                f.http_calls.clear(); f.git_calls.clear(); f.after_http = None
                if fault == "missing-claim": f.ledger = replace(f.ledger, tag_bindings=())
                elif fault == "annotation": f.tag_body["object"]["type"] = "tag"
                else:
                    def change(count, receiver):
                        if count == 10: f.tag_body["object"]["sha"] = "9" * 40
                    f.after_http = change
                with self.assertRaises(ValueError): f.run()

    def test_future_hosted_reserve_keeps_original_journal_cas_and_38_ios_schedule(self):
        f = self.fixture
        repo = MemoryRepository(f); source = SourceData(f); source.future_tag = TAG
        source.context = replace(source.context, confirmation="reserve-future-tag:ios:" + TAG)
        repo.context = source.context
        old_send = repo.send
        def send(role, request):
            if role == bind.READ:
                repo.calls.append((role, request)); return reply(status=404)
            return old_send(role, request)
        remote = bind._ReservationRemote(f.authority, source, send)
        settings = ci.Settings(f.authority, a.Checkpoint(0, repo.ledger.head_sha256, repo.head))
        result = host._reserve(source, settings, f.request.version_policy, remote, StoreData(f))
        self.assertEqual((result["futureTag"], result["sourceRef"], result["status"]), (TAG, BRANCH, "reserved"))
        self.assertEqual((len(repo.calls), repo.journal_puts, repo.ledger_puts), (38, 5, 1))
        original = host.Envelope.parse(repo.journal)
        self.assertEqual(original.state.candidates[0].request.future_tag, TAG)
        self.assertEqual(original.state.candidates[0].request.source, f.request.source)


if __name__ == "__main__": unittest.main()
