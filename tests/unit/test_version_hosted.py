"""Inert repository/object/clock doubles; no network, subprocess or native ACK.

The real existing Ledger, state transitions, transport schedule, allocator and
version renderer run against those doubles. This is not hosted qualification.
"""
import base64
import copy
import json
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import version_hosted as h
from mobile_release import version_allocation as a
from mobile_release import version_allocation_state as s
from mobile_release import version_policy as p
from mobile_release import version_ci as ci
from mobile_release import ios_store_versions as ios
from mobile_release import _github_connection_transport as transport
from mobile_release.github_preflight import HttpRequest
from test_version_ci import Fixture, NOW, BRANCH


def reply(body=None, status=200):
    return transport.ReadResult({"status": status, "body": body, "failure": "none"}, transport._control())


class MemoryRepository:
    """A synthetic Git object graph. Never used by a production factory."""
    def __init__(self, fixture):
        self.fixture = fixture
        self.ledger = a.Ledger(fixture.ledger.genesis)
        self.journal = None
        self.head = "0" * 39 + "1"
        self.commits = {self.head: (self.ledger, self.journal)}
        self.parents = {self.head: None}
        self.calls, self.ledger_puts, self.journal_puts = [], 0, 0
        self.fault = None
        self.history = []
        self.source_commit = fixture.request.source.commit
        self.foreign = False
        self.before = None

    def advance(self):
        parent = self.head
        self.head = f"{len(self.commits) + 1:040x}"
        self.parents[self.head] = parent
        self.commits[self.head] = (self.ledger, self.journal)

    def ancestor(self, before, after):
        while after is not None:
            if before == after:
                return True
            after = self.parents.get(after)
        return False

    def content(self, raw, path):
        return {"type": "file", "path": path, "encoding": "base64", "size": len(raw),
            "content": base64.b64encode(raw).decode(), "sha": h._blob(raw)}

    def send(self, role, http):
        self.calls.append((role, http))
        if self.before:
            self.before(role, http)
        prefix = "/repos/" + self.fixture.authority.repository
        assert http.path == prefix or http.path.startswith(prefix + "/")
        suffix = http.path[len(prefix):].lstrip("/")
        if http.method == "PUT":
            body = json.loads(http.body)
            assert body["branch"] == a.LEDGER_BRANCH
            raw = base64.b64decode(body["content"], validate=True)
            journal = role == h.JOURNAL_WRITE
            previous = self.journal if journal else self.ledger.to_bytes()
            if body.get("sha") != (None if previous is None else h._blob(previous)):
                return reply(status=409)
            if journal:
                self.journal_puts += 1
                h.Envelope.parse(raw)
                self.journal = raw
            else:
                self.ledger_puts += 1
                retained = h.Envelope.parse(self.journal).state.selected(self.fixture.authority)
                assert retained.pending is not None  # before sole real core PUT
                assert retained.pending.reservation.request == a.Ledger.parse(raw, self.fixture.authority).reservations[-1].request
                if self.fault == "ledger-before":
                    raise OSError("SYNTHETIC RAW PROVIDER SECRET")
                self.ledger = a.Ledger.parse(raw, self.fixture.authority)
            self.advance()
            if self.fault == ("journal-after" if journal else "ledger-after"):
                raise OSError("SYNTHETIC RAW PROVIDER SECRET")
            return reply({"content": {"path": h.JOURNAL_PATH if journal else a.LEDGER_PATH,
                "sha": h._blob(raw)}, "commit": {"sha": self.head}}, 201 if previous is None else 200)
        if suffix == "":
            return reply({"id": int(self.fixture.authority.repository_id),
                "full_name": self.fixture.authority.repository, "archived": self.foreign,
                "visibility": "private", "default_branch": "main"})
        if suffix.startswith("actions/runs/"):
            context = self.context
            return reply({"id": int(context.authority["runId"]), "run_attempt": context.authority["attempt"],
                "repository": {"id": int(context.repository["id"]), "full_name": context.repository["fullName"]},
                "head_repository": {"id": int(context.repository["id"]), "full_name": context.repository["fullName"]},
                "path": context.authority["callerPath"], "head_sha": context.authority["headSha"],
                "head_branch": "main", "event": "workflow_dispatch", "name": context.authority["workflow"]})
        if suffix.startswith("branches/"):
            return reply({"enforce_admins": {"enabled": True}, "allow_force_pushes": {"enabled": False},
                          "allow_deletions": {"enabled": False}})
        if suffix.startswith("git/ref/"):
            ref = "refs/" + suffix[len("git/ref/"):]
            return reply({"ref": ref, "object": {"type": "commit", "sha": self.head
                if ref == "refs/heads/" + a.LEDGER_BRANCH else self.source_commit}})
        if suffix.startswith("compare/"):
            before, after = suffix[8:].split("?")[0].split("...")
            return reply({"status": ("identical" if before == after else "ahead") if self.ancestor(before, after) else "diverged",
                "base_commit": {"sha": before}, "merge_base_commit": {"sha": before if self.ancestor(before, after) else self.head}})
        if suffix.startswith("contents/"):
            path, commit = suffix[len("contents/"):].split("?ref=")
            ledger, journal = self.commits[commit]
            raw = journal if path == h.JOURNAL_PATH else ledger.to_bytes()
            return reply(status=404) if raw is None else reply(self.content(raw, path))
        if suffix.startswith("commits?"):
            return reply(self.history)
        if suffix.startswith("git/commits/"):
            return reply({"sha": suffix[len("git/commits/"):], "tree": {"sha": self.fixture.request.source.tree}})
        raise AssertionError(suffix)


class SourceData:
    def __init__(self, fixture):
        self.binding = fixture.request.source
        self.base, self.identity = fixture.request.base_version, fixture.request.identity_revision
        self.enabled = fixture.platforms
        self.selection = h.version_text.public_version_selection(fixture.config_raw.decode())
        self.version_raw = fixture.before
        self.checks, self.expired = 0, False
        platform = "both" if len(self.enabled) == 2 else self.enabled[0]
        self.context = replace(fixture.context, current_job="version_reserve", platform=platform, selected_platform=platform,
            confirmation="reserve-version:" + platform + (":temporary-play-edit" if platform != "ios" else ""),
            authority={"workflow": "Mobile internal candidate", "runId": "50", "attempt": 1,
            "callerPath": ".github/workflows/mobile-candidate.yml", "reusableRepository": "trusted/tooling",
            "reusablePath": ".github/workflows/reusable-candidate.yml", "reusableCommit": "e" * 40,
            "headSha": fixture.before_commit, "ref": BRANCH, "event": "workflow_dispatch"})

    def remaining(self):
        h.need(not self.expired)
        return 10

    def epoch(self):
        self.remaining()
        return NOW

    def check(self):
        self.checks += 1
        self.remaining()


class StoreData:
    def __init__(self, fixture):
        self.context_hash = fixture.request.store_context_revision
        self.fail = False
        self.calls = 0
        self.inventory = ios.CurrentInventory(fixture.request.identity_revision, self.context_hash, "d" * 64,
                                              NOW, 7, "1.2.3", (1, 0, 0))

    def context(self, source):
        return self.context_hash

    def observe(self, source, context):
        self.calls += 1
        h.need(not self.fail, "store")
        return self.inventory


class HostedAllocationTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = Fixture(Path(self.temp.name), 2)
        self.repo = MemoryRepository(self.fixture)
        self.settings = ci.Settings(self.fixture.authority,
            a.Checkpoint(0, self.repo.ledger.head_sha256, self.repo.head))
        self.policy = self.fixture.request.version_policy
        self.source = SourceData(self.fixture)
        self.repo.context = self.source.context
        self.material = StoreData(self.fixture)

    def remote(self):
        return h._Remote(self.fixture.authority, self.source, self.repo.send)

    def run_reserve(self, remote=None):
        return h._reserve(self.source, self.settings, self.policy, remote or self.remote(), self.material)

    def journal(self):
        journal = h._Journal(self.remote(), self.settings)
        journal.load()
        return journal

    def make_request(self, candidate):
        return replace(self.fixture.request, candidate_id=candidate)

    def test_actual_allocator_pending_ack_then_single_put_final_state_and_exact_two_spans(self):
        remote = self.remote()
        result = self.run_reserve(remote)
        self.assertEqual((result["status"], self.repo.ledger_puts, result["version"]["build"]), ("reserved", 1, 8))
        self.assertEqual(self.repo.journal_puts, 5)
        self.assertLessEqual(remote.calls, h.MAX_REQUESTS)
        final = h.Envelope.parse(self.repo.journal)
        self.assertIsNone(final.state.selected(self.fixture.authority).pending)
        self.assertEqual(final.state.candidates[0].reservation, self.repo.ledger.reservations[0])
        self.assertEqual(result["candidateId"], final.state.candidates[0].request.candidate_id)
        changed = self.fixture.before
        for row in sorted(result["versionFile"]["replacements"], key=lambda row: row["start"], reverse=True):
            changed = changed[:row["start"]] + row["value"].encode() + changed[row["end"]:]
        self.assertEqual(changed, self.fixture.after)
        self.assertNotIn("# Exact comments", str(result))
        self.assertEqual(result["historicalUniqueness"], "not-established")
        self.assertTrue(all(http.method in {"GET", "PUT"} and (http.method != "PUT" or
            http.path.endswith((a.LEDGER_PATH, h.JOURNAL_PATH))) for _, http in self.repo.calls))

    def test_same_source_run_attempt_reuses_original_uuid_data_and_real_revision_cas(self):
        first = self.run_reserve()
        revision = h.Envelope.parse(self.repo.journal).revision
        second = self.run_reserve()
        self.assertEqual((first["candidateId"], first["version"], first["rowSha256"]),
                         (second["candidateId"], second["version"], second["rowSha256"]))
        self.assertEqual(self.repo.ledger_puts, 1)
        self.assertGreater(h.Envelope.parse(self.repo.journal).revision, revision)

    def test_two_fresh_journal_writers_cannot_replace_selection_or_send_ledger(self):
        left, right = self.journal(), self.journal()
        winner = left.choose(self.make_request)
        with self.assertRaises(h.Refused):
            right.choose(self.make_request)
        self.assertTrue(right._poisoned)
        self.assertEqual(self.repo.ledger_puts, 0)
        retry = self.journal().choose(self.make_request)
        self.assertEqual(retry, winner)

    def test_same_key_changed_full_request_refuses_without_new_selection_or_store(self):
        self.run_reserve()
        writes, calls = self.repo.journal_puts, self.material.calls
        self.policy = replace(self.policy, rules=(p.RefRule(BRANCH, "minor"),))
        with self.assertRaises(h.Refused):
            self.run_reserve()
        self.assertEqual((self.repo.journal_puts, self.material.calls), (writes, calls))

    def test_missing_journal_after_history_or_rewound_checkpoint_is_never_initialized(self):
        self.repo.history = [{"sha": "a" * 40}]
        journal = h._Journal(self.remote(), self.settings)
        with self.assertRaises(h.Refused):
            journal.load()
        calls = len(self.repo.calls)
        self.assertTrue(journal._poisoned)
        with self.assertRaises(ValueError): journal.choose(self.make_request)
        self.assertEqual(len(self.repo.calls), calls)
        self.assertEqual(self.repo.journal_puts, 0)
        self.repo.history = []
        self.settings = replace(self.settings, checkpoint=replace(self.settings.checkpoint, commit="f" * 40))
        with self.assertRaises(ValueError):
            self.run_reserve()
        self.assertEqual(self.repo.journal_puts, 0)

    def test_lost_selection_ack_keeps_complete_request_and_blocks_same_original(self):
        journal = self.journal()
        self.repo.fault = "journal-after"
        with self.assertRaises(h.Refused):
            journal.choose(self.make_request)
        original = h.Envelope.parse(self.repo.journal).state.candidates[0].request
        self.repo.fault = None
        with self.assertRaises(ValueError):
            journal.choose(self.make_request)
        with self.assertRaises(ValueError):
            journal.load()
        self.assertEqual(self.journal().choose(self.make_request), original)
        self.assertEqual(self.repo.ledger_puts, 0)

    def test_lost_ledger_ack_reconciles_read_only_and_absence_never_replays(self):
        for fault in ("ledger-before", "ledger-after"):
            with self.subTest(fault=fault):
                self.setUp()
                self.repo.fault = fault
                with self.assertRaises(h.Refused):
                    self.run_reserve()
                pending = h.Envelope.parse(self.repo.journal).state.selected(self.fixture.authority).pending
                self.assertIsNotNone(pending)
                self.repo.fault = None
                if fault == "ledger-after":
                    result = self.run_reserve()
                    self.assertEqual(result["candidateId"], pending.reservation.request.candidate_id)
                else:
                    with self.assertRaises(h.Refused):
                        self.run_reserve()
                    self.assertEqual(h.Envelope.parse(self.repo.journal).state.selected(self.fixture.authority).pending, pending)
                self.assertEqual(self.repo.ledger_puts, 1)

    def test_concurrent_desktop_ledger_cas_conflict_keeps_candidate_no_loop(self):
        def compete(role, http):
            if role == h.LEDGER_WRITE:
                self.repo.before = None
                other = replace(self.fixture.request, candidate_id="00000000-0000-4000-8000-000000000099")
                self.repo.ledger = self.repo.ledger.append(other, (self.material.inventory,), now=NOW)
                self.repo.advance()
        self.repo.before = compete
        with self.assertRaises(h.Refused):
            self.run_reserve()
        retained = h.Envelope.parse(self.repo.journal).state
        self.assertIsNone(retained.selected(self.fixture.authority).pending)
        original_id = retained.candidates[0].request.candidate_id
        self.assertEqual(self.repo.ledger_puts, 0)
        result = self.run_reserve()
        self.assertEqual((result["candidateId"], result["version"]["build"]), (original_id, 9))
        self.assertEqual(len(self.repo.ledger.reservations), 2)

    def test_current_store_failure_or_consumed_reuse_never_falls_back(self):
        self.material.fail = True
        with self.assertRaises(h.Refused):
            self.run_reserve()
        self.assertEqual(self.repo.ledger_puts, 0)
        self.material.fail = False
        result = self.run_reserve()
        self.material.inventory = replace(self.material.inventory, max_build=result["version"]["build"])
        with self.assertRaises(p.VersionPolicyError):
            self.run_reserve()
        self.assertEqual(self.repo.ledger_puts, 1)

    def test_source_drift_after_pending_ack_refuses_put_and_preserves_intent(self):
        def change(role, request):
            if role == h.JOURNAL_READ and self.repo.journal is not None:
                selected = h.Envelope.parse(self.repo.journal).state.selected(self.fixture.authority)
                if selected.pending is not None:
                    self.repo.source_commit = "d" * 40
        self.repo.before = change
        with self.assertRaises(h.Refused):
            self.run_reserve()
        self.assertEqual(self.repo.ledger_puts, 0)
        self.assertIsNotNone(h.Envelope.parse(self.repo.journal).state.selected(self.fixture.authority).pending)

    def test_after_write_interrupt_and_reentrant_callback_keep_original_poisoned(self):
        journal = self.journal()
        original = self.repo.send
        def interrupt(role, http):
            if role == h.JOURNAL_WRITE:
                with self.assertRaises(ValueError): journal.choose(self.make_request)
                original(role, http)
                raise KeyboardInterrupt()
            return original(role, http)
        journal.remote.send = interrupt
        with self.assertRaises(KeyboardInterrupt): journal.choose(self.make_request)
        self.assertTrue(journal._poisoned)
        with self.assertRaises(ValueError): journal.choose(self.make_request)
        self.assertEqual((self.repo.journal_puts, self.repo.ledger_puts), (1, 0))
        retained = h.Envelope.parse(self.repo.journal).state.candidates[0].request
        self.assertEqual(self.journal().choose(self.make_request), retained)

    def test_unchanged_state_still_cas_detects_another_acknowledged_revision(self):
        self.run_reserve()
        left, right = self.journal(), self.journal()
        request = left.choose(self.make_request)
        right.choose(self.make_request)
        row = self.repo.ledger.find(request)
        checkpoint = left.checkpoint(self.settings.authority)
        before = self.repo.journal
        left.record_reused(self.settings.authority, row, checkpoint)
        self.assertNotEqual(before, self.repo.journal)
        self.assertEqual(h.Envelope.parse(before).state, h.Envelope.parse(self.repo.journal).state)
        with self.assertRaises(h.Refused): right.record_reused(self.settings.authority, row, checkpoint)
        self.assertTrue(right._poisoned)
        self.assertEqual(self.repo.ledger_puts, 1)

    def test_late_or_wrong_journal_readback_ack_cannot_release_a_ledger_write(self):
        for wrong in ('late', 'bytes'):
            with self.subTest(wrong=wrong):
                self.setUp()
                original = self.repo.send
                def refuse(role, http):
                    result = original(role, http)
                    if role == h.JOURNAL_READ and self.repo.journal is not None:
                        if wrong == 'late': self.source.expired = True
                        else: result.observation['body']['sha'] = 'f' * 40
                    return result
                remote = self.remote(); remote.send = refuse
                with self.assertRaises(h.Refused): self.run_reserve(remote)
                self.assertEqual((self.repo.journal_puts, self.repo.ledger_puts), (1, 0))
                self.assertIsNotNone(self.repo.journal)

    def test_hosted_subcap_before_state_parse_and_before_any_cas(self):
        malformed = p.canonical({"revision": 1, "state": {"candidates": [{"x": 0}] * 5000}}) + b"\n"
        self.assertLess(len(malformed), h.MAX_STATE_BYTES)
        with patch.object(s.AllocationState, "parse", side_effect=AssertionError("must reject before ordinary parser")):
            with self.assertRaises(h.Refused):
                h.Envelope.parse(malformed)
        journal = self.journal()
        with patch.object(h, "MAX_STATE_BYTES", 128):
            with self.assertRaises(h.Refused):
                journal.choose(self.make_request)
        self.assertEqual(self.repo.journal_puts, 0)

    def test_fixed_roles_prohibit_other_paths_methods_bodies_and_profile_borrowing(self):
        path = "/repos/fixture/ci-reservation/contents/" + h.JOURNAL_PATH
        for method, suffix in (("DELETE", ""), ("POST", ""), ("PUT", "/extra"), ("PUT", "?ref=main")):
            with self.assertRaises(h.Refused):
                h.validate_endpoint(h.JOURNAL_WRITE, method, path + suffix)
        for role in h._ROLES:
            enum = next(item for item in transport._ResponseRole if item.value == role)
            with self.assertRaises(ValueError):
                transport._role_limits(transport._ExchangeProfile.VERSION_ALLOCATION, enum)
        with self.assertRaises(h.Refused):
            h.validate_endpoint("standard", "GET", "/repos/fixture/ci-reservation")
        budget = transport._Budget(100, monotonic=lambda: 101, _profile=transport._ExchangeProfile.HOSTED_VERSION)
        self.assertEqual((budget.end, budget.body_total_limit), (160, 10 * 1024 * 1024))
        for _ in range(44):
            budget.claim_request()
        with self.assertRaises(transport.ReadFailure):
            budget.claim_request()

    def test_explicit_default_or_wrong_job_never_selects_or_writes(self):
        env = {ci.AUTHORITY_ENV: p.canonical({"schemaVersion": 1, "authority": self.settings.authority.value(),
            "checkpoint": self.settings.checkpoint.value()}).decode(), h.POLICY_ENV: p.canonical(self.policy.value()).decode(),
            "MOBILE_RELEASE_OPERATION": "reserve-version", h.TOKEN_ENV: "INERT-same-job-App-token"}
        with patch.dict(h.os.environ, env, clear=True):
            self.assertEqual(h._admit(self.source.context), (self.settings, self.policy))
            for changed in (replace(self.source.context, current_job="ios_build"),
                            replace(self.source.context, selected_platform="both"),
                            replace(self.source.context, confirmation="candidate:ios:1.2.3:7")):
                with self.assertRaises(h.Refused):
                    h._admit(changed)
            with patch.dict(h.os.environ, {"MOBILE_RELEASE_OPERATION": "candidate"}):
                with self.assertRaises(h.Refused):
                    h._admit(self.source.context)
            for token in ("", "INERT with space", "x" * 4097):
                with patch.dict(h.os.environ, {h.TOKEN_ENV: token, "GH_TOKEN": "INERT-ambient"}):
                    with self.assertRaises(h.Refused) as refused:
                        h._admit(self.source.context)
                    self.assertEqual(refused.exception.reason, "credential")
        self.assertEqual(self.repo.calls, [])
