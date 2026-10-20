"""Hosted platform behaviour with synthetic Git/provider/HTTP boundaries.

Real existing source hashes, Material, frame parsers, allocation/state CAS and
two-span renderer are exercised. No Git, Ruby, network or credential runs.
One named test uses only the actual private finite-scratch file owner.
"""
import base64
import copy
from contextlib import contextmanager, ExitStack
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import version_hosted as h
from mobile_release import version_hosted_store as store
from mobile_release import version_ci as ci
from mobile_release import android_store_versions as android
from mobile_release import ios_store_versions as ios
from mobile_release import paired_store_versions as paired
from mobile_release import workflow
from mobile_release.build_inputs import finite_scratch
from mobile_release.cancellation import CleanupScope, DefaultCancellation
from mobile_release.owned_process import ProcessCleanupError
from test_version_ci import Fixture, NOW, oid
from test_version_hosted import MemoryRepository, SourceData


def google():
    return {"type": "service_account", "project_id": "inert-project",
        "private_key_id": "a" * 40, "private_key": "-----BEGIN PRIVATE KEY-----\nINERT\n-----END PRIVATE KEY-----\n",
        "client_email": "inert@inert-project.iam.gserviceaccount.com", "client_id": "123",
        "token_uri": "https://oauth2.googleapis.com/token"}


def environment(platform):
    result = {"PATH": "/inert", h.TOKEN_ENV: "INERT-App-token", "GH_TOKEN": "INERT-unrelated-token",
              "RUBYOPT": "-rINERT", "HTTPS_PROXY": "INERT", "SSL_CERT_FILE": "/ambient/INERT"}
    if platform in ("ios", "both"):
        result.update({store._KEY: "ABCDEFGHIJ", store._ISSUER: "00000000-0000-4000-8000-000000000001",
            store._P8: base64.b64encode(b"INERT P8 input; never parsed or used as a key").decode()})
    if platform in ("android", "both"):
        result[store._GOOGLE] = base64.b64encode(h.p.canonical(google()) + b"\n").decode()
    return result


class Case:
    """One inert attempt; only _Source/Material/allocator production types run."""
    def __init__(self, test, root, schema):
        self.test, self.root, self.clock = test, root, 100.0
        self.fixture = Fixture(root, schema)
        self.platform = {2: "ios", 3: "android", 4: "both"}[schema]
        self.tooling = root / "tooling"; self.tooling.mkdir()
        self.repo = MemoryRepository(self.fixture)
        self.context = SourceData(self.fixture).context
        self.repo.context = self.context
        self.settings = ci.Settings(self.fixture.authority, h.a.Checkpoint(0, self.repo.ledger.head_sha256, self.repo.head))
        self.policy = self.fixture.request.version_policy
        self.events, self.provider_calls, self.source = [], [], None
        self.failure = self.after_write = None
        self.after_child = None
        self.play_build = 13
        self.google_raw = self.google_snapshot = None
        self.ca = b"INERT fixed CA bytes, no SSL call\n"
        config = copy.deepcopy(self.fixture.config)
        if "ios" in self.fixture.platforms:
            config["ios"]["appStoreAppId"] = "1234567890"
        self.config_raw = h.p.canonical(config)
        self.blobs = {oid("blob", b): b for b in (self.config_raw, self.fixture.before, self.ca)}

    def current(self):
        h.need(self.failure != "stop", "read")

    def git(self, argv, **kwargs):
        args = argv[argv.index("-C") + 2:]
        self.test.assertFalse({h.TOKEN_ENV, "GH_TOKEN", store._P8, store._GOOGLE} & kwargs["environ"].keys())
        self.events.append(("git", tuple(args)))
        if args == ["rev-parse", "--verify", "HEAD"]:
            raw = (self.context.trusted_tooling_commit if kwargs["cwd"] == self.tooling
                   else self.fixture.before_commit) + "\n"
            return subprocess.CompletedProcess(argv, 0, raw.encode(), b"")
        if args[:2] == ["cat-file", "commit"]:
            raw = self.fixture.before_commit_raw
        elif args[:2] == ["cat-file", "blob"]:
            raw = self.blobs[args[2]]
        else:
            self.test.assertEqual(args[:3], ["ls-tree", "-z", "--full-tree"])
            self.test.assertEqual(args[-2], "--")
            path = args[-1]
            content = self.config_raw if path == h.version_text.CONFIG_PATH else self.ca if path == h.CA_PATH else self.fixture.before
            raw = f"100644 blob {oid('blob', content)}\t{path}\0".encode()
        return subprocess.CompletedProcess(argv, 0, raw, b"")

    def send(self, role, request):
        self.events.append(("http", role, request.method))
        result = self.repo.send(role, request)
        if role == h.JOURNAL_WRITE:
            value = h.Envelope.parse(self.repo.journal)
            self.events.append(("journal", value.revision, value.play_query is not None))
            if self.repo.journal_puts == self.after_write:
                raise OSError("INERT lost journal ACK")
        return result

    def play_frame(self, context):
        edit = "INERT-edit-private"
        data = [("insert", {"id": edit, "expiryTimeSeconds": "99999"}),
                ("tracks", {"tracks": [{"track": "internal", "releases": [{"status": "draft", "versionCodes": ["11"]}]}]}),
                ("bundles", {"bundles": [{"versionCode": 12}]}),
                ("apks", {"apks": [{"versionCode": self.play_build}]}), ("delete", b"")]
        value = {"schemaVersion": 1, "scope": android.SCOPE, "contextSha256": context,
            "packageName": self.source.package, "pages": [], "queryFinished": True,
            "temporaryEdit": {"insertAttempted": True, "editId": edit, "deleteAttempted": True, "deleteConfirmed": True}}
        for step, body in data:
            raw = body if type(body) is bytes else h.p.canonical(body)
            value["pages"].append({"step": step, "request": android.request(step, self.source.package,
                None if step == "insert" else edit), "response": {"status": 204 if step == "delete" else 200,
                "failure": None, "bodyBase64": base64.b64encode(raw).decode()}})
        if self.failure == "delete":
            value["temporaryEdit"]["deleteConfirmed"] = False
            value["pages"][-1]["response"].update(status=500, bodyBase64=base64.b64encode(b"INERT PRIVATE ERROR").decode())
        elif self.failure == "unsupported":
            value["pages"][3]["response"]["bodyBase64"] = base64.b64encode(h.p.canonical({"apks": [{"versionCode": "1.2"}]})).decode()
        elif self.failure == "not-started":
            value.update(pages=[], queryFinished=False, temporaryEdit={"insertAttempted": False,
                "editId": None, "deleteAttempted": False, "deleteConfirmed": False})
        elif self.failure == "wrong-context":
            value["contextSha256"] = "f" * 64
        return value

    def ios_frame(self, context):
        app = {"data": {"type": "apps", "id": self.source.app_id, "attributes": {"bundleId": self.source.bundle_id}}}
        pages = []
        for step in ("app-before", *ios.COLLECTIONS, "app-after"):
            rows = [{"type": "appStoreVersions", "id": "INERT-version", "attributes": {
                "versionString": "2.0.0", "platform": "IOS"}}] if step == "appStoreVersions" else []
            raw = h.p.canonical(app if step.startswith("app-") else {"data": rows,
                "links": {"next": None}, "meta": {"paging": {"total": len(rows), "limit": 200}}})
            pages.append({"step": step, "request": ios.request(step, self.source.app_id),
                "response": {"status": 200, "failure": None, "bodyBase64": base64.b64encode(raw).decode()}})
        return {"schemaVersion": 1, "scope": ios.SCOPE, "contextSha256": context,
            "appStoreAppId": self.source.app_id, "bundleId": self.source.bundle_id, "pages": pages,
            "queryFinished": self.failure != "ios"}

    @contextmanager
    def scratch(self, *, layout, cancellation):
        self.test.assertIs(cancellation, self.source.guard)
        self.events.append(("scratch-enter", layout))
        def put(role, raw):
            self.test.assertEqual((layout, role), ("store-selection", "google-adc"))
            self.google_raw, self.google_snapshot = raw, object()
            return self.google_snapshot
        def require(snapshot):
            self.test.assertIs(snapshot, self.google_snapshot)
            self.test.assertEqual(self.google_raw, self.material.google)
            self.events.append(("snapshot", "matched"))
            return self.root / "INERT-private-input"
        try:
            yield SimpleNamespace(_path=self.root, put=put, require=require)
        finally:
            self.events.append(("scratch-close", layout))
            if self.failure == "close-" + layout:
                raise OSError("INERT original close failure")

    def child(self, argv, **kwargs):
        platform = "ios" if tuple(argv) == ios.fixed_argv(self.tooling) else "android"
        self.test.assertEqual(tuple(argv), (ios if platform == "ios" else android).fixed_argv(self.tooling))
        self.provider_calls.append(platform); self.events.append(("child", platform))
        env = kwargs["environ"]
        self.test.assertIs(kwargs["cancellation"], self.source.guard)
        self.test.assertEqual((kwargs["text"], kwargs["output_limit"]), (False, 2 * 1024 * 1024))
        self.test.assertFalse({h.TOKEN_ENV, "GH_TOKEN", "HTTPS_PROXY", "RUBYOPT", store._GOOGLE} & env.keys())
        self.test.assertLessEqual(kwargs["timeout"], self.source.end - self.clock)
        if platform == "ios":
            self.test.assertNotIn(store._GAC, env)
            self.test.assertEqual(env[store._P8], os.environ[store._P8])
            value = self.ios_frame(env["MOBILE_RELEASE_ASC_BUNDLE_READ_CONTEXT"])
            self.test.assertIsNone(h.Envelope.parse(self.repo.journal).play_query)
            self.clock += 4
        else:
            self.test.assertFalse(set(store._IOS) & env.keys())
            pending = h.Envelope.parse(self.repo.journal).play_query
            self.test.assertIsNotNone(pending)
            self.test.assertEqual(pending.request_sha256, h.Envelope.parse(self.repo.journal).state.candidates[-1].request.sha256)
            self.test.assertEqual(int(env["MOBILE_RELEASE_PLAY_HARD_END_NS"]), self.source.end * 10**9)
            self.test.assertLessEqual(int(env["MOBILE_RELEASE_PLAY_READ_END_NS"]), (self.source.end - 10) * 10**9)
            value = self.play_frame(env["MOBILE_RELEASE_PLAY_CONTEXT"])
            if self.failure == "child-unknown":
                raise OSError("INERT unjoined child")
        raw = h.p.canonical(value) + b"\n"
        if self.failure == "partial" and platform == "android": raw = raw[:-30]
        completed = subprocess.CompletedProcess(argv, 1 if self.failure == "nonzero" else 0, raw,
            b"INERT PRIVATE STDERR" if self.failure == "stderr" else b"")
        if self.after_child: self.after_child(platform)
        if self.failure == "late" and platform == "android": self.clock = self.source.end
        if self.failure == "changed-key" and platform == "android": os.environ[store._GOOGLE] += "A"
        return completed

    def reserve(self):
        return h._reserve(self.source, self.settings, self.policy, self.remote, self.material)

    def select(self):
        journal = h._Journal(self.remote, self.settings); journal.load()
        request = journal.choose(lambda candidate: replace(self.fixture.request, candidate_id=candidate,
            source=self.source.binding, identity_revision=self.source.identity,
            store_context_revision=self.material.context(self.source)))
        return journal, request

    def restart(self):
        # A genuinely separate synthetic runner reads the same remote bytes.
        # No old Material/currentness/ACK object is adopted by this attempt.
        self.context = replace(self.context, authority={**self.context.authority,
            "attempt": self.context.authority["attempt"] + 1})
        self.repo.context = self.context
        self.source = h._Source(self.root, self.context, SimpleNamespace(check=self.current))
        self.source.capture(); self.source.checked_ca(self.tooling)
        self.material = store.Material(self.tooling, platform=self.platform)
        self.source.material = self.material
        self.remote = h._Remote(self.fixture.authority, self.source, self.send)


class HostedPlatformTests(unittest.TestCase):
    @contextmanager
    def case(self, schema=3):
        with TemporaryDirectory() as temporary, ExitStack() as stack:
            case = Case(self, Path(temporary), schema)
            stack.enter_context(patch.dict(os.environ, environment(case.platform), clear=True))
            stack.enter_context(patch.object(ci.time, "monotonic", lambda: case.clock))
            stack.enter_context(patch.object(h.time, "time", lambda: NOW + .75))
            stack.enter_context(patch.object(ci, "run_owned", case.git))
            stack.enter_context(patch.object(store, "run_owned", case.child))
            stack.enter_context(patch.object(store, "finite_scratch", case.scratch))
            stack.enter_context(patch.object(subprocess, "Popen", side_effect=AssertionError("no process permitted")))
            case.source = h._Source(case.root, case.context, SimpleNamespace(check=case.current))
            case.source.capture(); case.source.checked_ca(case.tooling)
            case.material = store.Material(case.tooling, platform=case.platform)
            case.source.material = case.material
            case.remote = h._Remote(case.fixture.authority, case.source, case.send)
            yield case

    def test_android_and_pair_actual_allocator_one_counter_seven_writes_and_exact_budgets(self):
        for schema in (3, 4):
            with self.subTest(schema=schema), self.case(schema) as c:
                result = c.reserve()
                self.assertEqual(c.provider_calls, ["android"] if schema == 3 else ["ios", "android"])
                self.assertEqual((c.source.git_calls, c.remote.calls, c.repo.journal_puts, c.repo.ledger_puts), (12, 44, 7, 1))
                self.assertEqual(result["version"], {"name": "1.2.3" if schema == 3 else "2.0.0", "build": 14})
                final = h.Envelope.parse(c.repo.journal)
                self.assertEqual(final.schema_version, 2); self.assertIsNone(final.play_query)
                row = final.state.candidates[0].reservation
                self.assertEqual(row, c.repo.ledger.reservations[0])
                self.assertEqual(row.request.enabled_platforms, c.source.enabled)
                self.assertEqual(c.repo.ledger.value()["schemaVersion"], schema)
                self.assertEqual(tuple(o.value()["platform"] for o in row.store_observations), c.source.enabled)
                self.assertEqual({o.observed_at for o in row.store_observations}, {NOW})
                pending_at = c.events.index(("journal", 2, True))
                child_at = c.events.index(("child", "android"))
                clear_at = c.events.index(("journal", 3, False))
                self.assertLess(pending_at, child_at)
                self.assertTrue(any(e[0] == "git" for e in c.events[pending_at + 1:child_at]))
                self.assertEqual(c.events[clear_at - 2:clear_at], [("scratch-close", "store-selection"), ("http", h.JOURNAL_WRITE, "PUT")])
                self.assertTrue(c.material._play_consumed)
                self.assertNotIn("INERT-edit-private", json.dumps(result))
                self.assertNotIn("client_email", c.repo.journal.decode())
                original = c.fixture.before
                for edit in sorted(result["versionFile"]["replacements"], key=lambda e: e["start"], reverse=True):
                    original = original[:edit["start"]] + edit["value"].encode() + original[edit["end"]:]
                self.assertEqual(hashlib.sha256(original).hexdigest(), result["versionFile"]["afterSha256"])

    def test_legacy_ios_digests_envelope_order_and_write_count_unchanged(self):
        with self.case(2) as c:
            expected_identity = h.p.digest({"platform": "ios", "appId": c.source.app_id, "bundleId": c.source.bundle_id})
            expected_context = h.p.digest({"purpose": "hosted-ios-current-inventory/1", "source": c.source.binding.value(),
                "appId": c.source.app_id, "bundleId": c.source.bundle_id,
                "keyId": os.environ[store._KEY], "issuerId": os.environ[store._ISSUER]})
            self.assertEqual(c.source.identity, expected_identity)
            self.assertEqual(c.material.context(c.source), expected_context)
            c.reserve()
            self.assertEqual((c.remote.calls, c.source.git_calls, c.repo.journal_puts), (37, 12, 5))
            final = h.Envelope.parse(c.repo.journal)
            self.assertEqual(final.schema_version, 1)
            self.assertEqual(c.repo.journal, h.p.canonical({"revision": final.revision, "state": final.state.value()}) + b"\n")
            self.assertEqual(sum(e[0] == "git" for e in c.events[:c.events.index(("journal", 1, False))]), 10)

    def test_first_ios_failure_has_zero_play_pending_or_child_and_no_fallback(self):
        with self.case(4) as c:
            c.failure = "ios"
            with self.assertRaises(h.Refused): c.reserve()
            self.assertEqual((c.provider_calls, c.repo.journal_puts, c.repo.ledger_puts), (["ios"], 1, 0))
            self.assertEqual(h.Envelope.parse(c.repo.journal).schema_version, 1)
            with self.assertRaises(h.Refused):
                c.material.observe_android(c.source, c.material.context(c.source),
                    h.PlayQuery(c.fixture.request.candidate_id, c.fixture.request.sha256, c.fixture.request.candidate_id))
            self.assertEqual(c.provider_calls, ["ios"])

    def test_full_retry_and_lost_ledger_ack_preserve_each_new_platform_candidate(self):
        for schema in (3, 4):
            for fault in (None, "ledger-before", "ledger-after"):
                with self.subTest(schema=schema, fault=fault), self.case(schema) as c:
                    c.repo.fault = fault
                    if fault is None:
                        first = c.reserve()
                    else:
                        with self.assertRaises(h.Refused): c.reserve()
                    original = h.Envelope.parse(c.repo.journal).state
                    request = original.candidates[0].request
                    c.repo.fault = None; c.restart()
                    if fault == "ledger-before":
                        with self.assertRaises(h.Refused): c.reserve()
                        self.assertEqual(h.Envelope.parse(c.repo.journal).state.selected(c.fixture.authority).pending,
                                         original.selected(c.fixture.authority).pending)
                    else:
                        result = c.reserve()
                        self.assertEqual(result["candidateId"], request.candidate_id)
                        self.assertEqual(result["rowSha256"], c.repo.ledger.reservations[0].sha256)
                        if fault is None:
                            self.assertEqual((result["rowSha256"], result["version"]), (first["rowSha256"], first["version"]))
                    final = h.Envelope.parse(c.repo.journal)
                    self.assertEqual(final.schema_version, 2)
                    self.assertIsNone(final.play_query)
                    self.assertEqual((len(final.state.candidates), c.repo.ledger_puts), (1, 1))
                    self.assertEqual(final.state.candidates[0].request, request)
                    self.assertLessEqual(c.remote.calls, 44)

    def test_pair_intersection_and_stale_first_material_never_become_android_only(self):
        with self.case(4) as c:
            c.play_build = 9999
            with self.assertRaises(h.Refused): c.reserve()
            self.assertEqual(c.repo.ledger_puts, 0)
            self.assertIsNone(h.Envelope.parse(c.repo.journal).play_query)  # deleted, but exhausted floor
        with self.case(4) as c:
            c.after_child = lambda platform: os.environ.__setitem__(store._KEY, "KLMNOPQRST") if platform == "android" else None
            with self.assertRaises(h.Refused): c.reserve()
            self.assertEqual(c.provider_calls, ["ios", "android"])
            self.assertIsNotNone(h.Envelope.parse(c.repo.journal).play_query)
            self.assertEqual(c.repo.ledger_puts, 0)

    def test_unknown_play_cleanup_or_late_material_or_close_keeps_durable_fence(self):
        for failure in ("delete", "partial", "wrong-context", "nonzero", "stderr", "child-unknown", "late", "changed-key",
                        "close-online-runner", "close-store-selection"):
            with self.subTest(failure=failure), self.case() as c:
                c.failure = failure
                with self.assertRaises(Exception): c.reserve()
                retained = h.Envelope.parse(c.repo.journal)
                self.assertEqual((c.repo.journal_puts, c.repo.ledger_puts), (2, 0))
                self.assertIsNotNone(retained.play_query)
                self.assertFalse(c.material._play_consumed)
                if failure not in ("partial", "wrong-context", "child-unknown"):
                    self.assertEqual(c.material._play_edit_id, "INERT-edit-private")
                if failure != "child-unknown": self.assertIsNotNone(c.material._play_return)
                self.assertNotIn("INERT-edit-private", c.repo.journal.decode())
                # A new runner cannot convert a stale frame/DTO into cleanup.
                c.failure = None; c.clock = 100.0
                os.environ[store._GOOGLE] = environment("android")[store._GOOGLE]
                source = SourceData(c.fixture)
                retry = h._Journal(h._Remote(c.fixture.authority, source, c.repo.send), c.settings); retry.load()
                with self.assertRaises(h.Refused) as error: retry.choose(lambda candidate: c.fixture.request)
                self.assertEqual(error.exception.reason, "play-pending")
                self.assertEqual(len(c.provider_calls), 1)

    def test_confirmed_cleanup_can_clear_unsupported_or_not_started_but_not_allocate(self):
        for failure in ("unsupported", "not-started"):
            with self.subTest(failure=failure), self.case() as c:
                c.failure = failure
                with self.assertRaises(h.Refused) as error: c.reserve()
                self.assertEqual(error.exception.reason, "store")
                final = h.Envelope.parse(c.repo.journal)
                self.assertEqual((final.schema_version, c.repo.journal_puts, c.repo.ledger_puts), (2, 3, 0))
                self.assertIsNone(final.play_query); self.assertTrue(c.material._play_consumed)
                self.assertIsNone(final.state.candidates[0].reservation)

    def test_source_drift_does_not_turn_cleanup_ack_into_floor_or_ledger_authority(self):
        with self.case(4) as c:
            c.after_child = lambda platform: setattr(c.repo, "source_commit", "f" * 40) if platform == "android" else None
            with self.assertRaises(h.Refused): c.reserve()
            final = h.Envelope.parse(c.repo.journal)
            self.assertIsNone(final.play_query)  # Real deleted edit only, not a floor grant.
            self.assertIsNotNone(final.state.selected(c.fixture.authority).pending)
            self.assertEqual(c.repo.ledger_puts, 0)

    def test_lost_pending_or_clear_ack_never_repeats_play_on_same_original(self):
        for at in (2, 3):
            with self.subTest(write=at), self.case() as c:
                c.after_write = at
                with self.assertRaises(h.Refused): c.reserve()
                final = h.Envelope.parse(c.repo.journal)
                self.assertEqual((c.repo.ledger_puts, c.provider_calls), (0, [] if at == 2 else ["android"]))
                self.assertEqual(final.play_query is not None, at == 2)
                self.assertEqual(c.material._play_consumed, at == 3)
                self.assertTrue(c.remote.stopped)
                calls = len(c.repo.calls)
                with self.assertRaises(h.Refused): c.reserve()
                self.assertEqual(len(c.repo.calls), calls)

    def test_two_runners_pending_cas_loser_cannot_open_edit_or_clear_winner(self):
        with self.case() as c:
            left, request = c.select()
            other_remote = h._Remote(c.fixture.authority, c.source, c.repo.send)
            right = h._Journal(other_remote, c.settings); right.load()
            right.choose(lambda candidate: replace(request, candidate_id=candidate))
            attempt = left.begin_play(request)
            with self.assertRaises(h.Refused): right.begin_play(request)
            self.assertTrue(right._poisoned)
            self.assertEqual(h.Envelope.parse(c.repo.journal).play_query, attempt)
            self.assertEqual((c.provider_calls, c.repo.ledger_puts), ([], 0))
            with self.assertRaises(h.Refused):
                left.record_checkpoint(c.settings.authority, replace(left.checkpoint(c.settings.authority), commit=c.repo.head))
            with self.assertRaises(h.Refused): left.finish_play(request, c.source, attempt)
            self.assertEqual(c.repo.journal_puts, 2)

    def test_sticky_v2_and_immutable_original_selection_after_clear(self):
        with self.case() as c:
            journal, request = c.select(); attempt = journal.begin_play(request)
            c.material.observe_android(c.source, request.store_context_revision, attempt)
            with self.assertRaises(h.Refused): journal.finish_play(request, c.source, replace(attempt))
            journal.finish_play(request, c.source, attempt)
            with self.assertRaises(h.Refused): journal.finish_play(request, c.source, attempt)
            original = h.Envelope.parse(c.repo.journal)
            journal.record_checkpoint(c.settings.authority, replace(journal.checkpoint(c.settings.authority), commit=c.repo.head))
            self.assertEqual(h.Envelope.parse(c.repo.journal).schema_version, 2)
            self.assertEqual(h.Envelope.parse(c.repo.journal).state.candidates, original.state.candidates)
            self.assertNotEqual(h.Envelope.parse(c.repo.journal).revision, original.revision)
            new = h._Journal(h._Remote(c.fixture.authority, c.source, c.repo.send), c.settings); new.load()
            self.assertEqual(new.choose(lambda candidate: replace(request, candidate_id=candidate)), request)
            with self.assertRaises(h.Refused):
                new.choose(lambda candidate: replace(request, candidate_id=candidate,
                    version_policy=replace(request.version_policy, rules=(h.p.RefRule(request.source.ref, "minor"),))))
            self.assertEqual(c.repo.ledger_puts, 0)

    def test_envelope_v2_rejects_unbound_or_foreign_play_query_no_silent_v1_downgrade(self):
        with self.case() as c:
            journal, request = c.select(); attempt = journal.begin_play(request)
            raw = c.repo.journal; decoded = json.loads(raw)
            self.assertEqual(h.Envelope.parse(raw).to_bytes(), raw)
            variants = []
            for key, value in (("requestSha256", "f" * 64), ("candidateId", "00000000-0000-4000-8000-000000000099"),
                               ("attemptId", "00000000-0000-4000-8000-00000000000A")):
                bad = copy.deepcopy(decoded); bad["playQuery"][key] = value; variants.append(bad)
            variants.extend(({"revision": decoded["revision"], "state": decoded["state"], "playQuery": None},
                             {**decoded, "schemaVersion": 1}, {**decoded, "playQuery": {}}))
            for value in variants:
                with self.assertRaises((ValueError, h.Refused)): h.Envelope.parse(h.p.canonical(value) + b"\n")
            with self.assertRaises(h.Refused): h.Envelope(decoded["revision"], journal._state, attempt, 1).to_bytes()

    def test_selected_material_no_unused_secret_or_wif_and_no_private_output(self):
        with TemporaryDirectory() as temporary:
            tooling = Path(temporary)
            for platform in ("ios", "android", "both"):
                good = environment(platform)
                with patch.dict(os.environ, good, clear=True):
                    self.assertIsInstance(store.Material(tooling, platform=platform), store.Material)
                changed = dict(good)
                changed[store._GAC] = "/ambient/wif.json"
                with patch.dict(os.environ, changed, clear=True), self.assertRaises(h.Refused): store.Material(tooling, platform=platform)
            invalid = [{"type": "external_account"}, {**google(), "token_uri": "https://untrusted.invalid/token"},
                       {**google(), "client_email": "other@else.iam.gserviceaccount.com"}]
            for value in invalid:
                with patch.dict(os.environ, {**environment("android"), store._GOOGLE: base64.b64encode(h.p.canonical(value)).decode()}, clear=True):
                    with self.assertRaises(h.Refused) as error: store.Material(tooling, platform="android")
                    self.assertEqual(error.exception.reason, "google")
                    self.assertNotIn(value.get("client_email", "INERT"), str(error.exception))
            for platform, key, value in (("ios", store._GOOGLE, environment("android")[store._GOOGLE]),
                                         ("android", store._P8, environment("ios")[store._P8]),
                                         ("both", store._GOOGLE, ""),
                                         ("android", store._GOOGLE, base64.b64encode(b"x" * (16 * 1024 + 1)).decode())):
                with patch.dict(os.environ, {**environment(platform), key: value}, clear=True), self.assertRaises(h.Refused):
                    store.Material(tooling, platform=platform)

    def test_both_context_only_closed_reserve_arm_and_exact_confirmation_policy(self):
        with self.case(4) as c:
            env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": c.context.repository["fullName"],
                "GITHUB_REPOSITORY_ID": c.context.repository["id"], "GITHUB_SHA": c.context.authority["headSha"],
                "GITHUB_REF": c.context.authority["ref"], "GITHUB_JOB": "version_reserve",
                "MOBILE_RELEASE_OPERATION": "reserve-version", "MOBILE_RELEASE_SELECTED_PLATFORM": "both",
                "MOBILE_RELEASE_CONFIRMATION": "reserve-version:both:temporary-play-edit",
                ci.AUTHORITY_ENV: h.p.canonical({"schemaVersion": 1, "authority": c.settings.authority.value(),
                    "checkpoint": c.settings.checkpoint.value()}).decode(), h.POLICY_ENV: h.p.canonical(c.policy.value()).decode()}
            with patch.dict(os.environ, env), patch.object(workflow, "workflow_authority", return_value=c.context.authority):
                current = workflow.Context.current("candidate", "both")
                self.assertEqual(h._admit(current), (c.settings, c.policy))
                self.assertEqual(workflow.PLATFORMS, ("android", "ios"))
                for key, value in (("GITHUB_JOB", "ios_store"), ("MOBILE_RELEASE_OPERATION", "candidate"),
                                   ("MOBILE_RELEASE_SELECTED_PLATFORM", "ios"), ("MOBILE_RELEASE_CONFIRMATION", "reserve-version:both")):
                    with patch.dict(os.environ, {key: value}), self.assertRaises(workflow.WorkflowError):
                        workflow.Context.current("candidate", "both")
                with self.assertRaises(workflow.WorkflowError): workflow.Context.current("production-submit", "both")
                with self.assertRaises(h.Refused): h._admit(replace(current, confirmation="reserve-version:android:temporary-play-edit"))
                with patch.dict(os.environ, {h.POLICY_ENV: h.p.canonical(replace(c.policy, store_scope=android.POLICY_SCOPE).value()).decode()}):
                    with self.assertRaises(h.Refused): h._admit(current)

    def test_actual_private_input_snapshot_and_close_are_required_before_clear(self):
        # Run this module under the existing unprivileged/networkless fixture
        # command. No process executes; only FiniteScratch creates private data.
        self.assertNotEqual(os.geteuid(), 0, "use the documented nonroot data-test command")
        with self.case() as c:
            guard = DefaultCancellation(ProcessCleanupError, "inert hosted material cleanup")
            c.source.guard = guard
            def scratch(**kwargs):
                return finite_scratch(**kwargs, parent=c.root)
            scope = CleanupScope(guard, lambda: None, owns_cancellation=True, first_primary=True)
            try:
                with scope:
                    guard.install(); guard.activate()
                    journal, request = c.select(); attempt = journal.begin_play(request)
                    with patch.object(store, "finite_scratch", scratch):
                        summary = c.material.observe_android(c.source, request.store_context_revision, attempt)
                    self.assertEqual(summary["temporaryEdit"], "deleted")
                    self.assertFalse(c.material._play_selection._path.exists())
                    self.assertFalse(c.material._play_runner._path.exists())
                    self.assertEqual(c.material._play_snapshot.sha256, hashlib.sha256(c.material.google).hexdigest())
                    journal.finish_play(request, c.source, attempt)
            finally:
                scope.__exit__(*sys.exc_info())
            self.assertIsNone(h.Envelope.parse(c.repo.journal).play_query)
