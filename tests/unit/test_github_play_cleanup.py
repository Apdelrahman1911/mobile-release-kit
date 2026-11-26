"""Actual closed policy/codec with inert HTTP/record storage, no dispatch.

Provider response bodies and ciphertext are synthetic DATA. No Git, network,
credential, decryptor, workflow or native finality is exercised by this suite.
"""
from __future__ import annotations

import base64
import copy
from dataclasses import replace
import hashlib
import io
import json
import unittest
from unittest.mock import patch

from mobile_release import github_play_cleanup as p
from mobile_release import _desktop_github_play_cleanup as wire
from mobile_release import _github_play_cleanup_transport as transport
from mobile_release import version_allocation_state as state
from mobile_release import version_hosted_play_recovery as recovery
from mobile_release._github_play_cleanup_journal import Journal
from mobile_release._github_connection_transport import (_Budget, _ExchangeProfile, _ResponseRole,
    _ResponseBody, _response_result, _control, _role_limits, ReadFailure, ReadResult)
from mobile_release.config import default_config_data

PROJECT = "00000000-0000-4000-8000-000000000001"
LEDGER = "00000000-0000-4000-8000-000000000002"
CANDIDATE = "00000000-0000-4000-8000-000000000003"
ATTEMPT = "00000000-0000-4000-8000-000000000004"
LOCAL = "e" * 32
A, B, C = "a" * 40, "b" * 40, "c" * 40
TREE_A, TREE_B = "d" * 40, "e" * 40


def target(**changes):
    scope = {"projectBinding": "f" * 64, "repository": "fixture/app", "accountId": "11", "repositoryId": "22"}
    scope.update(changes.pop("scope", {}))
    return p.Target.parse({"scope": scope, "toolingRepository": p.TOOLING_REPOSITORY,
        "toolingSha": "f" * 40, "marker": "a" * 32, **changes})


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def contents(path, raw):
    return {"type": "file", "path": path, "encoding": "base64", "size": len(raw),
        "sha": blob(raw), "content": base64.b64encode(raw).decode() + "\n"}


def tree(sha, files):
    rows = {}
    url = "https://api.github.com/repos/fixture/app/git/"
    for path, raw in files.items():
        parts = path.split("/")
        for n in range(1, len(parts)):
            parent = "/".join(parts[:n])
            rows[parent] = {"path": parent, "mode": "040000", "type": "tree", "sha": "1" * 40, "url": url + "trees/" + "1" * 40}
        rows[path] = {"path": path, "mode": "100644", "type": "blob", "sha": blob(raw),
            "size": len(raw), "url": url + "blobs/" + blob(raw)}
    return {"sha": sha, "url": url + "trees/" + sha, "truncated": False, "tree": list(rows.values())}


class Fixture:
    def __init__(self, platform="android", *, head=B):
        self.target = target()
        enabled = {"android": {"applicationId": "com.example.inert"}}
        if platform == "both":
            enabled["ios"] = {"bundleId": "com.example.inert"}
        config = default_config_data(enabled)
        config["source"]["candidateBranch"] = "main"
        if platform == "both":
            config["ios"]["appStoreAppId"] = "1234567890"
        self.config = p.canonical(config)
        self.source = p.Source.from_saved(self.config)
        self.version = b"# retained source, never executed\nVERSION_NAME=1.2.3\nBUILD_NUMBER=7\n"
        self.version_path = config["version"]["source"]
        version = p.ReleaseVersion("1.2.3", 7)
        self.ledger = p.allocation.Ledger(p.allocation.Genesis(PROJECT, "22", LEDGER, version))
        self.authority = p.allocation.AuthorityRegistration(PROJECT, "fixture/app", "22", LEDGER, self.ledger.genesis.sha256, True)
        self.checkpoint = p.allocation.Checkpoint(0, self.ledger.genesis.sha256, C)
        policy_scope = p.android.POLICY_SCOPE if platform == "android" else p.hosted.paired.POLICY_SCOPE
        settings = p.policy.VersionPolicy("automatic", (p.policy.RefRule("refs/heads/main", "build"),), store_scope=policy_scope)
        self.request = p.allocation.AllocationRequest(PROJECT, CANDIDATE, self.source.identity_revision,
            p.policy.SourceBinding(A, TREE_A, "refs/heads/main", hashlib.sha256(self.config).hexdigest(), hashlib.sha256(self.version).hexdigest()),
            version, ("android",) if platform == "android" else ("android", "ios"), settings, "2" * 64)
        self.capsule = recovery.Capsule("INERT-version", base64.b64encode(b"N" * 12).decode(),
            base64.b64encode(b"PRIVATE OPAQUE CIPHERTEXT - NOT AN EDIT ID").decode(), base64.b64encode(b"T" * 16).decode(),
            p.policy.digest({"schemaVersion": 1, "purpose": recovery.PURPOSE, "keyVersion": "INERT-version",
                "authority": self.authority.value(), "localProjectId": LOCAL, "candidateId": CANDIDATE,
                "requestSha256": self.request.sha256, "attemptId": ATTEMPT, "source": self.request.source.value(),
                "contextSha256": self.request.store_context_revision, "identityRevision": self.request.identity_revision}))
        self.envelope = p.hosted.Envelope(3, state.AllocationState((state.AuthorityState(self.authority, self.checkpoint),),
            (state.ProjectEnrollment(LOCAL, PROJECT),), (state.SelectedCandidate(LOCAL, self.request),)),
            p.hosted.PlayQuery(CANDIDATE, self.request.sha256, ATTEMPT, recovery.Record(self.capsule)), 3)
        self.head, self.counter = head, C
        self.calls = []
        self.change = None
        self.control = _control()

    def __call__(self, request):
        self.calls.append(request)
        root = "/repos/fixture/app"
        path = request.path
        status = 204 if request.method == "POST" else 200
        if request.method == "POST":
            value = None
        elif path == "/user":
            value = {"id": 11, "login": "fixture", "type": "User"}
        elif path == root:
            value = {"id": 22, "full_name": "fixture/app", "archived": False, "disabled": False, "permissions": {"push": True}}
        elif path == root + "/branches/main":
            value = {"name": "main", "commit": {"sha": self.head, "commit": {"tree": {"sha": TREE_B,
                "url": "https://api.github.com" + root + "/git/trees/" + TREE_B}}}}
        elif path == root + "/actions/workflows/mobile-candidate.yml":
            value = {"id": 33, "path": p.WORKFLOW_PATH, "name": p.WORKFLOW_NAME, "state": "active"}
        elif path == root + "/branches/" + p.allocation.LEDGER_BRANCH + "/protection":
            value = {"enforce_admins": {"enabled": True}, "allow_force_pushes": {"enabled": False}, "allow_deletions": {"enabled": False}}
        elif path == root + "/git/ref/heads/" + p.allocation.LEDGER_BRANCH:
            value = {"ref": "refs/heads/" + p.allocation.LEDGER_BRANCH, "object": {"type": "commit", "sha": self.counter}}
        elif path.startswith(root + "/contents/"):
            leaf = path[len(root + "/contents/"):].split("?", 1)[0]
            if leaf == p.WORKFLOW_PATH: raw = p.canonical_caller(self.target)
            elif leaf == p.version_text.CONFIG_PATH: raw = self.config
            elif leaf == p.allocation.LEDGER_PATH: raw = self.ledger.to_bytes()
            elif leaf == p.hosted.JOURNAL_PATH: raw = self.envelope.to_bytes()
            else:
                assert leaf == self.version_path
                raw = self.version
            value = contents(leaf, raw)
        elif path == root + "/git/commits/" + A:
            value = {"sha": A, "tree": {"sha": TREE_A, "url": "https://api.github.com" + root + "/git/trees/" + TREE_A}}
        elif path.startswith(root + "/git/trees/"):
            sha = path[len(root + "/git/trees/"):].split("?")[0]
            value = tree(sha, {p.WORKFLOW_PATH: p.canonical_caller(self.target)} if sha == TREE_B
                else {p.version_text.CONFIG_PATH: self.config, self.version_path: self.version})
        else:
            assert path.startswith(root + "/compare/") and path.endswith("?per_page=1&page=1"), path
            old, new = path[len(root + "/compare/"):].split("?")[0].split("...")
            value = {"status": "identical" if old == new else "ahead", "base_commit": {"sha": old},
                "merge_base_commit": {"sha": old}, "commits": [], "files": []}
        if self.change is not None:
            status, value = self.change(request, len(self.calls), status, value)
        return ReadResult({"status": status, "body": value, "failure": "none"}, self.control)

    def prepare(self):
        return p.prepare(self.target, self.source, self)[0]


class MemoryJournal(Journal):
    """Real fixed codec/exclusion, inert storage. Not native/disk durability."""
    def __init__(self, files=None, *, failure=None):
        super().__init__("/inert-task-home", end=60)
        self.files = {} if files is None else files
        self.failure = failure
    def _names(self): return set(self.files)
    def _read(self, name): return self.files[name]
    def _post(self): pass
    def _create(self, name, raw):
        if name in self.files: raise OSError("inert exclusive create")
        self.files[name] = raw
        if self.failure and self.failure in name: raise OSError("inert lost create acknowledgement")


class PlayCleanupTests(unittest.TestCase):
    def test_actual_nineteen_reads_bind_advanced_current_branch_and_original_candidate(self):
        for platform in ("android", "both"):
            with self.subTest(platform=platform):
                f = Fixture(platform); prepared = f.prepare()
                self.assertEqual(len(f.calls), 19)
                self.assertTrue(all(r.method == "GET" and r.body is None for r in f.calls))
                self.assertEqual((prepared.source_sha, prepared.candidate["source"]["commit"]), (B, A))
                self.assertEqual(prepared.candidate["platform"], platform)
                self.assertNotEqual(prepared.target.scope.project_binding, prepared.candidate["localProjectId"])
                self.assertEqual(prepared.authority, f.authority)
                self.assertEqual(prepared.checkpoint, f.checkpoint)
                self.assertEqual(p.digest(prepared), hashlib.sha256(p.canonical(prepared.value())).hexdigest())
                text = p.canonical(prepared.value())
                for secret in (b"PRIVATE", b"ciphertextBase64", b"keyVersion", b"editId", b"runId"):
                    self.assertNotIn(secret, text)
                for phrase in ("nonpublishing but mutating", "mutable", "actual dispatch head", "does not prove cleanup"):
                    self.assertIn(phrase, prepared.value()["confirmation"])
                self.assertLessEqual(len(text), p.MAX_PREPARED_BYTES)

    def test_full_original_source_identity_checkpoint_and_capsule_are_not_display_assertions(self):
        for cut in ("account", "repo", "workflow", "caller", "tree", "protection", "ref", "ledger", "journal",
                    "commit", "config", "version", "ancestry", "late-branch", "late-counter", "capsule-aad"):
            f = Fixture()
            if cut == "capsule-aad":
                f.envelope = replace(f.envelope, play_query=replace(f.envelope.play_query,
                    recovery=recovery.Record(replace(f.capsule, aad_sha256="f" * 64))))
            def changed(req, n, status, body):
                if cut == "account" and n == 1: body["id"] = 12
                if cut == "repo" and n == 2: body["id"] = 23
                if cut == "workflow" and n == 4: body["path"] = ".github/workflows/other.yml"
                if cut == "caller" and n == 5: body = contents(p.WORKFLOW_PATH, b"not the pinned caller")
                if cut == "tree" and n == 6: body["truncated"] = True
                if cut == "protection" and n == 7: body["allow_deletions"]["enabled"] = True
                if cut == "ref" and n == 8: body["object"]["type"] = "tag"
                if cut == "ledger" and n == 9: body["sha"] = "0" * 40
                if cut == "journal" and n == 10: body["sha"] = "0" * 40
                if cut == "commit" and n == 11: body["sha"] = "0" * 40
                if cut == "config" and n == 12: body = contents(p.version_text.CONFIG_PATH, b"{}")
                if cut == "version" and n == 14: body = contents(f.version_path, b"VERSION_NAME=9.9.9\nBUILD_NUMBER=8\n")
                if cut == "ancestry" and n == 15: body["status"] = "diverged"
                if cut == "late-branch" and n == 16: body["commit"]["sha"] = "0" * 40
                if cut == "late-counter" and n == 17: body["object"]["sha"] = "0" * 40
                return status, body
            f.change = changed
            with self.subTest(cut=cut), self.assertRaises(p.Refused):
                f.prepare()
            self.assertFalse(any(r.method == "POST" for r in f.calls))

    def test_claimed_absent_and_inaccessible_hosted_state_never_authorize_dispatch(self):
        for cut in ("absent", "no-capsule", "claimed", "inaccessible"):
            f = Fixture()
            if cut == "absent": f.envelope = replace(f.envelope, play_query=None)
            if cut == "no-capsule": f.envelope = replace(f.envelope, play_query=replace(f.envelope.play_query, recovery=None))
            if cut == "claimed": f.envelope = replace(f.envelope, play_query=replace(f.envelope.play_query,
                recovery=recovery.Record(f.capsule, recovery.Claim("00000000-0000-4000-8000-000000000005", "44", 1))))
            if cut == "inaccessible": f.change = lambda req, n, status, body: (404, None) if n == 10 else (status, body)
            with self.subTest(cut=cut), self.assertRaises(p.Refused): f.prepare()
            self.assertLessEqual(len(f.calls), 10)

    def test_exact_dispatch_after_immutable_intent_and_claim_is_only_204_acknowledged(self):
        prepared = Fixture().prepare(); f = Fixture(); journal = MemoryJournal()
        def before_post(req, n, status, body):
            if req.method == "POST":
                self.assertEqual(n, 12)
                self.assertTrue(journal.attempts[prepared.target.marker]["data"]["claimed"])
                self.assertEqual(req.path, "/repos/fixture/app/actions/workflows/33/dispatches")
                self.assertEqual(json.loads(req.body), {"ref": "main", "inputs": {"operation": "recover-play-edit",
                    "platform": "android", "confirmation": "recover-play-edit:" + CANDIDATE + ":" + ATTEMPT}})
            return status, body
        f.change = before_post
        result = p.dispatch(prepared, f.source, f, journal)
        self.assertEqual((result["effect"], result["reason"]), ("acknowledged-unconfirmed", "none"))
        self.assertEqual([r.method for r in f.calls].count("POST"), 1)
        self.assertIsNone(result["observed"])
        p.action_result(result, prepared, "dispatch")

    def test_changed_pre_send_branch_counter_full_journal_or_source_cannot_be_refreshed(self):
        prepared = Fixture().prepare()
        for cut in ("branch", "counter", "journal", "local-config", "late-ref", "permission"):
            f = Fixture(); journal = MemoryJournal()
            if cut == "local-config": f.source = replace(f.source, saved_sha256="0" * 64)
            def changed(req, n, status, body):
                if cut == "branch" and n == 3: body["commit"]["sha"] = "0" * 40
                if cut == "counter" and n == 6: body["object"]["sha"] = "0" * 40
                if cut == "journal" and n == 7: body = contents(p.hosted.JOURNAL_PATH, replace(f.envelope, revision=4).to_bytes())
                if cut == "late-ref" and n == 8: body["object"]["sha"] = "0" * 40
                if cut == "permission" and n == 11: body["permissions"]["push"] = False
                return status, body
            f.change = changed
            result = p.dispatch(prepared, f.source, f, journal)
            self.assertEqual(result["effect"], "not-sent", cut)
            self.assertEqual(journal.files, {}, cut)
            self.assertFalse(any(r.method == "POST" for r in f.calls), cut)

    def test_cross_account_project_alias_and_acknowledged_204_never_allow_same_tuple_again(self):
        prepared = Fixture().prepare(); journal = MemoryJournal(); f = Fixture()
        p.dispatch(prepared, f.source, f, journal)
        for acknowledged in (True, False):
            files = dict(journal.files)
            if not acknowledged: files.pop(prepared.target.marker + ".receipt.json")
            loaded = MemoryJournal(files); loaded._load()
            for change in ({"marker": "b" * 32}, {"marker": "c" * 32, "scope": {"accountId": "99"}},
                           {"marker": "d" * 32, "scope": {"projectBinding": "0" * 64}}):
                other = replace(prepared, target=target(**change))
                with self.subTest(acknowledged=acknowledged, change=change), self.assertRaises(p.Refused):
                    loaded.create_intent(other.value())
            self.assertEqual(loaded.files, files)

    def test_each_lost_local_create_ack_keeps_fence_and_lost_post_is_not_retried(self):
        prepared = Fixture().prepare()
        for cut in ("intent", "claim", "receipt", "POST"):
            journal = MemoryJournal(failure=cut); f = Fixture()
            if cut == "POST":
                def lost(req, n, status, body):
                    if req.method == "POST": raise ReadFailure("network-unavailable")
                    return status, body
                f.change = lost
            result = p.dispatch(prepared, f.source, f, journal)
            posts = [r for r in f.calls if r.method == "POST"]
            self.assertEqual(len(posts), int(cut in ("receipt", "POST")))
            self.assertEqual(result["acknowledged"], cut == "receipt")
            self.assertNotEqual(result["reason"], "none")
            loaded = MemoryJournal(journal.files); loaded._load()
            with self.assertRaises(p.Refused): loaded.create_intent(replace(prepared, target=target(marker="b" * 32)).value())
            with self.assertRaises(p.Refused): journal.claim()

    def test_later_absent_or_claimed_journal_is_data_not_cleanup_or_a_new_grant(self):
        prepared = Fixture().prepare()
        j = MemoryJournal(); j.create_intent(prepared.value()); j.claim()
        record = j.pending(prepared.target)[0]
        for cut in ("same-unclaimed", "same-claimed", "not-present"):
            f = Fixture()
            if cut == "same-claimed": f.envelope = replace(f.envelope, play_query=replace(f.envelope.play_query,
                recovery=recovery.Record(f.capsule, recovery.Claim("00000000-0000-4000-8000-000000000005", "44", 1))))
            if cut == "not-present": f.envelope = replace(f.envelope, play_query=None)
            result = p.observe(record, f)
            self.assertEqual((result["effect"], result["observed"]["pendingTuple"]), ("observed-unconfirmed", cut))
            self.assertFalse(result["acknowledged"])
            self.assertTrue(all(r.method == "GET" for r in f.calls))
            p.action_result(result, prepared, "observe")
            with self.assertRaises(p.Refused): j.create_intent(replace(prepared, target=target(marker="b" * 32)).value())

    def test_204_with_body_or_a201_run_id_is_not_dispatch_acknowledgement(self):
        prepared = Fixture().prepare()
        for status, body in ((201, {"id": 44}), (204, {"runId": "44"}), (302, None)):
            f = Fixture(); f.change = lambda req, n, s, b: (status, body) if req.method == "POST" else (s, b)
            result = p.dispatch(prepared, f.source, f, MemoryJournal())
            self.assertEqual(result["effect"], "potentially-applied")
            self.assertFalse(result["acknowledged"])
            self.assertIsNone(result["observed"])

    def test_real_closed_transport_grammar_forbids_old_release_markers_other_workflows_and_writes(self):
        prepared = Fixture().prepare(); body = p.dispatch_body(prepared)
        role = _ResponseRole.PLAY_CLEANUP_WRITE
        transport.validate_body(role, body)
        transport.validate_endpoint(role, "POST", "/repos/fixture/app/actions/workflows/33/dispatches")
        for field in ("desktop_request", "recovery_confirmation", "source_sha", "return_run_details", "policy"):
            value = json.loads(body); value["inputs"][field] = "INERT"
            with self.assertRaises(ValueError): transport.validate_body(role, p.canonical(value))
        for path in ("/repos/fixture/app/actions/workflows/other.yml/dispatches", "/repos/fixture/app/contents/a",
                     "/repos/fixture/app/actions/runs/33/cancel"):
            with self.assertRaises(ValueError): transport.validate_endpoint(role, "POST", path)
        with self.assertRaises(ValueError): _role_limits(_ExchangeProfile.ACTIONS_RETRY, role)
        for kind in ("prepare", "observe"):
            with self.assertRaises(ValueError):
                transport.request_role(prepared.target, Fixture().source if kind == "prepare" else None,
                    None if kind == "prepare" else prepared, kind,
                    p.HttpRequest("POST", "/repos/fixture/app/actions/workflows/33/dispatches", body))

    def test_original_204_reader_requires_actual_empty_eof_and_retains_original_cap(self):
        for tail, expected in ((b"", True), (b"x", False)):
            budget = _Budget(0, monotonic=lambda: 1, wall=lambda: 1, _profile=_ExchangeProfile.PLAY_CLEANUP)
            response = _ResponseBody(io.BytesIO(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n" + tail), budget,
                _role=_ResponseRole.PLAY_CLEANUP_WRITE)
            result = _response_result(response, budget)
            self.assertEqual(result.observation["failure"] == "none", expected)
            self.assertEqual(budget.body_total_limit, 2 * 1024 * 1024)
            self.assertEqual(budget.end, 60)
        budget = _Budget(0, monotonic=lambda: 1, _profile=_ExchangeProfile.PLAY_CLEANUP)
        for _ in range(19): budget.claim_request()
        with self.assertRaises(ReadFailure): budget.claim_request()
        self.assertEqual(_Budget(0, _profile=_ExchangeProfile.HOSTED_VERSION).body_total_limit, 10 * 1024 * 1024)

    def test_wire_exact_native_bound_review_and_maximum_token_without_public_private_values(self):
        prepared = Fixture().prepare()
        initial = p.canonical({"protocol": p.PROTOCOL, "id": "inert-cleanup", "action": {"kind": "dispatch",
            "target": prepared.target.value(), "source": {"root": "/inert", "rootIdentity": {"device": "1",
                "inode": "2", "mode": 16832, "uid": 0, "gid": 0}}, "home": "/inert-home", "preparedSha256": p.digest(prepared)}}) + b"\n"
        request = wire.parse_initial(initial)
        go = {"protocol": p.PROTOCOL, "id": request.id, "go": {"requestSha256": request.digest,
            "token": "\\" * 4096, "prepared": prepared.value()}}
        token, parsed = wire.parse_go(p.canonical(go) + b"\n", request)
        self.assertEqual(len(token), 4096); self.assertEqual(parsed, prepared)
        f = Fixture(); action = p.dispatch(prepared, f.source, f, MemoryJournal())
        result = {"schemaVersion": 1, "kind": "dispatch", "reason": action["reason"], "prepared": None,
            "cleanup": action, "pending": None, "control": _control()}
        raw = wire.encode_result(request, result, prepared)
        self.assertNotIn(b"token", raw); self.assertNotIn(b"capsule", raw)
        go["go"]["prepared"]["candidate"]["attemptId"] = "00000000-0000-4000-8000-000000000099"
        with self.assertRaises(ValueError): wire.parse_go(p.canonical(go) + b"\n", request)

    def test_prospective_decode_guards_run_before_outer_and_embedded_semantic_parsers(self):
        from mobile_release import _github_connection_transport as shared
        from mobile_release.github_setup_secret_inputs import _json_prelude, SecretConfigurationError
        raw = b'{"values":[' + b','.join([b'0'] * 8000) + b']}'
        budget = _Budget(0, monotonic=lambda: 1, _profile=_ExchangeProfile.PLAY_CLEANUP)
        response = _ResponseBody(io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '
            + str(len(raw)).encode() + b'\r\n\r\n' + raw), budget, _role=_ResponseRole.PLAY_CLEANUP_READ)
        with patch.object(shared, '_decode_json', side_effect=AssertionError('semantic decoder entered before bound')):
            result = _response_result(response, budget)
        self.assertEqual(result.observation['failure'], 'response-limit')
        f = Fixture(); op = p.Operation(f.target, f.source, f)
        with self.assertRaises(p.Refused) as refused:
            op.guard_document(raw)
        self.assertEqual(refused.exception.reason, 'response-limit')
        # Same original configuration guard semantics are not relaxed by the
        # new callback factor; tiny valid JSON still reaches its final check.
        class Check:
            calls = 0
            def check(self): self.calls += 1
        original = Check(); _json_prelude(b'{"a":1}', original)
        self.assertGreaterEqual(original.calls, 2)
        with self.assertRaises(SecretConfigurationError): _json_prelude(raw, original)

    def test_engine_late_known_observe_refusal_keeps_ack_but_withdraws_read_publication(self):
        prepared = Fixture().prepare(); stored = MemoryJournal()
        stored.create_intent(prepared.value()); stored.claim(); stored.record_accepted()
        class LateJournal(MemoryJournal):
            closed = completed = False
            def open(self): self._load()
            def close(self): self.closed = True
            def _post(self):
                if self.completed: raise p.Refused('source-changed')
        journal = LateJournal(stored.files); f = Fixture()
        original_observe = p.observe
        def returned_observe(record, exchange):
            value = original_observe(record, exchange)
            self.assertEqual(value['effect'], 'observed-unconfirmed')
            journal.completed = True
            return value
        request = wire.parse_initial(p.canonical({'protocol':p.PROTOCOL,'id':'inert-observe',
            'action':{'kind':'observe','target':prepared.target.value(),'source':None,'home':'/inert-home',
                      'preparedSha256':p.digest(prepared)}}) + b'\n')
        budget = _Budget(0, monotonic=lambda:1, _profile=_ExchangeProfile.PLAY_CLEANUP)
        with patch.object(wire, '_Budget', return_value=budget), patch.object(wire, 'Journal', return_value=journal), \
             patch.object(wire, 'make_exchange', return_value=f), patch.object(p, 'observe', side_effect=returned_observe):
            result = wire.execute(request, 'INERT_NOT_A_TOKEN', prepared, started=0, runtime_dir='/never-opened')
        self.assertTrue(journal.closed and journal.completed)
        self.assertEqual(result['reason'], 'source-changed')
        self.assertEqual(result['cleanup']['effect'], 'unresolved')
        self.assertTrue(result['cleanup']['claimed'] and result['cleanup']['acknowledged'])
        self.assertIsNone(result['cleanup']['observed'])
        self.assertIsNone(result['prepared']); self.assertIsNone(result['pending'])
        self.assertTrue(all(r.method == 'GET' for r in f.calls))
        wire.encode_result(request, result, prepared)
