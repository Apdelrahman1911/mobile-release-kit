"""Real fixed input/engine/file owners; fake provider, native ACK and C/A/W.

No Ruby, OpenSSL, network, native Store/vault or account operation is executed.
The synthetic command ledger is explicitly NOT evidence of native finality.
Tests run against the COMPLETE shared modules after the companion Root patch.
"""
from contextlib import contextmanager
import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import UUID

from mobile_release import _desktop_apple_provisioning_protocol as wire
from mobile_release import _desktop_apple_provisioning_control as control
from mobile_release import desktop_apple_provisioning as worker
from mobile_release import apple_provisioning_api as api
from mobile_release._desktop_apple_provisioning_engine import _Engine
from mobile_release._desktop_saved_command_engine import run_engine
from mobile_release._desktop_saved_command_control import SavedCommandDomain, source_domain
from mobile_release._desktop_store_preflight_control import PREFIX, SUFFIX
from mobile_release.apple_provisioning_recovery import AttemptRecord
from mobile_release.build_inputs import finite_scratch
from mobile_release.owned_process import ProcessCleanupError
from mobile_release.tooling import REQUIRED_TOOLING_FILES
from .helpers import ios_config

ISSUER = b"12345678-1234-1234-1234-123456789abc"
ACCOUNT = api.digest(b"mrk:apple-provisioning-account:1\0" + UUID(ISSUER.decode()).bytes)
OP, GENERATION, RECORD = "a" * 32, "b" * 32, "c" * 32
MATERIAL = (b"-----BEGIN PRIVATE KEY-----\nINERT-NEVER-VALIDATED\n-----END PRIVATE KEY-----\n", b"ABCDEFGHIJ", ISSUER)


def encode(value):
    return api.canonical(value) + b"\n"


def bundle(resource="BUNDLE123"):
    return {"id": resource, "type": "bundleIds", "attributes": {
        "identifier": "com.example.reader", "platform": "IOS", "seedId": "ABCDE12345"}}


def request(root, runtime, mode="review"):
    raw = (root / "release/mobile-release.json").read_bytes()
    version = (root / "release/version.properties").read_bytes()
    facts = root.stat()
    canonical = json.dumps(json.loads(raw), sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    clock = time.monotonic_ns()
    return {"protocol": wire.PROTOCOL, "operationId": OP, "ownerGeneration": GENERATION,
        "context": {"projectId": "test-project", "draftRevision": 1, "baselineGeneration": 2,
            "savedConfig": {"bytes": len(raw), "sha256": api.digest(raw)},
            "savedVersion": {"source": "release/version.properties", "bytes": len(version), "sha256": api.digest(version), "name": "1.2.3", "build": 42},
            "credentialContextRevision": 2, "recordId": RECORD, "recordRevision": 3, "executionMode": "local", "platform": "ios",
            "operation": "apple-bundle-provisioning", "mode": mode, "newApplication": mode == "register", "displayName": "Reader ü",
            "reference": None if mode == "review" else {"operationId": "d" * 32, "ownerGeneration": "e" * 32}},
        "native": {"profile": "macos-arm64", "projectRoot": str(root), "cwd": str(runtime),
            "rootIdentity": {"device": str(facts.st_dev), "inode": str(facts.st_ino), "mode": facts.st_mode, "uid": facts.st_uid, "gid": facts.st_gid},
            "credentialConfig": {"bytes": len(canonical), "sha256": api.digest(canonical)},
            "clock": {"workEndNs": str(clock + 1200_000_000_000), "hardEndNs": str(clock + 1210_000_000_000)}, "nonce": "f" * 32,
            "provisioning": {"projectId": "test-project", "clientId": "desktop", "operationId": OP, "observationRevision": 1,
                "accountRef": ACCOUNT, "credentialRecordId": RECORD, "credentialRevision": 3, "credentialContextRevision": 2},
            "target": {"bundleId": "com.example.reader", "teamId": "ABCDE12345", "appIdPrefix": "ABCDE12345", "displayName": "Reader ü", "existingApplication": False},
            "reviewedAt": datetime.now(timezone.utc).isoformat() if mode == "register" else None,
            "journalRevision": 0, "pending": [], "prior": None}}


def prior(value, *, returned=True):
    old = copy.deepcopy(value)
    old["operationId"] = old["native"]["provisioning"]["operationId"] = "d" * 32
    old["ownerGeneration"] = "e" * 32
    old["context"].update(mode="register", newApplication=True,
        reference={"operationId": "7" * 32, "ownerGeneration": "8" * 32})
    old["native"].update(reviewedAt=(datetime.now(timezone.utc) - timedelta(days=1)).isoformat(), prior=None)
    selected = wire.parse_request(encode(old))
    before, plan = wire.expected_plan(selected)
    root = value["native"]["rootIdentity"]
    record = AttemptRecord(plan.context, plan.sha256, "register_bundle_id", "unknown", "provider_outcome_unknown", True,
        "BUNDLE123" if returned else None, api.resource_sha256(api.BundleId.parse(bundle())) if returned else None)
    return {"intent": {"context": old["native"]["provisioning"], "target": old["native"]["target"],
        "observedAt": before.observed_at.isoformat(), "validUntil": plan.valid_until.isoformat(),
        "beforeSha256": before.sha256, "planSha256": plan.sha256, "requestBodySha256": api.digest(plan.request.body),
        "provenance": {"projectBinding": {"projectId": "9" * 32, "canonicalRoot": value["native"]["projectRoot"],
            "device": int(root["device"]), "inode": int(root["inode"])}, "operationId": "d" * 32, "ownerGeneration": "e" * 32,
            "registrationGeneration": 1, "registeredRoot": {"path": value["native"]["projectRoot"],
                **{name: int(root[name]) for name in ("device", "inode", "mode", "uid", "gid")}},
            "draftRevision": 1, "baselineGeneration": 2, "savedConfig": value["context"]["savedConfig"], "savedVersion": value["context"]["savedVersion"]}},
        "sendArmed": True, "attempt": {"sequence": 2, "record": wire.attempt_wire(record)}, "nativeSettlement": "unknown"}


class BundleWorkerTests(unittest.TestCase):
    @contextmanager
    def files(self):
        with tempfile.TemporaryDirectory(prefix="mrk-bundle-worker-test-") as temporary:
            base = Path(temporary).resolve()
            root, runtime = base / "project", base / "runtime with spaces"
            (root / "release").mkdir(parents=True)
            config = ios_config()
            config["ios"]["identityStatus"] = "unverified"
            del config["ios"]["appStoreAppId"]
            config["projectChecks"]["preflight"] = [["must-never-execute"]]
            (root / "release/mobile-release.json").write_text(json.dumps(config))
            (root / "release/version.properties").write_text("VERSION_NAME=1.2.3\nBUILD_NUMBER=42\n")
            for name in ("ruby", "bundle"):
                path = runtime / "store/bin" / name
                path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b"inert never executed\n"); path.chmod(0o755)
            for name in (*REQUIRED_TOOLING_FILES, *("fastlane/" + x for x in (
                    "apple_provisioning.rb", "apple_provisioning_bundle_read.rb", "apple_provisioning_bundle_registration.rb"))):
                path = runtime / "store/tooling" / name
                path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b"inert tooling never executed\n")
            yield base, root, runtime

    def execute(self, *, mode="register", fault=None, returned=True):
        """Run whole original engine; only command results/native ACK are fake."""
        with self.files() as (base, root, runtime):
            value = request(root, runtime, mode)
            if mode == "reconcile":
                value["native"]["prior"] = prior(value, returned=returned)
            if fault == "pending":
                value["native"]["pending"] = [{"accountRef": ACCOUNT, "operationId": "1" * 32,
                    "action": "register_bundle_id", "status": "succeeded", "nativeSettlement": "unknown"}]
            if fault == "old-review":
                value["native"]["reviewedAt"] = (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat()
            if fault == "config-before":
                (root / "release/version.properties").write_text("VERSION_NAME=1.2.3\nBUILD_NUMBER=43\n")
            body = PREFIX + encode({"schemaVersion": 1, "files": [{"role": role, "bytes": len(raw)}
                for role, raw in zip(("asc-p8", "asc-key-id", "asc-issuer-id"), MATERIAL)]}) + b"".join(MATERIAL) + SUFFIX
            saved = [os.dup(fd) for fd in (0, 1, 2)]
            readers, writers, frames, calls = [], [], [], []
            old_cwd = Path.cwd()
            engine = None
            original_write = _Engine.write
            original_run_owned = worker.run_owned

            def write(engine, raw, *, terminal=False):
                original_write(engine, raw, terminal=terminal)
                received = os.read(readers[1], wire.RESPONSE_LIMIT)
                self.assertEqual(received, raw)
                frame = json.loads(raw); frames.append(frame)
                if frame["kind"] in {"pending", "attempt"}:
                    sequence = frame["sequence"]
                    payload = frame["payload"]
                    reply = {"protocol": wire.PROTOCOL, "operationId": OP, "ownerGeneration": GENERATION,
                        "nonce": value["native"]["nonce"], "requestSha256": engine.request.digest, "kind": "journal-ack", "step": sequence,
                        "payload": {"revision": sequence, "sequence": sequence, "recordSha256": api.digest(api.canonical(payload["update"]))}}
                    if sequence == 1 and fault == "foreign-ack":
                        reply["ownerGeneration"] = "6" * 32
                    if sequence == 1 and fault == "late-ack":
                        engine.input.work_end = time.monotonic() - .01  # Expire, never renew original test clock.
                    if sequence == 1 and fault == "config-at-ack":
                        path = root / "release/version.properties"; path.write_bytes(path.read_bytes() + b"\n")
                    os.write(writers[0], encode(reply))

            def fake_command(argv, **kwargs):
                # This fake folds a DATA ledger result solely to exercise the
                # original worker's consuming checks; it is not a native join.
                operation = engine.service
                ledger = engine.guard.lifetime_ledger
                slot = object(); ledger._bind_command(slot)
                calls.append((tuple(argv), operation._wire_request.method if operation._wire_request else "probe"))
                ledger._finish_command(slot, dispatched=True, contained=True, cleanup_complete=True)
                index = len(calls) - 1
                self.assertLessEqual(kwargs["timeout"], 60)
                self.assertIsNone(kwargs.get("execution_scope")); self.assertIsNone(kwargs.get("journal_binding"))
                if index < 6:
                    output = ("", "3.3.12", "4.0.16", "", "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2", "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2")[index]
                    return subprocess.CompletedProcess(argv, 0, output, "")
                for denied in ("RUBYOPT", "RUBYLIB", "GITHUB_TOKEN", "MOBILE_RELEASE_STORE_MODE"):
                    self.assertNotIn(denied, kwargs["environ"])
                request = operation._wire_request
                if request.method == "POST":
                    self.assertTrue(engine.input._ack_consumed)
                    self.assertEqual([f["kind"] for f in frames][-1], "pending")
                    self.assertEqual(engine.input.reply_step, 1)
                status = 201 if request.method == "POST" else 200
                rows = [bundle("OTHER123" if fault == "different-resource" else "BUNDLE123")] if (
                    request.method == "POST" or mode == "reconcile" or fault == "already-found" or index == 8) else []
                document = {"data": rows[0]} if request.method == "POST" else {
                    "data": rows, "links": {"next": None}, "meta": {"paging": {"total": len(rows)}}}
                failure = None
                if fault == "denied":
                    status, failure = 403, "provider_request_unconfirmed"
                elif fault == "post-unknown" and request.method == "POST":
                    status, failure = 503, "provider_request_unconfirmed"
                raw = encode({"schemaVersion": 1, "contextSha256": api.digest(api.canonical(wire.core_context_wire(operation.context))),
                    "operationId": OP, "bundleId": operation.target.bundle_id, "requestSha256": api.request_sha256(request),
                    "ackSha256": engine.input._pending_ack if request.method == "POST" else None,
                    "response": {"status": status, "failure": failure, "bodyBase64": None if failure else __import__("base64").b64encode(api.canonical(document)).decode()}})
                if fault == "stop-post" and request.method == "POST":
                    engine.input.stop("cancelled")
                return subprocess.CompletedProcess(argv, 0, raw, b"")

            def scratch(**kwargs):
                if kwargs.get("parent") == Path("/private/tmp"):
                    kwargs["parent"] = base
                return finite_scratch(**kwargs)

            def provider_dispatch(argv, **kwargs):
                # Alter only the last pre-run_owned seam, AFTER the caller's
                # source/material/environment preparation, never an SDK call.
                if fault == "seam-environment":
                    kwargs["environ"] = {**kwargs["environ"], "RUBYOPT": "inert denied injection"}
                if fault == "seam-post-source" and engine.service._wire_request.method == "POST":
                    path = root / "release/version.properties"; path.write_bytes(path.read_bytes() + b"\n")
                return original_run_owned(argv, **kwargs)

            try:
                for fd in (0, 1, 2):
                    reader, writer = os.pipe(); readers.append(reader); writers.append(writer)
                    os.dup2(reader if fd == 0 else writer, fd)
                os.write(writers[0], encode(value) + body)
                os.chdir(runtime)
                engine = _Engine(time.monotonic())
                with patch.object(worker, "sys", SimpleNamespace(platform="darwin")), patch.object(worker, "finite_scratch", side_effect=scratch), \
                     patch.object(control.time, "CLOCK_UPTIME_RAW", time.CLOCK_MONOTONIC, create=True), \
                     patch.object(_Engine, "write", write), patch("mobile_release._command_process.run_command", side_effect=fake_command), \
                     patch.object(worker, "run_owned", side_effect=provider_dispatch), \
                     patch.object(subprocess, "Popen", side_effect=AssertionError("no real process permitted")), \
                     patch.dict(os.environ, {"TMPDIR": str(base), "RUBYOPT": "forbidden", "GITHUB_TOKEN": "inert forbidden"}, clear=True):
                    result = run_engine(engine)
            finally:
                os.chdir(old_cwd)
                for fd, saved_fd in enumerate(saved):
                    os.dup2(saved_fd, fd); os.close(saved_fd)
                for writer in writers:
                    os.close(writer)
            try:
                self.assertEqual(os.read(readers[2], 1024), b"")
            finally:
                for reader in readers:
                    os.close(reader)
            self.assertIsNotNone(engine)
            self.assertEqual(result, 0, repr(engine.primary))
            self.assertEqual(frames[-1]["kind"], "terminal", repr(engine.primary))
            self.assertNotIn("INERT-NEVER", json.dumps(frames))
            self.assertTrue(engine.service.closed(), repr(engine.primary))
            self.assertTrue(engine.input.material_closed(), repr(engine.primary))
            self.assertFalse((root / ".mobile-release").exists())
            return frames[-1]["payload"], frames, calls, engine

    def test_same_actual_engine_empty_review_is_not_write_consent(self):
        terminal, frames, calls, engine = self.execute(mode="review")
        self.assertEqual(terminal["outcome"], "complete", repr(engine.primary))
        self.assertEqual(terminal["result"]["decision"], "review-required")
        self.assertEqual(terminal["result"]["observation"], "not-returned")
        self.assertEqual([f["kind"] for f in frames], ["accepted", "observed", "terminal"])
        self.assertEqual([kind for _, kind in calls], ["probe"] * 6 + ["GET"])
        self.assertIsNone(engine.input._pending_ack)

    def test_same_original_pending_ack_one_post_and_readback_three_updates(self):
        terminal, frames, calls, engine = self.execute()
        self.assertEqual(terminal["outcome"], "complete", repr(engine.primary))
        self.assertEqual(terminal["result"]["decision"], "registration-confirmed")
        self.assertEqual(terminal["result"]["attempt"]["status"], "succeeded")
        self.assertEqual([f["kind"] for f in frames], ["accepted", "pending", "attempt", "attempt", "terminal"])
        self.assertEqual([kind for _, kind in calls], ["probe"] * 6 + ["GET", "POST", "GET"])
        self.assertTrue(engine.input._ack_consumed)
        for frame in frames[1:-1]:
            self.assertNotIn("nativeSettlement", frame["payload"])
        self.assertFalse(terminal["result"]["attempt"]["credentialReady"])

    def test_already_found_reuses_without_pending_or_post(self):
        terminal, frames, calls, engine = self.execute(fault="already-found")
        self.assertEqual(terminal["outcome"], "complete", repr(engine.primary))
        self.assertEqual(terminal["result"]["decision"], "reuse")
        self.assertEqual(len(calls), 7)
        self.assertEqual([f["kind"] for f in frames], ["accepted", "terminal"])

    def test_pending_unknown_native_axis_refuses_before_any_command(self):
        terminal, _, calls, _ = self.execute(fault="pending")
        self.assertEqual(terminal["reason"], "journal-unavailable")
        self.assertEqual(calls, [])

    def test_changed_saved_source_refuses_before_any_command(self):
        terminal, _, calls, _ = self.execute(fault="config-before")
        self.assertEqual(terminal["reason"], "saved-source-changed")
        self.assertEqual(calls, [])

    def test_foreign_late_ack_and_precall_source_drift_never_post(self):
        for fault in ("foreign-ack", "late-ack", "config-at-ack", "old-review"):
            with self.subTest(fault=fault):
                terminal, _, calls, engine = self.execute(fault=fault)
                self.assertNotEqual(terminal.get("result", {}).get("decision") if terminal.get("result") else None, "registration-confirmed")
                self.assertNotIn("POST", [kind for _, kind in calls])
                self.assertLessEqual(len(calls), 7)
                self.assertFalse(engine.input._ack_consumed)

    def test_actual_run_owned_seam_rechecks_environment_and_source_after_pending_ack(self):
        for fault, count, consumed in (("seam-environment", 6, False), ("seam-post-source", 7, True)):
            with self.subTest(fault=fault):
                terminal, _, calls, engine = self.execute(fault=fault)
                self.assertNotEqual(terminal["outcome"], "complete")
                self.assertEqual(len(calls), count)
                self.assertNotIn("POST", [kind for _, kind in calls])
                self.assertIs(engine.input._ack_consumed, consumed)

    def test_denied_read_never_becomes_absence(self):
        terminal, frames, calls, engine = self.execute(mode="review", fault="denied")
        self.assertEqual(terminal["outcome"], "complete", repr(engine.primary))
        self.assertEqual(terminal["result"]["observation"], "not-permitted")
        self.assertEqual(terminal["result"]["decision"], "blocked")
        self.assertIsNone(frames[1]["payload"]["beforeSha256"])
        self.assertEqual(len(calls), 7)

    def test_unknown_post_records_audit_once_and_never_retries_or_readbacks(self):
        terminal, frames, calls, engine = self.execute(fault="post-unknown")
        self.assertEqual([kind for _, kind in calls][-2:], ["GET", "POST"])
        self.assertEqual(len(calls), 8)
        self.assertNotEqual(terminal["outcome"], "complete")
        self.assertEqual(frames[-2]["payload"]["update"]["record"]["status"], "unknown")
        self.assertEqual(engine.input.reply_step, 2)

    def test_cancel_in_original_scope_tail_preserves_unknown_and_never_audits_fatal_custody(self):
        terminal, frames, calls, engine = self.execute(fault="stop-post")
        # The real checked runtime scope is interrupted during POST cleanup.
        # Its original ledger correctly refuses to infer known finality even
        # though the fake command itself supplied a positive C/A/W row.
        self.assertEqual(terminal["outcome"], "unknown", repr(engine.primary))
        self.assertEqual(terminal["lifetime"]["stopObserved"], "cancelled")
        self.assertEqual(len(calls), 8)
        self.assertEqual([f["kind"] for f in frames], ["accepted", "pending", "terminal"])
        self.assertTrue(frames[1]["payload"]["update"]["record"]["possibleSend"])
        self.assertTrue(engine.service.attempt.record.cancel_requested)
        self.assertTrue(engine.input._ack_consumed)
        self.assertEqual(engine.input.reply_step, 1)

    def test_restored_reconcile_only_compares_never_adopts_updates_or_posts(self):
        for returned, fault, comparison in ((True, None, "same-response"), (True, "different-resource", "different-response"), (False, None, "unattributed")):
            with self.subTest(comparison=comparison):
                terminal, frames, calls, engine = self.execute(mode="reconcile", returned=returned, fault=fault)
                self.assertEqual(terminal["outcome"], "complete", repr(engine.primary))
                self.assertEqual(terminal["result"]["comparison"], comparison)
                self.assertEqual(terminal["result"]["decision"], "comparison-only")
                self.assertEqual([f["kind"] for f in frames], ["accepted", "observed", "terminal"])
                self.assertEqual(len(calls), 7)
                self.assertIsNone(engine.input._pending_ack)

    def test_closed_grammar_new_domain_name_and_u64_are_not_old_access(self):
        with self.files() as (_, root, runtime):
            value = request(root, runtime, "register")
            value["native"]["journalRevision"] = 2**63
            encoded = encode(value)
            parsed = wire.parse_request(encoded)
            self.assertEqual(parsed.native["journalRevision"], 2**63)
            self.assertEqual(parsed.digest, api.digest(encoded))
            differently_encoded = encoded.replace(b'"protocol":', b'"protocol" : ', 1)
            self.assertEqual(wire.parse_request(differently_encoded).context, parsed.context)
            self.assertNotEqual(wire.parse_request(differently_encoded).digest, parsed.digest)
            from mobile_release import _desktop_store_preflight_protocol as access
            with self.assertRaises(ValueError):
                access.parse_request(encode(value))
            for member, changed in (("newApplication", False), ("displayName", "Other"), ("platform", "android"), ("reference", None)):
                bad = copy.deepcopy(value); bad["context"][member] = changed
                with self.subTest(member=member), self.assertRaises(ValueError):
                    wire.parse_request(encode(bad))
            for member in ("argv", "credentials", "environment", "query", "consent"):
                bad = copy.deepcopy(value); bad["native"][member] = {}
                with self.subTest(member=member), self.assertRaises(ValueError):
                    wire.parse_request(encode(bad))
            with self.assertRaises(ValueError):
                wire.parse_request(encode(value).replace(b'"mode":', b'"mode":"review","mode":', 1))

    def test_reconcile_row_exact_hashes_and_root_numbers_not_boolean(self):
        with self.files() as (_, root, runtime):
            value = request(root, runtime, "reconcile"); value["native"]["prior"] = prior(value)
            wire.parse_request(encode(value))
            for location, member, changed in (("intent", "planSha256", "f" * 64), ("intent", "observedAt", "2026-10-19T00:00:00Z"),
                                              ("row", "sendArmed", False), ("binding", "device", False)):
                bad = copy.deepcopy(value); row = bad["native"]["prior"]
                target = row if location == "row" else row["intent"]["provenance"]["projectBinding"] if location == "binding" else row["intent"]
                target[member] = changed
                with self.subTest(member=member), self.assertRaises(ValueError):
                    wire.parse_request(encode(bad))

    def test_original_input_rejects_lookalike_and_cross_domain(self):
        engine = _Engine(time.monotonic())
        self.assertIs(source_domain(engine.input), SavedCommandDomain.AppleProvisioning)
        class Imposter(control.AppleProvisioningInput):
            pass
        with self.assertRaises(ValueError):
            source_domain(Imposter(time.monotonic()))
        engine.input._domain = SavedCommandDomain.LocalStorePreflight
        with self.assertRaises(ValueError):
            source_domain(engine.input)

    def test_pending_event_and_ack_cannot_substitute_review_scope_or_receipt(self):
        with self.files() as (_, root, runtime):
            selected = wire.parse_request(encode(request(root, runtime, "register")))
            before, plan = wire.expected_plan(selected)
            record = AttemptRecord(plan.context, plan.sha256, "register_bundle_id", "running", "readback_required", True)
            payload = {"observedAt": before.observed_at.isoformat(), "validUntil": plan.valid_until.isoformat(), "beforeSha256": before.sha256,
                "planSha256": plan.sha256, "requestBodySha256": api.digest(plan.request.body), "update": {"sequence": 1, "record": wire.attempt_wire(record)}}
            wire.validate_event(selected, "pending", payload, 1)
            for member, changed in (("beforeSha256", "f" * 64), ("planSha256", "f" * 64), ("requestBodySha256", "f" * 64), ("nativeJoined", True)):
                bad = {**payload, member: changed}
                with self.subTest(member=member), self.assertRaises(ValueError):
                    wire.validate_event(selected, "pending", bad, 1)
            digest = api.digest(api.canonical(payload["update"]))
            reply = {"protocol": wire.PROTOCOL, "operationId": OP, "ownerGeneration": GENERATION, "nonce": selected.native["nonce"],
                "requestSha256": selected.digest, "kind": "journal-ack", "step": 1, "payload": {"revision": 1, "sequence": 1, "recordSha256": digest}}
            self.assertEqual(wire.reply(encode(reply), selected, 1, digest)[0], 1)
            for member, changed in (("operationId", "f" * 32), ("requestSha256", "f" * 64), ("step", True), ("nativeJoined", True)):
                bad = {**reply, member: changed}
                with self.subTest(member=member), self.assertRaises(ValueError):
                    wire.reply(encode(bad), selected, 1, digest)


if __name__ == "__main__":
    unittest.main()
