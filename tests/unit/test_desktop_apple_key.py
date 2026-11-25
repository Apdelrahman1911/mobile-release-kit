"""Same saved engine/input/scratch owners; explicitly inert provider/C-A-W DATA.

No RSA, Ruby, native vault, network or provider operation is executed. The
command outcome substitute below is NOT native completion evidence. Tests
exercise the real closed command, one-use ACK and private handoff branches.
"""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import struct
import subprocess
import time
from types import SimpleNamespace as Data
import unittest
from unittest.mock import patch

from mobile_release import _desktop_apple_provisioning_protocol as wire
from mobile_release import _desktop_apple_provisioning_control as source
from mobile_release import _desktop_apple_key_protocol as key_wire
from mobile_release import _desktop_apple_key_private as private
from mobile_release import _desktop_apple_distribution_key as child
from mobile_release import desktop_apple_provisioning as worker
from mobile_release import apple_provisioning_api as api
from mobile_release import apple_provisioning_signing as signing
from mobile_release.apple_provisioning import prepare
from mobile_release._desktop_apple_provisioning_engine import _Engine
from mobile_release._desktop_saved_command_engine import run_engine
from mobile_release._command_process import _Outer, CommandOutcomeSlot
from mobile_release.build_inputs import finite_scratch
from . import test_desktop_apple_provisioning as old
from . import test_apple_provisioning as fixtures


CSR = b"-----BEGIN CERTIFICATE REQUEST-----\nU1lOVEhFVElDIE5PVCBBIENTUg==\n-----END CERTIFICATE REQUEST-----\n"
KEY, SPKI = b"INERT not a private key", b"INERT not a public key"
FRAME = child.MAGIC + struct.pack(">III", len(KEY), len(CSR), len(SPKI)) + KEY + CSR + SPKI


class BodyFailure(Exception):
    """An inert original body error, never a native cancellation receipt."""


def payload(kind, *, certificate=False):
    rows = [old.bundle()] if kind == "list_bundle_ids" else [fixtures.certificate()] if certificate and kind == "list_certificates" else []
    value = {"data": rows, "links": {"next": None}, "meta": {"paging": {"total": len(rows)}}}
    if kind == "list_profiles":
        value["included"] = []
    return value


def selected(root, runtime, mode="key-review"):
    value = old.request(root, runtime)
    value["context"].update(mode=mode, newApplication=False)
    p8 = {"vaultId": "1" * 32, "generationId": "2" * 32, "recordId": old.RECORD,
          "revisionId": "3" * 32, "revisionCounter": 3}
    value["native"]["key"] = {"sourceP8": p8, "sourceKey": None, "destination": None,
        "entitlements": {}, "review": None, "vaultInventory": {"records": 1, "keys": 0}}
    if mode != "key-prepare":
        return value
    reference = {"operationId": "d" * 32, "ownerGeneration": "e" * 32}
    value["context"]["reference"] = reference
    value["native"]["key"]["destination"] = {**p8, "recordId": "4" * 32, "revisionId": "5" * 32, "revisionCounter": 1}
    at = datetime.now(timezone.utc)
    context, target = wire.core_context(value["native"]["provisioning"]), wire.target(value["native"]["target"])
    # Inert inventory DATA only; the production native review/Initial checks
    # and consent cannot be manufactured by this test fixture.
    port = Data(check=lambda _: None, send=lambda request: api.AppleResponse(200, api.canonical(payload(request.kind)), True))
    before = signing.observe_signing(context, target, port, now=at).observation
    plan = prepare(context, target, before, bindings=(), csr=None, pending=(), now=at)
    assert plan.action == "prepare_csr"
    bundle = plan.bundle
    value["native"]["reviewedAt"] = at.isoformat()
    value["native"]["key"]["review"] = {"reference": reference, "observedAt": at.isoformat(),
        "validUntil": plan.valid_until.isoformat(), "selection": {
            "bundle": {"resourceId": bundle.resource_id, "identifier": bundle.identifier,
                       "platform": bundle.platform, "seedId": bundle.seed_id},
            "beforeSha256": before.sha256, "planSha256": plan.sha256}}
    return value


class KeyWorkerTests(unittest.TestCase):
    def execute(self, mode="key-prepare", *, fault=None):
        with old.BundleWorkerTests.files(self) as (base, root, runtime):
            if mode == "key-recover":
                from .test_desktop_apple_key_recovery import selected as recover_selected
                value = recover_selected(root, runtime)
                if fault in {"recover-csr", "recover-spki", "recover-frame"}:
                    field = {"recover-csr": "csrSha256", "recover-spki": "publicKeySha256", "recover-frame": "frameSha256"}[fault]
                    value["native"]["key"]["recovery"]["output"][field] = "e" * 64
            else:
                value = selected(root, runtime, mode)
            if fault == "existing-key":
                value["native"]["key"]["vaultInventory"]["keys"] = 1
            if fault == "account-pending":
                value["native"]["pending"] = [{"accountRef": old.ACCOUNT, "operationId": "8" * 32,
                    "action": "key_prepare", "status": "unknown", "nativeSettlement": "known"}]
            for name in ("apple_provisioning_signing.rb", "apple_distribution_key.rb", "apple_distribution_key_verify.rb"):
                (runtime / "store/tooling/fastlane" / name).write_bytes(b"INERT never executed")
            roles, material = ("asc-p8", "asc-key-id", "asc-issuer-id"), old.MATERIAL
            if mode == "key-recover":
                from mobile_release._desktop_apple_certificate_private import ROLES
                roles = tuple(role for role, _ in ROLES)
                material += (base64.b64encode(KEY if fault != "recover-private" else b"different-inert-private"), CSR, base64.b64encode(SPKI))
            body = old.PREFIX + old.encode({"schemaVersion": 1, "files": [{"role": role, "bytes": len(raw)}
                for role, raw in zip(roles, material)]}) + b"".join(material) + old.SUFFIX
            saved = [os.dup(fd) for fd in (0, 1, 2)]
            readers, writers, frames, calls, received = [], [], [], [], bytearray()
            cwd = Path.cwd()
            engine = None
            original_write, original_private_write = _Engine.write, private.KeyOutput._write
            original_binding = child.AppleDistributionKeyWork._binding
            ordinary = BodyFailure("inert returned-command body failure")

            def binding(owned, operation):
                if fault == "late-body-error" and owned._parts is not None and not owned._command_active:
                    engine.input.stop("cancelled")
                    raise ordinary
                return original_binding(owned, operation)

            def reply(current, frame, *, wrong=False):
                sequence = frame["sequence"]
                digest = api.digest(api.canonical(frame["payload"]["update"] if sequence == 1 else frame["payload"]))
                result = {"protocol": wire.PROTOCOL, "operationId": old.OP, "ownerGeneration": old.GENERATION,
                    "nonce": "0" * 32 if wrong else value["native"]["nonce"], "requestSha256": current.request.digest,
                    "sequence": sequence, "kind": "key-pending-ack" if sequence == 1 else "key-retained",
                    "journalRevision": sequence, "ackSha256": digest}
                os.write(writers[0], old.encode(result))

            def write(current, raw, *, terminal=False):
                original_write(current, raw, terminal=terminal)
                self.assertEqual(os.read(readers[1], wire.response_limit(mode)), raw)
                frame = json.loads(raw); frames.append(frame)
                if frame["kind"] == "key-pending":
                    if fault == "stop-pending":
                        os.write(writers[0], key_wire.STOP)
                        return  # Actual native abandon_pending sends NO ACK.
                    elif fault == "stop-pending-with-ack":
                        os.write(writers[0], key_wire.STOP)
                    elif fault == "partial-pending-stop":
                        os.write(writers[0], b"{" + key_wire.STOP)
                        return
                    elif fault == "duplicate-pending-stop":
                        os.write(writers[0], key_wire.STOP * 2)
                        return
                    elif fault == "stale-pending":
                        (root / "release/version.properties").write_bytes(b"VERSION_NAME=1.2.3\nBUILD_NUMBER=43\n")
                    reply(current, frame, wrong=fault == "wrong-pending")
                elif frame["kind"] == "key-output" and fault == "stop-before-body":
                    os.write(writers[0], key_wire.STOP)
                elif frame["kind"] == "key-compared":
                    if fault == "recover-stop":
                        current.input.stop("cancelled")
                        return  # Original STOP prevents the read, not a fabricated reply.
                    if fault == "recover-source":
                        (root / "release/version.properties").write_bytes(b"VERSION_NAME=1.2.3\nBUILD_NUMBER=43\n")
                    ack = {"protocol": wire.PROTOCOL, "operationId": old.OP, "ownerGeneration": old.GENERATION,
                        "nonce": value["native"]["nonce"], "requestSha256": current.request.digest,
                        "kind": "key-compared-ack", "step": 1, "payload": {
                            "comparisonSha256": api.digest(api.canonical(frame["payload"])),
                            "originalRowSha256": value["native"]["key"]["recovery"]["rowSha256"]}}
                    if fault == "recover-foreign-ack":
                        ack["operationId"] = "9" * 32
                    if fault == "recover-wrong-row":
                        ack["payload"]["originalRowSha256"] = "0" * 64
                    os.write(writers[0], b"{}\n" if fault == "recover-partial-ack" else old.encode(ack))

            def write_private(output, data):
                original_private_write(output, data)
                captured = os.read(readers[1], private.TRANSFER_LIMIT)
                self.assertEqual(captured, data)
                received.extend(captured)
                if data is output._header and fault == "stop-during-body":
                    os.write(writers[0], key_wire.STOP)
                if data is output._frame:
                    if fault == "stop-before-ack":
                        os.write(writers[0], key_wire.STOP)
                    reply(engine, frames[-1], wrong=fault == "wrong-custody")

            def fake_command(argv, **kwargs):
                operation = engine.service
                ledger = engine.guard.lifetime_ledger
                fake = object(); ledger._bind_command(fake)
                ledger._finish_command(fake, dispatched=True, contained=True, cleanup_complete=True)
                index = len(calls)
                request = operation._wire_request
                calls.append(request.kind if request else ("verifier" if mode == "key-recover" else "generator") if index == 6 else "probe")
                self.assertLessEqual(kwargs["timeout"], 60)
                if index < 6:
                    text = ("", "3.3.12", "4.0.16", "", "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2", "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2")[index]
                    return subprocess.CompletedProcess(argv, 0, text, "")
                if mode == "key-review":
                    self.assertEqual(request.method, "GET")
                    document = payload(request.kind, certificate=fault == "existing-certificate")
                    if fault == "partial-inventory" and request.kind == "list_profiles":
                        del document["meta"]
                    raw = old.encode({"schemaVersion": 1, "scope": signing.SCOPE,
                        "contextSha256": api.digest(api.canonical(wire.core_context_wire(operation.context))),
                        "operationId": old.OP, "bundleId": operation.target.bundle_id,
                        "requestSha256": api.request_sha256(request), "ackSha256": None,
                        "response": {"status": 200, "failure": None, "bodyBase64": base64.b64encode(api.canonical(document)).decode("ascii")}})
                    return subprocess.CompletedProcess(argv, 0, raw, b"")
                self.assertEqual(index, 6)
                if mode == "key-recover":
                    self.assertIsNone(request)
                    self.assertEqual(engine.input.reply_step, 0)
                    self.assertFalse(engine.input._ack_consumed)
                    self.assertTrue(str(argv[3]).endswith("/apple_distribution_key_verify.rb"))
                    self.assertEqual(kwargs["output_limit"], child.PUBLIC_LIMIT)
                    self.assertFalse(any("MOBILE_RELEASE_ASC_" in name for name in kwargs["environ"]))
                    self.assertEqual(Path(argv[4]).read_bytes(), child._stored_frame(material[3:]))
                    public = child.PUBLIC_MAGIC + struct.pack(">II", len(CSR), len(SPKI)) + CSR + SPKI
                    outer, slot = object.__new__(_Outer), object.__new__(CommandOutcomeSlot)
                    slot._engine, outer.slot, outer.guard = outer, slot, engine.guard
                    outer.scope = outer.binding = outer.evidence = outer._store_timing = None
                    outer.owns = outer.text = False
                    outer.decoded, outer.outputs = (public, b""), [bytearray(public), bytearray()]
                    operation._distribution_key.bind_command_slot(outer, slot)
                    return subprocess.CompletedProcess(argv, 0, public, b"")
                self.assertEqual(engine.input.reply_step, 1)
                self.assertTrue(engine.input._ack_consumed)
                self.assertFalse(any("MOBILE_RELEASE_ASC_" in key for key in kwargs["environ"]))
                self.assertTrue(str(argv[3]).endswith("/apple_distribution_key.rb"))
                self.assertEqual(kwargs["output_limit"], child.PRIVATE_LIMIT)
                # Synthetic C/A/W object only. Actual production uses its
                # original pre-acquisition slot hook; no native fact is made.
                outer, slot = object.__new__(_Outer), object.__new__(CommandOutcomeSlot)
                slot._engine, outer.slot, outer.guard = outer, slot, engine.guard
                outer.scope = outer.binding = outer.evidence = outer._store_timing = None
                outer.owns = outer.text = False
                outer.decoded, outer.outputs = (FRAME, b""), [bytearray(FRAME), bytearray()]
                operation._distribution_key.bind_command_slot(outer, slot)
                if fault in {"stop-generator", "early-body-error"}:
                    engine.input.stop("cancelled")
                if fault == "early-body-error":
                    raise ordinary
                return subprocess.CompletedProcess(argv, 0, FRAME, b"")

            def scratch(**kwargs):
                if kwargs.get("parent") == Path("/private/tmp"):
                    kwargs["parent"] = base
                return finite_scratch(**kwargs)

            try:
                for fd in (0, 1, 2):
                    reader, writer = os.pipe(); readers.append(reader); writers.append(writer)
                    os.dup2(reader if fd == 0 else writer, fd)
                os.write(writers[0], old.encode(value) + body)
                os.chdir(runtime)
                engine = _Engine(time.monotonic())
                with patch.object(worker, "sys", Data(platform="darwin")), \
                     patch.object(worker, "finite_scratch", side_effect=scratch), \
                     patch.object(source.time, "CLOCK_UPTIME_RAW", time.CLOCK_MONOTONIC, create=True), \
                     patch.object(_Engine, "write", write), patch.object(private.KeyOutput, "_write", write_private), \
                     patch.object(child.AppleDistributionKeyWork, "_binding", binding), \
                     patch("mobile_release._command_process.run_command", side_effect=fake_command), \
                     patch.object(child.AppleDistributionKeyWork, "_outcome", autospec=True,
                         side_effect=lambda owned: Data(no_target=None, result_integrity="complete", returncode=0) if owned._slot else None), \
                     patch.object(subprocess, "Popen", side_effect=AssertionError("no real process permitted")), \
                     patch.dict(os.environ, {"TMPDIR": str(base), "RUBYOPT": "denied", "GITHUB_TOKEN": "inert denied"}, clear=True):
                    code = run_engine(engine)
            finally:
                os.chdir(cwd)
                for fd, original in enumerate(saved):
                    os.dup2(original, fd); os.close(original)
                for fd in readers + writers:
                    os.close(fd)
            self.assertNotIn(KEY.decode(), repr(frames))
            if mode != "key-recover":
                self.assertNotIn(CSR.decode(), repr(frames))
            else:
                # CSR belongs only to the same PRIVATE native comparison
                # event, never its public terminal/renderer result.
                self.assertNotIn(CSR.decode(), repr([row for row in frames if row["kind"] == "terminal"]))
            self.assertFalse((root / ".mobile-release").exists())
            return engine, code, frames, calls, bytes(received)

    def test_review_requires_complete_provider_and_native_inventory_without_post(self):
        engine, code, frames, calls, raw = self.execute("key-review")
        self.assertEqual(code, 0, repr(engine.primary))
        self.assertEqual(calls[6:], ["list_bundle_ids", "list_certificates", "list_profiles"])
        self.assertEqual(frames[-1]["payload"]["result"]["decision"], "prepare-review")
        self.assertEqual(raw, b"")
        for fault in ("existing-key", "existing-certificate", "partial-inventory", "account-pending"):
            with self.subTest(fault=fault):
                _, code, frames, calls, raw = self.execute("key-review", fault=fault)
                self.assertEqual(code, 0)
                self.assertNotEqual(frames[-1]["payload"]["result"]["decision"], "prepare-review")
                self.assertNotIn("generator", calls)
                self.assertEqual(raw, b"")

    def test_local_generator_only_after_pending_and_body_ack_not_saved_or_csr(self):
        engine, code, frames, calls, raw = self.execute()
        self.assertEqual(code, 0, repr(engine.primary))
        self.assertEqual(calls, ["probe"] * 6 + ["generator"])
        self.assertEqual([row["kind"] for row in frames], ["accepted", "key-pending", "key-output", "terminal"])
        self.assertEqual(raw, private.header(engine.request.digest, FRAME) + FRAME)
        result = frames[-1]["payload"]["result"]
        self.assertFalse(result["saved"] or result["certificateRequested"] or result["credentialReady"])
        self.assertTrue(engine.service._key_output.closed())
        self.assertTrue(engine.service._distribution_key.private_closed())

    def test_stop_before_during_body_and_before_ack_keeps_custody_not_success(self):
        for fault in ("stop-generator", "stop-before-body", "stop-during-body", "stop-before-ack"):
            with self.subTest(fault=fault):
                engine, code, frames, calls, raw = self.execute(fault=fault)
                self.assertEqual(code, 0, repr(engine.primary))
                self.assertEqual(calls.count("generator"), 1)
                self.assertEqual(raw, private.header(engine.request.digest, FRAME) + FRAME)
                self.assertEqual(frames[-1]["payload"]["outcome"], "cancelled")
                self.assertIsNone(frames[-1]["payload"]["result"])
                self.assertTrue(engine.service._key_output.closed())

    def test_pending_wrong_scope_stop_or_source_drift_never_enters_generator(self):
        for fault in ("wrong-pending", "stop-pending-with-ack", "partial-pending-stop",
                      "duplicate-pending-stop", "stale-pending"):
            with self.subTest(fault=fault):
                engine, _, frames, calls, raw = self.execute(fault=fault)
                self.assertNotIn("generator", calls)
                self.assertEqual(raw, b"")
                self.assertIsNone(engine.service._distribution_key)
                self.assertNotEqual(frames[-1]["payload"]["outcome"], "complete")
                if fault != "stale-pending":
                    self.assertTrue(engine.input.custody_unknown)
                    self.assertTrue(engine.input._key_ack_lost)
                    self.assertEqual(frames[-1]["payload"]["outcome"], "unknown")

    def test_exact_pre_pending_stop_closes_original_worker_without_generation_or_ack(self):
        engine, code, frames, calls, raw = self.execute(fault="stop-pending")
        self.assertEqual(code, 0, repr(engine.primary))
        self.assertEqual(calls, ["probe"] * 6)
        self.assertEqual(raw, b"")
        self.assertEqual([row["kind"] for row in frames], ["accepted", "key-pending", "terminal"])
        self.assertEqual(frames[-1]["payload"]["outcome"], "cancelled")
        self.assertIsNone(frames[-1]["payload"]["result"])
        lifetime = frames[-1]["payload"]["lifetime"]
        self.assertFalse(lifetime["fatal"])
        self.assertTrue(lifetime["contained"] and lifetime["inputClosed"]
                        and lifetime["handlersRestored"] and lifetime["invocationClosed"])
        self.assertTrue(engine.input._key_stop_seen and engine.input.closed)
        self.assertFalse(engine.input.custody_unknown or engine.input._key_ack_lost or engine.input._ack_consumed)
        self.assertIsNone(engine.input._pending_ack)
        self.assertIsNone(engine.service._distribution_key)
        self.assertTrue(engine.service._key_output.closed())
        # No simulated native NeverGenerated/save/retirement capability is
        # created here: those still require the real parent's exact originals.

    def test_all_family_pending_uses_native_certificate_action_without_losing_fence(self):
        with old.BundleWorkerTests.files(self) as (_, root, runtime):
            rows = [{"accountRef": old.ACCOUNT, "operationId": str(index) * 32,
                     "action": action, "status": "unknown", "nativeSettlement": "known"}
                    for index, action in enumerate(("register_bundle_id", "profile_setup",
                                                    "key_prepare", "create_certificate"), 1)]
            for request in (old.request(root, runtime), selected(root, runtime, "key-review"),
                            selected(root, runtime, "key-prepare")):
                request["native"]["pending"] = copy.deepcopy(rows)
                parsed = wire.parse_request(old.encode(request))
                pending = wire.pending(parsed.native["pending"], old.ACCOUNT)
                self.assertEqual([row.kind for row in pending], [row["action"] for row in rows])
                self.assertTrue(all(row.unresolved for row in pending))
                changed = copy.deepcopy(request)
                changed["native"]["pending"][-1]["action"] = "certificate_issue"
                with self.assertRaises(wire.ProtocolError):
                    wire.parse_request(old.encode(changed))

    def test_existing_or_late_body_error_is_not_hidden_by_returned_frame_and_stop(self):
        for fault in ("early-body-error", "late-body-error"):
            with self.subTest(fault=fault):
                engine, code, frames, calls, raw = self.execute(fault=fault)
                self.assertNotEqual(code, 0)
                self.assertIsInstance(engine.service.primary, BodyFailure)
                self.assertIs(engine.guard.lifetime_ledger._primary, engine.service.primary)
                self.assertTrue(engine.input._key_body_failed)
                self.assertEqual(calls.count("generator"), 1)
                self.assertEqual(raw, b"")
                self.assertIs(engine.service._distribution_key._frame, FRAME)
                self.assertFalse(engine.service._distribution_key.private_closed())
                self.assertEqual(frames[-1]["payload"]["outcome"], "unknown")

    def test_foreign_custody_ack_keeps_original_private_capture_and_unknown(self):
        engine, code, frames, calls, raw = self.execute(fault="wrong-custody")
        self.assertNotEqual(code, 0)
        self.assertEqual(calls.count("generator"), 1)
        self.assertEqual(raw, private.header(engine.request.digest, FRAME) + FRAME)
        self.assertFalse(engine.service._key_output.closed())
        self.assertIs(engine.service._distribution_key._frame, FRAME)
        self.assertTrue(engine.input.custody_unknown)
        self.assertEqual(frames[-1]["payload"]["outcome"], "unknown")

    def test_protocol_stays_closed_no_existing_mode_key_scope_or_unsupported_entry(self):
        with old.BundleWorkerTests.files(self) as (_, root, runtime):
            request = selected(root, runtime, "key-prepare")
            parsed = wire.parse_request(old.encode(request))
            self.assertEqual(wire.command_count("key-prepare"), 7)
            self.assertEqual(key_wire.expected_plan(parsed).sha256,
                             request["native"]["key"]["review"]["selection"]["planSha256"])
            for field, changed in (("destination", None), ("sourceKey", request["native"]["key"]["sourceP8"]),
                                   ("vaultInventory", {"records": 1, "keys": 1}),
                                   ("vaultInventory", {"records": 129, "keys": 0})):
                value = copy.deepcopy(request); value["native"]["key"][field] = changed
                with self.assertRaises(wire.ProtocolError):
                    wire.parse_request(old.encode(value))
            for mode in ("review", "profile-review", "certificate-create", "key-recover"):
                value = copy.deepcopy(request); value["context"]["mode"] = mode
                with self.assertRaises(wire.ProtocolError):
                    wire.parse_request(old.encode(value))


if __name__ == "__main__":
    unittest.main()
