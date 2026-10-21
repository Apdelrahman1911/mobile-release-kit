"""Real fixed engine/input/scratch owners; explicitly fake provider/C-A-W.

The synthetic key, CSR, leaf and ACKs are not native/crypto evidence. These
tests never execute a child, Ruby, network, vault or Apple operation.
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

from mobile_release import _desktop_apple_certificate_private as private
from mobile_release import _desktop_apple_certificate_protocol as certificate
from mobile_release import _desktop_apple_certificate_worker as steps
from mobile_release import _desktop_apple_certificate_control as control
from mobile_release import _desktop_ios_signed_operation as original_slot
from mobile_release import _desktop_apple_provisioning_control as source
from mobile_release import _desktop_apple_provisioning_protocol as wire
from mobile_release import _desktop_apple_distribution_key as child
from mobile_release import desktop_apple_provisioning as worker
from mobile_release import apple_provisioning_api as api
from mobile_release import apple_provisioning_certificate_issuance as issuance
from mobile_release import apple_provisioning_signing as signing
from mobile_release.apple_provisioning import PublicCSR
from mobile_release._desktop_apple_provisioning_engine import _Engine
from mobile_release._desktop_saved_command_engine import run_engine
from mobile_release._command_process import _Outer, CommandOutcomeSlot
from mobile_release.build_inputs import finite_scratch
from . import test_desktop_apple_provisioning as old
from . import test_desktop_apple_key as key_fixture
from . import test_apple_provisioning as fixture

KEY = {"vaultId": "1" * 32, "generationId": "2" * 32, "recordId": "4" * 32,
       "revisionId": "5" * 32, "revisionCounter": 1}
CSR, SPKI, PRIVATE = key_fixture.CSR, key_fixture.SPKI, key_fixture.KEY
FRAME = child.PUBLIC_MAGIC + struct.pack(">II", len(CSR), len(SPKI)) + CSR + SPKI


def inventory(kind, existing):
    rows = [old.bundle()] if kind == "list_bundle_ids" else [fixture.certificate()] if existing and kind == "list_certificates" else []
    value = {"data": rows, "links": {"next": None}, "meta": {"paging": {"total": len(rows)}}}
    if kind == "list_profiles":
        value["included"] = []
    return value


def selected(root, runtime, mode="certificate-review", *, key_history=True, prior_receipt=None):
    value = old.request(root, runtime)
    value["context"].update(mode=mode, keyRecordId=KEY["recordId"], keyRecordRevision=1, newApplication=False)
    p8 = {**KEY, "recordId": old.RECORD, "revisionId": "3" * 32, "revisionCounter": 3}
    history = {"reference": {"operationId": "6" * 32, "ownerGeneration": "7" * 32}, "sourceKey": KEY,
        "accountRef": old.ACCOUNT, "teamId": "ABCDE12345", "csrSha256": api.digest(CSR),
        "publicKeySha256": api.digest(SPKI), "updateSha256": "9" * 64} if key_history else None
    value["native"]["certificate"] = {"sourceP8": p8, "sourceKey": KEY, "entitlements": {},
        "keyPreparation": history, "review": None, "prior": None}
    if mode == "certificate-create":
        at = datetime.now(timezone.utc)
        reference = {"operationId": "d" * 32, "ownerGeneration": "e" * 32}
        value["context"]["reference"] = reference
        value["native"]["reviewedAt"] = at.isoformat()
        context, target = wire.core_context(value["native"]["provisioning"]), wire.target(value["native"]["target"])
        provider = Data(check=lambda _: None, send=lambda request: api.AppleResponse(200, api.canonical(inventory(request.kind, False)), True))
        before = signing.observe_signing(context, target, provider, now=at)
        plan = issuance.prepare_certificate(context, target, before, bindings=(),
            csr=PublicCSR(certificate.key_ref(KEY), CSR, api.digest(SPKI)), pending=(), now=at)
        value["native"]["certificate"]["review"] = {"reference": reference, "observedAt": at.isoformat(),
            "validUntil": plan.valid_until.isoformat(), "selection": {
                "bundle": {"resourceId": plan.bundle.resource_id, "identifier": target.bundle_id,
                           "platform": plan.bundle.platform, "seedId": plan.bundle.seed_id},
                "beforeSha256": before.observation.sha256, "planSha256": plan.sha256,
                "csrSha256": api.digest(CSR), "publicKeySha256": api.digest(SPKI)}}
    elif mode == "certificate-reconcile":
        # A restarted journal row is historical DATA, deliberately Unknown.
        # It creates neither an old native reservation nor a new approval.
        reference = {"operationId": "d" * 32, "ownerGeneration": "e" * 32}
        value["context"]["reference"] = reference
        previous = {"context": {**value["native"]["provisioning"], "operationId": reference["operationId"]},
            "planSha256": "f" * 64, "action": "create_certificate", "status": "unknown",
            "reason": "provider_outcome_unknown", "possibleSend": True,
            "responseResourceId": None if prior_receipt is None else prior_receipt.resource_id,
            "responseResourceSha256": None if prior_receipt is None else prior_receipt.sha256,
            "observedResourceId": None, "cancelRequested": False}
        value["native"]["certificate"]["prior"] = {"reference": reference, "sourceKey": KEY,
            "target": {**value["native"]["target"], "entitlementsSha256": api.digest(api.canonical({}))},
            "csrSha256": api.digest(CSR), "publicKeySha256": api.digest(SPKI), "record": previous,
            "receipt": None if prior_receipt is None else api.document(prior_receipt.private_record())}
    return value


class CertificateWorkerTests(unittest.TestCase):
    def execute(self, mode="certificate-review", *, existing=False, fault=None, prior_receipt=None, restored=False):
        with old.BundleWorkerTests.files(self) as (base, root, runtime):
            value = selected(root, runtime, mode, key_history=fault != "no-key-history", prior_receipt=prior_receipt)
            if restored:
                # NEW-only restore changes all ref identities, never the old
                # row. The real private verifier below remains explicitly fake.
                current = {"vaultId": "a" * 32, "generationId": "b" * 32, "recordId": "e" * 32,
                           "revisionId": "d" * 32, "revisionCounter": 1}
                scope = value["native"]["certificate"]
                scope["sourceKey"], scope["keyPreparation"] = current, None
                scope["sourceP8"].update(vaultId=current["vaultId"], generationId=current["generationId"])
                value["context"].update(keyRecordId=current["recordId"], keyRecordRevision=1)
            if fault in {"prior-csr", "prior-spki"}:
                field = "csrSha256" if fault == "prior-csr" else "publicKeySha256"
                value["native"]["certificate"]["prior"][field] = "e" * 64
            initial_prior = copy.deepcopy(value["native"]["certificate"]["prior"])
            material = old.MATERIAL + (base64.b64encode(PRIVATE), CSR, base64.b64encode(SPKI))
            body = old.PREFIX + old.encode({"schemaVersion": 1, "files": [{"role": role, "bytes": len(raw)}
                for (role, _), raw in zip(private.ROLES, material)]}) + b"".join(material) + old.SUFFIX
            saved = [os.dup(fd) for fd in (0, 1, 2)]
            readers, writers, frames, calls = [], [], [], []
            cwd, engine, posted = Path.cwd(), None, False
            original_write = _Engine.write
            retain = issuance.CertificateCreationAttempt.retain_returned_response
            body_error = ValueError("synthetic original returned-body failure")

            def retained(attempt, response):
                result = retain(attempt, response)
                if fault in {"stop-after-returned-201", "body-after-returned-201", "earlier-body-then-stop",
                             "foreign-closing-command", "expired-closing-command", "retired-closing-home",
                             "inactive-closing-invocation", "changed-closing-source", "later-missing-join"}:
                    engine.input.stop("cancelled")
                    if fault == "body-after-returned-201":
                        raise body_error
                    if fault == "earlier-body-then-stop":
                        engine.service.remember(body_error)
                    if fault == "foreign-closing-command":
                        engine.service._pending += 1
                    if fault == "expired-closing-command":
                        engine.input.first_failure -= 11
                    if fault == "retired-closing-home":
                        engine.service.runtime._home.active = False
                    if fault == "inactive-closing-invocation":
                        engine.service.invocation.active = False
                    if fault == "changed-closing-source":
                        engine.service.request.native["provisioning"]["credentialRevision"] += 1
                return result

            def write(current, raw, *, terminal=False):
                original_write(current, raw, terminal=terminal)
                self.assertEqual(os.read(readers[1], wire.response_limit(mode)), raw)
                frame = json.loads(raw); frames.append(frame)
                kind, payload = frame["kind"], frame["payload"]
                digest = api.digest(api.canonical(payload))
                if kind == "certificate-key":
                    ack = {"keySha256": digest, "csrSha256": api.digest(CSR), "publicKeySha256": api.digest(SPKI),
                           "keySavedAckSha256": None if restored or fault == "no-key-history" else "8" * 64}
                    if fault == "restored-key-stop":
                        engine.input.stop("cancelled")
                    if fault == "restored-key-source-changed":
                        (root / "release/version.properties").write_bytes(b"VERSION_NAME=1.2.3\nBUILD_NUMBER=43\n")
                    if fault == "restored-key-wrong-ack":
                        ack["keySha256"] = "0" * 64
                elif kind == "certificate-identities":
                    rows = payload["certificates"]
                    ack = {"identitySha256": digest, "batch": payload["batch"], "seen": len(rows), "ambiguous": False,
                        "checkedAt": int(datetime.now(timezone.utc).timestamp()), "selected": None if not rows else {
                            "resourceId": rows[0]["resourceId"], "certificateSha256": api.digest(fixture.CERT_BYTES),
                            "notBefore": int(fixture.CREATED.timestamp()), "notAfter": int(fixture.EXPIRES.timestamp())}}
                    if fault == "foreign-identity":
                        ack["identitySha256"] = "0" * 64
                    if fault == "stale-identity":
                        ack["checkedAt"] -= 301
                elif kind == "certificate-policy":
                    ack = {"policySha256": digest, "certificateSha256": payload["certificateSha256"]}
                elif kind in {"certificate-pending", "certificate-attempt"}:
                    update = payload["update"]
                    ack = {"revision": update["sequence"], "sequence": update["sequence"],
                           "recordSha256": api.digest(api.canonical(update))}
                    if kind == "certificate-attempt":
                        ack["stopped"] = current.input.stop_reason != "none"
                        if fault == "stopped-audit-before-next-get":
                            # Native has stopped; Python has NOT observed it.
                            # The actual closed ACK parser must latch it before
                            # another provider command can pass its checkpoint.
                            self.assertEqual(current.input.stop_reason, "none")
                            ack["stopped"] = True
                        elif fault == "missing-audit-stopped":
                            del ack["stopped"]
                        elif fault == "malformed-audit-stopped":
                            ack["stopped"] = 1
                    if kind == "certificate-pending":
                        if fault == "stale-pending":
                            (root / "release/version.properties").write_bytes(b"VERSION_NAME=1.2.3\nBUILD_NUMBER=43\n")
                        if fault == "stop-pending":
                            engine.input.stop("cancelled")
                        if fault == "foreign-pending":
                            ack["recordSha256"] = "0" * 64
                else:
                    return
                reply = {"protocol": wire.PROTOCOL, "operationId": old.OP, "ownerGeneration": old.GENERATION,
                    "nonce": value["native"]["nonce"], "requestSha256": current.request.digest,
                    "kind": kind + "-ack", "step": frame["sequence"], "payload": ack}
                os.write(writers[0], old.encode(reply))

            def command(argv, **kwargs):
                nonlocal posted
                operation = engine.service
                ledger = engine.guard.lifetime_ledger
                index, request = len(calls), operation._wire_request
                post = request is not None and request.method == "POST"
                if post:
                    # Actual constructor hook and owner context; C/A/W finality
                    # is explicitly synthetic here, never native qualification.
                    outer, slot = object.__new__(_Outer), object.__new__(CommandOutcomeSlot)
                    slot._engine, outer.slot, outer.guard = outer, slot, engine.guard
                    outer.scope = outer.binding = outer.evidence = outer._store_timing = None
                    outer.owns = outer.text = False
                    outer.decoded = None
                    ledger._bind_command(slot)
                    control.bind_post_command_slot(operation, outer, slot)
                else:
                    fake = object(); ledger._bind_command(fake)
                    ledger._finish_command(fake, dispatched=True, contained=True, cleanup_complete=True)
                calls.append(request.kind if request else "verifier" if index == 6 else "policy" if index > 6 else "probe")
                self.assertLessEqual(kwargs["timeout"], 60)
                if index < 6:
                    text = ("", "3.3.12", "4.0.16", "", "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2", "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2")[index]
                    return subprocess.CompletedProcess(argv, 0, text, "")
                if index == 6:
                    self.assertTrue(str(argv[3]).endswith("/apple_distribution_certificate_prepare.rb"))
                    self.assertEqual(kwargs["output_limit"], child.PUBLIC_LIMIT)
                    self.assertFalse(any("MOBILE_RELEASE_ASC_" in key for key in kwargs["environ"]))
                    self.assertEqual(Path(argv[4]).read_bytes(), child._stored_frame(material[3:]))
                    outer, slot = object.__new__(_Outer), object.__new__(CommandOutcomeSlot)
                    slot._engine, outer.slot, outer.guard = outer, slot, engine.guard
                    outer.scope = outer.binding = outer.evidence = outer._store_timing = None
                    outer.owns = outer.text = False
                    outer.decoded, outer.outputs = (FRAME, b""), [bytearray(FRAME), bytearray()]
                    operation._distribution_key.bind_command_slot(outer, slot)
                    return subprocess.CompletedProcess(argv, 0, FRAME, b"")
                if request is None:
                    self.assertTrue(str(argv[3]).endswith("/apple_distribution_certificate_verify.rb"))
                    self.assertEqual(kwargs["output_limit"], private.OUTPUT_LIMIT)
                    self.assertFalse(any("MOBILE_RELEASE_ASC_" in key for key in kwargs["environ"]))
                    policy = operation._certificate.policy
                    self.assertEqual(Path(argv[4]).read_bytes(), policy.body)
                    result = {"schemaVersion": 1, "scope": "offline-apple-distribution-certificate",
                        "requestBindingSha256": operation.request.digest, "identityAckSha256": policy.identity_ack,
                        "certificateSha256": api.digest(fixture.CERT_BYTES), "publicKeySha256": api.digest(SPKI),
                        "teamId": operation.target.team_id, "revocationChecked": False, "checkedAt": datetime.now(timezone.utc).isoformat(),
                        "chainSha256": [api.digest(fixture.CERT_BYTES), certificate.INTERMEDIATE_SHA256, certificate.ROOT_SHA256]}
                    if fault == "wrong-policy-ack":
                        result["identityAckSha256"] = "0" * 64
                    return subprocess.CompletedProcess(argv, 0, api.canonical(result), b"")
                self.assertNotIn(PRIVATE.decode(), repr(kwargs["environ"]))
                if request.method == "POST":
                    self.assertEqual(mode, "certificate-create")
                    self.assertTrue(engine.input._ack_consumed)
                    self.assertEqual(frames[-1]["kind"], "certificate-pending")
                    self.assertEqual(calls.count("create_certificate"), 1)
                    posted = True
                    document, status = {"data": {"id": "certificate-one", "type": "certificates"}}, 201
                else:
                    document, status = inventory(request.kind, existing or posted), 200
                failure = None
                if fault == "partial" and request.kind == "list_profiles":
                    del document["meta"]
                if fault == "denied" and request.kind == "list_certificates":
                    status, failure = 403, "provider_request_unconfirmed"
                if fault == "post-unknown" and request.method == "POST":
                    status, failure = 503, "provider_request_unconfirmed"
                raw = {"schemaVersion": 1, "scope": issuance.SCOPE,
                    "contextSha256": api.digest(api.canonical(wire.core_context_wire(operation.context))),
                    "operationId": old.OP, "bundleId": operation.target.bundle_id, "requestSha256": api.request_sha256(request),
                    "keySavedAckSha256": operation._certificate.key_saved_ack if request.method == "POST" else None,
                    "ackSha256": engine.input._pending_ack if request.method == "POST" else None,
                    "response": {"status": status, "failure": failure,
                        "bodyBase64": None if failure else base64.b64encode(api.canonical(document)).decode("ascii")}}
                raw = old.encode(raw)
                if post:
                    outer.decoded = (raw, b"")
                    ledger._finish_command(slot, dispatched=True, contained=True, cleanup_complete=True)
                return subprocess.CompletedProcess(argv, 0, raw, b"")

            def outcome(slot, guard, scope, binding):
                owned = engine.service._certificate
                if (fault == "missing-post-join" or fault == "later-missing-join" and owned._post_retained is not None
                        or owned._post_original is None or owned._post_original[0] is not slot
                        or guard is not engine.guard or scope is not None or binding is not None):
                    return None
                return Data(no_target=None, result_integrity="complete", returncode=0)

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
                with patch.object(worker, "sys", Data(platform="darwin")), patch.object(worker, "finite_scratch", side_effect=scratch), \
                     patch.object(source.time, "CLOCK_UPTIME_RAW", time.CLOCK_MONOTONIC, create=True), \
                     patch.object(_Engine, "write", write), patch("mobile_release._command_process.run_command", side_effect=command), \
                     patch.object(issuance.CertificateCreationAttempt, "retain_returned_response", retained), \
                     patch.object(original_slot, "original_outcome", side_effect=outcome), \
                     patch.object(child.AppleDistributionKeyWork, "_outcome", autospec=True,
                         side_effect=lambda owned: Data(no_target=None, result_integrity="complete", returncode=0) if owned._slot else None), \
                     patch.object(subprocess, "Popen", side_effect=AssertionError("no child execution")), \
                     patch.dict(os.environ, {"TMPDIR": str(base), "RUBYOPT": "denied", "GITHUB_TOKEN": "inert denied"}, clear=True):
                    code = run_engine(engine)
            finally:
                os.chdir(cwd)
                for fd, original in enumerate(saved):
                    os.dup2(original, fd); os.close(original)
                for descriptor in readers + writers:
                    os.close(descriptor)
            self.assertFalse((root / ".mobile-release").exists())
            self.assertNotIn(PRIVATE.decode(), repr(frames))
            self.assertNotIn(old.MATERIAL[0].decode(), repr(frames))
            self.assertEqual(value["native"]["certificate"]["prior"], initial_prior)
            if fault in {"body-after-returned-201", "earlier-body-then-stop"}:
                self.assertIs(engine.service.primary, body_error)
            return engine, code, frames, calls

    def test_fresh_key_and_complete_inventory_review_or_reuse_no_post(self):
        for existing, decision in ((False, "request-review"), (True, "reuse")):
            engine, code, frames, calls = self.execute(existing=existing)
            self.assertEqual(code, 0, repr(engine.primary))
            self.assertEqual(frames[-1]["payload"]["result"]["decision"], decision, repr(engine.primary))
            self.assertNotIn("create_certificate", calls)
            self.assertEqual(calls[:7], ["probe"] * 6 + ["verifier"])
            self.assertTrue(engine.service.closed() and engine.input.material_closed())

    def test_explicit_create_arms_once_then_fresh_full_readback_and_policy(self):
        engine, code, frames, calls = self.execute("certificate-create")
        self.assertEqual(code, 0, repr(engine.primary))
        result = frames[-1]["payload"]["result"]
        self.assertEqual(result["decision"], "request-confirmed", repr(engine.primary))
        self.assertEqual(calls[7:], ["list_bundle_ids", "list_certificates", "list_profiles", "create_certificate",
            "list_bundle_ids", "list_certificates", "list_profiles", "policy"])
        self.assertEqual(len([row for row in frames if row["kind"] == "certificate-identities"]), 2)
        self.assertFalse(result["p12Saved"] or result["profileSaved"] or result["credentialReady"] or result["revocationChecked"])
        self.assertTrue(engine.service.closed())

    def test_missing_history_incomplete_or_denied_inventory_never_offers_request(self):
        for fault in ("no-key-history", "partial", "denied"):
            with self.subTest(fault=fault):
                engine, code, frames, calls = self.execute(fault=fault)
                self.assertEqual(code, 0, repr(engine.primary))
                self.assertEqual(frames[-1]["payload"]["result"]["decision"], "blocked")
                self.assertNotIn("create_certificate", calls)

    def test_forged_or_stale_identity_and_wrong_policy_ack_refuse(self):
        for fault in ("foreign-identity", "stale-identity", "wrong-policy-ack"):
            with self.subTest(fault=fault):
                engine, _, frames, calls = self.execute(existing=True, fault=fault)
                self.assertNotEqual(frames[-1]["payload"]["outcome"], "complete", repr(engine.primary))
                self.assertNotIn("create_certificate", calls)

    def test_original_pending_cancel_scope_or_source_change_never_posts(self):
        for fault in ("foreign-pending", "stale-pending", "stop-pending"):
            with self.subTest(fault=fault):
                engine, _, frames, calls = self.execute("certificate-create", fault=fault)
                self.assertNotIn("create_certificate", calls)
                self.assertNotEqual(frames[-1]["payload"]["outcome"], "complete", repr(engine.primary))

    def test_known_returned_201_then_stop_keeps_receipt_and_failed_disposition(self):
        engine, code, frames, calls = self.execute("certificate-create", fault="stop-after-returned-201")
        self.assertEqual(code, 0, repr(engine.primary))
        self.assertEqual(frames[-1]["payload"]["outcome"], "cancelled", repr(engine.primary))
        self.assertIsNone(frames[-1]["payload"]["result"])
        self.assertEqual(engine.service.attempt.receipt.resource_id, "certificate-one")
        self.assertEqual(engine.service.attempt.record.response_resource_id, "certificate-one")
        self.assertTrue(engine.service.attempt.record.cancel_requested)
        self.assertEqual(calls.count("create_certificate"), 1)
        self.assertTrue(engine.service.closed() and engine.input.material_closed())
        self.assertFalse(engine.guard.lifetime_ledger.fatal)
        audit = [row for row in frames if row["kind"] == "certificate-attempt"]
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]["payload"]["update"]["receipt"]["resourceId"], "certificate-one")

    def test_returned_post_closing_never_repairs_body_foreign_expired_or_missing_originals(self):
        for fault in ("body-after-returned-201", "earlier-body-then-stop", "foreign-closing-command",
                      "expired-closing-command", "retired-closing-home", "inactive-closing-invocation",
                      "changed-closing-source", "missing-post-join", "later-missing-join"):
            with self.subTest(fault=fault):
                engine, _, frames, calls = self.execute("certificate-create", fault=fault)
                terminals = [row["payload"] for row in frames if row["kind"] == "terminal"]
                for terminal in terminals:
                    self.assertNotEqual(terminal["outcome"], "complete")
                    self.assertIsNone(terminal["result"])
                self.assertEqual(calls.count("create_certificate"), 1)
                if fault == "missing-post-join":
                    self.assertIsNone(engine.service.attempt.receipt)
                else:
                    self.assertEqual(engine.service.attempt.receipt.resource_id, "certificate-one")

    def test_same_writer_stopped_audit_is_latched_before_any_next_get(self):
        engine, code, frames, calls = self.execute("certificate-create", fault="stopped-audit-before-next-get")
        self.assertEqual(code, 0, repr(engine.primary))
        self.assertEqual(calls[7:], ["list_bundle_ids", "list_certificates", "list_profiles", "create_certificate"])
        self.assertEqual(frames[-1]["payload"]["outcome"], "cancelled", repr(engine.primary))
        self.assertIsNone(frames[-1]["payload"]["result"])
        self.assertEqual(engine.service.attempt.receipt.resource_id, "certificate-one")
        self.assertEqual(engine.input.stop_reason, "cancelled")
        self.assertIsNotNone(engine.input.first_failure)
        self.assertTrue(engine.service.closed() and engine.input.material_closed())

    def test_missing_or_malformed_stopped_audit_never_becomes_get_authority(self):
        for fault in ("missing-audit-stopped", "malformed-audit-stopped"):
            with self.subTest(fault=fault):
                engine, _, frames, calls = self.execute("certificate-create", fault=fault)
                self.assertEqual(calls[7:], ["list_bundle_ids", "list_certificates", "list_profiles", "create_certificate"])
                self.assertEqual(engine.service.attempt.receipt.resource_id, "certificate-one")
                self.assertNotEqual(frames[-1]["payload"]["outcome"], "complete")
                self.assertIsNone(frames[-1]["payload"]["result"])

    def test_unconfirmed_post_does_not_repeat_or_claim_certificate(self):
        engine, _, frames, calls = self.execute("certificate-create", fault="post-unknown")
        self.assertEqual(calls.count("create_certificate"), 1)
        self.assertIsNone(engine.service.attempt.receipt)
        self.assertNotEqual(frames[-1]["payload"].get("result", {}).get("decision") if frames[-1]["payload"]["result"] else None,
                            "request-confirmed")

    def test_restart_comparison_only_keeps_prior_unknown_and_never_arms_or_posts(self):
        same = issuance.CertificateCreationReceipt("certificate-one", None, None, None)
        other = issuance.CertificateCreationReceipt("different-certificate", None, None, None)
        for existing, receipt, comparison in ((True, same, "same-response"), (True, other, "different-response"),
                                              (True, None, "unattributed"), (False, same, "not-returned")):
            with self.subTest(comparison=comparison):
                engine, code, frames, calls = self.execute("certificate-reconcile", existing=existing, prior_receipt=receipt)
                self.assertEqual(code, 0, repr(engine.primary))
                result = frames[-1]["payload"]["result"]
                self.assertEqual((result["decision"], result["comparison"]), ("comparison-only", comparison))
                self.assertEqual(result["attempt"]["status"], "unknown")
                self.assertFalse(result["attempt"]["retryAllowed"] or result["credentialReady"])
                self.assertIsNone(engine.service.attempt)
                self.assertFalse(any(row["kind"] in {"certificate-pending", "certificate-attempt"} for row in frames))
                self.assertNotIn("create_certificate", calls)
                self.assertTrue(engine.service.closed() and engine.input.material_closed())

    def test_restored_new_reference_reconciles_same_key_without_restoring_old_history_or_post(self):
        receipt = issuance.CertificateCreationReceipt("certificate-one", None, None, None)
        engine, code, frames, calls = self.execute("certificate-reconcile", existing=True, prior_receipt=receipt, restored=True)
        self.assertEqual(code, 0, repr(engine.primary))
        native = engine.request.native["certificate"]
        self.assertNotEqual(native["sourceKey"], native["prior"]["sourceKey"])
        self.assertEqual(native["prior"]["sourceKey"], KEY)
        self.assertIsNone(native["keyPreparation"])
        result = frames[-1]["payload"]["result"]
        self.assertEqual((result["decision"], result["comparison"], result["attempt"]["status"]),
                         ("comparison-only", "same-response", "unknown"))
        self.assertFalse(result["attempt"]["retryAllowed"] or result["credentialReady"])
        self.assertEqual(calls[:7], ["probe"] * 6 + ["verifier"])
        self.assertNotIn("create_certificate", calls)
        self.assertIsNone(engine.service.attempt)
        self.assertFalse(any(row["kind"] in {"certificate-pending", "certificate-attempt"} for row in frames))
        self.assertTrue(engine.service.closed() and engine.input.material_closed())

    def test_restored_key_both_prior_hashes_stop_before_first_provider_get(self):
        for fault in ("prior-csr", "prior-spki"):
            with self.subTest(fault=fault):
                engine, code, frames, calls = self.execute("certificate-reconcile", restored=True, fault=fault)
                self.assertEqual(code, 0)  # A returned refusal is still a valid terminal transport.
                self.assertNotEqual(frames[-1]["payload"]["outcome"], "complete")
                self.assertIsNone(frames[-1]["payload"]["result"])
                self.assertEqual(calls, ["probe"] * 6 + ["verifier"])
                self.assertIsNone(engine.service.attempt)
                self.assertTrue(engine.service.closed() and engine.input.material_closed())

    def test_restored_key_stop_current_source_or_wrong_ack_cannot_start_inventory(self):
        for fault in ("restored-key-stop", "restored-key-source-changed", "restored-key-wrong-ack"):
            with self.subTest(fault=fault):
                engine, code, frames, calls = self.execute("certificate-reconcile", restored=True, fault=fault)
                self.assertEqual(code, 0)
                self.assertNotEqual(frames[-1]["payload"]["outcome"], "complete")
                self.assertEqual(calls, ["probe"] * 6 + ["verifier"])
                self.assertIsNone(frames[-1]["payload"]["result"])
                self.assertIsNone(engine.service.attempt)

    def test_restored_key_fresh_reuse_needs_no_old_key_saved_but_cannot_offer_issuance(self):
        for existing, decision, reason in ((True, "reuse", "existing-certificate"),
                                           (False, "blocked", "key-history-unavailable")):
            with self.subTest(existing=existing):
                engine, code, frames, calls = self.execute(existing=existing, restored=True)
                self.assertEqual(code, 0, repr(engine.primary))
                result = frames[-1]["payload"]["result"]
                self.assertEqual((result["decision"], result["reason"]), (decision, reason))
                self.assertIsNone(engine.request.native["certificate"]["keyPreparation"])
                self.assertNotIn("create_certificate", calls)

    def test_partial_or_denied_restart_read_cannot_become_absence_or_recovered_disposition(self):
        receipt = issuance.CertificateCreationReceipt("certificate-one", None, None, None)
        for fault in ("partial", "denied"):
            with self.subTest(fault=fault):
                engine, code, frames, calls = self.execute("certificate-reconcile", prior_receipt=receipt, fault=fault)
                self.assertEqual(code, 0, repr(engine.primary))
                result = frames[-1]["payload"]["result"]
                self.assertEqual(result["comparison"], "inconclusive")
                self.assertIsNone(result["certificateId"])
                self.assertEqual(result["attempt"]["status"], "unknown")
                self.assertNotIn("create_certificate", calls)
                self.assertFalse(any(row["kind"] == "certificate-pending" for row in frames))


class CertificateProtocolTests(unittest.TestCase):
    def test_restart_prior_preserves_valid_old_ref_and_exact_account_target_receipt(self):
        with old.BundleWorkerTests.files(self) as (_, root, runtime):
            receipt = issuance.CertificateCreationReceipt("certificate-one", None, None, None)
            value = selected(root, runtime, "certificate-reconcile", prior_receipt=receipt)
            wire.parse_request(old.encode(value))
            restored = copy.deepcopy(value)
            restored["native"]["certificate"]["prior"]["sourceKey"] = {**KEY, "revisionId": "f" * 32}
            wire.parse_request(old.encode(restored))  # DATA selection only; not key proof or a returned ACK.
            for field in ("key", "account", "name", "entitlements", "receipt"):
                invalid = copy.deepcopy(value)
                prior = invalid["native"]["certificate"]["prior"]
                if field == "key":
                    prior["sourceKey"] = {**prior["sourceKey"], "revisionId": "0" * 32}
                elif field == "account":
                    prior["record"]["context"]["accountRef"] = "f" * 64
                elif field == "name":
                    prior["target"]["displayName"] = "Not the explicit current selection"
                elif field == "entitlements":
                    prior["target"]["entitlementsSha256"] = "f" * 64
                else:
                    prior["receipt"]["resourceId"] = "another-certificate"
                with self.subTest(field=field), self.assertRaises(wire.ProtocolError):
                    wire.parse_request(old.encode(invalid))

    def test_restored_reference_never_aliases_key_preparation_or_makes_create_review(self):
        with old.BundleWorkerTests.files(self) as (_, root, runtime):
            value = selected(root, runtime, "certificate-create")
            value["native"]["certificate"]["sourceKey"] = {**KEY, "revisionId": "e" * 32}
            with self.assertRaises(wire.ProtocolError):
                wire.parse_request(old.encode(value))
            value["native"]["certificate"]["keyPreparation"] = None
            with self.assertRaises(wire.ProtocolError):
                wire.parse_request(old.encode(value))

    def test_modes_roles_and_original_limits_are_disjoint(self):
        with old.BundleWorkerTests.files(self) as (_, root, runtime):
            value = selected(root, runtime)
            request = wire.parse_request(old.encode(value))
            self.assertEqual(wire.command_count(request.context["mode"]), 14)
            self.assertEqual(wire.command_count("certificate-create"), 21)
            self.assertEqual(wire.response_limit("certificate-create"), 768 * 1024)
            for mode in ("review", "register", "profile-review", "key-review", "key-prepare"):
                invalid = copy.deepcopy(value); invalid["context"]["mode"] = mode
                with self.subTest(mode=mode), self.assertRaises(wire.ProtocolError):
                    wire.parse_request(old.encode(invalid))
            for change in ({"p12RecordId": "1" * 32, "p12RecordRevision": 1}, {"keyRecordRevision": 2**32 - 1},
                           {"keyRecordId": "0" * 32}, {"newApplication": True}):
                invalid = copy.deepcopy(value); invalid["context"].update(change)
                with self.assertRaises(wire.ProtocolError):
                    wire.parse_request(old.encode(invalid))
        header = {"schemaVersion": 1, "files": [{"role": role, "bytes": min(limit, 10)} for role, limit in private.ROLES]}
        header["files"][2]["bytes"] = 36
        self.assertEqual(len(private.material_header(old.encode(header))), 6)
        for index in range(6):
            invalid = copy.deepcopy(header); invalid["files"][index]["bytes"] = private.ROLES[index][1] + 1
            with self.assertRaises((wire.ProtocolError, ValueError)):
                private.material_header(old.encode(invalid))


if __name__ == "__main__":
    unittest.main()
