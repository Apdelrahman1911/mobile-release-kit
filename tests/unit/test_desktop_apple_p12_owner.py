"""Whole existing Apple engine/input/scratch owners, fake C/A/W and provider.

No Ruby, child, vault, native authority, credential, or network is exercised.
The separate Ruby recipe checks real synthetic PKCS12 crypto. Here private
frames/ACKs are deliberately inert DATA and are never native finality proof.
"""
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

from mobile_release import _desktop_apple_p12_assembly as assembly
from mobile_release import _desktop_apple_p12_private as private
from mobile_release import _desktop_apple_p12_protocol as p12
from mobile_release import _desktop_apple_certificate_private as policy_wire
from mobile_release import _desktop_apple_certificate_protocol as certificate
from mobile_release import _desktop_apple_distribution_key as key_child
from mobile_release import _desktop_apple_provisioning_p12 as extraction
from mobile_release import _desktop_apple_provisioning_control as source
from mobile_release import _desktop_apple_provisioning_protocol as wire
from mobile_release import desktop_apple_provisioning as worker
from mobile_release import apple_provisioning_api as api
from mobile_release import apple_provisioning_certificate_issuance as issuance
from mobile_release import apple_provisioning_signing as signing
from mobile_release._desktop_apple_provisioning_engine import _Engine
from mobile_release._desktop_saved_command_engine import run_engine
from mobile_release._command_process import _Outer, CommandOutcomeSlot
from mobile_release.build_inputs import finite_scratch
from . import test_desktop_apple_provisioning as old
from . import test_desktop_apple_certificate as cert_fixture
from . import test_apple_provisioning as fixture

KEY, CSR, SPKI, KEY_BYTES = cert_fixture.KEY, cert_fixture.CSR, cert_fixture.SPKI, cert_fixture.PRIVATE
PACKAGE, PASSWORD = b"inert-synthetic-package", b"a" * 64
P12_REF = {**KEY, "recordId": "7" * 32, "revisionId": "8" * 32, "revisionCounter": 4}
NEW_REF = {**KEY, "recordId": "9" * 32, "revisionId": "f" * 32}
ASSEMBLED = (assembly.MAGIC + struct.pack(">I", len(PACKAGE))
    + bytes.fromhex(api.digest(fixture.CERT_BYTES)) + bytes.fromhex(api.digest(SPKI)) + PACKAGE)
EXTRACTED = (extraction.MAGIC + extraction.HEADER.pack(len(fixture.CERT_BYTES), len(SPKI), 0)
    + fixture.CERT_BYTES + SPKI)


def selected(root, runtime, mode, bound, fault):
    value = cert_fixture.selected(root, runtime, key_history=False)
    value["context"].update(mode=mode, p12RecordId=P12_REF["recordId"] if bound else None,
        p12RecordRevision=P12_REF["revisionCounter"] if bound else None)
    native = value["native"]
    native["target"]["existingApplication"] = True
    native["p12"] = {"sourceP8": native["certificate"]["sourceP8"], "sourceKey": KEY,
        "selectedP12": P12_REF if bound else None,
        "expectedCertificateSha256": api.digest(fixture.CERT_BYTES) if bound else None,
        "p12Sha256": api.digest(PACKAGE) if bound else None,
        "destination": NEW_REF if mode == "p12-save" else None, "review": None, "previous": []}
    if mode != "p12-review":
        at = datetime.now(timezone.utc)
        value["context"]["reference"] = {"operationId": "d" * 32, "ownerGeneration": "e" * 32}
        context, target = wire.core_context(native["provisioning"]), certificate.target(Data(native=native))
        provider = Data(check=lambda _: None, send=lambda request: api.AppleResponse(200,
            api.canonical(cert_fixture.inventory(request.kind, True)), True))
        before = signing.observe_signing(context, target, provider, now=at)
        bundle = before.observation.bundles[0]
        choice = {"bundle": {"resourceId": bundle.resource_id, "identifier": bundle.identifier,
            "platform": bundle.platform, "seedId": bundle.seed_id},
            "certificate": {"resourceId": "certificate-one", "certificateType": "DISTRIBUTION",
                "notBefore": fixture.CREATED.isoformat(), "expiresAt": fixture.EXPIRES.isoformat(),
                "certificateSha256": api.digest(fixture.CERT_BYTES), "publicKeySha256": api.digest(SPKI)},
            "csrSha256": api.digest(CSR), "beforeSha256": before.observation.sha256}
        native["reviewedAt"] = at.isoformat()
        native["p12"]["review"] = {"reference": value["context"]["reference"], "observedAt": at.isoformat(),
            "validUntil": (at + timedelta(seconds=300)).isoformat(), "selection": choice,
            "selectedP12": P12_REF if bound else None}
    if fault in {"known-history", "pending-history"}:
        native["pending"] = [{"accountRef": old.ACCOUNT, "operationId": "6" * 32, "action": "key_prepare",
            "status": "succeeded", "nativeSettlement": "known" if fault == "known-history" else "unknown"}]
    if fault in {"relevant-history", "unrelated-history"}:
        native["p12"]["previous"] = [{"destination": {**P12_REF, "recordId": "a" * 32},
            "certificateSha256": "0" * 64, "publicKeySha256": api.digest(SPKI) if fault == "relevant-history" else "1" * 64,
            "unresolved": False}]
    return value


class P12OwnerTests(unittest.TestCase):
    def execute(self, mode="p12-review", *, bound=False, fault=None):
        with old.BundleWorkerTests.files(self) as (base, root, runtime):
            value = selected(root, runtime, mode, bound, fault)
            material = old.MATERIAL + (base64.b64encode(KEY_BYTES), CSR, base64.b64encode(SPKI))
            roles = list(private.BASE_ROLES)
            if mode == "p12-save":
                roles += [("p12-password", 64)]; material += (PASSWORD,)
            elif bound:
                roles += [("distribution-p12", 4 * 1024 * 1024), ("p12-password", 4096)]
                material += (PACKAGE, PASSWORD)
            body = old.PREFIX + old.encode({"schemaVersion": 1, "files": [
                {"role": role, "bytes": len(raw)} for (role, _), raw in zip(roles, material)]}) + b"".join(material) + old.SUFFIX
            saved = [os.dup(fd) for fd in (0, 1, 2)]
            readers, writers, frames, calls = [], [], [], []
            cwd, engine = Path.cwd(), None
            original_write, original_body = _Engine.write, private.P12Output.write_body

            def reply(frame, payload):
                result = {"protocol": wire.PROTOCOL, "operationId": old.OP, "ownerGeneration": old.GENERATION,
                    "nonce": value["native"]["nonce"], "requestSha256": engine.request.digest,
                    "kind": frame["kind"] + "-ack", "step": frame["sequence"], "payload": payload}
                os.write(writers[0], old.encode(result))

            def write(current, raw, *, terminal=False):
                original_write(current, raw, terminal=terminal)
                self.assertTrue(os.read(readers[1], wire.response_limit(mode)) == raw)
                frame = json.loads(raw); frames.append(frame)
                kind, payload = frame["kind"], frame["payload"]
                digest = api.digest(api.canonical(payload))
                if kind == "certificate-key":
                    ack = {"keySha256": digest, "csrSha256": api.digest(CSR), "publicKeySha256": api.digest(SPKI),
                           "keySavedAckSha256": None}
                elif kind == "certificate-identities":
                    rows = payload["certificates"]
                    ack = {"identitySha256": digest, "batch": payload["batch"], "seen": len(rows), "ambiguous": False,
                        "checkedAt": int(datetime.now(timezone.utc).timestamp()), "selected": {
                            "resourceId": "certificate-one", "certificateSha256": api.digest(fixture.CERT_BYTES),
                            "notBefore": int(fixture.CREATED.timestamp()), "notAfter": int(fixture.EXPIRES.timestamp())}}
                elif kind == "certificate-policy":
                    ack = {"policySha256": digest, "certificateSha256": payload["certificateSha256"]}
                elif kind == "p12-pending":
                    self.assertIsNone(current.service._p12_assembly)
                    ack = {"revision": 1, "sequence": 1, "recordSha256": api.digest(api.canonical(payload["update"]))}
                    if fault == "foreign-pending": ack["recordSha256"] = "0" * 64
                    if fault == "stale-pending": (root / "release/version.properties").write_bytes(b"VERSION_NAME=1.2.3\nBUILD_NUMBER=43\n")
                    if fault == "stop-before-assembly": current.input.stop("cancelled")
                else:
                    return  # p12-output has a raw body before its ACK.
                reply(frame, ack)

            def write_body(output):
                original_body(output)
                raw = os.read(readers[1], private.TRANSFER_LIMIT)
                self.assertTrue(raw == private.header(engine.request.digest, ASSEMBLED) + ASSEMBLED)
                payload = frames[-1]["payload"]
                ack = {"frameSha256": payload["frameSha256"], "p12Sha256": payload["p12Sha256"], "retained": True}
                if fault == "lost-custody":
                    ack["retained"] = False  # Explicit synthetic bad ACK, no hanging peer or timeout.
                reply(frames[-1], ack)

            def slot(owned, raw):
                outer, selected_slot = object.__new__(_Outer), object.__new__(CommandOutcomeSlot)
                selected_slot._engine, outer.slot, outer.guard = outer, selected_slot, engine.guard
                outer.scope = outer.binding = outer.evidence = outer._store_timing = None
                outer.owns = outer.text = False
                outer.decoded, outer.outputs = (raw, b""), [bytearray(raw), bytearray()]
                owned.bind_command_slot(outer, selected_slot)

            def command(argv, **kwargs):
                operation, ledger = engine.service, engine.guard.lifetime_ledger
                index, request = len(calls), operation._wire_request
                synthetic = object(); ledger._bind_command(synthetic)
                ledger._finish_command(synthetic, dispatched=True, contained=True, cleanup_complete=True)
                self.assertLessEqual(kwargs["timeout"], 60)
                if index < 6:
                    calls.append("probe")
                    return subprocess.CompletedProcess(argv, 0,
                        ("", "3.3.12", "4.0.16", "", "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2", "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2")[index], "")
                if request is None:
                    self.assertFalse(any(key.startswith("MOBILE_RELEASE_ASC_") for key in kwargs["environ"]))
                if index == 6:
                    calls.append("verifier")
                    self.assertTrue(str(argv[3]).endswith("/apple_distribution_certificate_prepare.rb"))
                    self.assertEqual(kwargs["output_limit"], key_child.PUBLIC_LIMIT)
                    self.assertTrue(Path(argv[4]).read_bytes() == key_child._stored_frame(material[3:6]))
                    slot(operation._distribution_key, cert_fixture.FRAME)
                    return subprocess.CompletedProcess(argv, 0, cert_fixture.FRAME, b"")
                if request is not None:
                    calls.append(request.kind)
                    self.assertEqual(request.method, "GET")
                    document = cert_fixture.inventory(request.kind, True)
                    raw = {"schemaVersion": 1, "scope": issuance.SCOPE,
                        "contextSha256": api.digest(api.canonical(wire.core_context_wire(operation.context))),
                        "operationId": old.OP, "bundleId": operation.target.bundle_id, "requestSha256": api.request_sha256(request),
                        "keySavedAckSha256": None, "ackSha256": None,
                        "response": {"status": 200, "failure": None, "bodyBase64": base64.b64encode(api.canonical(document)).decode("ascii")}}
                    return subprocess.CompletedProcess(argv, 0, old.encode(raw), b"")
                if str(argv[3]).endswith("/apple_distribution_certificate_verify.rb"):
                    calls.append("policy")
                    policy = operation._certificate.policy
                    self.assertTrue(Path(argv[4]).read_bytes() == policy.body)
                    result = {"schemaVersion": 1, "scope": "offline-apple-distribution-certificate",
                        "requestBindingSha256": operation.request.digest, "identityAckSha256": policy.identity_ack,
                        "certificateSha256": api.digest(fixture.CERT_BYTES), "publicKeySha256": api.digest(SPKI),
                        "teamId": operation.target.team_id, "revocationChecked": False, "checkedAt": datetime.now(timezone.utc).isoformat(),
                        "chainSha256": [api.digest(fixture.CERT_BYTES), certificate.INTERMEDIATE_SHA256, certificate.ROOT_SHA256]}
                    return subprocess.CompletedProcess(argv, 0, api.canonical(result), b"")
                if str(argv[3]).endswith("/apple_provisioning_p12.rb"):
                    calls.append("extract")
                    self.assertTrue(Path(argv[4]).read_bytes() == PACKAGE and Path(argv[5]).read_bytes() == PASSWORD)
                    raw = EXTRACTED if fault != "wrong-selected-leaf" else EXTRACTED[:-1] + b"!"
                    return subprocess.CompletedProcess(argv, 0, raw, b"")
                calls.append("assemble")
                self.assertEqual(mode, "p12-save")
                self.assertTrue(str(argv[3]).endswith("/apple_provisioning_p12_assemble.rb"))
                self.assertTrue(engine.input._ack_consumed)
                self.assertEqual(frames[-1]["kind"], "p12-pending")
                self.assertTrue(Path(argv[4]).read_bytes() == key_child._stored_frame(material[3:6]))
                self.assertTrue(Path(argv[5]).read_bytes() == PASSWORD and Path(argv[6]).read_bytes() == fixture.CERT_BYTES)
                self.assertEqual(kwargs["output_limit"], assembly.PRIVATE_LIMIT)
                slot(operation._p12_assembly, ASSEMBLED)
                return subprocess.CompletedProcess(argv, 0, ASSEMBLED, b"")

            def scratch(**kwargs):
                if kwargs.get("parent") == Path("/private/tmp"): kwargs["parent"] = base
                return finite_scratch(**kwargs)

            try:
                for fd in (0, 1, 2):
                    reader, writer = os.pipe(); readers.append(reader); writers.append(writer)
                    os.dup2(reader if fd == 0 else writer, fd)
                os.write(writers[0], old.encode(value) + body)
                os.chdir(runtime)
                with patch.object(worker, "sys", Data(platform="darwin")), patch.object(worker, "finite_scratch", side_effect=scratch), \
                     patch.object(source.time, "CLOCK_UPTIME_RAW", time.CLOCK_MONOTONIC, create=True), \
                     patch.object(_Engine, "write", write), patch.object(private.P12Output, "write_body", write_body), \
                     patch("mobile_release._command_process.run_command", side_effect=command), \
                     patch.object(key_child.AppleDistributionKeyWork, "_outcome", autospec=True,
                        side_effect=lambda owned: Data(no_target=None, result_integrity="complete", returncode=0) if owned._slot else None), \
                     patch.object(assembly.P12AssemblyWork, "_outcome", autospec=True,
                        side_effect=lambda owned: Data(no_target=None, result_integrity="complete", returncode=0) if owned._slot else None), \
                     patch.object(subprocess, "Popen", side_effect=AssertionError("no child execution")), \
                     patch.dict(os.environ, {"TMPDIR": str(base), "RUBYOPT": "inert denied", "GITHUB_TOKEN": "inert denied"}, clear=True):
                    engine = _Engine(time.monotonic())
                    code = run_engine(engine)
            finally:
                os.chdir(cwd)
                for fd, original in enumerate(saved): os.dup2(original, fd); os.close(original)
                for descriptor in readers + writers: os.close(descriptor)
            self.assertFalse((root / ".mobile-release").exists())
            self.assertNotIn(KEY_BYTES.decode(), repr(frames))
            self.assertNotIn(PASSWORD.decode(), repr(frames))
            self.assertNotIn(PACKAGE.decode(), repr(frames))
            return engine, code, frames, calls

    def test_review_uses_fresh_key_complete_gets_policy_and_no_assembler(self):
        engine, code, frames, calls = self.execute()
        self.assertEqual(code, 0, repr(engine.primary))
        self.assertEqual(frames[-1]["payload"]["result"]["decision"], "assemble-review")
        self.assertEqual(calls, ["probe"] * 6 + ["verifier", "list_bundle_ids", "list_certificates", "list_profiles", "policy"])
        self.assertTrue(engine.service.closed() and engine.input.material_closed())

    def test_actual_selected_extraction_reuses_only_exact_fresh_leaf_and_key(self):
        for mode, decision in (("p12-review", "reuse-review"), ("p12-reuse", "reused")):
            with self.subTest(mode=mode):
                engine, code, frames, calls = self.execute(mode, bound=True)
                self.assertEqual(code, 0, repr(engine.primary))
                self.assertEqual(frames[-1]["payload"]["result"]["decision"], decision)
                self.assertEqual(calls[-1], "extract"); self.assertNotIn("assemble", calls)
                self.assertTrue(engine.service.closed())

    def test_one_assembler_after_local_pending_and_raw_custody_before_terminal(self):
        engine, code, frames, calls = self.execute("p12-save")
        self.assertEqual(code, 0, repr(engine.primary))
        result = frames[-1]["payload"]["result"]
        self.assertEqual(result["decision"], "assembled")
        self.assertEqual([f["kind"] for f in frames], ["accepted", "certificate-key", "certificate-identities", "certificate-policy",
            "p12-pending", "p12-output", "terminal"])
        self.assertEqual(calls.count("assemble"), 1)
        self.assertTrue(engine.service.closed() and engine.service._p12_output.closed())
        self.assertFalse(result["p12Saved"] or result["credentialReady"])

    def test_known_key_history_and_unrelated_p12_do_not_block_multi_project_use(self):
        for fault in ("known-history", "unrelated-history"):
            engine, code, frames, _ = self.execute(fault=fault)
            self.assertEqual(code, 0, repr(engine.primary))
            self.assertEqual(frames[-1]["payload"]["result"]["decision"], "assemble-review")

    def test_same_key_history_and_unresolved_account_do_not_offer_duplicate_save(self):
        for fault, reason in (("relevant-history", "select-existing-package"), ("pending-history", "account-pending")):
            engine, code, frames, calls = self.execute(fault=fault)
            self.assertEqual(code, 0, repr(engine.primary))
            self.assertEqual(frames[-1]["payload"]["result"]["reason"], reason)
            self.assertNotIn("assemble", calls)

    def test_foreign_or_stale_pending_and_known_stop_cannot_enter_assembler(self):
        for fault in ("foreign-pending", "stale-pending", "stop-before-assembly"):
            engine, _, frames, calls = self.execute("p12-save", fault=fault)
            self.assertNotIn("assemble", calls)
            self.assertNotEqual(frames[-1]["payload"]["outcome"], "complete", repr(engine.primary))

    def test_lost_custody_retains_private_original_no_reassembly_or_success(self):
        engine, _, frames, calls = self.execute("p12-save", fault="lost-custody")
        self.assertEqual(calls.count("assemble"), 1)
        self.assertTrue(engine.service._p12_assembly._frame is not None)
        self.assertFalse(engine.service._p12_output.closed())
        self.assertNotEqual(frames[-1]["payload"]["outcome"], "complete")

    def test_changed_selected_public_key_never_falls_back_to_new_assembly(self):
        engine, _, frames, calls = self.execute(bound=True, fault="wrong-selected-leaf")
        self.assertIn("extract", calls); self.assertNotIn("assemble", calls)
        self.assertNotEqual(frames[-1]["payload"]["outcome"], "complete", repr(engine.primary))
