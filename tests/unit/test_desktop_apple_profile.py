"""Actual fixed saved-engine/file owners, fake command/native/CMS responses.

All certificate/profile/key strings are deliberately noncryptographic. These
tests exercise sequencing and custody, not macOS, CMS, X509, vault or provider
qualification. No process, socket, real key, account or native save is used.
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
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import _desktop_apple_profile_private as private
from mobile_release import _desktop_apple_profile_protocol as profile_wire
from mobile_release import _desktop_apple_profile_worker as profile_worker
from mobile_release import _desktop_apple_provisioning_control as control
from mobile_release import _desktop_apple_provisioning_protocol as wire
from mobile_release import _desktop_apple_provisioning_p12 as p12
from mobile_release import desktop_apple_provisioning as worker
from mobile_release import apple_provisioning_api as api
from mobile_release import apple_provisioning_signing as signing
from mobile_release.apple_provisioning import AuthenticatedProfile, CertificateBinding
from mobile_release._desktop_apple_provisioning_engine import _Engine
from mobile_release._desktop_saved_command_engine import run_engine
from mobile_release._lifetime_evidence import ProfileCallEvidence, ProfileVerdict
from mobile_release.build_inputs import finite_scratch
from . import test_desktop_apple_provisioning as old
from . import test_apple_provisioning as fixture

SPKI = b"SYNTHETIC full SPKI, no public key"
CHAIN = (b"SYNTHETIC chain, no trust",)
P12 = b"PRIVATE inert P12, not an identity"
PASSWORD = b"PRIVATE inert password"
KEY = fixture.KEY


def bundle():
    return fixture.bundle(seed="ABCDE12345", identifier="com.example.reader")


def profile(*, created=False, content=False):
    result = fixture.profile("profile-created" if created else "profile-one", content=content,
        name=signing.profile_name(old.OP) if created else "Synthetic existing profile")
    result["relationships"]["certificates"]["meta"] = {"paging": {"total": 1}}
    return result


def payload(kind, *, existing):
    if kind == "list_bundle_ids":
        rows = [bundle()]
    elif kind == "list_certificates":
        rows = [fixture.certificate()]
    else:
        rows = [profile()] if existing else []
    result = {"data": rows, "links": {"next": None}, "meta": {"paging": {"total": len(rows)}}}
    if kind == "list_profiles":
        certificate = fixture.certificate()
        del certificate["attributes"]["certificateContent"]
        result["included"] = [bundle(), certificate] if rows else []
    return result


def selected_request(root, runtime, mode, *, existing):
    value = old.request(root, runtime)
    value["context"].update(mode=mode, p12RecordId=KEY.record_id, p12RecordRevision=KEY.revision_counter)
    value["native"]["signing"] = {"sourceKey": profile_wire.key_wire(KEY), "destination": None,
        "expectedCertificateSha256": api.digest(fixture.CERT_BYTES), "p12Sha256": api.digest(P12),
        "entitlements": {}, "review": None, "prior": None}
    if mode not in profile_wire.SAVE_MODES:
        return value
    reference = {"operationId": "d" * 32, "ownerGeneration": "e" * 32}
    value["context"]["reference"] = reference
    source = profile_wire.key_wire(KEY)
    value["native"]["signing"]["destination"] = {**source, "recordId": "6" * 32, "revisionId": "7" * 32}
    before = datetime.now(timezone.utc)
    context = wire.core_context(value["native"]["provisioning"])
    target = wire.target(value["native"]["target"])
    # A fake read port supplies obvious DATA, not account inventory evidence.
    port = SimpleNamespace(check=lambda _: None,
        send=lambda request: api.AppleResponse(200, api.canonical(payload(request.kind, existing=existing)), True))
    inventory = signing.observe_signing(context, target, port, now=before)
    binding = CertificateBinding("certificate-one", api.digest(fixture.CERT_BYTES), api.digest(SPKI), KEY,
        target.team_id, fixture.CREATED, fixture.EXPIRES)
    plan = signing.prepare_existing_profile(context, target, inventory, bindings=(binding,), selected_key=KEY,
        pending=(), now=before)
    value["native"]["reviewedAt"] = before.isoformat()
    value["native"]["signing"]["review"] = {"reference": reference, "observedAt": before.isoformat(),
        "validUntil": plan.valid_until.isoformat(), "selection": profile_wire.selection_wire(plan)}
    return value


class ProfileWorkerTests(unittest.TestCase):
    def execute(self, mode="profile-review", *, existing=True, fault=None):
        with old.BundleWorkerTests.files(self) as (base, root, runtime):
            path = root / "release/mobile-release.json"
            config = json.loads(path.read_bytes())
            config["ios"]["distributionCertificateSha256"] = api.digest(fixture.CERT_BYTES)
            path.write_text(json.dumps(config))
            for name in ("apple_provisioning_signing.rb", "apple_provisioning_p12.rb"):
                (runtime / "store/tooling/fastlane" / name).write_bytes(b"inert tooling never executed")
            value = selected_request(root, runtime, mode, existing=existing)
            if fault == "pending":
                value["native"]["pending"] = [{"accountRef": old.ACCOUNT, "operationId": "8" * 32,
                    "action": "create_profile", "status": "succeeded", "nativeSettlement": "unknown"}]
            material = old.MATERIAL + (P12, PASSWORD)
            body = old.PREFIX + old.encode({"schemaVersion": 1, "files": [{"role": role, "bytes": len(raw)}
                for (role, _), raw in zip(private._ROLES, material)]}) + b"".join(material) + old.SUFFIX
            saved = [os.dup(fd) for fd in (0, 1, 2)]
            readers, writers, frames, calls, deadlines = [], [], [], [], []
            original_write, cwd = _Engine.write, Path.cwd()
            engine = None

            def write(current, raw, *, terminal=False):
                original_write(current, raw, terminal=terminal)
                self.assertEqual(os.read(readers[1], profile_wire.JSON_LIMIT), raw)
                frame = json.loads(raw)
                frames.append(frame)
                sequence = frame["sequence"]
                if frame["kind"] == "identity":
                    facts = frame["payload"]
                    reply = {"kind": "identity-ack", "payload": {"identitySha256": api.digest(api.canonical(facts)),
                        "certificateSha256": api.digest(fixture.CERT_BYTES), "publicKeySha256": api.digest(SPKI),
                        "teamId": "ABCDE12345", "notBefore": int(fixture.CREATED.timestamp()),
                        "notAfter": int(fixture.EXPIRES.timestamp()), "checkedAt": int(datetime.now(timezone.utc).timestamp())}}
                    if fault == "wrong-identity":
                        reply["payload"]["publicKeySha256"] = "0" * 64
                    elif fault == "stale-identity":
                        reply["payload"]["checkedAt"] -= 301
                elif frame["kind"] in {"profile-pending", "profile-attempt"}:
                    reply = {"kind": "journal-ack", "payload": {"revision": sequence - 1, "sequence": sequence - 1,
                        "recordSha256": api.digest(api.canonical(frame["payload"]["update"]))}}
                    if fault == "cancel-pending" and sequence == 2:
                        current.input.stop("cancelled")
                else:
                    return
                reply.update(protocol=wire.PROTOCOL, operationId=old.OP, ownerGeneration=old.GENERATION,
                    nonce=value["native"]["nonce"], requestSha256=current.request.digest, step=sequence)
                if fault == "foreign-pending" and sequence == 2:
                    reply["ownerGeneration"] = "0" * 32
                if fault == "replayed-identity" and sequence == 2:
                    reply.update(kind="identity-ack", step=1)
                if fault == "config-at-pending" and sequence == 2:
                    version = root / "release/version.properties"
                    version.write_bytes(version.read_bytes() + b"\n")
                if fault == "late-identity" and sequence == 1:
                    current.input.work_end = time.monotonic() - .01
                os.write(writers[0], old.encode(reply))

            def fake_command(argv, **kwargs):
                ledger = engine.guard.lifetime_ledger
                slot = object()
                ledger._bind_command(slot)
                ledger._finish_command(slot, dispatched=True, contained=True, cleanup_complete=True)
                operation = engine.service
                request = operation._wire_request
                calls.append(request.kind if request else "fixed-private-or-probe")
                index = len(calls) - 1
                self.assertLessEqual(kwargs["timeout"], 60)
                if index < 6:
                    text = ("", "3.3.12", "4.0.16", "", "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2", "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2")[index]
                    return subprocess.CompletedProcess(argv, 0, text, "")
                if index == 6:
                    self.assertTrue(str(argv[3]).endswith("/apple_provisioning_p12.rb"))
                    self.assertFalse(any("MOBILE_RELEASE_ASC_" in key for key in kwargs["environ"]))
                    self.assertEqual(Path(argv[4]).read_bytes(), P12)
                    self.assertEqual(Path(argv[5]).read_bytes(), PASSWORD)
                    self.assertNotIn(PASSWORD.decode(), repr(argv) + repr(kwargs["environ"]))
                    raw = p12.MAGIC + p12.HEADER.pack(len(fixture.CERT_BYTES), len(SPKI), len(CHAIN)) + fixture.CERT_BYTES + SPKI
                    raw += b"".join(struct.pack(">I", len(part)) + part for part in CHAIN)
                    return subprocess.CompletedProcess(argv, 0, raw, b"")
                self.assertNotIn(PASSWORD.decode(), repr(kwargs["environ"]))
                if request.method == "POST":
                    self.assertEqual(request.kind, "create_profile")
                    self.assertEqual(engine.input.reply_step, 2)
                    self.assertTrue(engine.input._ack_consumed)
                    document, status = {"data": {"type": "profiles", "id": "profile-created"}}, 201
                elif request.kind == "download_profile":
                    document, status = {"data": profile(created=not existing, content=True)}, 200
                else:
                    document, status = payload(request.kind, existing=existing), 200
                failure = None
                if fault == "denied" and request.kind == "list_profiles":
                    status, failure = 403, "provider_request_unconfirmed"
                if fault == "post-unknown" and request.method == "POST":
                    status, failure = 503, "provider_request_unconfirmed"
                if fault == "relationship-incomplete" and request.kind == "list_profiles":
                    document["data"][0]["attributes"]["profileState"] = "INVALID"
                    del document["data"][0]["relationships"]["certificates"]["meta"]
                raw = old.encode({"schemaVersion": 1, "scope": signing.SCOPE,
                    "contextSha256": api.digest(api.canonical(wire.core_context_wire(operation.context))),
                    "operationId": old.OP, "bundleId": operation.target.bundle_id,
                    "requestSha256": api.request_sha256(request),
                    "ackSha256": engine.input._pending_ack if request.method == "POST" else None,
                    "response": {"status": status, "failure": failure,
                        "bodyBase64": None if failure else base64.b64encode(api.canonical(document)).decode("ascii")}})
                return subprocess.CompletedProcess(argv, 0, raw, b"")

            def fake_chain(leaf, chain, *, cancellation, deadline):
                self.assertEqual((leaf, chain), (fixture.CERT_BYTES, CHAIN))
                self.assertIs(cancellation, engine.guard)
                deadlines.append(deadline)
                deadline.check()
                return datetime.now(timezone.utc)

            def fake_cms(plan, response, *, cancellation, now, deadline):
                self.assertIs(cancellation, engine.guard)
                self.assertIs(deadline, deadlines[0])
                deadlines.append(deadline)
                deadline.check()
                # Explicit fake crypto lifetime facts folded through the real
                # ledger. No native producer or assignment proof is created.
                evidence = ProfileCallEvidence(operation="decode")
                ledger = cancellation.lifetime_ledger
                ledger._bind_profile(evidence)
                ledger._finish_profile(evidence, ProfileVerdict(True, False, "ATTEMPT_ARMED", "RUN_ATTEMPT_ARMED",
                    True, True, True, True, "RESTORED", False))
                parsed = api.Profile.parse(api.document(response.body)["data"], require_content=True)
                return AuthenticatedProfile(parsed, plan.binding.key_ref, plan.binding.certificate_sha256)

            def scratch(**kwargs):
                if kwargs.get("parent") == Path("/private/tmp"):
                    kwargs["parent"] = base
                return finite_scratch(**kwargs)

            try:
                for fd in (0, 1, 2):
                    reader, writer = os.pipe()
                    readers.append(reader); writers.append(writer)
                    os.dup2(reader if fd == 0 else writer, fd)
                os.write(writers[0], old.encode(value) + body)
                os.chdir(runtime)
                engine = _Engine(time.monotonic())
                with patch.object(worker, "sys", SimpleNamespace(platform="darwin")), \
                     patch.object(worker, "finite_scratch", side_effect=scratch), \
                     patch.object(control.time, "CLOCK_UPTIME_RAW", time.CLOCK_MONOTONIC, create=True), \
                     patch.object(_Engine, "write", write), \
                     patch("mobile_release._command_process.run_command", side_effect=fake_command), \
                     patch.object(profile_worker, "_verify_leaf_chain_in_worker", side_effect=fake_chain), \
                     patch.object(profile_worker, "authenticate_downloaded_profile", side_effect=fake_cms), \
                     patch.object(subprocess, "Popen", side_effect=AssertionError("no real process permitted")), \
                     patch.dict(os.environ, {"TMPDIR": str(base), "RUBYOPT": "denied", "GITHUB_TOKEN": "inert denied"}, clear=True):
                    result = run_engine(engine)
            finally:
                os.chdir(cwd)
                for fd, original in enumerate(saved):
                    os.dup2(original, fd); os.close(original)
                for writer in writers:
                    os.close(writer)
            try:
                trailer = os.read(readers[1], private.TRAILER_LIMIT)
                self.assertEqual(os.read(readers[2], 1024), b"")
            finally:
                for reader in readers:
                    os.close(reader)
            self.assertEqual(result, 0, repr(engine.primary))
            self.assertEqual(frames[-1]["kind"], "terminal", repr(engine.primary))
            self.assertNotIn(P12.decode(), repr(frames))
            self.assertNotIn(PASSWORD.decode(), repr(frames))
            self.assertTrue(engine.service.closed(), repr(engine.primary))
            self.assertTrue(engine.input.material_closed(), repr(engine.primary))
            self.assertFalse((root / ".mobile-release").exists())
            self.assertTrue(trailer.startswith(private.MAGIC), repr(engine.primary))
            count, digest, bound = private.HEADER.unpack_from(trailer, len(private.MAGIC))
            raw = trailer[len(private.MAGIC) + private.HEADER.size:]
            self.assertEqual(count, len(raw))
            self.assertEqual(digest.hex(), api.digest(raw))
            self.assertEqual(bound.hex(), engine.request.digest)
            return frames, calls, raw, deadlines, engine.service.primary or engine.primary

    def test_review_reuses_existing_profile_without_post_download_or_vault_claim(self):
        frames, calls, raw, deadlines, error = self.execute()
        self.assertIsNone(error)
        self.assertEqual(calls[7:], ["list_bundle_ids", "list_certificates", "list_profiles"])
        self.assertEqual([row["kind"] for row in frames], ["accepted", "identity", "profile-observed", "terminal"])
        self.assertEqual(frames[-1]["payload"]["result"]["decision"], "reuse-available")
        self.assertFalse(frames[-1]["payload"]["result"]["saved"])
        self.assertEqual(raw, b"")
        self.assertEqual(len(deadlines), 1)

    def test_reuse_get_only_requires_pending_ack_and_keeps_profile_off_public_json(self):
        frames, calls, raw, deadlines, error = self.execute("profile-reuse")
        self.assertIsNone(error)
        self.assertEqual(calls[7:], ["list_bundle_ids", "list_certificates", "list_profiles", "download_profile"])
        self.assertEqual([row["kind"] for row in frames][1:-1], ["identity", "profile-pending", "profile-attempt"])
        self.assertEqual(raw, fixture.PROFILE_BYTES)
        self.assertNotIn(fixture.PROFILE_BYTES.decode(), repr(frames))
        self.assertFalse(frames[-1]["payload"]["result"]["credentialReady"])
        self.assertEqual(len(deadlines), 2)
        self.assertIs(deadlines[0], deadlines[1])

    def test_create_single_post_after_ack_sparse_id_exact_get_and_same_deadline(self):
        frames, calls, raw, deadlines, error = self.execute("profile-create", existing=False)
        self.assertIsNone(error)
        self.assertEqual(calls[7:], ["list_bundle_ids", "list_certificates", "list_profiles", "create_profile", "download_profile"])
        self.assertEqual([row["kind"] for row in frames][1:-1], ["identity", "profile-pending", "profile-attempt", "profile-attempt"])
        self.assertEqual(raw, fixture.PROFILE_BYTES)
        self.assertEqual(frames[-1]["payload"]["result"]["decision"], "download-returned")
        self.assertIs(deadlines[0], deadlines[1])

    def test_identity_ack_binding_freshness_and_original_deadline_precede_provider(self):
        for fault in ("wrong-identity", "stale-identity", "late-identity"):
            with self.subTest(fault=fault):
                frames, calls, raw, _, _ = self.execute(fault=fault)
                self.assertEqual(len(calls), 7)
                self.assertNotEqual(frames[-1]["payload"]["outcome"], "complete")
                self.assertEqual(raw, b"")

    def test_foreign_replayed_stale_or_cancelled_pending_never_sends_post(self):
        for fault in ("foreign-pending", "replayed-identity", "config-at-pending", "cancel-pending"):
            with self.subTest(fault=fault):
                frames, calls, raw, _, _ = self.execute("profile-create", existing=False, fault=fault)
                self.assertNotIn("create_profile", calls)
                self.assertEqual(raw, b"")
                self.assertNotEqual(frames[-1]["payload"]["outcome"], "complete")

    def test_sent_unknown_does_not_retry_get_save_or_erase_pending(self):
        frames, calls, raw, _, error = self.execute("profile-create", existing=False, fault="post-unknown")
        self.assertIsInstance(error, api.ProvisioningError)
        self.assertEqual(error.code, "provider_outcome_unknown")
        self.assertEqual(calls.count("create_profile"), 1)
        self.assertNotIn("download_profile", calls)
        self.assertEqual(raw, b"")
        update = next(row for row in reversed(frames) if row["kind"] == "profile-attempt")["payload"]["update"]
        self.assertEqual(update["provider"]["record"]["status"], "unknown")
        self.assertTrue(update["provider"]["record"]["possibleSend"])
        self.assertEqual(update["save"], "not-entered")

    def test_denied_or_incomplete_inventory_is_not_absence_or_create_permission(self):
        for fault in ("denied", "relationship-incomplete"):
            with self.subTest(fault=fault):
                frames, calls, raw, _, error = self.execute(fault=fault)
                self.assertIsNone(error)
                self.assertEqual(frames[-1]["payload"]["result"]["decision"], "blocked")
                self.assertNotIn("create_profile", calls)
                self.assertEqual(raw, b"")


class ProfilePrivateDataTests(unittest.TestCase):
    def test_exact_five_roles_caps_and_order_no_ambient_material(self):
        data = {"schemaVersion": 1, "files": [{"role": role, "bytes": limit} for role, limit in private._ROLES]}
        self.assertEqual(private.material_header(old.encode(data)), tuple(limit for _, limit in private._ROLES))
        for index in range(5):
            bad = copy.deepcopy(data)
            bad["files"][index]["bytes"] += 1
            with self.assertRaises(api.ProvisioningError):
                private.material_header(old.encode(bad))
        for bad in ({**data, "path": "/inert/no-read"}, {**data, "files": data["files"][:3]},
                    {**data, "files": list(reversed(data["files"]))}):
            with self.assertRaises(api.ProvisioningError):
                private.material_header(old.encode(bad))

    def test_old_mode_rejects_profile_context_and_identity_phase(self):
        with old.BundleWorkerTests.files(self) as (_, root, runtime):
            value = old.request(root, runtime)
            ordinary = wire.parse_request(old.encode(value))
            with self.assertRaises(wire.ProtocolError):
                wire.validate_event(ordinary, "identity", {}, 1)
            value["context"].update(p12RecordId=KEY.record_id, p12RecordRevision=1)
            with self.assertRaises(wire.ProtocolError):
                wire.parse_request(old.encode(value))


if __name__ == "__main__":
    unittest.main()
