"""Closed DATA/role tests only; no original loan, callback or effect is faked."""
import copy
import struct
from types import SimpleNamespace as Data
import unittest

from mobile_release import _desktop_apple_p12_protocol as wire
from mobile_release import _desktop_apple_p12_private as private
from mobile_release import _desktop_apple_p12_assembly as assembly
from mobile_release import apple_provisioning_api as api


def reference(record, revision=1):
    return {"vaultId": "1" * 32, "generationId": "2" * 32, "recordId": record * 32,
            "revisionId": "9" * 32, "revisionCounter": revision}


def request(mode="p12-save", *, selected=False):
    context = {"projectId": "test-project", "draftRevision": 1, "baselineGeneration": 2,
        "savedConfig": {"bytes": 2, "sha256": "a" * 64},
        "savedVersion": {"source": "release/version.properties", "bytes": 44, "sha256": "b" * 64, "name": "1.2.3", "build": 42},
        "credentialContextRevision": 1, "recordId": "3" * 32, "recordRevision": 1,
        "executionMode": "local", "platform": "ios", "operation": "apple-bundle-provisioning",
        "displayName": "Example", "newApplication": False, "mode": mode,
        "keyRecordId": "4" * 32, "keyRecordRevision": 1,
        "p12RecordId": "5" * 32 if selected else None, "p12RecordRevision": 1 if selected else None,
        "reference": None if mode == "p12-review" else {"operationId": "7" * 32, "ownerGeneration": "8" * 32}}
    choice = {"bundle": {"resourceId": "BUNDLE123", "identifier": "com.example.app", "platform": "IOS", "seedId": "ABCDE12345"},
        "certificate": {"resourceId": "CERT123", "certificateType": "DISTRIBUTION",
            "notBefore": "2026-01-01T00:00:00+00:00", "expiresAt": "2027-01-01T00:00:00+00:00",
            "certificateSha256": "c" * 64, "publicKeySha256": "d" * 64},
        "csrSha256": "e" * 64, "beforeSha256": "f" * 64}
    review = None if mode == "p12-review" else {"reference": context["reference"],
        "observedAt": "2026-10-20T00:00:00+00:00", "validUntil": "2026-10-20T00:05:00+00:00",
        "selection": choice, "selectedP12": reference("5") if selected else None}
    native = {"target": {"bundleId": "com.example.app", "teamId": "ABCDE12345", "appIdPrefix": "ABCDE12345",
        "displayName": "Example", "existingApplication": True}, "prior": None,
        "nonce": "6" * 32, "reviewedAt": None if review is None else review["observedAt"],
        "certificate": {"sourceP8": reference("3"), "sourceKey": reference("4"), "entitlements": {},
            "keyPreparation": None, "review": None, "prior": None},
        "p12": {"sourceP8": reference("3"), "sourceKey": reference("4"),
            "selectedP12": reference("5") if selected else None,
            "p12Sha256": "b" * 64 if selected else None, "expectedCertificateSha256": "c" * 64 if selected else None,
            "destination": reference("6") if mode == "p12-save" else None, "review": review, "previous": []}}
    return Data(context=context, native=native, digest="a" * 64, operation_id="a" * 32, owner_generation="b" * 32), choice


def result(req, *, reused=False):
    output = {"frameBytes": assembly.HEADER + 4, "frameSha256": "a" * 64,
        "p12Bytes": 4, "p12Sha256": "b" * 64, "certificateSha256": "c" * 64, "publicKeySha256": "d" * 64}
    reuse = {"sourceP12": reference("5"), "p12Sha256": "b" * 64, "certificateSha256": "c" * 64,
        "publicKeySha256": "d" * 64, "policyAckSha256": "f" * 64}
    return {"schemaVersion": 1, "scope": "local-ios-p12-setup", "mode": req.context["mode"],
        "decision": "reused" if reused else "assembled", "reason": "existing-package" if reused else "producer-returned",
        "certificateId": "CERT123", "certificateSha256": "c" * 64, "publicKeySha256": "d" * 64,
        "output": None if reused else output, "reused": reuse if reused else None,
        "p12Saved": False, "profileSaved": False, "credentialReady": False, "revocationChecked": False}


class P12ProtocolTests(unittest.TestCase):
    def test_three_closed_modes_keep_exact_key_and_optional_selected_record(self):
        for mode, selected in (("p12-review", False), ("p12-review", True), ("p12-reuse", True), ("p12-save", False)):
            req, _ = request(mode, selected=selected)
            self.assertEqual(wire.context(req.context), req.context)
            wire.validate_native(req.context, req.native)
        for mode, selected in (("p12-reuse", False), ("p12-save", True)):
            req, _ = request(mode, selected=selected)
            with self.assertRaises(ValueError): wire.context(req.context)

    def test_other_context_or_missing_observation_fields_cannot_retarget_p12(self):
        req, _ = request()
        for changes in ({"mode": "certificate-create"}, {"platform": "android"}, {"executionMode": "github"},
                        {"newApplication": True}, {"keyRecordRevision": True}, {"command": ["anything"]}):
            with self.assertRaises(ValueError): wire.context({**req.context, **changes})
        invalid = dict(req.context); del invalid["p12RecordRevision"]
        with self.assertRaises(ValueError): wire.context(invalid)

    def test_new_destination_and_both_fresh_original_full_refs_are_required(self):
        req, _ = request()
        for field, replacement in (("destination", reference("4")), ("destination", reference("6", 2)),
                ("sourceP8", reference("3", 2)), ("sourceKey", reference("4", 2))):
            native = copy.deepcopy(req.native); native["p12"][field] = replacement
            with self.assertRaises(ValueError): wire.validate_native(req.context, native)
        native = copy.deepcopy(req.native); native["certificate"]["keyPreparation"] = {"old": "history"}
        with self.assertRaises(ValueError): wire.validate_native(req.context, native)

    def test_existing_record_requires_exact_saved_leaf_and_p12_comparison_values(self):
        req, _ = request("p12-reuse", selected=True)
        for field in ("selectedP12", "p12Sha256", "expectedCertificateSha256"):
            native = copy.deepcopy(req.native); native["p12"][field] = None
            with self.assertRaises(ValueError): wire.validate_native(req.context, native)
        native = copy.deepcopy(req.native); native["p12"]["selectedP12"]["generationId"] = "f" * 32
        with self.assertRaises(ValueError): wire.validate_native(req.context, native)

    def test_review_is_exact_original_reference_and_five_minutes_not_renewable(self):
        req, _ = request()
        for path, value in (("validUntil", "2026-10-20T00:06:00+00:00"), ("reference", {"operationId": "f" * 32, "ownerGeneration": "8" * 32}),
                           ("selectedP12", reference("5"))):
            native = copy.deepcopy(req.native); native["p12"]["review"][path] = value
            with self.assertRaises(ValueError): wire.validate_native(req.context, native)

    def test_local_pending_has_no_provider_attempt_or_save_fact(self):
        req, choice = request()
        payload = {"observedAt": "2026-10-20T00:00:00+00:00", "validUntil": "2026-10-20T00:05:00+00:00",
                   "selection": choice, "update": wire.initial_update()}
        wire.validate_event(req, "p12-pending", payload, 4)
        for field, value in (("sequence", True), ("cancelRequested", 0), ("save", "read-back"), ("possibleSend", True)):
            invalid = copy.deepcopy(payload); invalid["update"][field] = value
            with self.assertRaises(ValueError): wire.validate_event(req, "p12-pending", invalid, 4)
        for kind, sequence in (("certificate-pending", 4), ("p12-pending", 3), ("p12-pending", 5)):
            with self.assertRaises(ValueError): wire.validate_event(req, kind, payload, sequence)

    def test_worker_assembled_never_claims_saved_bound_ready_or_revocation(self):
        req, _ = request(); value = result(req)
        self.assertEqual(wire.validate_result(value, req), value)
        for field in ("p12Saved", "profileSaved", "credentialReady", "revocationChecked"):
            with self.assertRaises(ValueError): wire.validate_result({**value, field: True}, req)
        for changes in ({"schemaVersion": True}, {"mode": "p12-reuse"}, {"publicKeySha256": "0" * 64}, {"privateKey": "never-input"}):
            with self.assertRaises(ValueError): wire.validate_result({**value, **changes}, req)

    def test_reuse_report_cannot_substitute_a_different_revision_or_extract(self):
        req, _ = request("p12-reuse", selected=True); value = result(req, reused=True)
        wire.validate_result(value, req)
        for field, changed in (("sourceP12", reference("5", 2)), ("p12Sha256", "f" * 64),
                               ("certificateSha256", "e" * 64), ("publicKeySha256", "e" * 64)):
            invalid = copy.deepcopy(value); invalid["reused"][field] = changed
            with self.assertRaises(ValueError): wire.validate_result(invalid, req)

    def test_original_reply_is_scoped_and_custody_is_not_save_ack(self):
        req, _ = request(); payload = result(req)["output"]
        ack = {"protocol": wire.common.PROTOCOL, "operationId": req.operation_id,
            "ownerGeneration": req.owner_generation, "nonce": req.native["nonce"], "requestSha256": req.digest,
            "kind": "p12-output-ack", "step": 5,
            "payload": {"frameSha256": payload["frameSha256"], "p12Sha256": payload["p12Sha256"], "retained": True}}
        wire.reply(api.canonical(ack) + b"\n", req, "p12-output", 5, payload)
        for change in ({"step": True}, {"ownerGeneration": "f" * 32}, {"kind": "p12-pending-ack"}, {"kind": "p12-output"},
                       {"payload": {**ack["payload"], "saved": True}}):
            with self.assertRaises(ValueError): wire.reply(api.canonical({**ack, **change}) + b"\n", req, "p12-output", 5, payload)


class P12PrivateShapeTests(unittest.TestCase):
    def test_material_header_has_fixed_original_roles_and_mode_specific_password(self):
        for mode, selected in (("p12-save", False), ("p12-review", False), ("p12-review", True), ("p12-reuse", True)):
            req, _ = request(mode, selected=selected)
            roles = list(private.BASE_ROLES)
            if mode == "p12-save": roles += [("p12-password", 64)]
            elif selected: roles += [("distribution-p12", 4 * 1024 * 1024), ("p12-password", 4096)]
            value = {"schemaVersion": 1, "files": [{"role": role, "bytes": limit} for role, limit in roles]}
            self.assertEqual(private.material_header(api.canonical(value) + b"\n", req), tuple(limit for _, limit in roles))
            for index in range(len(roles)):
                bad = copy.deepcopy(value); bad["files"][index]["bytes"] += 1
                with self.assertRaises(ValueError): private.material_header(api.canonical(bad) + b"\n", req)
            bad = copy.deepcopy(value); bad["files"][0]["role"] = "arbitrary-file"
            with self.assertRaises(ValueError): private.material_header(api.canonical(bad) + b"\n", req)

    def test_duplicate_boolean_and_public_private_field_header_errors(self):
        req, _ = request()
        value = {"schemaVersion": 1, "files": [{"role": role, "bytes": limit} for role, limit in (*private.BASE_ROLES, ("p12-password", 64))]}
        for changes in ({"schemaVersion": True}, {"password": "not-a-header-field"}):
            with self.assertRaises(ValueError): private.material_header(api.canonical({**value, **changes}) + b"\n", req)
        value["files"][0]["bytes"] = True
        with self.assertRaises(ValueError): private.material_header(api.canonical(value) + b"\n", req)
        with self.assertRaises(ValueError): private.material_header(b'{"schemaVersion":1,"schemaVersion":1,"files":[]}\n', req)

    def test_raw_header_binds_exact_request_and_raw_frame_without_public_material(self):
        raw = assembly.MAGIC + struct.pack(">I", 4) + b"L" * 32 + b"S" * 32 + b"DATA"
        header = private.header("a" * 64, raw)
        length, request_digest, frame_digest = private.HEADER.unpack(header[len(private.MAGIC):])
        self.assertEqual(length, len(raw)); self.assertEqual(request_digest, bytes.fromhex("a" * 64))
        self.assertEqual(frame_digest.hex(), api.digest(raw))
        self.assertNotIn(b"DATA", header)
        with self.assertRaises(api.ProvisioningError): private.header("a" * 64, raw + b"x")


if __name__ == "__main__": unittest.main()
