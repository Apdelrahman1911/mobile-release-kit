"""Recovery on the existing fixed engine fixture; no crypto/provider/native.

The original fixture owns finite files/pipes and patches every command/SDK.
Its outcome and ACK DATA do not construct the native recovery proof or CAS.
"""
import copy
import unittest

from mobile_release import _desktop_apple_key_recovery as recovery
from mobile_release import _desktop_apple_provisioning_protocol as wire
from mobile_release import apple_provisioning_api as api
from . import test_desktop_apple_key as original
from . import test_desktop_apple_provisioning as old
from . import test_desktop_apple_certificate as certificate_original

KEY = {"vaultId": "1" * 32, "generationId": "2" * 32, "recordId": "4" * 32,
       "revisionId": "5" * 32, "revisionCounter": 1}
OLD = {"operationId": "6" * 32, "ownerGeneration": "7" * 32}
ASSOCIATION = {"operationId": "8" * 32, "ownerGeneration": "9" * 32}


def selected(root, runtime, *, settled="pending", associated=False):
    value = old.request(root, runtime)
    value["context"].update(mode="key-recover", reference=None, keyRecordId=KEY["recordId"], keyRecordRevision=1)
    value["native"]["key"] = {"sourceP8": {**KEY, "recordId": old.RECORD, "revisionId": "3" * 32, "revisionCounter": 3},
        "sourceKey": KEY, "destination": None, "entitlements": {}, "review": None, "vaultInventory": None,
        "recovery": {"reference": OLD, "rowSha256": "d" * 64, "nativeSettlement": settled,
            "output": {"frameBytes": len(original.FRAME), "frameSha256": api.digest(original.FRAME),
                "csrSha256": api.digest(original.CSR), "publicKeySha256": api.digest(original.SPKI)},
            "recovery": {"reference": ASSOCIATION, "sha256": "e" * 64} if associated else None}}
    value["native"]["pending"] = [{"accountRef": old.ACCOUNT, "operationId": OLD["operationId"], "action": "key_prepare",
        "status": "unknown" if settled == "pending" else "succeeded", "nativeSettlement": settled}]
    if associated:
        value["native"]["keyRecoveries"] = [{"accountRef": old.ACCOUNT, **ASSOCIATION,
            "originalOperationId": OLD["operationId"], "originalOwnerGeneration": OLD["ownerGeneration"],
            "originalRowSha256": "d" * 64, "recordSha256": "e" * 64}]
    return value


class KeyRecoveryWorkerTests(unittest.TestCase):
    # Reuse the SAME actual engine fixture, no substitute provisioning runner.
    execute = original.KeyWorkerTests.execute

    def test_original_verifier_comparison_only_has_no_provider_generator_or_private_export(self):
        engine, code, frames, calls, raw = self.execute("key-recover")
        self.assertEqual(code, 0, repr(engine.primary))
        self.assertEqual(calls, ["probe"] * 6 + ["verifier"])
        self.assertEqual([row["kind"] for row in frames], ["accepted", "key-compared", "terminal"])
        result = frames[-1]["payload"]["result"]
        self.assertEqual(result["decision"], "compared")
        self.assertEqual(result["reason"], "stored-key-checked")
        self.assertFalse(result["saved"] or result["certificateRequested"] or result["credentialReady"])
        self.assertEqual(raw, b"")
        self.assertIsNone(engine.service.attempt)
        self.assertFalse(engine.input._ack_consumed)
        self.assertEqual(engine.input.reply_step, 1)
        self.assertTrue(engine.service.closed() and engine.input.material_closed())
        self.assertTrue(engine.service._distribution_key.private_closed())

    def test_each_original_hash_and_actual_private_frame_must_match_before_comparison_ack(self):
        for fault in ("recover-csr", "recover-spki", "recover-frame", "recover-private"):
            with self.subTest(fault=fault):
                engine, _, frames, calls, raw = self.execute("key-recover", fault=fault)
                self.assertEqual(calls, ["probe"] * 6 + ["verifier"])
                self.assertNotIn("key-compared", [row["kind"] for row in frames])
                self.assertNotEqual(frames[-1]["payload"]["outcome"], "complete")
                self.assertIsNone(frames[-1]["payload"]["result"])
                self.assertIsNone(engine.service._key_recovery.ack)
                self.assertEqual(raw, b"")

    def test_stop_source_change_foreign_or_missing_reply_never_becomes_recovery_success(self):
        for fault in ("recover-stop", "recover-source", "recover-foreign-ack", "recover-wrong-row", "recover-partial-ack"):
            with self.subTest(fault=fault):
                engine, _, frames, calls, raw = self.execute("key-recover", fault=fault)
                self.assertEqual(calls, ["probe"] * 6 + ["verifier"])
                self.assertNotEqual(frames[-1]["payload"]["outcome"], "complete")
                self.assertIsNone(frames[-1]["payload"]["result"])
                self.assertEqual(raw, b"")
                self.assertFalse(engine.input._ack_consumed)
                self.assertIsNone(engine.service.attempt)

    def test_native_selection_requires_null_reference_current_key_and_validated_exact_relation(self):
        with old.BundleWorkerTests.files(self) as (_, root, runtime):
            for settled, associated in (("pending", False), ("pending", True), ("known", False)):
                value = selected(root, runtime, settled=settled, associated=associated)
                parsed = wire.parse_request(old.encode(value))
                self.assertEqual(parsed.context["reference"], None)
                self.assertEqual(wire.command_count("key-recover"), 7)
                self.assertEqual(parsed.native["pending"], value["native"]["pending"])
            value = selected(root, runtime, associated=True)
            for change in ("reference", "missing-key", "extra-p12", "foreign-account", "wrong-old-owner",
                           "wrong-row-hash", "duplicate", "unknown", "restored-new", "missing-relation"):
                bad = copy.deepcopy(value)
                if change == "reference": bad["context"]["reference"] = OLD
                if change == "missing-key": del bad["context"]["keyRecordId"]
                if change == "extra-p12": bad["context"]["p12RecordId"] = "e" * 32
                if change == "foreign-account": bad["native"]["keyRecoveries"][0]["accountRef"] = "f" * 64
                if change == "wrong-old-owner": bad["native"]["keyRecoveries"][0]["originalOwnerGeneration"] = "d" * 32
                if change == "wrong-row-hash": bad["native"]["keyRecoveries"][0]["originalRowSha256"] = "f" * 64
                if change == "duplicate": bad["native"]["keyRecoveries"] *= 2
                if change == "unknown": bad["native"]["key"]["recovery"]["nativeSettlement"] = "unknown"
                if change == "restored-new": bad["native"]["key"]["sourceKey"]["recordId"] = "e" * 32
                if change == "missing-relation": del bad["native"]["keyRecoveries"]
                with self.subTest(change=change), self.assertRaises((ValueError, api.ProvisioningError)):
                    wire.parse_request(old.encode(bad))

    def test_effective_fence_adapter_preserves_raw_old_pending_and_all_other_families(self):
        with old.BundleWorkerTests.files(self) as (_, root, runtime):
            value = selected(root, runtime, associated=True)
            for action in ("register_bundle_id", "profile_setup", "create_certificate", "p12_setup"):
                native = copy.deepcopy(value["native"])
                native["pending"].append({"accountRef": old.ACCOUNT, "operationId": "e" * 32, "action": action,
                    "status": "unknown", "nativeSettlement": "unknown"})
                retained = copy.deepcopy(native)
                effective = recovery.effective_pending(native, old.ACCOUNT)
                self.assertEqual([row.kind for row in effective], [action])
                self.assertTrue(effective[0].unresolved)
                self.assertEqual(native, retained)
                # A relation cannot discharge any other family, unknown
                # native state, a missing row, or a duplicate operation.
                for change in ("kind", "settlement", "missing", "same-operation", "extra"):
                    bad = copy.deepcopy(native)
                    if change == "kind": bad["pending"][0]["action"] = action
                    if change == "settlement": bad["pending"][0]["nativeSettlement"] = "unknown"
                    if change == "missing": bad["pending"].pop(0)
                    if change == "same-operation": bad["keyRecoveries"][0]["operationId"] = OLD["operationId"]
                    if change == "extra": bad["keyRecoveries"][0]["eligible"] = True
                    with self.subTest(action=action, change=change), self.assertRaises((ValueError, api.ProvisioningError)):
                        recovery.effective_pending(bad, old.ACCOUNT)


class RecoveredCertificateWorkerTests(unittest.TestCase):
    execute = certificate_original.CertificateWorkerTests.execute

    def test_new_original_certificate_review_uses_recovered_origin_not_old_key_saved_ack(self):
        engine, code, frames, calls = self.execute(recovered=True)
        self.assertEqual(code, 0, repr(engine.primary))
        self.assertEqual(frames[-1]["payload"]["result"]["decision"], "request-review")
        self.assertIsNone(engine.service._certificate.key_saved_ack)
        self.assertEqual(engine.service._certificate.key_recovery_ack, "e" * 64)
        self.assertNotIn("create_certificate", calls)
        self.assertTrue(engine.service.closed())

    def test_separate_explicit_create_keeps_original_pending_and_exact_new_origin(self):
        engine, code, frames, calls = self.execute("certificate-create", recovered=True)
        self.assertEqual(code, 0, repr(engine.primary))
        self.assertEqual(calls.count("create_certificate"), 1)  # Inert SDK response only.
        self.assertEqual(frames[-1]["payload"]["result"]["decision"], "request-confirmed")
        self.assertIsNone(engine.service._certificate.key_saved_ack)
        self.assertTrue(engine.service.closed() and engine.input.material_closed())

    def test_missing_both_or_foreign_origin_refuses_before_first_provider_read(self):
        for fault in ("recovery-both-origins", "recovery-missing-origin", "recovery-wrong-origin", "recovery-private-frame"):
            with self.subTest(fault=fault):
                engine, _, frames, calls = self.execute("certificate-create", recovered=True, fault=fault)
                self.assertEqual(calls, ["probe"] * 6 + ["verifier"])
                self.assertNotEqual(frames[-1]["payload"]["outcome"], "complete")
                self.assertIsNone(frames[-1]["payload"]["result"])
                self.assertFalse(engine.input._ack_consumed)

    def test_normal_origin_keeps_its_shape_and_cannot_adopt_a_recovery_or_foreign_ack(self):
        engine, code, frames, calls = self.execute("certificate-create")
        self.assertEqual(code, 0, repr(engine.primary))
        self.assertEqual(engine.service._certificate.key_saved_ack, "9" * 64)
        self.assertIsNone(engine.service._certificate.key_recovery_ack)
        self.assertNotIn("keyRecoverySha256", engine.service._certificate.key_ack)
        self.assertEqual(calls.count("create_certificate"), 1)
        for fault in ("normal-wrong-origin", "normal-recovery-origin", "normal-missing-origin"):
            with self.subTest(fault=fault):
                engine, _, frames, calls = self.execute("certificate-create", fault=fault)
                self.assertEqual(calls, ["probe"] * 6 + ["verifier"])
                self.assertNotEqual(frames[-1]["payload"]["outcome"], "complete")
                self.assertIsNone(frames[-1]["payload"]["result"])
                self.assertFalse(engine.input._ack_consumed)


if __name__ == "__main__":
    unittest.main()
