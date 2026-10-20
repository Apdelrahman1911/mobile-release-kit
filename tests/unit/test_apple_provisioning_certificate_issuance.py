"""Synthetic DATA/provider doubles only: no key/CSR, native, SDK or HTTP work.

The inherited fake CertificateBinding stands for an actual native conjunction
that these tests do NOT qualify. No test opens a vault or grants a saved ACK.
"""
from __future__ import annotations

import base64
import unittest
from dataclasses import replace
from datetime import timedelta
from unittest.mock import patch

from mobile_release import apple_provisioning_api as api
from mobile_release import apple_provisioning_certificate_issuance as issuance
from mobile_release.apple_provisioning import PendingMutation
from mobile_release.apple_provisioning_signing import observe_signing
from tests.unit.test_apple_provisioning import (
    BUNDLE, CERT_BYTES, CONTEXT, CSR, KEY, NOW, TARGET, FakeOwner, FakeProvider,
    approval, binding, bundle, certificate, response,
)


def inventory(provider, *, now=NOW):
    return observe_signing(CONTEXT, TARGET, provider, now=now)


def planned(provider, *, csr=CSR, bindings=(), pending=()):
    snapshot = inventory(provider)
    plan = issuance.prepare_certificate(CONTEXT, TARGET, snapshot, bindings=bindings, csr=csr, pending=pending, now=NOW)
    return plan, snapshot.observation


def attempt(mutation=None):
    provider = FakeProvider(certificates=[], profiles=[], mutation=mutation if mutation is not None else
        response({"type": "certificates", "id": "certificate-one"}, status=201))
    plan, before = planned(provider)
    return provider, plan, before, issuance.CertificateCreationAttempt(plan, before), FakeOwner()


def later(provider, *, certificates=None, now=NOW + timedelta(seconds=1)):
    provider.responses["list_certificates"] = response([certificate()] if certificates is None else certificates)
    return inventory(provider, now=now).observation


class AppleCertificateIssuanceTests(unittest.TestCase):
    def test_reuse_first_never_work_around_missing_private_key_or_pending_account(self):
        provider = FakeProvider(profiles=[])
        plan, _ = planned(provider, csr=None, bindings=(binding(),))
        self.assertEqual(plan.action, "reuse_certificate")
        self.assertIsNone(plan.request)
        self.assertFalse(provider.writes)
        plan, _ = planned(provider, csr=CSR)
        self.assertEqual(plan.action, "recover_existing_key")
        self.assertIsNone(plan.request)
        for native in ("pending", "unknown"):
            row = PendingMutation(CONTEXT.account_ref, "old-attempt", "create_certificate", "succeeded", native)
            plan, _ = planned(provider, pending=(row,))
            self.assertEqual(plan.action, "reconcile")
            self.assertIsNone(plan.request)
        provider = FakeProvider(certificates=[], profiles=[])
        plan, _ = planned(provider, csr=None)
        self.assertEqual(plan.action, "prepare_csr")
        plan, _ = planned(provider)
        self.assertEqual(plan.action, "create_certificate")
        self.assertEqual(plan.request, api.create_certificate(CSR.csr_pem))

    def test_closed_certificate_scope_does_not_register_download_or_create_profile(self):
        for request in (api.register_bundle_id(BUNDLE, "Synthetic"), api.create_profile("Synthetic", "b", "c"),
                        api.download_profile("synthetic-profile")):
            with self.subTest(kind=request.kind), self.assertRaises(api.ProvisioningError):
                issuance.validate_request(request, TARGET, csr=CSR)
        with self.assertRaises(api.ProvisioningError):
            issuance.validate_request(api.list_bundle_ids("different.invalid.example"), TARGET, csr=None)
        with self.assertRaises(api.ProvisioningError):
            issuance.validate_request(api.create_certificate(CSR.csr_pem), TARGET, csr=None)
        provider = FakeProvider(bundles=[], certificates=[], profiles=[])
        snapshot = inventory(provider)
        plan = issuance.prepare_certificate(CONTEXT, replace(TARGET, existing_application=False), snapshot,
            bindings=(), csr=CSR, pending=(), now=NOW)
        self.assertEqual((plan.action, plan.reason, plan.request), ("manual", "bundle_registration_required", None))

    def test_exact_context_key_reference_and_observation_bind_the_single_plan(self):
        provider, plan, before, operation, owner = attempt()
        changed = replace(plan, csr=replace(CSR, key_ref=replace(KEY, revision_id="a" * 32)))
        self.assertNotEqual(plan.sha256, changed.sha256)
        for fresh in (replace(before, context=replace(CONTEXT, credential_revision=2)),
                      replace(before, certificates=(api.Certificate.parse(certificate()),))):
            with self.assertRaises(api.ProvisioningError):
                operation.execute(approval(plan), fresh, provider, owner, now=NOW)
        self.assertFalse(provider.writes)
        self.assertFalse(owner.records)
        with self.assertRaises(api.ProvisioningError):
            operation.execute(approval(changed), before, provider, owner, now=NOW)

    def test_durable_ack_precedes_post_and_failed_or_reentrant_ack_never_retries(self):
        provider, plan, before, operation, owner = attempt()
        owner.fail_persist = True
        result = operation.execute(approval(plan), before, provider, owner, now=NOW)
        self.assertEqual(result.reason, "journal_settlement_required")
        self.assertFalse(provider.writes)
        owner.fail_persist = False
        with self.assertRaises(api.ProvisioningError):
            operation.execute(approval(plan), before, provider, owner, now=NOW)
        provider, plan, before, operation, owner = attempt()
        original_persist = owner.persist
        def persist(record):
            if not owner.records:
                self.assertTrue(record.possible_send)
                self.assertFalse(provider.writes)
                with self.assertRaises(api.ProvisioningError):
                    operation.execute(approval(plan), before, provider, owner, now=NOW)
            original_persist(record)
        owner.persist = persist
        result = operation.execute(approval(plan), before, provider, owner, now=NOW)
        self.assertEqual(len(provider.writes), 1)
        self.assertEqual((result.status, result.reason), ("recovery_required", "readback_required"))

    def test_sparse_201_is_not_success_until_exact_current_native_readback(self):
        provider, plan, before, operation, owner = attempt()
        result = operation.execute(approval(plan), before, provider, owner, now=NOW)
        self.assertEqual(result.response_resource_id, "certificate-one")
        self.assertEqual(result.response_resource_sha256, operation.receipt.sha256)
        self.assertEqual(result.status, "recovery_required")
        observed = later(provider)
        result = operation.reconcile(observed, owner, bindings=(), now=observed.observed_at)
        self.assertEqual(result.status, "unknown")
        result = operation.reconcile(observed, owner, bindings=(binding(),), now=observed.observed_at)
        self.assertEqual((result.status, result.reason), ("succeeded", "provider_resource_confirmed"))
        self.assertFalse(result.summary()["credentialReady"])
        self.assertFalse(result.summary()["retryAllowed"])
        self.assertEqual(len(provider.writes), 1)
        self.assertNotIn("certificate-one", str(result.summary()))

    def test_sparse_present_attributes_are_constraints_not_inferred_fields(self):
        raw = response(certificate(), status=201)
        provider, plan, before, operation, owner = attempt(raw)
        operation.execute(approval(plan), before, provider, owner, now=NOW)
        original = operation.receipt
        self.assertEqual(original.certificate_sha256, api.digest(CERT_BYTES))
        self.assertFalse(original.matches(api.Certificate.parse(certificate(content=b"different synthetic DER"))))
        self.assertFalse(original.matches(api.Certificate.parse(certificate(expires=NOW + timedelta(days=91)))))
        self.assertTrue(original.matches(api.Certificate.parse(certificate())))
        # A sparse ID retains no claimed DER/time/type. Full GET validation and
        # native binding, never the missing receipt fields, must supply them.
        sparse = issuance.CertificateCreationReceipt.parse(response({"type": "certificates", "id": "new"}, status=201), before)
        self.assertIsNone(sparse.certificate_sha256)
        self.assertIsNone(sparse.expires_at)
        self.assertIsNone(sparse.certificate_type)

    def test_wrong_sparse_shape_existing_id_type_extra_relationship_or_content_refused(self):
        _, _, before, _, _ = attempt()
        bad = [
            {"type": "certificates", "id": "new", "attributes": {"certificateType": "IOS_DISTRIBUTION"}},
            {"type": "certificates", "id": "new", "attributes": {"platform": "MAC_OS"}},
            {"type": "certificates", "id": "new", "attributes": {"platform": []}},
            {"type": "certificates", "id": "new", "attributes": {"certificateContent": "!!!!"}},
            {"type": "certificates", "id": "new", "attributes": {"expirationDate": "not-a-date"}},
            {"type": "certificates", "id": "new", "relationships": {}},
            {"type": "certificates", "id": "new", "attributes": {"privateKey": "SYNTHETIC_PRIVATE"}},
        ]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(api.ProvisioningError):
                issuance.CertificateCreationReceipt.parse(response(value, status=201), before)
        with self.assertRaises(api.ProvisioningError):
            issuance.CertificateCreationReceipt.parse(response(certificate(), status=201),
                replace(before, certificates=(api.Certificate.parse(certificate()),)))
        with self.assertRaises(api.ProvisioningError):
            issuance.CertificateCreationReceipt.parse(response(certificate(), status=200), before)

    def test_timeout_unique_match_needs_review_not_attribution_or_second_post(self):
        provider, plan, before, operation, owner = attempt(TimeoutError("SYNTHETIC_PRIVATE_PROVIDER_DETAIL"))
        result = operation.execute(approval(plan), before, provider, owner, now=NOW)
        self.assertTrue(result.possible_send)
        self.assertEqual(result.status, "unknown")
        observed = later(provider)
        result = operation.reconcile(observed, owner, bindings=(binding(),), now=observed.observed_at)
        self.assertEqual((result.status, result.reason), ("recovery_required", "resource_found_review_required"))
        self.assertIsNone(result.response_resource_id)
        self.assertEqual(result.observed_resource_id, "certificate-one")
        self.assertIn("Review", issuance.recovery_guidance(result))
        with self.assertRaises(api.ProvisioningError):
            operation.execute(approval(plan), before, provider, owner, now=NOW)
        self.assertEqual(len(provider.writes), 1)

    def test_empty_ambiguous_wrong_key_team_spki_and_native_unknown_preserve_uncertainty(self):
        for rows, bindings, expected in [
            ([], (), "provider_outcome_still_unknown"),
            ([certificate(), certificate("certificate-two")], (binding(), binding("certificate-two")), "ambiguous_recovery_resources"),
            ([certificate()], (binding(key=replace(KEY, record_id="a" * 32)),), "provider_outcome_still_unknown"),
            ([certificate()], (replace(binding(), public_key_sha256="a" * 64),), "provider_outcome_still_unknown"),
            ([certificate()], (binding(team="OTHERTEAM1"),), "resource_validation_required"),
        ]:
            with self.subTest(expected=expected):
                provider, plan, before, operation, owner = attempt(TimeoutError("inert"))
                operation.execute(approval(plan), before, provider, owner, now=NOW)
                observed = later(provider, certificates=rows)
                result = operation.reconcile(observed, owner, bindings=bindings, now=observed.observed_at)
                self.assertEqual(result.reason, expected)
                self.assertNotEqual(result.status, "succeeded")
                self.assertEqual(len(provider.writes), 1)
        provider, plan, before, operation, owner = attempt()
        owner.settled = False
        result = operation.execute(approval(plan), before, provider, owner, now=NOW)
        self.assertEqual(result.reason, "original_transport_unsettled")
        self.assertIsNone(operation.receipt)
        self.assertIsNone(result.response_resource_id)

    def test_known_rejection_vs_unknown_rate_limit_server_failure_no_key_rotation(self):
        for status in (400, 401, 403, 404, 405, 409, 422, 429, 500):
            with self.subTest(status=status):
                provider, plan, before, operation, owner = attempt(api.AppleResponse(status, b"{}", True))
                result = operation.execute(approval(plan), before, provider, owner, now=NOW)
                self.assertEqual(result.status, "unknown" if status in {429, 500} else "failed")
                if status not in {429, 500}:
                    self.assertIn("agreements", issuance.recovery_guidance(result))
                self.assertTrue(result.possible_send)
                self.assertFalse(result.summary()["retryAllowed"])
                with self.assertRaises(api.ProvisioningError):
                    operation.execute(approval(plan), before, provider, owner, now=NOW)
                self.assertEqual(len(provider.writes), 1)
                self.assertEqual(provider.writes[0].kind, "create_certificate")

    def test_read_only_restart_retains_sparse_receipt_but_never_rearms_send(self):
        provider, plan, before, operation, owner = attempt()
        record = operation.execute(approval(plan), before, provider, owner, now=NOW)
        receipt = issuance.CertificateCreationReceipt.from_private_record(operation.receipt.private_record())
        restored = issuance.CertificateCreationAttempt.resume(plan, before, record, receipt=receipt)
        with self.assertRaises(api.ProvisioningError):
            restored.execute(approval(plan), before, provider, owner, now=NOW)
        observed = later(provider)
        owner.current = False
        result = restored.reconcile(observed, owner, bindings=(binding(),), now=observed.observed_at)
        self.assertEqual(result.reason, "reconciliation_context_changed")
        owner.current = True
        result = restored.reconcile(observed, owner, bindings=(binding(),), now=observed.observed_at)
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(len(provider.writes), 1)
        for changed in (None, replace(receipt, resource_id="other"), replace(receipt, certificate_sha256="b" * 64)):
            with self.assertRaises(api.ProvisioningError):
                issuance.CertificateCreationAttempt.resume(plan, before, record, receipt=changed)
        # A NEW backup reference cannot reuse the old operation's identity.
        changed = replace(plan, csr=replace(CSR, key_ref=replace(KEY, record_id="a" * 32)))
        with self.assertRaises(api.ProvisioningError):
            issuance.CertificateCreationAttempt.resume(changed, before, record, receipt=receipt)

    def test_receipt_is_bounded_canonical_nonsecret_data_not_restored_authority(self):
        _, _, before, _, _ = attempt()
        receipt = issuance.CertificateCreationReceipt.parse(response(certificate(), status=201), before)
        encoded = receipt.private_record()
        self.assertEqual(issuance.CertificateCreationReceipt.from_private_record(encoded), receipt)
        self.assertLess(len(encoded), issuance.RECEIPT_LIMIT)
        self.assertNotIn(base64.b64encode(CERT_BYTES), encoded)
        self.assertNotIn(CSR.csr_pem, encoded)
        for raw in (b" " + encoded, encoded.replace(b'"schemaVersion":1', b'"schemaVersion":true'),
                    encoded.replace(b'"certificateType":"DISTRIBUTION"', b'"certificateType":[]'),
                    encoded.replace(b'"resourceId":', b'"extra":null,"resourceId":'),
                    encoded.replace(b'"resourceId":', b'"resourceId":"other","resourceId":'),
                    b" " * (issuance.RECEIPT_LIMIT + 1)):
            with self.subTest(raw=raw[:40]), self.assertRaises(api.ProvisioningError):
                issuance.CertificateCreationReceipt.from_private_record(raw)
        with self.assertRaises(api.ProvisioningError):
            issuance.CertificateCreationAttempt.resume(None, before, None, receipt=None)


class AppleCertificateFrameTests(unittest.TestCase):
    def frame(self, *, body=b'{"data":[]}', status=200, failure=None):
        request = api.create_certificate(CSR.csr_pem)
        data = {"schemaVersion": 1, "scope": issuance.SCOPE, "contextSha256": "a" * 64, "bundleId": BUNDLE,
            "operationId": CONTEXT.operation_id, "requestSha256": api.request_sha256(request),
            "keySavedAckSha256": "b" * 64, "ackSha256": "c" * 64,
            "response": {"status": status, "bodyBase64": base64.b64encode(body).decode() if failure is None else None,
                         "failure": failure}}
        return data

    def parse(self, value, *, settled=True):
        return issuance.response_from_frame(api.canonical(value), context_sha256="a" * 64,
            operation_id=CONTEXT.operation_id, target=TARGET, request=api.create_certificate(CSR.csr_pem), csr=CSR,
            key_saved_ack_sha256="b" * 64, ack_sha256="c" * 64, settled=settled)

    def test_raw_duplicates_and_external_finality_remain_separate(self):
        raw = b'{"data":{},"data":[]}'
        result = self.parse(self.frame(body=raw), settled=False)
        self.assertEqual(result.body, raw)
        self.assertFalse(result.settled)
        with self.assertRaises(api.ProvisioningError):
            api.document(result.body)
        changed = self.frame(); changed["settled"] = True
        with self.assertRaises(api.ProvisioningError):
            self.parse(changed)

    def test_wrong_scope_context_request_either_ack_or_status_refused(self):
        for name, value in (("scope", "existing-p12-app-store-profile"), ("contextSha256", "d" * 64),
                            ("bundleId", "different.invalid.example"), ("operationId", "other"),
                            ("requestSha256", "d" * 64), ("keySavedAckSha256", None), ("ackSha256", "d" * 64),
                            ("schemaVersion", True)):
            changed = self.frame(); changed[name] = value
            with self.subTest(name=name), self.assertRaises(api.ProvisioningError):
                self.parse(changed)
        changed = self.frame(); changed["response"]["status"] = True
        with self.assertRaises(api.ProvisioningError):
            self.parse(changed)

    def test_encoded_oversize_refused_before_decode_and_rejections_stay_distinct(self):
        changed = self.frame()
        changed["response"]["bodyBase64"] = "A" * (4 * ((issuance.RAW_LIMIT + 2) // 3) + 4)
        with patch.object(issuance.base64, "b64decode", side_effect=AssertionError("must refuse before decoding")):
            with self.assertRaises(api.ProvisioningError):
                self.parse(changed)
        for status in (403, 409, 429, 500, None):
            value = self.frame(status=status, failure="provider_request_unconfirmed")
            if status in (403, 409):
                self.assertEqual(self.parse(value).body, b"{}")
            else:
                with self.assertRaises(api.ProvisioningError):
                    self.parse(value)


if __name__ == "__main__":
    unittest.main()
