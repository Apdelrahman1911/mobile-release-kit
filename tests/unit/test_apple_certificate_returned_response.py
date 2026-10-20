"""Inert original-attempt regressions; no HTTP, credentials or native proof."""
from dataclasses import replace
import unittest

from mobile_release import apple_provisioning_api as api
from mobile_release import apple_provisioning_certificate_issuance as issuance
from tests.unit.test_apple_provisioning_certificate_issuance import attempt, later
from tests.unit.test_apple_provisioning import NOW, approval, binding, response


class ReturnedCertificateTests(unittest.TestCase):
    def returned(self, hook):
        provider, plan, before, operation, owner = attempt()
        send = provider.send

        def captured(request):
            result = send(request)
            operation.retain_returned_response(result)
            hook(operation, owner, result)
            return result

        provider.send = captured
        return provider, plan, before, operation, owner

    def test_returned_201_survives_later_authorization_loss_not_success(self):
        provider, plan, before, operation, owner = self.returned(lambda _, owner, __: setattr(owner, "current", False))
        result = operation.execute(approval(plan), before, provider, owner, now=NOW)
        self.assertEqual((result.status, result.reason), ("unknown", "authorization_changed_after_send"))
        self.assertEqual(result.response_resource_id, "certificate-one")
        self.assertEqual(result.response_resource_sha256, operation.receipt.sha256)
        self.assertEqual(owner.records[-1], result)
        self.assertEqual(len(provider.writes), 1)
        with self.assertRaises(api.ProvisioningError):
            operation.execute(approval(plan), before, provider, owner, now=NOW)

    def test_returned_201_then_stop_preserves_exact_primary_and_cancel(self):
        stopped = KeyboardInterrupt("inert stop")

        def cancel(operation, _, __):
            operation.request_cancel()
            raise stopped

        provider, plan, before, operation, owner = self.returned(cancel)
        with self.assertRaises(KeyboardInterrupt) as raised:
            operation.execute(approval(plan), before, provider, owner, now=NOW)
        self.assertIs(raised.exception, stopped)
        self.assertEqual(operation.record.status, "unknown")
        self.assertTrue(operation.record.cancel_requested)
        self.assertTrue(operation.record.possible_send)
        self.assertEqual(owner.records[-1].response_resource_id, "certificate-one")
        self.assertEqual(len(provider.writes), 1)

    def test_journal_failure_with_reentrant_cancel_does_not_discard_receipt(self):
        provider, plan, before, operation, owner = self.returned(lambda *_: None)
        persist = owner.persist

        def fail_late(record):
            persist(record)
            if record.response_resource_id is not None:
                # Must not deadlock: the original state gate is released before
                # this actual callback, and cancellation is not overwritten.
                operation.request_cancel()
                raise OSError("inert journal failure")

        owner.persist = fail_late
        result = operation.execute(approval(plan), before, provider, owner, now=NOW)
        self.assertEqual((result.status, result.reason), ("recovery_required", "journal_settlement_required"))
        self.assertTrue(result.cancel_requested)
        self.assertEqual(result.response_resource_sha256, operation.receipt.sha256)
        self.assertEqual(result.response_resource_id, "certificate-one")
        self.assertEqual(len(provider.writes), 1)

    def test_no_receipt_from_absent_unsettled_wrong_status_or_pre_send(self):
        for invalid in (None, api.AppleResponse(201, b'{"data":{"type":"certificates","id":"new"}}', False),
                        response({"type": "certificates", "id": "new"}, status=200)):
            with self.subTest(invalid=type(invalid)):
                provider, plan, before, operation, owner = attempt()
                send = provider.send

                def capture(request):
                    send(request)
                    operation.retain_returned_response(invalid)
                    self.fail("invalid receipt accepted")

                provider.send = capture
                result = operation.execute(approval(plan), before, provider, owner, now=NOW)
                self.assertEqual(result.status, "unknown")
                self.assertIsNone(operation.receipt)
                self.assertIsNone(result.response_resource_id)
        provider, plan, before, operation, owner = attempt()
        with operation._action_gate:
            with self.assertRaises(api.ProvisioningError):
                operation.retain_returned_response(provider.mutation)
        owner.fail_persist = True
        operation.execute(approval(plan), before, provider, owner, now=NOW)
        with operation._action_gate:
            with self.assertRaises(api.ProvisioningError):
                operation.retain_returned_response(provider.mutation)
        self.assertIsNone(operation.receipt)
        self.assertFalse(provider.writes)

    def test_same_parse_is_stable_conflict_never_replaces_first_or_confirms(self):
        def duplicate(operation, _, result):
            first = operation.receipt
            self.assertIs(operation.retain_returned_response(result), first)
            operation.retain_returned_response(response({"type": "certificates", "id": "other"}, status=201))

        provider, plan, before, operation, owner = self.returned(duplicate)
        result = operation.execute(approval(plan), before, provider, owner, now=NOW)
        self.assertEqual((result.status, result.response_resource_id), ("unknown", "certificate-one"))
        self.assertEqual(operation.receipt.resource_id, "certificate-one")
        observed = later(provider)
        result = operation.reconcile(observed, owner, bindings=(binding(),), now=observed.observed_at)
        self.assertEqual((result.status, result.reason), ("unknown", "provider_result_requires_reconciliation"))
        self.assertEqual(len(provider.writes), 1)

    def test_documented_information_is_bounded_typed_and_not_receipt_authority(self):
        _, _, before, _, _ = attempt()
        value = {"type": "certificates", "id": "new", "attributes": {
            "displayName": "Synthetic Distribution", "name": "Synthetic", "serialNumber": "AABBCC", "activated": True}}
        receipt = issuance.CertificateCreationReceipt.parse(response(value, status=201), before)
        self.assertIsNone(receipt.certificate_sha256)
        self.assertIsNone(receipt.certificate_type)
        self.assertIsNone(receipt.expires_at)
        self.assertNotIn(b"Synthetic", receipt.private_record())
        for name, invalid in (("displayName", {}), ("name", "x" * 1025), ("name", "text\x00"),
                              ("serialNumber", 12), ("activated", 1), ("privateKey", "no")):
            changed = {**value, "attributes": {**value["attributes"], name: invalid}}
            with self.subTest(name=name), self.assertRaises(api.ProvisioningError):
                issuance.CertificateCreationReceipt.parse(response(changed, status=201), before)


if __name__ == "__main__":
    unittest.main()
