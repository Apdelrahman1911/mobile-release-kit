"""Pure existing-profile policy and fake-call wiring, never native acceptance.

No P12, private key, signed profile, Security call, child or account is created.
One negative test deliberately feeds a result-shaped decode into the REAL
profile-evidence consumer: it must refuse without an original joined producer.
"""
from __future__ import annotations

import hashlib
import json
import pickle
import unittest
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from mobile_release import apple_provisioning_existing as existing
from mobile_release.apple_provisioning import CertificateBinding, ProvisioningTarget
from mobile_release.apple_provisioning_api import ProvisioningError
from mobile_release.cancellation import DefaultCancellation
from mobile_release.errors import ValidationError
from mobile_release.inspection import InspectionDeadline
from mobile_release.owned_process import ProcessCleanupError, ProcessError


NOW = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
CREATED, EXPIRES = NOW - timedelta(days=1), NOW + timedelta(days=30)
TEAM, BUNDLE = "TESTTEAM01", "invalid.example.existing"
LEAF = b"obviously fake public leaf; not DER"
INTERMEDIATE = b"obviously fake intermediate; not a CA"
PROFILE = b"obviously fake profile; not CMS"
TARGET = ProvisioningTarget(BUNDLE, TEAM, TEAM, "Synthetic reuse", True)


def payload():
    return {"UUID": "11111111-2222-3333-4444-555555555555", "ApplicationIdentifierPrefix": [TEAM],
            "Platform": ["iOS"], "TeamIdentifier": [TEAM], "DeveloperCertificates": [LEAF],
            "CreationDate": CREATED.replace(tzinfo=None), "ExpirationDate": EXPIRES.replace(tzinfo=None),
            "Entitlements": TARGET.base_entitlements()}


@contextmanager
def active_guard():
    guard = DefaultCancellation(ProcessCleanupError, "synthetic guard restoration failed")
    try:
        guard.install()
        guard.activate()
        yield guard
    finally:
        guard.restore()


class ExistingProfilePolicyTests(unittest.TestCase):
    def compare(self, value=None, *, target=TARGET, leaf=LEAF, now=NOW):
        return existing._profile_comparison(target, leaf, payload() if value is None else value, now=now)

    def test_exact_profile_scope_is_only_a_pure_comparison(self):
        uuid, created, expires = self.compare()
        self.assertEqual((uuid, created, expires), (payload()["UUID"], CREATED, EXPIRES))
        self.assertNotIsInstance((uuid, created, expires), CertificateBinding)

    def test_exact_leaf_no_prefix_hash_only_or_multiple_certificates(self):
        for certificates in ([], [LEAF, INTERMEDIATE], [INTERMEDIATE], [LEAF + b"extra"],
                             [bytearray(LEAF)], (LEAF,), [hashlib.sha256(LEAF).digest()]):
            with self.subTest(certificates_type=type(certificates)):
                value = payload()
                value["DeveloperCertificates"] = certificates
                with self.assertRaises(ProvisioningError) as failure:
                    self.compare(value)
                self.assertEqual(failure.exception.code, "existing_profile_certificate_mismatch")

    def test_exact_team_application_platform_prefix_and_uuid_are_required(self):
        cases = [("TeamIdentifier", ["OTHERTEAM1"]), ("TeamIdentifier", (TEAM,)),
                 ("Platform", ["OSX"]), ("Platform", ["iOS", "OSX"]), ("Platform", "iOS"),
                 ("ApplicationIdentifierPrefix", ["OTHERTEAM1"]), ("UUID", "bad-uuid"),
                 ("UUID", payload()["UUID"] + "\0extra")]
        for key, changed in cases:
            with self.subTest(field=key):
                value = payload()
                value[key] = changed
                with self.assertRaises(ProvisioningError):
                    self.compare(value)
        for key, changed in (("application-identifier", TEAM + ".invalid.example.other"),
                             ("com.apple.developer.team-identifier", "OTHERTEAM1")):
            value = payload()
            value["Entitlements"][key] = changed
            with self.assertRaises(ProvisioningError):
                self.compare(value)

    def test_development_adhoc_enterprise_and_missing_appstore_grants_refuse(self):
        cases = [("ProvisionedDevices", ["synthetic-device"]), ("ProvisionsAllDevices", True)]
        for key, changed in cases:
            value = payload()
            value[key] = changed
            with self.subTest(field=key), self.assertRaises(ProvisioningError):
                self.compare(value)
        for key, changed in (("get-task-allow", True), ("get-task-allow", 0), ("beta-reports-active", False),
                             ("beta-reports-active", 1), ("beta-reports-active", None)):
            value = payload()
            value["Entitlements"][key] = changed
            with self.subTest(entitlement=key), self.assertRaises(ProvisioningError):
                self.compare(value)

    def test_typed_entitlement_claims_must_be_covered_by_same_profile(self):
        target = replace(TARGET, entitlements_json=b'{"keychain-access-groups":["TESTTEAM01.invalid.example.existing"]}')
        with self.assertRaises(ProvisioningError):
            self.compare(target=target)
        value = payload()
        value["Entitlements"]["keychain-access-groups"] = [TEAM + "." + BUNDLE]
        self.compare(value, target=target)
        value["Entitlements"]["keychain-access-groups"] = TEAM + "." + BUNDLE
        with self.assertRaises(ProvisioningError):
            self.compare(value, target=target)

    def test_existing_strict_profile_policy_does_not_support_legacy_seed_prefix(self):
        target = replace(TARGET, app_id_prefix="LEGACY0001")
        value = payload()
        value["ApplicationIdentifierPrefix"] = [target.app_id_prefix]
        value["Entitlements"]["application-identifier"] = target.app_id_prefix + "." + BUNDLE
        with self.assertRaises(ProvisioningError) as failure:
            self.compare(value, target=target)
        self.assertEqual(failure.exception.code, "legacy_app_id_prefix_unsupported")

    def test_validity_is_typed_current_half_open_including_fractional_endpoint(self):
        self.compare(now=CREATED)
        self.compare(now=EXPIRES - timedelta(microseconds=1))
        for at in (CREATED - timedelta(microseconds=1), EXPIRES, EXPIRES + timedelta(microseconds=1)):
            with self.subTest(at=at), self.assertRaises(ProvisioningError):
                self.compare(now=at)
        for key, changed in (("CreationDate", NOW.isoformat()), ("ExpirationDate", 1),
                             ("CreationDate", EXPIRES), ("ExpirationDate", CREATED)):
            value = payload()
            value[key] = changed
            with self.subTest(field=key), self.assertRaises(ProvisioningError):
                self.compare(value)


class ExistingProfileWiringTests(unittest.TestCase):
    def invoke(self, *, value=None, target=TARGET, leaf=LEAF, profile=PROFILE,
               native=None, dates=None, decode_error=None, consumer=True):
        self.deadline = InspectionDeadline()
        with active_guard() as guard:
            self.guard = guard
            with patch("mobile_release.ios_profiles.decode_authenticated_profile", return_value=payload() if value is None else value,
                       side_effect=decode_error) as decode, \
                    patch.object(existing, "_utc_now", side_effect=dates or [NOW, NOW]), \
                    patch.object(existing, "_verify_leaf_chain_in_worker", side_effect=native, return_value=NOW) as verify:
                self.decode, self.verify = decode, verify
                if not consumer:
                    return existing._inspect_existing_profile_in_worker(target, leaf, (INTERMEDIATE,), profile,
                        cancellation=guard, deadline=self.deadline)
                # A fake-call seam ONLY; this deliberately supplies NO original
                # evidence. The separate test below exercises the real refusal.
                with patch("mobile_release._profile_callers.consume_profile_evidence", return_value=None) as consume:
                    self.consume = consume
                    return existing._inspect_existing_profile_in_worker(target, leaf, (INTERMEDIATE,), profile,
                        cancellation=guard, deadline=self.deadline)

    def test_fake_call_wiring_borrows_exact_inputs_guard_deadline_and_keeps_scope_private(self):
        result = self.invoke()
        self.decode.assert_called_once()
        self.assertIs(self.decode.call_args.args[0], PROFILE)
        self.assertIs(self.decode.call_args.kwargs["deadline"], self.deadline)
        self.assertIs(self.decode.call_args.kwargs["cancellation"], self.guard)
        self.assertIs(self.consume.call_args.args[0], self.decode.call_args.kwargs["_evidence"])
        self.assertIsNone(self.consume.call_args.kwargs["primary"])
        self.assertEqual(self.verify.call_args.args, (LEAF, (INTERMEDIATE,)))
        self.assertIs(self.verify.call_args.kwargs["deadline"], self.deadline)
        self.assertIs(self.verify.call_args.kwargs["cancellation"], self.guard)
        self.assertIs(result.certificate_der, LEAF)
        self.assertIs(result.profile_bytes, PROFILE)
        self.assertIs(result.target, TARGET)
        self.assertEqual(result.certificate_sha256, hashlib.sha256(LEAF).hexdigest())
        self.assertEqual(result.profile_sha256, hashlib.sha256(PROFILE).hexdigest())
        self.assertEqual(result.profile_created_at, CREATED)
        self.assertEqual(result.profile_expires_at, EXPIRES)
        self.assertEqual(result.chain_checked_at, NOW)
        self.assertEqual(result.profile_checked_at, NOW)
        self.assertFalse(hasattr(result, "__dict__"))
        for field in ("key_ref", "ready", "credential_ready", "binding", "certificate_id", "action"):
            self.assertFalse(hasattr(result, field))
        with self.assertRaises(TypeError):
            json.dumps(result)
        with self.assertRaises(TypeError):
            pickle.dumps(result)
        self.assertNotIn("obviously fake", repr(result))

    def test_plain_decode_result_without_real_profile_producer_finality_refuses(self):
        with self.assertRaises(ProcessError) as failure:
            self.invoke(consumer=False)
        self.assertTrue(failure.exception.fatal)
        self.verify.assert_not_called()

    def test_both_profile_comparisons_borrow_original_deadline_without_renewal(self):
        from mobile_release import ios_entitlements

        with patch.object(ios_entitlements, "validate_profile_entitlements",
                          wraps=ios_entitlements.validate_profile_entitlements) as validate, \
                patch.object(ios_entitlements, "InspectionDeadline",
                             side_effect=AssertionError("inspection budget must not renew")) as renewed:
            self.invoke()
        self.assertEqual(validate.call_count, 2)
        for call in validate.call_args_list:
            self.assertIs(call.kwargs["deadline"], self.deadline)
        renewed.assert_not_called()

    def test_wrong_profile_scope_refuses_before_generic_chain_call(self):
        value = payload()
        value["TeamIdentifier"] = ["OTHERTEAM1"]
        with self.assertRaises(ProvisioningError):
            self.invoke(value=value)
        self.verify.assert_not_called()

    def test_chain_refusal_and_fatal_unknown_never_produce_comparison(self):
        for failure in (ProvisioningError("existing_chain_invalid"), ProcessError("synthetic unknown", contained=False)):
            with self.subTest(fatal=isinstance(failure, ProcessError)), self.assertRaises(type(failure)) as caught:
                self.invoke(native=failure)
            self.assertIs(caught.exception, failure)

    def test_profile_expiring_during_native_chain_check_refuses_afterward(self):
        with self.assertRaises(ProvisioningError) as failure:
            self.invoke(dates=[NOW, EXPIRES])
        self.assertEqual(failure.exception.code, "existing_profile_not_current")
        self.verify.assert_called_once()

    def test_conflicting_native_clock_cannot_be_relabelled_as_current_profile_check(self):
        for at in (NOW - timedelta(seconds=1), NOW + timedelta(seconds=1), None):
            with self.subTest(native_time=at), self.assertRaises(ProvisioningError) as failure:
                self.invoke(native=lambda *args, **kwargs: at)
            self.assertEqual(failure.exception.code, "existing_chain_clock_changed")

    def test_cancellation_or_shared_deadline_after_chain_never_returns_late_result(self):
        def cancelled(*args, **kwargs):
            kwargs["cancellation"].cancelled = True
            return NOW

        with self.assertRaises(KeyboardInterrupt):
            self.invoke(native=cancelled)

        def expired(*args, **kwargs):
            kwargs["deadline"]._expires_at = 0
            return NOW

        with self.assertRaises(ValidationError):
            self.invoke(native=expired)

    def test_first_decode_interruption_and_fatal_error_remain_nonresults(self):
        interruption = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt) as failure:
            self.invoke(decode_error=interruption, consumer=False)
        self.assertIs(failure.exception, interruption)
        self.verify.assert_not_called()
        fatal = ProcessError("synthetic profile lifetime unknown", contained=False)
        with self.assertRaises(ProcessError) as failure:
            self.invoke(decode_error=fatal, consumer=False)
        self.assertTrue(failure.exception.fatal)
        self.verify.assert_not_called()

    def test_invalid_inputs_and_legacy_scope_never_start_decode(self):
        for target, leaf, profile in ((replace(TARGET, app_id_prefix="LEGACY0001"), LEAF, PROFILE),
                                      (TARGET, b"", PROFILE), (TARGET, LEAF, b""),
                                      (TARGET, LEAF, bytearray(PROFILE)),
                                      (TARGET, LEAF, b"x" * (existing.MAX_PROFILE_BYTES + 1))):
            with self.subTest(profile_type=type(profile)), self.assertRaises(ProvisioningError):
                self.invoke(target=target, leaf=leaf, profile=profile)
            self.decode.assert_not_called()
            self.verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
