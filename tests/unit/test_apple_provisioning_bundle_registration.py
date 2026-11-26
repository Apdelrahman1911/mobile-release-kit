"""Pure/fake provider DATA only: no account, private key, native or IO authority."""
from __future__ import annotations

import base64
import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import unittest

from mobile_release import apple_provisioning_api as api
from mobile_release import apple_provisioning_bundle_registration as bundle
from mobile_release.apple_provisioning import (
    BUNDLE_ID_SCOPE, SIGNING_SCOPE, Observation, PendingMutation,
    ProvisioningContext, ProvisioningTarget, prepare,
)
from mobile_release.apple_provisioning_recovery import ProvisioningApproval, ProvisioningAttempt

NOW = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
CONTEXT = ProvisioningContext("synthetic-project", "synthetic-client", "synthetic-operation", 1,
                              "a" * 64, "synthetic-p8-record", 1, 1)
TARGET = ProvisioningTarget("invalid.example.registration", "TESTTEAM01", "TESTTEAM01", "Synthetic App", False)


def row(**attributes):
    return {"type": "bundleIds", "id": "synthetic-bundle", "attributes": {
        "identifier": TARGET.bundle_id, "platform": "IOS", "seedId": TARGET.team_id, **attributes}}


def page(rows=()):
    return {"data": list(rows), "links": {}, "meta": {"paging": {"total": len(rows)}}}


def response(value, status=200, settled=True):
    return api.AppleResponse(status, api.canonical(value), settled)


class Provider:
    def __init__(self, value=None):
        self.value = response(page()) if value is None else value
        self.created = response({"data": row()}, 201)
        self.calls = []
        self.current = True
        self.after_send = None

    def check(self, context):
        if not self.current or context != CONTEXT:
            raise ValueError("PRIVATE native selected account detail")

    def send(self, request):
        self.calls.append(request)
        result = self.value if request.method == "GET" else self.created
        if self.after_send:
            self.after_send()
        if isinstance(result, BaseException):
            raise result
        return result

    @property
    def writes(self):
        return [item for item in self.calls if item.method == "POST"]


class Owner:
    """Fake callback ordering, NOT native original settlement evidence."""
    def __init__(self):
        self.records = []
        self.current = self.settled = True
        self.lose_ack = False
        self.after_persist = None

    def authorize(self, plan, approval):
        if not self.current:
            raise ValueError("PRIVATE lease detail")

    def persist(self, record):
        self.records.append(record)
        if self.after_persist:
            self.after_persist()
        if self.lose_ack:
            raise OSError("PRIVATE journal descriptor")

    def transport_settled(self, record):
        return self.settled

    def reconciliation_current(self, plan, record):
        return self.current


def observed(provider, *, target=TARGET, now=NOW):
    return bundle.observe_bundle(CONTEXT, target, provider, now=now)


def prepared(provider=None, *, target=TARGET, pending=()):
    provider = Provider() if provider is None else provider
    before = observed(provider, target=target)
    return bundle.prepare_bundle(CONTEXT, target, before, pending=pending, now=NOW), before, provider


def approval(plan):
    return ProvisioningApproval(plan.context, plan.sha256, plan.action)


def frame(request, *, body=None, status=200, failure=None, ack=None):
    body = api.canonical(page()) if body is None else body
    return {"schemaVersion": 1, "contextSha256": "b" * 64, "bundleId": TARGET.bundle_id,
            "operationId": CONTEXT.operation_id, "requestSha256": api.request_sha256(request), "ackSha256": ack,
            "response": {"status": status, "bodyBase64": None if failure else base64.b64encode(body).decode(), "failure": failure}}


def decode(value, request=None, *, ack=None, settled=True):
    request = api.list_bundle_ids(TARGET.bundle_id) if request is None else request
    return bundle.response_from_frame(value if type(value) is bytes else api.canonical(value),
        context_sha256="b" * 64, operation_id=CONTEXT.operation_id, target=TARGET, request=request,
        ack_sha256=ack, settled=settled)


class BundleRegistrationScopeTests(unittest.TestCase):
    def test_single_get_reuses_existing_identity_without_signing_claim(self):
        for platform in ("IOS", "UNIVERSAL"):
            plan, before, provider = prepared(Provider(response(page([row(platform=platform)]))))
            self.assertEqual(plan.action, "reuse_bundle_id")
            self.assertIsNone(plan.request)
            self.assertEqual(provider.calls, [api.list_bundle_ids(TARGET.bundle_id)])
            self.assertEqual(before.scope, BUNDLE_ID_SCOPE)
            self.assertFalse(before.summary()["credentialReady"])
            self.assertIsNone(plan.binding)
            self.assertEqual(before.certificates, ())

    def test_empty_read_needs_explicit_new_application_not_inferred_continuity(self):
        plan, _, provider = prepared()
        self.assertEqual(plan.request, api.register_bundle_id(TARGET.bundle_id, TARGET.display_name))
        self.assertEqual(plan.action, "register_bundle_id")
        old, _, _ = prepared(target=replace(TARGET, existing_application=True))
        self.assertEqual(old.action, "blocked")
        self.assertEqual(old.reason, "existing_application_identity_missing")
        self.assertFalse(provider.writes)

    def test_scope_is_hashed_and_never_empty_full_signing_inventory(self):
        plan, before, _ = prepared()
        full = replace(before, scope=SIGNING_SCOPE)
        self.assertNotEqual(before.sha256, full.sha256)
        with self.assertRaises(api.ProvisioningError):
            prepare(CONTEXT, TARGET, before, bindings=(), csr=None, pending=(), now=NOW)
        with self.assertRaises(api.ProvisioningError):
            bundle.prepare_bundle(CONTEXT, TARGET, full, pending=(), now=NOW)
        with self.assertRaises(api.ProvisioningError):
            Observation(CONTEXT, TARGET.bundle_id, NOW, True, "observed", certificates=(object(),), scope=BUNDLE_ID_SCOPE)
        with self.assertRaises(api.ProvisioningError):
            bundle.prepare_bundle(CONTEXT, replace(TARGET, entitlements_json=b'{"get-task-allow":false}'), before, pending=(), now=NOW)
        self.assertIsNone(plan.csr)

    def test_partial_sparse_foreign_or_paginated_page_never_authorizes_create(self):
        mutations = [lambda p: p.pop("meta"), lambda p: p.pop("links"), lambda p: p.update(included=[]),
            lambda p: p["meta"]["paging"].update(total=True), lambda p: p["meta"]["paging"].update(total=2),
            lambda p: p["links"].update(next="https://foreign.invalid/v1/bundleIds"),
            lambda p: p["links"].update(next="https://api.appstoreconnect.apple.com/v1/bundleIds?cursor=next"),
            lambda p: p["data"][0]["attributes"].update(profileContent="PRIVATE"),
            lambda p: p["data"][0]["attributes"].update(teamId=TARGET.team_id),
            lambda p: p["data"][0]["attributes"].update(identifier="invalid.example.other"),
            lambda p: p["data"][0]["attributes"].update(platform="MAC_OS")]
        for mutate in mutations:
            value = page([row()]); mutate(value)
            plan, before, provider = prepared(Provider(response(value)))
            self.assertFalse(before.available)
            self.assertEqual(plan.action, "blocked")
            self.assertEqual(len(provider.calls), 1)
        for rows in ([row(), row()], [row(), {**row(), "id": "other"}], [row()] * 201):
            self.assertFalse(observed(Provider(response(page(rows)))).available)

    def test_denied_error_wrong_success_status_and_unsettled_never_mean_absent(self):
        for status in (201, 204, 301, 400, 401, 403, 404, 409, 429, 500):
            plan, before, provider = prepared(Provider(response(page(), status)))
            self.assertFalse(before.available)
            self.assertEqual(plan.action, "blocked")
            self.assertEqual(len(provider.calls), 1)
            if status in (401, 403):
                self.assertEqual(before.reason, "account_access_denied")
        self.assertFalse(observed(Provider(response(page(), settled=False))).available)
        self.assertFalse(observed(Provider(response(page(), settled=1))).available)

    def test_raw_duplicate_members_survive_sdk_normalization_and_refuse(self):
        raw = b'{"data":[{"hidden":"PRIVATE"}],"data":[],"links":{},"meta":{"paging":{"total":0}}}'
        self.assertEqual(json.loads(raw)["data"], [])
        provider = Provider(api.AppleResponse(200, raw, True))
        plan, before, _ = prepared(provider)
        self.assertFalse(before.available)
        self.assertEqual(plan.action, "blocked")

    def test_original_currentness_both_sides_and_interruptions_not_swallowed(self):
        provider = Provider(); provider.current = False
        self.assertFalse(observed(provider).available)
        self.assertFalse(provider.calls)
        provider = Provider(); provider.after_send = lambda: setattr(provider, "current", False)
        self.assertFalse(observed(provider).available)
        self.assertEqual(len(provider.calls), 1)
        with self.assertRaises(KeyboardInterrupt):
            observed(Provider(KeyboardInterrupt()))
        result = observed(Provider(OSError("PRIVATE account URL")))
        self.assertNotIn("PRIVATE", json.dumps(result.summary()))

    def test_native_pending_axis_is_account_wide_even_after_helper_terminal(self):
        for status in ("succeeded", "failed", "cancelled", "unknown", "running"):
            for native in ("pending", "unknown"):
                pending = PendingMutation(CONTEXT.account_ref, "other-project-operation", "register_bundle_id", status, native)
                plan, _, _ = prepared(pending=(pending,))
                self.assertEqual(plan.action, "reconcile")
        known = PendingMutation(CONTEXT.account_ref, "old", "register_bundle_id", "failed", "known")
        self.assertEqual(prepared(pending=(known,))[0].action, "register_bundle_id")
        self.assertEqual(prepared(pending=(replace(known, status="unknown"),))[0].action, "reconcile")
        self.assertEqual(prepared(pending=(replace(known, account_ref="other", native_settlement="unknown"),))[0].action,
                         "register_bundle_id")
        with self.assertRaises(api.ProvisioningError):
            prepared(pending=(known,) * 33)
        with self.assertRaises(api.ProvisioningError):
            prepared(pending=None)

    def test_expiry_and_selected_prefix_are_only_comparison_inputs(self):
        _, before, _ = prepared()
        for now in (NOW - timedelta(microseconds=1), NOW + timedelta(minutes=5)):
            with self.assertRaises(api.ProvisioningError):
                bundle.prepare_bundle(CONTEXT, TARGET, before, pending=(), now=now)
        self.assertEqual(prepared(target=replace(TARGET, app_id_prefix="OTHERPRE01"))[0].action, "manual")
        self.assertEqual(prepared(Provider(response(page([row(seedId="OTHERPRE01")]))))[0].action, "blocked")


class BundleRegistrationAttemptTests(unittest.TestCase):
    def test_exact_empty_before_and_selected_request_required_before_any_post(self):
        plan, before, provider = prepared()
        changes = [dict(request=api.register_bundle_id("invalid.example.other", TARGET.display_name)),
                   dict(request=api.register_bundle_id(TARGET.bundle_id, "Different name")),
                   dict(bundle=api.BundleId.parse(row()))]
        for change in changes:
            with self.assertRaises(api.ProvisioningError):
                ProvisioningAttempt(replace(plan, **change), before)
        found = replace(before, bundles=(api.BundleId.parse(row()),))
        with self.assertRaises(api.ProvisioningError):
            ProvisioningAttempt(replace(plan, observation_sha256=found.sha256), found)
        self.assertFalse(provider.writes)

    def test_first_durable_arm_then_one_post_readback_no_native_settlement(self):
        plan, before, provider = prepared()
        owner, attempt = Owner(), ProvisioningAttempt(plan, before)
        provider.after_send = lambda: self.assertTrue(owner.records[0].possible_send)
        result = attempt.execute(approval(plan), before, provider, owner, now=NOW)
        self.assertEqual(result.reason, "readback_required")
        provider.value = response(page([row()]))
        readback = observed(provider, now=NOW + timedelta(seconds=1))
        result = attempt.reconcile(readback, owner, bindings=(), now=NOW + timedelta(seconds=1))
        self.assertEqual(result.status, "succeeded")
        self.assertTrue(result.pending().unresolved)  # Parent joins are still owed.
        self.assertFalse(result.summary()["credentialReady"])
        self.assertFalse(result.summary()["retryAllowed"])
        self.assertEqual(len(provider.writes), 1)

    def test_lost_pending_ack_is_zero_post_and_never_replays_original(self):
        plan, before, provider = prepared()
        owner, attempt = Owner(), ProvisioningAttempt(plan, before)
        owner.lose_ack = True
        result = attempt.execute(approval(plan), before, provider, owner, now=NOW)
        self.assertTrue(owner.records[0].possible_send)
        self.assertFalse(result.possible_send)
        self.assertTrue(result.pending().unresolved)
        self.assertEqual(result.reason, "journal_settlement_required")
        with self.assertRaises(api.ProvisioningError):
            attempt.execute(approval(plan), before, provider, owner, now=NOW)
        self.assertFalse(provider.writes)

    def test_change_or_cancel_after_ack_vetoes_send_without_disarming_journal(self):
        for cancel in (False, True):
            plan, before, provider = prepared()
            owner, attempt = Owner(), ProvisioningAttempt(plan, before)
            owner.after_persist = attempt.request_cancel if cancel else lambda: setattr(owner, "current", False)
            result = attempt.execute(approval(plan), before, provider, owner, now=NOW)
            self.assertIn(result.status, ("failed", "cancelled"))
            self.assertTrue(owner.records[0].possible_send)
            self.assertFalse(provider.writes)
            self.assertTrue(result.pending().unresolved)

    def test_unknown_post_and_empty_or_matching_readback_never_retry_or_attribute(self):
        for rows in ([], [row()]):
            plan, before, provider = prepared()
            owner, attempt = Owner(), ProvisioningAttempt(plan, before)
            provider.created = TimeoutError("PRIVATE URL")
            self.assertEqual(attempt.execute(approval(plan), before, provider, owner, now=NOW).status, "unknown")
            provider.value = response(page(rows))
            result = attempt.reconcile(observed(provider), owner, bindings=(), now=NOW)
            self.assertEqual(result.reason, "resource_found_review_required" if rows else "provider_outcome_still_unknown")
            with self.assertRaises(api.ProvisioningError):
                attempt.execute(approval(plan), before, provider, owner, now=NOW)
            self.assertEqual(len(provider.writes), 1)

    def test_rejected_write_or_wrong_create_status_never_get_another_attempt(self):
        for status in (200, 400, 401, 403, 404, 409, 422, 429, 500):
            plan, before, provider = prepared()
            provider.created = response({"data": row()}, status)
            owner, attempt = Owner(), ProvisioningAttempt(plan, before)
            result = attempt.execute(approval(plan), before, provider, owner, now=NOW)
            self.assertIn(result.status, ("failed", "unknown"))
            self.assertTrue(result.pending().unresolved)
            with self.assertRaises(api.ProvisioningError):
                attempt.execute(approval(plan), before, provider, owner, now=NOW)
            self.assertEqual(len(provider.writes), 1)

    def test_different_scope_or_readback_identity_cannot_confirm(self):
        plan, before, provider = prepared()
        owner, attempt = Owner(), ProvisioningAttempt(plan, before)
        attempt.execute(approval(plan), before, provider, owner, now=NOW)
        provider.value = response(page([{**row(), "id": "different-resource"}]))
        readback = observed(provider)
        with self.assertRaises(api.ProvisioningError):
            attempt.reconcile(replace(readback, scope=SIGNING_SCOPE), owner, bindings=(), now=NOW)
        self.assertEqual(attempt.reconcile(readback, owner, bindings=(), now=NOW).reason, "response_readback_disagrees")
        self.assertEqual(len(provider.writes), 1)


class BundleRegistrationFrameTests(unittest.TestCase):
    def test_exact_read_and_write_scope_raw_bytes_and_original_settlement_input(self):
        read = api.list_bundle_ids(TARGET.bundle_id)
        self.assertFalse(decode(frame(read), settled=False).settled)
        write = api.register_bundle_id(TARGET.bundle_id, TARGET.display_name)
        body = b'{"data":{"before":"PRIVATE"},"data":{}}'
        result = decode(frame(write, body=body, status=201, ack="c" * 64), write, ack="c" * 64)
        self.assertEqual(result.body, body)
        with self.assertRaises(api.ProvisioningError):
            api.document(result.body)

    def test_context_request_operation_ack_and_forged_finality_rejected(self):
        request = api.list_bundle_ids(TARGET.bundle_id)
        for field, value in (("contextSha256", "c" * 64), ("operationId", "other"), ("bundleId", "invalid.example.other"),
                             ("requestSha256", "d" * 64), ("ackSha256", "e" * 64), ("schemaVersion", True), ("settled", True)):
            wrong = frame(request); wrong[field] = value
            with self.assertRaises(api.ProvisioningError): decode(wrong)
        write = api.register_bundle_id(TARGET.bundle_id, TARGET.display_name)
        with self.assertRaises(api.ProvisioningError): decode(frame(write), write)

    def test_strict_bounded_raw_envelope_status_and_base64(self):
        request = api.list_bundle_ids(TARGET.bundle_id)
        good = frame(request)
        for field, value in (("status", True), ("bodyBase64", "e30=\n"), ("bodyBase64", "!!!"),
                             ("bodyBase64", base64.b64encode(b"x" * (bundle.RAW_LIMIT + 1)).decode()),
                             ("failure", "PRIVATE details"), ("settled", True)):
            wrong = copy.deepcopy(good); wrong["response"][field] = value
            with self.assertRaises(api.ProvisioningError): decode(wrong)
        for value in (b"", b" " * (bundle.FRAME_LIMIT + 1), api.canonical(good).replace(b'"schemaVersion":1', b'"schemaVersion":0,"schemaVersion":1')):
            with self.assertRaises(api.ProvisioningError): decode(value)

    def test_error_frames_preserve_known_rejection_not_absence(self):
        request = api.list_bundle_ids(TARGET.bundle_id)
        for status in (400, 401, 403, 404, 405, 409, 422):
            result = decode(frame(request, status=status, failure="provider_request_unconfirmed"))
            self.assertEqual(result.status, status)
            self.assertFalse(observed(Provider(result)).available)
        for status in (None, 200, 201, 429, 500):
            with self.assertRaises(api.ProvisioningError):
                decode(frame(request, status=status, failure="provider_request_unconfirmed"))


if __name__ == "__main__":
    unittest.main()
