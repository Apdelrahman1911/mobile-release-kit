"""Synthetic provider/DATA cases, NOT a P12, chain, CMS or native pass.

Uses the existing deliberately noncryptographic fixture and original one-send
engine. No network, native process, real credential, vault or profile writes.
"""
from __future__ import annotations

import base64
import copy
import unittest
from dataclasses import replace
from datetime import timedelta
from unittest.mock import Mock, patch

from mobile_release import apple_provisioning as core
from mobile_release import apple_provisioning_api as api
from mobile_release import apple_provisioning_signing as signing
from mobile_release.apple_provisioning_recovery import ProvisioningAttempt
from test_apple_provisioning import (
    BUNDLE, CERT_BYTES, CONTEXT, CREATED, EXPIRES, KEY, NOW, PROFILE_BYTES, TARGET,
    FakeOwner, FakeProvider, approval, binding, bundle, certificate, date, profile, response,
)


def complete_profile(identity="profile-one", **kwargs):
    value = profile(identity, **kwargs)
    value["relationships"]["certificates"]["meta"] = {"paging": {"total": 1}}
    return value


def page(rows, *, included=None, total=None, next_url=None):
    result = api.document(response(rows, total=total, next_url=next_url).body)
    if included is not None:
        result["included"] = included
    return api.AppleResponse(200, api.canonical(result), True)


def included_certificate(identity="certificate-one"):
    value = certificate(identity)
    del value["attributes"]["certificateContent"]
    return value


def provider(*, profiles=None, certificates=None, bundles=None):
    result = FakeProvider(bundles=bundles, certificates=certificates, profiles=[])
    rows = [complete_profile()] if profiles is None else profiles
    result.responses["list_profiles"] = page(rows, included=[bundle(), included_certificate()] if rows else [])
    return result


def inventory(source):
    return signing.observe_signing(CONTEXT, TARGET, source, now=NOW)


def plan_for(source, **options):
    observed = inventory(source)
    return signing.prepare_existing_profile(CONTEXT, TARGET, observed, bindings=(binding(),),
        selected_key=KEY, pending=(), now=NOW, **options), observed


def created_attempt():
    source = provider(profiles=[])
    source.mutation = response({"type": "profiles", "id": "profile-created"}, status=201)
    plan, observed = plan_for(source)
    return source, signing.ProfileCreationAttempt(plan, observed), FakeOwner(), observed


def downloaded(identity="profile-created", **kwargs):
    value = complete_profile(identity, content=True, name=signing.profile_name(CONTEXT.operation_id), **kwargs)
    return value, response(value)


class SigningInventoryTests(unittest.TestCase):
    def test_complete_existing_profile_reused_no_post_or_certificate_creation(self):
        source = provider()
        plan, observed = plan_for(source)
        self.assertTrue(observed.observation.available)
        self.assertTrue(observed.profile_relationships_complete)
        self.assertEqual(plan.action, "download_profile")
        self.assertEqual([item.kind for item in source.calls], ["list_bundle_ids", "list_certificates", "list_profiles"])
        self.assertEqual(source.writes, [])
        self.assertFalse(plan.summary()["credentialReady"])

    def test_empty_complete_profile_inventory_only_proposes_one_explicit_post(self):
        source = provider(profiles=[])
        plan, observed = plan_for(source)
        self.assertEqual(plan.action, "create_profile")
        self.assertTrue(observed.profile_relationships_complete)
        self.assertTrue(plan.summary()["approvalRequired"])
        self.assertEqual(api.document(plan.request.body)["data"]["attributes"]["name"], signing.profile_name(CONTEXT.operation_id))
        self.assertEqual(source.writes, [])

    def test_no_key_or_missing_bundle_cannot_enter_csr_or_certificate_issuance(self):
        source = provider(certificates=[], profiles=[])
        observed = inventory(source)
        plan = signing.prepare_existing_profile(CONTEXT, TARGET, observed, bindings=(), selected_key=KEY, pending=(), now=NOW)
        self.assertEqual((plan.action, plan.reason, plan.request), ("manual", "existing_distribution_identity_required", None))
        target = replace(TARGET, existing_application=False)
        source = provider(bundles=[], profiles=[])
        observed = signing.observe_signing(CONTEXT, target, source, now=NOW)
        plan = signing.prepare_existing_profile(CONTEXT, target, observed, bindings=(binding(),), selected_key=KEY, pending=(), now=NOW)
        self.assertEqual((plan.action, plan.reason, plan.request), ("manual", "bundle_registration_required", None))

    def test_denial_missing_total_and_partial_page_never_imply_no_profile(self):
        for changed in (api.AppleResponse(403, b"{}", True), api.AppleResponse(200, b'{"data":[],"links":{}}', True),
                        page([], total=1), api.AppleResponse(200, b'{"data":[],"data":[],"links":{},"meta":{"paging":{"total":0}}}', True)):
            with self.subTest(response=changed.status):
                source = provider(profiles=[])
                source.responses["list_profiles"] = changed
                plan, observed = plan_for(source)
                self.assertFalse(observed.observation.available)
                self.assertEqual(observed.observation.profiles, ())
                self.assertEqual(plan.action, "blocked")
                self.assertIsNone(plan.request)
                self.assertEqual(source.writes, [])

    def test_missing_relationship_total_or_referent_can_nominate_reuse_not_creation(self):
        for missing in ("total", "included"):
            source = provider()
            value = api.document(source.responses["list_profiles"].body)
            if missing == "total":
                del value["data"][0]["relationships"]["certificates"]["meta"]
            else:
                value["included"] = []
            source.responses["list_profiles"] = api.AppleResponse(200, api.canonical(value), True)
            plan, observed = plan_for(source)
            self.assertTrue(observed.observation.available)
            self.assertFalse(observed.profile_relationships_complete)
            self.assertEqual(plan.action, "download_profile")
            value["data"][0]["attributes"]["profileState"] = "INVALID"
            source.responses["list_profiles"] = api.AppleResponse(200, api.canonical(value), True)
            plan, observed = plan_for(source)
            self.assertEqual((plan.action, plan.reason), ("blocked", "profile_relationship_evidence_incomplete"))
            self.assertIsNone(plan.request)

    def test_sparse_content_rejected_before_download_parser_even_for_unrelated_row(self):
        for where, key in (("data", "profileContent"), ("included", "certificateContent")):
            source = provider()
            value = api.document(source.responses["list_profiles"].body)
            row = value[where][0 if where == "data" else 1]
            row["attributes"][key] = base64.b64encode(b"NOT_SIGNING_MATERIAL").decode("ascii")
            source.responses["list_profiles"] = api.AppleResponse(200, api.canonical(value), True)
            with patch.object(api.Profile, "parse", side_effect=AssertionError("must not decode")) as parse:
                observed = inventory(source)
            self.assertFalse(observed.observation.available)
            parse.assert_not_called()

    def test_contradictory_team_certificate_and_missing_linkage_are_unavailable(self):
        changes = [lambda p: p["included"][0]["attributes"].update(seedId="OTHERTEAM0"),
                   lambda p: p["included"][1]["attributes"].update(expirationDate=date(EXPIRES + timedelta(days=1))),
                   lambda p: p["data"][0]["relationships"]["certificates"].pop("data"),
                   lambda p: p["data"][0]["relationships"]["certificates"].update(links={"next": "https://foreign.invalid"})]
        for change in changes:
            source = provider()
            value = api.document(source.responses["list_profiles"].body)
            change(value)
            source.responses["list_profiles"] = api.AppleResponse(200, api.canonical(value), True)
            self.assertFalse(inventory(source).observation.available)

    def test_only_two_pages_exact_origin_query_and_no_third_provider_call(self):
        initial = api.list_certificates()
        next_one = replace(initial, query=initial.query + (("cursor", "page-two"),))
        next_two = replace(initial, query=initial.query + (("cursor", "page-three"),))
        source = provider(profiles=[])
        replies = [page([certificate()], total=3, next_url=next_one.url),
                   page([certificate("certificate-two")], total=3, next_url=next_two.url)]
        original = source.send
        def send(request):
            if request.kind == "list_certificates":
                source.calls.append(request)
                return replies.pop(0)
            return original(request)
        source.send = send
        observed = inventory(source)
        self.assertFalse(observed.observation.available)
        self.assertEqual([call.kind for call in source.calls].count("list_certificates"), 2)
        self.assertNotIn("list_profiles", [call.kind for call in source.calls])
        for unsafe in (next_one.url.replace("api.appstoreconnect.apple.com", "foreign.invalid"),
                       next_one.url.replace("/v1/certificates", "/v1/profiles"), next_one.url + "&limit=200"):
            source = provider(profiles=[])
            source.responses["list_certificates"] = page([certificate()], total=2, next_url=unsafe)
            self.assertFalse(inventory(source).observation.available)
            self.assertEqual([call.kind for call in source.calls].count("list_certificates"), 1)

    def test_second_page_duplicate_and_total_drift_cannot_be_complete(self):
        initial = api.list_certificates()
        next_one = replace(initial, query=initial.query + (("cursor", "second"),))
        for second in (page([certificate()], total=2), page([certificate("second")], total=3)):
            source = provider(profiles=[])
            replies = [page([certificate()], total=2, next_url=next_one.url), second]
            original = source.send
            def send(request):
                if request.kind == "list_certificates":
                    source.calls.append(request)
                    return replies.pop(0)
                return original(request)
            source.send = send
            self.assertFalse(inventory(source).observation.available)

    def test_original_currentness_interrupt_and_per_page_limit(self):
        source = provider()
        source.callback = lambda: setattr(source, "current", False)
        self.assertFalse(inventory(source).observation.available)
        self.assertEqual(len(source.calls), 1)
        source = provider()
        source.responses["list_certificates"] = api.AppleResponse(200, b" " * (signing.PAGE_LIMIT + 1), True)
        self.assertFalse(inventory(source).observation.available)
        source = provider()
        source.responses["list_certificates"] = KeyboardInterrupt("synthetic interruption")
        with self.assertRaises(KeyboardInterrupt):
            inventory(source)

    def test_account_unknown_veto_current_key_and_expiry_remain_core_checks(self):
        source = provider(profiles=[])
        observed = inventory(source)
        unresolved = core.PendingMutation(CONTEXT.account_ref, "other-project-op", "profile-save", "succeeded", "unknown")
        plan = signing.prepare_existing_profile(CONTEXT, TARGET, observed, bindings=(binding(),), selected_key=KEY,
                                               pending=(unresolved,), now=NOW)
        self.assertEqual(plan.action, "reconcile")
        other_key = replace(KEY, revision_counter=2)
        plan = signing.prepare_existing_profile(CONTEXT, TARGET, observed, bindings=(binding(),), selected_key=other_key,
                                               pending=(), now=NOW)
        self.assertEqual(plan.action, "recover_existing_key")
        with self.assertRaises(api.ProvisioningError):
            signing.prepare_existing_profile(CONTEXT, TARGET, observed, bindings=(binding(),), selected_key=KEY,
                                             pending=(), now=NOW + timedelta(minutes=5))


class SigningReceiptTests(unittest.TestCase):
    def test_sparse_201_retains_id_then_exact_get_not_post_response_success(self):
        source, attempt, owner, observed = created_attempt()
        result = attempt.execute(approval(attempt.plan), observed.observation, source, owner, now=NOW)
        self.assertEqual((result.status, result.reason), ("recovery_required", "readback_required"))
        self.assertEqual(result.response_resource_id, "profile-created")
        self.assertTrue(owner.records[0].possible_send)
        self.assertEqual(owner.records[0].status, "running")
        row, download = downloaded()
        plan = signing.created_download_plan(attempt, download, now=NOW)
        self.assertEqual(plan.action, "download_profile")
        self.assertNotEqual(api.resource_sha256(plan.profile), attempt.receipt.sha256)
        after = replace(observed.observation, profiles=(api.Profile.parse(row, require_content=True),))
        result = attempt.reconcile(after, owner, bindings=(binding(),), now=NOW)
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(len(source.writes), 1)
        with self.assertRaises(api.ProvisioningError):
            attempt.execute(approval(attempt.plan), observed.observation, source, owner, now=NOW)
        self.assertEqual(len(source.writes), 1)

    def test_no_pending_ack_no_post_and_sent_failure_never_replays(self):
        source, attempt, owner, observed = created_attempt()
        owner.fail_persist = True
        result = attempt.execute(approval(attempt.plan), observed.observation, source, owner, now=NOW)
        self.assertEqual(result.reason, "journal_settlement_required")
        self.assertEqual(source.writes, [])
        source, attempt, owner, observed = created_attempt()
        source.mutation = OSError("PRIVATE_PROVIDER_DETAIL")
        result = attempt.execute(approval(attempt.plan), observed.observation, source, owner, now=NOW)
        self.assertEqual(result.status, "unknown")
        self.assertTrue(result.possible_send)
        with self.assertRaises(api.ProvisioningError):
            attempt.execute(approval(attempt.plan), observed.observation, source, owner, now=NOW)
        self.assertEqual(len(source.writes), 1)
        self.assertNotIn("PRIVATE_PROVIDER_DETAIL", str(result.summary()))

    def test_sparse_wrong_identity_and_conflicting_supplied_fields_never_nominate_get(self):
        changes = [lambda p: p.update(type="certificates"), lambda p: p.update(id="bad/id"),
                   lambda p: p.update(attributes={"name": "different profile"}),
                   lambda p: p.update(attributes={"profileType": "IOS_APP_ADHOC"}),
                   lambda p: p.update(relationships={"certificates": {"data": [{"type": "certificates", "id": "other"}]}})]
        for change in changes:
            source, attempt, owner, observed = created_attempt()
            raw = {"type": "profiles", "id": "profile-created"}
            change(raw)
            source.mutation = response(raw, status=201)
            result = attempt.execute(approval(attempt.plan), observed.observation, source, owner, now=NOW)
            self.assertEqual(result.status, "unknown")
            self.assertIsNone(result.response_resource_id)
            self.assertIsNone(attempt.receipt)
            self.assertEqual(len(source.writes), 1)

    def test_present_201_uuid_dates_and_content_must_agree_with_exact_get(self):
        for name, value in (("uuid", "99999999-2222-3333-4444-555555555555"),
                            ("expirationDate", date(EXPIRES + timedelta(days=1))),
                            ("profileContent", base64.b64encode(b"synthetic different content").decode("ascii"))):
            source, attempt, owner, observed = created_attempt()
            source.mutation = response({"type": "profiles", "id": "profile-created", "attributes": {name: value}}, status=201)
            attempt.execute(approval(attempt.plan), observed.observation, source, owner, now=NOW)
            _, download = downloaded()
            with self.assertRaises(api.ProvisioningError):
                signing.created_download_plan(attempt, download, now=NOW)
            self.assertEqual(len(source.writes), 1)

    def test_get_wrong_leaf_relationship_type_length_or_status_is_not_profile_authentication(self):
        source, attempt, owner, observed = created_attempt()
        attempt.execute(approval(attempt.plan), observed.observation, source, owner, now=NOW)
        for change in (lambda p: p["relationships"]["certificates"]["data"][0].update(id="other-cert"),
                       lambda p: p["attributes"].update(profileType="IOS_APP_ADHOC"),
                       lambda p: p["attributes"].update(profileContent=base64.b64encode(b"x" * (signing.PROFILE_LIMIT + 1)).decode("ascii"))):
            row, _ = downloaded()
            change(row)
            with self.assertRaises(api.ProvisioningError):
                signing.created_download_plan(attempt, response(row), now=NOW)
        _, download = downloaded()
        for bad in (replace(download, settled=False), replace(download, status=201), replace(download, status=404)):
            with self.assertRaises(api.ProvisioningError):
                signing.created_download_plan(attempt, bad, now=NOW)

    def test_current_owner_loss_and_cancel_preserve_possible_send_not_assignment(self):
        source, attempt, owner, observed = created_attempt()
        attempt.execute(approval(attempt.plan), observed.observation, source, owner, now=NOW)
        row, _ = downloaded()
        after = replace(observed.observation, profiles=(api.Profile.parse(row, require_content=True),))
        owner.settled = False
        result = attempt.reconcile(after, owner, bindings=(binding(),), now=NOW)
        self.assertEqual(result.reason, "original_transport_unsettled")
        self.assertTrue(result.possible_send)
        attempt.request_cancel()
        self.assertTrue(attempt.record.cancel_requested)
        self.assertEqual(len(source.writes), 1)
        with self.assertRaises(api.ProvisioningError):
            signing.ProfileCreationAttempt.resume(attempt.plan, observed.observation, attempt.record)

    def test_old_full_profile_attempt_still_uses_full_resource_hash(self):
        source, proposed, owner, observed = created_attempt()
        row, _ = downloaded()
        source.mutation = response(row, status=201)
        old = ProvisioningAttempt(proposed.plan, observed.observation)
        result = old.execute(approval(old.plan), observed.observation, source, owner, now=NOW)
        self.assertEqual(result.response_resource_sha256, api.resource_sha256(api.Profile.parse(row)))
        changed = copy.deepcopy(row)
        changed["attributes"]["uuid"] = "99999999-2222-3333-4444-555555555555"
        after = replace(observed.observation, profiles=(api.Profile.parse(changed),))
        self.assertEqual(old.reconcile(after, owner, bindings=(binding(),), now=NOW).reason, "response_readback_disagrees")


class SigningFrameTests(unittest.TestCase):
    def frame(self, request, *, body=b'{"data":[]}', status=200, ack=None):
        return api.canonical({"schemaVersion": 1, "scope": signing.SCOPE, "contextSha256": "a" * 64,
            "bundleId": BUNDLE, "operationId": CONTEXT.operation_id, "requestSha256": api.request_sha256(request),
            "ackSha256": ack, "response": {"status": status, "bodyBase64": base64.b64encode(body).decode("ascii"), "failure": None}})

    def decode(self, raw, request, ack=None, settled=True):
        return signing.response_from_frame(raw, context_sha256="a" * 64, operation_id=CONTEXT.operation_id,
                                          target=TARGET, request=request, ack_sha256=ack, settled=settled)

    def test_exact_frame_preserves_duplicate_raw_json_not_sdk_normalization(self):
        request = api.list_profiles()
        raw = b'{"data":["conflict"],"data":[]}'
        value = self.decode(self.frame(request, body=raw), request, settled=False)
        self.assertFalse(value.settled)
        self.assertEqual(value.body, raw)
        with self.assertRaises(api.ProvisioningError):
            api.document(value.body)

    def test_cross_scope_request_context_operation_ack_and_caps_are_closed(self):
        request = api.list_profiles()
        for key, value in (("scope", "bundle-id-only"), ("requestSha256", "b" * 64), ("contextSha256", "b" * 64),
                           ("operationId", "other"), ("bundleId", "com.example.other"), ("settled", True), ("ackSha256", "b" * 64)):
            raw = api.document(self.frame(request)); raw[key] = value
            with self.assertRaises(api.ProvisioningError):
                self.decode(api.canonical(raw), request)
        with self.assertRaises(api.ProvisioningError):
            self.decode(self.frame(request, body=b" " * (signing.PAGE_LIMIT + 1)), request)
        for foreign in (api.register_bundle_id(BUNDLE, "Fixture"), api.create_certificate(b"-----BEGIN CERTIFICATE REQUEST-----\neA==\n-----END CERTIFICATE REQUEST-----\n")):
            with self.assertRaises(api.ProvisioningError):
                self.decode(self.frame(foreign, ack="a" * 64), foreign, ack="a" * 64)
        post = api.create_profile(signing.profile_name(CONTEXT.operation_id), "bundle-one", "certificate-one")
        self.assertEqual(self.decode(self.frame(post, ack="b" * 64, status=201), post, ack="b" * 64).status, 201)

    def test_known_denial_no_raw_body_and_unknown_errors_never_empty_success(self):
        request = api.list_profiles()
        raw = api.document(self.frame(request))
        for status in (401, 403, 404, 409, 429, None):
            raw["response"] = {"status": status, "bodyBase64": None, "failure": "provider_request_unconfirmed"}
            if status in {401, 403, 404, 409}:
                value = self.decode(api.canonical(raw), request)
                self.assertEqual(value.status, status)
                with self.assertRaises(api.ProvisioningError):
                    api._checked_response(value)
            else:
                with self.assertRaises(api.ProvisioningError):
                    self.decode(api.canonical(raw), request)


class OriginalDeadlineTests(unittest.TestCase):
    def test_same_deadline_reaches_cms_and_policy_no_budget_renewal(self):
        # Wiring test only. Fake decoder/evidence consumer cannot claim CMS or
        # native finality. The actual policy still validates the fixture claims.
        source = provider()
        plan, _ = plan_for(source)
        row = complete_profile(content=True)
        decoded = {"UUID": row["attributes"]["uuid"].upper(), "ApplicationIdentifierPrefix": [TARGET.team_id],
                   "Platform": ["iOS"], "CreationDate": CREATED, "ExpirationDate": EXPIRES,
                   "DeveloperCertificates": [CERT_BYTES], "TeamIdentifier": [TARGET.team_id],
                   "Entitlements": TARGET.base_entitlements()}
        from mobile_release.inspection import InspectionDeadline
        deadline, cancellation = InspectionDeadline(), Mock()
        from mobile_release.ios_entitlements import validate_profile_entitlements
        with patch("mobile_release.inspection.InspectionDeadline", side_effect=AssertionError("no renewed clock")), \
             patch("mobile_release.ios_profiles.decode_authenticated_profile", return_value=decoded) as decoder, \
             patch("mobile_release._profile_callers.consume_profile_evidence") as consume, \
             patch("mobile_release.ios_entitlements.validate_profile_entitlements", wraps=validate_profile_entitlements) as policy:
            result = core.authenticate_downloaded_profile(plan, response(row), cancellation=cancellation, now=NOW, deadline=deadline)
        self.assertIs(decoder.call_args.kwargs["deadline"], deadline)
        self.assertIs(policy.call_args.kwargs["deadline"], deadline)
        self.assertEqual(consume.call_count, 1)
        self.assertEqual(result.profile.content, PROFILE_BYTES)
        # This DATA result is not a native Bind/assignment or a vault write.

    def test_expired_original_refuses_before_decoder_and_first_interruption_survives(self):
        source = provider()
        plan, _ = plan_for(source)
        row = complete_profile(content=True)
        deadline, cancellation = Mock(), Mock()
        deadline.check.side_effect = api.ProvisioningError("original_deadline_expired")
        with patch("mobile_release.ios_profiles.decode_authenticated_profile") as decoder:
            with self.assertRaises(api.ProvisioningError):
                core.authenticate_downloaded_profile(plan, response(row), cancellation=cancellation, now=NOW, deadline=deadline)
        decoder.assert_not_called()
        deadline.check.side_effect = None
        original = KeyboardInterrupt("synthetic first failure")
        with patch("mobile_release.ios_profiles.decode_authenticated_profile", side_effect=original), \
             patch("mobile_release._profile_callers.consume_profile_evidence") as consume:
            with self.assertRaises(KeyboardInterrupt) as caught:
                core.authenticate_downloaded_profile(plan, response(row), cancellation=cancellation, now=NOW, deadline=deadline)
        self.assertIs(caught.exception, original)
        self.assertIs(consume.call_args.kwargs["primary"], original)


if __name__ == "__main__":
    unittest.main()
