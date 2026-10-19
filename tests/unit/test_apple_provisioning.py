"""Synthetic public-provider contracts only: no native keys/account/HTTP calls.

The certificate/CSR/profile strings below are deliberately NOT cryptographic
assets. CertificateBinding stands for a trusted native result in these policy
tests; this suite does not qualify native matching, CMS authority or assignment.
"""
from __future__ import annotations

import base64
import copy
import json
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from mobile_release import apple_provisioning_api as api
from mobile_release.apple_provisioning import (
    CertificateBinding, NativeKeyRef, PendingMutation, ProvisioningContext,
    ProvisioningTarget, PublicCSR, observe, prepare, validate_download, validate_profile_claims,
)
from mobile_release.apple_provisioning_recovery import ProvisioningApproval, ProvisioningAttempt


NOW = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
CREATED = NOW - timedelta(days=1)
EXPIRES = NOW + timedelta(days=90)
CERT_BYTES = b"synthetic provider certificate envelope; not X.509 or signing material"
PROFILE_BYTES = b"synthetic provider profile envelope; not CMS or a native authentication pass"
CSR_BYTES = b"-----BEGIN CERTIFICATE REQUEST-----\nbm90LWEtcmVhbC1DU1I=\n-----END CERTIFICATE REQUEST-----\n"
TEAM = "TESTTEAM01"
BUNDLE = "invalid.example.provisioning"
KEY = NativeKeyRef("1" * 32, "2" * 32, "3" * 32, "4" * 32, 1)
CSR = PublicCSR(KEY, CSR_BYTES, "5" * 64)
CONTEXT = ProvisioningContext("synthetic-project", "synthetic-client", "synthetic-operation", 1,
                              "synthetic-account", "synthetic-api-record", 1, 1)
TARGET = ProvisioningTarget(BUNDLE, TEAM, TEAM, "Synthetic provisioning test", True)


def date(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def bundle(resource_id="bundle-one", *, seed=TEAM, identifier=BUNDLE):
    return {"type": "bundleIds", "id": resource_id,
            "attributes": {"identifier": identifier, "platform": "IOS", "seedId": seed}}


def certificate(resource_id="certificate-one", *, content=CERT_BYTES, expires=EXPIRES):
    return {"type": "certificates", "id": resource_id, "attributes": {
        "certificateType": "DISTRIBUTION", "platform": "UNIVERSAL", "expirationDate": date(expires),
        "certificateContent": base64.b64encode(content).decode("ascii")}}


def profile(resource_id="profile-one", *, bundle_id="bundle-one", certificate_id="certificate-one",
            content=False, name="Synthetic existing profile", expires=EXPIRES):
    attributes = {"name": name, "platform": "IOS", "profileType": "IOS_APP_STORE", "profileState": "ACTIVE",
                  "uuid": "11111111-2222-3333-4444-555555555555", "createdDate": date(CREATED), "expirationDate": date(expires)}
    if content:
        attributes["profileContent"] = base64.b64encode(PROFILE_BYTES).decode("ascii")
    return {"type": "profiles", "id": resource_id, "attributes": attributes, "relationships": {
        "bundleId": {"data": {"type": "bundleIds", "id": bundle_id}},
        "certificates": {"data": [{"type": "certificates", "id": certificate_id}]},
    }}


def response(data, *, status=200, total=None, next_url=None, settled=True):
    payload = {"data": data}
    if type(data) is list:
        payload.update(links={"next": next_url}, meta={"paging": {"total": len(data) if total is None else total}})
    return api.AppleResponse(status, api.canonical(payload), settled)


def binding(resource_id="certificate-one", *, content=CERT_BYTES, team=TEAM, key=KEY, expires=EXPIRES):
    return CertificateBinding(resource_id, api.digest(content), CSR.public_key_sha256, key, team, CREATED, expires)


class FakeProvider:
    def __init__(self, *, bundles=None, certificates=None, profiles=None, mutation=None):
        self.responses = {"list_bundle_ids": response([bundle()] if bundles is None else bundles),
                          "list_certificates": response([certificate()] if certificates is None else certificates),
                          "list_profiles": response([profile()] if profiles is None else profiles)}
        self.mutation = mutation
        self.calls = []
        self.current = True
        self.callback = None

    def check(self, context):
        if not self.current or context != CONTEXT:
            raise ValueError("private native account detail must not be reported")

    def send(self, request):
        self.calls.append(request)
        if self.callback:
            self.callback()
        value = self.responses.get(request.kind) if request.method == "GET" else self.mutation
        if isinstance(value, BaseException):
            raise value
        if value is None:
            raise AssertionError("fixture has no response for the expected request")
        return value

    @property
    def writes(self):
        return [request for request in self.calls if request.method != "GET"]


class FakeOwner:
    def __init__(self):
        self.records = []
        self.settled = True
        self.current = True
        self.fail_persist = False

    def authorize(self, plan, approval):
        if not self.current:
            raise ValueError("private native permission detail must not be reported")

    def persist(self, record):
        if self.fail_persist:
            raise OSError("private journal path must not be reported")
        self.records.append(record)

    def transport_settled(self, record):
        return self.settled

    def reconciliation_current(self, plan, record):
        return self.current


def observed(provider, *, target=TARGET, now=NOW):
    return observe(CONTEXT, target, provider, now=now)


def plan_for(provider, *, target=TARGET, bindings=None, csr=None, pending=(), **options):
    snapshot = observed(provider, target=target)
    plan = prepare(CONTEXT, target, snapshot, bindings=(binding(),) if bindings is None else bindings,
                   csr=csr, pending=pending, now=NOW, **options)
    return plan, snapshot


def approval(plan):
    return ProvisioningApproval(plan.context, plan.sha256, plan.action)


def certificate_attempt():
    provider = FakeProvider(certificates=[], profiles=[], mutation=response(certificate(), status=201))
    plan, snapshot = plan_for(provider, bindings=(), csr=CSR)
    return provider, plan, snapshot, ProvisioningAttempt(plan, snapshot), FakeOwner()


class ProvisioningWireTests(unittest.TestCase):
    def test_closed_public_api_request_shapes(self):
        self.assertEqual(api.create_certificate(CSR_BYTES).path, "/v1/certificates")
        body = json.loads(api.create_certificate(CSR_BYTES).body)
        self.assertEqual(body["data"]["attributes"]["certificateType"], "DISTRIBUTION")
        self.assertEqual(set(body["data"]["attributes"]), {"certificateType", "csrContent"})
        body = json.loads(api.create_profile("Synthetic", "bundle-one", "certificate-one").body)
        self.assertEqual(body["data"]["attributes"]["profileType"], "IOS_APP_STORE")
        self.assertEqual(set(body["data"]["relationships"]), {"bundleId", "certificates"})
        self.assertNotIn("filter[bundleId]", dict(api.list_profiles().query))
        self.assertNotIn("profileContent", dict(api.list_profiles().query)["fields[profiles]"])

    def test_private_adapter_wire_revalidates_manually_constructed_requests(self):
        requests = [api.list_bundle_ids(BUNDLE), api.list_certificates(), api.list_profiles(),
                    api.download_profile("profile-one"), api.register_bundle_id(BUNDLE, "Synthetic"),
                    api.create_certificate(CSR_BYTES), api.create_profile("Synthetic", "bundle-one", "certificate-one")]
        for request in requests:
            with self.subTest(kind=request.kind):
                wire = api.request_wire(request)
                self.assertEqual(set(wire), {"kind", "method", "path", "query", "body"})
                self.assertEqual(api.request_sha256(request), api.digest(api.canonical(wire)))
                for changed in [replace(request, method="DELETE"), replace(request, path="/v1/apps"),
                                replace(request, resource_type="apps"), replace(request, query=(("other", "query"),))]:
                    with self.assertRaises(api.ProvisioningError):
                        api.request_wire(changed)
        request = api.create_profile("Synthetic", "bundle-one", "certificate-one")
        body = api.document(request.body)
        body["data"]["relationships"]["devices"] = {"data": []}
        with self.assertRaises(api.ProvisioningError):
            api.request_wire(replace(request, body=api.canonical(body)))

    def test_adapter_frame_never_supplies_its_own_lifecycle_finality(self):
        frame = api.canonical({"status": 200, "body": response([]).body.decode(), "failure": None})
        result = api.response_from_adapter(frame, settled=False)
        self.assertFalse(result.settled)
        with self.assertRaises(api.ProvisioningError):
            api.collect(api.list_certificates(), lambda _: result)
        forged = api.document(frame)
        forged["settled"] = True
        with self.assertRaises(api.ProvisioningError):
            api.response_from_adapter(api.canonical(forged), settled=True)
        for status in (None, 201, 429, 500):
            frame = api.canonical({"status": status, "body": None, "failure": "provider_request_unconfirmed"})
            with self.subTest(status=status), self.assertRaises(api.ProvisioningError):
                api.response_from_adapter(frame, settled=True)
        frame = api.canonical({"status": 403, "body": None, "failure": "provider_request_unconfirmed"})
        result = api.response_from_adapter(frame, settled=True)
        self.assertEqual(result.status, 403)
        self.assertEqual(result.body, b"{}")

    def test_request_digest_matches_ruby_private_owner_gate_fixture(self):
        request = api.register_bundle_id(BUNDLE, "Synthetic café 🍎")
        self.assertEqual(api.request_sha256(request),
                         "f2bf3d53ff01255fbc588099c17830348b748a6e2eab6bc439d6e385848bc356")

    def test_bounded_json_depth_nodes_and_nonfinite_numbers(self):
        for payload in [b'{"v":NaN}', api.canonical({"v": [0] * 100_001}),
                        b'{"v":' + b'[' * 33 + b'0' + b']' * 33 + b'}']:
            with self.subTest(), self.assertRaises(api.ProvisioningError):
                api.document(payload)

    def test_private_key_and_malformed_csr_not_accepted_as_public_csr(self):
        for value in [b"-----BEGIN PRIVATE KEY-----\naaaa\n-----END PRIVATE KEY-----\n", b"invalid", b"a" * 32769]:
            with self.subTest(size=len(value)), self.assertRaises(api.ProvisioningError):
                api.create_certificate(value)

    def test_native_reference_preserves_generation_and_random_revision(self):
        with self.assertRaises(api.ProvisioningError):
            replace(KEY, generation_id=1)
        with self.assertRaises(api.ProvisioningError):
            replace(KEY, revision_counter=True)
        self.assertNotEqual(KEY, replace(KEY, revision_id="a" * 32))
        for changes in [{"record_id": "0" * 32}, {"generation_id": KEY.vault_id},
                        {"record_id": KEY.generation_id}, {"revision_id": KEY.record_id}]:
            with self.subTest(), self.assertRaises(api.ProvisioningError):
                replace(KEY, **changes)

    def test_complete_pagination_collects_unique_resources(self):
        request = api.list_certificates()
        next_url = replace(request, query=(*request.query, ("cursor", "next-page"))).url
        pages = iter([response([certificate()], total=2, next_url=next_url), response([certificate("certificate-two")], total=2)])
        calls = []
        def send(request):
            calls.append(request)
            return next(pages)
        self.assertEqual(len(api.collect(request, send)), 2)
        self.assertEqual(calls[1].path, "/v1/certificates")

    def test_foreign_origin_path_query_fragment_or_cursor_rejected(self):
        request = api.list_certificates()
        valid = replace(request, query=(*request.query, ("cursor", "next"))).url
        links = [valid.replace("api.appstoreconnect.apple.com", "other.invalid"),
                 valid.replace("/v1/certificates", "/v1/apps"), valid + "#fragment",
                 valid.replace("https://", "http://"), valid.replace("200", "100"),
                 valid + "&cursor=duplicate", valid.replace("next", ""),
                 {"href": valid}]
        for link in links:
            with self.subTest(link_type=type(link).__name__), self.assertRaises(api.ProvisioningError):
                api.collect(request, lambda _: response([certificate()], total=2, next_url=link))

    def test_incomplete_duplicate_and_drifted_inventory_refused(self):
        for payload in [response([], total=1), response([certificate(), certificate()]),
                        api.AppleResponse(200, b'{"data":[],"links":{}}', True)]:
            with self.subTest(), self.assertRaises(api.ProvisioningError):
                api.collect(api.list_certificates(), lambda _: payload)
        request = api.list_certificates()
        next_url = replace(request, query=(*request.query, ("cursor", "next"))).url
        pages = iter([response([certificate()], total=2, next_url=next_url), response([certificate("two")], total=3)])
        with self.assertRaises(api.ProvisioningError):
            api.collect(request, lambda _: next(pages))

    def test_duplicate_json_keys_malformed_base64_and_missing_fields_refused(self):
        with self.assertRaises(api.ProvisioningError):
            api.document(b'{"data":[],"data":null}')
        for value in ["not-base64", "A" * (api.MAX_CERTIFICATE_BYTES * 2), ""]:
            data = certificate()
            data["attributes"]["certificateContent"] = value
            with self.subTest(), self.assertRaises(api.ProvisioningError):
                api.Certificate.parse(data)
        data = profile()
        del data["relationships"]["certificates"]["data"]
        with self.assertRaises(api.ProvisioningError):
            api.Profile.parse(data)

    def test_truncated_profile_certificate_relationship_refused(self):
        data = profile()
        data["relationships"]["certificates"]["meta"] = {"paging": {"total": 2}}
        with self.assertRaises(api.ProvisioningError):
            api.Profile.parse(data)

    def test_result_shape_does_not_imply_transport_finality(self):
        result = api.AppleResponse(200, response([]).body)
        with self.assertRaisesRegex(api.ProvisioningError, "transport unsettled"):
            api.collect(api.list_certificates(), lambda _: result)


class ReuseFirstTests(unittest.TestCase):
    def test_valid_reuse_has_no_writes_and_requires_native_validation(self):
        provider = FakeProvider()
        plan, snapshot = plan_for(provider)
        self.assertTrue(snapshot.available)
        self.assertEqual(plan.action, "download_profile")
        self.assertEqual(plan.reason, "reuse_existing_assets")
        self.assertFalse(plan.summary()["credentialReady"])
        self.assertFalse(plan.summary()["approvalRequired"])
        self.assertEqual(provider.writes, [])

    def test_denied_not_found_and_incomplete_queries_are_not_absence(self):
        for value in [response([], status=401), response([], status=403), response([], status=404), response([], total=1)]:
            provider = FakeProvider()
            provider.responses["list_bundle_ids"] = value
            plan, snapshot = plan_for(provider, target=replace(TARGET, existing_application=False), bindings=(), csr=CSR)
            self.assertFalse(snapshot.available)
            self.assertEqual(plan.action, "blocked")
            self.assertIsNone(plan.request)
            self.assertEqual(provider.writes, [])

    def test_no_native_key_for_existing_certificate_never_consumes_quota(self):
        plan, _ = plan_for(FakeProvider(), bindings=(), csr=CSR)
        self.assertEqual(plan.action, "recover_existing_key")
        self.assertIsNone(plan.request)

    def test_multiple_owned_certificates_or_profiles_require_selection(self):
        provider = FakeProvider(certificates=[certificate(), certificate("two")])
        plan, _ = plan_for(provider, bindings=(binding(), binding("two", key=replace(KEY, record_id="6" * 32))))
        self.assertEqual(plan.action, "select_existing_certificate")
        selected, _ = plan_for(provider, bindings=(binding(), binding("two", key=replace(KEY, record_id="6" * 32))), selected_key=KEY)
        self.assertEqual(selected.action, "download_profile")
        plan, _ = plan_for(FakeProvider(profiles=[profile(), profile("two")]))
        self.assertEqual(plan.action, "select_existing_profile")
        selected, _ = plan_for(FakeProvider(profiles=[profile(), profile("two")]), selected_profile="two")
        self.assertEqual(selected.profile.resource_id, "two")

    def test_existing_application_missing_identity_cannot_become_new_app(self):
        plan, _ = plan_for(FakeProvider(bundles=[], certificates=[], profiles=[]), bindings=(), csr=CSR)
        self.assertEqual(plan.reason, "existing_application_identity_missing")
        self.assertIsNone(plan.request)
        plan, _ = plan_for(FakeProvider(bundles=[], certificates=[], profiles=[]),
                           target=replace(TARGET, existing_application=False), bindings=(), csr=CSR)
        self.assertEqual(plan.action, "register_bundle_id")

    def test_seed_prefix_and_native_team_contradictions_fail_closed(self):
        plan, _ = plan_for(FakeProvider(bundles=[bundle(seed="OTHERTEAM1")]))
        self.assertEqual(plan.reason, "bundle_identity_conflict")
        plan, _ = plan_for(FakeProvider(), target=replace(TARGET, app_id_prefix="OLDPREFIX1"))
        self.assertEqual(plan.reason, "legacy_app_id_prefix_unsupported")
        with self.assertRaises(api.ProvisioningError):
            plan_for(FakeProvider(), bindings=(binding(team="OTHERTEAM1"),))

    def test_contradictory_included_team_and_certificate_evidence_refused(self):
        variants = [bundle(seed="OTHERTEAM1"), bundle(identifier="invalid.example.other"),
                    certificate(expires=EXPIRES + timedelta(days=1)), certificate(content=b"different synthetic DER")]
        for included in variants:
            provider = FakeProvider()
            page = api.document(provider.responses["list_profiles"].body)
            page["included"] = [included]
            provider.responses["list_profiles"] = api.AppleResponse(200, api.canonical(page), True)
            with self.subTest():
                plan, snapshot = plan_for(provider)
                self.assertFalse(snapshot.available)
                self.assertEqual(plan.action, "blocked")
                self.assertEqual(provider.writes, [])

    def test_expired_profiles_get_approved_replacement_not_revocation(self):
        expired = profile(expires=NOW - timedelta(hours=1))
        plan, _ = plan_for(FakeProvider(profiles=[expired]))
        self.assertEqual(plan.action, "create_profile")
        self.assertEqual(plan.request.method, "POST")
        self.assertTrue(plan.summary()["approvalRequired"])

    def test_certificate_issuance_requires_complete_inventory_and_native_csr(self):
        provider = FakeProvider(certificates=[], profiles=[])
        plan, _ = plan_for(provider, bindings=())
        self.assertEqual(plan.action, "prepare_csr")
        plan, _ = plan_for(provider, bindings=(), csr=CSR)
        self.assertEqual(plan.action, "create_certificate")
        self.assertEqual(provider.writes, [])
        self.assertNotEqual(plan.sha256, replace(plan, csr=replace(CSR, key_ref=replace(KEY, revision_id="a" * 32))).sha256)

    def test_manual_capabilities_are_not_silently_enabled(self):
        target = replace(TARGET, entitlements_json=b'{"aps-environment":"production"}')
        plan, _ = plan_for(FakeProvider(profiles=[]), target=target)
        self.assertEqual(plan.action, "manual")
        self.assertIsNone(plan.request)
        reuse, _ = plan_for(FakeProvider(), target=target)
        self.assertEqual(reuse.action, "download_profile")

    def test_nondefault_keychain_group_needs_capability_review_before_create(self):
        target = replace(TARGET, entitlements_json=api.canonical({"keychain-access-groups": [TEAM + ".shared"]}))
        plan, _ = plan_for(FakeProvider(profiles=[]), target=target)
        self.assertEqual(plan.action, "manual")
        target = replace(TARGET, entitlements_json=api.canonical({"keychain-access-groups": [TEAM + "." + BUNDLE]}))
        plan, _ = plan_for(FakeProvider(profiles=[]), target=target)
        self.assertEqual(plan.action, "create_profile")

    def test_plan_fingerprint_binds_selected_resource_metadata(self):
        plan, _ = plan_for(FakeProvider())
        self.assertNotEqual(plan.sha256, replace(plan, profile=replace(plan.profile, uuid="other")).sha256)
        self.assertNotEqual(plan.sha256, replace(plan, certificate=replace(plan.certificate, content=b"other")).sha256)

    def test_pending_certificate_request_blocks_account_wide_new_plan(self):
        pending = PendingMutation(CONTEXT.account_ref, "another-project-operation", "create_certificate", "unknown")
        plan, _ = plan_for(FakeProvider(certificates=[], profiles=[]), bindings=(), csr=CSR, pending=(pending,))
        self.assertEqual(plan.action, "reconcile")
        self.assertIsNone(plan.request)

    def test_observation_expiry_and_context_change_refuse_plan(self):
        snapshot = observed(FakeProvider())
        for context, now in [(CONTEXT, NOW + timedelta(minutes=5)), (replace(CONTEXT, credential_revision=2), NOW)]:
            with self.subTest(), self.assertRaises(api.ProvisioningError):
                prepare(context, TARGET, snapshot, bindings=(binding(),), csr=None, pending=(), now=now)


class ProfileValidationTests(unittest.TestCase):
    def setUp(self):
        self.plan, _ = plan_for(FakeProvider())
        self.profile = validate_download(self.plan, response(profile(content=True)), now=NOW)
        self.payload = {"UUID": self.profile.uuid, "TeamIdentifier": [TEAM], "ApplicationIdentifierPrefix": [TEAM],
                        "Platform": ["iOS"], "CreationDate": CREATED, "ExpirationDate": EXPIRES,
                        "DeveloperCertificates": [CERT_BYTES], "Entitlements": TARGET.base_entitlements()}

    def test_profile_format_response_remains_unassignable_without_native_authority(self):
        self.assertEqual(self.profile.content, PROFILE_BYTES)
        self.assertFalse(self.plan.summary()["credentialReady"])
        # Pure synthetic policy success does NOT produce an authenticated object.
        self.assertIsNone(validate_profile_claims(self.plan, self.profile, self.payload, now=NOW))

    def test_downloaded_wrong_relationship_uuid_expiry_or_state_refused(self):
        variants = [profile(content=True, bundle_id="other-bundle"), profile(content=True, certificate_id="other-cert"),
                    profile(content=True, expires=EXPIRES + timedelta(days=1))]
        invalid = profile(content=True)
        invalid["attributes"]["profileState"] = "INVALID"
        variants.append(invalid)
        for data in variants:
            with self.subTest(), self.assertRaises(api.ProvisioningError):
                validate_download(self.plan, response(data), now=NOW)

    def test_wrong_team_prefix_certificate_and_entitlements_are_rejected(self):
        variants = []
        for key, value in [("TeamIdentifier", ["OTHERTEAM1"]), ("ApplicationIdentifierPrefix", ["OLDPREFIX1"]),
                           ("DeveloperCertificates", [b"different synthetic certificate"]),
                           ("ExpirationDate", EXPIRES + timedelta(days=1)), ("ProvisionedDevices", ["synthetic-device"])]:
            payload = copy.deepcopy(self.payload)
            payload[key] = value
            variants.append(payload)
        for key, value in [("get-task-allow", 0), ("beta-reports-active", 1),
                           ("application-identifier", TEAM + ".invalid.example.other"),
                           ("com.apple.developer.team-identifier", "OTHERTEAM1")]:
            payload = copy.deepcopy(self.payload)
            payload["Entitlements"][key] = value
            variants.append(payload)
        for payload in variants:
            with self.subTest(), self.assertRaises(api.ProvisioningError):
                validate_profile_claims(self.plan, self.profile, payload, now=NOW)


class ProvisioningRecoveryTests(unittest.TestCase):
    def test_action_and_closed_request_kind_must_agree(self):
        _, plan, snapshot, _, _ = certificate_attempt()
        with self.assertRaises(api.ProvisioningError):
            ProvisioningAttempt(replace(plan, action="register_bundle_id"), snapshot)

    def test_profile_mutation_exact_reviewed_relations_name_and_scope_required(self):
        provider = FakeProvider(profiles=[])
        plan, snapshot = plan_for(provider)
        name = api.document(plan.request.body)["data"]["attributes"]["name"]
        requests = [api.create_profile(name, "other-bundle", "certificate-one"),
                    api.create_profile(name, "bundle-one", "other-certificate"),
                    api.create_profile("other-name", "bundle-one", "certificate-one")]
        for request in requests:
            with self.subTest(), self.assertRaises(api.ProvisioningError):
                ProvisioningAttempt(replace(plan, request=request), snapshot)
        for changed in [replace(snapshot, context=replace(CONTEXT, credential_revision=2)),
                        replace(snapshot, bundle_id="invalid.example.other")]:
            # Recomputing a data fingerprint cannot excuse mismatched scope.
            with self.subTest(), self.assertRaises(api.ProvisioningError):
                ProvisioningAttempt(replace(plan, observation_sha256=changed.sha256), changed)
        self.assertEqual(provider.writes, [])

    def test_reentrant_execute_before_owner_authorization_returns_cannot_duplicate_send(self):
        provider, plan, snapshot, attempt, owner = certificate_attempt()
        nested = []
        def authorize(_plan, _approval):
            if nested:
                return
            nested.append(True)
            with self.assertRaisesRegex(api.ProvisioningError, "operation busy"):
                attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
        owner.authorize = authorize
        attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
        self.assertEqual(len(provider.writes), 1)

    def test_owner_errors_before_send_are_sanitized_without_provider_call(self):
        provider, plan, snapshot, attempt, owner = certificate_attempt()
        owner.current = False
        with self.assertRaisesRegex(api.ProvisioningError, "authorization changed") as failure:
            attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
        self.assertNotIn("private", str(failure.exception))
        self.assertEqual(provider.writes, [])

    def test_original_cancel_during_authorization_is_latched_before_send(self):
        provider, plan, snapshot, attempt, owner = certificate_attempt()
        owner.authorize = lambda _plan, _approval: attempt.request_cancel()
        record = attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
        self.assertEqual(record.status, "cancelled")
        self.assertTrue(record.cancel_requested)
        self.assertFalse(record.possible_send)
        self.assertEqual(provider.writes, [])

    def test_wrong_approval_or_stale_observation_prevents_send(self):
        for kind in ("approval", "context", "observation"):
            provider, plan, snapshot, attempt, owner = certificate_attempt()
            consent, fresh = approval(plan), snapshot
            if kind == "approval": consent = replace(consent, plan_sha256="f" * 64)
            if kind == "context": consent = replace(consent, context=replace(CONTEXT, credential_revision=2))
            if kind == "observation": fresh = replace(snapshot, certificates=(api.Certificate.parse(certificate()),))
            with self.subTest(kind=kind), self.assertRaises(api.ProvisioningError):
                attempt.execute(consent, fresh, provider, owner, now=NOW)
            self.assertEqual(provider.writes, [])
            self.assertEqual(owner.records, [])

    def test_journal_must_acknowledge_before_any_send(self):
        provider, plan, snapshot, attempt, owner = certificate_attempt()
        owner.fail_persist = True
        record = attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
        self.assertFalse(record.possible_send)
        self.assertEqual(record.status, "recovery_required")
        self.assertEqual(provider.writes, [])
        with self.assertRaises(api.ProvisioningError):
            attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)

    def test_provider_success_requires_readback_and_native_key_match(self):
        provider, plan, snapshot, attempt, owner = certificate_attempt()
        provider.callback = lambda: self.assertTrue(owner.records[-1].possible_send)
        record = attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
        self.assertEqual(record.status, "recovery_required")
        after = observed(FakeProvider(profiles=[]), now=NOW + timedelta(seconds=1))
        missing = attempt.reconcile(after, owner, bindings=(), now=NOW + timedelta(seconds=1))
        self.assertNotEqual(missing.status, "succeeded")
        final = attempt.reconcile(after, owner, bindings=(binding(),), now=NOW + timedelta(seconds=1))
        self.assertEqual(final.status, "succeeded")
        self.assertFalse(final.summary()["credentialReady"])
        self.assertEqual(len(provider.writes), 1)

    def test_same_returned_id_with_different_der_cannot_confirm_response(self):
        provider, plan, snapshot, attempt, owner = certificate_attempt()
        attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
        other = b"other synthetic certificate DER with the same fake SPKI"
        after = observed(FakeProvider(certificates=[certificate(content=other)], profiles=[]))
        record = attempt.reconcile(after, owner, bindings=(binding(content=other),), now=NOW)
        self.assertEqual(record.status, "unknown")
        self.assertEqual(record.reason, "response_readback_disagrees")

    def test_profile_readback_requires_current_original_certificate_binding(self):
        provider = FakeProvider(profiles=[])
        plan, snapshot = plan_for(provider)
        name = api.document(plan.request.body)["data"]["attributes"]["name"]
        created = profile(name=name)
        provider.mutation = response(created, status=201)
        owner, attempt = FakeOwner(), ProvisioningAttempt(plan, snapshot)
        attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
        after = observed(FakeProvider(profiles=[created]))
        record = attempt.reconcile(after, owner, bindings=(), now=NOW)
        self.assertEqual(record.reason, "resource_validation_required")
        record = attempt.reconcile(after, owner, bindings=(binding(),), now=NOW)
        self.assertEqual(record.status, "succeeded")
        self.assertFalse(record.summary()["credentialReady"])

    def test_current_original_owner_required_during_reconciliation(self):
        provider, plan, snapshot, attempt, owner = certificate_attempt()
        attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
        after = observed(FakeProvider(profiles=[]))
        owner.current = False
        record = attempt.reconcile(after, owner, bindings=(binding(),), now=NOW)
        self.assertEqual(record.status, "unknown")
        self.assertEqual(record.reason, "reconciliation_context_changed")
        self.assertEqual(len(provider.writes), 1)

    def test_reentrant_reconciliation_cannot_publish_a_stale_parallel_result(self):
        provider, plan, snapshot, attempt, owner = certificate_attempt()
        attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
        after = observed(FakeProvider(profiles=[]))
        def current(_plan, _record):
            with self.assertRaisesRegex(api.ProvisioningError, "operation busy"):
                attempt.reconcile(after, owner, bindings=(binding(),), now=NOW)
            return True
        owner.reconciliation_current = current
        record = attempt.reconcile(after, owner, bindings=(binding(),), now=NOW)
        self.assertEqual(record.status, "succeeded")
        self.assertEqual(len(provider.writes), 1)

    def test_sent_timeout_empty_readback_is_not_retryable(self):
        provider, plan, snapshot, attempt, owner = certificate_attempt()
        provider.mutation = TimeoutError("PRIVATE RESPONSE DETAILS")
        self.assertEqual(attempt.execute(approval(plan), snapshot, provider, owner, now=NOW).status, "unknown")
        after = replace(snapshot, observed_at=NOW + timedelta(seconds=1))
        for _ in range(2):
            record = attempt.reconcile(after, owner, bindings=(), now=after.observed_at)
            self.assertEqual(record.status, "unknown")
            self.assertFalse(record.summary()["retryAllowed"])
            with self.assertRaises(api.ProvisioningError):
                attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
        self.assertEqual(len(provider.writes), 1)
        self.assertNotIn("PRIVATE", json.dumps(record.summary()))

    def test_lost_reply_exact_public_key_found_requires_review_not_duplicate(self):
        provider, plan, snapshot, attempt, owner = certificate_attempt()
        provider.mutation = TimeoutError("synthetic lost reply")
        attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
        after = observed(FakeProvider(profiles=[]), now=NOW + timedelta(seconds=1))
        found = attempt.reconcile(after, owner, bindings=(binding(),), now=after.observed_at)
        self.assertEqual(found.status, "recovery_required")
        self.assertEqual(found.reason, "resource_found_review_required")
        self.assertEqual(found.observed_resource_id, "certificate-one")
        self.assertEqual(len(provider.writes), 1)
        blocked = prepare(CONTEXT, TARGET, after, bindings=(binding(),), csr=CSR,
                          pending=(found.pending(),), now=after.observed_at)
        self.assertEqual(blocked.action, "reconcile")

    def test_ambiguous_or_wrong_key_readback_remains_unresolved(self):
        provider, plan, snapshot, attempt, owner = certificate_attempt()
        provider.mutation = TimeoutError("synthetic lost reply")
        attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
        after = observed(FakeProvider(certificates=[certificate(), certificate("two")], profiles=[]))
        result = attempt.reconcile(after, owner, bindings=(binding(), binding("two")), now=NOW)
        self.assertEqual(result.reason, "ambiguous_recovery_resources")
        wrong = replace(binding(), public_key_sha256="f" * 64)
        after = observed(FakeProvider(profiles=[]))
        result = attempt.reconcile(after, owner, bindings=(wrong,), now=NOW)
        self.assertEqual(result.status, "unknown")

    def test_known_sent_rejection_is_not_retried_or_revoked(self):
        for status in (400, 401, 403, 409, 422):
            provider, plan, snapshot, attempt, owner = certificate_attempt()
            provider.mutation = response({}, status=status)
            record = attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
            self.assertEqual(record.status, "failed")
            with self.assertRaises(api.ProvisioningError):
                attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
            self.assertEqual(len(provider.writes), 1)
            self.assertTrue(all(request.method == "POST" for request in provider.writes))

    def test_original_transport_unsettled_cannot_be_replaced_by_good_resource(self):
        provider, plan, snapshot, attempt, owner = certificate_attempt()
        owner.settled = False
        record = attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
        self.assertEqual(record.status, "unknown")
        after = observed(FakeProvider(profiles=[]))
        record = attempt.reconcile(after, owner, bindings=(binding(),), now=NOW)
        self.assertEqual(record.reason, "original_transport_unsettled")
        self.assertEqual(record.status, "unknown")

    def test_credential_switch_after_send_preserves_uncertain_outcome(self):
        provider, plan, snapshot, attempt, owner = certificate_attempt()
        provider.callback = lambda: setattr(provider, "current", False)
        record = attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
        self.assertEqual(record.reason, "authorization_changed_after_send")
        self.assertEqual(record.status, "unknown")
        self.assertTrue(record.possible_send)

    def test_cancelled_after_send_requires_settlement_and_keeps_created_asset(self):
        provider, plan, snapshot, attempt, owner = certificate_attempt()
        provider.callback = attempt.request_cancel
        record = attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
        self.assertNotEqual(record.status, "cancelled")
        after = observed(FakeProvider(profiles=[]))
        record = attempt.reconcile(after, owner, bindings=(binding(),), now=NOW)
        self.assertEqual(record.status, "cancelled")
        self.assertEqual(record.reason, "cancelled_after_settlement")
        self.assertEqual(record.observed_resource_id, "certificate-one")
        self.assertEqual(len(provider.writes), 1)

    def test_cancel_before_send_never_reaches_provider(self):
        provider, plan, snapshot, attempt, owner = certificate_attempt()
        attempt.request_cancel()
        with self.assertRaises(api.ProvisioningError):
            attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
        self.assertEqual(provider.writes, [])

    def test_resumed_unknown_operation_cannot_send_again(self):
        provider, plan, snapshot, attempt, owner = certificate_attempt()
        provider.mutation = TimeoutError("synthetic timeout")
        record = attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
        resumed = ProvisioningAttempt.resume(plan, snapshot, record)
        with self.assertRaises(api.ProvisioningError):
            resumed.execute(approval(plan), snapshot, provider, owner, now=NOW)
        with self.assertRaises(api.ProvisioningError):
            ProvisioningAttempt.resume(plan, snapshot, replace(record, plan_sha256="f" * 64))
        self.assertEqual(resumed.reconcile(snapshot, owner, bindings=(), now=NOW).status, "unknown")

    def test_partial_bundle_success_survives_later_certificate_failure(self):
        target = replace(TARGET, existing_application=False)
        provider = FakeProvider(bundles=[], certificates=[], profiles=[], mutation=response(bundle(), status=201))
        plan, snapshot = plan_for(provider, target=target, bindings=(), csr=CSR)
        owner = FakeOwner()
        first = ProvisioningAttempt(plan, snapshot)
        first.execute(approval(plan), snapshot, provider, owner, now=NOW)
        after = observed(FakeProvider(certificates=[], profiles=[]), target=target)
        confirmed = first.reconcile(after, owner, bindings=(), now=NOW)
        self.assertEqual(confirmed.status, "succeeded")
        next_plan = prepare(CONTEXT, target, after, bindings=(), csr=CSR,
                            pending=(confirmed.pending(),), now=NOW)
        second = ProvisioningAttempt(next_plan, after)
        provider.mutation = response({}, status=403)
        second.execute(approval(next_plan), after, provider, owner, now=NOW)
        self.assertEqual(second.record.status, "failed")
        self.assertEqual(first.record.status, "succeeded")
        self.assertEqual(first.record.observed_resource_id, "bundle-one")
        self.assertEqual([request.method for request in provider.writes], ["POST", "POST"])

    def test_private_material_and_resource_identity_absent_from_diagnostics(self):
        provider, plan, snapshot, attempt, owner = certificate_attempt()
        attempt.execute(approval(plan), snapshot, provider, owner, now=NOW)
        text = json.dumps([plan.summary(), snapshot.summary(), attempt.record.summary()])
        text += repr(plan) + repr(CSR) + repr(KEY) + repr(attempt.record)
        for private in [CSR_BYTES.decode(), CERT_BYTES.decode(), TEAM, BUNDLE, KEY.record_id, "certificate-one"]:
            self.assertNotIn(private, text)


if __name__ == "__main__":
    unittest.main()
