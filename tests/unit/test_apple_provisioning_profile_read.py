"""Metadata DATA + actual existing input/file owners with fake command replies.

No SDK, real credentials, subprocess, Apple account or native qualification.
Run against the full actual package with Root's proposed source hooks applied.
"""
from contextlib import contextmanager
import copy
from datetime import datetime, timedelta, timezone
import json
import os
import subprocess
import unittest
from unittest.mock import patch

from mobile_release import apple_provisioning_api as api
from mobile_release import apple_provisioning_bundle_read as bundle
from mobile_release import apple_provisioning_profile_read as profiles
from mobile_release import _desktop_store_preflight_protocol as wire
from mobile_release import desktop_store_preflight as service
from mobile_release.owned_process import ProcessError, ProcessOutcomeUnknown
from mobile_release.reporting import Finding, Status
from . import test_apple_provisioning_bundle_read as bundle_tests
from . import test_desktop_store_preflight as original

CONTEXT = "a" * 64
BUNDLE = "com.example.reader"
NOW = datetime(2026, 10, 19, 12, 30, 0, 123456, tzinfo=timezone.utc)


def bundle_row(resource="bundle-1", identifier=BUNDLE, **attributes):
    return {"type": "bundleIds", "id": resource, "attributes": {
        "identifier": identifier, "platform": "IOS", "seedId": "ZZZZZ12345", **attributes}}


def certificate(resource="certificate-1", **attributes):
    return {"type": "certificates", "id": resource, "attributes": {
        "certificateType": "DISTRIBUTION", "platform": "IOS", "expirationDate": "2028-01-01T00:00:00Z", **attributes}}


def profile(number=1, bundle_resource="bundle-1", certificates=("certificate-1",), **attributes):
    return {"type": "profiles", "id": f"profile-{number}", "attributes": {
        "name": "SYNTHETIC_PRIVATE_PROFILE_NAME", "platform": "IOS", "profileType": "IOS_APP_STORE", "profileState": "ACTIVE",
        "uuid": f"00000000-0000-4000-8000-{number:012d}", "createdDate": "2026-01-01T00:00:00Z",
        "expirationDate": "2027-01-01T00:00:00Z", **attributes}, "relationships": {
            "bundleId": {"data": {"type": "bundleIds", "id": bundle_resource}},
            "certificates": {"data": [{"type": "certificates", "id": value} for value in certificates],
                             "meta": {"paging": {"total": len(certificates)}}}}}


def page(rows=None, included=None):
    rows = [profile()] if rows is None else rows
    included = [bundle_row(), certificate()] if included is None else included
    return {"data": rows, "included": included, "links": {}, "meta": {"paging": {"total": len(rows)}}}


def observe(payload, *, now=NOW, **frame_options):
    raw = payload if type(payload) is bytes else api.canonical(payload)
    return profiles.summary_from_frame(bundle_tests.frame(raw, **frame_options), context_sha256=CONTEXT, bundle_id=BUNDLE, now=now)


class ProfileMetadataDataTests(unittest.TestCase):
    def test_matching_metadata_is_only_a_native_inspection_candidate(self):
        with patch.object(api.Certificate, "parse", side_effect=AssertionError("no DER object")), \
                patch.object(api, "_content", side_effect=AssertionError("no content decoding")):
            result = observe(page())
        self.assertEqual(result, {"observation": "found", "checkedAt": "2026-10-19T12:30:00.123456Z", "counts": {
            "matchingProfiles": 1, "activeProfiles": 1, "currentMetadataCandidates": 1, "relatedCertificates": 1}})
        self.assertTrue(profiles.valid_summary(result))
        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(result))
        self.assertNotIn("certificate-1", json.dumps(result))
        self.assertNotIn("ZZZZZ12345", json.dumps(result))  # Seed is not team proof.

    def test_parse_all_resources_but_count_only_matching_profile_references(self):
        data = page([profile(), profile(2), profile(3, bundle_resource="other", certificates=("other-cert",))],
                    [bundle_row(), certificate(), bundle_row("other", "com.example.other"), certificate("other-cert")])
        self.assertEqual(observe(data)["counts"], {"matchingProfiles": 2, "activeProfiles": 2,
            "currentMetadataCandidates": 2, "relatedCertificates": 1})  # Distinct, not repeated links.
        data["data"] = data["data"][2:]; data["included"] = data["included"][2:]; data["meta"]["paging"]["total"] = 1
        self.assertEqual(observe(data)["observation"], "not-returned")
        self.assertEqual(set(observe(data)["counts"].values()), {0})
        data["included"][1]["attributes"]["platform"] = "MAC_OS"
        self.assertEqual(observe(data), profiles.unavailable("inconclusive"))  # Unrelated contradictions still refuse.

    def test_expiry_and_creation_use_one_fractional_half_open_comparison(self):
        for attr, when, expected in (("expirationDate", NOW, 0), ("expirationDate", NOW + timedelta(microseconds=1), 1),
                                     ("createdDate", NOW, 1), ("createdDate", NOW + timedelta(microseconds=1), 0)):
            with self.subTest(attr=attr, when=when):
                data = page(); data["data"][0]["attributes"][attr] = when.isoformat()
                self.assertEqual(observe(data)["counts"]["currentMetadataCandidates"], expected)
        for when, expected in ((NOW, 0), (NOW + timedelta(microseconds=1), 1)):
            data = page(); data["included"][1]["attributes"]["expirationDate"] = when.isoformat()
            self.assertEqual(observe(data)["counts"]["currentMetadataCandidates"], expected)
        data = page([profile(profileState="INVALID")])
        self.assertEqual(observe(data)["counts"], {"matchingProfiles": 1, "activeProfiles": 0,
            "currentMetadataCandidates": 0, "relatedCertificates": 1})

    def test_all_referenced_certificates_not_any_row_must_pass_date_comparison(self):
        data = page([profile(certificates=("certificate-1", "second"))],
                    [bundle_row(), certificate(), certificate("second", certificateType="IOS_DISTRIBUTION")])
        self.assertEqual(observe(data)["counts"]["currentMetadataCandidates"], 1)
        data["included"][2]["attributes"]["expirationDate"] = NOW.isoformat()
        value = observe(data)
        self.assertEqual(value["observation"], "found")
        self.assertEqual(value["counts"]["currentMetadataCandidates"], 0)
        self.assertEqual(value["counts"]["relatedCertificates"], 2)

    def test_missing_to_many_total_or_any_pagination_is_inconclusive(self):
        changes = [lambda p: p.pop("meta"), lambda p: p["meta"]["paging"].update(total=True),
            lambda p: p["meta"]["paging"].update(total=2), lambda p: p["links"].update(next="https://other.invalid/next"),
            lambda p: p["data"][0]["relationships"]["certificates"].pop("meta"),
            lambda p: p["data"][0]["relationships"]["certificates"]["meta"]["paging"].update(total=2),
            lambda p: p["data"][0]["relationships"]["certificates"].update(links={"next": "https://api.appstoreconnect.apple.com/v1/profiles"}),
            lambda p: p["data"][0]["relationships"]["bundleId"].update(meta={"paging": {"total": 2}}),
            lambda p: p["data"][0]["relationships"]["bundleId"].update(links={"next": ""})]
        for change in changes:
            data = page(); change(data)
            self.assertEqual(observe(data), profiles.unavailable("inconclusive"))
        empty = page([], [])
        self.assertEqual(observe(empty)["observation"], "not-returned")
        self.assertEqual(set(observe(empty)["counts"].values()), {0})

    def test_exact_included_union_duplicate_and_contradictory_identifiers(self):
        changes = [lambda p: p["included"].pop(), lambda p: p["included"].append(certificate("extra")),
            lambda p: p["included"].append(copy.deepcopy(p["included"][0])),
            lambda p: p["data"].append(copy.deepcopy(p["data"][0])),
            lambda p: p["data"][0]["relationships"]["certificates"]["data"].append({"type": "certificates", "id": "certificate-1"}),
            lambda p: p["included"][0]["attributes"].update(seedId="not-a-seed"),
            lambda p: p["included"][1]["attributes"].update(certificateType="DEVELOPMENT"),
            lambda p: p["data"][0]["attributes"].update(profileType="IOS_APP_DEVELOPMENT")]
        for change in changes:
            data = page(); change(data); data["meta"]["paging"]["total"] = len(data["data"])
            self.assertEqual(observe(data), profiles.unavailable("inconclusive"))
        conflicting = page([profile(), profile(2, bundle_resource="duplicate-bundle")],
                           [bundle_row(), certificate(), bundle_row("duplicate-bundle", seedId="XXXXX12345")])
        self.assertEqual(observe(conflicting), profiles.unavailable("inconclusive"))
        duplicate_uuid = page([profile(), profile(2, uuid=profile()["attributes"]["uuid"])])
        self.assertEqual(observe(duplicate_uuid), profiles.unavailable("inconclusive"))

    def test_unsolicited_content_is_rejected_before_any_download_capable_parser(self):
        for target, attribute in (("profile", "profileContent"), ("certificate", "certificateContent"),
                                  ("bundle", "teamId"), ("profile", "extra")):
            data = page()
            row = data["data"][0] if target == "profile" else data["included"][1 if target == "certificate" else 0]
            row["attributes"][attribute] = "PRIVATE_UNSOLICITED_CONTENT"
            with patch.object(api.Profile, "parse") as parse, patch.object(api, "_content") as decode:
                self.assertEqual(observe(data), profiles.unavailable("inconclusive"))
                parse.assert_not_called(); decode.assert_not_called()

    def test_raw_duplicate_members_cannot_be_hidden_by_sdk_normalization(self):
        for raw in (b'{"data":[{"hidden":1}],"data":[],"included":[],"links":{},"meta":{"paging":{"total":0}}}',
                    api.canonical(page()).replace(b'"profileState":"ACTIVE"', b'"profileState":"INVALID","profileState":"ACTIVE"'),
                    api.canonical(page()).replace(b'"total":1', b'"total":2,"total":1', 1)):
            json.loads(raw)  # An ordinary SDK decoder accepts/collapses these.
            self.assertEqual(observe(raw), profiles.unavailable("inconclusive"))

    def test_certificate_reference_occurrences_are_bounded_separately_from_unique_resources(self):
        ids = tuple(f"c{n}" for n in range(50))
        data = page([profile(n, certificates=ids) for n in range(1, 9)], [bundle_row(), *(certificate(value) for value in ids)])
        self.assertLess(len(api.canonical(data)), bundle.RAW_LIMIT)
        self.assertEqual(observe(data)["counts"]["relatedCertificates"], 50)  # 400 links, 50 distinct.
        data["data"].append(profile(9, certificates=("c0",)))
        data["meta"]["paging"]["total"] = 9
        self.assertEqual(observe(data), profiles.unavailable("inconclusive"))  # 401 links.

    def test_denied_unknown_wrong_context_and_output_bounds_never_become_absence(self):
        for status in (401, 403):
            self.assertEqual(observe(b"{}", status=status), profiles.unavailable("not-permitted"))
            self.assertEqual(observe(b"{}", status=status, failure="provider_request_unconfirmed"), profiles.unavailable("not-permitted"))
        for status in (204, 301, 404, 409, 429, 500):
            self.assertEqual(observe(page([], []), status=status), profiles.unavailable("inconclusive"))
        for options in ({"context": "b" * 64}, {"bundle_id": "com.example.other"}):
            self.assertEqual(observe(page(), **options), profiles.unavailable("inconclusive"))
        self.assertEqual(observe(b" " * (bundle.RAW_LIMIT + 1)), profiles.unavailable("inconclusive"))

    def test_public_projection_is_closed_and_never_reports_provider_names_or_signing_ready(self):
        findings = [Finding("credential-material.apple-p8", Status.PASS, "PRIVATE", details={"secret": "PRIVATE"})]
        good = profiles.project_result(findings, observe(page()))
        self.assertTrue(profiles.valid_result(good)); wire.validate_result(good, platform="ios", query=profiles.QUERY)
        self.assertNotIn("PRIVATE", json.dumps(good))
        for other in (None, bundle.QUERY):
            with self.assertRaises(ValueError): wire.validate_result(good, platform="ios", query=other)
        for mutate in (lambda v: v["profileReuse"]["counts"].update(currentMetadataCandidates=2),
                       lambda v: v["profileReuse"].update(observation="not-returned"),
                       lambda v: v["profileReuse"].update(checkedAt="2026-02-30T00:00:00.000000Z"),
                       lambda v: v["profileReuse"].update(privateKeyMatched=True), lambda v: v.update(observation="found"),
                       lambda v: v["findings"].append({"check": "store-access", "status": "PASS"})):
            value = copy.deepcopy(good); mutate(value); self.assertFalse(profiles.valid_result(value))


class ProfileMetadataOriginalOwnerTests(unittest.TestCase):
    @contextmanager
    def original_query(self):
        actual_request = original.request
        def selected(root, runtime):
            value = actual_request(root, runtime); value["context"].update(platform="ios", query=profiles.QUERY)
            return value
        with patch.object(original, "request", side_effect=selected), original.DesktopStorePreflightTests().original(platform="ios") as values:
            yield values

    def commands(self, operation, final):
        return bundle_tests.BundleReadOriginalOwnerTests.fake_commands(self, operation, final)

    def test_real_original_run_uses_same_seven_commands_selected_material_and_finality(self):
        with self.original_query() as (_, _, runtime, source, operation):
            def final(argv, kwargs):
                self.assertEqual(tuple(argv), profiles.fixed_argv(runtime / "store/tooling"))
                self.assertEqual(kwargs["output_limit"], bundle.FRAME_LIMIT); self.assertFalse(kwargs["text"])
                env = kwargs["environ"]
                self.assertEqual(env["MOBILE_RELEASE_ASC_KEY_ID"], original.apple_material()[1].decode())
                self.assertNotIn("MOBILE_RELEASE_PREFLIGHT_READBACK_PATH", env)
                self.assertNotIn("HTTPS_PROXY", env); self.assertNotIn("MOBILE_RELEASE_STORE_MODE", env)
                return subprocess.CompletedProcess(argv, 0, stdout=bundle_tests.frame(api.canonical(page()),
                    context=env["MOBILE_RELEASE_ASC_BUNDLE_READ_CONTEXT"]), stderr=b"")
            calls, call = self.commands(operation, final)
            with patch("mobile_release._command_process.run_command", side_effect=call), \
                    patch.object(profiles, "datetime") as clock, patch.dict(os.environ, {"HTTPS_PROXY": "https://other.invalid"}):
                clock.now.return_value = NOW; operation.run()
            self.assertEqual(len(calls), 7)
            self.assertEqual([scratch.layout for scratch in operation.scratches], ["online-runner", "store-selection", "store-selection", "online-runner"])
            self.assertEqual(operation.report["profileReuse"], observe(page()))
            self.assertTrue(operation.closed()); self.assertIsNone(operation.terminal()["result"])  # Input/handlers still owe joins.
            with patch("mobile_release._command_process.run_command") as again:
                with self.assertRaises(ValueError): operation.run()
                again.assert_not_called()
        self.assertTrue(source.material_closed())

    def test_failed_selected_key_validator_means_not_checked_not_missing_resources(self):
        with self.original_query() as (_, _, _, _, operation):
            with patch("mobile_release._command_process.run_command", return_value=subprocess.CompletedProcess([], 1, stdout="PRIVATE", stderr="PRIVATE")) as call:
                operation.run()
            self.assertEqual(call.call_count, 1)
            self.assertEqual(operation.report["profileReuse"], profiles.unavailable("not-checked"))
            self.assertNotIn("PRIVATE", json.dumps(operation.report))

    def test_source_post_drift_vetoes_success_shaped_metadata(self):
        with self.original_query() as (_, root, _, _, operation):
            def final(argv, kwargs):
                path = root / "release/version.properties"; path.write_bytes(path.read_bytes() + b"\n")
                return subprocess.CompletedProcess(argv, 0, stdout=bundle_tests.frame(api.canonical(page()),
                    context=kwargs["environ"]["MOBILE_RELEASE_ASC_BUNDLE_READ_CONTEXT"]), stderr=b"")
            calls, call = self.commands(operation, final)
            with patch("mobile_release._command_process.run_command", side_effect=call):
                with self.assertRaises(service._Refused): operation.run()
            self.assertEqual(len(calls), 7); self.assertIsNone(operation.report); self.assertTrue(operation.closed())

    def test_original_stop_prevents_all_commands(self):
        operation = source = None
        with self.assertRaises((ProcessError, KeyboardInterrupt)), self.original_query() as (_, _, _, source, operation):
            source.buffer.extend(b"!")
            with patch("mobile_release._command_process.run_command") as call:
                try: operation.run()
                finally: call.assert_not_called()
        self.assertEqual(source.stop_reason, "cancelled")
        self.assertTrue(operation.closed()); self.assertTrue(source.material_closed())

    def test_unknown_command_keeps_no_metadata_result_and_cannot_replay(self):
        with self.assertRaises(ProcessError), self.original_query() as (_, _, _, _, operation):
            def final(_argv, _kwargs): raise ProcessOutcomeUnknown("synthetic unknown return")
            calls, call = self.commands(operation, final)
            with patch("mobile_release._command_process.run_command", side_effect=call):
                try: operation.run()
                finally:
                    self.assertEqual(len(calls), 7); self.assertIsNone(operation.report)
                    self.assertIsNone(operation.terminal()["result"])

    def test_profile_query_does_not_widen_prepare_execute_reconcile_or_bundle_wrapper(self):
        from mobile_release import _desktop_store_prepare_protocol as prepare
        from mobile_release import _desktop_store_execute_protocol as execute
        from mobile_release import _desktop_store_reconcile_protocol as reconcile
        with original.DesktopStorePreflightTests().files(platform="ios") as (_, root, runtime):
            value = original.request(root, runtime); value["context"]["platform"] = "ios"
            access = wire.parse_request(original.encode(value)).context
            query = {**access, "query": profiles.QUERY}
            with self.assertRaises(ValueError): wire.context(query, apple_access=True)
            self.assertEqual(wire.context(query, apple_access=True, bundle_query=True), query)
            candidate = {**access, "operation": "local-store-prepare", "candidateOperationId": "12345678-1234-4234-9234-123456789abc",
                         "candidateSha256": "d" * 64, "confirmation": "candidate:ios:1.2.3:42"}
            execution = {**candidate, "operation": "local-store-execute", "intentSha256": "e" * 64}
            recovery = {**candidate, "operation": "local-store-reconcile", "intentSha256": "e" * 64}
            with patch("mobile_release._command_process.run_command") as call:
                for parse, context in ((lambda c: prepare.context(c, apple_prepare=True), candidate),
                                       (execute.context, execution), (reconcile.context, recovery)):
                    self.assertEqual(parse(context), context)
                    with self.assertRaises(ValueError): parse({**context, "query": profiles.QUERY})
                call.assert_not_called()
        with self.original_query() as (_, _, _, _, operation), patch("mobile_release._command_process.run_command") as call:
            with self.assertRaises(api.ProvisioningError): bundle.read_saved_bundle_id(operation, None, None)
            call.assert_not_called()
