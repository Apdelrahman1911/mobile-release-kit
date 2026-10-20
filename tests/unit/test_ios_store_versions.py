"""Raw synthetic provider DATA only; no HTTP, keys, subprocesses or native receipts."""
import base64
import copy
from contextlib import contextmanager, nullcontext
import json
import os
import subprocess
import unittest
from dataclasses import replace
from urllib.parse import urlencode
from unittest.mock import patch

from mobile_release import ios_store_versions as v
from mobile_release import version_policy as p
from mobile_release import desktop_store_preflight as store
from mobile_release import _desktop_store_preflight_protocol as wire
from mobile_release.owned_process import ProcessError, ProcessOutcomeUnknown
from . import test_desktop_store_preflight as original
from . import test_apple_provisioning_bundle_read as bundle_original

APP, BUNDLE, CONTEXT, IDENTITY = "1234567890", "com.example.version", "a" * 64, "b" * 64


def relation(kind, resource):
    return {"data": {"type": kind, "id": resource} if resource is not None else None}


def app():
    return {"type": "apps", "id": APP, "attributes": {"bundleId": BUNDLE}}


def train(name="1.2.3", resource="train1", platform="IOS"):
    return {"type": "preReleaseVersions", "id": resource, "attributes": {"version": name, "platform": platform},
            "relationships": {"app": relation("apps", APP)}}


def build(number="8", resource="build1", train_id="train1"):
    return {"type": "builds", "id": resource, "attributes": {"version": number},
            "relationships": {"app": relation("apps", APP), "preReleaseVersion": relation("preReleaseVersions", train_id)}}


def upload(number="9", name="1.2.3", resource="upload1"):
    return {"type": "buildUploads", "id": resource, "attributes": {
        "cfBundleVersion": number, "cfBundleShortVersionString": name, "platform": "IOS"},
        "relationships": {"build": relation("builds", None)}}


def version(name="1.3.0", resource="version1"):
    return {"type": "appStoreVersions", "id": resource, "attributes": {"versionString": name, "platform": "IOS"}}


def collection(rows=(), included=(), *, total=None, following=None):
    result = {"data": list(rows), "links": {"next": following}, "meta": {"paging": {
        "total": len(rows) if total is None else total, "limit": 200}}}
    if included:
        result["included"] = list(included)
    return result


def page(kind, body, *, cursor=None, status=200):
    raw = body if type(body) is bytes else p.canonical(body)
    return {"step": kind, "request": v.request(kind, APP, cursor=cursor), "response": {
        "status": status, "bodyBase64": base64.b64encode(raw).decode(), "failure": None}}


def frame(*, builds=(), includes=(), uploads=(), versions=(), pages=None):
    if pages is None:
        pages = [page("app-before", {"data": app()}), page("builds", collection(builds, includes)),
                 page("buildUploads", collection(uploads)), page("appStoreVersions", collection(versions)),
                 page("app-after", {"data": app()})]
    return {"schemaVersion": 1, "scope": v.SCOPE, "contextSha256": CONTEXT,
            "appStoreAppId": APP, "bundleId": BUNDLE, "pages": pages, "queryFinished": True}


def observe(value):
    raw = value if type(value) is bytes else p.canonical(value)
    return v.summary_from_frame(raw, context_sha256=CONTEXT, app_id=APP, bundle_id=BUNDLE)


class IOSCurrentInventoryTests(unittest.TestCase):
    def test_ruby_frame_terminator_preserves_exact_framing_and_original_byte_limit(self):
        raw = p.canonical(frame(uploads=[upload()]))
        expected = observe(raw)
        self.assertEqual((expected["observation"], expected["maxBuild"]), ("observed", 9))
        self.assertEqual(observe(raw + b"\n"), expected)
        for changed in (raw + b"\n\n", raw + b"\r\n", raw + b" \n",
                        raw + b"\n ", raw + b"\n" + raw + b"\n", b"\n" + raw + b"\n", b"\n"):
            with self.subTest(raw=changed[-12:]):
                self.assertEqual(observe(changed), v.unavailable("inconclusive"))
        # A terminator is part of the original capture, not free extra bytes.
        with patch.object(v, "FRAME_LIMIT", len(raw)):
            self.assertEqual(observe(raw), expected)
            self.assertEqual(observe(raw + b"\n"), v.unavailable("inconclusive"))
        with patch.object(v, "FRAME_LIMIT", len(raw) + 1):
            self.assertEqual(observe(raw + b"\n"), expected)
        with self.assertRaises(ValueError):
            v._json(b"{}\n")  # Raw provider-page grammar was not widened.

    def test_three_current_collections_include_every_train_and_pending_null_build(self):
        value = frame(builds=[build(), build("12", "build2", "train2")],
            includes=[app(), train(), train("0.9.0", "train2")],
            uploads=[upload("14", "1.3.0")], versions=[version("2.0.0")])
        result = observe(value)
        self.assertEqual(result["observation"], "observed")
        self.assertEqual((result["maxBuild"], result["marketingVersion"]), (14, "2.0.0"))
        self.assertEqual(result["counts"], {"builds": 2, "buildUploads": 1, "appStoreVersions": 1})
        self.assertEqual(result["historicalUniqueness"], "not-established")
        for kind in v.COLLECTIONS:
            query = v.request(kind, APP)["query"]
            self.assertFalse(any(key in query for key in ("filter[version]", "filter[expired]", "filter[state]",
                                                         "filter[processingState]", "filter[preReleaseVersion.version]")))

    def test_marketing_only_and_empty_are_distinct_neither_claims_unused_app(self):
        empty = observe(frame())
        marketing = observe(frame(versions=[version("3.2.1")]))
        self.assertEqual(empty["observation"], "observed")
        self.assertEqual((empty["maxBuild"], empty["marketingVersion"]), (0, None))
        self.assertEqual((marketing["maxBuild"], marketing["marketingVersion"]), (0, "3.2.1"))
        for result in (empty, marketing):
            self.assertTrue(v.valid_summary(result))
            self.assertEqual(result["historicalUniqueness"], "not-established")
            self.assertNotIn("available", result.values())

    def test_exact_two_page_traversal_preserves_count_and_rejects_changed_total_or_third_page(self):
        expected = v.request("buildUploads", APP, cursor="page2")
        next_url = v.ORIGIN + expected["path"] + "?" + urlencode(expected["query"])
        pages = frame()["pages"]
        pages[2:3] = [page("buildUploads", collection([upload()], total=2, following=next_url)),
                      page("buildUploads", collection([upload("11", resource="upload2")], total=2), cursor="page2")]
        result = observe(frame(pages=pages))
        self.assertEqual((result["observation"], result["maxBuild"]), ("observed", 11))
        bad = copy.deepcopy(pages)
        bad[3] = page("buildUploads", collection([upload("11", resource="upload2")], total=3), cursor="page2")
        self.assertEqual(observe(frame(pages=bad))["observation"], "inconclusive")
        for total in (401, 99999):
            bad = copy.deepcopy(pages)
            bad[2] = page("buildUploads", collection([upload()], total=total, following=next_url))
            self.assertEqual(observe(frame(pages=bad))["observation"], "too-many")
        third = v.request("buildUploads", APP, cursor="page3")
        bad = copy.deepcopy(pages)
        bad[2] = page("buildUploads", collection([upload()], total=3, following=next_url))
        bad[3] = page("buildUploads", collection([upload("11", resource="upload2")], total=3,
                      following=v.ORIGIN + third["path"] + "?" + urlencode(third["query"])), cursor="page2")
        self.assertEqual(observe(frame(pages=bad))["observation"], "too-many")

    def test_foreign_app_missing_join_or_unjoinable_processing_row_never_skipped(self):
        good = frame(builds=[build()], includes=[app(), train()])
        for change in (lambda row: row["relationships"]["app"].update(data={"type": "apps", "id": "999"}),
                       lambda row: row["relationships"]["preReleaseVersion"].update(data=None),
                       lambda row: row["relationships"].pop("preReleaseVersion")):
            row = build(); change(row)
            self.assertEqual(observe(frame(builds=[row], includes=[app(), train()]))["observation"], "inconclusive")
        for prefix in (0, 4):
            bad = copy.deepcopy(good)
            wrong = app(); wrong["attributes"]["bundleId"] = "com.example.other"
            bad["pages"][prefix] = page("app-before" if prefix == 0 else "app-after", {"data": wrong})
            self.assertEqual(observe(bad)["observation"], "inconclusive")
        foreign = train(); foreign["relationships"]["app"] = relation("apps", "999")
        self.assertEqual(observe(frame(builds=[build()], includes=[app(), foreign]))["observation"], "inconclusive")
        self.assertEqual(observe(frame(builds=[build()], includes=[app()]))["observation"], "inconclusive")

    def test_non_ios_rows_only_excluded_after_exact_join_platform_never_guessed(self):
        result = observe(frame(builds=[build("bad")], includes=[app(), train(platform="MAC_OS")]))
        self.assertEqual(result["observation"], "observed")
        self.assertEqual(result["maxBuild"], 0)
        unknown = train(platform="NEW_UNKNOWN_PLATFORM")
        self.assertEqual(observe(frame(builds=[build()], includes=[app(), unknown]))["observation"], "inconclusive")

    def test_format_unsupported_preserves_manual_instead_of_coercing(self):
        for number in ("1.2", "0004", "4b1", "0", "-1", "2147483647", 7, None):
            result = observe(frame(uploads=[upload(number)]))
            self.assertEqual(result["observation"], "unsupported-format")
            self.assertIsNone(result["maxBuild"])
        for name in ("release-one", "1", None):
            self.assertEqual(observe(frame(versions=[version(name)]))["observation"], "unsupported-format")

    def test_raw_duplicates_missing_counts_wrong_origin_cycles_and_extra_pages_refuse(self):
        malformed = b'{"data":[],"data":[],"links":{},"meta":{"paging":{"total":0}}}'
        good = frame()
        bad = copy.deepcopy(good); bad["pages"][1] = page("builds", malformed)
        self.assertEqual(observe(bad)["observation"], "inconclusive")
        for link in ("https://other.invalid/v1/builds?cursor=a", "http://api.appstoreconnect.apple.com/v1/builds?cursor=a",
                     v.ORIGIN + "/v1/builds?cursor=a&cursor=b", v.ORIGIN + "/v1/builds?cursor=a#x"):
            bad = copy.deepcopy(good)
            bad["pages"][1] = page("builds", collection([build()], [app(), train()], total=2, following=link))
            self.assertEqual(observe(bad)["observation"], "inconclusive")
        for body in ({"data": [], "links": {}}, collection([upload(), upload()])):
            bad = copy.deepcopy(good); bad["pages"][2] = page("buildUploads", body)
            self.assertEqual(observe(bad)["observation"], "inconclusive")
        bad = copy.deepcopy(good); bad["pages"].append(copy.deepcopy(bad["pages"][-1]))
        self.assertEqual(observe(bad)["observation"], "inconclusive")

    def test_full_private_bounds_authorization_and_scope_never_become_zero_floor(self):
        for status in ("FAIL", "MISSING", "BLOCKED", "INVALID"):
            result = v.project_result([], observe(frame()))
            result["findings"] = [{"check": "credential-format", "status": status}]
            self.assertFalse(v.valid_result(result))
            result["currentVersions"] = v.unavailable("not-checked")
            self.assertTrue(v.valid_result(result))
        for finished in (False, None, 1):
            bad = frame(); bad["queryFinished"] = finished
            self.assertEqual(observe(bad)["observation"], "inconclusive")
        for status in (401, 403, 404, 429, 500):
            bad = frame(); bad["pages"][1]["response"]["status"] = status
            self.assertEqual(observe(bad)["observation"], "not-permitted" if status in (401, 403) else "inconclusive")
        for name, value in (("scope", "application-all-builds"), ("contextSha256", "c" * 64),
                            ("appStoreAppId", "999"), ("bundleId", "com.example.other")):
            bad = frame(); bad[name] = value
            self.assertEqual(observe(bad)["observation"], "inconclusive")
        for raw in (b" " * (v.FRAME_LIMIT + 1), b"\xff", b'{"data":NaN}'):
            self.assertEqual(observe(raw)["observation"], "inconclusive")

    def test_explicit_v2_observation_marketing_only_age_and_context_not_v1(self):
        original = v.CurrentInventory(IDENTITY, CONTEXT, "c" * 64, 100, 0, "3.2.1", (0, 0, 1))
        self.assertEqual(v.CurrentInventory.parse(original.value()), original)
        selected = p.VersionPolicy("automatic", (p.RefRule("refs/heads/main", "build"),), store_scope=v.POLICY_SCOPE)
        self.assertEqual(v.constraints((original,), ("ios",), IDENTITY, CONTEXT, selected, now=100), (0, ("3.2.1",)))
        with self.assertRaises(p.VersionPolicyError): p.StoreObservation.parse(original.value())
        with self.assertRaises(p.VersionPolicyError): p.store_constraints((original,), ("ios",), IDENTITY, selected, now=100)
        for changes in ({"now": 99}, {"now": 1001}, {"context_revision": "d" * 64}, {"identity_revision": "d" * 64},
                        {"enabled": ("android", "ios")}):
            args = dict(enabled=("ios",), identity_revision=IDENTITY, context_revision=CONTEXT, selected=selected, now=100)
            args.update(changes)
            with self.assertRaises(p.VersionPolicyError): v.constraints((original,), **args)
        consumed = replace(original, max_build=10, counts=(1, 0, 1))
        with self.assertRaises(p.VersionPolicyError):
            v.check_reserved(p.ReleaseVersion("3.2.1", 10), selected, enabled=("ios",), identity_revision=IDENTITY,
                             context_revision=CONTEXT, observations=(consumed,), now=100)


class IOSCurrentInventoryOriginalTests(unittest.TestCase):
    """Actual original file/input/cancellation owners; every command is fake."""

    @contextmanager
    def original_query(self, *, alter_config=None):
        request = original.request
        def selected(root, runtime):
            # Inert executable bytes, never executed. The genuine runtime reader
            # still checks the fixed selected resource rather than a test shim.
            (runtime / "store/tooling/fastlane/apple_store_versions.rb").write_bytes(b"inert reader\n")
            if alter_config:
                path = root / "release/mobile-release.json"
                data = json.loads(path.read_bytes()); alter_config(data)
                path.write_bytes(p.canonical(data) + b"\n")
            value = request(root, runtime)
            value["context"].update(platform="ios", query=v.QUERY)
            return value
        with patch.object(original, "request", side_effect=selected), original.DesktopStorePreflightTests().original(platform="ios") as values:
            yield values

    def raw(self, environment, *, marketing=False):
        with patch(__name__ + ".BUNDLE", environment["MOBILE_RELEASE_ASC_BUNDLE_ID"]):
            value = frame(versions=[version()] if marketing else [], uploads=[upload()])
        value["contextSha256"] = environment["MOBILE_RELEASE_ASC_BUNDLE_READ_CONTEXT"]
        # Real AppleStoreVersions::Input.frame writes this single terminal LF.
        return p.canonical(value) + b"\n"

    def test_same_original_seven_commands_selected_p8_and_raw_bound_no_new_owner(self):
        with self.original_query() as (_, _, runtime, source, operation):
            def final(argv, kwargs):
                self.assertEqual(tuple(argv), v.fixed_argv(runtime / "store/tooling"))
                self.assertFalse(kwargs["text"])
                self.assertEqual(kwargs["output_limit"], v.FRAME_LIMIT)
                env = kwargs["environ"]
                self.assertEqual(env["MOBILE_RELEASE_ASC_APP_ID"], APP)
                self.assertEqual(base64.b64decode(env["MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"]), original.apple_material()[0])
                self.assertEqual(env["MOBILE_RELEASE_ASC_KEY_ID"], original.apple_material()[1].decode())
                self.assertEqual(env["MOBILE_RELEASE_ASC_ISSUER_ID"], original.apple_material()[2].decode())
                for key in ("HTTPS_PROXY", "MOBILE_RELEASE_STORE_MODE", "RUBYOPT", "GH_TOKEN"):
                    self.assertNotIn(key, env)
                return subprocess.CompletedProcess(argv, 0, stdout=self.raw(env, marketing=True), stderr=b"")
            calls, call = bundle_original.BundleReadOriginalOwnerTests.fake_commands(self, operation, final)
            with patch("mobile_release._command_process.run_command", side_effect=call), patch.dict(os.environ, {
                    "HTTPS_PROXY": "https://not-used.invalid", "MOBILE_RELEASE_STORE_MODE": "execute", "GH_TOKEN": "INERT"}):
                operation.run()
            self.assertEqual(len(calls), 7)
            summary = operation.report["currentVersions"]
            self.assertEqual((summary["observation"], summary["maxBuild"], summary["marketingVersion"]), ("observed", 9, "1.3.0"))
            wire.validate_result(operation.report, platform="ios", query=v.QUERY)
            self.assertNotIn("INERT", json.dumps(operation.report))
            self.assertNotIn("upload1", json.dumps(operation.report))
            self.assertTrue(operation.closed())
            self.assertIsNone(operation.terminal()["result"])  # Input/handlers are not yet returned.
            with patch("mobile_release._command_process.run_command") as repeat:
                with self.assertRaises(ValueError): operation.run()
                repeat.assert_not_called()
        self.assertTrue(source.material_closed())

    def test_missing_app_id_or_invalid_key_never_calls_current_inventory(self):
        def no_app(data):
            data["ios"].pop("appStoreAppId")
            data["ios"]["identityStatus"] = "unverified"
        for missing_app in (False, True):
            with self.subTest(missing_app=missing_app), self.original_query(
                    alter_config=no_app if missing_app else None) as (_, _, _, _, operation):
                with patch("mobile_release._command_process.run_command", return_value=subprocess.CompletedProcess(
                        [], 0 if missing_app else 1, stdout="PRIVATE", stderr="")) as run:
                    operation.run()
                self.assertEqual(run.call_count, 1)
                self.assertEqual(operation.report["currentVersions"], v.unavailable("not-checked"))
                self.assertNotIn("PRIVATE", json.dumps(operation.report))

    def test_actual_source_postcheck_vetoes_complete_inventory(self):
        with self.original_query() as (_, root, _, _, operation):
            def final(argv, kwargs):
                raw = self.raw(kwargs["environ"])
                path = root / "release/version.properties"; path.write_bytes(path.read_bytes() + b"\n")
                return subprocess.CompletedProcess(argv, 0, stdout=raw, stderr=b"")
            calls, call = bundle_original.BundleReadOriginalOwnerTests.fake_commands(self, operation, final)
            with patch("mobile_release._command_process.run_command", side_effect=call):
                with self.assertRaises(store._Refused): operation.run()
            self.assertEqual(len(calls), 7)
            self.assertIsNone(operation.report)

    def test_unknown_command_or_wrong_raw_context_cannot_mint_currentness(self):
        for unknown in (False, True):
            scope = self.assertRaises(ProcessError) if unknown else nullcontext()
            with self.subTest(unknown=unknown), scope, self.original_query() as (_, _, _, _, operation):
                def final(argv, kwargs):
                    if unknown: raise ProcessOutcomeUnknown("synthetic unknown")
                    value = json.loads(self.raw(kwargs["environ"])); value["contextSha256"] = "f" * 64
                    return subprocess.CompletedProcess(argv, 0, stdout=p.canonical(value), stderr=b"")
                calls, call = bundle_original.BundleReadOriginalOwnerTests.fake_commands(self, operation, final)
                with patch("mobile_release._command_process.run_command", side_effect=call):
                    try: operation.run()
                    finally:
                        self.assertEqual(len(calls), 7)
                        self.assertIsNone(operation.terminal()["result"])
                self.assertEqual(operation.report["currentVersions"], v.unavailable("inconclusive"))

    def test_new_query_never_widens_other_store_operations_or_access_consent(self):
        with original.DesktopStorePreflightTests().files(platform="ios") as (_, root, runtime):
            value = original.request(root, runtime)
            value["context"].update(platform="ios", query=v.QUERY)
            parsed = wire.parse_request(original.encode(value))
            with self.assertRaises(ValueError): wire.context(parsed.context, apple_access=True)
            for query in (None, "ios-all-history", "create-build"):
                changed = copy.deepcopy(value); changed["context"]["query"] = query
                with self.assertRaises(ValueError): wire.parse_request(original.encode(changed))
            for scope in (None, "bundle-id-registration", "app-store-profile-reuse"):
                with self.assertRaises(ValueError): wire.validate_result(v.project_result([], v.unavailable("not-checked")), platform="ios", query=scope)


if __name__ == "__main__":
    unittest.main()
