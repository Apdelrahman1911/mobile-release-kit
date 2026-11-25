"""Original synthetic file/input owners + fake command responses only.

No key generation, installed Ruby, Apple requests or native finality evidence.
Shared-hook tests require the actual Root wiring patch, not extracted functions.
"""
import base64
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from mobile_release import apple_provisioning_api as api
from mobile_release import apple_provisioning_bundle_read as bundle
from mobile_release import _desktop_store_preflight_protocol as wire
from mobile_release import desktop_store_preflight as service
from mobile_release.config import ReleaseConfig
from mobile_release.owned_process import ProcessError, ProcessOutcomeUnknown
from mobile_release.reporting import Finding, Status
from . import test_desktop_store_preflight as original
from .helpers import ios_config

CONTEXT = "a" * 64
BUNDLE = "com.example.reader"


def page(rows=None):
    rows = [] if rows is None else rows
    return {"data": rows, "links": {"self": "https://api.appstoreconnect.apple.com/v1/bundleIds"},
            "meta": {"paging": {"total": len(rows), "limit": 200}}}


def row(**attributes):
    return {"type": "bundleIds", "id": "synthetic-resource", "attributes": {
        "identifier": BUNDLE, "platform": "IOS", "seedId": "ZZZZZ12345", **attributes}}


def frame(body=None, *, status=200, context=CONTEXT, bundle_id=BUNDLE, failure=None):
    if body is None:
        body = api.canonical(page())
    return api.canonical({"schemaVersion": 1, "contextSha256": context, "bundleId": bundle_id,
        "response": {"status": status, "bodyBase64": base64.b64encode(body).decode() if failure is None else None,
                     "failure": failure}})


def observe(body, **kwargs):
    return bundle.observation_from_frame(frame(body, **kwargs), context_sha256=CONTEXT, bundle_id=BUNDLE)


class BundleReadDataTests(unittest.TestCase):
    def test_exact_single_page_only_and_seed_is_not_team_proof(self):
        self.assertEqual(observe(api.canonical(page())), "not-returned")
        for platform in ("IOS", "UNIVERSAL"):
            self.assertEqual(observe(api.canonical(page([row(platform=platform)]))), "found")
        self.assertEqual(bundle.OBSERVATIONS, {"found", "not-returned", "not-permitted", "inconclusive", "not-checked"})
        # The comparison takes NO selected team or claimed team-authority input.
        self.assertNotIn("team", frame(api.canonical(page([row()]))).decode().lower())

    def test_partial_counts_pagination_and_foreign_resources_are_inconclusive(self):
        changes = [lambda p: p.pop("meta"), lambda p: p.pop("links"),
            lambda p: p["meta"]["paging"].update(total=True), lambda p: p["meta"]["paging"].update(total=2),
            lambda p: p["links"].update(next="https://other.invalid/v1/bundleIds?cursor=next"),
            lambda p: p["links"].update(next="https://api.appstoreconnect.apple.com/v1/certificates"),
            lambda p: p["links"].update(next=""), lambda p: p.update(errors=[]),
            lambda p: p["data"][0]["attributes"].update(identifier="com.example.other"),
            lambda p: p["data"][0]["attributes"].update(platform="MAC_OS"),
            lambda p: p["data"][0]["attributes"].update(seedId="invalid"),
            lambda p: p["data"][0]["attributes"].update(teamId="ZZZZZ12345"),
            lambda p: p["data"][0].update(type="certificates")]
        for change in changes:
            p = page([row()]); change(p)
            self.assertEqual(observe(api.canonical(p)), "inconclusive")
        for rows in ([row(), row()], [row(), {**row(), "id": "different"}], [row()] * 201):
            self.assertEqual(observe(api.canonical(page(rows))), "inconclusive")

    def test_duplicate_raw_members_cannot_be_hidden_by_sdk_json_collapse(self):
        body = b'{"data":[{"private":"earlier"}],"data":[],"links":{},"meta":{"paging":{"total":0}}}'
        # A normal SDK parser would hide the first data member and look empty.
        self.assertEqual(json.loads(body)["data"], [])
        self.assertEqual(observe(body), "inconclusive")
        for raw in (api.canonical(page()).replace(b'"total":0', b'"total":1,"total":0'),
                    api.canonical(page([row()])).replace(b'"identifier":', b'"identifier":"com.example.other","identifier":')):
            self.assertEqual(observe(raw), "inconclusive")

    def test_authorization_errors_are_never_absence_and_other_statuses_are_unknown(self):
        for status in (401, 403):
            self.assertEqual(observe(b'{"errors":[{"detail":"PRIVATE"}]}', status=status), "not-permitted")
            self.assertEqual(observe(b"", status=status, failure="provider_request_unconfirmed"), "not-permitted")
        for status in (204, 301, 404, 409, 429, 500, 503):
            self.assertEqual(observe(api.canonical(page()), status=status), "inconclusive")
            self.assertEqual(observe(b"", status=status, failure="provider_request_unconfirmed"), "inconclusive")

    def test_bounded_original_envelope_exact_context_and_canonical_encoding(self):
        good = frame()
        for raw in (b"", b" " * (bundle.FRAME_LIMIT + 1), good.replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1'),
                    frame(context="b" * 64), frame(bundle_id="com.example.other")):
            self.assertEqual(bundle.observation_from_frame(raw, context_sha256=CONTEXT, bundle_id=BUNDLE), "inconclusive")
        for name, value in (("bodyBase64", "***"), ("bodyBase64", "e30=\n"), ("status", True),
                            ("failure", "PRIVATE"), ("nativeSettled", True)):
            bad = json.loads(good); bad["response"][name] = value
            self.assertEqual(bundle.observation_from_frame(api.canonical(bad), context_sha256=CONTEXT, bundle_id=BUNDLE), "inconclusive")
        for body in (b"x" * (bundle.RAW_LIMIT + 1), b'{"data":NaN}', b'{"data":[]', b'\xff',
                     b'{"nest":' + b'[' * 33 + b'0' + b']' * 33 + b'}'):
            self.assertEqual(observe(body), "inconclusive")

    def test_finite_public_projection_has_no_resource_private_details_or_authority(self):
        findings = [Finding("credential-material.apple-p8", Status.PASS, "PRIVATE", details={"token": "PRIVATE"})]
        for observation in bundle.OBSERVATIONS:
            result = bundle.project_result(findings, observation)
            self.assertTrue(bundle.valid_result(result))
            self.assertEqual(set(result), {"schemaVersion", "scope", "observation", "findings", "limitations"})
            self.assertNotIn("PRIVATE", json.dumps(result))
            wire.validate_result(result, platform="ios", query=bundle.QUERY)
            with self.assertRaises(ValueError): wire.validate_result(result, platform="ios")
        for observation in (None, "available", "ready", True):
            with self.assertRaises(api.ProvisioningError): bundle.project_result(findings, observation)
        result = bundle.project_result(findings, "found")
        result["findings"].append({"check": "store-access", "status": "PASS"})
        self.assertFalse(bundle.valid_result(result))

    def test_query_needs_saved_identifier_not_app_record_or_testflight_group(self):
        data = ios_config()
        data["ios"]["identityStatus"] = "unverified"
        for key in ("appStoreAppId", "externalTestFlightGroup", "teamId"):
            data["ios"].pop(key)
        config = ReleaseConfig(Path("/inert/config"), Path("/inert"), data)
        self.assertTrue(bundle.query_prerequisites(config))
        data["ios"]["identityStatus"] = "blocked"
        self.assertFalse(bundle.query_prerequisites(config))


class BundleReadOriginalOwnerTests(unittest.TestCase):
    @contextmanager
    def original_query(self, *, alter_config=None):
        actual_request = original.request
        def selected(root, runtime):
            if alter_config:
                path = root / "release/mobile-release.json"
                data = json.loads(path.read_bytes()); alter_config(data)
                path.write_bytes(api.canonical(data) + b"\n")
            value = actual_request(root, runtime)
            value["context"].update(platform="ios", query=bundle.QUERY)
            return value
        with patch.object(original, "request", side_effect=selected), original.DesktopStorePreflightTests().original(platform="ios") as values:
            yield values

    def fake_commands(self, operation, final):
        calls = []
        outputs = ("", "3.3.12", "4.0.16", "", "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2", "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2")
        endpoint = operation.source.work_end
        def call(argv, **kwargs):
            index = len(calls); calls.append((tuple(argv), kwargs))
            self.assertEqual(operation.source.work_end, endpoint)
            self.assertIs(kwargs["cancellation"], operation.guard)
            self.assertTrue(kwargs["capture"])
            self.assertLessEqual(kwargs["timeout"], 60)
            self.assertIsNone(kwargs["_evidence"])
            return final(argv, kwargs) if index == 6 else subprocess.CompletedProcess(argv, 0, stdout=outputs[index], stderr="")
        return calls, call

    def test_actual_closed_seven_commands_use_same_material_no_fastfile_or_readback(self):
        from mobile_release.credentials import APPLE_P8_CHECK
        def no_store_app(data):
            data["ios"]["identityStatus"] = "unverified"
            data["ios"].pop("appStoreAppId"); data["ios"].pop("externalTestFlightGroup")
        with self.original_query(alter_config=no_store_app) as (_, _, runtime, source, operation):
            def final(argv, kwargs):
                self.assertEqual(tuple(argv), bundle.fixed_argv(runtime / "store/tooling"))
                self.assertFalse(kwargs["text"])
                self.assertEqual(kwargs["output_limit"], bundle.FRAME_LIMIT)
                env = kwargs["environ"]
                self.assertEqual(base64.b64decode(env["MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"]), original.apple_material()[0])
                self.assertEqual(env["MOBILE_RELEASE_ASC_KEY_ID"], original.apple_material()[1].decode())
                self.assertEqual(env["MOBILE_RELEASE_ASC_ISSUER_ID"], original.apple_material()[2].decode())
                self.assertEqual(env["MOBILE_RELEASE_ASC_BUNDLE_ID"], BUNDLE)
                self.assertEqual(env["MOBILE_RELEASE_ASC_BUNDLE_READ_CONTEXT"], api.digest(api.canonical(operation.request.context)))
                for key in ("GITHUB_ACTIONS", "RUBYOPT", "SPACESHIP_CONNECT_API_IN_HOUSE", "MOBILE_RELEASE_STORE_MODE", "MOBILE_RELEASE_PREFLIGHT_READBACK_PATH", "HTTPS_PROXY"):
                    self.assertNotIn(key, env)
                return subprocess.CompletedProcess(argv, 0, stdout=frame(api.canonical(page([row()])), context=env["MOBILE_RELEASE_ASC_BUNDLE_READ_CONTEXT"]), stderr=b"")
            calls, call = self.fake_commands(operation, final)
            with patch("mobile_release._command_process.run_command", side_effect=call), patch.dict(os.environ, {"HTTPS_PROXY": "https://other.invalid", "MOBILE_RELEASE_STORE_MODE": "execute", "SPACESHIP_CONNECT_API_IN_HOUSE": "true"}):
                operation.run()
            self.assertEqual(len(calls), 7)
            self.assertEqual(calls[0][0][5], APPLE_P8_CHECK)
            self.assertEqual([s.layout for s in operation.scratches], ["online-runner", "store-selection", "store-selection", "online-runner"])
            self.assertEqual(operation.report, bundle.project_result([Finding("credential-material.apple-p8", Status.PASS, "DATA")], "found"))
            self.assertTrue(operation.closed())
            self.assertIsNone(operation.terminal()["result"])  # Original input/handlers not closed here.
            with patch("mobile_release._command_process.run_command") as again:
                with self.assertRaises(ValueError): operation.run()
                again.assert_not_called()
        self.assertTrue(source.material_closed())

    def test_bad_validator_prevents_query_without_treating_key_as_missing(self):
        with self.original_query() as (_, _, _, source, operation):
            with patch("mobile_release._command_process.run_command", return_value=subprocess.CompletedProcess([], 1, stdout="PRIVATE", stderr="PRIVATE")) as run:
                operation.run()
            self.assertEqual(run.call_count, 1)
            self.assertEqual(operation.report["observation"], "not-checked")
            self.assertNotIn("PRIVATE", json.dumps(operation.report))
        self.assertTrue(source.material_closed())

    def test_post_changed_source_vetoes_even_success_shaped_private_response(self):
        with self.original_query() as (_, root, _, _, operation):
            def final(argv, kwargs):
                path = root / "release/version.properties"; path.write_bytes(path.read_bytes() + b"\n")
                return subprocess.CompletedProcess(argv, 0, stdout=frame(context=kwargs["environ"]["MOBILE_RELEASE_ASC_BUNDLE_READ_CONTEXT"]), stderr=b"")
            calls, call = self.fake_commands(operation, final)
            with patch("mobile_release._command_process.run_command", side_effect=call):
                with self.assertRaises(service._Refused): operation.run()
            self.assertEqual(len(calls), 7)
            self.assertIsNone(operation.report)
            self.assertTrue(operation.closed())

    def test_stop_on_original_input_prevents_all_query_commands(self):
        operation = source = None
        with self.assertRaises((ProcessError, KeyboardInterrupt)), self.original_query() as (_, _, _, source, operation):
            source.buffer.extend(b"!")
            with patch("mobile_release._command_process.run_command") as run:
                try: operation.run()
                finally: run.assert_not_called()
        self.assertEqual(source.stop_reason, "cancelled")
        self.assertTrue(operation.closed())
        self.assertTrue(source.material_closed())

    def test_unknown_command_return_cannot_become_observation_or_repeat(self):
        with self.assertRaises(ProcessError), self.original_query() as (_, _, _, _, operation):
            def final(_argv, _kwargs):
                raise ProcessOutcomeUnknown("synthetic lost command return")
            calls, call = self.fake_commands(operation, final)
            with patch("mobile_release._command_process.run_command", side_effect=call):
                try: operation.run()
                finally:
                    self.assertEqual(len(calls), 7)
                    self.assertIsNone(operation.report)
                    self.assertIsNone(operation.terminal()["result"])

    def test_nonzero_stderr_wrong_frame_and_raw_duplicate_are_inconclusive(self):
        for mode in ("nonzero", "stderr", "wrong-context", "duplicate"):
            with self.subTest(mode=mode), self.original_query() as (_, _, _, _, operation):
                def final(argv, kwargs):
                    context = kwargs["environ"]["MOBILE_RELEASE_ASC_BUNDLE_READ_CONTEXT"]
                    raw = api.canonical(page()).replace(b'"data":[]', b'"data":[1],"data":[]') if mode == "duplicate" else api.canonical(page())
                    return subprocess.CompletedProcess(argv, 1 if mode == "nonzero" else 0,
                        stdout=frame(raw, context=CONTEXT if mode == "wrong-context" else context),
                        stderr=b"PRIVATE" if mode == "stderr" else b"")
                calls, call = self.fake_commands(operation, final)
                with patch("mobile_release._command_process.run_command", side_effect=call): operation.run()
                self.assertEqual(len(calls), 7)
                self.assertEqual(operation.report["observation"], "inconclusive")

    def test_query_protocol_is_distinct_from_old_access_and_never_mutation_context(self):
        with original.DesktopStorePreflightTests().files(platform="ios") as (_, root, runtime):
            value = original.request(root, runtime); value["context"].update(platform="ios", query=bundle.QUERY)
            request = wire.parse_request(original.encode(value))
            for name, bad in (("query", None), ("query", "create-bundle-id"), ("platform", "android"), ("teamId", "ZZZZZ12345")):
                changed = copy.deepcopy(value); changed["context"][name] = bad
                with self.assertRaises(ValueError): wire.parse_request(original.encode(changed))
            with self.assertRaises(ValueError): wire.context(request.context)
            old = copy.deepcopy(value); del old["context"]["query"]
            self.assertNotIn("query", wire.parse_request(original.encode(old)).context)
            result = bundle.project_result([], "not-returned")
            terminal = {"schemaVersion": 1, "context": request.context, "outcome": "complete", "reason": "none", "result": result,
                "lifetime": {"complete": True, "fatal": False, "contained": True, "commandDispatched": True, "commands": 7, "profileCalls": 0,
                             "inputClosed": True, "handlersRestored": True, "invocationClosed": True, "stopObserved": "none"}}
            wire.validate_terminal(terminal, request)  # Codec DATA only, not native proof.
            for key in ("inputClosed", "handlersRestored", "invocationClosed", "complete", "contained"):
                invalid = copy.deepcopy(terminal); invalid["lifetime"][key] = False
                with self.assertRaises(ValueError): wire.validate_terminal(invalid, request)
                invalid.update(outcome="unknown", reason="cleanup-unknown", result=None)
                wire.validate_terminal(invalid, request)

    def test_apple_access_opt_in_does_not_widen_prepare_execute_or_reconcile(self):
        from mobile_release import _desktop_store_prepare_protocol as prepare
        from mobile_release import _desktop_store_execute_protocol as execute
        from mobile_release import _desktop_store_reconcile_protocol as reconcile
        with original.DesktopStorePreflightTests().files(platform="ios") as (_, root, runtime):
            value = original.request(root, runtime); value["context"]["platform"] = "ios"
            access = wire.parse_request(original.encode(value)).context
            query = {**access, "query": bundle.QUERY}
            with self.assertRaises(ValueError): wire.context(query, apple_access=True)
            self.assertEqual(wire.context(query, apple_access=True, bundle_query=True), query)
            candidate = {**access, "operation": "local-store-prepare", "candidateOperationId": "12345678-1234-4234-9234-123456789abc",
                         "candidateSha256": "d" * 64, "confirmation": "candidate:ios:1.2.3:42"}
            recovery = {**candidate, "operation": "local-store-reconcile", "intentSha256": "e" * 64}
            execution = {**candidate, "operation": "local-store-execute", "intentSha256": "e" * 64}
            readiness = {**recovery, "action": "external-readiness", "stageOperationId": "12345678-1234-4234-9234-123456789abd",
                "executionReceiptSha256": "f" * 64, "confirmation": "external-testing:ios:1.2.3:42",
                "supplementalAssignments": {"reviewContact": {"recordId": "e" * 32, "recordRevision": 1},
                    "commitment": {"recordId": "f" * 32, "recordRevision": 1}, "reviewDemo": None}}
            with patch("mobile_release._command_process.run_command") as run:
                for parse, context in ((lambda c: prepare.context(c, apple_prepare=True), candidate),
                                       (execute.context, execution), (reconcile.context, recovery), (reconcile.context, readiness)):
                    self.assertEqual(parse(context), context)  # Actual valid legacy controls.
                    with self.assertRaises(ValueError): parse({**context, "query": bundle.QUERY})
                run.assert_not_called()
