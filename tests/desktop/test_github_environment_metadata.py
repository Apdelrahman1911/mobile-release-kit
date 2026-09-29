"""Read-only P1 DATA/schedule regressions, never native/TLS/service evidence."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from mobile_release import github_environment_metadata as metadata
from mobile_release._desktop_github_engine import MetadataRequest, ProtocolError, parse_request
from mobile_release._github_connection_transport import ReadFailure, ReadResult, _control
from mobile_release.config import ReleaseConfig
from mobile_release.credential_requirements import ENVIRONMENT_INPUT_TYPES, ENVIRONMENT_NAMES, requirements

TIME = "2026-09-28T12:00:00Z"
NAME = "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_VERSION"
PRIVATE = "INERT_VARIABLE_VALUE_MUST_NOT_REACH_UI"
REQUEST = MetadataRequest("read-1", "owner/app", "11", "22", "INERT_TOKEN", "production", NAME)


def success(body):
    return ReadResult({"status": 200, "body": body, "failure": "none"}, _control())


def refusal(code, reason, cooldown=None):
    return ReadResult({"status": code, "body": None, "failure": "none"}, _control(reason, cooldown))


def observations(request=REQUEST):
    repository = {"id": 22, "full_name": "owner/app", "default_branch": "main",
                  "visibility": "private", "archived": False, "permissions": {}}
    return {
        "account": success({"id": 11, "login": "owner"}),
        "repository-before": success(deepcopy(repository)),
        "environment": success({"id": 33, "name": ENVIRONMENT_NAMES[request.stage],
                                "protection_rules": [{"type": "uninterpreted"}]}),
        "field": success({"name": request.name, "created_at": TIME, "updated_at": TIME, "value": PRIVATE}),
        "repository-after": success(deepcopy(repository)),
    }


class Reader:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def read(self, step):
        self.calls.append(step)
        result = self.rows[step]
        if isinstance(result, Exception):
            raise result
        return result


def observe(rows, request=REQUEST):
    reader = Reader(rows)
    result = metadata.observe(request, reader, observed_at=TIME)
    encoded = metadata.encode_response(request, result)
    return reader, result, encoded


class GitHubEnvironmentMetadataTests(unittest.TestCase):
    def test_core_requirements_and_routes_share_one_canonical_type_authority(self):
        # Pure ReleaseConfig DATA only; no config file, path access or credentials.
        config = ReleaseConfig(Path("unused.json"), Path("."), {
            "android": {"enabled": True}, "ios": {"enabled": True, "review": {"demoAccountRequired": True}},
            "services": {"androidFirebase": "required", "iosFirebase": "required"},
            "source": {"projectReadTokenRequired": True},
        })
        rows = requirements(config)
        self.assertEqual({row.name for row in rows}, set(ENVIRONMENT_INPUT_TYPES))
        for row in rows:
            self.assertEqual(metadata.target(row.stage, row.name), (ENVIRONMENT_NAMES[row.stage], row.kind))
        for stage, name in [("unknown", NAME), ("production", NAME + "_PATH"), ("production", "../value"),
                            ("production", "MOBILE_RELEASE_NOT_CORE_OWNED"), ([], NAME), ("candidate", {})]:
            with self.assertRaises(ValueError):
                metadata.target(stage, name)

    def test_private_frame_is_exact_and_requires_both_immutable_pins(self):
        frame = {"protocol": metadata.PROTOCOL, "id": REQUEST.id,
                 "params": {"repository": REQUEST.repository, "expectedAccountId": "11",
                            "expectedRepositoryId": "22", "token": "INERT_TOKEN",
                            "stage": REQUEST.stage, "name": REQUEST.name}}
        self.assertEqual(parse_request(json.dumps(frame).encode() + b"\n"), REQUEST)
        for key, value in [("root", "/unused"), ("kind", "secret"), ("url", "https://example.invalid"),
                           ("expectedAccountId", None), ("expectedRepositoryId", None), ("name", "MOBILE_RELEASE_UNKNOWN")]:
            changed = deepcopy(frame)
            changed["params"][key] = value
            with self.assertRaises(ProtocolError):
                parse_request(json.dumps(changed).encode() + b"\n")
        old = deepcopy(frame)
        old["protocol"] = "mrk-github-readonly/1"
        with self.assertRaises(ProtocolError):
            parse_request(json.dumps(old).encode() + b"\n")

    def test_fixed_reader_has_five_gets_current_routes_and_no_replay(self):
        calls = []
        def exchange(method, path, body):
            calls.append((method, path, body))
            return success({})
        with patch.object(metadata, "_make_live_exchange", return_value=exchange) as factory:
            reader = metadata._make_live_reader(REQUEST, started=1.0, runtime_dir="/unused-runtime")
            with self.assertRaises(ValueError):
                reader.read("field")
            for step in metadata.STEPS:
                reader.read(step)
            with self.assertRaises(ValueError):
                reader.read("repository-after")
            factory.assert_called_once_with("INERT_TOKEN", started=1.0, runtime_dir="/unused-runtime",
                                            api_version="2026-03-10")
        self.assertEqual(calls, [("GET", "/user", None), ("GET", "/repos/owner/app", None),
                                ("GET", "/repos/owner/app/environments/mobile-production", None),
                                ("GET", "/repos/owner/app/environments/mobile-production/variables/" + NAME, None),
                                ("GET", "/repos/owner/app", None)])
        secret_request = MetadataRequest("read-2", "owner/app", "11", "22", "INERT_TOKEN",
                                         "candidate", "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD")
        calls.clear()
        with patch.object(metadata, "_make_live_exchange", return_value=exchange):
            reader = metadata._make_live_reader(secret_request, started=1.0, runtime_dir="/unused-runtime")
            for step in metadata.STEPS:
                reader.read(step)
        self.assertIn("/secrets/" + secret_request.name, calls[3][1])
        calls.clear()
        with patch.object(metadata, "_make_live_exchange", return_value=exchange):
            reader = metadata._make_live_reader(REQUEST, started=1.0, runtime_dir="/unused-runtime")
            for step in ("account", "repository-before", "environment", "repository-after"):
                reader.read(step)
            with self.assertRaises(ValueError):
                reader.read("field")
        self.assertEqual(len(calls), 4)

    def test_metadata_only_projection_discards_variable_and_unknown_fields(self):
        rows = observations()
        reader, result, encoded = observe(rows)
        self.assertEqual(reader.calls, list(metadata.STEPS))
        self.assertNotIn(PRIVATE.encode(), encoded)
        self.assertNotIn(b"INERT_TOKEN", encoded)
        self.assertNotIn(b"protection_rules", encoded)
        self.assertEqual(rows["field"].observation["body"], {})
        self.assertEqual(result["metadata"]["field"]["value"],
                         {"name": NAME, "kind": "variable", "createdAt": TIME, "updatedAt": TIME})
        self.assertEqual(result["metadata"]["environment"]["value"], {"id": "33", "name": "mobile-production"})
        self.assertEqual(result["facts"]["automation"]["state"], "unavailable")
        self.assertEqual(result["facts"]["automation"]["reason"], "cancelled")
        self.assertEqual(json.loads(encoded)["protocol"], metadata.PROTOCOL)
        self.assertEqual(result["control"]["reason"], "none")

    def test_original_identity_is_required_before_field_and_after_observation(self):
        for step, key, changed, count in [("account", "id", 12, 1), ("account", "id", "12", 1),
                                         ("repository-before", "id", 23, 2),
                                         ("repository-before", "full_name", "owner/replacement", 2),
                                         ("repository-after", "id", 23, 5)]:
            rows = observations()
            rows[step].observation["body"][key] = changed
            reader, result, _ = observe(rows)
            self.assertEqual(len(reader.calls), count)
            self.assertEqual(result["control"]["reason"], "target-changed")
            self.assertIsNone(result["metadata"]["field"]["value"])
            self.assertIsNone(result["metadata"]["environment"]["value"])

    def test_404_is_ambiguous_and_ordinary_environment_refusal_skips_only_field(self):
        for step in ("environment", "field"):
            rows = observations()
            rows[step] = refusal(404, "not-found-or-inaccessible")
            reader, result, encoded = observe(rows)
            self.assertEqual(reader.calls[-1], "repository-after")
            self.assertEqual("field" in reader.calls, step == "field")
            self.assertEqual(result["metadata"][step]["reason"], "not-found-or-inaccessible")
            self.assertIsNone(result["metadata"]["field"]["value"])
            self.assertEqual(result["facts"]["repository"]["state"], "observed")
            self.assertNotIn(b'"absent"', encoded)
        rows = observations()
        rows["environment"] = refusal(403, "forbidden")
        reader, result, _ = observe(rows)
        self.assertEqual(reader.calls, ["account", "repository-before", "environment", "repository-after"])
        self.assertEqual(result["control"]["reason"], "forbidden")

    def test_fatal_rate_transport_and_malformed_bodies_stop_the_original_schedule(self):
        rows = observations()
        rows["environment"] = refusal(403, "rate-limited", 7)
        reader, result, _ = observe(rows)
        self.assertEqual(len(reader.calls), 3)
        self.assertEqual(result["control"]["cooldownSeconds"], 7)
        self.assertEqual(result["control"]["reason"], "rate-limited")
        for result_or_error in [refusal(401, "unauthorized"), ReadFailure("network-unavailable"),
                                success({"name": NAME, "created_at": "not-a-time", "updated_at": TIME, "value": PRIVATE})]:
            rows = observations()
            rows["field"] = result_or_error
            reader, result, encoded = observe(rows)
            self.assertEqual(reader.calls[-1], "field")
            self.assertEqual(len(reader.calls), 4)
            self.assertIsNone(result["metadata"]["field"]["value"])
            self.assertNotIn(PRIVATE.encode(), encoded)
            if type(result_or_error) is ReadResult and result_or_error.observation["body"] is not None:
                self.assertEqual(result_or_error.observation["body"], {})

    def test_reply_bounds_include_discarded_values_and_failed_field_is_cleared(self):
        for oversized in ["x" * (256 * 1024), list(range(4001))]:
            rows = observations()
            rows["field"].observation["body"]["value"] = oversized
            reader, result, encoded = observe(rows)
            self.assertEqual(reader.calls[-1], "field")
            self.assertEqual(result["control"]["reason"], "response-limit")
            self.assertEqual(rows["field"].observation["body"], {})
            self.assertLess(len(encoded), 64 * 1024)
        rows = observations()
        for name in rows:
            rows[name].observation["body"]["padding"] = "x" * (220 * 1024)
        reader, result, _ = observe(rows)
        self.assertEqual(len(reader.calls), 5)
        self.assertEqual(result["control"]["reason"], "response-limit")
        self.assertEqual(rows["repository-after"].observation["body"], {})
        self.assertIsNone(result["metadata"]["field"]["value"])

    def test_encoder_rejects_value_reflection_unknown_selection_and_fabricated_workflow_facts(self):
        _, original, _ = observe(observations())
        for change in [
            lambda result: result["metadata"]["field"]["value"].update(value=PRIVATE),
            lambda result: result["metadata"]["selection"].update(name="MOBILE_RELEASE_UNKNOWN"),
            lambda result: result["metadata"]["field"]["value"].update(kind="secret"),
            lambda result: result["facts"]["automation"].update(reason="forbidden"),
        ]:
            result = deepcopy(original)
            change(result)
            with self.assertRaises(ValueError):
                metadata.encode_response(REQUEST, result)


if __name__ == "__main__":
    unittest.main()
