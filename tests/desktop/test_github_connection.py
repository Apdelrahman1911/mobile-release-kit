"""Inert G1 projection/help cases only; no HTTP, credentials or native owner.

Only five fixed shipped catalogue/help resources are read. All observations are
supplied fakes, not account access, TLS or original-settlement evidence.
"""
from __future__ import annotations

import builtins
import copy
import json
import os
import socket
import subprocess
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from mobile_release.api import _github_connection as connection
from mobile_release.api import _catalog as catalog_api
from mobile_release.api.contracts import ApiError
from mobile_release.workflow_payloads import GITHUB_WORKFLOWS

TIME = "2026-09-17T12:00:00Z"
SENTINEL = "INERT_PRIVATE_TOKEN_MUST_NOT_ESCAPE"


def read(body=None, status=200, failure="none"):
    return {"status": status, "body": body, "failure": failure}


def repository(identity=22):
    return {"id": identity, "full_name": "Owner/App", "default_branch": "main", "visibility": "private",
            "archived": False, "permissions": {"pull": True, "push": False}, "ignored": SENTINEL}


def workflow(index):
    return {"id": index + 100, "path": GITHUB_WORKFLOWS[index][1], "state": "active", "name": SENTINEL, "url": SENTINEL}


def supplied():
    return {"repository": "Owner/App", "observedAt": TIME, "expectedAccountId": None, "expectedRepositoryId": None,
            "account": read({"id": 11, "login": "Owner", "email": SENTINEL, "avatar_url": SENTINEL}),
            "repositoryBefore": read(repository()), "repositoryAfter": read(repository()),
            "workflowPages": [read({"total_count": 4, "workflows": [workflow(i) for i in range(4)], "extra": SENTINEL})]}


def project(value=None):
    return connection.project_github_observations(supplied() if value is None else value)


def hundred():
    return [workflow(0)] + [{"id": i + 1000, "path": f".github/workflows/other-{i}.yml", "state": "active"} for i in range(99)]


class GitHubConnectionTests(unittest.TestCase):
    def rejected(self, value):
        with self.assertRaises(ApiError) as caught:
            project(value)
        self.assertEqual(caught.exception.code, "github_observation_invalid")
        self.assertNotIn(SENTINEL, str(caught.exception))

    def test_whitelist_decimal_ids_roles_and_fixed_roster(self):
        data = supplied()
        data["account"]["body"]["id"] = 2**64 - 1
        result = project(data)
        self.assertEqual(result["account"]["value"], {"id": "18446744073709551615", "login": "Owner"})
        self.assertEqual(result["repository"]["value"]["permissions"], {"pull": "reported-allowed", "push": "reported-denied", "admin": "unknown"})
        self.assertEqual(result["automation"]["value"]["coverage"], "complete")
        self.assertEqual([r["id"] for r in result["automation"]["value"]["workflows"]], [i for i, _ in GITHUB_WORKFLOWS])
        self.assertTrue(all(r["presence"] == "listed" for r in result["automation"]["value"]["workflows"]))
        text = json.dumps(result)
        self.assertNotIn(SENTINEL, text)
        for authority in ("token", "session", "operation", "revision", "capability", "expiresAt"):
            self.assertNotIn(authority, result)
        self.assertLessEqual(len(text.encode()), connection.MAX_RESULT_BYTES)

    def test_http_failures_never_become_workflow_absence(self):
        reasons = {401: "unauthorized", 403: "forbidden", 404: "not-found-or-inaccessible", 429: "rate-limited", 503: "network-unavailable", 302: "response-invalid"}
        for code, reason in reasons.items():
            data = supplied(); data["repositoryBefore"] = read(None, code)
            with self.subTest(code=code):
                result = project(data)
                self.assertEqual(result["account"]["state"], "observed")
                for key in ("repository", "automation"):
                    self.assertEqual(result[key], {"state": "unavailable", "value": None, "observedAt": None, "reason": reason})
        data = supplied(); data["account"] = read(None, 401)
        self.assertTrue(all(project(data)[key]["value"] is None for key in ("account", "repository", "automation")))
        data["account"]["body"] = {"message": SENTINEL}  # Error bodies are not part of the closed supplied contract.
        self.rejected(data)

    def test_transport_failures_are_closed_and_do_not_echo_diagnostics(self):
        for reason in ("tls-failed", "network-unavailable", "response-limit", "response-invalid", "cancelled"):
            data = supplied(); data["repositoryAfter"] = read(None, None, reason)
            self.assertEqual(project(data)["repository"]["reason"], reason)
        data = supplied(); data["repositoryAfter"] = read(None, None, SENTINEL)
        self.rejected(data)

    def test_identity_replacement_and_wrong_coordinate_do_not_adopt_new_ids(self):
        data = supplied(); data["expectedAccountId"] = "44"
        result = project(data)
        self.assertEqual(result["account"]["reason"], "target-changed")
        self.assertTrue(all(result[key]["value"] is None for key in ("account", "repository", "automation")))
        for change in ("bracket", "expected", "name"):
            data = supplied(); data["expectedAccountId"] = "11"
            if change == "bracket": data["repositoryAfter"]["body"]["id"] = 999
            elif change == "expected": data["expectedRepositoryId"] = "999"
            else: data["repositoryAfter"]["body"]["full_name"] = "Owner/Replacement"
            with self.subTest(change=change):
                self.assertEqual(project(data)["repository"]["reason"], "target-changed")
                self.assertIsNone(project(data)["automation"]["value"])

    def test_complete_empty_listing_is_not_git_file_absence(self):
        data = supplied(); data["workflowPages"] = [read({"total_count": 0, "workflows": []})]
        value = project(data)["automation"]["value"]
        self.assertEqual(value["coverage"], "complete")
        self.assertTrue(all(row["presence"] == "not-listed" and row["remoteId"] is None for row in value["workflows"]))
        self.assertNotIn("file", json.dumps(value))

    def test_partial_duplicate_and_changing_pages_never_claim_absence(self):
        data = supplied(); data["workflowPages"] = [read({"total_count": 101, "workflows": hundred()})]
        value = project(data)["automation"]["value"]
        self.assertEqual(value["coverage"], "limited")
        self.assertEqual(value["workflows"][0]["presence"], "listed")
        self.assertTrue(all(row["presence"] == "unknown" for row in value["workflows"][1:]))
        for total, last in ((101, workflow(0)), (102, workflow(1))):
            data["workflowPages"] = [read({"total_count": 101, "workflows": hundred()}), read({"total_count": total, "workflows": [last]})]
            value = project(data)["automation"]["value"]
            self.assertEqual(value["coverage"], "limited")
            self.assertTrue(all(row["presence"] == "unknown" for row in value["workflows"]))
        data["workflowPages"] = [read({"total_count": 101, "workflows": hundred()}), read({"total_count": 101, "workflows": [workflow(1)]})]
        self.assertEqual(project(data)["automation"]["value"]["coverage"], "complete")

    def test_exact_workflow_path_not_name_or_remote_url_selects_records(self):
        data = supplied(); row = data["workflowPages"][0]["body"]["workflows"][0]
        row["path"] = ".github/workflows/not-the-preflight.yml"
        row["name"] = "preflight"; row["url"] = GITHUB_WORKFLOWS[0][1]
        self.assertEqual(project(data)["automation"]["value"]["workflows"][0]["presence"], "not-listed")
        data = supplied(); data["workflowPages"][0]["body"]["workflows"][0]["state"] = "disabled_manually"
        self.assertEqual(project(data)["automation"]["value"]["workflows"][0]["state"], "disabled")

    def test_noncanonical_ids_input_unicode_controls_and_dates_refuse(self):
        for identity in (True, 0, -1, 2**64, "0", "01", "1\n", "18446744073709551616"):
            data = supplied(); data["account"]["body"]["id"] = identity
            with self.subTest(identity=identity): self.rejected(data)
        for target in ("https://github.com/Owner/App", "owner/repo\n", "owner/.repo", "é/app", "owner/repo/extra"):
            data = supplied(); data["repository"] = target; self.rejected(data)
        for text in (SENTINEL + "\n", "a\u0085b", "a\u202eb", "\ud800", "a" * 97):
            data = supplied(); data["account"]["body"]["login"] = text; self.rejected(data)
        for time in ("2025-02-29T00:00:00Z", "0000-01-01T00:00:00Z", TIME + "\n", "2026-09-17T12:00:60Z"):
            data = supplied(); data["observedAt"] = time; self.rejected(data)

    def test_body_count_depth_and_closed_envelope_limits(self):
        data = supplied(); data["token"] = SENTINEL; self.rejected(data)
        data = supplied(); del data["expectedRepositoryId"]; self.rejected(data)
        data = supplied(); data["workflowPages"] *= 3; self.rejected(data)
        data = supplied(); data["account"]["body"]["ignored"] = "x" * (256 * 1024); self.rejected(data)
        data = supplied(); data["workflowPages"][0]["body"]["workflows"] = hundred() + [workflow(1)]; self.rejected(data)
        data = supplied(); deep = {}
        for _ in range(25): deep = {"nested": deep}
        data["account"]["body"]["ignored"] = deep; self.rejected(data)
        data = supplied(); data["account"]["body"]["cycle"] = data; self.rejected(data)

    def test_stale_facts_keep_original_values_and_times_without_native_authority(self):
        original = project(); saved = copy.deepcopy(original)
        for reason in ("stale", "expired", "cancelled", "cleanup-unknown"):
            stale = connection.stale_github_observations(original, reason)
            for key in ("account", "repository", "automation"):
                self.assertEqual(stale[key]["value"], original[key]["value"])
                self.assertEqual(stale[key]["observedAt"], TIME)
                self.assertEqual(stale[key]["state"], "stale")
                self.assertEqual(stale[key]["reason"], reason)
            stale["account"]["value"]["login"] = "Changed fake copy"
            self.assertEqual(original, saved)
        bad = copy.deepcopy(original); bad["account"]["state"] = "not-observed"
        with self.assertRaises(ApiError): connection.stale_github_observations(bad)
        bad = copy.deepcopy(original); bad["repository"].update(state="stale", reason="stale")
        with self.assertRaises(ApiError): connection.stale_github_observations(bad)

    def test_fixed_help_before_input_and_resource_refusal_without_fallback(self):
        help_data = connection.github_connection_help()
        self.assertEqual([r["id"] for r in help_data["inputs"]], list(connection.INPUT_IDS))
        self.assertEqual([r["id"] for r in help_data["guidance"]], list(connection.GUIDANCE_IDS))
        self.assertLessEqual(len(json.dumps(help_data).encode()), connection.MAX_RESOURCE_BYTES)
        malformed = [b'{"schemaVersion":1,"schemaVersion":1}', b'\xff', b'x' * (connection.MAX_RESOURCE_BYTES + 1)]
        extra = copy.deepcopy(help_data); extra[SENTINEL] = SENTINEL
        malformed.append(json.dumps(extra).encode())
        extra = copy.deepcopy(help_data); extra["inputs"][1]["requiredness"] = "optional"
        malformed.append(json.dumps(extra).encode())
        for raw in malformed:
            with patch.object(connection, "_read_resource_bytes", return_value=raw), self.assertRaises(ApiError) as caught:
                connection.github_connection_help()
            self.assertEqual(caught.exception.code, "resource_unavailable")
            self.assertNotIn(SENTINEL, str(caught.exception))

    def test_projection_and_stale_paths_do_not_use_ambient_io(self):
        data = supplied()
        raw_help = connection._read_resource_bytes()
        with ExitStack() as stack:
            for target in ((builtins, "open"), (socket, "socket"), (subprocess, "Popen"), (os, "getenv")):
                stack.enter_context(patch.object(*target, side_effect=AssertionError("ambient IO tripwire")))
            stack.enter_context(patch.object(connection, "_read_resource_bytes", return_value=raw_help))
            result = project(data)
            connection.stale_github_observations(result)
            connection.github_connection_help()
        self.assertNotIn(SENTINEL, json.dumps(result))

    def test_catalogue_connection_help_is_additive_and_error_isolation_is_exact(self):
        original = catalog_api.catalog()
        self.assertEqual(original["githubConnection"], connection.github_connection_help())
        without_connection = {key: value for key, value in original.items() if key != "githubConnection"}
        for failure in (OSError("inert missing resource"), None):
            kwargs = {"side_effect": failure} if failure else {"return_value": b'{"schemaVersion":2}'}
            with patch.object(connection, "_read_resource_bytes", **kwargs):
                result = catalog_api.catalog()
            self.assertIsNone(result["githubConnection"])
            self.assertEqual({key: value for key, value in result.items() if key != "githubConnection"}, without_connection)
        unrelated = ApiError("inert_unrelated_failure", "Not a resource-unavailable refusal")
        with patch.object(connection, "github_connection_help", side_effect=unrelated), self.assertRaises(ApiError) as caught:
            catalog_api.catalog()
        self.assertIs(caught.exception, unrelated)


if __name__ == "__main__":
    unittest.main()
