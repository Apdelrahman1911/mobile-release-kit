"""Focused inert GitHub proposal contracts; no CLI/native/network execution.

Only fixed shipped source/resource bytes are read. Other cases use in-memory
JSON/bytes and explicit failure tripwires. No temporary project, credential,
Git process, workflow run, package build, installation or file write is needed.
"""
from __future__ import annotations

import ast
import builtins
import copy
import hashlib
import importlib
import io
import json
import os
import socket
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from mobile_release import _desktop_engine as engine
from mobile_release.api import ApiError, METHODS, execute
from mobile_release.api import _github_setup as setup
from mobile_release.api._catalog import requirement_descriptors
from mobile_release.api.contracts import assurance
from mobile_release.config import ReleaseConfig
from mobile_release.errors import ValidationError
from mobile_release.workflow_payloads import (MissingWorkflowPlaceholder, normalize_tooling_reference,
                                             pinned_schema_reference, render_workflow_caller)

SOURCE = Path(__file__).resolve().parents[2]
RESOURCE = SOURCE / "src/mobile_release/api/data/github-setup-v1.json"
IDS = ("preflight", "candidate", "external-testing", "production-submit")
GUIDES = ("source-authority", "protected-environments", "runner-policy", "credentials", "preflight-and-releases", "scope")
COMMON = {"schemaVersion", "state", "validation", "facts", "assurance"}
PROPOSED = COMMON | {"templateSet", "tooling", "workflows", "settings"}


def draft():
    return {
        "schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "production"},
        "android": {"enabled": True, "applicationId": "org.fixture.app", "identityStatus": "unverified"},
        "ios": {"enabled": False},
        "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": []},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []},
    }


def params(**changes):
    value = {"draft": draft(), "toolingRepository": "Example/mobile-release-kit", "toolingSha": "A" * 40,
             "suppliedSnapshot": None}
    value.update(changes)
    return value


def propose(**changes):
    return execute("github.setup.propose", params(**changes))


def resource_bytes(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


class GitHubSetupTests(unittest.TestCase):
    def test_shared_reference_grammar_normalization_and_informational_schema(self):
        for repository in ("a/b", "Owner-1/Repo._-1", "o" * 39 + "/" + "r" * 100):
            self.assertEqual(normalize_tooling_reference(repository, "F" * 40), (repository, "f" * 40))
            self.assertEqual(pinned_schema_reference(repository, "F" * 40),
                             f"https://raw.githubusercontent.com/{repository}/{'f' * 40}/schemas/project.schema.json")
        for repository in (None, 1, [], "", "owner", "owner/repo/extra", "owner/repo@main", "owner/.repo",
                           "owner-/repo", "owner/repo.", "https://github.com/owner/repo", "own er/repo",
                           "é/repo", "owner/repo\n", "o" * 40 + "/repo", "owner/" + "r" * 101):
            with self.subTest(repository=repository), self.assertRaises(ValidationError):
                normalize_tooling_reference(repository, "a" * 40)
        for sha in (None, True, [], "", "a" * 39, "a" * 41, "a" * 64, "main", "v1.0.0", "g" * 40, "a" * 40 + "\n"):
            with self.subTest(sha=sha), self.assertRaisesRegex(ValidationError, "tooling-sha"):
                normalize_tooling_reference("owner/repo", sha)

    def test_leaf_render_preserves_nonmarker_bytes_and_does_not_parse_yaml(self):
        template = ("\ufeff# café\r\nuses: __MOBILE_RELEASE_KIT_REPOSITORY__/reusable.yml@__MOBILE_RELEASE_KIT_SHA__\r\n"
                    "sha: __MOBILE_RELEASE_KIT_SHA__\r\nsource: ${{ github.sha }}\r\n").encode()
        expected = template.replace(b"__MOBILE_RELEASE_KIT_SHA__", b"b" * 40).replace(
            b"__MOBILE_RELEASE_KIT_REPOSITORY__", b"Owner/toolkit")
        self.assertEqual(render_workflow_caller(template, "Owner/toolkit", "B" * 40), expected)
        for invalid in (b"no markers", b"__MOBILE_RELEASE_KIT_SHA__", b"__MOBILE_RELEASE_KIT_REPOSITORY__"):
            with self.assertRaises(MissingWorkflowPlaceholder):
                render_workflow_caller(invalid, "owner/repo", "a" * 40)
        for invalid in (b"\xff", "not bytes", b"x" * (1024 * 1024 + 1)):
            with self.assertRaises(ValidationError):
                render_workflow_caller(invalid, "owner/repo", "a" * 40)

    def test_cli_extraction_is_static_and_keeps_transaction_and_resource_selection(self):
        # Inspect source as data; importing CLI would load unrelated operations.
        tree = ast.parse((SOURCE / "src/mobile_release/cli.py").read_text())
        body = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_init_apply")
        calls = [node.func for node in ast.walk(body) if isinstance(node, ast.Call)]
        names = {node.id for node in calls if isinstance(node, ast.Name)}
        self.assertTrue({"normalize_tooling_reference", "pinned_schema_reference", "render_workflow_caller",
                         "_find_template_dir", "_validate_init_destination", "validate_paths"} <= names)
        self.assertEqual(sum(isinstance(node, ast.Attribute) and node.attr == "apply" for node in calls), 1)
        self.assertTrue(any(isinstance(node, ast.Attribute) and node.attr == "observe" for node in calls))
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                             and node.func.attr == "replace" for node in ast.walk(body)))

    def test_packaged_mirror_matches_exact_canonical_bytes_and_existing_package_data(self):
        resource = json.loads(RESOURCE.read_bytes())
        self.assertEqual(set(resource), {"schemaVersion", "workflows", "help"})
        self.assertEqual(set(resource["workflows"]), set(IDS))
        canonical = SOURCE / "templates/workflows"
        self.assertEqual({path.name for path in canonical.glob("*.yml")},
                         {f"mobile-{identity}.yml" for identity in IDS})
        for identity in IDS:
            raw = (canonical / f"mobile-{identity}.yml").read_bytes()
            self.assertEqual(resource["workflows"][identity].encode("utf-8"), raw)
        packaging = tomllib.loads((SOURCE / "pyproject.toml").read_text())
        self.assertIn("api/data/*.json", packaging["tool"]["setuptools"]["package-data"]["mobile_release"])

    def test_resource_read_uses_only_fixed_package_name_bound_and_closed_stream(self):
        raw = RESOURCE.read_bytes()
        reads = []

        class Stream(io.BytesIO):
            def read(self, size=-1):
                reads.append(size)
                return super().read(size)

        stream = Stream(raw)
        with patch.object(setup, "files") as selected:
            selected.return_value.joinpath.return_value.open.return_value = stream
            result = setup.github_setup_help()
        selected.assert_called_once_with("mobile_release.api")
        selected.return_value.joinpath.assert_called_once_with("data", "github-setup-v1.json")
        selected.return_value.joinpath.return_value.open.assert_called_once_with("rb")
        self.assertEqual(reads, [128 * 1024 + 1])
        self.assertTrue(stream.closed)
        self.assertEqual(result["schemaVersion"], 1)

    def test_catalog_has_closed_beginner_help_without_a_draft_or_proposal(self):
        with patch.object(setup, "propose_github_setup", side_effect=AssertionError("proposal not requested")):
            catalog_result = execute("catalog", {})
        result = catalog_result["githubSetup"]
        self.assertEqual(set(result), {"schemaVersion", "inputs", "guidance"})
        self.assertEqual([item["id"] for item in result["inputs"]], ["toolingRepository", "toolingSha", "suppliedSnapshot"])
        self.assertEqual([item["requiredness"] for item in result["inputs"]], ["required", "required", "optional"])
        self.assertEqual([item["id"] for item in result["guidance"]], list(GUIDES))
        fields = {"id", "label", "what", "why", "where", "format", "failure"}
        for group in ("inputs", "guidance"):
            for item in result[group]:
                self.assertEqual(set(item), fields | {"requiredness"} if group == "inputs" else fields)
                for field in fields - {"id"}:
                    self.assertTrue(item[field].strip())
                    self.assertLessEqual(len(item[field].encode()), 96 if field == "label" else 1024)
        combined = json.dumps(result)
        for expected in ("not the application repository", "40", "not a snapshot read", "self-hosted", "secrets: inherit"):
            self.assertIn(expected, combined)
        credential_help = {item["name"]: item for item in catalog_result["credentials"]}
        for name, field, source_advice in (
            ("ANDROID_KEYSTORE_BASE64", "where", "Your existing upload-key keystore"),
            ("ANDROID_KEYSTORE_PASSWORD", "format", "A nonempty private keystore password"),
            ("ANDROID_GOOGLE_SERVICES_JSON_BASE64", "format",
             "The original Firebase client JSON; later checks must bind its application identity."),
        ):
            item = credential_help[f"MOBILE_RELEASE_{name}"]
            text = item[field]
            self.assertEqual(item["requiredness"], "conditional")
            self.assertLessEqual(len(text.encode()), 1024)
            self.assertIn(source_advice, text)
            self.assertIn("Credentials & Signing", text)
            self.assertIn("when available", text)
            self.assertNotIn("future", text)
            self.assertNotIn("Import is not yet implemented", text)
            self.assertIn("No values are collected, read or checked here.", item["failure"])
        for name, field in (("ANDROID_KEYSTORE_BASE64", "where"), ("ANDROID_GOOGLE_SERVICES_JSON_BASE64", "format")):
            self.assertIn("current availability and scope", credential_help[f"MOBILE_RELEASE_{name}"][field])
        password_help = credential_help["MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD"]["format"]
        self.assertIn("private controls", password_help)
        self.assertIn("Never enter it in this checklist, project configuration or command arguments", password_help)
        result["inputs"][0]["label"] = "mutated by caller"
        self.assertNotEqual(execute("catalog", {})["githubSetup"]["inputs"][0]["label"], "mutated by caller")

    def test_valid_result_exact_union_rosters_identities_and_non_authority(self):
        result = propose()
        self.assertEqual(set(result), PROPOSED)
        self.assertEqual((result["schemaVersion"], result["state"]), (1, "proposed"))
        self.assertEqual(set(result["validation"]), {"valid", "state", "issues", "requirements", "assurance"})
        self.assertEqual((result["validation"]["valid"], result["validation"]["state"], result["validation"]["issues"]),
                         (True, "format-valid", []))
        self.assertEqual(result["assurance"], assurance("schema-policy"))
        self.assertEqual(result["validation"]["assurance"], result["assurance"])
        self.assertEqual(result["facts"], {"githubContacted": False, "repositoryObserved": False,
                         "toolingRefResolved": False, "templateCompatibility": "unknown",
                         "comparisonBasis": "caller-supplied-digest-summary", "snapshotProvided": False, "applyAvailable": False})
        self.assertEqual(set(result["templateSet"]), {"coreVersion", "resourceVersion", "resourceSha256"})
        self.assertEqual(result["templateSet"]["resourceSha256"], hashlib.sha256(RESOURCE.read_bytes()).hexdigest())
        self.assertEqual(result["templateSet"]["resourceVersion"], 1)
        self.assertEqual(result["tooling"], {"repository": "Example/mobile-release-kit", "sha": "a" * 40,
                         "schemaReference": f"https://raw.githubusercontent.com/Example/mobile-release-kit/{'a' * 40}/schemas/project.schema.json",
                         "state": "format-only"})
        self.assertEqual(result["settings"], {
            "configPath": "release/mobile-release.json",
            "sourcePolicy": {"candidateBranch": "main", "productionBranch": "production", "basis": "configured-policy"},
            "environments": [{"stage": "candidate", "name": "mobile-candidate"},
                             {"stage": "external-testing", "name": "mobile-external-testing"},
                             {"stage": "production", "name": "mobile-production"}], "guidanceIds": list(GUIDES)})
        self.assertEqual([item["id"] for item in result["workflows"]], list(IDS))
        for item in result["workflows"]:
            self.assertEqual(set(item), {"id", "path", "content", "byteLength", "sha256", "comparison"})
            self.assertEqual(item["path"], f".github/workflows/mobile-{item['id']}.yml")
            encoded = item["content"].encode()
            self.assertEqual((item["byteLength"], item["sha256"]), (len(encoded), hashlib.sha256(encoded).hexdigest()))
            self.assertEqual(item["comparison"], "not-supplied")
        self.assertLessEqual(len(resource_bytes(result)), 256 * 1024)

    def test_all_four_callers_equal_shared_rendering_and_keep_existing_authority_inputs(self):
        for item in propose()["workflows"]:
            raw = (SOURCE / "templates/workflows" / f"mobile-{item['id']}.yml").read_bytes()
            self.assertEqual(item["content"].encode(), render_workflow_caller(raw, "Example/mobile-release-kit", "A" * 40))
            expected_source = ("${{ inputs.desktop_source_sha || github.sha }}"
                               if item["id"] == "preflight" else "${{ github.sha }}")
            self.assertEqual(
                [line for line in item["content"].splitlines() if line.lstrip().startswith("source_sha:")],
                [f"      source_sha: {expected_source}"],
            )
            self.assertEqual(item["content"].count("a" * 40), 2)
            self.assertNotIn("secrets: inherit", item["content"])
            if item["id"] != "preflight":
                self.assertIn("recovery_confirmation:", item["content"])
                self.assertIn("permissions: {}", item["content"])

    def test_invalid_configuration_is_redacted_and_has_no_generated_payload_or_resource_read(self):
        value = draft()
        value["private-unknown-key"] = "private-rejected-value"
        with patch.object(setup, "_read_resource_bytes", side_effect=AssertionError("invalid draft read templates")):
            result = propose(draft=value)
        self.assertEqual(set(result), COMMON)
        self.assertEqual(result["state"], "invalid")
        self.assertEqual(result["validation"], {
            "valid": False, "state": "invalid", "requirements": [], "assurance": assurance("schema-policy"),
            "issues": [{"code": "config.invalid", "status": "INVALID",
                        "message": "Configuration does not satisfy the shared core format/policy rules; review the draft and contextual field guidance.",
                        "remediation": "Correct the input and validate again; no changes were saved."}]})
        self.assertNotIn("private-", json.dumps(result))
        self.assertFalse(result["facts"]["repositoryObserved"] or result["facts"]["applyAvailable"])

    def test_requirements_reuse_shared_platform_stage_and_conditional_policy(self):
        value = draft()
        value["ios"] = {"enabled": True, "bundleId": "org.fixture.app", "identityStatus": "unverified",
                        "review": {"usesNonExemptEncryption": False, "demoAccountRequired": True}}
        value["metadata"]["iosLocales"] = ["en-US"]
        value["services"] = {"androidFirebase": "required", "iosFirebase": "required"}
        value["source"]["projectReadTokenRequired"] = True
        requirements = propose(draft=value)["validation"]["requirements"]
        self.assertEqual(requirements, requirement_descriptors(value))
        names = {item["name"] for item in requirements}
        for name in ("MOBILE_RELEASE_PROJECT_READ_TOKEN", "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64",
                     "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64", "MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_PASSWORD",
                     "MOBILE_RELEASE_OPERATION_COMMITMENT_KEY_BASE64"):
            self.assertIn(name, names)
        for item in requirements:
            self.assertEqual(item["state"], "unknown")
            self.assertEqual(set(item), {"name", "kind", "stage", "platform", "environment", "alternatives", "reason", "state"})
            if "KEYSTORE" in item["name"] or "DISTRIBUTION_P12" in item["name"] or "PROVISIONING_PROFILE" in item["name"]:
                self.assertEqual(item["stage"], "candidate")
        for platform in ("android", "ios"):
            one = copy.deepcopy(value)
            one[platform] = {"enabled": False}
            one["services"][platform + "Firebase"] = "disabled"
            self.assertFalse(any(item["platform"] == platform for item in propose(draft=one)["validation"]["requirements"]))

    def test_comparison_uses_both_asserted_length_and_digest_without_file_authority(self):
        items = propose()["workflows"]
        summary = {"workflows": [
            {"id": "production-submit", "state": "present", "byteLength": items[3]["byteLength"] + 1, "sha256": items[3]["sha256"]},
            {"id": "candidate", "state": "absent"},
            {"id": "external-testing", "state": "present", "byteLength": items[2]["byteLength"], "sha256": items[2]["sha256"]},
        ]}
        result = propose(suppliedSnapshot=summary)
        self.assertEqual([item["comparison"] for item in result["workflows"]],
                         ["not-supplied", "reported-absent", "supplied-digest-match", "supplied-digest-differs"])
        self.assertTrue(result["facts"]["snapshotProvided"])
        self.assertFalse(result["facts"]["repositoryObserved"] or result["facts"]["applyAvailable"])
        summary["workflows"][0]["byteLength"] = items[3]["byteLength"]
        summary["workflows"][0]["sha256"] = "0" * 64
        self.assertEqual(propose(suppliedSnapshot=summary)["workflows"][3]["comparison"], "supplied-digest-differs")

    def test_null_empty_and_zero_length_comparisons_do_not_invent_absence(self):
        for summary, provided in ((None, False), ({"workflows": []}, True)):
            result = propose(suppliedSnapshot=summary)
            self.assertIs(result["facts"]["snapshotProvided"], provided)
            self.assertEqual({item["comparison"] for item in result["workflows"]}, {"not-supplied"})
        summary = {"workflows": [{"id": "preflight", "state": "present", "byteLength": 0, "sha256": hashlib.sha256(b"").hexdigest()}]}
        self.assertEqual(propose(suppliedSnapshot=summary)["workflows"][0]["comparison"], "supplied-digest-differs")

        # The separate remote DATA path never treats absent optional policy as
        # a default, and a complete unchanged resource needs no write consent.
        from mobile_release import github_setup_remote as remote
        from mobile_release._github_connection_transport import ReadFailure, ReadResult, _control
        now = "2026-10-09T12:00:00Z"
        for selection, policy in (
            ({"kind": "actions_enabled", "enabled": True},
             {"enabled": False, "allowed_actions": "selected", "sha_pinning_required": True}),
            ({"kind": "workflow_token_policy", "defaultWorkflowPermissions": "write",
              "canApprovePullRequestReviews": True},
             {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False}),
        ):
            target = {"projectBinding": "a" * 64, "repository": "owner/repo", "accountId": "1",
                      "repositoryId": "2", "selection": selection}
            action = remote.Action.parse({"kind": "prepare", "target": target, "prepared": None})
            repo = {"id": 2, "full_name": "owner/repo", "default_branch": "main",
                    "visibility": "private", "archived": False}
            class Reader:
                def __init__(self, supplied, fault=None):
                    self.supplied, self.fault = supplied, fault
                    self.cursor = remote.Schedule(action)
                def read(self, step, reference=None):
                    request = self.cursor.claim(step, reference)
                    if step == self.fault:
                        raise ReadFailure("network-unavailable")
                    if step == "account":
                        body = {"id": 1, "login": "owner"}
                    elif step.startswith("repository-"):
                        body = repo
                    else:
                        body = self.supplied
                    self_test.assertEqual(request.method, "GET")
                    self_test.assertIsNone(request.body)
                    return ReadResult({"status": 200, "body": body, "failure": "none"}, _control())
            self_test = self
            original = copy.deepcopy((target, policy))
            reader = Reader(policy)
            result = remote.execute(action, reader, observed_at=now)
            self.assertEqual(reader.cursor.steps, ["account", "repository-before", "resource-before", "repository-after"])
            self.assertEqual(result["reason"], "none")
            prepared = remote.Prepared.parse(result["prepared"])
            self.assertEqual(prepared.before.value(), policy)
            self.assertFalse(result["writeClaimed"] or result["writeAcknowledged"])
            raw = (json.dumps({"protocol": remote.PROTOCOL, "id": "case", "action": action.value()}) + "\n").encode()
            request = remote.parse_initial(raw)
            self.assertEqual(json.loads(remote.encode_result(request, result))["result"], result)
            unchanged = Reader(prepared.after.value())
            no_change = remote.execute(action, unchanged, observed_at=now)
            self.assertEqual((no_change["reason"], no_change["prepared"]), ("no-change", None))
            self.assertEqual(len(unchanged.cursor.steps), 4)
            remote.encode_result(request, no_change)
            # Equality alone is not JSON boolean validation (True == 1).
            for field, value in prepared.after.value().items():
                if type(value) is bool:
                    forged = copy.deepcopy(prepared.value())
                    forged["after"][field] = int(value)
                    with self.assertRaises(ValueError):
                        remote.Prepared.parse(forged)
            for output in (result, no_change):
                for field, value in output["observed"].items():
                    if type(value) is bool:
                        forged = copy.deepcopy(output)
                        forged["observed"][field] = int(value)
                        with self.assertRaises(ValueError):
                            remote.encode_result(request, forged)
            self.assertEqual((target, policy), original)
            for index, step in enumerate(reader.cursor.steps):
                failed = Reader(policy, step)
                row = remote.execute(action, failed, observed_at=now)
                self.assertEqual(failed.cursor.steps, reader.cursor.steps[:index + 1])
                self.assertEqual((row["reason"], row["effect"]), ("network-unavailable", "not-started"))
                self.assertIsNone(row["prepared"])
                self.assertIsNone(row["observed"])
                remote.encode_result(request, row)
            if selection["kind"] == "actions_enabled":
                self.assertEqual(prepared.after.value(), {**policy, "enabled": True})
                for field in policy:
                    missing = {key: value for key, value in policy.items() if key != field}
                    refused = Reader(missing)
                    row = remote.execute(action, refused, observed_at=now)
                    self.assertEqual((row["reason"], row["prepared"], len(refused.cursor.steps)),
                                     ("policy-unsupported", None, 3))
                    self.assertFalse(row["writeClaimed"])
                with_url = Reader({**policy, "selected_actions_url": "https://untrusted.invalid/not-followed"})
                observed = remote.execute(action, with_url, observed_at=now)
                self.assertEqual(observed, result)
                self.assertNotIn("untrusted", remote.encode_result(request, observed).decode())
                for allowed in ("all", "local_only", "selected"):
                    for sha in (False, True):
                        preserved = remote.Policy.parse(selection["kind"], {**policy, "allowed_actions": allowed,
                                                                            "sha_pinning_required": sha})
                        self.assertEqual(preserved.changed(action.target.selection).fields[1:], (allowed, sha))
                for extra in ({"future_restriction": True}, {"selected_actions_url": None}):
                    row = remote.execute(action, Reader({**policy, **extra}), observed_at=now)
                    self.assertNotEqual(row["reason"], "none")
                    self.assertIsNone(row["prepared"])

        # Fixed inert environment responses: no credential, transport or operation.
        from mobile_release import github_setup_remote as remote
        now = "2026-10-09T12:00:00Z"
        selection = {"kind": "environment_protection", "mode": "configure", "stage": "candidate",
                     "waitTimerMinutes": 30, "preventSelfReview": True, "reviewerLogin": None, "branches": None}
        target_value = {"projectBinding": "a" * 64, "repository": "owner/repo", "accountId": "1",
                        "repositoryId": "2", "selection": selection}
        body = {"id": 71, "node_id": "environment-node", "name": "mobile-candidate",
                "url": "https://api.github.com/repos/owner/repo/environments/mobile-candidate",
                "html_url": "https://github.com/owner/repo/deployments", "created_at": now, "updated_at": now,
                "protection_rules": [
                    {"id": 1, "node_id": "wait-node", "type": "wait_timer", "wait_timer": 10},
                    {"id": 2, "node_id": "review-node", "type": "required_reviewers", "prevent_self_review": False,
                     "reviewers": [{"type": "User", "reviewer": {"id": 91, "type": "User", "login": "Alice"}},
                                   {"type": "Team", "reviewer": {"id": 92, "name": "Release"}}]},
                    {"id": 3, "node_id": "branch-node", "type": "branch_policy"}],
                "deployment_branch_policy": {"protected_branches": True, "custom_branch_policies": False}}
        target = remote.EnvironmentTarget.parse(target_value)
        facts = remote.EnvironmentFacts.upstream(body, target.selection.name)
        prepared = remote.EnvironmentPrepared(target, facts, None, now)
        prepared = remote.EnvironmentPrepared.parse(prepared.value())
        empty_custom = {"total_count": 0, "custom_deployment_protection_rules": []}
        permission = {"permission": "read", "role_name": "triage",
                      "user": {"id": 91, "login": "Alice", "type": "User"}}
        remote.environment_custom_rules_empty(empty_custom)
        self.assertEqual(prepared.after.reviewers, facts.policy.reviewers)
        self.assertTrue(prepared.after.protected_branches)
        self.assertEqual(prepared.after.wait_timer, 30)
        self.assertTrue(prepared.after.prevent_self_review)
        self.assertIn("no atomic compare-and-set", prepared.value()["confirmation"])
        self.assertIn("Administrator bypass is not observed", prepared.value()["confirmation"])
        put = prepared.after.put_value()
        self.assertEqual(set(put), {"wait_timer", "prevent_self_review", "reviewers", "deployment_branch_policy"})
        self.assertEqual(put["reviewers"], [{"type": "Team", "id": 92}, {"type": "User", "id": 91}])
        reordered = copy.deepcopy(body)
        reordered["protection_rules"].reverse()
        reordered["protection_rules"][1]["reviewers"].reverse()
        self.assertEqual(remote.EnvironmentFacts.upstream(reordered, facts.name), facts)
        # Known rule absence in the complete array is distinct from a malformed present rule.
        no_rules = {**body, "protection_rules": [], "deployment_branch_policy": None}
        unprotected = remote.EnvironmentFacts.upstream(no_rules, facts.name)
        self.assertEqual(unprotected.policy.put_value(), {"wait_timer": 0, "prevent_self_review": False,
                                                         "reviewers": None, "deployment_branch_policy": None})
        timer_only_target = remote.EnvironmentTarget.parse({**target_value,
            "selection": {**selection, "preventSelfReview": None}})
        timer_only = remote.EnvironmentPrepared.parse(remote.EnvironmentPrepared(timer_only_target, unprotected, None, now).value())
        self.assertIsNone(timer_only.after.prevent_self_review)
        self.assertEqual(timer_only.after.reviewers, ())
        # Six existing reviewers are preserved, including exact signed64 boundary IDs.
        six = copy.deepcopy(body)
        six["protection_rules"][1]["reviewers"] = [
            {"type": "Team", "reviewer": {"id": 2**63 - 1 - index}} for index in range(6)]
        maximal = remote.EnvironmentPrepared.parse(remote.EnvironmentPrepared(target,
            remote.EnvironmentFacts.upstream(six, facts.name), None, now).value())
        self.assertEqual(len(maximal.after.put_value()["reviewers"]), 6)
        self.assertLessEqual(len(remote._canonical(maximal.after.value())), remote.ENVIRONMENT_POLICY_BYTES)
        self.assertLessEqual(len(remote._canonical(maximal.before.value())), remote.ENVIRONMENT_FACTS_BYTES)
        self.assertLessEqual(len(remote._canonical(maximal.value())), remote.ENVIRONMENT_PREPARED_BYTES)
        # The future ENVIRONMENT_WRITE role must admit exactly this 43-node body;
        # existing32-node roles remain unchanged and are intentionally insufficient.
        from mobile_release._desktop_github_engine import _check_values
        _check_values(maximal.after.put_value(), nodes=64, depth=3)
        with self.assertRaises(ValueError):
            _check_values(maximal.after.put_value(), nodes=32, depth=3)
        for stage, name in remote._ENVIRONMENT_NAMES:
            for branches in ("all", "protected"):
                create = remote.EnvironmentTarget.parse({**target_value, "selection": {
                    **selection, "mode": "create", "stage": stage, "reviewerLogin": "Alice", "branches": branches}})
                absent = remote.EnvironmentFacts.absent({"total_count": 0, "environments": []}, name)
                for base_permission in ("read", "write", "admin"):
                    reviewer = remote.EnvironmentReviewer.upstream({**permission, "permission": base_permission}, "alice")
                    created = remote.EnvironmentPrepared.parse(remote.EnvironmentPrepared(create, absent, reviewer, now).value())
                    self.assertEqual(created.after.reviewers, (("User", "91"),))
                    self.assertTrue(created.after.prevent_self_review)
                    self.assertEqual(created.after.protected_branches, branches == "protected")
                    self.assertEqual(created.before.value(), {"name": name, "id": None, "policy": None})
                    created.check_fresh(absent, reviewer)
        untouched = copy.deepcopy(body)
        remote.EnvironmentFacts.upstream(body, facts.name)
        self.assertEqual(body, untouched)

        # Secret Prepare reads real fixed roles; absence exists only after its
        # environment GET and never authorizes a value comparison or an Apply.
        from mobile_release import github_setup_remote as remote
        from mobile_release._github_connection_transport import ReadFailure, ReadResult, _control
        selected = {"kind": "environment_secret", "mode": "create", "stage": "candidate",
                    "requirement": "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
                    "source": {"recordId": "1" * 32, "recordRevision": 2, "contextRevision": 3}}
        target = {"projectBinding": "a" * 64, "repository": "owner/repo", "accountId": "1",
                  "repositoryId": "2", "selection": selected}
        content = {"bytes": 27, "sha256": "b" * 64}
        source = {"root": "/inert/project", "rootIdentity": {"device": "1", "inode": "2", "mode": 0o40700, "uid": 1, "gid": 1},
                  "draft": content, "platform": "android", "purpose": "signing",
                  "material": {"encoding": "utf8", "plaintextBytes": 4}}
        action_value = {"kind": "prepare", "target": target, "prepared": None, "source": source}
        action = remote.SecretAction.parse(action_value)
        configuration = {"savedConfig": content, "canonicalConfig": content}
        now = "2026-10-09T12:00:00Z"
        steps = ("account", "repository-before", "environment-before", "secret-before", "key-before", "repository-after")
        class SecretReader:
            def __init__(self, action=action, changes=None, fault=None):
                self.schedule, self.calls = remote.SecretSchedule(action), []
                self.changes, self.fault = changes or {}, fault
            def read(self, step, reference=None):
                request = self.schedule.claim(step, reference)
                self.calls.append((step, request))
                if step == self.fault:
                    raise ReadFailure("network-unavailable")
                if step == "account":
                    body = {"id": 1, "login": "owner"}
                elif step.startswith("repository-"):
                    body = {"id": 2, "full_name": "owner/repo", "default_branch": "main", "visibility": "private", "archived": False}
                elif step == "environment-before":
                    body = {"id": 3, "name": "mobile-candidate", "protection_rules": []}
                elif step == "key-before":
                    body = {"key_id": "inert-public-key", "key": "A" * 43 + "="}
                else:
                    body = None
                body = self.changes.get(step, body)
                return ReadResult({"status": 404 if body is None else 200, "body": body, "failure": "none"}, _control())
        reader = SecretReader()
        result = remote.execute_secret_read(action, reader, configuration, observed_at=now)
        self.assertEqual([step for step, _ in reader.calls], list(steps))
        self.assertTrue(all(q.method == "GET" and q.body is None for _, q in reader.calls))
        self.assertEqual(reader.calls[3][1].path, "/repos/owner/repo/environments/mobile-candidate/secrets/" + selected["requirement"])
        self.assertEqual(reader.calls[4][1].path, "/repos/owner/repo/environments/mobile-candidate/secrets/public-key")
        self.assertIsNone(result["before"]["metadata"])
        self.assertNotIn("prepared", result)  # Python cannot mint sealed consent.
        request = remote.parse_initial(resource_bytes({"protocol": remote.PROTOCOL, "id": "secret_1", "action": action_value}) + b"\n")
        reply = json.loads(remote.encode_result(request, result))
        self.assertEqual(set(reply), {"protocol", "id", "secretRead"})
        self.assertNotIn("ciphertext", json.dumps(reply))
        self.assertLessEqual(len(remote.encode_result(request, result)), 8192)
        metadata = {"name": selected["requirement"], "created_at": now, "updated_at": "2026-10-08T12:00:00Z"}
        refused = remote.execute_secret_read(action, SecretReader(changes={"secret-before": metadata}), configuration, observed_at=now)
        self.assertEqual(refused["reason"], "secret-exists")
        replaced = copy.deepcopy(action_value); replaced["target"]["selection"]["mode"] = "replace"
        replacement = remote.SecretAction.parse(replaced)
        missing = remote.execute_secret_read(replacement, SecretReader(replacement), configuration, observed_at=now)
        self.assertEqual(missing["reason"], "secret-missing")
        found = remote.execute_secret_read(replacement, SecretReader(replacement, {"secret-before": metadata}), configuration, observed_at=now)
        self.assertEqual(found["before"]["metadata"]["updatedAt"], metadata["updated_at"])
        # Timestamps are independently valid UTC; no undocumented ordering rule.
        for fault in steps:
            reader = SecretReader(fault=fault)
            failed = remote.execute_secret_read(action, reader, configuration, observed_at=now)
            self.assertEqual(failed["reason"], "network-unavailable")
            self.assertEqual([step for step, _ in reader.calls], list(steps[:steps.index(fault)+1]))
            self.assertIs(failed["writeClaimed"], False)
            self.assertIsNone(failed["prepared"])

    def test_snapshot_nested_shapes_and_no_authority_fields_are_closed(self):
        record = {"id": "preflight", "state": "present", "byteLength": 1, "sha256": "a" * 64}
        bad = [[], {}, {"workflows": {}}, {"workflows": [], "revision": "not-authority"},
               {"workflows": [record] * 2}, {"workflows": [record] * 5}, {"workflows": [None]},
               {"workflows": [{"id": "preflight", "state": "absent", "sha256": "a" * 64}]}]
        for field, values in (("id", ("../preflight", "unknown", [], True)),
                              ("state", ("unknown", [], False)),
                              ("byteLength", (-1, True, 1.0, 1048577)),
                              ("sha256", ("A" * 64, "a" * 63, "g" * 64, "a" * 64 + "\n", None))):
            bad.extend({"workflows": [{**record, field: value}]} for value in values)
        bad.extend({"workflows": [{**record, key: "must-not-admit"}]} for key in ("path", "content", "token", "revision", "apply"))
        with patch.object(setup, "_read_resource_bytes", side_effect=AssertionError("malformed input read templates")):
            for summary in bad:
                with self.subTest(summary=summary), self.assertRaises(ApiError) as caught:
                    propose(suppliedSnapshot=summary)
                self.assertEqual(caught.exception.code, "invalid_params")

        # Actual fixed settings sequences, including every failure prefix.
        # No Operation, credential, subprocess, filesystem or network is used.
        from mobile_release import github_setup_remote as remote
        from mobile_release._github_connection_transport import ReadFailure, ReadResult, _control
        now = "2026-10-09T12:00:00Z"
        for selection, before in (
            ({"kind": "actions_enabled", "enabled": True},
             {"enabled": False, "allowed_actions": "selected", "sha_pinning_required": True}),
            ({"kind": "workflow_token_policy", "defaultWorkflowPermissions": "write", "canApprovePullRequestReviews": True},
             {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False}),
        ):
            target = remote.Target.parse({"projectBinding": "a" * 64, "repository": "owner/repo",
                                          "accountId": "1", "repositoryId": "2", "selection": selection})
            prepared = remote.Prepared.parse(remote.Prepared(target, remote.Policy.parse(selection["kind"], before), now).value())
            action = remote.Action.parse({"kind": "apply", "target": target.value(), "prepared": prepared.value()})
            initial = remote.parse_initial((json.dumps({"protocol": remote.PROTOCOL, "id": "apply", "action": action.value()}) + "\n").encode())
            steps = ["account", "repository-before", "resource-before", "write", "resource-after", "repository-after"]
            class Reader:
                def __init__(self, fault=None, replacement=None):
                    self.cursor = remote.Schedule(action)
                    self.requests = []
                    self.fault, self.replacement = fault, replacement
                def read(self, step, reference=None):
                    request = self.cursor.claim(step, reference)
                    self.requests.append(request)
                    if step == self.fault:
                        if self.replacement is None:
                            raise ReadFailure("network-unavailable")
                        return self.replacement
                    body = ({"id": 1, "login": "owner"} if step == "account" else
                            {"id": 2, "full_name": "owner/repo", "default_branch": "main", "visibility": "private", "archived": False}
                            if step.startswith("repository-") else before if step == "resource-before" else prepared.after.value())
                    return ReadResult({"status": 204 if step == "write" else 200,
                                       "body": None if step == "write" else body, "failure": "none"}, _control())
            reader = Reader()
            result = remote.execute(action, reader, observed_at=now)
            self.assertEqual(reader.cursor.steps, steps)
            self.assertEqual([r.method for r in reader.requests], ["GET", "GET", "GET", "PUT", "GET", "GET"])
            endpoint = "/repos/owner/repo/actions/permissions" + ("/workflow" if selection["kind"] == "workflow_token_policy" else "")
            self.assertEqual([r.path for r in reader.requests], ["/user", "/repos/owner/repo", endpoint, endpoint, endpoint, "/repos/owner/repo"])
            self.assertEqual(json.loads(reader.requests[3].body), prepared.after.value())
            self.assertLessEqual(len(reader.requests[3].body), remote.MAX_BODY_BYTES)
            self.assertEqual((result["reason"], result["effect"], result["writeClaimed"], result["writeAcknowledged"]),
                             ("none", "readback-confirmed", True, True))
            self.assertEqual(result["observed"], prepared.after.value())
            remote.encode_result(initial, result)
            for field, value in result["observed"].items():
                if type(value) is bool:
                    forged = copy.deepcopy(result)
                    forged["observed"][field] = int(value)
                    with self.assertRaises(ValueError):
                        remote.encode_result(initial, forged)
            with self.assertRaises(ValueError):
                reader.cursor.claim("write")
            for index, step in enumerate(steps):
                failed = Reader(step)
                row = remote.execute(action, failed, observed_at=now)
                self.assertEqual(failed.cursor.steps, steps[:index + 1])
                self.assertEqual(row["reason"], "network-unavailable")
                self.assertEqual(row["writeClaimed"], index >= 3)
                self.assertEqual(row["writeAcknowledged"], index > 3)
                self.assertEqual(row["effect"], "unknown" if index >= 3 else "not-started")
                self.assertIsNone(row["observed"])
                remote.encode_result(initial, row)
            # Stale policy is not silently rebased; successful PUT followed by
            # changed readback or failed identity POST never becomes success.
            for step, body, reason in (
                ("resource-before", prepared.after.value(), "policy-changed"),
                ("resource-after", before, "policy-changed"),
                ("account", {"id": 9, "login": "other"}, "target-changed"),
                ("repository-after", {"id": 9, "full_name": "owner/repo", "default_branch": "main", "visibility": "private", "archived": False}, "target-changed"),
            ):
                failed = Reader(step, ReadResult({"status": 200, "body": body, "failure": "none"}, _control()))
                row = remote.execute(action, failed, observed_at=now)
                self.assertEqual(row["reason"], reason)
                self.assertIsNone(row["observed"])
                self.assertEqual(row["writeClaimed"], steps.index(step) >= 3)
                remote.encode_result(initial, row)
            for status, body, failure in ((200, {}, "none"), (201, None, "none"), (204, {}, "none"),
                                          (204, None, "cancelled"), (409, None, "none")):
                failed = Reader("write", ReadResult({"status": status, "body": body, "failure": failure}, _control()))
                row = remote.execute(action, failed, observed_at=now)
                self.assertFalse(row["writeAcknowledged"])
                self.assertEqual(row["effect"], "unknown")
                self.assertEqual(len(failed.cursor.steps), 4)
                self.assertEqual(row["reason"], "organization-restricted" if status == 409 and selection["kind"] == "workflow_token_policy" else "response-invalid")
                remote.encode_result(initial, row)
            stopped = Reader("resource-before", ReadResult({"status": None, "body": None, "failure": "cancelled"}, _control("cancelled")))
            row = remote.execute(action, stopped, observed_at=now)
            self.assertEqual((row["reason"], row["effect"], len(stopped.cursor.steps)), ("cancelled", "not-started", 3))
            remote.encode_result(initial, row)
            for field, bad in (("effect", "accepted"), ("writeClaimed", False), ("writeAcknowledged", False),
                               ("observed", before), ("reason", "cancelled"), ("schemaVersion", True)):
                with self.assertRaises(ValueError):
                    remote.encode_result(initial, {**result, field: bad})

        # Fixed inert environment responses: no credential, transport or operation.
        from mobile_release import github_setup_remote as remote
        now = "2026-10-09T12:00:00Z"
        selection = {"kind": "environment_protection", "mode": "configure", "stage": "candidate",
                     "waitTimerMinutes": 30, "preventSelfReview": True, "reviewerLogin": None, "branches": None}
        target_value = {"projectBinding": "a" * 64, "repository": "owner/repo", "accountId": "1",
                        "repositoryId": "2", "selection": selection}
        body = {"id": 71, "node_id": "environment-node", "name": "mobile-candidate",
                "url": "https://api.github.com/repos/owner/repo/environments/mobile-candidate",
                "html_url": "https://github.com/owner/repo/deployments", "created_at": now, "updated_at": now,
                "protection_rules": [
                    {"id": 1, "node_id": "wait-node", "type": "wait_timer", "wait_timer": 10},
                    {"id": 2, "node_id": "review-node", "type": "required_reviewers", "prevent_self_review": False,
                     "reviewers": [{"type": "User", "reviewer": {"id": 91, "type": "User", "login": "Alice"}},
                                   {"type": "Team", "reviewer": {"id": 92, "name": "Release"}}]},
                    {"id": 3, "node_id": "branch-node", "type": "branch_policy"}],
                "deployment_branch_policy": {"protected_branches": True, "custom_branch_policies": False}}
        target = remote.EnvironmentTarget.parse(target_value)
        facts = remote.EnvironmentFacts.upstream(body, target.selection.name)
        prepared = remote.EnvironmentPrepared(target, facts, None, now)
        prepared = remote.EnvironmentPrepared.parse(prepared.value())
        empty_custom = {"total_count": 0, "custom_deployment_protection_rules": []}
        permission = {"permission": "read", "role_name": "triage",
                      "user": {"id": 91, "login": "Alice", "type": "User"}}
        bad_bodies = []
        for field in body:
            bad = copy.deepcopy(body)
            del bad[field]
            bad_bodies.append(bad)
        for kind in ("unknown", "custom", "required_reviewers", "wait_timer", "branch_policy"):
            bad = copy.deepcopy(body)
            bad["protection_rules"] = [dict(body["protection_rules"][0], type=kind)]
            if kind in {"wait_timer", "branch_policy"}:
                bad["protection_rules"].append(copy.deepcopy(bad["protection_rules"][0]))
            bad_bodies.append(bad)
        for original_rule in body["protection_rules"]:
            duplicate = [copy.deepcopy(original_rule), copy.deepcopy(original_rule)]
            if original_rule["type"] != "branch_policy":
                duplicate.append(copy.deepcopy(body["protection_rules"][2]))
            bad_bodies.append({**body, "protection_rules": duplicate})
        for rule_index, field in ((0, "wait_timer"), (1, "prevent_self_review"), (1, "reviewers")):
            bad = copy.deepcopy(body)
            del bad["protection_rules"][rule_index][field]
            bad_bodies.append(bad)
        for field, values in (("wait_timer", (True, -1, 43201, 1.0)), ("prevent_self_review", (0, 1, None))):
            for value in values:
                bad = copy.deepcopy(body)
                bad["protection_rules"][0 if field == "wait_timer" else 1][field] = value
                bad_bodies.append(bad)
        for value in ([], None, body["protection_rules"][1]["reviewers"] * 4,
                      [body["protection_rules"][1]["reviewers"][0]] * 2):
            bad = copy.deepcopy(body)
            bad["protection_rules"][1]["reviewers"] = value
            bad_bodies.append(bad)
        for branch in ({"protected_branches": False, "custom_branch_policies": True},
                       {"protected_branches": 1, "custom_branch_policies": 0}, {}, None):
            bad_bodies.append({**body, "deployment_branch_policy": branch})
        bad_bodies.extend(({**body, "can_admins_bypass": False}, {**body, "id": True},
                           {**body, "id": 2**63}, {**body, "name": "other"}))
        for bad in bad_bodies:
            with self.subTest(environment=bad), self.assertRaises(ValueError):
                remote.EnvironmentFacts.upstream(bad, facts.name)
        for bad in ({}, {"total_count": False, "custom_deployment_protection_rules": []},
                    {"total_count": 1, "custom_deployment_protection_rules": []},
                    {"total_count": 0, "custom_deployment_protection_rules": [{}]},
                    {**empty_custom, "next_page": None}):
            with self.assertRaises(ValueError):
                remote.environment_custom_rules_empty(bad)
        for bad in ({}, {"total_count": True, "environments": []}, {"total_count": 1, "environments": []},
                    {"total_count": 101, "environments": [{"id": index + 1, "name": "e" + str(index)} for index in range(101)]},
                    {"total_count": 2, "environments": [{"id": 1, "name": "Other"}, {"id": 2, "name": "other"}]},
                    {"total_count": 2, "environments": [{"id": 1, "name": "one"}, {"id": 1, "name": "two"}]},
                    {"total_count": 1, "environments": [{"id": 71, "name": "MOBILE-CANDIDATE"}]}):
            with self.assertRaises(ValueError):
                remote.EnvironmentFacts.absent(bad, facts.name)
        complete = {"total_count": 100, "environments": [{"id": i + 1, "name": "other-" + str(i)} for i in range(100)]}
        self.assertIsNone(remote.EnvironmentFacts.absent(complete, facts.name).identity)
        for bad in ({**permission, "permission": "none"}, {**permission, "permission": "triage"},
                    {**permission, "permission": "maintain"}, {**permission, "permission": True},
                    {**permission, "user": None}, {**permission, "user": {**permission["user"], "type": "Bot"}},
                    {**permission, "user": {**permission["user"], "id": True}},
                    {**permission, "user": {**permission["user"], "login": "Mallory"}}):
            with self.assertRaises(ValueError):
                remote.EnvironmentReviewer.upstream(bad, "Alice")
        for field, bad_value in (("waitTimerMinutes", True), ("preventSelfReview", 1), ("stage", "other"),
                                 ("branches", "all"), ("reviewerLogin", "Alice"), ("mode", "delete")):
            with self.assertRaises(ValueError):
                remote.EnvironmentSelection.parse({**selection, field: bad_value})
        for login in ("../x", "a/b", "-a", "a-", "a--b", "a" * 40, "a\n", "é"):
            with self.assertRaises(ValueError):
                remote.EnvironmentSelection.parse({**selection, "mode": "create", "branches": "all", "reviewerLogin": login})
        for field, bad_value in (("waitTimerMinutes", True), ("protectedBranches", 1)):
            bad = prepared.value()
            bad["after"][field] = bad_value
            with self.assertRaises(ValueError):
                remote.EnvironmentPrepared.parse(bad)
        bad = prepared.value()
        bad["after"]["requiredReviewers"]["preventSelfReview"] = 1
        with self.assertRaises(ValueError):
            remote.EnvironmentPrepared.parse(bad)
        for field in ("target", "before", "after", "reviewer", "observedAt", "confirmation"):
            bad = prepared.value()
            del bad[field]
            with self.assertRaises(ValueError):
                remote.EnvironmentPrepared.parse(bad)
        for bad in ({"name": facts.name, "id": None, "policy": facts.policy.value()},
                    {"name": facts.name, "id": "71", "policy": None}):
            with self.assertRaises(ValueError):
                remote.EnvironmentFacts.parse(bad)
        unsupported = remote.EnvironmentFacts.upstream({**body, "protection_rules": [], "deployment_branch_policy": None}, facts.name)
        with self.assertRaises(ValueError):
            remote.EnvironmentPrepared.parse(remote.EnvironmentPrepared(target, unsupported, None, now).value())
        no_change_target = remote.EnvironmentTarget.parse({**target_value, "selection": {
            **selection, "waitTimerMinutes": 10, "preventSelfReview": None}})
        with self.assertRaises(remote.Refused) as caught:
            remote.EnvironmentPrepared.parse(remote.EnvironmentPrepared(no_change_target, facts, None, now).value())
        self.assertEqual(caught.exception.reason, "no-change")

        # Strict secret read-back DATA does not inherit Python bool/int equality.
        from mobile_release import github_setup_remote as remote
        from mobile_release._github_connection_transport import ReadFailure, ReadResult, _control
        selected = {"kind": "environment_secret", "mode": "create", "stage": "candidate",
                    "requirement": "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
                    "source": {"recordId": "1" * 32, "recordRevision": 2, "contextRevision": 3}}
        target = {"projectBinding": "a" * 64, "repository": "owner/repo", "accountId": "1",
                  "repositoryId": "2", "selection": selected}
        content = {"bytes": 27, "sha256": "b" * 64}
        source = {"root": "/inert/project", "rootIdentity": {"device": "1", "inode": "2", "mode": 0o40700, "uid": 1, "gid": 1},
                  "draft": content, "platform": "android", "purpose": "signing",
                  "material": {"encoding": "utf8", "plaintextBytes": 4}}
        action_value = {"kind": "prepare", "target": target, "prepared": None, "source": source}
        action = remote.SecretAction.parse(action_value)
        configuration = {"savedConfig": content, "canonicalConfig": content}
        now = "2026-10-09T12:00:00Z"
        steps = ("account", "repository-before", "environment-before", "secret-before", "key-before", "repository-after")
        class SecretReader:
            def __init__(self, action=action, changes=None, fault=None):
                self.schedule, self.calls = remote.SecretSchedule(action), []
                self.changes, self.fault = changes or {}, fault
            def read(self, step, reference=None):
                request = self.schedule.claim(step, reference)
                self.calls.append((step, request))
                if step == self.fault:
                    raise ReadFailure("network-unavailable")
                if step == "account":
                    body = {"id": 1, "login": "owner"}
                elif step.startswith("repository-"):
                    body = {"id": 2, "full_name": "owner/repo", "default_branch": "main", "visibility": "private", "archived": False}
                elif step == "environment-before":
                    body = {"id": 3, "name": "mobile-candidate", "protection_rules": []}
                elif step == "key-before":
                    body = {"key_id": "inert-public-key", "key": "A" * 43 + "="}
                else:
                    body = None
                body = self.changes.get(step, body)
                return ReadResult({"status": 404 if body is None else 200, "body": body, "failure": "none"}, _control())
        result = remote.execute_secret_read(action, SecretReader(), configuration, observed_at=now)
        request = remote.parse_initial(resource_bytes({"protocol": remote.PROTOCOL, "id": "secret_1", "action": action_value}) + b"\n")
        for pointer, bad in (("schemaVersion", True), ("material.plaintextBytes", True),
                             ("configuration.savedConfig.bytes", True), ("before.environmentId", 3),
                             ("key.value", "A" * 42 + "B="), ("key.value", "A" * 44),
                             ("key.id", "bad key"), ("target.selection.source.recordRevision", True)):
            changed = copy.deepcopy(result); node = changed
            parts = pointer.split(".")
            for part in parts[:-1]: node = node[part]
            node[parts[-1]] = bad
            with self.subTest(pointer=pointer, bad=bad), self.assertRaises((ValueError, TypeError)):
                remote.encode_result(request, changed)
        for role in ("environment-before", "repository-before", "key-before"):
            value = remote.execute_secret_read(action, SecretReader(changes={role: None}), configuration, observed_at=now)
            self.assertNotIn("target", value)
            self.assertNotEqual(value["reason"], "none")
        for name, (platform, encoding) in remote.SECRET_REQUIREMENTS.items():
            value = copy.deepcopy(action_value)
            value["target"]["selection"]["requirement"] = name
            value["source"].update(platform=platform, material={"encoding": encoding, "plaintextBytes": 49152})
            remote.SecretAction.parse(value)
            value["source"]["material"]["plaintextBytes"] += 1
            with self.assertRaises(ValueError): remote.SecretAction.parse(value)

    def test_request_keys_pin_errors_and_future_action_names_reject_without_reads(self):
        bad = []
        for key in params():
            missing = params()
            del missing[key]
            bad.append(missing)
        bad.extend(params(**{key: "private-value"}) for key in ("root", "templateDir", "template", "url", "token", "secrets", "apply", "force", "revision"))
        bad.extend((params(toolingRepository="private-invalid-url"), params(toolingSha="private-invalid-pin")))
        with patch.object(setup, "_read_resource_bytes", side_effect=AssertionError("malformed input read templates")):
            for request in bad:
                with self.assertRaises(ApiError) as caught:
                    execute("github.setup.propose", request)
                self.assertEqual(caught.exception.code, "invalid_params")
                self.assertNotIn("private-", caught.exception.message)
            for action in ("github.setup", "github.authenticate", "github.setup.apply"):
                with self.assertRaises(ApiError):
                    execute(action, {})

        from mobile_release import github_setup_remote as remote
        target = {"projectBinding": "a" * 64, "repository": "owner/repo", "accountId": "1", "repositoryId": "2",
                  "selection": {"kind": "actions_enabled", "enabled": True}}
        action = {"kind": "prepare", "target": target, "prepared": None}
        envelope = {"protocol": remote.PROTOCOL, "id": "request_1", "action": action}
        raw = (json.dumps(envelope) + "\n").encode()
        request = remote.parse_initial(raw)
        self.assertEqual(request.digest, hashlib.sha256(raw).hexdigest())
        self.assertEqual(json.loads(remote.ready_frame(request)), {"protocol": remote.PROTOCOL, "id": "request_1", "ready": {"requestSha256": request.digest}})
        go = {"protocol": remote.PROTOCOL, "id": "request_1", "go": {"requestSha256": request.digest, "token": "inert-token"}}
        encode = lambda value: (json.dumps(value) + "\n").encode()
        self.assertEqual(remote.parse_go(encode(go), request), "inert-token")
        self.assertNotIn("inert-token", repr(request))
        self.assertEqual((remote.MAX_INITIAL_BYTES, remote.MAX_GO_BYTES, remote.MAX_READY_BYTES, remote.MAX_RESULT_BYTES), (8192, 8192, 512, 65536))
        for bad in (raw[:-1], raw + b"\n", b" \n" + raw, raw.replace(b"\n", b"\r\n"),
                    b" " * remote.MAX_INITIAL_BYTES + raw,
                    raw.replace(b'"id": "request_1"', b'"id": "request_1", "id": "second"')):
            with self.assertRaises(ValueError):
                remote.parse_initial(bad)
        for key in ("token", "url", "home", "pendingScope", "method", "body", "deadline"):
            with self.assertRaises(ValueError):
                remote.parse_initial(encode({**envelope, key: "private-not-authority"}))
        for key, bad in (("protocol", "mrk-github-readonly/1"), ("id", "different")):
            with self.assertRaises(ValueError):
                remote.parse_go(encode({**go, key: bad}), request)
        for key, bad in (("requestSha256", "b" * 64), ("token", ""), ("token", "x" * 4097),
                         ("token", "line\nbreak"), ("token", "é"), ("url", "https://untrusted.invalid")):
            with self.assertRaises(ValueError):
                remote.parse_go(encode({**go, "go": {**go["go"], key: bad}}), request)
        for selection in ({"kind": "secret", "enabled": True}, {"kind": "environment", "enabled": True},
                          {"kind": "actions_enabled", "enabled": 1}, {"kind": "actions_enabled", "enabled": True, "allowed_actions": "all"},
                          {"kind": "workflow_token_policy", "defaultWorkflowPermissions": "admin", "canApprovePullRequestReviews": False}):
            with self.assertRaises(ValueError):
                remote.Action.parse({**action, "target": {**target, "selection": selection}})
        for changes in ({"kind": "apply"}, {"prepared": {}}, {"kind": "delete"}, {"url": "https://untrusted.invalid"}):
            with self.assertRaises(ValueError):
                remote.Action.parse({**action, **changes})
        original = copy.deepcopy(envelope)
        remote.parse_initial(raw)
        self.assertEqual(envelope, original)
        # These pure codecs do not activate a route or instantiate transport.
        self.assertFalse(hasattr(remote, "main"))
        with patch.object(remote, "_make_live_reader", side_effect=AssertionError("pure codec entered transport")):
            remote.parse_initial(raw)
            remote.parse_go(encode(go), request)

        # Fixed inert environment responses: no credential, transport or operation.
        from mobile_release import github_setup_remote as remote
        now = "2026-10-09T12:00:00Z"
        selection = {"kind": "environment_protection", "mode": "configure", "stage": "candidate",
                     "waitTimerMinutes": 30, "preventSelfReview": True, "reviewerLogin": None, "branches": None}
        target_value = {"projectBinding": "a" * 64, "repository": "owner/repo", "accountId": "1",
                        "repositoryId": "2", "selection": selection}
        body = {"id": 71, "node_id": "environment-node", "name": "mobile-candidate",
                "url": "https://api.github.com/repos/owner/repo/environments/mobile-candidate",
                "html_url": "https://github.com/owner/repo/deployments", "created_at": now, "updated_at": now,
                "protection_rules": [
                    {"id": 1, "node_id": "wait-node", "type": "wait_timer", "wait_timer": 10},
                    {"id": 2, "node_id": "review-node", "type": "required_reviewers", "prevent_self_review": False,
                     "reviewers": [{"type": "User", "reviewer": {"id": 91, "type": "User", "login": "Alice"}},
                                   {"type": "Team", "reviewer": {"id": 92, "name": "Release"}}]},
                    {"id": 3, "node_id": "branch-node", "type": "branch_policy"}],
                "deployment_branch_policy": {"protected_branches": True, "custom_branch_policies": False}}
        target = remote.EnvironmentTarget.parse(target_value)
        facts = remote.EnvironmentFacts.upstream(body, target.selection.name)
        prepared = remote.EnvironmentPrepared(target, facts, None, now)
        prepared = remote.EnvironmentPrepared.parse(prepared.value())
        empty_custom = {"total_count": 0, "custom_deployment_protection_rules": []}
        permission = {"permission": "read", "role_name": "triage",
                      "user": {"id": 91, "login": "Alice", "type": "User"}}
        create_target = remote.EnvironmentTarget.parse({**target_value, "selection": {
            **selection, "mode": "create", "reviewerLogin": "Alice", "branches": "protected"}})
        absent = remote.EnvironmentFacts.absent({"total_count": 0, "environments": []}, facts.name)
        reviewer = remote.EnvironmentReviewer.upstream(permission, "Alice")
        creation = remote.EnvironmentPrepared.parse(remote.EnvironmentPrepared(create_target, absent, reviewer, now).value())
        with patch.object(remote, "_make_live_reader", side_effect=AssertionError("environment DATA entered live transport")):
            for plan in (prepared, creation):
                for action_kind in ("prepare", "apply"):
                    action = remote.EnvironmentAction.parse({"kind": action_kind, "target": plan.target.value(),
                        "prepared": None if action_kind == "prepare" else plan.value()})
                    schedule = remote.EnvironmentSchedule(action)
                    is_create = plan.target.selection.mode == "create"
                    expected = ["account", "repository-before"] + (
                        ["absence-before", "reviewer-before"] if is_create else ["environment-before", "custom-before"])
                    if action_kind == "apply":
                        expected += ["write", "environment-after", "custom-after"]
                    expected += ["repository-after"]
                    with self.assertRaises(ValueError):
                        schedule.claim("write")
                    self.assertEqual(schedule.steps, [])
                    with self.assertRaises(ValueError):
                        schedule.claim("account", "https://untrusted.invalid/")
                    requests = [schedule.claim(step) for step in expected]
                    self.assertEqual(schedule.steps, expected)
                    self.assertEqual(len(requests), 5 if action_kind == "prepare" else 8)
                    self.assertEqual(sum(request.method == "PUT" for request in requests), int(action_kind == "apply"))
                    self.assertEqual(requests[0].path, "/user")
                    self.assertEqual(requests[1].path, "/repos/owner/repo")
                    self.assertEqual(requests[-1].path, "/repos/owner/repo")
                    prefix = "/repos/owner/repo/environments/mobile-candidate"
                    self.assertEqual(requests[2].path, "/repos/owner/repo/environments?per_page=100&page=1" if is_create else prefix)
                    self.assertEqual(requests[3].path, "/repos/owner/repo/collaborators/Alice/permission" if is_create else prefix + "/deployment_protection_rules")
                    if action_kind == "apply":
                        self.assertEqual(requests[4].path, prefix)
                        self.assertEqual(json.loads(requests[4].body), plan.after.put_value())
                        self.assertEqual(requests[5].path, prefix)
                        self.assertEqual(requests[6].path, prefix + "/deployment_protection_rules")
                    for step in ("account", "write", "repository-after", "retry"):
                        with self.assertRaises(ValueError):
                            schedule.claim(step)
                    # Old Action/Schedule never admit this new DATA variant.
                    with self.assertRaises(ValueError):
                        remote.Action.parse(action.value())
                    with self.assertRaises(ValueError):
                        remote.Schedule(action)
        self.assertEqual(remote.MAX_REQUESTS, 6)
        self.assertEqual(remote.KINDS, {"actions_enabled", "workflow_token_policy"})
        prepared.check_fresh(facts, None)
        after = remote.EnvironmentFacts.parse({"name": facts.name, "id": facts.identity, "policy": prepared.after.value()})
        prepared.check_readback(after, after)
        creation_after = remote.EnvironmentFacts.parse({"name": facts.name, "id": "72", "policy": creation.after.value()})
        creation.check_readback(creation_after, creation_after)
        for changed in (absent, remote.EnvironmentFacts.parse({**facts.value(), "id": "72"}), after):
            with self.assertRaises(ValueError):
                prepared.check_fresh(changed, None)
        with self.assertRaises(ValueError):
            creation.check_fresh(facts, reviewer)
        for changed in (remote.EnvironmentReviewer("92", "Alice", "read"),
                        remote.EnvironmentReviewer("91", "Alice", "write"),
                        remote.EnvironmentReviewer("91", "Bob", "read"), None):
            with self.assertRaises(ValueError):
                creation.check_fresh(absent, changed)
        recreated = remote.EnvironmentFacts.parse({**after.value(), "id": "72"})
        for ack, post in ((after, facts), (after, absent), (after, recreated), (recreated, recreated)):
            with self.assertRaises(ValueError):
                prepared.check_readback(ack, post)
        # No finality or write-success flag is manufactured by these DATA comparisons.
        self.assertIsNone(prepared.check_readback(after, after))
        self.assertFalse(hasattr(remote.EnvironmentSchedule, "execute"))

        # Same real EnvironmentSchedule and execute_environment, with inert
        # returned observations. Every claimed exchange can fail independently.
        from mobile_release._github_connection_transport import ReadResult, ReadFailure, _control
        repo = {"id": 2, "full_name": "owner/repo", "default_branch": "main", "visibility": "private", "archived": False}
        def env_body(plan, identity):
            desired = plan.after
            rules = [{"id": 1, "node_id": "wait", "type": "wait_timer", "wait_timer": desired.wait_timer}]
            if desired.prevent_self_review is not None:
                rules.append({"id": 2, "node_id": "review", "type": "required_reviewers",
                    "prevent_self_review": desired.prevent_self_review,
                    "reviewers": [{"type": kind, "reviewer": {"id": int(number), **({"type": "User"} if kind == "User" else {})}}
                                  for kind, number in desired.reviewers]})
            if desired.protected_branches:
                rules.append({"id": 3, "node_id": "branch", "type": "branch_policy"})
            return {**body, "id": identity, "name": plan.target.selection.name, "protection_rules": rules,
                    "deployment_branch_policy": desired.put_value()["deployment_branch_policy"]}
        class EnvironmentReader:
            def __init__(self, action, rows, fault=None, failure=None):
                self.cursor = remote.EnvironmentSchedule(action)
                self.rows, self.fault, self.failure = rows, fault, failure
            def read(self, step, reference=None):
                self.cursor.claim(step, reference)
                if step == self.fault:
                    if self.failure is None:
                        raise ReadFailure("network-unavailable")
                    return self.failure
                return ReadResult({"status": 200, "body": self.rows[step], "failure": "none"}, _control())
        for plan in (prepared, creation):
            is_create = plan.target.selection.mode == "create"
            rows = {"account": {"id": 1, "login": "owner"}, "repository-before": repo, "repository-after": repo,
                    "environment-before": body, "custom-before": empty_custom,
                    "absence-before": {"total_count": 0, "environments": []}, "reviewer-before": permission,
                    "write": env_body(plan, 72 if is_create else 71),
                    "environment-after": env_body(plan, 72 if is_create else 71), "custom-after": empty_custom}
            for action_kind in ("prepare", "apply"):
                action = remote.EnvironmentAction.parse({"kind": action_kind, "target": plan.target.value(),
                    "prepared": plan.value() if action_kind == "apply" else None})
                initial = remote.parse_initial(remote._canonical({"protocol": remote.PROTOCOL, "id": "setup",
                                                                  "action": action.value()}) + b"\n")
                reader = EnvironmentReader(action, rows)
                result = remote.execute_environment(action, reader, observed_at=now)
                steps = reader.cursor.steps
                self.assertEqual((result["reason"], result["effect"], len(steps)),
                                 ("none", "readback-confirmed" if action_kind == "apply" else "not-started",
                                  8 if action_kind == "apply" else 5))
                self.assertEqual(result["writeClaimed"], action_kind == "apply")
                self.assertEqual(result["writeAcknowledged"], action_kind == "apply")
                self.assertEqual(json.loads(remote.encode_result(initial, result))["result"], result)
                for fault in steps:
                    cut = EnvironmentReader(action, rows, fault)
                    failed = remote.execute_environment(action, cut, observed_at=now)
                    write_claimed = "write" in cut.cursor.steps
                    self.assertEqual(failed["effect"], "unknown" if write_claimed else "not-started")
                    self.assertEqual(failed["writeAcknowledged"], write_claimed and fault != "write")
                    self.assertIsNone(failed["prepared"])
                    self.assertIsNone(failed["observed"])
                    self.assertEqual(len(cut.cursor.steps), steps.index(fault) + 1)
                    remote.encode_result(initial, failed)
                if action_kind == "apply":
                    for status in (204, 409, 422, 401, 403, 404, 500):
                        failed = remote.execute_environment(action, EnvironmentReader(action, rows, "write",
                            ReadResult({"status": status, "body": None, "failure": "none"}, _control())), observed_at=now)
                        self.assertEqual(failed["effect"], "unknown")
                        self.assertFalse(failed["writeAcknowledged"])
                        self.assertEqual(failed["reason"], {422: "policy-unsupported", 401: "unauthorized", 403: "forbidden",
                            404: "not-found-or-inaccessible", 500: "network-unavailable"}.get(status, "response-invalid"))
                        remote.encode_result(initial, failed)
                    mutations = [("custom-after", {"total_count": 1, "custom_deployment_protection_rules": [{}]}),
                        ("environment-after", {**rows["environment-after"], "id": 73}),
                        ("repository-after", {**repo, "id": 9}), ("write", {**rows["write"], "protection_rules": []})]
                    mutations += ([("absence-before", {"total_count": 1, "environments": [{"id": 71, "name": facts.name}]}),
                                   ("reviewer-before", {**permission, "user": {**permission["user"], "id": 92}})] if is_create else
                                  [("custom-before", {"total_count": 1, "custom_deployment_protection_rules": [{}]}),
                                   ("environment-before", {**body, "id": 73})])
                    for step, changed in mutations:
                        cut = EnvironmentReader(action, {**rows, step: changed})
                        failed = remote.execute_environment(action, cut, observed_at=now)
                        self.assertNotEqual(failed["reason"], "none")
                        self.assertEqual(failed["effect"], "unknown" if "write" in cut.cursor.steps else "not-started")
                        self.assertIsNone(failed["observed"])
                        remote.encode_result(initial, failed)
                    for key, altered in (("observed", facts.value()), ("writeClaimed", False), ("writeAcknowledged", False),
                                         ("effect", "not-started"), ("reason", "cancelled")):
                        with self.assertRaises(ValueError):
                            remote.encode_result(initial, {**result, key: altered})
        # Configure no-change still performs the final identity observation and
        # creates neither consent nor an invented write opportunity.
        same_target = remote.EnvironmentTarget.parse({**target_value, "selection": {
            **selection, "waitTimerMinutes": 10, "preventSelfReview": None}})
        same = remote.EnvironmentAction("prepare", same_target)
        same_rows = {"account": {"id": 1, "login": "owner"}, "repository-before": repo, "repository-after": repo,
                     "environment-before": body, "custom-before": empty_custom}
        same_reader = EnvironmentReader(same, same_rows)
        same_result = remote.execute_environment(same, same_reader, observed_at=now)
        self.assertEqual((same_result["reason"], len(same_reader.cursor.steps)), ("no-change", 5))
        initial = remote.parse_initial(remote._canonical({"protocol": remote.PROTOCOL, "id": "setup", "action": same.value()}) + b"\n")
        remote.encode_result(initial, same_result)
        self.assertIsNone(same_result["prepared"])

        # The new private source is mandatory only for the exact secret Prepare;
        # no generic material, field, arbitrary name or missing Apply Prepared.
        from mobile_release import github_setup_remote as remote
        from mobile_release._github_connection_transport import ReadFailure, ReadResult, _control
        selected = {"kind": "environment_secret", "mode": "create", "stage": "candidate",
                    "requirement": "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
                    "source": {"recordId": "1" * 32, "recordRevision": 2, "contextRevision": 3}}
        target = {"projectBinding": "a" * 64, "repository": "owner/repo", "accountId": "1",
                  "repositoryId": "2", "selection": selected}
        content = {"bytes": 27, "sha256": "b" * 64}
        source = {"root": "/inert/project", "rootIdentity": {"device": "1", "inode": "2", "mode": 0o40700, "uid": 1, "gid": 1},
                  "draft": content, "platform": "android", "purpose": "signing",
                  "material": {"encoding": "utf8", "plaintextBytes": 4}}
        action_value = {"kind": "prepare", "target": target, "prepared": None, "source": source}
        action = remote.SecretAction.parse(action_value)
        configuration = {"savedConfig": content, "canonicalConfig": content}
        now = "2026-10-09T12:00:00Z"
        steps = ("account", "repository-before", "environment-before", "secret-before", "key-before", "repository-after")
        class SecretReader:
            def __init__(self, action=action, changes=None, fault=None):
                self.schedule, self.calls = remote.SecretSchedule(action), []
                self.changes, self.fault = changes or {}, fault
            def read(self, step, reference=None):
                request = self.schedule.claim(step, reference)
                self.calls.append((step, request))
                if step == self.fault:
                    raise ReadFailure("network-unavailable")
                if step == "account":
                    body = {"id": 1, "login": "owner"}
                elif step.startswith("repository-"):
                    body = {"id": 2, "full_name": "owner/repo", "default_branch": "main", "visibility": "private", "archived": False}
                elif step == "environment-before":
                    body = {"id": 3, "name": "mobile-candidate", "protection_rules": []}
                elif step == "key-before":
                    body = {"key_id": "inert-public-key", "key": "A" * 43 + "="}
                else:
                    body = None
                body = self.changes.get(step, body)
                return ReadResult({"status": 404 if body is None else 200, "body": body, "failure": "none"}, _control())
        for mutate in (
            lambda v: v.update(kind="apply"), lambda v: v.pop("source"),
            lambda v: v.update(request=v.pop("target")),
            lambda v: v["source"].update(material={"encoding": "base64", "plaintextBytes": 4}),
            lambda v: v["target"]["selection"].update(requirement="MOBILE_RELEASE_ANDROID_KEY_ALIAS"),
            lambda v: v["target"]["selection"]["source"].update(field="storePassword"),
            lambda v: v["target"]["selection"]["source"].update(recordRevision=True),
            lambda v: v["source"].update(rootIdentity={"device": "01", "inode": "2", "mode": 0o40700, "uid": 1, "gid": 1}),
        ):
            value = copy.deepcopy(action_value); mutate(value)
            with self.assertRaises((ValueError, TypeError, KeyError)):
                remote.parse_initial(resource_bytes({"protocol": remote.PROTOCOL, "id": "secret_1", "action": value}) + b"\n")
        request = remote.parse_initial(resource_bytes({"protocol": remote.PROTOCOL, "id": "secret_1", "action": action_value}) + b"\n")
        failed = {"schemaVersion": 1, "action": "prepare", "reason": "resources-unavailable", "effect": "not-started",
                  "writeClaimed": False, "writeAcknowledged": False, "prepared": None, "observed": None, "control": _control()}
        self.assertEqual(json.loads(remote.encode_result(request, failed))["result"]["reason"], "resources-unavailable")
        # Actual HTTP control must survive a later configuration POST failure,
        # including a prior finite failure already returned by the read engine.
        for actual in (_control("unauthorized"), _control("rate-limited", 31),
                       _control("rate-limited", blocked=True), _control("response-invalid", 9),
                       {**_control(), "credentialExpiresAt": now}):
            converted = remote.secret_configuration_failure("configuration-changed", actual)
            self.assertEqual(converted["control"], actual)
            self.assertIsNot(converted["control"], actual)
            self.assertEqual(converted["reason"], actual["reason"] if actual["reason"] != "none" else "configuration-changed")
            self.assertEqual((converted["writeClaimed"], converted["writeAcknowledged"], converted["effect"]), (False, False, "not-started"))
            self.assertEqual(json.loads(remote.encode_result(request, converted))["result"]["control"], actual)
            prior = {**converted, "reason": actual["reason"] if actual["reason"] != "none" else "network-unavailable"}
            self.assertEqual(remote.secret_configuration_failure("resources-unavailable", actual, prior)["reason"], prior["reason"])
        with self.assertRaises(ValueError):
            remote.secret_configuration_failure("none", _control())
        with self.assertRaises(ValueError):
            remote.secret_configuration_failure("configuration-changed", _control("rate-limited", 0))
        for field, value in (("reason", "none"), ("writeClaimed", 0), ("effect", "accepted-not-value-verified"), ("prepared", {})):
            changed = {**failed, field: value}
            with self.assertRaises(ValueError): remote.encode_result(request, changed)
        schedule = remote.SecretSchedule(action)
        with self.assertRaises(ValueError): schedule.claim("key-before")
        for step in steps: schedule.claim(step)
        with self.assertRaises(ValueError): schedule.claim("account")

        # Sealed Apply uses the same explicit source/configuration but a new
        # fixed nine-step plan. These ciphertext bytes are inert public DATA.
        import base64
        prepared_secret = {"target": target, "before": {"environmentName": "mobile-candidate", "environmentId": "3",
            "name": selected["requirement"], "metadata": None}, "after": {"name": selected["requirement"], **source["material"]},
            "configuration": configuration, "observedAt": now, "confirmation": remote.SECRET_CONFIRMATION}
        applying = remote.SecretAction.parse({**action_value, "kind": "apply", "prepared": prepared_secret})
        sealed = {"key": {"id": "inert-public-key", "value": "A" * 43 + "="}, "encryptedValue": base64.b64encode(bytes(52)).decode("ascii")}
        apply_initial = remote.parse_initial(resource_bytes({"protocol": remote.PROTOCOL, "id": "secret_1", "action": applying.value()}) + b"\n")
        go = {"protocol": remote.PROTOCOL, "id": "secret_1", "go": {"requestSha256": apply_initial.digest, "token": "inert", "sealed": sealed}}
        go_raw = resource_bytes(go) + b"\n"
        self.assertEqual(remote.parse_secret_apply_go(go_raw, apply_initial), ("inert", sealed))
        with self.assertRaises(ValueError): remote.parse_go(go_raw, apply_initial)
        with self.assertRaises(ValueError): remote.parse_secret_apply_go(go_raw, request)
        for change in (lambda v: v["go"].update(requestSha256="c" * 64), lambda v: v["go"]["sealed"].update(encryptedValue="A" * 70),
                       lambda v: v["go"]["sealed"].update(key={"id": "bad key", "value": "A" * 43 + "="}),
                       lambda v: v.update(action="apply"), lambda v: v["go"].update(token="x" * 4097)):
            changed = copy.deepcopy(go); change(changed)
            with self.assertRaises(ValueError): remote.parse_secret_apply_go(resource_bytes(changed) + b"\n", apply_initial)
        class ApplyReader:
            def __init__(self, failure=None, changed=None):
                self.plan = remote.SecretApplySchedule(applying, sealed)
                self.steps = []; self.failure = failure; self.changed = changed
            def read(self, step, reference=None):
                admitted = self.plan.claim(step, reference); self.steps.append(step)
                if self.failure == step: raise ReadFailure("network-unavailable")
                if step == "write":
                    self_outer.assertEqual((admitted.method, admitted.path), ("PUT", "/repos/owner/repo/environments/mobile-candidate/secrets/" + selected["requirement"]))
                    self_outer.assertEqual(json.loads(admitted.body), {"encrypted_value": sealed["encryptedValue"], "key_id": sealed["key"]["id"]})
                    return ReadResult({"status": 201, "body": {}, "failure": "none"}, _control())
                if step == "secret-after":
                    body = {"name": selected["requirement"], "created_at": now, "updated_at": now}
                elif step == "environment-after": body = {"id": 3, "name": "mobile-candidate"}
                else:
                    source_reader = SecretReader()
                    # Only observation rows are reused; actual Apply schedule
                    # above still consumes every request in strict order.
                    source_reader.schedule.next = steps.index(step)
                    return source_reader.read(step)
                if self.changed == step: body["id"] = 4
                return ReadResult({"status": 200, "body": body, "failure": "none"}, _control())
        self_outer = self
        all_steps = ("account", "repository-before", "environment-before", "secret-before", "key-before", "write",
                     "secret-after", "environment-after", "repository-after")
        reader = ApplyReader(); progress = remote.SecretApplyProgress()
        applied = remote.execute_secret_apply(applying, reader, configuration, key=sealed["key"], progress=progress)
        self.assertEqual(reader.steps, list(all_steps))
        self.assertEqual((applied["reason"], applied["effect"], applied["writeClaimed"], applied["writeAcknowledged"]),
                         ("none", "accepted-not-value-verified", True, True))
        self.assertEqual(json.loads(remote.encode_result(apply_initial, applied))["result"], applied)
        for index, step in enumerate(all_steps):
            reader = ApplyReader(failure=step); progress = remote.SecretApplyProgress()
            failed_apply = remote.execute_secret_apply(applying, reader, configuration, key=sealed["key"], progress=progress)
            self.assertEqual(reader.steps, list(all_steps[:index + 1]))
            self.assertEqual((failed_apply["reason"], failed_apply["writeClaimed"], failed_apply["writeAcknowledged"]),
                             ("network-unavailable", index >= 5, index > 5))
            self.assertEqual(failed_apply["effect"], "unknown" if index >= 5 else "not-started")
            remote.encode_result(apply_initial, failed_apply)
        changed_reader = ApplyReader(changed="environment-after")
        changed = remote.execute_secret_apply(applying, changed_reader, configuration, key=sealed["key"], progress=remote.SecretApplyProgress())
        self.assertEqual((changed["reason"], changed["effect"], changed["writeAcknowledged"]), ("target-changed", "unknown", True))
        self.assertEqual(changed_reader.steps[-1], "environment-after")
        stale_key = {**sealed["key"], "id": "different-public-key"}
        reader = ApplyReader()
        changed = remote.execute_secret_apply(applying, reader, configuration, key=stale_key, progress=remote.SecretApplyProgress())
        self.assertEqual((changed["reason"], len(reader.steps), changed["writeClaimed"]), ("secret-key-changed", 5, False))
        progress = remote.SecretApplyProgress(); progress.claimed = True; progress.acknowledged = True
        post_failure = remote.secret_configuration_failure("configuration-changed", _control(), applied, progress=progress)
        self.assertEqual((post_failure["effect"], post_failure["writeClaimed"], post_failure["writeAcknowledged"], post_failure["observed"]),
                         ("unknown", True, True, None))
        remote.encode_result(apply_initial, post_failure)
        self.assertEqual(remote.SECRET_APPLY_BUFFERS, sum((73728,65600,73729,73728,73728,65600,49200,65600,69632,69632,69632,32768,16384,8192,8192)))

        # Actual private Initial/GO/result dispatch admits only the new fixed
        # Variable action; the old token-only and secret Apply readers refuse it.
        from mobile_release import github_setup_variable_runtime as variable_runtime
        from mobile_release import github_setup_variables as variables
        selected = {"kind": "environment_variable", "mode": "create", "stage": "candidate",
            "requirement": "MOBILE_RELEASE_ANDROID_KEY_ALIAS", "source": {"recordId": "a" * 32,
            "recordRevision": 1, "contextRevision": 2}}
        text = "release.alias"
        fingerprint = {"bytes": len(text), "sha256": hashlib.sha256(text.encode()).hexdigest()}
        source = {"root": "/inert/project", "rootIdentity": {"device": "1", "inode": "2", "mode": 0o40700, "uid": 1, "gid": 1},
            "draft": {"bytes": 2, "sha256": "b" * 64}, "platform": "android", "purpose": "signing", "material": fingerprint}
        action = {"kind": "prepare", "target": {"projectBinding": "a" * 64, "repository": "owner/repo",
            "accountId": "1", "repositoryId": "2", "selection": selected}, "prepared": None, "source": source}
        initial = {"protocol": remote.PROTOCOL, "id": "variable_1", "action": action}
        request = remote.parse_initial(encode(initial))
        self.assertIs(type(request.action), variable_runtime.VariableRuntimeAction)
        final = {"protocol": remote.PROTOCOL, "id": request.id, "go": {"requestSha256": request.digest, "token": "inert", "value": text}}
        self.assertEqual(variable_runtime.parse_variable_go(encode(final), request), ("inert", text))
        for changed in ({**final, "go": {**final["go"], "value": "other"}},
                        {**final, "go": {**final["go"], "sealed": {}}}):
            with self.assertRaises(ValueError): variable_runtime.parse_variable_go(encode(changed), request)
        with self.assertRaises(ValueError): remote.parse_go(encode(final), request)
        with self.assertRaises(ValueError): remote.parse_secret_apply_go(encode(final), request)
        for selection_kind in ("environment_secret", "environment_protection", "unknown"):
            changed = copy.deepcopy(initial); changed["action"]["target"]["selection"]["kind"] = selection_kind
            with self.assertRaises(ValueError): remote.parse_initial(encode(changed))
        failed = {"schemaVersion": 1, "action": "prepare", "reason": "configuration-changed", "effect": "not-started",
            "writeClaimed": False, "writeAcknowledged": False, "prepared": None, "observed": None, "control": _control()}
        self.assertEqual(json.loads(remote.encode_result(request, failed, variable_value=text))["result"], failed)
        for key, changed in (("reason", "none"), ("observed", {}), ("effect", "accepted-not-value-verified")):
            with self.assertRaises(ValueError): remote.encode_result(request, {**failed, key: changed}, variable_value=text)
        with self.assertRaises(ValueError): remote.encode_result(request, failed)

    def test_python_only_complex_oversized_and_invalid_unicode_inputs_reject(self):
        deep = 0
        for _ in range(35):
            deep = [deep]
        cycle = []
        cycle.append(cycle)
        bad = (None, [], {1: "key"}, {"x": object()}, {"x": (1,)}, {"x": float("nan")},
               {"x": float("inf")}, {"x": "\ud800"}, {"x": "x" * (512 * 1024 + 1)},
               {"x": [0] * 8001}, {"x": deep}, {"x": cycle})
        with patch.object(setup, "_read_resource_bytes", side_effect=AssertionError("malformed input read templates")):
            for value in bad:
                with self.subTest(kind=type(value).__name__), self.assertRaises(ApiError) as caught:
                    propose(draft=value)
                self.assertEqual(caught.exception.code, "invalid_params")
        value = draft()
        value["source"]["candidateBranch"] = "é" * 255
        self.assertEqual(propose(draft=value)["settings"]["sourcePolicy"]["candidateBranch"], "é" * 255)

    def test_resource_unavailable_corrupt_duplicate_and_nonfinite_refuse_no_fallback(self):
        raw = RESOURCE.read_bytes()
        for broken in (b"\xff", b"{", b"[]", b" " * (128 * 1024 + 1),
                       b'{"schemaVersion":1,' + raw[1:],
                       raw.replace(b'"workflows": {', b'"workflows": {"preflight":"duplicate",', 1),
                       raw.replace(b'"help": {', b'"help": {"schemaVersion":1,', 1),
                       raw.replace(b'"schemaVersion": 1', b'"schemaVersion": NaN', 1),
                       raw.replace(b'"schemaVersion": 1', b'"schemaVersion": true', 1)):
            with patch.object(setup, "_read_resource_bytes", return_value=broken), self.assertRaises(ApiError) as caught:
                propose()
            self.assertEqual(caught.exception.code, "resource_unavailable")
        with patch.object(setup, "_read_resource_bytes", side_effect=OSError("private-path")), self.assertRaises(ApiError) as caught:
            setup.github_setup_help()
        self.assertEqual(caught.exception.code, "resource_unavailable")
        self.assertNotIn("private-path", caught.exception.message)

    def test_resource_rosters_help_fields_and_marker_policy_are_closed(self):
        original = json.loads(RESOURCE.read_bytes())
        mutations = [lambda x: x.update(extra=False), lambda x: x["workflows"].update(other="template"),
                     lambda x: x["workflows"].pop("preflight"), lambda x: x["help"].update(extra=False),
                     lambda x: x["help"]["inputs"].reverse(), lambda x: x["help"]["guidance"].pop(),
                     lambda x: x["help"]["inputs"][0].update(requiredness="optional"),
                     lambda x: x["help"]["inputs"][0].update(example="not-in-contract"),
                     lambda x: x["help"]["guidance"][0].update(requiredness="required"),
                     lambda x: x["help"]["inputs"][0].update(label="é" * 49),
                     lambda x: x["help"]["inputs"][0].update(what="é" * 513),
                     lambda x: x["help"]["inputs"][0].update(why="line\nbreak"),
                     lambda x: x["help"]["inputs"][0].update(where="\ud800"),
                     lambda x: x["help"]["inputs"][0].update(format=""),
                     lambda x: x["workflows"].update(preflight="no markers"),
                     lambda x: x["workflows"].update(preflight="x" * (16 * 1024 + 1))]
        for mutate in mutations:
            changed = copy.deepcopy(original)
            mutate(changed)
            with patch.object(setup, "_read_resource_bytes", return_value=resource_bytes(changed)), self.assertRaises(ApiError) as caught:
                setup.github_setup_help()
            self.assertEqual(caught.exception.code, "resource_unavailable")

    def test_render_expansion_and_complete_result_overflow_never_return_partial_payload(self):
        changed = json.loads(RESOURCE.read_bytes())
        markers = "__MOBILE_RELEASE_KIT_SHA__ __MOBILE_RELEASE_KIT_REPOSITORY__"
        changed["workflows"]["preflight"] = markers + "x" * (16 * 1024 - len(markers))
        with patch.object(setup, "_read_resource_bytes", return_value=resource_bytes(changed)), self.assertRaises(ApiError) as caught:
            propose(toolingRepository="o" * 39 + "/" + "r" * 100)
        self.assertEqual(caught.exception.code, "proposal_output_limit")
        changed["workflows"] = {identity: markers for identity in IDS}
        # The production aggregate cap equals four individual caps. Lower only
        # the aggregate here to exercise its independent post-render refusal.
        with patch.object(setup, "_read_resource_bytes", return_value=resource_bytes(changed)), \
             patch.object(setup, "MAX_WORKFLOWS_BYTES", len(markers) * 4), self.assertRaises(ApiError) as caught:
            propose(toolingRepository="o" * 39 + "/" + "r" * 100)
        self.assertEqual(caught.exception.code, "proposal_output_limit")
        for value in (draft(), {}):
            with patch.object(setup, "MAX_RESULT_BYTES", 1), self.assertRaises(ApiError) as caught:
                propose(draft=value)
            self.assertEqual(caught.exception.code, "proposal_output_limit")

    def test_requirement_output_growth_refuses_instead_of_truncating(self):
        validation = copy.deepcopy(propose()["validation"])
        validation["requirements"] = validation["requirements"][:1] * 129
        with patch.object(setup, "_validate", return_value=validation), self.assertRaises(ApiError) as caught:
            propose()
        self.assertEqual(caught.exception.code, "proposal_output_limit")

    def test_inputs_are_unchanged_and_ambient_credentials_never_appear(self):
        value = params(suppliedSnapshot={"workflows": [{"id": "preflight", "state": "absent"}]})
        value["draft"]["$schema"] = "https://untrusted.invalid/never-fetch"
        value["draft"]["projectChecks"]["preflight"] = [["./must-not-run"]]
        original = copy.deepcopy(value)
        with patch.dict(os.environ, {"MOBILE_RELEASE_TOOLING_ROOT": "/private-alternate-template-root",
                                     "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": "private-credential-value"}):
            result = execute("github.setup.propose", value)
        self.assertEqual(value, original)
        self.assertNotIn("/private-alternate-template-root", json.dumps(result))
        self.assertNotIn("private-credential-value", json.dumps(result))
        self.assertNotIn("must-not-run", json.dumps(result))
        self.assertNotIn("untrusted.invalid", json.dumps(result))

    def test_portable_proposal_and_help_use_no_project_process_network_or_write_capability(self):
        raw = RESOURCE.read_bytes()
        with patch.object(setup, "_read_resource_bytes", return_value=raw), \
             patch.object(sys, "platform", "win32"), \
             patch.object(builtins, "open", side_effect=AssertionError("file read")), \
             patch.object(Path, "open", side_effect=AssertionError("path read")), \
             patch.object(os, "open", side_effect=AssertionError("descriptor open")), \
             patch.object(os, "mkdir", side_effect=AssertionError("filesystem write")), \
             patch.object(os, "rename", side_effect=AssertionError("filesystem write")), \
             patch.object(os, "unlink", side_effect=AssertionError("filesystem write")), \
             patch.object(os, "system", side_effect=AssertionError("shell execution")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process creation")), \
             patch.object(socket, "socket", side_effect=AssertionError("network")), \
             patch.object(ReleaseConfig, "project_path", side_effect=AssertionError("project read")), \
             patch.object(ReleaseConfig, "release_version", side_effect=AssertionError("version read")):
            self.assertEqual(propose()["state"], "proposed")
            self.assertEqual(setup.github_setup_help()["schemaVersion"], 1)
            caps = execute("capabilities", {})
            self.assertEqual(caps["hostPlatform"], "windows")
            self.assertTrue(next(item for item in caps["methods"] if item["method"] == "github.setup.propose")["available"])
            self.assertFalse(any(item["available"] for item in caps["actions"]))
            with self.assertRaisesRegex(AssertionError, "network"):
                socket.socket()  # Negative control calls only the patched tripwire.

    def test_fresh_import_graph_and_real_proposal_remain_passive(self):
        raw = RESOURCE.read_bytes()
        forbidden = {"mobile_release.cli", "mobile_release.tooling", "mobile_release.credentials",
                     "mobile_release.owned_process", "mobile_release._native_process", "mobile_release._command_process",
                     "mobile_release._profile_process", "mobile_release.cancellation", "mobile_release.build_inputs",
                     "mobile_release.local_signing", "mobile_release.preflight", "mobile_release.android", "mobile_release.ios",
                     "mobile_release.stores", "mobile_release.workflow", "ctypes", "_ctypes", "fcntl"}

        class Guard:
            def find_spec(self, fullname, path=None, target=None):
                if fullname in forbidden:
                    raise AssertionError("forbidden runtime import")
                return None

        with patch.dict(sys.modules):
            for name in tuple(sys.modules):
                if name == "mobile_release" or name.startswith("mobile_release.") or name in {"ctypes", "_ctypes", "fcntl"}:
                    del sys.modules[name]
            with patch.object(sys, "meta_path", [Guard(), *sys.meta_path]), \
                 patch.object(os, "register_at_fork", create=True, side_effect=AssertionError("fork hook")), \
                 patch.object(os, "system", side_effect=AssertionError("shell execution")), \
                 patch.object(subprocess, "Popen", side_effect=AssertionError("process creation")), \
                 patch.object(socket, "socket", side_effect=AssertionError("network")):
                fresh = importlib.import_module("mobile_release.api")
                service = sys.modules["mobile_release.api._github_setup"]
                with patch.object(service, "_read_resource_bytes", return_value=raw):
                    self.assertEqual(fresh.execute("github.setup.propose", params())["state"], "proposed")
                self.assertFalse(forbidden & set(sys.modules))
                with self.assertRaisesRegex(AssertionError, "forbidden runtime import"):
                    importlib.import_module("mobile_release.cli")

    def test_engine_api_allowlist_agreement_strict_framing_and_future_actions_disabled(self):
        self.assertEqual(engine.METHODS, frozenset(METHODS))
        request = {"protocol": 1, "id": "github-pure", "method": "github.setup.propose", "params": params()}
        raw = json.dumps(request, separators=(",", ":")).encode() + b"\n"
        parsed = engine.parse_request(raw)
        self.assertEqual(parsed.method, "github.setup.propose")
        self.assertEqual(parsed.params, params())
        result = execute(parsed.method, parsed.params)
        encoded = engine.encode_response(parsed, result=result)
        self.assertEqual(json.loads(encoded)["result"], result)
        for bad in (raw + raw, raw[:-1], raw.replace(b'"suppliedSnapshot":null', b'"suppliedSnapshot":null,"suppliedSnapshot":null')):
            with self.assertRaises(engine.ProtocolError):
                engine.parse_request(bad)
        actions = {item["id"]: item["available"] for item in execute("capabilities", {})["actions"]}
        self.assertIs(actions["github.authenticate"], False)
        self.assertIs(actions["github.setup"], False)


if __name__ == "__main__":
    unittest.main()
