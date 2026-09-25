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
            self.assertIn("${{ github.sha }}", item["content"])
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
