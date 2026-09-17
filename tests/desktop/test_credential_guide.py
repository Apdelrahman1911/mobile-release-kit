"""Inert static credential-guide/import/resource contracts, not vault tests.

Only fixed shipped source/resource bytes and fictional in-memory JSON are used.
No credential value/source path, native parser, CLI importer, keyring, Store,
process, package build or temporary project is needed.
"""
from __future__ import annotations

import builtins
import copy
import importlib
import io
import json
import os
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from mobile_release.api import ApiError, METHODS, execute
from mobile_release.api import _catalog as catalog_api
from mobile_release.api import _credential_guide as guide
from mobile_release.api._catalog import _credential_catalog, requirement_descriptors
from mobile_release.credential_policy import CREDENTIAL_POLICY_VERSION, material_size_limit
from mobile_release.credential_requirements import requirements
from mobile_release.config import ReleaseConfig

SOURCE = Path(__file__).resolve().parents[2]
RESOURCE = SOURCE / "src/mobile_release/api/data/credential-guide-v1.json"
HELP_FIELDS = ("label", "requiredness", "requiredWhen", "what", "why", "where", "format", "failure")


def raw_resource(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def all_branches():
    return {"android": {"enabled": True}, "ios": {"enabled": True, "review": {"demoAccountRequired": True}},
            "services": {"androidFirebase": "required", "iosFirebase": "required"},
            "source": {"projectReadTokenRequired": True}}


class CredentialGuideTests(unittest.TestCase):
    def test_full_self_contained_resource_and_additive_catalogue(self):
        resource = json.loads(RESOURCE.read_bytes())
        result = execute("catalog", {})
        self.assertEqual(result["credentialGuide"], resource)
        self.assertEqual(result["credentials"], _credential_catalog())
        self.assertEqual(resource["policyVersion"], CREDENTIAL_POLICY_VERSION)
        self.assertEqual(resource["availability"], "guide-only")
        self.assertEqual([item["id"] for item in resource["kinds"]], list(guide.KIND_IDS))
        self.assertEqual([item["id"] for item in resource["controls"]], list(guide.CONTROL_IDS))
        self.assertEqual([item["id"] for item in resource["states"]], list(guide.STATE_IDS))
        self.assertEqual(sum(len(item["fields"]) for item in resource["kinds"]), 15)
        self.assertFalse(result["assurance"]["credentialsRead"])
        self.assertEqual(METHODS, ("capabilities", "catalog", "project.snapshot", "config.validate",
                                   "config.suggest", "config.preview", "github.setup.propose", "credentials.assess"))
        self.assertTrue(all(not item["available"] for item in execute("capabilities", {})["actions"]))
        # Pure supplied-input policy is additive; no native/vault action or
        # general credential operation becomes a method through guide loading.
        self.assertIn("credentials.assess", METHODS)
        for native_method in ("assets.import", "credentials.prepare", "credentials.vault", "credentials.assign"):
            with self.assertRaises(ApiError) as raised:
                execute(native_method, {})
            self.assertEqual(raised.exception.code, "unknown_method")

    def test_unavailable_guide_retains_catalogue_and_only_its_resource_error_is_contained(self):
        baseline = execute("catalog", {})
        self.assertIsNotNone(baseline["credentialGuide"])
        expected = {**baseline, "credentialGuide": None}
        faults = (
            ("missing", {"side_effect": OSError("fictional missing guide")}),
            ("corrupt", {"return_value": b"{"}),
            ("incompatible", {"return_value": b"{}"}),
        )
        for label, fault in faults:
            with self.subTest(guide=label), \
                 patch.object(guide, "_read_resource_bytes", **fault) as read, \
                 patch.object(guide, "files", side_effect=AssertionError("alternate guide resource read")) as alternate:
                result = execute("catalog", {})
                read.assert_called_once_with()
                alternate.assert_not_called()
                self.assertIsNone(result["credentialGuide"])
                # Every non-guide catalogue field remains unchanged.
                self.assertEqual(result, expected)
                self.assertFalse(result["assurance"]["credentialsRead"])

        unrelated = ApiError("invalid_params", "Fictional unrelated guide refusal")
        with patch.object(catalog_api, "credential_guide", side_effect=unrelated):
            with self.assertRaises(ApiError) as raised:
                execute("catalog", {})
            self.assertIs(raised.exception, unrelated)

        original_resource = catalog_api._resource
        for failed_name in ("project.schema.json", "field-help.json"):
            original_error = ApiError("resource_unavailable", "Fictional original catalogue resource failure")

            def resource_or_error(name):
                if name == failed_name:
                    raise original_error
                return original_resource(name)

            with self.subTest(resource=failed_name), \
                 patch.object(catalog_api, "_resource", side_effect=resource_or_error), \
                 patch.object(catalog_api, "credential_guide") as additive:
                with self.assertRaises(ApiError) as raised:
                    execute("catalog", {})
                self.assertIs(raised.exception, original_error)
                additive.assert_not_called()

        for target in ("mobile_release.api._catalog._credential_catalog",
                       "mobile_release.api._github_setup.github_setup_help"):
            original_error = ApiError("resource_unavailable", "Fictional original guidance failure")
            guide_error = ApiError("resource_unavailable", "Fictional unavailable additive guide")
            with self.subTest(resource=target), patch(target, side_effect=original_error), \
                 patch.object(catalog_api, "credential_guide", side_effect=guide_error) as additive:
                with self.assertRaises(ApiError) as raised:
                    execute("catalog", {})
                self.assertIs(raised.exception, original_error)
                additive.assert_called_once_with()

    def test_kind_associations_limits_and_existing_deferred_guidance(self):
        result = execute("catalog", {})
        by_name = {item["name"]: item for item in requirement_descriptors(all_branches())}
        guided = set()
        for kind in result["credentialGuide"]["kinds"]:
            self.assertTrue(kind["defaultLabel"].strip())
            self.assertTrue(all(item.startswith("Planned only, not run: ") for item in kind["plannedChecks"]))
            self.assertTrue(kind["notVerified"])
            for field in kind["fields"]:
                name = field["requirement"]
                self.assertNotIn(name, guided)
                guided.add(name)
                self.assertEqual(field["alternatives"], by_name[name]["alternatives"])
                self.assertEqual(kind["platform"], by_name[name]["platform"])
                self.assertEqual(field["requiredness"], "conditional")
                if field["input"] == "file":
                    self.assertEqual(field["maxBytes"], material_size_limit(name))
                    self.assertTrue(field["suffixes"])
                else:
                    self.assertIsNone(field["maxBytes"])
                    self.assertEqual(field["suffixes"], [])
                for key in HELP_FIELDS:
                    self.assertTrue(field[key].strip(), (kind["id"], field["id"], key))
        legacy_names = {item["name"] for item in result["credentials"]}
        self.assertEqual(legacy_names, set(by_name))
        self.assertLess(guided, legacy_names)
        for suffix in ("OPERATION_COMMITMENT_KEY_BASE64", "OPERATION_COMMITMENT_KEY_VERSION",
                       "APPLE_REVIEW_CONTACT_EMAIL", "APPLE_DEMO_ACCOUNT_PASSWORD"):
            self.assertIn("MOBILE_RELEASE_" + suffix, legacy_names - guided)
        self.assertNotIn("GOOGLE_APPLICATION_CREDENTIALS", guided)

    def test_requirements_remain_the_only_stage_platform_purpose_selector(self):
        config = ReleaseConfig(Path("unused"), Path("."), all_branches())
        for stage in ("candidate", "external-testing", "production"):
            signing = {item.name for item in requirements(config, stage, purpose="signing")}
            store = {item.name for item in requirements(config, stage, purpose="store")}
            self.assertNotIn("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", signing)
            self.assertNotIn("MOBILE_RELEASE_GOOGLE_WIF_PROVIDER", signing)
            self.assertNotIn("MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64", store)
            if stage != "candidate":
                self.assertEqual(signing, set())
        # The project-token branch is deliberately not rewritten as a platform
        # requirement or conditioned on the catalogue's eight kind descriptors.
        selected = requirements(config, "candidate", purpose="signing", platforms=())
        self.assertEqual([(item.name, item.platform) for item in selected],
                         [("MOBILE_RELEASE_PROJECT_READ_TOKEN", "project")])
        self.assertEqual(requirements(config, "candidate", purpose="store", platforms=()), [])

    def test_control_and_state_help_cover_future_unavailable_lifecycle(self):
        resource = guide.credential_guide()
        controls = {item["id"]: item for item in resource["controls"]}
        for control in controls.values():
            for key in HELP_FIELDS:
                self.assertTrue(control[key].strip(), (control["id"], key))
        self.assertIn("keyboard", controls["review"]["format"])
        self.assertIn("write-only", controls["review"]["format"])
        self.assertIn("outside", controls["choose"]["format"])
        self.assertIn("chmod", controls["choose"]["failure"])
        self.assertIn("unavailable", controls["replace"]["format"])
        self.assertIn("not secure", controls["delete"]["format"])
        self.assertIn("timeout is not rollback", controls["cancel"]["format"])
        self.assertIn("reassignment", controls["assign"]["format"])
        self.assertIn("no wrapping-key", controls["lock"]["format"].lower())
        states = {item["id"]: item["meaning"] for item in resource["states"]}
        self.assertIn("not native or service validity", states["format-valid"].lower())
        self.assertIn("no credential inputs", states["unavailable"])

    def test_closed_resource_refuses_incompatible_or_private_extra_fields(self):
        base = json.loads(RESOURCE.read_bytes())
        mutations = [
            lambda value: value.update(schemaVersion=True),
            lambda value: value.update(schemaVersion=2),
            lambda value: value.update(policyVersion="another-policy"),
            lambda value: value.update(availability="enabled"),
            lambda value: value.update(values="fictional-private-marker"),
            lambda value: value["kinds"].pop(),
            lambda value: value["kinds"].append(value["kinds"][0]),
            lambda value: value["kinds"][0].update(id="new-kind"),
            lambda value: value["kinds"][0].update(platform="ios"),
            lambda value: value["kinds"][0].update(defaultLabel=""),
            lambda value: value["kinds"][0].update(plannedChecks=["verified"]),
            lambda value: value["kinds"][0].update(notVerified=[]),
            lambda value: value["kinds"][0]["fields"][0].update(maxBytes=True),
            lambda value: value["kinds"][0]["fields"][0].update(maxBytes=1),
            lambda value: value["kinds"][0]["fields"][0].update(suffixes=["*"]),
            lambda value: value["kinds"][0]["fields"][0].update(requirement="GOOGLE_APPLICATION_CREDENTIALS"),
            lambda value: value["kinds"][0]["fields"][0].update(alternatives=[]),
            lambda value: value["kinds"][0]["fields"][1].update(maxBytes=4096),
            lambda value: value["kinds"][0]["fields"][1].update(requiredness="required"),
            lambda value: value["kinds"][0]["fields"][1].update(value="fictional-private-marker"),
            lambda value: value["controls"][0].update(label="a\x00b"),
            lambda value: value["controls"][0].update(what="x" * 1025),
            lambda value: value["controls"][0].update(what="é" * 513),
            lambda value: value["states"][0].update(id="verified"),
            lambda value: value["states"][0].update(meaning=" "),
        ]
        for index, mutate in enumerate(mutations):
            value = copy.deepcopy(base)
            mutate(value)
            with self.subTest(index=index), patch.object(guide, "_read_resource_bytes", return_value=raw_resource(value)):
                with self.assertRaises(ApiError) as raised:
                    guide.credential_guide()
                self.assertEqual(raised.exception.code, "resource_unavailable")
                self.assertNotIn("fictional-private-marker", str(raised.exception))

    def test_resource_decoding_bounds_duplicates_and_no_fallback(self):
        raw = RESOURCE.read_bytes()
        for content in (b"", b"null", b"[]", b"\xff", b"{" + raw[1:].replace(b'"schemaVersion": 1', b'"schemaVersion": 1, "schemaVersion": 1', 1),
                        raw.replace(b'"maxBytes": 33554432', b'"maxBytes": NaN', 1),
                        b"[" * 40 + b"0" + b"]" * 40,
                        b"x" * (guide.MAX_RESOURCE_BYTES + 1)):
            with self.subTest(length=len(content)), patch.object(guide, "_read_resource_bytes", return_value=content):
                with self.assertRaises(ApiError) as raised:
                    guide.credential_guide()
                self.assertEqual(raised.exception.code, "resource_unavailable")
        with patch.object(guide, "_read_resource_bytes", side_effect=OSError("fictional-private-marker")) as read:
            with self.assertRaises(ApiError) as raised:
                guide.credential_guide()
            read.assert_called_once_with()
            self.assertNotIn("fictional-private-marker", str(raised.exception))
        with patch.object(guide, "material_size_limit", return_value=1):
            with self.assertRaises(ApiError):
                guide.credential_guide()

    def test_exact_selected_package_read_and_no_ambient_or_cached_values(self):
        raw = RESOURCE.read_bytes()
        with patch.object(guide, "files") as package, patch.dict(os.environ, {
            "MOBILE_RELEASE_TOOLING_ROOT": "/fictional/not-the-selected-package",
            "MOBILE_RELEASE_PROJECT_READ_TOKEN": "fictional-private-marker",
        }):
            package.return_value.joinpath.return_value.open.return_value.__enter__.return_value = io.BytesIO(raw)
            value = guide.credential_guide()
            package.assert_called_once_with("mobile_release.api")
            package.return_value.joinpath.assert_called_once_with("data", "credential-guide-v1.json")
            package.return_value.joinpath.return_value.open.assert_called_once_with("rb")
            self.assertNotIn("fictional-private-marker", json.dumps(value))
        first = guide.credential_guide()
        first["kinds"][0]["label"] = "changed caller copy"
        self.assertNotEqual(first, guide.credential_guide())

    def test_passive_import_and_catalogue_do_not_reach_native_credential_graph(self):
        forbidden = {"mobile_release.credentials", "mobile_release.checked_files", "mobile_release.cancellation",
                     "mobile_release.owned_process", "mobile_release.build_inputs", "mobile_release.local_signing",
                     "mobile_release.cli", "mobile_release.stores", "ssl", "plistlib", "pyexpat", "xml.parsers.expat"}
        original_import = builtins.__import__

        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
            absolute = importlib.util.resolve_name("." * level + name, globals["__package__"]) if level else name
            names = {absolute, *(absolute + "." + item for item in fromlist or () if item != "*")}
            if names & forbidden:
                raise AssertionError("forbidden credential/native import")
            return original_import(name, globals, locals, fromlist, level)

        with patch.dict(sys.modules):
            for name in tuple(sys.modules):
                if name == "mobile_release" or name.startswith("mobile_release."):
                    del sys.modules[name]
            with patch.object(builtins, "__import__", side_effect=guarded_import), \
                 patch.object(os, "register_at_fork", create=True, side_effect=AssertionError("fork hook")), \
                 patch.object(subprocess, "Popen", side_effect=AssertionError("process")), \
                 patch.object(os, "system", side_effect=AssertionError("shell")):
                fresh = importlib.import_module("mobile_release.api")
                result = fresh.execute("catalog", {})
                self.assertFalse(result["assurance"]["credentialsRead"])
                self.assertTrue(all(not action["available"] for action in fresh.execute("capabilities", {})["actions"]))
                with self.assertRaisesRegex(AssertionError, "forbidden credential/native import"):
                    guarded_import("mobile_release.credentials")

    def test_source_resource_is_in_existing_package_data_without_building(self):
        packaging = tomllib.loads((SOURCE / "pyproject.toml").read_text())
        self.assertIn("api/data/*.json", packaging["tool"]["setuptools"]["package-data"]["mobile_release"])
        self.assertTrue(RESOURCE.is_file())
        self.assertTrue((SOURCE / "src/mobile_release/credential_policy.py").is_file())
        self.assertTrue((SOURCE / "src/mobile_release/api/_credential_guide.py").is_file())
        preparation = (SOURCE / "desktop/tools/prepare_runtime.py").read_text()
        self.assertIn('package = _root(source / "src/mobile_release")', preparation)
        self.assertIn("candidates = files(package)", preparation)
        self.assertIn('{".py", ".json", ".pem"}', preparation)


if __name__ == "__main__":
    unittest.main()
