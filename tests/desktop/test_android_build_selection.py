"""Inert Start-selection policy cases; no IO, tool, native or custody proof."""
from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from mobile_release import _desktop_android_build_selection as selection
from mobile_release.config import MAX_CONFIG_BYTES, MAX_VERSION_BYTES


def config_data():
    return {
        "schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "main"},
        "android": {"enabled": True, "applicationId": "org.example.saved", "identityStatus": "unverified",
                    "module": ":app", "variant": "release"},
        "ios": {"enabled": False},
        "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": []},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []},
    }


def encode(data):
    return json.dumps(data, separators=(",", ":")).encode("utf-8")


def comparison(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def expected_version(raw=b"VERSION_NAME=1.2.3\r\nBUILD_NUMBER=7\r\n", **changes):
    return {"source": "release/version.properties", **comparison(raw), "name": "1.2.3", "build": 7, **changes}


def selected_config(data=None):
    raw = encode(config_data() if data is None else data)
    return selection.select_saved_android_configuration(raw, comparison(raw))


class AndroidBuildSelectionTests(unittest.TestCase):
    def refuse(self, reason, call):
        with self.assertRaises(selection.AndroidSelectionRefused) as raised:
            call()
        self.assertEqual(raised.exception.reason, reason)
        self.assertEqual(str(raised.exception), "The saved Android release selection was refused")

    def test_saved_config_selects_private_policy_and_one_immutable_effective_version(self):
        data = config_data()
        data["android"].update(module=":mobile:app", variant="demoRelease", applicationId="org.example.current")
        data["version"].update(source="release/current.properties", nameKey="NAME", buildKey="BUILD")
        raw = encode(data)
        version_raw = b"# saved comments are not normalized\r\nNAME=2.3.4\r\nBUILD=19\r\n"
        with patch.object(selection, "parse_config_text", wraps=selection.parse_config_text) as parse_config, \
             patch.object(selection, "release_version_from_values", wraps=selection.release_version_from_values) as parse_version:
            private, configured = selection.select_saved_android_configuration(raw, comparison(raw))
            bound = selection.bind_saved_android_version(configured, version_raw, {
                "source": "release/current.properties", **comparison(version_raw), "name": "2.3.4", "build": 19,
            })
        self.assertEqual((parse_config.call_count, parse_version.call_count), (1, 1))
        self.assertEqual((bound.release.name, bound.release.build), ("2.3.4", 19))
        self.assertIs(bound.configuration, configured)
        self.assertIs(bound.configuration.raw, raw)
        self.assertIs(bound.version_raw, version_raw)
        self.assertEqual((configured.module, configured.variant, configured.application_id),
                         (":mobile:app", "demoRelease", "org.example.current"))
        private["android"]["module"] = ":other"
        data["android"]["variant"] = "debug"
        self.assertEqual((configured.module, configured.variant), (":mobile:app", "demoRelease"))
        with self.assertRaises(FrozenInstanceError):
            bound.release.build = 20

    def test_correct_byte_hashes_cannot_authorize_different_source_name_or_build(self):
        _, configured = selected_config()
        raw = b"VERSION_NAME=1.2.3\r\nBUILD_NUMBER=7\r\n"
        for change in ({"source": "release/other.properties"}, {"name": "9.9.9"}, {"build": 8}):
            with self.subTest(change=change):
                self.refuse("saved-version-changed", lambda: selection.bind_saved_android_version(
                    configured, raw, expected_version(raw, **change)))

    def test_semantically_equal_or_same_size_changed_bytes_do_not_match_old_consent(self):
        data = config_data()
        original = encode(data)
        reformat = json.dumps(data, indent=2).encode("utf-8")
        self.refuse("saved-config-changed", lambda: selection.select_saved_android_configuration(
            reformat, comparison(original)))
        modified = original.replace(b'":app"', b'":new"')
        self.assertEqual(len(modified), len(original))
        self.refuse("saved-config-changed", lambda: selection.select_saved_android_configuration(
            modified, comparison(original)))
        _, configured = selected_config()
        raw = b"VERSION_NAME=1.2.3\r\nBUILD_NUMBER=7\r\n"
        for changed in (raw.replace(b"\r\n", b"\n"), raw.replace(b"=7", b"=8")):
            self.refuse("saved-version-changed", lambda: selection.bind_saved_android_version(
                configured, changed, expected_version(raw)))

    def test_required_module_platform_and_safe_config_selected_source_are_not_guessed(self):
        data = config_data()
        del data["android"]["module"]
        self.refuse("module-required", lambda: selected_config(data))
        for module in (":.", ":..", ":app:.."):
            unsafe = config_data()
            unsafe["android"]["module"] = module
            self.refuse("saved-config-unsafe", lambda: selected_config(unsafe))
        root = config_data()
        root["android"]["module"] = ":"
        self.assertEqual(selected_config(root)[1].module, ":")
        disabled = config_data()
        disabled["android"] = {"enabled": False}
        disabled["ios"] = {"enabled": True, "bundleId": "org.example.saved", "identityStatus": "unverified"}
        disabled["metadata"].update(androidLocales=[], iosLocales=["en-US"])
        self.refuse("platform-disabled", lambda: selected_config(disabled))
        unsafe = config_data()
        unsafe["version"]["source"] = "release/private/version.properties"
        self.refuse("saved-version-unsafe", lambda: selected_config(unsafe))

    def test_missing_oversized_encoding_and_closed_comparisons_refuse(self):
        raw = encode(config_data())
        self.refuse("saved-config-missing", lambda: selection.select_saved_android_configuration(None, comparison(raw)))
        self.refuse("saved-config-invalid", lambda: selection.select_saved_android_configuration(b"\xff", comparison(b"\xff")))
        self.refuse("saved-config-too-large", lambda: selection.select_saved_android_configuration(
            b"x" * (MAX_CONFIG_BYTES + 1), comparison(raw)))
        for changed in ({"bytes": True}, {"bytes": 0}, {"sha256": "A" * 64}, {"extra": "PRIVATE_INPUT"}):
            bad = {**comparison(raw), **changed}
            self.refuse("protocol-error", lambda: selection.select_saved_android_configuration(raw, bad))
        _, configured = selected_config()
        expected = expected_version()
        self.refuse("saved-version-missing", lambda: selection.bind_saved_android_version(configured, None, expected))
        self.refuse("saved-version-too-large", lambda: selection.bind_saved_android_version(
            configured, b"x" * (MAX_VERSION_BYTES + 1), expected))
        self.refuse("saved-version-invalid", lambda: selection.bind_saved_android_version(
            configured, b"\xff", expected_version(b"\xff")))
        for change in ({"build": True}, {"name": 7}, {"extra": "PRIVATE_INPUT"}):
            bad = {**expected, **change}
            self.refuse("protocol-error", lambda: selection.bind_saved_android_version(configured, b"", bad))

    def test_shared_policy_errors_and_secret_material_never_become_public_messages(self):
        _, configured = selected_config()
        for raw in (b"VERSION_NAME=PRIVATE_VALUE\nBUILD_NUMBER=7\n", b"VERSION_NAME=1.2.3\nBUILD_NUMBER=07\n"):
            self.refuse("saved-version-invalid", lambda: selection.bind_saved_android_version(
                configured, raw, expected_version(raw)))
        raw = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n# -----BEGIN PRIVATE KEY-----\n"
        self.refuse("saved-version-sensitive", lambda: selection.bind_saved_android_version(
            configured, raw, expected_version(raw)))
        data = copy.deepcopy(config_data())
        data["android"]["unknown"] = "PRIVATE_VALUE"
        self.refuse("saved-config-invalid", lambda: selected_config(data))
        with patch.object(selection, "parse_config_text", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                selected_config()
