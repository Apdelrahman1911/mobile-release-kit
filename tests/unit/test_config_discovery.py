from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mobile_release.config import ConfigurationError, load_config, parse_key_value_file
from mobile_release.discovery import (
    discover_android,
    discover_ios,
    discover_project,
    discover_version_source,
    selected_android_details,
)

from .helpers import android_config, ios_config, write_project


class ConfigDiscoveryTests(unittest.TestCase):
    def test_config_requires_enabled_platform_complete_track_and_regular_bounded_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = android_config()
            value["android"]["externalTrack"] = {"kind": "open"}
            path = write_project(root, value)
            with self.assertRaisesRegex(ConfigurationError, "externalTrack.name"):
                load_config(path)

            value["android"] = {"enabled": False}
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ConfigurationError, "at least one release platform"):
                load_config(path)

            target = root / "release/real-config.json"
            target.write_text(json.dumps(android_config()), encoding="utf-8")
            path.unlink()
            path.symlink_to(target)
            with self.assertRaisesRegex(ConfigurationError, "symlink"):
                load_config(path)

            path.unlink()
            path.write_bytes(b"x" * (600 * 1024))
            with self.assertRaisesRegex(ConfigurationError, "unexpectedly large"):
                load_config(path)

    def test_loads_unverified_identity_without_store_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = write_project(root, android_config(status="unverified"))
            config = load_config(path)
            self.assertEqual(config.release_version().name, "1.2.3")
            self.assertNotIn("externalTrack", config.section("android"))

    def test_rejects_duplicate_json_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release/mobile-release.json"
            path.parent.mkdir(parents=True)
            path.write_text('{"schemaVersion":1,"schemaVersion":1}', encoding="utf-8")
            with self.assertRaisesRegex(ConfigurationError, "duplicate JSON key"):
                load_config(path)

    def test_rejects_shell_syntax_but_allows_bounded_path_placeholder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = android_config()
            value["projectChecks"]["androidArtifact"] = [
                ["./verify", "${MOBILE_RELEASE_AAB_PATH}"]
            ]
            path = write_project(root, value)
            load_config(path)
            value["projectChecks"]["androidArtifact"] = [["./verify", "$(steal)"]]
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ConfigurationError, "shell syntax"):
                load_config(path)
            value["projectChecks"]["androidArtifact"] = [
                ["./verify", "${MOBILE_RELEASE_AAB_PATH}${"]
            ]
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ConfigurationError, "placeholder"):
                load_config(path)
            for invalid in (
                "${MOBILE_RELEASE_AAB_PATH",
                "${}",
                "${MOBILE_RELEASE_AAB_PATH:-fallback}",
                "${MOBILE_RELEASE_AAB_PATH}${UNKNOWN}",
                "${MOBILE_RELEASE_AAB_PATH${MOBILE_RELEASE_IPA_PATH}",
            ):
                value["projectChecks"]["androidArtifact"] = [["./verify", invalid]]
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaisesRegex(ConfigurationError, "placeholder"):
                    load_config(path)

    def test_explicit_root_android_module_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = android_config()
            value["android"]["module"] = ":"
            config = load_config(write_project(root, value))
            self.assertEqual(config.section("android")["module"], ":")

    def test_schema_reference_must_be_a_bounded_absolute_uri(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = write_project(root, android_config())
            valid = android_config()
            valid["$schema"] = (
                "https://raw.githubusercontent.com/example/mobile-release-kit/"
                f"{'1' * 40}/schemas/project.schema.json"
            )
            path.write_text(json.dumps(valid), encoding="utf-8")
            load_config(path)
            for invalid in (
                "schemas/project.schema.json",
                "https://example.invalid/schema with space.json",
                "x" * 2049,
            ):
                candidate = android_config()
                candidate["$schema"] = invalid
                path.write_text(json.dumps(candidate), encoding="utf-8")
                with self.assertRaisesRegex(ConfigurationError, "absolute URI"):
                    load_config(path)

    def test_version_parser_rejects_duplicate_and_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "version.properties"
            path.write_text("A=1\nA=2\n", encoding="utf-8")
            with self.assertRaisesRegex(ConfigurationError, "duplicate"):
                parse_key_value_file(path)
            path.write_text("A=${HOME}\n", encoding="utf-8")
            with self.assertRaisesRegex(ConfigurationError, "unsafe"):
                parse_key_value_file(path)

    def test_version_parser_canonical_corpus_and_build_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "version.properties"
            path.write_text(
                "# comment\n// comment\n; comment\n"
                "VERSION_NAME='1.2.3'\nBUILD_NUMBER=42\n",
                encoding="utf-8",
            )
            self.assertEqual(
                parse_key_value_file(path),
                {"VERSION_NAME": "1.2.3", "BUILD_NUMBER": "42"},
            )
            for invalid in (
                "VERSION_NAME=\"1.2.3\nBUILD_NUMBER=42\n",
                "VERSION_NAME=\"\"\nBUILD_NUMBER=42\n",
                "VERSION_NAME=$VERSION\nBUILD_NUMBER=42\n",
            ):
                path.write_text(invalid, encoding="utf-8")
                with self.assertRaises(ConfigurationError):
                    parse_key_value_file(path)

            config = load_config(write_project(root / "app", android_config()))
            version_path = root / "app/release/version.properties"
            for build in ("0", "00", "042", "+42", "2100000001"):
                version_path.write_text(
                    f"VERSION_NAME=1.2.3\nBUILD_NUMBER={build}\n", encoding="utf-8"
                )
                with self.assertRaises(ConfigurationError):
                    config.release_version()

    def test_runtime_rejects_bool_schema_version_colon_fingerprint_and_length_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = android_config()
            path = write_project(root, value)
            for mutation in (
                lambda item: item.update(schemaVersion=True),
                lambda item: item["android"].update(
                    uploadCertificateSha256=":".join(["aa"] * 32)
                ),
                lambda item: item["android"].update(applicationId="a." + "b" * 254),
                lambda item: item["android"].update(variant="r" * 129),
                lambda item: item["version"].update(source="C:/private/version.properties"),
            ):
                candidate = android_config()
                mutation(candidate)
                path.write_text(json.dumps(candidate), encoding="utf-8")
                with self.assertRaises(ConfigurationError):
                    load_config(path)

    def test_config_and_project_paths_reject_symlinked_parent_components(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".git").mkdir()
            real_release = root / "tracked-release"
            real_release.mkdir()
            config_path = real_release / "mobile-release.json"
            config_path.write_text(json.dumps(android_config()), encoding="utf-8")
            (root / "release").symlink_to(real_release, target_is_directory=True)
            with self.assertRaisesRegex(ConfigurationError, "symlink"):
                load_config(root / "release/mobile-release.json")

            (root / "release").unlink()
            valid = write_project(root / "app", android_config())
            config = load_config(valid)
            target = config.root / "real-output"
            target.mkdir()
            (config.root / "linked-output").symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(ConfigurationError, "symbolic link"):
                config.project_path("linked-output/result.json")

    def test_ios_marketing_version_is_rejected_before_xcode_when_store_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, ios_config(), platform="ios"))
            (root / "release/version.properties").write_text(
                "VERSION_NAME=1.2.3-beta\nBUILD_NUMBER=42\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ConfigurationError, "iOS marketing version"):
                config.release_version()

    def test_all_zero_approved_fingerprint_fails_doctor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ConfigurationError, "placeholder"):
                load_config(write_project(root, android_config(fingerprint="0" * 64)))

    def test_version_catalog_alias_ignores_root_apply_false(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalog = root / "gradle/libs.versions.toml"
            catalog.parent.mkdir(parents=True)
            catalog.write_text(
                '[plugins]\nandroid-application = { id = "com.android.application", version = "9.0.0" }\n',
                encoding="utf-8",
            )
            (root / "build.gradle.kts").write_text(
                "plugins { alias(libs.plugins.android.application) apply false }\n",
                encoding="utf-8",
            )
            app = root / "app-android"
            app.mkdir()
            (app / "build.gradle.kts").write_text(
                "plugins { alias(libs.plugins.android.application) }\n"
                'android { namespace = "com.example.reader"; defaultConfig { '
                'applicationId = "com.example.reader" }; buildTypes { debug { '
                'applicationIdSuffix = ".debug" } } }\n',
                encoding="utf-8",
            )
            self.assertEqual(discover_android(root)["module"], ":app-android")

    def test_prefixed_version_keys_are_discovered_without_project_specific_rules(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config"
            config.mkdir()
            (config / "product-version.xcconfig").write_text(
                "PRODUCT_VERSION_NAME = 1.2.3\nPRODUCT_BUILD_NUMBER = 42\n",
                encoding="utf-8",
            )
            self.assertEqual(
                discover_version_source(root),
                {
                    "versionSource": "config/product-version.xcconfig",
                    "versionNameKey": "PRODUCT_VERSION_NAME",
                    "versionBuildKey": "PRODUCT_BUILD_NUMBER",
                },
            )

            (root / "version.properties").write_text(
                "VERSION_NAME=1.2.3\nVERSION_CODE=100\nBUILD_NUMBER=7\n",
                encoding="utf-8",
            )
            self.assertEqual(
                discover_version_source(root)["versionBuildKey"], "VERSION_CODE"
            )

    def test_configured_module_selects_matching_ambiguous_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = write_project(root, android_config())
            other = root / "sample"
            other.mkdir()
            (other / "build.gradle.kts").write_text(
                'plugins { id("com.android.application") }\n'
                'android { namespace = "com.example.sample"; defaultConfig { '
                'applicationId = "com.example.sample" } }\n',
                encoding="utf-8",
            )
            config = load_config(path)
            selected = selected_android_details(config, discover_project(root))
            self.assertEqual(selected["module"], ":app")
            self.assertEqual(selected["applicationId"], "com.example.reader")

    def test_xcconfig_variable_expands_debug_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "iosApp/App.xcodeproj"
            project.mkdir(parents=True)
            (project / "project.pbxproj").write_text(
                "PRODUCT_BUNDLE_IDENTIFIER = $(BUNDLE_ID);\n"
                "PRODUCT_BUNDLE_IDENTIFIER = $(BUNDLE_ID).debug;\n",
                encoding="utf-8",
            )
            config = root / "config"
            config.mkdir()
            (config / "Identity.xcconfig").write_text(
                "BUNDLE_ID = com.example.reader\n", encoding="utf-8"
            )
            discovered = discover_ios(root)
            self.assertEqual(
                discovered["bundleIds"], ["com.example.reader", "com.example.reader.debug"]
            )

    def test_empty_xcconfig_assignment_does_not_consume_next_line(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "iosApp/App.xcodeproj"
            project.mkdir(parents=True)
            (project / "project.pbxproj").write_text(
                "PRODUCT_BUNDLE_IDENTIFIER = $(BUNDLE_ID);\n"
                "PRODUCT_BUNDLE_IDENTIFIER = $(BUNDLE_ID).debug;\n",
                encoding="utf-8",
            )
            config = root / "config"
            config.mkdir()
            (config / "Config.xcconfig").write_text(
                "TEAM_ID =\nBUNDLE_ID = com.example.reader\n", encoding="utf-8"
            )
            discovered = discover_ios(root)
            self.assertEqual(
                discovered["bundleIds"], ["com.example.reader", "com.example.reader.debug"]
            )

    def test_discovery_never_reads_release_private_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "iosApp/App.xcodeproj"
            project.mkdir(parents=True)
            (project / "project.pbxproj").write_text(
                "PRODUCT_BUNDLE_IDENTIFIER = com.public.reader;\n"
                "PRODUCT_BUNDLE_IDENTIFIER = com.public.reader.debug;\n",
                encoding="utf-8",
            )
            private = root / "release/private"
            private.mkdir(parents=True)
            (private / "secret.xcconfig").write_text(
                "BUNDLE_ID = com.private.must.not.be.read\n", encoding="utf-8"
            )
            from mobile_release import discovery

            real_read = discovery._read_small

            def guarded_read(path: Path, limit: int = 2_000_000) -> str:
                self.assertNotEqual(path.parts[-3:-1], ("release", "private"))
                return real_read(path, limit)

            with patch("mobile_release.discovery._read_small", side_effect=guarded_read):
                found = discover_ios(root)
            self.assertEqual(
                found["bundleIds"], ["com.public.reader", "com.public.reader.debug"]
            )

    def test_internal_xcode_project_workspace_is_not_selected_as_app_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "iosApp/App.xcodeproj"
            project.mkdir(parents=True)
            (project / "project.pbxproj").write_text(
                "PRODUCT_BUNDLE_IDENTIFIER = com.example.reader;\n", encoding="utf-8"
            )
            (project / "project.xcworkspace").mkdir()
            found = discover_ios(root)
            self.assertEqual(found["project"], "iosApp/App.xcodeproj")
            self.assertEqual(found["workspaces"], [])


if __name__ == "__main__":
    unittest.main()
