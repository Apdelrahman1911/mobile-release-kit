from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from mobile_release.config import load_config
from mobile_release.credentials import (
    _open_profile_directory,
    _parse_certificate_datetime,
    _temporary_apple_signing_environment,
    _utc_datetime,
    _validate_android_material,
    credential_values_from_environment,
    credential_findings,
    resolve_credential_values,
    load_credentials_file,
    materialize_build_inputs,
    requirements,
    store_lane_environment,
)
from mobile_release.errors import CredentialError
from mobile_release.metadata import build_metadata_archive, metadata_findings
from mobile_release.reporting import Status

from .helpers import android_config, ios_config, write_project


class CredentialMetadataTests(unittest.TestCase):
    def test_firebase_target_is_restored_when_apple_signing_setup_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = ios_config()
            value["services"]["iosFirebase"] = "required"
            config = load_config(write_project(root, value, platform="ios"))
            marker = root / "iosApp/GoogleService-Info.plist.example"
            marker.write_text("public marker\n", encoding="utf-8")
            target = marker.with_suffix("")
            target.write_bytes(b"original-private-client")
            target.chmod(0o640)
            values = {
                "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64": base64.b64encode(
                    b"p12"
                ).decode("ascii"),
                "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD": "password",
                "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64": base64.b64encode(
                    b"profile"
                ).decode("ascii"),
                "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64": base64.b64encode(
                    b"new-private-client"
                ).decode("ascii"),
            }

            class FailingSigningContext:
                def __enter__(self) -> object:
                    raise CredentialError("injected signing setup failure")

                def __exit__(self, *_args: object) -> None:
                    return None

            with patch.dict(
                os.environ, {"MOBILE_RELEASE_IOS_PROFILE_SPECIFIER": ""}, clear=False
            ), patch(
                "mobile_release.credentials._temporary_apple_signing_environment",
                return_value=FailingSigningContext(),
            ):
                with self.assertRaisesRegex(CredentialError, "injected"):
                    with materialize_build_inputs(
                        config,
                        values=values,
                        platforms=("ios",),
                        prepare_ios_signing=True,
                    ):
                        self.fail("signing context unexpectedly entered")
            self.assertEqual(target.read_bytes(), b"original-private-client")
            self.assertEqual(target.stat().st_mode & 0o777, 0o640)

    def test_credential_inputs_reject_unknown_names_and_ignore_unrelated_ambient_paths(self) -> None:
        filtered = credential_values_from_environment(
            {
                "MOBILE_RELEASE_PROJECT_READ_TOKEN": "read-token",
                "GITHUB_EVENT_PATH": "/tmp/event.json",
                "CMAKE_PREFIX_PATH": "/tmp/cmake",
            }
        )
        self.assertEqual(filtered, {"MOBILE_RELEASE_PROJECT_READ_TOKEN": "read-token"})

        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary).resolve()
            app_root = private_root / "app"
            write_project(app_root, android_config())
            credentials = private_root / "credentials.env"
            credentials.write_text(
                "MOBILE_RELEASE_APPLE_PROVISIONING_PROFIL_PATH=/tmp/typo\n",
                encoding="utf-8",
            )
            credentials.chmod(0o600)
            with self.assertRaisesRegex(CredentialError, "unsupported credential name"):
                load_credentials_file(credentials, app_root)

    def test_store_lane_materializes_documented_p8_path_as_base64(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary).resolve()
            app_root = private_root / "app"
            config = load_config(write_project(app_root, ios_config(), platform="ios"))
            key = private_root / "AuthKey.p8"
            key.write_bytes(b"private-p8-content")
            key.chmod(0o600)
            environment = store_lane_environment(
                config,
                values={"MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH": str(key)},
                platforms=("ios",),
            )
            self.assertEqual(
                base64.b64decode(environment["MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"]),
                b"private-p8-content",
            )
            self.assertNotIn("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH", environment)

    def test_credential_file_precedence_and_ambiguous_material_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary)
            root = private_root / "app"
            config = load_config(write_project(root, android_config()))
            keystore = private_root / "release.jks"
            keystore.write_bytes(b"keystore")
            keystore.chmod(0o600)
            credentials = private_root / "credentials.env"
            credentials.write_text(
                f"MOBILE_RELEASE_ANDROID_KEYSTORE_PATH={keystore}\n", encoding="utf-8"
            )
            credentials.chmod(0o600)
            resolved = resolve_credential_values(
                config,
                credentials_file=credentials,
                credentials_from_env=True,
                environ={"MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64": base64.b64encode(b"old").decode()},
            )
            self.assertEqual(resolved, {"MOBILE_RELEASE_ANDROID_KEYSTORE_PATH": str(keystore)})
            with self.assertRaisesRegex(CredentialError, "ambiguous"):
                resolve_credential_values(
                    config,
                    credentials_from_env=True,
                    environ={
                        "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64": "a2V5",
                        "MOBILE_RELEASE_ANDROID_KEYSTORE_PATH": str(keystore),
                    },
                )

    def test_github_inventory_never_accepts_local_path_secret_alternative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = load_config(write_project(Path(temporary), android_config()))
            secrets = {
                "MOBILE_RELEASE_ANDROID_KEYSTORE_PATH",
                "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
                "MOBILE_RELEASE_ANDROID_KEY_PASSWORD",
            }
            variables = {"MOBILE_RELEASE_ANDROID_KEY_ALIAS"}
            with patch(
                "mobile_release.credentials._github_names",
                return_value=(secrets, variables, None),
            ):
                findings = credential_findings(
                    config,
                    stage="candidate",
                    purpose="signing",
                    github=True,
                )
            keystore = next(item for item in findings if "keystore_base64" in item.code)
            self.assertEqual(keystore.status, Status.MISSING)

    def test_materialized_build_environment_contains_only_platform_build_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            values = {
                "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64": base64.b64encode(b"key").decode(),
                "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": "store-password",
                "MOBILE_RELEASE_ANDROID_KEY_ALIAS": "release",
                "MOBILE_RELEASE_ANDROID_KEY_PASSWORD": "key-password",
                "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64": base64.b64encode(b"p8").decode(),
                "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD": "p12-password",
                "MOBILE_RELEASE_PROJECT_READ_TOKEN": "read-token",
            }
            with materialize_build_inputs(
                config, values=values, platforms=("android",)
            ) as environment:
                path = Path(environment["MOBILE_RELEASE_ANDROID_KEYSTORE_PATH"])
                self.assertTrue(path.is_file())
                self.assertEqual(
                    set(environment),
                    {
                        "MOBILE_RELEASE_ANDROID_KEYSTORE_PATH",
                        "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD",
                        "MOBILE_RELEASE_ANDROID_KEY_ALIAS",
                        "MOBILE_RELEASE_ANDROID_KEY_PASSWORD",
                        "MOBILE_RELEASE_PROJECT_READ_TOKEN",
                    },
                )
            self.assertFalse(path.exists())

    def test_android_firebase_never_writes_through_symlinked_module(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = android_config()
            value["services"]["androidFirebase"] = "required"
            config = load_config(write_project(root, value))
            target = root / "tracked-module"
            target.mkdir()
            sentinel = target / "keep.txt"
            sentinel.write_text("keep\n", encoding="utf-8")
            (root / "linked").symlink_to(target, target_is_directory=True)
            values = {
                "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64": base64.b64encode(
                    b'{"project_info":{}}'
                ).decode()
            }
            with patch(
                "mobile_release.discovery.selected_android_module", return_value=":linked"
            ), patch("mobile_release.discovery.discover_project", return_value={}):
                with self.assertRaisesRegex(CredentialError, "symbolic link"):
                    with materialize_build_inputs(
                        config, values=values, platforms=("android",)
                    ):
                        self.fail("unsafe Firebase destination was entered")
            self.assertFalse((target / "google-services.json").exists())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep\n")

    def test_local_apple_signing_material_is_installed_and_cleaned_ephemerally(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / "private"
            private.mkdir()
            p12 = private / "distribution.p12"
            profile = private / "profile.mobileprovision"
            p12.write_bytes(b"p12")
            profile.write_bytes(b"profile")
            profile_uuid = "12345678-1234-1234-1234-1234567890AB"
            fake_plist = types.ModuleType("plistlib")
            fake_plist.InvalidFileException = ValueError
            fake_plist.loads = lambda _value: {"UUID": profile_uuid}
            calls: list[list[str]] = []

            def fake_private_run(
                argv: list[str], *, environ: object, timeout: int = 30
            ) -> subprocess.CompletedProcess[str]:
                del environ, timeout
                calls.append(argv)
                stdout = ""
                if argv[0] == "openssl" and "-out" in argv:
                    Path(argv[argv.index("-out") + 1]).write_text(
                        "extracted\n", encoding="utf-8"
                    )
                if argv[1:4] == ["default-keychain", "-d", "user"] and "-s" not in argv:
                    stdout = '"/tmp/login.keychain-db"\n'
                elif argv[1:4] == ["list-keychains", "-d", "user"] and "-s" not in argv:
                    stdout = '"/tmp/login.keychain-db" "/tmp/secondary.keychain-db"\n'
                elif argv[1:3] == ["cms", "-D"]:
                    stdout = "plist"
                return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

            with patch.dict(sys.modules, {"plistlib": fake_plist}), patch(
                "mobile_release.credentials._run_private", side_effect=fake_private_run
            ):
                with _temporary_apple_signing_environment(
                    p12=p12,
                    password="private-password",
                    profile=profile,
                    directory=private,
                    home=root,
                ) as updates:
                    installed = (
                        root
                        / "Library/MobileDevice/Provisioning Profiles"
                        / f"{profile_uuid}.mobileprovision"
                    )
                    self.assertEqual(
                        updates["MOBILE_RELEASE_IOS_PROFILE_SPECIFIER"], profile_uuid
                    )
                    self.assertEqual(installed.read_bytes(), b"profile")
                self.assertFalse(installed.exists())
            self.assertTrue(any(command[1] == "import" for command in calls))
            self.assertTrue(any(command[1] == "delete-keychain" for command in calls))
            activation = next(
                command
                for command in calls
                if command[1:5] == ["list-keychains", "-d", "user", "-s"]
                and "signing.keychain-db" in " ".join(command)
            )
            self.assertEqual(len(activation), 6)
            restored_search = next(
                command
                for command in calls
                if command[1:5] == ["list-keychains", "-d", "user", "-s"]
                and "signing.keychain-db" not in " ".join(command)
            )
            self.assertEqual(
                restored_search[-2:],
                ["/tmp/login.keychain-db", "/tmp/secondary.keychain-db"],
            )

    def test_apple_profile_install_rejects_symlinked_parent_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            outside = Path(temporary) / "outside"
            home.mkdir()
            outside.mkdir()
            (home / "Library").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(CredentialError, "symbolic link"):
                _open_profile_directory(home)
            self.assertEqual(list(outside.iterdir()), [])

    def test_certificate_validity_parsing_rejects_future_android_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root / "app", android_config()))
            values = {
                "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64": base64.b64encode(b"key").decode(),
                "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": "store-password",
                "MOBILE_RELEASE_ANDROID_KEY_ALIAS": "release",
                "MOBILE_RELEASE_ANDROID_KEY_PASSWORD": "key-password",
            }
            fingerprint = ":".join(["AA"] * 32)
            output = (
                "Entry type: PrivateKeyEntry\n"
                f"SHA256: {fingerprint}\n"
                "Valid from: Thu Aug 20 00:00:00 UTC 2099 until: Fri Aug 20 00:00:00 UTC 2100\n"
            )
            result = subprocess.CompletedProcess([], 0, stdout=output, stderr="")
            with patch("mobile_release.credentials._run_private", return_value=result):
                finding = _validate_android_material(config, values, root)
            self.assertEqual(finding.status, Status.INVALID)
            self.assertIn("not currently valid", finding.message)

    def test_aware_certificate_dates_are_converted_to_utc(self) -> None:
        parsed = _parse_certificate_datetime("Aug 20 03:00:00 2026 +0300")
        self.assertEqual(parsed.hour, 0)
        self.assertEqual(_utc_datetime(parsed), parsed)

    def test_stage_and_capability_requirements_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = load_config(write_project(Path(temporary), ios_config(demo=True), platform="ios"))
            external = requirements(config, "external-testing")
            names = {item.name for item in external}
            self.assertIn("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", names)
            self.assertIn("MOBILE_RELEASE_APPLE_REVIEW_CONTACT_FIRST_NAME", names)
            self.assertIn("MOBILE_RELEASE_APPLE_DEMO_ACCOUNT_USERNAME", names)
            self.assertTrue(all(item.stage == "external-testing" for item in external))
            signing = {item.name for item in requirements(config, "candidate", purpose="signing")}
            self.assertIn("MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64", signing)
            self.assertNotIn("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", signing)
            store = {item.name for item in requirements(config, "candidate", purpose="store")}
            self.assertIn("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", store)
            self.assertNotIn("MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64", store)

    def test_private_path_inside_repository_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            private = root / "secret.jks"
            private.write_bytes(b"not-a-keystore")
            findings = credential_findings(
                config,
                stage="candidate",
                purpose="signing",
                credentials_from_env=True,
                environ={
                    "MOBILE_RELEASE_ANDROID_KEYSTORE_PATH": str(private),
                    "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": "x",
                    "MOBILE_RELEASE_ANDROID_KEY_ALIAS": "release",
                    "MOBILE_RELEASE_ANDROID_KEY_PASSWORD": "x",
                },
            )
            key = next(item for item in findings if "keystore_base64" in item.code)
            self.assertEqual(key.status, Status.INVALID)
            self.assertNotIn(str(private), key.message)

    def test_metadata_rejects_hidden_junk_and_archive_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            metadata_root = root / "release/store"
            (metadata_root / "android/.DS_Store").write_bytes(b"junk")
            findings = metadata_findings(config, platforms=("android",))
            self.assertTrue(any(item.status == Status.INVALID for item in findings))
            (metadata_root / "android/.DS_Store").unlink()
            (metadata_root / ".gitkeep").write_text("", encoding="utf-8")
            first = root / "first.zip"
            second = root / "second.zip"
            self.assertEqual(
                build_metadata_archive(metadata_root, first),
                build_metadata_archive(metadata_root, second),
            )
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertTrue(
                    all(item.compress_type == zipfile.ZIP_STORED for item in archive.infolist())
                )

    def test_android_metadata_isolated_from_ios_changes_and_secret_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            metadata_root = root / "release/store"
            ios = metadata_root / "ios/en-US"
            ios.mkdir(parents=True)
            foreign = ios / "notes.txt"
            foreign.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic\n")
            first = root / "android-first.zip"
            second = root / "android-second.zip"
            first_hash = build_metadata_archive(metadata_root, first, platform="android")
            foreign.write_text("\"client_secret\": \"synthetic-secret-value\"\n")
            second_hash = build_metadata_archive(metadata_root, second, platform="android")
            self.assertEqual(first_hash, second_hash)
            self.assertFalse(
                any(item.status in {Status.FAIL, Status.INVALID} for item in metadata_findings(
                    config, platforms=("android",)
                ))
            )

            android_text = metadata_root / "android/en-US/full_description.txt"
            android_text.write_text("-----BEGIN ENCRYPTED PRIVATE KEY-----\nsynthetic\n")
            findings = metadata_findings(config, platforms=("android",))
            self.assertTrue(any(item.code == "metadata.secret-pattern" for item in findings))

    def test_asset_only_locale_cannot_pass_store_metadata_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            locale = root / "release/store/android/en-US"
            for path in locale.glob("*.txt"):
                path.unlink()
            (locale / "feature.png").write_bytes(
                b"\x89PNG\r\n\x1a\n" + b"\x00" * 8 + b"\x00\x00\x00\x01\x00\x00\x00\x01"
            )
            findings = metadata_findings(config, platforms=("android",))
            required = next(
                item for item in findings if item.code.endswith(".required-text")
            )
            self.assertEqual(required.status, Status.MISSING)

    def test_ios_metadata_requires_testflight_copy_and_safe_https_urls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, ios_config(), platform="ios"))
            metadata_root = root / "release/store"
            what_to_test = metadata_root / "testflight/what-to-test.txt"
            what_to_test.unlink()
            findings = metadata_findings(config, platforms=("ios",))
            self.assertTrue(
                any(
                    item.status == Status.MISSING and "what-to-test.txt" in item.message
                    for item in findings
                )
            )

            what_to_test.write_text("x" * 4001, encoding="utf-8")
            (metadata_root / "ios/en-US/privacy_url.txt").write_text(
                "http://user:password@example.test/privacy\n", encoding="utf-8"
            )
            findings = metadata_findings(config, platforms=("ios",))
            self.assertTrue(
                any(item.code == "metadata.url" and item.status == Status.INVALID for item in findings)
            )
            self.assertTrue(
                any(
                    item.code == "metadata.length"
                    and "what-to-test.txt" in item.message
                    for item in findings
                )
            )
            (metadata_root / "ios/en-US/privacy_url.txt").write_text(
                "https://example.test/privacy?token=synthetic#fragment\n", encoding="utf-8"
            )
            findings = metadata_findings(config, platforms=("ios",))
            self.assertTrue(any(item.code == "metadata.url" for item in findings))


if __name__ == "__main__":
    unittest.main()
