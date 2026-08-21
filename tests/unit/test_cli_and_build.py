from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
import types
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from mobile_release.cli import (
    _candidate_context_matches,
    _init,
    _set_artifact_environment,
    _validate_ci_artifact_selection,
    build_parser,
)
from mobile_release.config import load_config
from mobile_release.discovery import GitContext
from mobile_release.errors import MutationGuardError, StoreOperationError, ValidationError
from mobile_release.android import (
    _bundletool_manifest,
    _signer_fingerprint,
    _verify_jar_signature,
    run_android_build,
    validate_aab,
)
from mobile_release.credentials import (
    artifact_validation_environment,
    scrub_credential_capabilities,
)
from mobile_release.discovery import discover_project
from mobile_release.ios import run_ios_build
from mobile_release.metadata import build_metadata_archive
from mobile_release.preflight import (
    _effective_android_identity_finding,
    _xcode_toolchain_finding,
    preflight,
)
from mobile_release.provenance import sha256_file
from mobile_release.reporting import FAILING_STATUSES, Finding, Report, Status
from mobile_release.stores import (
    StoreRequest,
    _validate_online_readback,
    execute_store_operation,
    guard_ci_mutation,
    online_preflight_findings,
)
from mobile_release.tooling import REQUIRED_TOOLING_FILES, resolve_tooling_root

from .helpers import android_config, ios_config, write_project


class CliBuildTests(unittest.TestCase):
    @staticmethod
    def _write_init_fixture(root: Path) -> Path:
        (root / "app").mkdir(parents=True)
        (root / "app/build.gradle.kts").write_text(
            'plugins { id("com.android.application") }\n'
            'android { defaultConfig { applicationId = "com.example.reader" } }\n',
            encoding="utf-8",
        )
        templates = root / "templates"
        templates.mkdir()
        for name in ("a.yml", "z.yml"):
            (templates / name).write_text(
                "uses: __MOBILE_RELEASE_KIT_REPOSITORY__/.github/workflows/reusable.yml@"
                "__MOBILE_RELEASE_KIT_SHA__\n",
                encoding="utf-8",
            )
        return templates

    def test_public_cli_contract_parses(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "preflight",
                "--config",
                "release/mobile-release.json",
                "--signing",
                "--platform",
                "ios",
                "--run-builds",
            ]
        )
        self.assertTrue(args.signing)
        ci = parser.parse_args(
            [
                "ci",
                "production-submit",
                "--platform",
                "android",
                "--output-dir",
                "out",
                "--confirm",
                "production-submit:android:1.2.3:42",
                "--candidate-manifest",
                "candidate.json",
                "--external-receipt",
                "external.json",
            ]
        )
        self.assertEqual(ci.ci_command, "production-submit")

    def test_effective_android_identity_uses_modern_components_api(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            discovered = discover_project(root)

            def run_gradle(command, **_kwargs):
                self.assertIn("--no-configuration-cache", command)
                init_script = Path(command[command.index("--init-script") + 1]).read_text(
                    encoding="utf-8"
                )
                self.assertIn("androidComponents", init_script)
                self.assertIn("components.onVariants", init_script)
                self.assertIn("applicationVariants", init_script)
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=(
                        "MOBILE_RELEASE_EFFECTIVE_ANDROID_ID|"
                        "demoDebug|com.example.reader.debug\n"
                    ),
                    stderr="",
                )

            with (
                patch("mobile_release.preflight.discover_project", return_value=discovered),
                patch("mobile_release.preflight.subprocess.run", side_effect=run_gradle),
            ):
                finding = _effective_android_identity_finding(config)

            self.assertEqual(finding.status, Status.PASS)
            self.assertEqual(finding.details, {"verifiedVariants": ["demoDebug"]})

    def test_distribution_declares_and_resolves_single_source_tooling_assets(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        pyproject = tomllib.loads((repository / "pyproject.toml").read_text(encoding="utf-8"))
        data_files = pyproject["tool"]["setuptools"]["data-files"]
        self.assertEqual(pyproject["build-system"]["requires"], ["setuptools==80.9.0"])
        self.assertIn("Gemfile.lock", data_files["share/mobile-release-kit"])
        self.assertIn(
            "fastlane/release_support.rb",
            data_files["share/mobile-release-kit/fastlane"],
        )
        self.assertIn(
            "templates/workflows/*.yml",
            data_files["share/mobile-release-kit/templates/workflows"],
        )
        self.assertEqual(
            data_files["share/mobile-release-kit/schemas"], ["schemas/*.json"]
        )
        self.assertEqual(
            resolve_tooling_root(environ={}, candidates=(repository,)), repository
        )

        with tempfile.TemporaryDirectory() as temporary:
            installed = Path(temporary) / "share/mobile-release-kit"
            for relative in REQUIRED_TOOLING_FILES:
                path = installed / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("installed fixture\n", encoding="utf-8")
            self.assertEqual(
                resolve_tooling_root(environ={}, candidates=(installed,)),
                installed.resolve(),
            )
            (installed / "templates/workflows/mobile-preflight.yml").unlink()
            self.assertIsNone(
                resolve_tooling_root(environ={}, candidates=(installed,))
            )

    def test_module_entrypoint_ignores_cwd_shadowing_in_safe_path_mode(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as temporary:
            attacker = Path(temporary)
            marker = attacker / "shadow-imported"
            (attacker / "mobile_release.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('unsafe')\n",
                encoding="utf-8",
            )
            environment = {
                "PATH": os.environ.get("PATH", ""),
                "PYTHONPATH": str(repository / "src"),
                "PYTHONPYCACHEPREFIX": str(attacker / "pycache"),
                "PYTHONSAFEPATH": "1",
            }
            completed = subprocess.run(
                [sys.executable, "-P", "-m", "mobile_release", "--version"],
                cwd=attacker,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), "mobile-release 0.1.2")
            self.assertFalse(marker.exists())

    def test_init_preflights_sha_and_every_destination_before_writing(self) -> None:
        parser = build_parser()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            templates = self._write_init_fixture(root)
            missing_sha = parser.parse_args(
                ["init", "--root", str(root), "--apply", "--template-dir", str(templates)]
            )
            with self.assertRaisesRegex(ValidationError, "--tooling-sha"):
                _init(missing_sha)
            self.assertFalse((root / "release/mobile-release.json").exists())
            self.assertFalse((root / ".github").exists())

            later_caller = root / ".github/workflows/z.yml"
            later_caller.parent.mkdir(parents=True)
            later_caller.write_text("owned by application\n", encoding="utf-8")
            conflicting = parser.parse_args(
                [
                    "init",
                    "--root",
                    str(root),
                    "--apply",
                    "--template-dir",
                    str(templates),
                    "--tooling-sha",
                    "a" * 40,
                    "--tooling-repository",
                    "example/mobile-release-kit",
                ]
            )
            with self.assertRaisesRegex(ValidationError, "refusing to overwrite workflow caller"):
                _init(conflicting)
            self.assertFalse((root / "release/mobile-release.json").exists())
            self.assertFalse((root / ".github/workflows/a.yml").exists())
            self.assertEqual(later_caller.read_text(encoding="utf-8"), "owned by application\n")

    def test_init_rejects_symlink_destination_even_with_force(self) -> None:
        parser = build_parser()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            templates = self._write_init_fixture(root)
            outside = root / "outside.yml"
            outside.write_text("must remain unchanged\n", encoding="utf-8")
            destination = root / ".github/workflows/a.yml"
            destination.parent.mkdir(parents=True)
            destination.symlink_to(outside)
            args = parser.parse_args(
                [
                    "init",
                    "--root",
                    str(root),
                    "--apply",
                    "--force",
                    "--template-dir",
                    str(templates),
                    "--tooling-sha",
                    "b" * 40,
                    "--tooling-repository",
                    "example/mobile-release-kit",
                ]
            )
            with self.assertRaisesRegex(ValidationError, "symbolic link"):
                _init(args)
            self.assertFalse((root / "release/mobile-release.json").exists())
            self.assertEqual(outside.read_text(encoding="utf-8"), "must remain unchanged\n")

    def test_init_writes_pinned_schema_metadata_skeleton_and_preserves_gitignore(self) -> None:
        parser = build_parser()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            templates = self._write_init_fixture(root)
            (root / ".gitignore").write_text("build/\n", encoding="utf-8")
            sha = "c" * 40
            args = parser.parse_args(
                [
                    "init",
                    "--root",
                    str(root),
                    "--apply",
                    "--template-dir",
                    str(templates),
                    "--tooling-sha",
                    sha,
                    "--tooling-repository",
                    "example/mobile-release-kit",
                ]
            )
            _init(args)
            configured = json.loads(
                (root / "release/mobile-release.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                configured["$schema"],
                "https://raw.githubusercontent.com/example/mobile-release-kit/"
                f"{sha}/schemas/project.schema.json",
            )
            title = root / "release/store/android/en-US/title.txt"
            self.assertTrue(title.is_file())
            self.assertEqual(title.read_text(encoding="utf-8"), "")
            self.assertEqual(
                (root / ".gitignore").read_text(encoding="utf-8"),
                "build/\n.mobile-release/\n",
            )
            self.assertIn(
                "example/mobile-release-kit/.github/workflows/reusable.yml@" + sha,
                (root / ".github/workflows/a.yml").read_text(encoding="utf-8"),
            )

    def test_init_rejects_unusable_pin_repository_and_empty_project(self) -> None:
        parser = build_parser()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            templates = self._write_init_fixture(root)
            args = parser.parse_args(
                [
                    "init",
                    "--root",
                    str(root),
                    "--apply",
                    "--template-dir",
                    str(templates),
                    "--tooling-sha",
                    "d" * 64,
                    "--tooling-repository",
                    "owner/repo",
                ]
            )
            with self.assertRaisesRegex(ValidationError, "tooling-sha"):
                _init(args)
            args.tooling_sha = "d" * 40
            args.tooling_repository = "owner/repo@main"
            with self.assertRaisesRegex(ValidationError, "OWNER/REPO"):
                _init(args)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = parser.parse_args(["init", "--root", str(root)])
            with self.assertRaisesRegex(ValidationError, "no supported"):
                _init(args)
            self.assertFalse((root / "release").exists())

    def test_promotion_requires_current_metadata_to_match_candidate_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            archive = root / "candidate-metadata.zip"
            build_metadata_archive(root / "release/store", archive)
            payload = {
                "version": {"marketing": "1.2.3", "build": 42},
                "platforms": {"android": {"applicationId": "com.example.reader"}},
                "configuration": {
                    "sha256": sha256_file(config.path),
                    "metadataSha256": sha256_file(archive),
                },
            }
            with patch("mobile_release.cli.verify_sealed", return_value=payload):
                _candidate_context_matches(config, {}, "android")
                (root / "release/store/android/en-US/title.txt").write_text(
                    "Changed after candidate\n", encoding="utf-8"
                )
                with self.assertRaisesRegex(ValidationError, "immutable candidate metadata"):
                    _candidate_context_matches(config, {}, "android")

    def test_mutation_guard_requires_exact_ci_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = load_config(write_project(Path(temporary), android_config()))
            request = StoreRequest(
                stage="candidate",
                platform="android",
                confirmation="candidate:android:1.2.3:42",
                execute=True,
                output_dir=Path(temporary),
            )
            git = GitContext("example/app", "1", "2" * 40, "3" * 40, "refs/heads/main", "main", False)
            with self.assertRaisesRegex(MutationGuardError, "GitHub Actions"):
                guard_ci_mutation(
                    request=request,
                    config=config,
                    release=config.release_version(),
                    git=git,
                    environ={},
                )

    def test_mutation_guard_binds_github_sha_to_checked_out_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = load_config(write_project(Path(temporary), android_config()))
            request = StoreRequest(
                stage="candidate",
                platform="android",
                confirmation="candidate:android:1.2.3:42",
                execute=True,
                output_dir=Path(temporary),
            )
            git = GitContext(
                "example/app",
                "1",
                "2" * 40,
                "3" * 40,
                "refs/heads/main",
                "main",
                False,
            )
            environment = {
                "GITHUB_ACTIONS": "true",
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "MOBILE_RELEASE_CI_MUTATIONS_ALLOWED": "true",
                "MOBILE_RELEASE_ENVIRONMENT": "mobile-candidate",
                "GITHUB_SHA": "4" * 40,
            }
            with self.assertRaisesRegex(MutationGuardError, "GITHUB_SHA"):
                guard_ci_mutation(
                    request=request,
                    config=config,
                    release=config.release_version(),
                    git=git,
                    environ=environment,
                )
            environment["GITHUB_SHA"] = git.commit
            guard_ci_mutation(
                request=request,
                config=config,
                release=config.release_version(),
                git=git,
                environ=environment,
            )
            for dirty in (None, True):
                uncertain = GitContext(
                    git.repository,
                    git.repository_id,
                    git.commit,
                    git.tree,
                    git.ref,
                    git.branch,
                    dirty,
                )
                with self.assertRaisesRegex(MutationGuardError, "provably clean"):
                    guard_ci_mutation(
                        request=request,
                        config=config,
                        release=config.release_version(),
                        git=uncertain,
                        environ=environment,
                    )

    def test_ios_archive_receives_committed_version_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, ios_config(), platform="ios"))
            commands: list[list[str]] = []
            overrides: list[dict[str, str]] = []

            def fake_run(
                argv: list[str],
                _root: Path,
                _timeout: int,
                *,
                environment_overrides: dict[str, str] | None = None,
            ) -> None:
                commands.append(argv)
                overrides.append(environment_overrides or {})
                archive_index = argv.index("-archivePath") + 1 if "-archivePath" in argv else None
                if archive_index:
                    Path(argv[archive_index]).mkdir(parents=True, exist_ok=True)

            with patch("mobile_release.ios.sys.platform", "darwin"), patch(
                "mobile_release.ios._run_checked", side_effect=fake_run
            ):
                run_ios_build(config, signed=False)
            archive_command = commands[-1]
            self.assertIn("MARKETING_VERSION=1.2.3", archive_command)
            self.assertIn("CURRENT_PROJECT_VERSION=42", archive_command)
            self.assertFalse(
                any(value.startswith("PRODUCT_BUNDLE_IDENTIFIER=") for value in archive_command)
            )
            self.assertEqual(overrides[-1]["MOBILE_RELEASE_DEFER_EXTERNAL_UPLOADS"], "1")
            self.assertEqual(overrides[-1]["MOBILE_RELEASE_VERSION_NAME"], "1.2.3")
            self.assertEqual(overrides[-1]["MOBILE_RELEASE_BUILD_NUMBER"], "42")

    def test_android_build_overrides_ambient_ci_version_with_committed_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            discovered = discover_project(root)
            captured_environment: dict[str, str] = {}
            stale = root / ".mobile-release/build/android/mapping.txt"
            stale.parent.mkdir(parents=True)
            stale.write_text("stale mapping\n", encoding="utf-8")

            def fake_run(*_args: object, **kwargs: object) -> object:
                captured_environment.update(kwargs["env"])
                bundle = root / "app/build/outputs/bundle/release/app-release.aab"
                bundle.parent.mkdir(parents=True)
                with zipfile.ZipFile(bundle, "w") as archive:
                    archive.writestr("BundleConfig.pb", b"x")
                    archive.writestr("base/manifest/AndroidManifest.xml", b"x")
                    archive.writestr("base/dex/classes.dex", b"x")
                return type("Completed", (), {"returncode": 0})()

            with patch.dict(os.environ, {"GITHUB_RUN_NUMBER": "999999"}, clear=False), patch(
                "mobile_release.android.discover_project", return_value=discovered
            ), patch("mobile_release.android.subprocess.run", side_effect=fake_run):
                artifacts = run_android_build(config, signed=False)
            self.assertEqual(captured_environment["MOBILE_RELEASE_VERSION_NAME"], "1.2.3")
            self.assertEqual(captured_environment["MOBILE_RELEASE_BUILD_NUMBER"], "42")
            self.assertNotIn("android-mapping", artifacts)
            self.assertFalse(stale.exists())
            with patch(
                "mobile_release.android._bundletool_manifest",
                return_value=(
                    '<manifest package="com.example.reader" android:versionCode="42" '
                    'android:versionName="1.2.3" />'
                ),
            ):
                findings = validate_aab(
                    artifacts["android-aab"],
                    expected_application_id="com.example.reader",
                    release=config.release_version(),
                    expected_fingerprint=None,
                    check_signer=False,
                )
            self.assertFalse(any(item.status in FAILING_STATUSES for item in findings))

    def test_signed_android_build_canonicalizes_final_aab_without_password_argv(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            discovered = discover_project(root)
            keystore = Path(temporary) / "upload.jks"
            keystore.write_bytes(b"fixture")
            commands: list[list[str]] = []
            signing_environment: dict[str, str] = {}

            def fake_run(command, **kwargs):
                commands.append(command)
                if Path(command[0]).name == "gradlew":
                    bundle = root / "app/build/outputs/bundle/release/app-release.aab"
                    bundle.parent.mkdir(parents=True)
                    with zipfile.ZipFile(bundle, "w") as archive:
                        archive.writestr("BundleConfig.pb", b"x")
                        archive.writestr("base/manifest/AndroidManifest.xml", b"x")
                        archive.writestr("base/dex/classes.dex", b"x")
                else:
                    signing_environment.update(kwargs["env"])
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

            signing = {
                "MOBILE_RELEASE_ANDROID_KEYSTORE_PATH": str(keystore),
                "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": "store-secret",
                "MOBILE_RELEASE_ANDROID_KEY_ALIAS": "upload",
                "MOBILE_RELEASE_ANDROID_KEY_PASSWORD": "key-secret",
            }
            with (
                patch.dict(os.environ, signing, clear=False),
                patch("mobile_release.android.discover_project", return_value=discovered),
                patch("mobile_release.android.subprocess.run", side_effect=fake_run),
            ):
                run_android_build(config, signed=True)

            jarsigner = commands[-1]
            self.assertEqual(jarsigner[0], "jarsigner")
            self.assertIn("-storepass:env", jarsigner)
            self.assertIn("-keypass:env", jarsigner)
            self.assertNotIn("store-secret", jarsigner)
            self.assertNotIn("key-secret", jarsigner)
            self.assertEqual(
                signing_environment["MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD"],
                "store-secret",
            )
            self.assertEqual(
                signing_environment["MOBILE_RELEASE_ANDROID_KEY_PASSWORD"],
                "key-secret",
            )
            self.assertNotIn("MOBILE_RELEASE_ANDROID_KEYSTORE_PATH", signing_environment)

    def test_signed_ios_archive_uses_target_safe_generic_signing_variables(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, ios_config(), platform="ios"))
            commands: list[list[str]] = []

            def fake_run(
                argv: list[str],
                _root: Path,
                _timeout: int,
                *,
                environment_overrides: dict[str, str] | None = None,
            ) -> None:
                self.assertEqual(
                    environment_overrides,
                    {
                        "MOBILE_RELEASE_DEFER_EXTERNAL_UPLOADS": "1",
                        "MOBILE_RELEASE_VERSION_NAME": "1.2.3",
                        "MOBILE_RELEASE_BUILD_NUMBER": "42",
                    },
                )
                commands.append(argv)
                if "-archivePath" in argv:
                    Path(argv[argv.index("-archivePath") + 1]).mkdir(parents=True, exist_ok=True)
                if "-exportPath" in argv:
                    export = Path(argv[argv.index("-exportPath") + 1])
                    export.mkdir(parents=True, exist_ok=True)
                    (export / "Reader.ipa").write_bytes(b"ipa")

            fake_plist = types.ModuleType("plistlib")
            fake_plist.dump = lambda _value, handle, sort_keys=True: handle.write(b"plist")
            with patch.dict(
                os.environ,
                {"MOBILE_RELEASE_IOS_PROFILE_SPECIFIER": "PROFILE-UUID"},
                clear=False,
            ), patch.dict(sys.modules, {"plistlib": fake_plist}), patch(
                "mobile_release.ios.sys.platform", "darwin"
            ), patch("mobile_release.ios._run_checked", side_effect=fake_run):
                run_ios_build(config, signed=True)
            archive_command = commands[0]
            self.assertIn("MOBILE_RELEASE_IOS_CODE_SIGN_STYLE=Manual", archive_command)
            self.assertIn(
                "MOBILE_RELEASE_IOS_DEVELOPMENT_TEAM=ABCDE12345", archive_command
            )
            self.assertIn(
                "MOBILE_RELEASE_IOS_PROVISIONING_PROFILE_SPECIFIER=PROFILE-UUID",
                archive_command,
            )
            forbidden = (
                "CODE_SIGN_STYLE=",
                "DEVELOPMENT_TEAM=",
                "PROVISIONING_PROFILE_SPECIFIER=",
                "PRODUCT_BUNDLE_IDENTIFIER=",
            )
            self.assertFalse(
                any(
                    argument.startswith(prefix)
                    for argument in archive_command
                    for prefix in forbidden
                )
            )

    def test_jarsigner_accepts_only_verified_content_and_self_signed_chain_warning(self) -> None:
        accepted = subprocess.CompletedProcess(
            args=[],
            returncode=4,
            stdout="jar verified, with signer errors.\n",
            stderr=(
                "Error:\n"
                "This jar contains entries whose certificate chain is invalid. Reason: "
                "PKIX path building failed: test: unable to find valid certification path "
                "to requested target\n"
                "This jar contains entries whose signer certificate is self-signed.\n"
                "Warning:\nThis jar contains signatures that do not include a timestamp.\n"
                "POSIX file permission and/or symlink attributes detected. These attributes "
                "are ignored when signing and are not protected by the signature.\n"
            ),
        )
        with patch("mobile_release.android.subprocess.run", return_value=accepted):
            self.assertTrue(_verify_jar_signature(Path("candidate.aab")))
        for warning in (
            "The SHA1 algorithm is disabled by the security properties.",
            "The signer certificate has expired.",
        ):
            unsafe_warning = subprocess.CompletedProcess(
                args=[],
                returncode=4,
                stdout="jar verified.\n",
                stderr=(
                    "This jar contains entries whose certificate chain is invalid. Reason: "
                    "PKIX path building failed: test: unable to find valid certification path "
                    "to requested target\n"
                    "This jar contains entries whose signer certificate is self-signed.\n"
                    f"{warning}\n"
                ),
            )
            with patch("mobile_release.android.subprocess.run", return_value=unsafe_warning):
                with self.assertRaisesRegex(ValidationError, "jarsigner rejected"):
                    _verify_jar_signature(Path("candidate.aab"))
        unknown_warning = subprocess.CompletedProcess(
            args=[],
            returncode=4,
            stdout="jar verified, with signer errors.\n",
            stderr=(
                "Error:\n"
                "This jar contains entries whose certificate chain is invalid. Reason: "
                "PKIX path building failed: test: unable to find valid certification path "
                "to requested target\n"
                "This jar contains entries whose signer certificate is self-signed.\n"
                "Warning:\nUnexpected verifier warning.\n"
            ),
        )
        with patch("mobile_release.android.subprocess.run", return_value=unknown_warning):
            with self.assertRaisesRegex(ValidationError, "jarsigner rejected"):
                _verify_jar_signature(Path("candidate.aab"))
        rejected = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="signature verification failed"
        )
        with patch("mobile_release.android.subprocess.run", return_value=rejected):
            with self.assertRaisesRegex(ValidationError, "jarsigner rejected"):
                _verify_jar_signature(Path("candidate.aab"))

        incomplete_chain = subprocess.CompletedProcess(
            args=[],
            returncode=4,
            stdout="jar verified.\n",
            stderr="This jar contains entries whose signer certificate is self-signed.\n",
        )
        with patch("mobile_release.android.subprocess.run", return_value=incomplete_chain):
            with self.assertRaisesRegex(ValidationError, "jarsigner rejected"):
                _verify_jar_signature(Path("candidate.aab"))

    def test_aab_signer_fingerprint_rejects_multiple_distinct_leaf_certificates(self) -> None:
        first = ":".join(["11"] * 32)
        second = ":".join(["22"] * 32)
        single = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=f"Signer #1:\n\nCertificate #1:\n SHA256: {first}\n",
            stderr="",
        )
        with patch("mobile_release.android.subprocess.run", return_value=single):
            self.assertEqual(_signer_fingerprint(Path("candidate.aab")), "11" * 32)
        multiple = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                f"Signer #1:\n\nCertificate #1:\n SHA256: {first}\n"
                f"Signer #2:\n\nCertificate #1:\n SHA256: {second}\n"
            ),
            stderr="",
        )
        with patch("mobile_release.android.subprocess.run", return_value=multiple):
            with self.assertRaisesRegex(ValidationError, "multiple distinct"):
                _signer_fingerprint(Path("candidate.aab"))

    def test_artifact_subprocess_environment_scrubs_external_capabilities(self) -> None:
        source = {
            "PATH": "/usr/bin",
            "CI": "true",
            "MOBILE_RELEASE_AAB_PATH": "/safe/app.aab",
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.invalid",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc-token",
            "AWS_SECRET_ACCESS_KEY": "secret",
            "GITHUB_TOKEN": "token",
            "MY_API_KEY": "key",
            "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64": "private",
            "JAVA_TOOL_OPTIONS": "-javaagent:/untrusted/agent.jar",
            "PYTHONPATH": "/untrusted",
        }
        scrubbed = scrub_credential_capabilities(source)
        self.assertEqual(scrubbed["PATH"], "/usr/bin")
        self.assertEqual(scrubbed["CI"], "true")
        self.assertEqual(scrubbed["MOBILE_RELEASE_AAB_PATH"], "/safe/app.aab")
        for name in {
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "MY_API_KEY",
            "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64",
        }:
            self.assertNotIn(name, scrubbed)
        validation = artifact_validation_environment(source)
        self.assertEqual(validation["PATH"], "/usr/bin")
        self.assertEqual(validation["CI"], "true")
        self.assertEqual(validation["LANG"], "C")
        self.assertEqual(validation["LC_ALL"], "C")
        self.assertNotIn("JAVA_TOOL_OPTIONS", validation)
        self.assertNotIn("PYTHONPATH", validation)
        self.assertNotIn("MOBILE_RELEASE_AAB_PATH", validation)

    def test_application_artifact_check_receives_only_minimal_runtime_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = android_config()
            value["projectChecks"]["androidArtifact"] = [["verify-aab"]]
            config = load_config(write_project(root, value))
            aab = root / "candidate.aab"
            aab.write_bytes(b"fixture")
            captured: dict[str, str] = {}

            def fake_checks(
                _config: object, phase: str, *, environ: dict[str, str]
            ) -> list[Finding]:
                if phase == "androidArtifact":
                    captured.update(environ)
                return []

            with patch.dict(
                os.environ,
                {
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc-token",
                    "AWS_SECRET_ACCESS_KEY": "cloud-secret",
                    "JAVA_TOOL_OPTIONS": "-javaagent:/untrusted/agent.jar",
                    "PYTHONPATH": "/untrusted",
                },
                clear=False,
            ), patch(
                "mobile_release.preflight.validate_aab", return_value=[]
            ), patch(
                "mobile_release.preflight.run_project_checks", side_effect=fake_checks
            ):
                preflight(
                    config,
                    mode="offline",
                    platforms=("android",),
                    run_builds=False,
                    artifacts={"android-aab": aab},
                )
            self.assertEqual(captured["MOBILE_RELEASE_AAB_PATH"], str(aab))
            self.assertEqual(captured["MOBILE_RELEASE_VERSION_NAME"], "1.2.3")
            self.assertEqual(captured["MOBILE_RELEASE_BUILD_NUMBER"], "42")
            for name in (
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                "AWS_SECRET_ACCESS_KEY",
                "JAVA_TOOL_OPTIONS",
                "PYTHONPATH",
            ):
                self.assertNotIn(name, captured)

    def test_generated_build_root_symlink_is_rejected_without_deleting_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            tracked = root / "tracked-output"
            tracked.mkdir()
            sentinel = tracked / "keep.txt"
            sentinel.write_text("keep\n", encoding="utf-8")
            (root / ".mobile-release").symlink_to(tracked, target_is_directory=True)
            with patch("mobile_release.android.subprocess.run") as run:
                with self.assertRaisesRegex(ValidationError, "symbolic link"):
                    run_android_build(config, signed=False)
            self.assertFalse(
                any(
                    any("gradlew" in str(argument) for argument in call.args[0])
                    for call in run.call_args_list
                )
            )
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep\n")

    def test_bundletool_path_and_reviewed_hash_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            jar = Path(temporary) / "bundletool.jar"
            jar.write_bytes(b"not the reviewed jar")
            with patch.dict(
                os.environ, {"MOBILE_RELEASE_BUNDLETOOL_JAR": str(jar)}, clear=False
            ), patch("mobile_release.android.subprocess.run") as run:
                with self.assertRaisesRegex(ValidationError, "reviewed SHA-256"):
                    _bundletool_manifest(Path("candidate.aab"))
            run.assert_not_called()
            target = Path(temporary) / "target.jar"
            target.write_bytes(b"target")
            jar.unlink()
            jar.symlink_to(target)
            with patch.dict(
                os.environ, {"MOBILE_RELEASE_BUNDLETOOL_JAR": str(jar)}, clear=False
            ):
                with self.assertRaisesRegex(ValidationError, "symbolic-link"):
                    _bundletool_manifest(Path("candidate.aab"))

    def test_ci_artifact_environment_uses_store_adapter_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
            root = Path(temporary)
            artifacts = {
                "android-aab": root / "app.aab",
                "android-mapping": root / "mapping.txt",
                "ios-ipa": root / "app.ipa",
            }
            _set_artifact_environment(artifacts)
            self.assertEqual(
                os.environ["MOBILE_RELEASE_ANDROID_AAB_PATH"], str(artifacts["android-aab"])
            )
            self.assertEqual(
                os.environ["MOBILE_RELEASE_ANDROID_MAPPING_PATH"],
                str(artifacts["android-mapping"]),
            )
            self.assertEqual(
                os.environ["MOBILE_RELEASE_IOS_IPA_PATH"], str(artifacts["ios-ipa"])
            )
            self.assertNotIn("MOBILE_RELEASE_AAB_PATH", os.environ)
            self.assertNotIn("MOBILE_RELEASE_IPA_PATH", os.environ)

    def test_ci_candidate_artifacts_are_platform_scoped_and_promotions_are_receipt_only(self) -> None:
        artifact = Path("artifact")
        _validate_ci_artifact_selection(
            stage="candidate",
            platform="android",
            artifacts={
                "android-aab": artifact,
                "validation-report": artifact,
            },
        )
        for artifacts in (
            {"android-aab": artifact},
            {
                "android-aab": artifact,
                "ios-ipa": artifact,
                "validation-report": artifact,
            },
            {
                "android-aab": artifact,
                "store-metadata": artifact,
                "validation-report": artifact,
            },
        ):
            with self.assertRaises(ValidationError):
                _validate_ci_artifact_selection(
                    stage="candidate", platform="android", artifacts=artifacts
                )
        for stage in ("external-testing", "production-submit"):
            with self.assertRaisesRegex(ValidationError, "never accepts binaries"):
                _validate_ci_artifact_selection(
                    stage=stage,
                    platform="android",
                    artifacts={"android-aab": artifact},
                )

    def test_report_output_rejects_symlinked_private_parent_even_when_target_tree_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "tracked"
            (target / "reports").mkdir(parents=True)
            (root / ".mobile-release").symlink_to(target, target_is_directory=True)
            report = Report("test")
            with self.assertRaisesRegex(ValidationError, "symbolic link"):
                report.emit(
                    output_format="json",
                    output=Path(".mobile-release/reports/report.json"),
                    root=root,
                )
            self.assertFalse((target / "reports/report.json").exists())

    def test_xcode_toolchain_requires_exact_shared_baseline(self) -> None:
        exact = subprocess.CompletedProcess(
            [], 0, stdout="Xcode 26.3\nBuild version 17C529\n", stderr=""
        )
        mismatch = subprocess.CompletedProcess(
            [], 0, stdout="Xcode 26.2\nBuild version 17B99\n", stderr=""
        )
        with patch("mobile_release.preflight.sys.platform", "darwin"), patch(
            "mobile_release.preflight.shutil.which", return_value="/usr/bin/xcodebuild"
        ), patch("mobile_release.preflight.subprocess.run", return_value=exact):
            self.assertEqual(_xcode_toolchain_finding().status, Status.PASS)
        with patch("mobile_release.preflight.sys.platform", "darwin"), patch(
            "mobile_release.preflight.shutil.which", return_value="/usr/bin/xcodebuild"
        ), patch("mobile_release.preflight.subprocess.run", return_value=mismatch):
            self.assertEqual(_xcode_toolchain_finding().status, Status.FAIL)

    def test_store_adapter_uses_pinned_ruby_lane_runner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            tooling = root / "tooling"
            (tooling / "fastlane").mkdir(parents=True)
            (tooling / "schemas").mkdir()
            (tooling / "fastlane/Fastfile").write_text("# test\n", encoding="utf-8")
            (tooling / "fastlane/run_lane.rb").write_text("# test\n", encoding="utf-8")
            (tooling / "fastlane/release_support.rb").write_text("# test\n", encoding="utf-8")
            (tooling / "Gemfile").write_text("source 'https://rubygems.org'\n", encoding="utf-8")
            (tooling / "Gemfile.lock").write_text("GEM\n", encoding="utf-8")
            for name in ("candidate.schema.json", "project.schema.json", "receipt.schema.json"):
                (tooling / "schemas" / name).write_text("{}\n", encoding="utf-8")
            for relative in REQUIRED_TOOLING_FILES:
                path = tooling / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists():
                    path.write_text("# installed fixture\n", encoding="utf-8")
            receipt_path = root / "raw-store-receipt.json"
            aab = root / "candidate.aab"
            aab.write_bytes(b"candidate")
            (root / "fastlane").mkdir()
            (root / "fastlane/Appfile").write_text("raise 'consumer config loaded'\n")
            (root / "fastlane/Pluginfile").write_text("raise 'consumer plugin loaded'\n")
            captured: list[str] = []
            captured_environment: dict[str, str] = {}
            captured_cwd: Path | None = None

            def fake_store_run(argv: list[str], **kwargs: object) -> object:
                nonlocal captured_cwd
                if argv[:2] == ["ruby", "-e"]:
                    return subprocess.CompletedProcess(argv, 0, stdout="3.3.12", stderr="")
                if argv == ["bundle", "--version"]:
                    return subprocess.CompletedProcess(
                        argv, 0, stdout="Bundler version 4.0.16", stderr=""
                    )
                if argv == ["bundle", "check"]:
                    return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
                captured.extend(argv)
                captured_environment.update(kwargs["env"])
                captured_cwd = Path(kwargs["cwd"])
                receipt_path.write_text(
                    json.dumps(
                        {
                            "schemaVersion": 1,
                            "operation": "android_internal_upload",
                            "platform": "android",
                            "appIdentity": "com.example.reader",
                            "marketingVersion": "1.2.3",
                            "buildNumber": 42,
                            "observedAt": "2026-01-01T00:00:00Z",
                            "result": "accepted",
                            "state": "available-to-testers",
                            "versionCode": 42,
                            "destinationTrack": "internal",
                            "releaseStatus": "completed",
                            "storeEditId": "edit-1",
                        }
                    ),
                    encoding="utf-8",
                )
                return type("Completed", (), {"returncode": 0})()

            request = StoreRequest(
                stage="candidate",
                platform="android",
                confirmation="candidate:android:1.2.3:42",
                execute=True,
                output_dir=root,
                store_receipt=receipt_path,
            )
            with patch.dict(
                os.environ,
                {
                    "MOBILE_RELEASE_TOOLING_ROOT": str(tooling),
                    "MOBILE_RELEASE_ANDROID_AAB_PATH": str(aab),
                    "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": "must-not-leak",
                    "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64": "must-not-leak",
                    "AWS_SECRET_ACCESS_KEY": "must-not-leak",
                },
                clear=False,
            ), patch("mobile_release.stores.shutil.which", return_value="/usr/bin/tool"), patch(
                "mobile_release.stores.subprocess.run", side_effect=fake_store_run
            ):
                execute_store_operation(
                    config=config,
                    release=config.release_version(),
                    request=request,
                )
                preserved = receipt_path.read_bytes()
                with self.assertRaisesRegex(StoreOperationError, "never overwritten"):
                    execute_store_operation(
                        config=config,
                        release=config.release_version(),
                        request=request,
                    )
                self.assertEqual(receipt_path.read_bytes(), preserved)
            self.assertEqual(captured[:3], ["bundle", "exec", "ruby"])
            self.assertEqual(captured[3], str((tooling / "fastlane/run_lane.rb").resolve()))
            self.assertEqual(captured[-1], "android_internal_upload")
            self.assertEqual(len(captured), 5)
            self.assertEqual(
                captured_environment["BUNDLE_GEMFILE"], str((tooling / "Gemfile").resolve())
            )
            self.assertEqual(
                Path(captured_environment["MOBILE_RELEASE_ANDROID_AAB_PATH"]), aab.resolve()
            )
            self.assertNotEqual(captured_cwd, root)
            self.assertNotIn("MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD", captured_environment)
            self.assertNotIn("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", captured_environment)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", captured_environment)

    def test_store_adapter_fails_before_lane_when_pinned_bundle_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            tooling = root / "tooling"
            (tooling / "fastlane").mkdir(parents=True)
            (tooling / "schemas").mkdir()
            for relative in (
                "fastlane/Fastfile",
                "fastlane/run_lane.rb",
                "fastlane/release_support.rb",
                "Gemfile",
                "Gemfile.lock",
            ):
                (tooling / relative).write_text("# pinned\n", encoding="utf-8")
            for name in ("candidate.schema.json", "project.schema.json", "receipt.schema.json"):
                (tooling / "schemas" / name).write_text("{}\n", encoding="utf-8")
            for relative in REQUIRED_TOOLING_FILES:
                path = tooling / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists():
                    path.write_text("# installed fixture\n", encoding="utf-8")
            request = StoreRequest(
                stage="candidate",
                platform="android",
                confirmation="candidate:android:1.2.3:42",
                execute=True,
                output_dir=root,
            )
            def missing_bundle(argv: list[str], **_kwargs: object) -> object:
                if argv[:2] == ["ruby", "-e"]:
                    return subprocess.CompletedProcess(argv, 0, stdout="3.3.12", stderr="")
                if argv == ["bundle", "--version"]:
                    return subprocess.CompletedProcess(argv, 0, stdout="Bundler 4.0.16", stderr="")
                return subprocess.CompletedProcess(argv, 1, stdout="", stderr="missing")

            with patch.dict(
                os.environ, {"MOBILE_RELEASE_TOOLING_ROOT": str(tooling)}, clear=False
            ), patch("mobile_release.stores.shutil.which", return_value="/usr/bin/tool"), patch(
                "mobile_release.stores.subprocess.run", side_effect=missing_bundle
            ) as run:
                with self.assertRaisesRegex(
                    StoreOperationError, "Pinned Fastlane dependencies"
                ):
                    execute_store_operation(
                        config=config,
                        release=config.release_version(),
                        request=request,
                    )
            self.assertEqual(run.call_args_list[-1].args[0], ["bundle", "check"])
            self.assertEqual(run.call_count, 3)

    def test_offline_build_reports_private_dependency_token_gate_before_gradle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = android_config()
            value["source"]["projectReadTokenRequired"] = True
            config = load_config(write_project(root, value))
            with patch("mobile_release.preflight.run_android_build") as build:
                report = preflight(
                    config,
                    mode="offline",
                    platforms=("android",),
                    run_builds=True,
                )
            build.assert_not_called()
            finding = next(
                item for item in report.findings if item.code == "build.project-read-token"
            )
            self.assertIn("MOBILE_RELEASE_PROJECT_READ_TOKEN", finding.message)

    def test_local_preflight_checks_receive_explicit_credentials_file_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary).resolve()
            root = private_root / "app"
            value = android_config()
            value["source"]["projectReadTokenRequired"] = True
            value["projectChecks"]["preflight"] = [["verify-private-dependency"]]
            config = load_config(write_project(root, value))
            credential_file = private_root / "mobile-release.env"
            credential_file.write_text(
                "MOBILE_RELEASE_PROJECT_READ_TOKEN=read-only-token\n", encoding="utf-8"
            )
            credential_file.chmod(0o600)
            captured_environment: dict[str, str] = {}

            def fake_project_checks(
                _config: object, _phase: str, *, environ: dict[str, str]
            ) -> list[object]:
                captured_environment.update(environ)
                return []

            with patch.dict(
                os.environ,
                {
                    "MOBILE_RELEASE_PROJECT_READ_TOKEN": "ambient-token",
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "ambient-oidc-token",
                    "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.invalid",
                    "AWS_SECRET_ACCESS_KEY": "ambient-cloud-secret",
                    "GITHUB_EVENT_PATH": str(root / "ambient-event.json"),
                    "CMAKE_PREFIX_PATH": str(root / "ambient-cmake"),
                },
                clear=False,
            ), patch(
                "mobile_release.preflight.run_project_checks",
                side_effect=fake_project_checks,
            ):
                preflight(
                    config,
                    mode="offline",
                    platforms=("android",),
                    run_builds=False,
                    credentials_file=credential_file,
                    credentials_from_env=True,
                )
            self.assertEqual(
                captured_environment["MOBILE_RELEASE_PROJECT_READ_TOKEN"], "read-only-token"
            )
            self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_TOKEN", captured_environment)
            self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_URL", captured_environment)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", captured_environment)

    def test_closed_play_online_preflight_requires_nonempty_group_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            raw = {
                "schemaVersion": 1,
                "platform": "android",
                "appIdentity": "com.example.reader",
                "buildNumber": 42,
                "buildUnused": True,
                "requiredTracks": ["internal", "closed-testing"],
                "observedAt": "2026-01-01T00:00:00Z",
            }
            with self.assertRaisesRegex(
                StoreOperationError, "closedTesterAssignmentVerified"
            ):
                _validate_online_readback(
                    raw,
                    config=config,
                    release=config.release_version(),
                    platform="android",
                )
            raw["closedTesterAssignmentVerified"] = True
            _validate_online_readback(
                raw,
                config=config,
                release=config.release_version(),
                platform="android",
            )

    def test_online_preflight_can_verify_unverified_identity_despite_unrelated_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = ios_config()
            value["ios"]["identityStatus"] = "unverified"
            value["projectChecks"]["preflight"] = [["must-not-run-online"]]
            for key in ("distributionCertificateSha256", "symbols", "review"):
                value["ios"].pop(key)
            config = load_config(write_project(root, value, platform="ios"))
            (root / "release/store/review/ios-notes.txt").unlink()
            configured = Finding(
                "credential.candidate.ios.api",
                Status.CONFIGURED,
                "API authentication is configured.",
            )
            online_pass = Finding(
                "store.online.ios", Status.PASS, "Read-only ownership proof succeeded."
            )
            def online_without_app_credentials(**_kwargs: object) -> list[Finding]:
                self.assertNotIn("GOOGLE_APPLICATION_CREDENTIALS", os.environ)
                self.assertNotIn("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", os.environ)
                self.assertNotIn("GOOGLE_GHA_CREDS_PATH", os.environ)
                return [online_pass]

            with patch.dict(
                os.environ,
                {
                    "GOOGLE_APPLICATION_CREDENTIALS": "/private/adc.json",
                    "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE": "/private/cloudsdk.json",
                    "GOOGLE_GHA_CREDS_PATH": "/private/gha.json",
                },
                clear=False,
            ), patch(
                "mobile_release.preflight.credential_findings", return_value=[configured]
            ) as inventory, patch(
                "mobile_release.preflight.validate_store_material", return_value=[]
            ), patch(
                "mobile_release.preflight.online_preflight_findings",
                side_effect=online_without_app_credentials,
            ) as online, patch("mobile_release.preflight.run_project_checks") as project_checks:
                report = preflight(
                    config,
                    mode="online",
                    platforms=("ios",),
                    run_builds=False,
                )
            self.assertEqual(inventory.call_args.kwargs["stage"], "candidate")
            online.assert_called_once()
            project_checks.assert_not_called()
            self.assertTrue(any(item.code == "store.online.ios" for item in report.findings))
            self.assertTrue(
                any(
                    item.code == "ios.identity-status" and item.status == Status.BLOCKED
                    for item in report.findings
                )
            )

    def test_android_local_online_requires_adc_before_store_runner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary)
            root = private_root / "app"
            config = load_config(write_project(root, android_config()))
            credentials = private_root / "credentials.env"
            credentials.write_text(
                "MOBILE_RELEASE_GOOGLE_WIF_PROVIDER=projects/1/providers/test\n"
                "MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT=release@example.test\n",
                encoding="utf-8",
            )
            credentials.chmod(0o600)
            with patch("mobile_release.preflight.online_preflight_findings") as online:
                report = preflight(
                    config,
                    mode="online",
                    platforms=("android",),
                    run_builds=False,
                    credentials_file=credentials,
                )
            online.assert_not_called()
            finding = next(
                item
                for item in report.findings
                if item.code == "credential-material.google-adc"
            )
            self.assertEqual(finding.status, Status.MISSING)

    def test_online_readback_path_is_inside_app_and_accepted_by_ruby_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root, android_config()))
            report_relative = Path(".mobile-release/store/preflight-android.json")
            repository = Path(__file__).resolve().parents[2]
            if shutil.which("ruby"):
                ruby = subprocess.run(
                    [
                        "ruby",
                        "-I",
                        str(repository / "fastlane"),
                        "-e",
                        "require 'release_support'; puts MobileReleaseKit.safe_path(ARGV[0], ARGV[1], must_exist: false)",
                        str(root),
                        str(report_relative),
                    ],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(ruby.returncode, 0, ruby.stderr)
                self.assertEqual(
                    Path(ruby.stdout.strip()).resolve(), (root / report_relative).resolve()
                )

            captured_cwd: Path | None = None

            def fake_lane(argv: list[str], **kwargs: object) -> object:
                nonlocal captured_cwd
                captured_cwd = Path(kwargs["cwd"])
                path = Path(kwargs["env"]["MOBILE_RELEASE_PREFLIGHT_READBACK_PATH"])
                path.resolve().relative_to(root.resolve())
                path.write_text(
                    json.dumps(
                        {
                            "schemaVersion": 1,
                            "platform": "android",
                            "appIdentity": "com.example.reader",
                            "buildNumber": 42,
                            "buildUnused": True,
                            "requiredTracks": ["internal", "closed-testing"],
                            "closedTesterAssignmentVerified": True,
                            "observedAt": "2026-01-01T00:00:00Z",
                        }
                    ),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(argv, 0)

            with patch.dict(
                os.environ,
                {"MOBILE_RELEASE_PREFLIGHT_READBACK_PATH": str(report_relative)},
                clear=False,
            ), patch(
                "mobile_release.stores.resolve_tooling_root", return_value=repository
            ), patch("mobile_release.stores._require_fastlane_bundle"), patch(
                "mobile_release.stores.subprocess.run", side_effect=fake_lane
            ):
                findings = online_preflight_findings(
                    config=config,
                    release=config.release_version(),
                    platforms=("android",),
                )
            self.assertEqual(findings[-1].status, Status.PASS)
            self.assertNotEqual(captured_cwd, root)

    def test_online_preflight_blocks_explicitly_blocked_or_incomplete_query_identity(self) -> None:
        for status, missing_key in (("blocked", None), ("unverified", "appStoreAppId")):
            with self.subTest(status=status, missing_key=missing_key), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                value = ios_config()
                value["ios"]["identityStatus"] = status
                if missing_key:
                    value["ios"].pop(missing_key)
                config = load_config(write_project(root, value, platform="ios"))
                with patch(
                    "mobile_release.preflight.credential_findings", return_value=[]
                ), patch(
                    "mobile_release.preflight.validate_store_material", return_value=[]
                ), patch(
                    "mobile_release.preflight.online_preflight_findings"
                ) as online:
                    report = preflight(
                        config,
                        mode="online",
                        platforms=("ios",),
                        run_builds=False,
                    )
                online.assert_not_called()
                gate = next(item for item in report.findings if item.code == "store.online.gate")
                self.assertEqual(gate.status, Status.SKIP)


if __name__ == "__main__":
    unittest.main()
