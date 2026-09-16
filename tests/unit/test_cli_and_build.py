from __future__ import annotations

import base64
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
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

from mobile_release import __version__, stores
from mobile_release._profile_callers import first_primary_context
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
from mobile_release.build_inputs import app_private_namespace, finite_scratch, invocation_custody
from mobile_release.cancellation import DefaultCancellation
from mobile_release.owned_process import ProcessCleanupError, ProcessError
from mobile_release.credentials import (
    _selected_store_material,
    artifact_validation_environment,
    scrub_credential_capabilities,
)
from mobile_release.discovery import discover_project
from mobile_release.ios import run_ios_build
from mobile_release.init_transaction import IGNORE_LINES
from mobile_release.metadata import build_metadata_archive
from mobile_release.preflight import (
    _effective_android_identity_finding,
    _xcode_toolchain_finding,
    effective_identity_findings,
    preflight,
)
from mobile_release.provenance import sha256_file, write_evidence
from mobile_release.reporting import FAILING_STATUSES, Finding, Report, Status
from mobile_release.stores import (
    StoreRequest,
    _require_fastlane_bundle,
    _runtime_environment,
    _store_environment,
    _validate_online_readback,
    execute_store_operation,
    guard_ci_mutation,
    online_preflight_findings,
)
from mobile_release.tooling import REQUIRED_TOOLING_FILES, resolve_tooling_root

from .helpers import android_config, ios_config, write_project
from .evidence_helpers import build_lifecycle, raw_receipt, workflow_environment
from .store_lane_model import StoreLaneModel


class CliBuildTests(unittest.TestCase):
    @contextmanager
    def _online_material(self, config, *, platforms=("android",)):
        """Real input/guard custody, with no native call or Store authentication."""
        with tempfile.TemporaryDirectory(prefix="mrk-selected-store-fixture-") as temporary:
            adc = Path(temporary) / "adc.json"
            adc.write_bytes(b'{"type":"authorized_user","synthetic":true}')
            adc.chmod(0o600)
            values = {"GOOGLE_APPLICATION_CREDENTIALS": str(adc)}
            if "ios" in platforms:
                values["MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"] = base64.b64encode(b"synthetic-p8").decode("ascii")

            def p8_validator(selected_path, *, execution_source=None, cancellation=None):
                self.assertEqual(selected_path().read_bytes(), b"synthetic-p8")
                self.assertIs(cancellation, invocation.cancellation)
                return Finding("credential-material.apple-p8", Status.PASS,
                               "Synthetic native-validator boundary, not cryptographic evidence.")

            with invocation_custody(config.root, mode="online") as invocation, _selected_store_material(
                    config, values=values, platforms=platforms, invocation=invocation) as material:
                with patch("mobile_release.credentials._validate_selected_p8", side_effect=p8_validator):
                    findings = material.validate()
                self.assertFalse(any(item.status in FAILING_STATUSES for item in findings))
                material.require(config=config, platforms=platforms, invocation=invocation)
                yield invocation, material

    @contextmanager
    def _store_material(self, config, request):
        """Actual selection/cleanup; synthetic key validation is not crypto evidence."""
        with first_primary_context(ExitStack(), expose_owner=True) as (resources, guard):
            record = stores.new_store_lane_evidence(config, request, guard)
            try:
                invocation = resources.enter_context(invocation_custody(config.root,
                    mode="store", cancellation=guard, lane_evidence=record))
                adc = config.root / "synthetic-adc.json"
                adc.write_bytes(b'{"type":"authorized_user","synthetic":true}'); adc.chmod(0o600)
                values = {"GOOGLE_APPLICATION_CREDENTIALS": str(adc),
                    "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64": base64.b64encode(b"synthetic-p8").decode("ascii")}
                material = resources.enter_context(_selected_store_material(config, values=values,
                    platforms=(request.platform,), invocation=invocation, cancellation=guard,
                    lane_evidence=record, stage="production" if request.stage == "production-submit" else request.stage))
                with patch("mobile_release.credentials._validate_selected_p8", return_value=Finding(
                        "credential-material.apple-p8", Status.PASS, "Synthetic validation boundary only")):
                    material.validate()
                yield invocation, material, record
            finally:
                stores.close_store_operation_resources(resources, record, cancellation=guard,
                                                       primary=sys.exc_info()[1])

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
                patch("mobile_release.preflight.run_owned", side_effect=run_gradle),
            ):
                finding = _effective_android_identity_finding(config)

            self.assertEqual(finding.status, Status.PASS)
            self.assertEqual(finding.details, {"verifiedVariants": ["demoDebug"]})

    def test_identity_query_boundaries_use_only_explicit_policy_enabled_dependency_token(self) -> None:
        capabilities = {
            "MOBILE_RELEASE_PROJECT_READ_TOKEN": "ambient-project-token",
            "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64": "ambient-store-key",
            "GOOGLE_APPLICATION_CREDENTIALS": "/fictional/ambient-adc.json",
            "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": "ambient-signing-password",
            "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD": "ambient-p12-password",
            "MOBILE_RELEASE_IOS_PROFILE_SPECIFIER": "ambient-profile",
            "GITHUB_TOKEN": "ambient-github-token",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "ambient-oidc-token",
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.invalid",
            "AWS_SECRET_ACCESS_KEY": "ambient-cloud-secret",
        }
        cases = (
            (True, {"project_read_token": "selected-project-token"}, "selected-project-token"),
            (True, {}, None),
            (True, {"project_read_token": ""}, None),
            (False, {"project_read_token": "selected-project-token"}, None),
        )
        for platform in ("android", "ios"):
            with tempfile.TemporaryDirectory() as temporary:
                value = android_config() if platform == "android" else ios_config()
                if platform == "ios":
                    value["ios"].update(prepareCommand=["prepare-private-dependencies"],
                                        archiveConfiguration="StoreRelease")
                config = load_config(write_project(Path(temporary), value, platform=platform))
                for required, arguments, expected_token in cases:
                    with self.subTest(platform=platform, required=required, arguments=arguments):
                        config.data["source"]["projectReadTokenRequired"] = required
                        calls, scopes = [], []
                        # Forwarding sentinels only: no owner installation or native execution.
                        cancellation = DefaultCancellation(ProcessCleanupError, "fixture cancellation")

                        def new_scope():
                            scopes.append(object())
                            return scopes[-1]

                        def native(command, *, environ, **kwargs):
                            self.assertEqual({name: environ[name] for name in capabilities if name in environ},
                                             {"MOBILE_RELEASE_PROJECT_READ_TOKEN": expected_token}
                                             if expected_token else {})
                            self.assertEqual(environ["LANG"], "C")
                            self.assertIs(kwargs["cancellation"], cancellation)
                            self.assertIs(kwargs["execution_scope"], scopes[-1])
                            self.assertEqual(kwargs["cwd"], config.root)
                            if "--init-script" in command:
                                calls.append("android")
                                self.assertEqual(environ["MOBILE_RELEASE_VERSION_NAME"], "1.2.3")
                                self.assertEqual(environ["MOBILE_RELEASE_BUILD_NUMBER"], "42")
                                output = "MOBILE_RELEASE_EFFECTIVE_ANDROID_ID|demoDebug|com.example.reader.debug\n"
                            elif command == ["prepare-private-dependencies"]:
                                calls.append("prepare")
                                self.assertEqual(environ["MOBILE_RELEASE_VERSION_NAME"], "1.2.3")
                                self.assertEqual(environ["MOBILE_RELEASE_BUILD_NUMBER"], "42")
                                self.assertEqual(environ["MOBILE_RELEASE_DEFER_EXTERNAL_UPLOADS"], "1")
                                output = ""
                            else:
                                self.assertEqual(command[0], "xcodebuild")
                                self.assertIn("-showBuildSettings", command)
                                configuration = command[command.index("-configuration") + 1]
                                calls.append(configuration)
                                identity = "com.example.reader.debug" if configuration == "Debug" else "com.example.reader"
                                output = json.dumps([{"buildSettings": {
                                    "PRODUCT_TYPE": "com.apple.product-type.application",
                                    "PRODUCT_BUNDLE_IDENTIFIER": identity,
                                }}])
                            return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

                        with (
                            patch.dict(os.environ, {**capabilities, "LANG": "C"}),
                            patch("mobile_release.preflight.sys", types.SimpleNamespace(platform="darwin")),
                            patch("mobile_release.preflight.shutil.which", return_value="/fictional/xcodebuild"),
                            patch("mobile_release.preflight.run_owned", side_effect=native),
                            patch("mobile_release.discovery.run_owned", side_effect=AssertionError("unexpected Git query")),
                            patch.object(subprocess, "Popen", side_effect=AssertionError("unexpected native process")),
                        ):
                            original = dict(os.environ)
                            findings = effective_identity_findings(
                                config, (platform,), **arguments, cancellation=cancellation,
                                execution_source=types.SimpleNamespace(new_scope=new_scope),
                            )
                            self.assertEqual(dict(os.environ), original)
                        self.assertEqual([item.status for item in findings], [Status.PASS])
                        self.assertEqual(calls, ["android"] if platform == "android" else ["prepare", "Debug", "StoreRelease"])
                        self.assertEqual(len(scopes), len(calls))

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
        helpers = (
            "fastlane/native_process_spawn.rb", "fastlane/native_upload_process.rb",
            "fastlane/store_document.rb", "fastlane/store_lane_lifetime.rb",
            "fastlane/store_lane_resources.rb", "fastlane/store_lane_runtime.rb",
            "fastlane/store_lane_fastlane_bridges.rb",
        )
        for helper in helpers:
            self.assertIn(helper, data_files["share/mobile-release-kit/fastlane"])
            self.assertIn(helper, REQUIRED_TOOLING_FILES)
        for module in ("_native_process.py", "_profile_process.py"):
            self.assertTrue((repository / "src/mobile_release" / module).is_file())
        self.assertEqual(pyproject["project"]["requires-python"], ">=3.11")
        self.assertEqual(pyproject["project"]["dependencies"], [])
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
            for missing in (*helpers, "templates/workflows/mobile-preflight.yml"):
                with self.subTest(missing=missing):
                    target = installed / missing
                    original = target.read_bytes()
                    target.unlink()
                    self.assertIsNone(resolve_tooling_root(environ={}, candidates=(installed,)))
                    self.assertIsNone(resolve_tooling_root(
                        environ={"MOBILE_RELEASE_TOOLING_ROOT": str(installed)},
                        candidates=(repository,),
                    ))
                    target.write_bytes(original)

    def test_automatic_tooling_resolution_never_borrows_another_installation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            prefix = root / "prefix"
            installed = prefix / "share/mobile-release-kit"
            source = root / "checkout"
            wheel_module = prefix / "lib/python3.11/site-packages/mobile_release/tooling.py"
            source_module = source / "src/mobile_release/tooling.py"
            decoy = wheel_module.parents[2]
            for location in (installed, source, decoy):
                for relative in REQUIRED_TOOLING_FILES:
                    path = location / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"fictional installed asset\n")
            for module in (wheel_module, source_module):
                module.parent.mkdir(parents=True, exist_ok=True)
                module.write_bytes(b"fictional module origin\n")
            for helper in ("fastlane/native_process_spawn.rb", "fastlane/native_upload_process.rb"):
                for module, selected in ((wheel_module, installed), (source_module, source)):
                    with self.subTest(module=module, helper=helper), patch(
                        "mobile_release.tooling.__file__", str(module)
                    ), patch("mobile_release.tooling.sysconfig.get_path", return_value=str(prefix)):
                        self.assertEqual(resolve_tooling_root(environ={}), selected)
                        target = selected / helper
                        content = target.read_bytes()
                        target.unlink()
                        self.assertIsNone(resolve_tooling_root(environ={}))
                        target.write_bytes(content)

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
            self.assertEqual(completed.stdout.strip(), f"mobile-release {__version__}")
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
            notes = root / "release/store/android/en-US/changelogs/default.txt"
            self.assertTrue(notes.is_file())
            self.assertEqual(notes.read_bytes(), b"")
            self.assertEqual(
                (root / ".gitignore").read_text(encoding="utf-8"),
                "build/\n" + "".join(line + "\n" for line in IGNORE_LINES),
            )
            self.assertIn(
                "example/mobile-release-kit/.github/workflows/reusable.yml@" + sha,
                (root / ".github/workflows/a.yml").read_text(encoding="utf-8"),
            )
            notes.write_bytes(b"Existing reviewed notes\r\n")
            args.force = True
            _init(args)
            self.assertEqual(notes.read_bytes(), b"Existing reviewed notes\r\n")

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
                signing_session=None, execution_source=None, cancellation=None,
            ) -> None:
                self.assertIsNone(signing_session)
                self.assertIsNone(execution_source)
                self.assertIsNotNone(cancellation)
                cancellation.check()
                commands.append(argv)
                overrides.append(environment_overrides or {})
                archive_index = argv.index("-archivePath") + 1 if "-archivePath" in argv else None
                if archive_index:
                    Path(argv[archive_index]).mkdir(parents=True, exist_ok=True)

            with patch("mobile_release.ios.sys", types.SimpleNamespace(platform="darwin")), patch(
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
            with app_private_namespace(config.root) as namespace:
                (namespace.path / "build").mkdir(mode=0o700)
                stale.parent.mkdir(mode=0o700)
            stale.write_text("stale mapping\n", encoding="utf-8")

            def fake_run(*_args: object, **kwargs: object) -> object:
                captured_environment.update(kwargs["environ"])
                bundle = root / "app/build/outputs/bundle/release/app-release.aab"
                bundle.parent.mkdir(parents=True)
                with zipfile.ZipFile(bundle, "w") as archive:
                    archive.writestr("BundleConfig.pb", b"x")
                    archive.writestr("base/manifest/AndroidManifest.xml", b"x")
                    archive.writestr("base/dex/classes.dex", b"x")
                return type("Completed", (), {"returncode": 0})()

            with patch.dict(os.environ, {"GITHUB_RUN_NUMBER": "999999"}, clear=False), patch(
                "mobile_release.android.discover_project", return_value=discovered
            ), patch("mobile_release.android.run_owned", side_effect=fake_run):
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
            root = Path(temporary) / "application"
            config = load_config(write_project(root, android_config()))
            discovered = discover_project(root)
            keystore = Path(temporary) / "upload.jks"
            keystore.write_bytes(b"fixture")
            keystore.chmod(0o600)
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
                    selected_keystore = Path(command[command.index("-keystore") + 1])
                    self.assertNotEqual(selected_keystore, keystore)
                    self.assertEqual(selected_keystore.read_bytes(), b"fixture")
                    self.assertEqual(selected_keystore.stat().st_mode & 0o777, 0o600)
                    self.assertIsNotNone(kwargs["cancellation"])
                    kwargs["cancellation"].check()
                    signing_environment.update(kwargs["environ"])
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
                patch("mobile_release.android.run_owned", side_effect=fake_run),
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
            guard = DefaultCancellation(ProcessCleanupError, "synthetic signed build owner")
            guard._installation, guard._activated, guard.depth = "INSTALLED", True, 0
            session = types.SimpleNamespace(assert_owner=lambda: None, cancellation=guard)

            def fake_run(
                argv: list[str],
                _root: Path,
                _timeout: int,
                *,
                environment_overrides: dict[str, str] | None = None,
                signing_session=None, execution_source=None, cancellation=None,
            ) -> None:
                self.assertIs(signing_session, session)
                self.assertIsNone(execution_source)
                self.assertIs(cancellation, guard)
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
            export_options = {}
            def capture_export(value, handle, sort_keys=True):
                export_options.update(value)
                handle.write(b"plist")
            fake_plist.dump = capture_export
            with patch.dict(
                os.environ,
                {"MOBILE_RELEASE_IOS_PROFILE_SPECIFIER": "PROFILE-UUID"},
                clear=False,
            ), patch.dict(sys.modules, {"plistlib": fake_plist}), patch(
                "mobile_release.ios.sys", types.SimpleNamespace(platform="darwin")
            ), patch("mobile_release.ios._run_checked", side_effect=fake_run):
                run_ios_build(config, signed=True, signing_session=session)
            self.assertIs(export_options["stripSwiftSymbols"], False)
            self.assertEqual(export_options["thinning"], "<none>")
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
        with patch("mobile_release.android.run_owned", return_value=accepted):
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
            with patch("mobile_release.android.run_owned", return_value=unsafe_warning):
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
        with patch("mobile_release.android.run_owned", return_value=unknown_warning):
            with self.assertRaisesRegex(ValidationError, "jarsigner rejected"):
                _verify_jar_signature(Path("candidate.aab"))
        rejected = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="signature verification failed"
        )
        with patch("mobile_release.android.run_owned", return_value=rejected):
            with self.assertRaisesRegex(ValidationError, "jarsigner rejected"):
                _verify_jar_signature(Path("candidate.aab"))

        incomplete_chain = subprocess.CompletedProcess(
            args=[],
            returncode=4,
            stdout="jar verified.\n",
            stderr="This jar contains entries whose signer certificate is self-signed.\n",
        )
        with patch("mobile_release.android.run_owned", return_value=incomplete_chain):
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
        with patch("mobile_release.android.run_owned", return_value=single):
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
        with patch("mobile_release.android.run_owned", return_value=multiple):
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
                _config: object, phase: str, *, environ: dict[str, str],
                execution_source=None, cancellation=None,
            ) -> list[Finding]:
                self.assertIsNone(execution_source)
                self.assertIsNotNone(cancellation)
                cancellation.check()
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
            with patch("mobile_release.android.run_owned") as run:
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
            # Keep correctly retained failed-copy residue inside this fixture;
            # do not leave an unknown synthetic snapshot in shared /tmp.
            def scratch_for_fixture(**kwargs):
                return finite_scratch(parent=Path(temporary), **kwargs)
            with patch.dict(os.environ, {"MOBILE_RELEASE_BUNDLETOOL_JAR": str(jar)}, clear=False), patch(
                    "mobile_release.android.finite_scratch", side_effect=scratch_for_fixture), patch(
                    "mobile_release.android.run_owned") as run:
                with self.assertRaises(ValidationError):
                    _bundletool_manifest(Path("candidate.aab"))
            run.assert_not_called()
            self.assertEqual(jar.read_bytes(), b"not the reviewed jar")
            target = Path(temporary) / "target.jar"
            target.write_bytes(b"target")
            jar.unlink()
            jar.symlink_to(target)
            with patch.dict(os.environ, {"MOBILE_RELEASE_BUNDLETOOL_JAR": str(jar)}, clear=False), patch(
                    "mobile_release.android.finite_scratch", side_effect=scratch_for_fixture), patch(
                    "mobile_release.android.run_owned") as run:
                with self.assertRaisesRegex(ValidationError, "symbolic link"):
                    _bundletool_manifest(Path("candidate.aab"))
            run.assert_not_called()
            self.assertTrue(jar.is_symlink())
            self.assertEqual(target.read_bytes(), b"target")

    def test_ci_artifact_environment_uses_store_adapter_names(self) -> None:
        original = {"MOBILE_RELEASE_IOS_IPA_PATH": "original-value"}
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, original, clear=True):
            root = Path(temporary)
            artifacts = {"android-aab": root / "app.aab", "android-mapping": root / "mapping.txt",
                "ios-ipa": root / "app.ipa", "ios-archive": root / "archive.zip", "ios-dsyms": root / "dsyms.zip"}
            with invocation_custody(root, mode="online") as invocation, ExitStack() as resources:
                _set_artifact_environment(artifacts, resources=resources, invocation=invocation)
                for name, variable in (("android-aab", "MOBILE_RELEASE_ANDROID_AAB_PATH"),
                    ("android-mapping", "MOBILE_RELEASE_ANDROID_MAPPING_PATH"),
                    ("ios-ipa", "MOBILE_RELEASE_IOS_IPA_PATH"), ("ios-archive", "MOBILE_RELEASE_IOS_ARCHIVE_PATH"),
                    ("ios-dsyms", "MOBILE_RELEASE_IOS_DSYMS_PATH")):
                    self.assertEqual(os.environ[variable], str(artifacts[name]))
                self.assertNotIn("MOBILE_RELEASE_AAB_PATH", os.environ)
                self.assertNotIn("MOBILE_RELEASE_IPA_PATH", os.environ)
            self.assertEqual(dict(os.environ), original)

    def test_ci_candidate_artifacts_are_platform_scoped_and_promotions_are_receipt_only(self) -> None:
        artifact = Path("artifact")
        with self.assertRaisesRegex(ValidationError, "ios-archive"):
            _validate_ci_artifact_selection(stage="candidate", platform="ios", artifacts={"ios-ipa": artifact, "validation-report": artifact})
        _validate_ci_artifact_selection(stage="candidate", platform="ios", artifacts={"ios-ipa": artifact, "ios-archive": artifact, "validation-report": artifact})
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
        with patch("mobile_release.preflight.sys", types.SimpleNamespace(platform="darwin")), patch(
            "mobile_release.preflight.shutil.which", return_value="/usr/bin/xcodebuild"
        ), patch("mobile_release.preflight.run_owned", return_value=exact):
            self.assertEqual(_xcode_toolchain_finding().status, Status.PASS)
        with patch("mobile_release.preflight.sys", types.SimpleNamespace(platform="darwin")), patch(
            "mobile_release.preflight.shutil.which", return_value="/usr/bin/xcodebuild"
        ), patch("mobile_release.preflight.run_owned", return_value=mismatch):
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
            intent = build_lifecycle(config)["candidate_intent"]
            intent_path = root / "store-operation-intent.json"
            write_evidence(intent_path, intent)
            receipt_path = root / "raw-store-receipt.json"
            aab = root / "app.aab"
            (root / "fastlane").mkdir()
            (root / "fastlane/Appfile").write_text("raise 'consumer config loaded'\n")
            (root / "fastlane/Pluginfile").write_text("raise 'consumer plugin loaded'\n")
            adc = root / "synthetic-adc.json"
            adc.write_bytes(b'{"type":"authorized_user","synthetic":true}'); adc.chmod(0o600)
            model = StoreLaneModel(lambda _argv, _env: (raw_receipt(intent), 0))
            self.addCleanup(model.close)

            def fake_store_run(argv, **kwargs):
                environment = kwargs["environ"]
                self.assertEqual(environment["BUNDLER_VERSION"], "4.0.16")
                self.assertEqual(environment["BUNDLE_IGNORE_CONFIG"], "1")
                self.assertEqual(environment["BUNDLE_AUTO_INSTALL"], "false")
                self.assertEqual(environment["BUNDLE_FROZEN"], "true")
                self.assertEqual(environment["BUNDLE_PATH"], "/fictional/pinned-bundle")
                if "_evidence" in kwargs:
                    return model(argv, **kwargs)
                if argv[:2] == ["ruby", "-e"]:
                    return subprocess.CompletedProcess(argv, 0, stdout="3.3.12", stderr="")
                if argv == ["bundle", "--version"]:
                    return subprocess.CompletedProcess(argv, 0, stdout="4.0.16", stderr="")
                if argv == ["bundle", "check"]:
                    return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
                if argv[-1] == str(tooling / "fastlane/native_process_spawn.rb"):
                    return subprocess.CompletedProcess(argv, 0, stdout="MRK_RUNTIME_3.3.12_FIDDLE_1.1.2", stderr="")
                raise AssertionError("unmodeled Store caller command")

            request = StoreRequest(
                stage="candidate",
                platform="android",
                confirmation="candidate:android:1.2.3:42",
                execute=True,
                output_dir=root,
                store_receipt=receipt_path,
                operation_intent=intent_path,
            )
            with patch.dict(
                os.environ,
                {
                    **workflow_environment(),
                    "MOBILE_RELEASE_TOOLING_ROOT": str(tooling),
                    "GOOGLE_APPLICATION_CREDENTIALS": str(adc),
                    "BUNDLE_PATH": "/fictional/pinned-bundle",
                    "BUNDLER_VERSION": "99.0.0",
                    "BUNDLE_IGNORE_CONFIG": "0",
                    "BUNDLE_AUTO_INSTALL": "true",
                    "BUNDLE_FROZEN": "false",
                    "MOBILE_RELEASE_ANDROID_AAB_PATH": str(aab),
                    "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": "must-not-leak",
                    "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64": "must-not-leak",
                    "AWS_SECRET_ACCESS_KEY": "must-not-leak",
                    "MOBILE_RELEASE_VALIDATION_PYTHON": "/attacker/bin/python",
                    "MOBILE_RELEASE_VALIDATION_MODULE_ROOT": "/attacker/toolkit",
                    "MOBILE_RELEASE_BUNDLETOOL_JAR": "/public/pinned-bundletool.jar",
                    "JAVA_HOME": "/public/jdk-21",
                    "JAVA_TOOL_OPTIONS": "-agentlib:must-not-run",
                    "_JAVA_OPTIONS": "-agentlib:must-not-run",
                    "JDK_JAVA_OPTIONS": "-agentlib:must-not-run",
                    "PYTHONPATH": "/attacker/application-code",
                    "RUBYOPT": "-r/attacker/application-code.rb",
                },
                clear=False,
            ), patch("mobile_release.stores.shutil.which", return_value="/usr/bin/tool"), patch(
                "mobile_release.stores.subprocess.run", side_effect=fake_store_run
            ), patch("mobile_release.stores.run_owned", side_effect=fake_store_run):
                execute_store_operation(
                    config=config,
                    release=config.release_version(),
                    request=request,
                    operation_intent=intent,
                )
                preserved = receipt_path.read_bytes()
                with self.assertRaisesRegex(StoreOperationError, "original live composite"):
                    execute_store_operation(config=config, release=config.release_version(),
                                            request=request, operation_intent=intent)
                self.assertEqual(receipt_path.read_bytes(), preserved)
            self.assertEqual(len(model.calls), 1)
            argv, captured_cwd, captured_environment, _guard = model.calls[0]
            captured = list(argv)
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
            self.assertEqual(
                Path(captured_environment["MOBILE_RELEASE_PLAY_STATE_PATH"]),
                receipt_path.with_name("raw-store-receipt-play-state.json").resolve(),
            )
            self.assertNotEqual(captured_cwd, root)
            self.assertNotIn("MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD", captured_environment)
            self.assertNotIn("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64", captured_environment)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", captured_environment)
            self.assertNotIn("PYTHONPATH", captured_environment)
            self.assertNotIn("RUBYOPT", captured_environment)
            for name in ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"):
                self.assertNotIn(name, captured_environment)
            self.assertEqual(captured_environment["MOBILE_RELEASE_BUNDLETOOL_JAR"], "/public/pinned-bundletool.jar")
            self.assertEqual(captured_environment["JAVA_HOME"], "/public/jdk-21")
            self.assertEqual(captured_environment["MOBILE_RELEASE_VALIDATION_PYTHON"], str(Path(sys.executable).absolute()))
            self.assertEqual(captured_environment["MOBILE_RELEASE_VALIDATION_MODULE_ROOT"], str(Path(sys.modules["mobile_release.stores"].__file__).resolve().parent.parent))

    def test_android_native_tool_context_is_not_transferred_to_other_store_operations(self) -> None:
        for platform, factory in (("android", android_config), ("ios", ios_config)):
            for stage in ("candidate", "external-testing", "production-submit"):
                with self.subTest(platform=platform, stage=stage), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    config = load_config(write_project(root, factory()))
                    request = StoreRequest(
                        stage=stage, platform=platform, confirmation="not-executed",
                        execute=False, output_dir=root,
                    )
                    source = {
                        **workflow_environment(stage),
                        "MOBILE_RELEASE_BUNDLETOOL_JAR": "/public/pinned-bundletool.jar",
                        "JAVA_HOME": "/public/jdk-21",
                        "JAVA_TOOL_OPTIONS": "-agentlib:must-not-run",
                        "_JAVA_OPTIONS": "-agentlib:must-not-run",
                        "JDK_JAVA_OPTIONS": "-agentlib:must-not-run",
                    }
                    with patch.dict(os.environ, source, clear=True), self._store_material(config, request) as (invocation, material, record):
                        actual = _store_environment(config, config.release_version(), request, root / "raw.json", root / "tooling",
                            material=material, invocation=invocation, lane_evidence=record,
                            source_environment=source, authority=stores.workflow_authority(stage))
                    for name in ("MOBILE_RELEASE_BUNDLETOOL_JAR", "JAVA_HOME"):
                        if (platform, stage) == ("android", "candidate"):
                            self.assertEqual(actual[name], source[name])
                        else:
                            self.assertNotIn(name, actual)
                    for name in ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"):
                        self.assertNotIn(name, actual)

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
            intent = build_lifecycle(config)["candidate_intent"]
            intent_path = root / "store-operation-intent.json"
            write_evidence(intent_path, intent)
            request = StoreRequest(
                stage="candidate",
                platform="android",
                confirmation="candidate:android:1.2.3:42",
                execute=True,
                output_dir=root,
                operation_intent=intent_path,
            )
            def missing_bundle(argv: list[str], **_kwargs: object) -> object:
                if argv[:2] == ["ruby", "-e"]:
                    return subprocess.CompletedProcess(argv, 0, stdout="3.3.12", stderr="")
                if argv == ["bundle", "--version"]:
                    return subprocess.CompletedProcess(argv, 0, stdout="4.0.16", stderr="")
                return subprocess.CompletedProcess(argv, 1, stdout="", stderr="missing")

            with patch.dict(
                os.environ, {**workflow_environment(), "MOBILE_RELEASE_TOOLING_ROOT": str(tooling)}, clear=False
            ), patch("mobile_release.stores.shutil.which", return_value="/usr/bin/tool"), patch(
                "mobile_release.stores.run_owned", side_effect=missing_bundle
            ) as run, patch("mobile_release.stores.subprocess.run") as lane:
                with self.assertRaisesRegex(
                    StoreOperationError, "Pinned Fastlane dependencies"
                ):
                    execute_store_operation(
                        config=config,
                        release=config.release_version(),
                        request=request,
                        operation_intent=intent,
                    )
            self.assertEqual(run.call_args_list[-1].args[0], ["bundle", "check"])
            self.assertEqual(run.call_count, 3)
            lane.assert_not_called()

    def test_store_runtime_controls_preserve_explicit_paths_and_ignore_foreign_config(self) -> None:
        supplied = {
            "BUNDLE_PATH": "/fictional/pinned-bundle",
            "BUNDLE_APP_CONFIG": "/fictional/bundle-config",
            "BUNDLE_DEPLOYMENT": "true",
            "BUNDLE_WITHOUT": "test",
            "BUNDLER_VERSION": "99.0.0",
            "BUNDLE_IGNORE_CONFIG": "0",
            "BUNDLE_AUTO_INSTALL": "true",
            "BUNDLE_FROZEN": "false",
            "RUBYOPT": "-r/fictional/untrusted",
            "RUBYLIB": "/fictional/untrusted",
            "BUNDLE_GEMFILE": "/fictional/untrusted/Gemfile",
            "BUNDLE_DISABLE_CHECKSUM_VALIDATION": "true",
        }
        original = dict(supplied)
        actual = _runtime_environment(supplied)
        self.assertEqual(supplied, original)
        self.assertEqual(actual, {
            "BUNDLE_PATH": supplied["BUNDLE_PATH"],
            "BUNDLE_APP_CONFIG": supplied["BUNDLE_APP_CONFIG"],
            "BUNDLE_DEPLOYMENT": "true", "BUNDLE_WITHOUT": "test",
            "BUNDLER_VERSION": "4.0.16", "BUNDLE_IGNORE_CONFIG": "1",
            "BUNDLE_AUTO_INSTALL": "false", "BUNDLE_FROZEN": "true",
        })

    def test_store_runtime_controls_reach_the_online_lane_without_inheriting_preloads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = load_config(write_project(root / "application", android_config()))
            tooling = root / "tooling"
            for relative in REQUIRED_TOOLING_FILES:
                path = tooling / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fictional pinned tooling\n")
            calls, runner_directories = [], []
            explicit = config.root / ".mobile-release/store/explicit-android.json"

            def fake_lane(argv, **kwargs):
                calls.append(tuple(argv))
                environment = kwargs["environ"]
                self.assertEqual(environment["BUNDLE_GEMFILE"], str(tooling / "Gemfile"))
                self.assertEqual(environment["BUNDLE_PATH"], "/fictional/pinned-bundle")
                self.assertEqual(environment["BUNDLER_VERSION"], "4.0.16")
                self.assertEqual(environment["BUNDLE_IGNORE_CONFIG"], "1")
                self.assertEqual(environment["BUNDLE_AUTO_INSTALL"], "false")
                self.assertEqual(environment["BUNDLE_FROZEN"], "true")
                self.assertNotIn("RUBYOPT", environment)
                self.assertNotIn("RUBYLIB", environment)
                self.assertIs(kwargs["cancellation"], invocation.cancellation)
                self.assertIsNone(kwargs["_evidence"])
                self.assertEqual((kwargs["capture"], kwargs["timeout"]), (False, 900))
                self.assertEqual(Path(environment["MOBILE_RELEASE_PREFLIGHT_READBACK_PATH"]), explicit)
                self.assertEqual(json.loads(Path(environment["GOOGLE_APPLICATION_CREDENTIALS"]).read_bytes()),
                                 {"type": "authorized_user", "synthetic": True})
                runner_directories.append(Path(kwargs["cwd"]))
                # Only the call mapping is exercised. No invented successful
                # original writer, finality receipt or Store readback is used.
                return subprocess.CompletedProcess(argv, 1)

            with patch.dict(os.environ, {
                "BUNDLE_PATH": "/fictional/pinned-bundle", "BUNDLER_VERSION": "99.0.0",
                "BUNDLE_IGNORE_CONFIG": "0", "BUNDLE_AUTO_INSTALL": "true", "BUNDLE_FROZEN": "false",
                "RUBYOPT": "-r/fictional/foreign", "RUBYLIB": "/fictional/foreign",
                "MOBILE_RELEASE_PREFLIGHT_READBACK_PATH": str(explicit),
            }, clear=True), patch("mobile_release.stores.resolve_tooling_root", return_value=tooling), patch(
                "mobile_release.stores._require_fastlane_bundle"
            ), patch("mobile_release.stores.run_owned", side_effect=fake_lane), self._online_material(config) as (
                    invocation, material):
                findings = online_preflight_findings(
                    config=config, release=config.release_version(), platforms=("android",),
                    invocation=invocation, material=material,
                )
            self.assertEqual(findings[-1].status, Status.FAIL)
            self.assertEqual(calls, [("bundle", "exec", "ruby", str(tooling / "fastlane/run_lane.rb"),
                                     "android_online_preflight")])
            self.assertFalse(explicit.exists())
            self.assertTrue(all(not directory.exists() for directory in runner_directories))

    def test_store_runtime_admission_rejects_wrong_pins_and_unconfirmed_fiddle_before_lane(self) -> None:
        marker = "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2"
        expected_outputs = ("3.3.12", "4.0.16", "", marker, marker)
        cases = (
            ("pinned-runtime", None, "", 0, "", ""),
            ("older-ruby", 0, "3.3.11", 0, "", "Ruby 3.3.12"),
            ("other-ruby", 0, "3.4.0", 0, "", "Ruby 3.3.12"),
            ("missing-ruby", 0, "", 1, "", "Ruby 3.3.12"),
            ("wrong-bundler", 1, "4.0.17", 0, "", "Bundler 4.0.16"),
            ("legacy-bundler-output", 1, "Bundler version 4.0.16", 0, "", "Bundler 4.0.16"),
            ("simulated-bundler-output", 1, "4.0.16 (simulating Bundler 4.0.17)", 0, "", "Bundler 4.0.16"),
            ("appended-bundler-output", 1, "4.0.16\nunexpected", 0, "", "Bundler 4.0.16"),
            ("missing-bundler", 1, "", 1, "", "Bundler 4.0.16"),
            ("missing-bundle", 2, "", 1, "", "Pinned Fastlane dependencies"),
            ("wrong-default-fiddle", 3, "MRK_RUNTIME_3.3.12_FIDDLE_1.1.3", 0, "", "loaded origin"),
            ("missing-default-fiddle", 3, "", 1, "", "loaded origin"),
            ("wrong-bundle-fiddle", 4, "wrong origin", 0, "", "loaded origin"),
            ("missing-helper", 4, "", 1, "", "loaded origin"),
            ("unconfirmed-runtime", 4, marker, 0, "fictional private diagnostic", "loaded origin"),
        )
        tooling = Path("/fictional/pinned-tooling")
        for label, failed, output, code, stderr, diagnostic in cases:
            calls = []

            def fake(argv, **kwargs):
                index = len(calls)
                calls.append(argv)
                self.assertEqual(kwargs["environ"]["BUNDLE_PATH"], "/fictional/pinned-bundle")
                self.assertEqual(kwargs["environ"]["BUNDLE_GEMFILE"], str(tooling / "Gemfile"))
                self.assertEqual(kwargs["environ"]["BUNDLER_VERSION"], "4.0.16")
                self.assertEqual(kwargs["environ"]["BUNDLE_IGNORE_CONFIG"], "1")
                self.assertEqual(kwargs["environ"]["BUNDLE_AUTO_INSTALL"], "false")
                self.assertEqual(kwargs["environ"]["BUNDLE_FROZEN"], "true")
                self.assertNotIn("BUNDLE_SIMULATE_VERSION", kwargs["environ"])
                if index == failed:
                    return subprocess.CompletedProcess(argv, code, stdout=output, stderr=stderr)
                return subprocess.CompletedProcess(argv, 0, stdout=expected_outputs[index], stderr="")

            with self.subTest(label=label), patch.dict(os.environ, {
                "BUNDLE_PATH": "/fictional/pinned-bundle", "BUNDLE_AUTO_INSTALL": "true",
                "BUNDLER_VERSION": "99.0.0", "BUNDLE_IGNORE_CONFIG": "0", "BUNDLE_FROZEN": "false",
                "BUNDLE_SIMULATE_VERSION": "4.0.17",
            }, clear=True), patch("mobile_release.stores.shutil.which", return_value="/fictional/ruby"), patch(
                "mobile_release.stores.run_owned", side_effect=fake
            ), patch.object(subprocess, "Popen", side_effect=AssertionError("unexpected real admission process")) as popen:
                if failed is None:
                    _require_fastlane_bundle(tooling)
                else:
                    with self.assertRaisesRegex(StoreOperationError, diagnostic) as raised:
                        _require_fastlane_bundle(tooling)
                    self.assertNotIn("fictional private diagnostic", str(raised.exception))
                expected_calls = 5 if failed is None else failed + 1
                self.assertEqual(len(calls), expected_calls)
                self.assertEqual(calls[:3], [["ruby", "-e", "print RUBY_VERSION"],
                                            ["bundle", "--version"], ["bundle", "check"]][:expected_calls])
                self.assertFalse(any("install" in call for call in calls))
                if expected_calls >= 4:
                    self.assertIn("--disable=rubyopt,gems,did_you_mean,error_highlight,syntax_suggest,rjit,yjit", calls[3])
                    self.assertEqual(calls[3][-1], str(tooling / "fastlane/native_process_spawn.rb"))
                if expected_calls == 5:
                    self.assertEqual(calls[4][:3], ["bundle", "exec", "ruby"])
                    self.assertEqual(calls[4][-1], calls[3][-1])
                popen.assert_not_called()
        with patch("mobile_release.stores.shutil.which", return_value=None), patch(
            "mobile_release.stores.run_owned"
        ) as run, patch.object(subprocess, "Popen", side_effect=AssertionError("unexpected real admission process")) as popen:
            with self.assertRaisesRegex(StoreOperationError, "Ruby 3.3.12"):
                _require_fastlane_bundle(tooling)
            run.assert_not_called()
            popen.assert_not_called()

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
                _config: object, _phase: str, *, environ: dict[str, str],
                execution_source=None, cancellation=None,
            ) -> list[object]:
                self.assertIsNone(execution_source)
                self.assertIsNotNone(cancellation)
                cancellation.check()
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

    def test_buildful_preflight_selects_dependency_token_through_actual_identity_and_build_seam(self) -> None:
        # Hosted-only: real invocation/project/environment and cancellation custody.
        # Native commands/build output are synthetic; real artifact validation must reject it.
        token_name = "MOBILE_RELEASE_PROJECT_READ_TOKEN"
        capabilities = {
            token_name: "environment-project-token",
            "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64": "environment-store-key",
            "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": "environment-signing-password",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "environment-oidc-token",
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.invalid",
            "AWS_SECRET_ACCESS_KEY": "environment-cloud-secret",
        }
        cases = (
            ("file-precedence", True, True, True, True, "file-project-token"),
            ("file-only", True, True, False, True, "file-project-token"),
            ("explicit-environment", True, False, True, True, "environment-project-token"),
            ("ambient-not-selected", True, False, False, True, None),
            ("missing-in-explicit-environment", True, False, True, False, None),
            ("policy-disabled", False, True, True, True, None),
        )
        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary).resolve()
            value = android_config()
            value["projectChecks"]["preflight"] = [["verify-private-dependency"]]
            value["projectChecks"]["androidArtifact"] = [["verify-artifact"]]
            config = load_config(write_project(private_root / "app", value))
            credential_file = private_root / "mobile-release.env"
            credential_file.write_text(
                f"{token_name}=file-project-token\n"
                "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64=file-store-key\n"
                "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD=file-signing-password\n",
                encoding="utf-8",
            )
            credential_file.chmod(0o600)
            invalid_aab = config.root / "synthetic-invalid.aab"
            for label, required, use_file, from_env, has_ambient_token, expected_token in cases:
                with self.subTest(case=label):
                    config.data["source"]["projectReadTokenRequired"] = required
                    environment = {**scrub_credential_capabilities(os.environ), **capabilities}
                    if not has_ambient_token:
                        environment.pop(token_name)
                    calls, guards = [], []

                    def check_environment(environ, expected):
                        self.assertEqual({name: environ[name] for name in capabilities if name in environ},
                                         {token_name: expected} if expected else {})

                    def check_guard(cancellation):
                        self.assertIsNotNone(cancellation)
                        cancellation.check()
                        if guards:
                            self.assertIs(cancellation, guards[0])
                        guards.append(cancellation)

                    def native(command, *, environ, cancellation, execution_scope, **_kwargs):
                        check_guard(cancellation)
                        self.assertIsNone(execution_scope)
                        if command == ["verify-private-dependency"]:
                            calls.append("preflight")
                            check_environment(environ, expected_token)
                            output = ""
                        elif command == ["verify-artifact"]:
                            calls.append("artifact")
                            check_environment(environ, None)
                            self.assertEqual(environ["MOBILE_RELEASE_AAB_PATH"], str(invalid_aab))
                            output = ""
                        else:
                            self.assertIn("--init-script", command)
                            calls.append("identity")
                            check_environment(environ, expected_token)
                            check_environment(os.environ, expected_token)
                            output = "MOBILE_RELEASE_EFFECTIVE_ANDROID_ID|demoDebug|com.example.reader.debug\n"
                        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

                    def build(selected_config, *, signed, cancellation, execution_source, build_inputs):
                        self.assertIs(selected_config, config)
                        self.assertFalse(signed)
                        self.assertIsNone(execution_source)
                        self.assertIsNone(build_inputs)
                        check_guard(cancellation)
                        check_environment(os.environ, expected_token)
                        calls.append("build")
                        invalid_aab.write_bytes(b"synthetic unvalidated build output, not an AAB")
                        return {"android-aab": invalid_aab}

                    with (
                        patch.dict(os.environ, environment, clear=True),
                        patch("mobile_release.discovery.run_owned", return_value=subprocess.CompletedProcess([], 1, "", "")),
                        patch("mobile_release.preflight.run_owned", side_effect=native),
                        patch("mobile_release.preflight.run_android_build", side_effect=build) as builder,
                        patch("mobile_release.android.run_owned", side_effect=AssertionError("invalid artifact reached native tools")),
                        patch.object(subprocess, "Popen", side_effect=AssertionError("unexpected native process")),
                    ):
                        original = dict(os.environ)
                        report = preflight(config, mode="offline", platforms=("android",), run_builds=True,
                                           credentials_file=credential_file if use_file else None,
                                           credentials_from_env=from_env)
                        self.assertEqual(dict(os.environ), original)
                    blocked = required and expected_token is None
                    self.assertEqual(calls, ["preflight"] if blocked else ["preflight", "identity", "build", "artifact"])
                    self.assertEqual(builder.call_count, 0 if blocked else 1)
                    self.assertEqual([(item.code, item.status) for item in report.findings if item.status in FAILING_STATUSES],
                                     [("build.project-read-token", Status.MISSING)] if blocked
                                     else [("android.aab.structure", Status.FAIL)])
                    if not blocked:
                        identity = next(item for item in report.findings if item.code == "android.debug-identity.effective")
                        self.assertEqual(identity.status, Status.PASS)
                    self.assertTrue(guards)
                    self.assertEqual(guards[0].handler_state, "RESTORED")

    def test_buildful_preflight_dependency_query_failure_or_cancellation_restores_environment(self) -> None:
        # Hosted-only: exercise the original environment frame and cancellation cleanup.
        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary).resolve()
            value = android_config()
            value["source"]["projectReadTokenRequired"] = True
            config = load_config(write_project(private_root / "app", value))
            credential_file = private_root / "mobile-release.env"
            credential_file.write_text("MOBILE_RELEASE_PROJECT_READ_TOKEN=selected-project-token\n", encoding="utf-8")
            credential_file.chmod(0o600)
            for outcome in ("failed-query", "cancelled-query"):
                with self.subTest(outcome=outcome):
                    guards = []

                    def native(command, *, environ, cancellation, **_kwargs):
                        self.assertIn("--init-script", command)
                        self.assertEqual(environ["MOBILE_RELEASE_PROJECT_READ_TOKEN"], "selected-project-token")
                        self.assertEqual(os.environ["MOBILE_RELEASE_PROJECT_READ_TOKEN"], "selected-project-token")
                        self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_TOKEN", environ)
                        guards.append(cancellation)
                        if outcome == "cancelled-query":
                            cancellation.cancelled = True
                            cancellation.check()
                            self.fail("cancelled identity query continued")
                        return subprocess.CompletedProcess(command, 7, "", "")

                    with (
                        patch.dict(os.environ, {"MOBILE_RELEASE_PROJECT_READ_TOKEN": "original-ambient-token",
                                                "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "original-ambient-oidc"}),
                        patch("mobile_release.discovery.run_owned", return_value=subprocess.CompletedProcess([], 1, "", "")),
                        patch("mobile_release.preflight.run_owned", side_effect=native) as query,
                        patch("mobile_release.preflight.run_android_build") as build,
                        patch("mobile_release.preflight.validate_aab") as validation,
                        patch.object(subprocess, "Popen", side_effect=AssertionError("unexpected native process")),
                    ):
                        original = dict(os.environ)
                        arguments = dict(mode="offline", platforms=("android",), run_builds=True,
                                         credentials_file=credential_file)
                        if outcome == "cancelled-query":
                            with self.assertRaises(KeyboardInterrupt):
                                preflight(config, **arguments)
                        else:
                            report = preflight(config, **arguments)
                            identity = next(item for item in report.findings if item.code == "android.debug-identity.effective")
                            self.assertEqual(identity.status, Status.BLOCKED)
                        self.assertEqual(dict(os.environ), original)
                        query.assert_called_once()
                        build.assert_not_called()
                        validation.assert_not_called()
                    self.assertEqual(len(guards), 1)
                    self.assertEqual(guards[0].handler_state, "RESTORED")

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
            root = Path(temporary) / "application"
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
            credential_file = Path(temporary) / "candidate.env"
            original_p8 = Path(temporary) / "selected.p8"
            original_p8.write_bytes(b"synthetic-selected-p8")
            original_p8.chmod(0o600)
            credential_file.write_text("MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_PATH=" +
                str(original_p8) + "\n", encoding="utf-8")
            credential_file.chmod(0o600)
            routed = Finding("store.online.ios", Status.NOT_APPLICABLE,
                             "Synthetic adapter routing, not a successful Store readback.")
            selected_guards = []
            def validate_selected_p8(selected_path, *, execution_source=None, cancellation=None):
                self.assertNotEqual(selected_path(), original_p8)
                self.assertEqual(selected_path().read_bytes(), b"synthetic-selected-p8")
                cancellation.check()
                selected_guards.append(cancellation)
                original_p8.write_bytes(b"intervening-external-p8-edit")
                original_p8.unlink()
                return Finding("credential-material.apple-p8", Status.PASS,
                               "Synthetic native-validator boundary only.")
            def online_without_app_credentials(*, config, release, platforms, material, invocation) -> list[Finding]:
                material.require(config=config, platforms=platforms, invocation=invocation)
                self.assertEqual(selected_guards, [invocation.cancellation])
                self.assertFalse(original_p8.exists())
                self.assertEqual(base64.b64decode(material.lane_environment(platform="ios")[
                    "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"]), b"synthetic-selected-p8")
                self.assertEqual(base64.b64decode(os.environ["MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64"]),
                                 b"synthetic-selected-p8")
                self.assertNotIn("GOOGLE_APPLICATION_CREDENTIALS", os.environ)
                self.assertNotIn("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", os.environ)
                self.assertNotIn("GOOGLE_GHA_CREDS_PATH", os.environ)
                return [routed]

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
                "mobile_release.credentials._validate_selected_p8", side_effect=validate_selected_p8
            ), patch(
                "mobile_release.preflight.online_preflight_findings",
                side_effect=online_without_app_credentials,
            ) as online, patch("mobile_release.preflight.run_project_checks") as project_checks:
                report = preflight(
                    config,
                    mode="online",
                    platforms=("ios",),
                    run_builds=False,
                    credentials_file=credential_file,
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
                        "ruby", "-I", str(repository / "fastlane"), "-e",
                        "require 'release_support'; puts MobileReleaseKit.safe_path(ARGV[0], ARGV[1], must_exist: false)",
                        str(root), str(report_relative),
                    ],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                )
                self.assertEqual(ruby.returncode, 0, ruby.stderr)
                self.assertEqual(Path(ruby.stdout.strip()).resolve(), (root / report_relative).resolve())
            captured = {}

            def failed_lane(argv, **kwargs):
                path = Path(kwargs["environ"]["MOBILE_RELEASE_PREFLIGHT_READBACK_PATH"])
                self.assertEqual(path, root / report_relative)
                path.relative_to(root)
                self.assertIs(kwargs["cancellation"], invocation.cancellation)
                self.assertIsNone(kwargs["_evidence"])
                captured.update(path=path, cwd=Path(kwargs["cwd"]))
                # A caller-owned failure output is preserved, never stale-cleared
                # or adopted for scratch deletion after the failed native call.
                with path.open("xb") as output:
                    output.write(b"synthetic-partial-output")
                path.chmod(0o600)
                return subprocess.CompletedProcess(argv, 1)

            with patch.dict(os.environ, {"MOBILE_RELEASE_PREFLIGHT_READBACK_PATH": str(report_relative)}, clear=True), patch(
                    "mobile_release.stores.resolve_tooling_root", return_value=repository), patch(
                    "mobile_release.stores._require_fastlane_bundle"), patch(
                    "mobile_release.stores.run_owned", side_effect=failed_lane), patch(
                    "mobile_release.stores.read_readback_bytes") as readback, self._online_material(config) as (
                    invocation, material):
                findings = online_preflight_findings(config=config, release=config.release_version(),
                    platforms=("android",), invocation=invocation, material=material)
            self.assertEqual(findings[-1].status, Status.FAIL)
            readback.assert_not_called()
            self.assertEqual(captured["path"].read_bytes(), b"synthetic-partial-output")
            self.assertNotEqual(captured["cwd"], root)
            self.assertFalse(captured["cwd"].exists())

    def test_online_readback_override_refuses_occupied_names_and_multiple_platforms_before_native_work(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = android_config()
            value["ios"] = ios_config()["ios"]
            config = load_config(write_project(root, value))
            for kind in ("file", "dangling", "multiple-platforms"):
                relative = Path(".mobile-release/store") / (kind + ".json")
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                if kind == "file":
                    path.write_bytes(b"foreign-existing-output")
                elif kind == "dangling":
                    path.symlink_to(root / "absent-original-target")
                before = path.lstat() if os.path.lexists(path) else None
                platforms = ("android", "ios") if kind == "multiple-platforms" else ("android",)
                with self.subTest(kind=kind), patch.dict(os.environ, {
                        "MOBILE_RELEASE_PREFLIGHT_READBACK_PATH": str(relative)}, clear=True), self._online_material(
                        config, platforms=platforms) as (invocation, material), patch(
                        "mobile_release.stores.resolve_tooling_root") as tooling, patch(
                        "mobile_release.stores._require_fastlane_bundle") as bundle, patch(
                        "mobile_release.stores.run_owned") as run:
                    with self.assertRaises(StoreOperationError) as caught:
                        online_preflight_findings(config=config, release=config.release_version(),
                            platforms=platforms, invocation=invocation, material=material)
                    if kind == "multiple-platforms":
                        self.assertIn("exactly one platform", str(caught.exception))
                    tooling.assert_not_called()
                    bundle.assert_not_called()
                    run.assert_not_called()
                if before is None:
                    self.assertFalse(os.path.lexists(path))
                else:
                    self.assertEqual((path.lstat().st_ino, path.lstat().st_mode), (before.st_ino, before.st_mode))
                    self.assertEqual(path.read_bytes() if kind == "file" else os.readlink(path),
                                     b"foreign-existing-output" if kind == "file" else str(root / "absent-original-target"))

    def test_online_readback_default_requires_actual_writer_and_stops_other_platforms(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = android_config()
            value["ios"] = ios_config()["ios"]
            config = load_config(write_project(root, value))
            calls, outputs = [], []

            def unbound_success(argv, **kwargs):
                calls.append(tuple(argv))
                self.assertIsNotNone(kwargs["_evidence"])
                path = Path(kwargs["environ"]["MOBILE_RELEASE_PREFLIGHT_READBACK_PATH"])
                with path.open("xb") as output:
                    output.write(b'{"untrusted":"no original writer receipt"}')
                path.chmod(0o600)
                outputs.append(path)
                # Deliberately not an actual command outcome: no sidecar/private
                # outcome fields are patched or manufactured by this fixture.
                return subprocess.CompletedProcess(argv, 0)

            with patch.dict(os.environ, {}, clear=True), patch("mobile_release.stores.resolve_tooling_root",
                    return_value=Path(__file__).resolve().parents[2]), patch(
                    "mobile_release.stores._require_fastlane_bundle"), patch(
                    "mobile_release.stores.run_owned", side_effect=unbound_success), self.assertRaises(ProcessError):
                with self._online_material(config, platforms=("android", "ios")) as (invocation, material):
                    online_preflight_findings(config=config, release=config.release_version(),
                        platforms=("android", "ios"), invocation=invocation, material=material)
            self.assertEqual(len(calls), 1, "unconfirmed first writer allowed another platform")
            self.assertEqual(len(outputs), 1)
            self.assertTrue(invocation.cancellation.lifetime_ledger.fatal)
            self.assertEqual(outputs[0].read_bytes(), b'{"untrusted":"no original writer receipt"}')
            # TemporaryDirectory owns the entire synthetic fixture, including
            # the correctly retained unknown output; no user output is removed.

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
                    "mobile_release.preflight._selected_store_material"
                ) as selection, patch(
                    "mobile_release.preflight.online_preflight_findings"
                ) as online:
                    report = preflight(
                        config,
                        mode="online",
                        platforms=("ios",),
                        run_builds=False,
                    )
                online.assert_not_called()
                selection.assert_not_called()
                gate = next(item for item in report.findings if item.code == "store.online.gate")
                self.assertEqual(gate.status, Status.SKIP)


if __name__ == "__main__":
    unittest.main()
