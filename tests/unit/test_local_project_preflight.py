"""Local/release policy tests with inert seam responses only; no actual commands.

The real shared doctor/check traversal runs, but filesystem/discovery/version and
process boundaries are patched. These establish policy, not native containment.
"""
from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
import copy
import os
import subprocess
import unittest
from unittest.mock import Mock, patch

from mobile_release import cli, preflight
from mobile_release.config import ConfigurationError, ReleaseConfig, default_config_data
from mobile_release.errors import ValidationError
from mobile_release.reporting import Status


def configuration():
    data = default_config_data({"android": {"applicationId": "org.inert.app"}})
    data["android"]["module"] = ":app"
    data["projectChecks"]["preflight"] = [["inert-project-check"]]
    return ReleaseConfig(Path("/inert/project/release/mobile-release.json"), Path("/inert/project"), data)


def invocation():
    return SimpleNamespace(cancellation=None, signing_lease=None, require=Mock())


def seams(stack: ExitStack, *, returncode=0):
    stack.enter_context(patch.object(preflight, "discover_project", return_value={"git": {}, "android": {"module": ":app"}}))
    stack.enter_context(patch.object(ReleaseConfig, "release_version", return_value=SimpleNamespace(name="1.2.3", build=7)))
    stack.enter_context(patch.object(Path, "is_file", return_value=True))
    stack.enter_context(patch.object(Path, "read_text", return_value="/.mobile-release/\n"))
    return stack.enter_context(patch.object(preflight, "run_owned", return_value=subprocess.CompletedProcess([], returncode)))


class LocalProjectPreflightTests(unittest.TestCase):
    def test_local_runs_actual_shared_checks_without_store_or_credentials(self):
        for returncode in (0, 1):
            with self.subTest(returncode=returncode), ExitStack() as stack:
                config, owner = configuration(), invocation()
                command = seams(stack, returncode=returncode)
                for name in ("metadata_findings", "resolve_credential_values", "credential_values_for_purpose", "run_android_build",
                             "run_ios_build", "validate_signing_material", "online_preflight_findings", "validate_aab"):
                    stack.enter_context(patch.object(preflight, name, side_effect=AssertionError("later-stage capability")))
                stack.enter_context(patch.dict(os.environ, {"MOBILE_RELEASE_PROJECT_READ_TOKEN": "INERT_NOT_REAL", "MOBILE_RELEASE_BUILD_NUMBER": "999"}, clear=True))
                result = preflight._preflight(config, mode="offline", platforms=("android",), run_builds=False,
                    scope="local-project", invocation=owner)
                self.assertEqual(result.ok, returncode == 0)
                self.assertEqual(result.context["validationScope"], "local-project")
                command.assert_called_once()
                self.assertEqual(command.call_args.args, (["inert-project-check"],))
                environment = command.call_args.kwargs["environ"]
                self.assertNotIn("MOBILE_RELEASE_PROJECT_READ_TOKEN", environment)
                self.assertEqual(environment["MOBILE_RELEASE_VERSION_NAME"], "1.2.3")
                self.assertEqual(environment["MOBILE_RELEASE_BUILD_NUMBER"], "7")
                self.assertTrue(owner.require.called)
                codes = {finding.code for finding in result.findings}
                self.assertTrue({"version.source", "android.module", "android.gradle-wrapper", "workspace.private-output", "project-check.preflight.0"} <= codes)
                self.assertFalse(any(code.startswith("metadata.") for code in codes))

    def test_default_release_still_blocks_unverified_store_identity(self):
        with ExitStack() as stack:
            command = seams(stack)
            metadata = stack.enter_context(patch.object(preflight, "metadata_findings", return_value=[]))
            stack.enter_context(patch.object(preflight, "resolve_credential_values", side_effect=AssertionError("past failed initial policy")))
            result = preflight._preflight(configuration(), mode="offline", platforms=("android",), run_builds=False, invocation=invocation())
            self.assertFalse(result.ok)
            self.assertTrue(any(f.code == "android.identity-status" and f.status in {Status.FAIL, Status.BLOCKED} for f in result.findings))
            command.assert_not_called()
            metadata.assert_called_once()
            self.assertNotIn("validationScope", result.context)

    def test_local_missing_version_module_wrapper_and_gitignore_still_block(self):
        for fault in ("version", "module", "wrapper", "gitignore"):
            with self.subTest(fault=fault), ExitStack() as stack:
                config = configuration()
                command = seams(stack)
                if fault == "version":
                    stack.enter_context(patch.object(ReleaseConfig, "release_version", side_effect=ConfigurationError("inert missing version")))
                elif fault == "module":
                    config.data["android"].pop("module")
                    stack.enter_context(patch.object(preflight, "discover_project", return_value={"git": {}, "android": {}}))
                elif fault == "wrapper":
                    stack.enter_context(patch.object(Path, "is_file", side_effect=lambda: False))
                else:
                    stack.enter_context(patch.object(Path, "read_text", return_value=""))
                stack.enter_context(patch.object(preflight, "metadata_findings", side_effect=AssertionError("local metadata")))
                result = preflight._preflight(config, mode="offline", platforms=("android",), run_builds=False,
                    scope="local-project", invocation=invocation())
                self.assertFalse(result.ok)
                command.assert_not_called()

    def test_closed_scope_refuses_before_discovery_or_invocation_and_preserves_schema(self):
        base = dict(mode="offline", platforms=("android",), run_builds=False, scope="local-project")
        bad = [{"scope": None}, {"scope": {}}, {"scope": "local"}, {"platforms": ("ios",)}, {"mode": "signing"},
               {"run_builds": True}, {"artifacts": {}}, {"credentials_file": Path("/inert/never-read")},
               {"credentials_from_env": True}, {"require_tools": True}]
        with patch.object(preflight, "invocation_custody", side_effect=AssertionError("scope must precede ownership")), \
             patch.object(preflight, "discover_project", side_effect=AssertionError("scope must precede discovery")):
            for invalid in bad:
                with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                    preflight.preflight(configuration(), **{**base, **invalid})
        for patch_value in ({"applicationId": "invalid"}, {"externalTrack": {"name": "alpha", "kind": "invalid"}}):
            config = configuration()
            config.data["android"].update(patch_value)
            with patch.object(preflight, "discover_project", side_effect=AssertionError("bad schema before discovery")), \
                 patch.object(ReleaseConfig, "release_version", side_effect=AssertionError("bad schema before reads")), \
                 self.assertRaises(ConfigurationError):
                preflight.doctor(config, ("android",), scope="local-project")

    def test_legacy_cli_explicit_optin_normalizes_only_absent_artifacts(self):
        parser = cli.build_parser()
        args = parser.parse_args(["preflight", "--config", "/inert/config", "--offline", "--platform", "android", "--skip-builds", "--local-project-checks"])
        with patch.object(cli, "load_config", return_value=configuration()), patch.object(cli, "preflight", return_value=object()) as call, \
             patch.object(cli, "_emit", return_value=0):
            self.assertEqual(cli._preflight(args), 0)
            self.assertEqual(call.call_args.kwargs["scope"], "local-project")
            self.assertIsNone(call.call_args.kwargs["artifacts"])
            self.assertEqual(call.call_args.kwargs["platforms"], ("android",))
            normal = copy.copy(args)
            normal.local_project_checks = False
            cli._preflight(normal)
            self.assertEqual(call.call_args.kwargs["scope"], "release")
            self.assertEqual(call.call_args.kwargs["artifacts"], {})
        for field, value in (("artifact", ["invalid-supplied"]), ("offline", False), ("run_builds", True), ("credentials_from_env", True)):
            changed = copy.copy(args)
            setattr(changed, field, value)
            with patch.object(cli, "load_config", side_effect=AssertionError("refusal before file read")), self.assertRaises(ValidationError):
                cli._preflight(changed)


if __name__ == "__main__":
    unittest.main()
