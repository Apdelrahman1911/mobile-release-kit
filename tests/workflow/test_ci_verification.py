"""Focused CI contracts; native isolation is verified separately on hosted VMs.

Shell tests first require the fixed reviewed command body, then replace its
external entry points with inert functions. They never invoke sudo, a package
installer, the controller, a sandbox, or a product process.
"""
from __future__ import annotations

import base64
import contextlib
import csv
import dataclasses
import functools
import importlib.util
import hashlib
import io
import json
import os
import subprocess
import stat
import sys
import tempfile
import time
import tomllib
import unittest
import warnings
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from .workflow_harness import load_workflow, simulate_steps


ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github/workflows/ci.yml"
HOSTED_GUARD = '''set -euo pipefail
[[ "$MOBILE_RELEASE_RUNNER_ENVIRONMENT" == github-hosted ]]
'''
LINUX_TOOL_SETUP = '''set -euo pipefail
if [[ ! -x /usr/bin/bwrap ]]; then
  sudo -n env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \\
    DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get update
  sudo -n env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \\
    DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get install \\
    --yes --no-install-recommends bubblewrap
fi
[[ -x /usr/bin/bwrap && -x /usr/bin/setpriv ]]
'''


@functools.lru_cache(maxsize=2)
def ci_module(name: str):
    """Load inert helper definitions, never an adapter or product entry point."""
    if name not in {"verify_ci", "ci_checks"}:
        raise ValueError("unsupported pure helper")
    spec = importlib.util.spec_from_file_location(
        "_mrk_ci_contracts_" + name, ROOT / ".github/scripts" / (name + ".py"),
    )
    if spec is None or spec.loader is None:
        raise AssertionError("the required CI controller is missing")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    return module


def controller_module():
    return ci_module("verify_ci")


def fixture_paths(controller):
    # The catalog reads tracked Ruby source to count literal tests. All runtime
    # roots are synthetic; no files beneath those paths are created or opened.
    return controller.Paths(source=ROOT, work=Path("/fixture/work"), inputs=Path("/fixture/inputs"),
                            python=Path("/fixture/python/bin/python"), ruby=Path("/fixture/ruby/bin/ruby"),
                            java_home=Path("/fixture/jdk21"))


def coordinator_shell(platform: str) -> str:
    if platform not in {"linux", "macos"}:
        raise ValueError("unsupported CI platform")
    java = '--java-home "$JAVA_HOME_21_X64" ' if platform == "linux" else ""
    return '''set -euo pipefail
ruby_executable="$(command -v ruby)"
[[ "$MRK_PYTHON" == /* && "$ruby_executable" == /* ]]
sudo -n env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin PYTHONSAFEPATH=1 \\
  "$MRK_PYTHON" -I -B .github/scripts/verify_ci.py \\
  --platform PLATFORM --source "$GITHUB_WORKSPACE" \\
  --python "$MRK_PYTHON" --ruby "$ruby_executable" \\
  --runner-home "$HOME" --runner-temp "$RUNNER_TEMP" \\
  --commit "$GITHUB_SHA" --run-id "$GITHUB_RUN_ID" \\
  --run-attempt "$GITHUB_RUN_ATTEMPT" --image "$ImageOS/$ImageVersion" \\
  JAVA--summary "$GITHUB_STEP_SUMMARY"
'''.replace("PLATFORM", platform).replace("JAVA", java)


class CIWorkflowIsolationTests(unittest.TestCase):
    def test_only_hosted_preparation_and_the_fixed_controller_run_in_each_job(self):
        workflow = load_workflow(CI)
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertEqual(workflow["env"], {"PYTHONSAFEPATH": "1"})
        self.assertNotIn("defaults", workflow)
        self.assertEqual(set(workflow["jobs"]), {"test-linux", "test-native-profiles", "test"})
        text = CI.read_text(encoding="utf-8")
        self.assertNotIn("secrets.", text)
        self.assertNotIn("id-token:", text)
        for platform, name, image in (("linux", "test-linux", "ubuntu-24.04"),
                                      ("macos", "test-native-profiles", "macos-26")):
            with self.subTest(platform=platform):
                job = workflow["jobs"][name]
                self.assertEqual(job["runs-on"], image)
                self.assertEqual(job["timeout-minutes"], 60)
                for forbidden in ("if", "continue-on-error", "environment", "container", "services", "strategy", "defaults", "env"):
                    self.assertNotIn(forbidden, job)
                self.assertEqual(job.get("permissions", workflow["permissions"]), {"contents": "read"})
                steps = job["steps"]
                self.assertEqual(len(steps), 6 if platform == "linux" else 5)
                for step in steps:
                    self.assertNotIn("if", step)
                    self.assertNotIn("continue-on-error", step)
                self.assertEqual(steps[0]["run"], HOSTED_GUARD)
                self.assertEqual(set(steps[0]), {"name", "shell", "env", "run"})
                self.assertEqual(steps[0]["shell"], "bash")
                self.assertEqual(steps[0]["env"], {
                    "MOBILE_RELEASE_RUNNER_ENVIRONMENT": "${{ runner.environment }}",
                })
                self.assertEqual(steps[1]["uses"], "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1")
                self.assertEqual(set(steps[1]), {"name", "uses", "with"})
                self.assertEqual(steps[1]["with"], {"persist-credentials": False})
                self.assertEqual(steps[2]["id"], "python")
                self.assertEqual(set(steps[2]), {"name", "id", "uses", "with"})
                self.assertEqual(steps[2]["uses"], "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97")
                self.assertEqual(steps[2]["with"], {"python-version": "3.11"})
                self.assertEqual(steps[3]["uses"], "ruby/setup-ruby@95ef2b042f9d7a56d8268cba8559e2842e2ad01b")
                self.assertEqual(set(steps[3]), {"name", "uses", "with"})
                self.assertEqual(steps[3]["with"], {
                    "ruby-version": "3.3.12", "bundler": "none", "bundler-cache": False,
                })
                for step in steps[1:4]:
                    self.assertNotIn("run", step)
                    self.assertNotIn("env", step)
                if platform == "linux":
                    self.assertEqual(set(steps[4]), {"name", "shell", "run"})
                    self.assertEqual(steps[4]["shell"], "bash")
                    self.assertEqual(steps[4]["run"], LINUX_TOOL_SETUP)
                    self.assertNotIn("env", steps[4])
                owner = steps[-1]
                self.assertEqual(set(owner), {"name", "shell", "env", "run"})
                self.assertEqual(owner["env"], {"MRK_PYTHON": "${{ steps.python.outputs.python-path }}"})
                self.assertEqual(owner["shell"], "bash")
                self.assertEqual(owner["run"], coordinator_shell(platform))

    def test_actual_guard_rejects_non_hosted_or_missing_runner_identity(self):
        workflow = load_workflow(CI)
        for name in ("test-linux", "test-native-profiles"):
            body = workflow["jobs"][name]["steps"][0]["run"]
            self.assertEqual(body, HOSTED_GUARD)  # Do not execute arbitrary workflow text.
            for identity in ("github-hosted", "self-hosted", "", "GitHub-hosted", None):
                with self.subTest(job=name, identity=identity):
                    env = {"PATH": "/usr/bin:/bin"}
                    if identity is not None:
                        env["MOBILE_RELEASE_RUNNER_ENVIRONMENT"] = identity
                    result = subprocess.run(["bash", "--noprofile", "--norc", "-c", body],
                                            env=env, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode == 0, identity == "github-hosted")

    def test_coordinator_shell_passes_explicit_bindings_and_preserves_real_exit_status(self):
        fixture = '''command() {
  [[ "$#" == 2 && "$1" == -v && "$2" == ruby ]] || return 99
  printf '%s\\n' "$FIXTURE_RUBY"
}
sudo() {
  printf '%s\\0' "$@"
  return "$FIXTURE_STATUS"
}
'''
        env = {
            "PATH": "/usr/bin:/bin", "MRK_PYTHON": "/fixture/python/bin/python",
            "FIXTURE_RUBY": "/fixture/ruby/bin/ruby", "GITHUB_WORKSPACE": "/fixture/source with spaces",
            "HOME": "/fixture/runner home", "RUNNER_TEMP": "/fixture/runner temp",
            "GITHUB_SHA": "1" * 40, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2",
            "ImageOS": "fixture-image", "ImageVersion": "20260909.1",
            "JAVA_HOME_21_X64": "/fixture/jdk21", "GITHUB_STEP_SUMMARY": "/fixture/private summary",
        }
        workflow = load_workflow(CI)
        for platform, job in (("linux", "test-linux"), ("macos", "test-native-profiles")):
            body = workflow["jobs"][job]["steps"][-1]["run"]
            self.assertEqual(body, coordinator_shell(platform))  # Only the inert, fixed shell may run.
            expected = [
                "-n", "env", "-i", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "PYTHONSAFEPATH=1",
                env["MRK_PYTHON"], "-I", "-B", ".github/scripts/verify_ci.py", "--platform", platform,
                "--source", env["GITHUB_WORKSPACE"], "--python", env["MRK_PYTHON"], "--ruby", env["FIXTURE_RUBY"],
                "--runner-home", env["HOME"], "--runner-temp", env["RUNNER_TEMP"],
                "--commit", env["GITHUB_SHA"], "--run-id", env["GITHUB_RUN_ID"],
                "--run-attempt", env["GITHUB_RUN_ATTEMPT"], "--image", "fixture-image/20260909.1",
            ]
            if platform == "linux":
                expected += ["--java-home", env["JAVA_HOME_21_X64"]]
            expected += ["--summary", env["GITHUB_STEP_SUMMARY"]]
            for status in (0, 1, 125):
                with self.subTest(platform=platform, status=status):
                    result = subprocess.run(["bash", "--noprofile", "--norc", "-c", fixture + body],
                                            env={**env, "FIXTURE_STATUS": str(status)},
                                            capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertEqual(result.stdout.decode().split("\0"), [*expected, ""])
            for key in ("MRK_PYTHON", "FIXTURE_RUBY"):
                with self.subTest(platform=platform, relative_runtime=key):
                    result = subprocess.run(["bash", "--noprofile", "--norc", "-c", fixture + body],
                                            env={**env, "FIXTURE_STATUS": "0", key: "relative-runtime"},
                                            capture_output=True, timeout=5)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")

    def test_failed_or_cancelled_setup_cannot_reach_the_controller(self):
        workflow = load_workflow(CI)
        for name in ("test-linux", "test-native-profiles"):
            job = workflow["jobs"][name]
            owner = job["steps"][-1]
            for failed in job["steps"][:-1]:
                for mode in ("fail", "cancel"):
                    with self.subTest(job=name, step=failed["name"], mode=mode):
                        executed, _ = simulate_steps(job, mode="ci", **{mode: failed["name"]})
                        self.assertNotIn(owner, executed)
            executed, _ = simulate_steps(job, mode="ci")
            self.assertEqual(executed, job["steps"])


class CIControllerContractTests(unittest.TestCase):
    def test_complete_fixed_gate_inventory_cannot_omit_duplicate_or_reorder_a_step(self):
        controller = controller_module()
        before = ("source-copy", "source-environment", "source-dependencies", "bundler", "bundle-install",
                  "editable-install", "source-freeze", "source-pip-check", "bundle-check")
        ruby = ("ruby-support", "ruby-native-capture", "ruby-native-signal-observation",
                "ruby-play_store", "ruby-play_lanes", "ruby-apple_store",
                "ruby-apple_lanes", "ruby-apple_production", "ruby-apple_production_lane", "ruby-apple_asset_upload",
                "ruby-ios_upload_validation", "ruby-android_upload_validation", "ruby-workflow-yaml", "ruby-supply-wif")
        wheel = ("wheel-copy", "wheel-build", "wheel-inspect", "wheel-environment", "wheel-pip", "wheel-install",
                 "wheel-freeze", "wheel-pip-check", "wheel-smoke", "wheel-consumer")
        expected = {
            "linux": (*before, "python-full", *ruby, "fastfile", "actionlint", "jdk-signers", *wheel,
                      "python-wheel", "source-integrity"),
            "macos": (*before, "native-tools", "native-profile-source", "ruby-native-capture",
                      "ruby-native-signal-observation",
                      "ruby-ios_upload_validation", "ruby-android_upload_validation", *wheel,
                      "native-profile-wheel", "source-integrity"),
        }
        for platform in expected:
            steps = controller.catalog(fixture_paths(controller), platform, deadline=1000.0)
            with self.subTest(platform=platform):
                self.assertEqual(tuple(step.id for step in steps), expected[platform])
                self.assertEqual(controller.required_gate_ids(platform), expected[platform])
            altered = [(), steps[:-1], (*steps, steps[-1]), (steps[1], steps[0], *steps[2:]),
                       (dataclasses.replace(steps[0], id="unknown-gate"), *steps[1:])]
            altered.extend((*steps[:index], *steps[index + 1:]) for index in range(len(steps)))
            for invalid in altered:
                with self.subTest(platform=platform, ids=[step.id for step in invalid]):
                    seen = []
                    with self.assertRaisesRegex(controller.VerificationError, "REQUIRED_GATE_INVENTORY"):
                        controller.execute_pipeline(invalid, lambda step: seen.append(step.id), platform=platform)
                    self.assertEqual(seen, [])
        with self.assertRaisesRegex(controller.VerificationError, "UNSUPPORTED_PLATFORM"):
            controller.required_gate_ids("windows")

    def test_every_early_or_final_failure_is_latched_and_later_gates_are_unexecuted(self):
        controller = controller_module()
        for platform in ("linux", "macos"):
            steps = controller.catalog(fixture_paths(controller), platform, deadline=1000.0)
            ids = [step.id for step in steps]
            for failed in (None, *ids):
                for raised in (False, True):
                    with self.subTest(platform=platform, failed=failed, raised=raised):
                        seen = []

                        def perform(step):
                            seen.append(step.id)
                            if step.id == failed:
                                if raised:
                                    raise OSError("synthetic failure after success-shaped output")
                                return controller.CheckResult(False, {"ok": True, "status": "PASS"}, "FIXTURE_FAILURE")
                            return controller.CheckResult(True, {"fixture": True})

                        report = controller.execute_pipeline(steps, perform, platform=platform)
                        index = len(steps) if failed is None else ids.index(failed)
                        self.assertIs(report.ok, failed is None)
                        self.assertEqual(seen, ids if failed is None else ids[:index + 1])
                        self.assertEqual([row["id"] for row in report.rows], ids)
                        statuses = ["PASS"] * index
                        if failed is not None:
                            statuses += ["FAIL", *(["UNEXECUTED"] * (len(steps) - index - 1))]
                            self.assertEqual(report.error, "CHECK_EXECUTION_FAILED" if raised else "FIXTURE_FAILURE")
                        else:
                            self.assertIsNone(report.error)
                        self.assertEqual([row["status"] for row in report.rows], statuses)

    def test_non_contract_results_and_cancellation_are_not_success(self):
        controller = controller_module()
        steps = controller.catalog(fixture_paths(controller), "linux", deadline=1000.0)
        for value in (None, True, {"ok": True}, SimpleNamespace(ok=True), controller.CheckResult(1)):
            with self.subTest(result_type=type(value).__name__):
                seen = []

                def perform(step):
                    seen.append(step.id)
                    return value

                report = controller.execute_pipeline(steps, perform, platform="linux")
                self.assertFalse(report.ok)
                self.assertEqual(report.error, "INVALID_CHECK_RESULT")
                self.assertEqual(seen, [steps[0].id])
                self.assertTrue(all(row["status"] == "UNEXECUTED" for row in report.rows[1:]))

        def cancelled(_step):
            raise KeyboardInterrupt("synthetic cancellation")

        report = controller.execute_pipeline(steps, cancelled, platform="linux")
        self.assertFalse(report.ok)
        self.assertTrue(all(row["status"] == "UNEXECUTED" for row in report.rows[1:]))

    def test_environment_is_constructed_without_ambient_credentials_configuration_or_hooks(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        forbidden = {"GITHUB_TOKEN", "GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY", "PYTHONPATH", "PYTHONHOME",
                     "RUBYOPT", "RUBYLIB", "BASH_ENV", "ENV", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "HTTPS_PROXY",
                     "SSH_AUTH_SOCK", "AWS_ACCESS_KEY_ID", "GOOGLE_APPLICATION_CREDENTIALS", "BUNDLE_WITHOUT"}
        for platform in ("linux", "macos"):
            with patch.dict(os.environ, {key: "AMBIENT_FIXTURE" for key in forbidden}):
                env = dict(controller.environment(paths, platform))
            with self.subTest(platform=platform):
                self.assertTrue(forbidden.isdisjoint(env))
                self.assertEqual(env["HOME"], "/fixture/work/home")
                self.assertEqual(env["PIP_CONFIG_FILE"], "/dev/null")
                self.assertEqual(env["PIP_NO_INDEX"], "1")
                self.assertEqual(env["BUNDLE_IGNORE_CONFIG"], "1")
                self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")
                self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")
                self.assertEqual(env["MOBILE_RELEASE_REQUIRE_RUBY_CONTRACTS"], "1")
                self.assertEqual(env["FASTLANE_SKIP_UPDATE_CHECK"], "true")
                self.assertEqual(env["PYTHONSAFEPATH"], "1")
                self.assertNotIn("", env["PATH"].split(os.pathsep))
                self.assertTrue(all(Path(part).is_absolute() for part in env["PATH"].split(os.pathsep)))
                if platform == "macos":
                    self.assertEqual(env["DEVELOPER_DIR"], "/Applications/Xcode_26.3.app/Contents/Developer")

    def test_one_original_deadline_and_headroom_limit_are_not_renewed(self):
        controller = controller_module()
        self.assertEqual(controller.AGGREGATE_SECONDS, 3300)
        for platform in ("linux", "macos"):
            for step in controller.catalog(fixture_paths(controller), platform, deadline=4321.5):
                if "--deadline" in step.argv:
                    self.assertEqual(step.argv[step.argv.index("--deadline") + 1], "4321.5")
            for invalid in (float("nan"), float("inf"), -float("inf"), "4321.5", True):
                with self.assertRaisesRegex(controller.VerificationError, "INVALID_DEADLINE"):
                    controller.catalog(fixture_paths(controller), platform, deadline=invalid)
        with patch.object(controller.time, "monotonic", return_value=4321.499):
            controller.check_clock(4321.5)
        for now in (4321.5, 4322.0):
            with patch.object(controller.time, "monotonic", return_value=now):
                with self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                    controller.check_clock(4321.5)
        self.assertEqual(controller.DISK_RESERVE, 4 * 1024**3 + 512 * 1024**2)
        for free, prospective, accepted in ((controller.DISK_RESERVE, 0, True),
                                            (controller.DISK_RESERVE, 1, False),
                                            (controller.DISK_RESERVE - 1, 0, False)):
            with patch.object(controller.shutil, "disk_usage", return_value=SimpleNamespace(free=free)):
                if accepted:
                    controller.check_capacity(Path("/fixture/work"), prospective)
                else:
                    with self.assertRaisesRegex(controller.VerificationError, "DISK_HEADROOM"):
                        controller.check_capacity(Path("/fixture/work"), prospective)

    def test_native_text_parser_normalizes_real_method_identity_and_rejects_incomplete_output(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        expected = ("unit.synthetic.NativeContracts.test_native",)

        def identities(source, selection, **_kwargs):
            self.assertEqual(source, ROOT)
            self.assertEqual(selection, "native")
            return expected

        checks = SimpleNamespace(expected_python_ids=identities)
        step = controller.Step("native-profile-source", parser="native")
        footer = "\nRan 1 test in 0.01s\n\nOK\n"
        full = "test_native (unit.synthetic.NativeContracts.test_native) ... ok\n"
        legacy = "test_native (unit.synthetic.NativeContracts) ... ok\n"

        def capture(text, **changes):
            values = dict(ok=True, returncode=0, waited=True, stdout_eof=True, stderr_eof=True,
                          domain_finality=True, primary_error=None, cleanup_errors=(), stdout=b"",
                          stderr=text.encode("ascii"), duration=0.01)
            return SimpleNamespace(**{**values, **changes})

        for line in (full, legacy):
            self.assertTrue(controller.parse_capture(step, capture(line + footer), paths, "macos", checks).ok)
        for text in (footer, full + full + footer, full + footer + footer,
                     full.replace("... ok", "... skipped 'fixture'") + footer,
                     full.replace("test_native)", "test_different)") + footer,
                     full + footer.replace("OK", "OK (skipped=1)")):
            with self.subTest(text=text), self.assertRaises(controller.VerificationError):
                controller.parse_capture(step, capture(text), paths, "macos", checks)
        for field, value in (("ok", False), ("returncode", 1), ("returncode", False), ("waited", False),
                             ("stdout_eof", False), ("stderr_eof", False), ("domain_finality", False),
                             ("primary_error", "FIXTURE_FAILURE"), ("cleanup_errors", ("FIXTURE_CLOSE",))):
            with self.subTest(finality_field=field), self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                controller.parse_capture(step, capture(full + footer, **{field: value}), paths, "macos", checks)


class CIProductEvidenceContractTests(unittest.TestCase):
    def test_tree_checks_incremental_count_and_byte_budget_before_later_file_reads(self):
        checks = ci_module("ci_checks")
        original_reader, original_open = checks._read_regular, os.open
        deadline = time.monotonic() + 30.0
        with tempfile.TemporaryDirectory(prefix="mrk-ci-tree-budget-") as temporary:
            root = Path(temporary)
            paths = [root / name for name in ("first", "crossing", "later")]
            for path, data in zip(paths, (b"aaaa", b"bbbb", b"c")):
                path.write_bytes(data)
            for capacity, entries_limit, accepted, expected_reads, expected_stats in (
                (9, 3, True, [("first", 9), ("crossing", 5), ("later", 1)], ["first", "crossing", "later"]),
                (6, 3, False, [("first", 6)], ["first", "crossing"]),
                (9, 1, False, [("first", 9)], ["first"]),
            ):
                with self.subTest(bytes=capacity, entries=entries_limit):
                    reads, stats = [], []

                    def entry(path):
                        def metadata(*, follow_symlinks):
                            self.assertFalse(follow_symlinks)
                            stats.append(path.name)
                            return path.lstat()
                        return SimpleNamespace(path=str(path), stat=metadata)

                    entries = [entry(path) for path in paths]

                    def reader(path, maximum, **kwargs):
                        reads.append((path.name, maximum))
                        return original_reader(path, maximum, **kwargs)

                    with patch.object(checks, "MAX_WHEEL_BYTES", capacity), patch.object(checks, "MAX_TREE_ENTRIES", entries_limit), \
                            patch.object(checks.os, "scandir", side_effect=lambda _path: contextlib.nullcontext(iter(entries))), \
                            patch.object(checks, "_read_regular", side_effect=reader), \
                            patch.object(checks.os, "open", wraps=original_open) as opened:
                        if accepted:
                            self.assertEqual(checks._tree(root, deadline=deadline),
                                             ({"first": b"aaaa", "crossing": b"bbbb", "later": b"c"}, set()))
                        else:
                            with self.assertRaisesRegex(checks.CheckError, "TREE_LIMIT"):
                                checks._tree(root, deadline=deadline)
                        self.assertEqual([Path(call.args[0]).name for call in opened.call_args_list],
                                         [name for name, _ in expected_reads])
                    self.assertEqual(reads, expected_reads)
                    self.assertEqual(stats, expected_stats)

    def test_regular_reader_closes_once_and_preserves_primary_plus_cleanup_failures(self):
        checks = ci_module("ci_checks")
        info = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o600,
                               st_nlink=1, st_size=3, st_mtime_ns=4, st_ctime_ns=5)
        for failed_at, coded, close_fails in (("read", True, True), ("read", False, True),
                                             ("stat", True, True), ("none", False, True),
                                             ("read", True, False), ("none", False, False)):
            with self.subTest(stage=failed_at, coded=coded, close_fails=close_fails):
                primary = checks.CheckError("FIXTURE_PRIMARY") if coded else OSError("synthetic read error")
                close_error = OSError("synthetic close error")
                closed, reads = [], []
                chunks = iter((b"a", b"bc"))

                def metadata(fd):
                    self.assertEqual(fd, 47)
                    if failed_at == "stat":
                        raise primary
                    return info

                def read(fd, maximum):
                    self.assertEqual(fd, 47)
                    reads.append(maximum)
                    if failed_at == "read":
                        raise primary
                    return next(chunks)

                def close(fd):
                    closed.append(fd)
                    if close_fails:
                        raise close_error

                facade = SimpleNamespace(open=lambda *_args: 47, fstat=metadata, read=read, close=close,
                                         O_RDONLY=os.O_RDONLY, O_NOFOLLOW=os.O_NOFOLLOW, O_NONBLOCK=os.O_NONBLOCK)
                with patch.object(checks, "os", facade):
                    if failed_at == "none" and not close_fails:
                        self.assertEqual(checks._read_regular(Path("/synthetic/file"), 3), b"abc")
                        self.assertEqual(reads, [3, 2])
                    else:
                        with self.assertRaises((checks.CheckError, OSError)) as caught:
                            checks._read_regular(Path("/synthetic/file"), 3)
                        error = caught.exception
                        if failed_at != "none" and coded:
                            self.assertIs(error, primary)
                            self.assertEqual(error.cleanup_errors, ["FILE_CLOSE_FAILED"] if close_fails else [])
                        elif failed_at != "none":
                            self.assertEqual(str(error), "FILE_READ_FAILED")
                            self.assertIs(error.__cause__, primary)
                            self.assertEqual(error.cleanup_errors, ["FILE_CLOSE_FAILED"])
                        else:
                            self.assertEqual(str(error), "FILE_CLOSE_FAILED")
                            self.assertIs(error.__cause__, close_error)
                self.assertEqual(closed, [47])

    def test_exact_native_skip_identities_and_all_unsuccessful_outcomes_fail_closed(self):
        checks = ci_module("ci_checks")
        families = {
            "unit.test_ios_profile_authority.NativeProfileAuthorityTests": (
                "actual_signature_integrity_and_exact_signer_are_checked_before_policy",
                "complete_two_layer_synthetic_signature_succeeds_only_with_explicit_policy_seam",
                "default_policy_rejects_even_valid_signature_with_production_looking_fake_issuer",
                "real_production_policy_accepts_apple_public_issuer_not_test_or_macos_purpose",
                "signed_outer_cannot_authorize_unsigned_or_substituted_inner_profile",
            ),
            "unit.test_macho_native.NativeMachOTests": (
                "real_dsym_and_independently_valid_different_build_pair_rejected",
                "real_fat_resigning_relocates_slices_without_changing_images",
                "real_native_der_and_nonhost_slice_entitlement_mismatch",
                "real_resigned_same_uuid_changed_code_or_linkedit_remains_different",
                "real_sdk_support_copy_unsigned_to_signed_keeps_vendor_original",
                "real_unsigned_and_signature_growth_shrink_with_residual_slack",
            ),
            "unit.test_macho_native.NativePlistTests": (
                "native_binary_invalid_markers_and_spans_are_rejected_before_conversion",
                "native_data_reference_divergence_is_rejected_not_normalized",
                "native_date_bits_and_wide_integer_semantics_are_not_rounded_into_equality",
                "native_original_numeric_reference_eight_nine_digit_boundary",
                "native_real_bits_preserve_signed_zero_width_and_finite_boundaries",
                "supported_lexical_values_match_actual_native_binary_conversion",
            ),
        }
        native = {f"{group}.test_{method}" for group, methods in families.items() for method in methods}
        self.assertEqual(checks.linux_allowed_skips(), frozenset(native))
        self.assertEqual(len(native), 17)
        ids = ("unit.fixture.Contracts.test_positive", *sorted(native))
        rows = [{"id": identifier, "outcome": "skip" if identifier in native else "ok"} for identifier in ids]
        checks.validate_test_outcomes(ids, rows, "linux")
        for platform in ("darwin", "macos"):
            checks.validate_test_outcomes(ids, [{"id": identifier, "outcome": "ok"} for identifier in ids], platform)
            with self.assertRaises(checks.CheckError):
                checks.validate_test_outcomes(ids, rows, platform)
        invalid = [rows[:-1], [*rows, rows[0]], [rows[0], rows[0], *rows[2:]],
                   [{"id": "unknown", "outcome": "ok"}, *rows[1:]],
                   [{"id": ids[0], "outcome": "ok", "optional": True}, *rows[1:]],
                   [rows[0], {"id": ids[1], "outcome": "ok"}, *rows[2:]]]
        invalid += [[{"id": ids[0], "outcome": outcome}, *rows[1:]]
                    for outcome in ("skip", "failure", "error", "expected-failure", "unexpected-success", "incomplete", "pass", True)]
        for index, altered in enumerate(invalid):
            with self.subTest(mutation=index), self.assertRaises(checks.CheckError):
                checks.validate_test_outcomes(ids, altered, "linux")

    def test_expected_wheel_test_inventory_is_static_and_rejects_omissions_and_duplicate_methods(self):
        checks = ci_module("ci_checks")
        names = ("test_init_transaction.py", "test_ios_entitlements.py", "test_ios_plist_binary.py")
        with tempfile.TemporaryDirectory(prefix="mrk-ci-ast-") as temporary:
            source = Path(temporary)
            directory = source / "tests/unit"
            directory.mkdir(parents=True)
            data = "raise RuntimeError('THIS_SOURCE_MUST_NOT_BE_IMPORTED')\nimport unittest\nclass Contracts(unittest.TestCase):\n    def test_one(self): pass\n"
            for name in names:
                (directory / name).write_text(data, encoding="utf-8")
            self.assertEqual(checks.expected_python_ids(source, "wheel"),
                             tuple(sorted(f"unit.{Path(name).stem}.Contracts.test_one" for name in names)))
            first = directory / names[0]
            first.write_text(data + "    def test_one(self): pass\n", encoding="utf-8")
            with self.assertRaisesRegex(checks.CheckError, "TEST_DUPLICATE_METHOD"):
                checks.expected_python_ids(source, "wheel")
            first.unlink()
            with self.assertRaisesRegex(checks.CheckError, "TEST_PATTERN_INVENTORY"):
                checks.expected_python_ids(source, "wheel")

    def wheel_members(self, checks):
        """Ordinary ZIP data fixture; never installed and not backend evidence."""
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        package = ROOT / "src/mobile_release"
        members = {"mobile_release/" + path.relative_to(package).as_posix(): path.read_bytes()
                   for path in package.rglob("*") if path.is_file()}
        shared = "mobile_release_kit-0.3.0.data/data/share/mobile-release-kit/"
        members.update({shared + name: (ROOT / name).read_bytes() for name in checks.TOOLING_FILES})
        dist = "mobile_release_kit-0.3.0.dist-info/"
        headers = ["Metadata-Version: 2.4", "Name: mobile-release-kit", "Version: 0.3.0",
                   "Summary: " + project["description"], "Author: Mobile Release Kit contributors",
                   "License-Expression: MIT", "License-File: LICENSE", "Requires-Python: >=3.11",
                   "Description-Content-Type: text/markdown", "Provides-Extra: test"]
        for requirement in project["optional-dependencies"]["test"]:
            headers.append("Requires-Dist: " + requirement + (' and extra == "test"' if ";" in requirement else '; extra == "test"'))
        members[dist + "METADATA"] = ("\n".join(headers) + "\n\n").encode() + (ROOT / "README.md").read_bytes()
        members[dist + "WHEEL"] = (b"Wheel-Version: 1.0\nGenerator: contract-fixture (not a build)\n"
                                    b"Root-Is-Purelib: true\nTag: py3-none-any\n\n")
        members[dist + "licenses/LICENSE"] = (ROOT / "LICENSE").read_bytes()
        members[dist + "entry_points.txt"] = b"[console_scripts]\nmobile-release = mobile_release.cli:main\n"
        members[dist + "top_level.txt"] = b"mobile_release\n"
        return members

    def write_wheel(self, path, members, *, record_edit=None, modes=None, duplicate=None):
        members = dict(members)
        record = "mobile_release_kit-0.3.0.dist-info/RECORD"
        table = io.StringIO(newline="")
        writer = csv.writer(table, lineterminator="\n")
        for name, data in sorted(members.items()):
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
            writer.writerow((name, "sha256=" + digest, str(len(data))))
        writer.writerow((record, "", ""))
        encoded = table.getvalue().encode("utf-8")
        members[record] = record_edit(encoded) if record_edit else encoded
        with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_STORED) as archive:
            for name in [*members, *([duplicate] if duplicate else [])]:
                member = zipfile.ZipInfo(name, (2000, 1, 1, 0, 0, 0))
                member.create_system = 3
                member.external_attr = (modes or {}).get(name, stat.S_IFREG | 0o644) << 16
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", message="Duplicate name:", category=UserWarning)
                    archive.writestr(member, members[name])

    def test_wheel_data_requires_complete_inventory_bytes_record_metadata_and_safe_members(self):
        checks = ci_module("ci_checks")
        original = self.wheel_members(checks)
        dist = "mobile_release_kit-0.3.0.dist-info/"
        package = "mobile_release/__init__.py"
        edits = (
            ("missing", lambda values: values.pop(package), {}, "WHEEL_COMPLETE_INVENTORY"),
            ("extra", lambda values: values.update({"extra.txt": b"fixture"}), {}, "WHEEL_COMPLETE_INVENTORY"),
            ("source-bytes", lambda values: values.update({package: b"different source bytes\n"}), {}, "WHEEL_FIRST_PARTY_BYTES"),
            ("resource-bytes", lambda values: values.update({dist + "licenses/LICENSE": b"different license\n"}), {}, "WHEEL_FIRST_PARTY_BYTES"),
            ("runtime-dependency", lambda values: values.update({dist + "METADATA": values[dist + "METADATA"].replace(
                b"Provides-Extra: test\n", b"Provides-Extra: test\nRequires-Dist: unexpected-runtime==1\n")}), {}, "WHEEL_RUNTIME_OR_UNPINNED_DEPENDENCY"),
            ("tag", lambda values: values.update({dist + "WHEEL": values[dist + "WHEEL"].replace(b"py3-none-any", b"cp311-none-linux")}), {}, "WHEEL_ENTRY_CONTRACT"),
            ("record-hash", lambda values: None, {"record_edit": lambda data: data.replace(b"sha256=", b"sha512=", 1)}, "WHEEL_RECORD_BYTES"),
            ("record-missing", lambda values: None, {"record_edit": lambda data: b"".join(data.splitlines(keepends=True)[1:])}, "WHEEL_RECORD_INVENTORY"),
            ("duplicate", lambda values: None, {"duplicate": package}, "WHEEL_DUPLICATE_OR_OVERSIZED_MEMBER"),
            ("special-mode", lambda values: None, {"modes": {package: stat.S_IFLNK | 0o777}}, "WHEEL_UNSAFE_MEMBER"),
            ("parent-path", lambda values: values.update({"../outside.txt": b"fixture"}), {}, "WHEEL_UNSAFE_MEMBER"),
        )
        deadline = time.monotonic() + 60.0
        with tempfile.TemporaryDirectory(prefix="mrk-ci-wheel-") as temporary:
            root = Path(temporary)
            valid = root / "valid.whl"
            self.write_wheel(valid, original)
            observed = checks.inspect_project_wheel(valid, ROOT, deadline=deadline)
            self.assertEqual(observed["sha256"], hashlib.sha256(valid.read_bytes()).hexdigest())
            self.assertEqual(observed["member_count"], len(original) + 1)
            self.assertEqual(observed["runtime_dependencies"], [])
            for name, edit, options, code in edits:
                with self.subTest(mutation=name):
                    members = dict(original)
                    edit(members)
                    path = root / (name + ".whl")
                    self.write_wheel(path, members, **options)
                    with self.assertRaisesRegex(checks.CheckError, code):
                        checks.inspect_project_wheel(path, ROOT, deadline=deadline)

    def test_consumer_requires_all_four_callers_empty_default_note_and_no_pending_transaction(self):
        checks = ci_module("ci_checks")
        configuration = {
            "$schema": "https://raw.githubusercontent.com/example/mobile-release-kit/" + "1" * 40 + "/schemas/project.schema.json",
            "schemaVersion": 1, "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
            "source": {"candidateBranch": "main", "productionBranch": "main"},
            "android": {"enabled": True, "applicationId": "com.example.wheelsmoke", "identityStatus": "unverified"},
            "ios": {"enabled": False}, "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": []},
            "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
            "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []},
        }
        files = {
            "app/build.gradle.kts": b'plugins { id("com.android.application") }\nandroid { namespace = "com.example.wheelsmoke"; defaultConfig { applicationId = "com.example.wheelsmoke" } }\n',
            ".gitignore": b".mobile-release/\n.mobile-release-init-prepare/\n.mobile-release-init/\n.mobile-release-init-cleanup/\n",
            "release/mobile-release.json": json.dumps(configuration).encode(),
        }
        for filename in ("title.txt", "short_description.txt", "full_description.txt", "changelogs/default.txt"):
            files["release/store/android/en-US/" + filename] = b""
        for stage in ("preflight", "candidate", "external-testing", "production-submit"):
            name = "mobile-" + stage + ".yml"
            files[".github/workflows/" + name] = (ROOT / "templates/workflows" / name).read_bytes().replace(
                b"__MOBILE_RELEASE_KIT_SHA__", b"1" * 40).replace(b"__MOBILE_RELEASE_KIT_REPOSITORY__", b"example/mobile-release-kit")
        deadline = time.monotonic() + 60.0
        note = "release/store/android/en-US/changelogs/default.txt"
        edits = (
            ("valid", lambda root: None),
            ("missing-note", lambda root: (root / note).unlink()),
            ("nonempty-note", lambda root: (root / note).write_bytes(b"unexpected default text")),
            ("missing-caller", lambda root: (root / ".github/workflows/mobile-production-submit.yml").unlink()),
            ("wrong-caller", lambda root: (root / ".github/workflows/mobile-candidate.yml").write_bytes(b"different caller\n")),
            ("pending-transaction", lambda root: (root / ".mobile-release-init").mkdir()),
            ("extra-file", lambda root: (root / "unexpected.txt").write_bytes(b"unexpected")),
            ("executable-config", lambda root: (root / "release/mobile-release.json").chmod(0o700)),
        )
        with tempfile.TemporaryDirectory(prefix="mrk-ci-consumer-") as temporary:
            for name, edit in edits:
                with self.subTest(mutation=name):
                    root = Path(temporary) / name
                    for relative, data in files.items():
                        path = root / relative
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(data)
                    edit(root)
                    if name == "valid":
                        self.assertEqual(checks.inspect_wheel_consumer(root, ROOT, deadline=deadline),
                                         {"file_count": len(files), "caller_count": 4, "default_note_bytes": 0, "transaction_state": []})
                    else:
                        with self.assertRaises(checks.CheckError):
                            checks.inspect_wheel_consumer(root, ROOT, deadline=deadline)

    def test_jdk_diagnostic_classification_is_exact_but_is_not_native_evidence(self):
        checks = ci_module("ci_checks")
        diagnostics = {
            "outside-warning-window": "",
            "inside-warning-window": "This jar contains entries whose signer certificate will expire within six months.\n",
            "expired": "This jar contains entries whose signer certificate has expired.\n",
            "not-yet-valid": "This jar contains entries whose signer certificate is not yet valid.\n",
        }
        for scenario, diagnostic in diagnostics.items():
            stdout = b"jar verified, with signer errors.\n"
            stderr = diagnostic.encode("ascii")
            checks.validate_jdk_diagnostics(scenario, 4, stdout, stderr)
            altered = [(0, stdout, stderr), (4, stdout * 2, stderr), (4, b"", stderr),
                       (4, stdout, stderr + b"An unrelated signer has expired.\n"),
                       (4, stdout, stderr + b"jarsigner error: synthetic failure\n"),
                       (4, stdout, stderr + b"weak algorithm\n")]
            if diagnostic:
                altered += [(4, stdout, b""), (4, stdout, stderr * 2)]
            for index, (status, out, err) in enumerate(altered):
                with self.subTest(scenario=scenario, mutation=index), self.assertRaises(checks.CheckError):
                    checks.validate_jdk_diagnostics(scenario, status, out, err)


if __name__ == "__main__":
    unittest.main()
