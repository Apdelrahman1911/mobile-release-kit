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

from .workflow_harness import evaluate_condition, load_workflow, simulate_steps


ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github/workflows/ci.yml"
_PYTHON_POISON_FIXTURES = (
    ("poison-wait-loss", "unit.test_native_process.NativeProcessLifecycleTests.test_native_consumed_wait_result_loss_never_retries_numeric_custody"),
    ("poison-startup-error", "unit.test_native_process.NativeProcessLifecycleTests.test_native_error_startup_is_unknown_not_a_wait_receipt"),
    ("poison-full-zero", "workflow.test_profile_processes.ProfileProcessTests.test_unknown_malformed_c_full_zero_retains_scratch"),
    ("poison-full-failure", "workflow.test_profile_processes.ProfileProcessTests.test_unknown_malformed_c_full_failure_retains_scratch"),
    ("poison-marker-parent-death", "workflow.test_profile_processes.ProfileProcessTests.test_unknown_marker_parent_death_requires_domain_disposal"),
    ("poison-committed-parent-death", "workflow.test_profile_processes.ProfileProcessTests.test_unknown_committed_parent_death_requires_domain_disposal"),
    ("poison-orphan", "workflow.test_profile_processes.ProfileProcessTests.test_killed_ancestor_cannot_strand_independent_native_worker_group"),
    ("poison-payload-writer-close-failure", "workflow.test_profile_processes.ProfileGroupCleanupTests.test_unknown_payload_writer_close_failure_retains_scratch"),
    ("poison-payload-reader-close-failure", "workflow.test_profile_processes.ProfileGroupCleanupTests.test_unknown_payload_reader_close_failure_retains_scratch"),
    ("poison-payload-reader-close-unresolved", "workflow.test_profile_processes.ProfileGroupCleanupTests.test_unknown_payload_reader_close_unresolved_retains_scratch"),
    ("poison-read-restored-int", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_read_restored_int"),
    ("poison-source-restored-int", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_source_restored_int"),
    ("poison-capture-restored-int", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_capture_restored_int"),
    ("poison-read-restored-term-fatal", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_read_restored_term_fatal"),
    ("poison-source-restored-term-fatal", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_source_restored_term_fatal"),
    ("poison-capture-restored-term-fatal", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_capture_restored_term_fatal"),
    ("poison-capture-control-close-failure", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_capture_control_close_failure"),
    ("poison-capture-status-close-failure", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_capture_status_close_failure"),
    ("poison-capture-payload-close-failure", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_capture_payload_close_failure"),
    ("poison-capture-payload-close-unresolved", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_capture_payload_close_unresolved"),
    ("poison-source-control-close-failure", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_source_control_close_failure"),
    ("poison-source-status-close-failure", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_source_status_close_failure"),
    ("poison-source-payload-close-failure", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_source_payload_close_failure"),
    ("poison-source-payload-close-unresolved", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_source_payload_close_unresolved"),
    ("poison-source-scratch-cleanup-failure", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_source_scratch_cleanup_failure"),
    ("poison-source-scratch-cleanup-unresolved", "unit.test_default_cancellation.ProfileResourceSignalTests.test_unknown_source_scratch_cleanup_unresolved"),
    ("poison-read-raw-close-before-completion", "unit.test_default_cancellation.ProfileResourceIOTests.test_unknown_read_raw_close_before_completion"),
    ("poison-read-raw-close-after-completion", "unit.test_default_cancellation.ProfileResourceIOTests.test_unknown_read_raw_close_after_completion"),
    ("poison-source-raw-close-before-completion", "unit.test_default_cancellation.ProfileResourceIOTests.test_unknown_source_raw_close_before_completion"),
    ("poison-source-raw-close-after-completion", "unit.test_default_cancellation.ProfileResourceIOTests.test_unknown_source_raw_close_after_completion"),
    ("poison-unpublished-scratch", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_attempted_unpublished_scratch_acquisition_retains_unknown_across_unwind_and_gc"),
    ("poison-directory-replacement", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_unknown_directory_replacement"),
    ("poison-symlink-replacement", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_unknown_symlink_replacement"),
    ("poison-unexpected-child", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_unknown_unexpected_child"),
    ("poison-keyboard-interrupt-cleanup-failure", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_unknown_keyboard_interrupt_cleanup_failure"),
    ("poison-keyboard-interrupt-restore-failure", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_unknown_keyboard_interrupt_restore_failure"),
    ("poison-keyboard-interrupt-cleanup-and-restore-failure", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_unknown_keyboard_interrupt_cleanup_and_restore_failure"),
    ("poison-system-exit-cleanup-failure", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_unknown_system_exit_cleanup_failure"),
    ("poison-system-exit-restore-failure", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_unknown_system_exit_restore_failure"),
    ("poison-system-exit-cleanup-and-restore-failure", "unit.test_default_cancellation.ProfileScratchFinalityTests.test_unknown_system_exit_cleanup_and_restore_failure"),
)
HOSTED_GUARD = '''set -euo pipefail
[[ "$MOBILE_RELEASE_RUNNER_ENVIRONMENT" == github-hosted ]]
'''
LINUX_TARGET_CONDITION = "${{ github.event_name != 'workflow_dispatch' || inputs.verification_target != 'macos' }}"
VERIFICATION_CONCURRENCY = "release-kit-ci-${{ github.ref }}-${{ github.event_name }}-${{ inputs.verification_target || 'full' }}"
AGGREGATE_GUARD = '''set -euo pipefail
[[ "$LINUX_RESULT" == success && "$NATIVE_RESULT" == success ]]
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
                            java_home=Path("/fixture/jdk21"), compatibility_runtimes=tuple(
                                (Path(f"/fixture/python{line}/bin/python"), Path(f"/fixture/python{line}"))
                                for line in ("312", "313", "314")))


def coordinator_shell(platform: str) -> str:
    if platform not in {"linux", "macos"}:
        raise ValueError("unsupported CI platform")
    java = '--java-home "$JAVA_HOME_21_X64" ' if platform == "linux" else ""
    return '''set -euo pipefail
ruby_executable="$(command -v ruby)"
[[ "$MRK_PYTHON" == /* && "$ruby_executable" == /* ]]
[[ "$MRK_PYTHON_312" == /* && "$MRK_PYTHON_313" == /* && "$MRK_PYTHON_314" == /* ]]
sudo -n env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin PYTHONSAFEPATH=1 \\
  "$MRK_PYTHON" -I -B .github/scripts/verify_ci.py \\
  --platform PLATFORM --source "$GITHUB_WORKSPACE" \\
  --python "$MRK_PYTHON" --ruby "$ruby_executable" \\
  --python-312 "$MRK_PYTHON_312" --python-313 "$MRK_PYTHON_313" --python-314 "$MRK_PYTHON_314" \\
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
        # The pinned Psych loader parses YAML's unquoted `on` as true; JSON
        # serializes that mapping key as "true". Do not invent a second parser.
        self.assertEqual(workflow["true"], {
            "pull_request": None, "push": {"branches": ["main"]},
            "workflow_dispatch": {"inputs": {"verification_target": {
                "description": "Full verification, or macOS-only candidate evidence (aggregate remains incomplete)",
                "type": "choice", "required": True, "default": "full", "options": ["full", "macos"],
            }}},
        })
        self.assertEqual(workflow["concurrency"], {"group": VERIFICATION_CONCURRENCY, "cancel-in-progress": True})
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
                if platform == "linux":
                    self.assertEqual(job["if"], LINUX_TARGET_CONDITION)
                else:
                    self.assertNotIn("if", job)
                for forbidden in ("continue-on-error", "environment", "container", "services", "strategy", "defaults", "env"):
                    self.assertNotIn(forbidden, job)
                self.assertEqual(job.get("permissions", workflow["permissions"]), {"contents": "read"})
                steps = job["steps"]
                self.assertEqual(len(steps), 9 if platform == "linux" else 8)
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
                for index, line in enumerate(("312", "313", "314"), start=3):
                    self.assertEqual(set(steps[index]), {"name", "id", "uses", "with"})
                    self.assertEqual(steps[index]["id"], "python" + line)
                    self.assertEqual(steps[index]["uses"], steps[2]["uses"])
                    self.assertEqual(steps[index]["with"], {"python-version": "3." + line[1:]})
                self.assertEqual(steps[6]["uses"], "ruby/setup-ruby@95ef2b042f9d7a56d8268cba8559e2842e2ad01b")
                self.assertEqual(set(steps[6]), {"name", "uses", "with"})
                self.assertEqual(steps[6]["with"], {
                    "ruby-version": "3.3.12", "bundler": "none", "bundler-cache": False,
                })
                for step in steps[1:7]:
                    self.assertNotIn("run", step)
                    self.assertNotIn("env", step)
                if platform == "linux":
                    self.assertEqual(set(steps[7]), {"name", "shell", "run"})
                    self.assertEqual(steps[7]["shell"], "bash")
                    self.assertEqual(steps[7]["run"], LINUX_TOOL_SETUP)
                    self.assertNotIn("env", steps[7])
                owner = steps[-1]
                self.assertEqual(set(owner), {"name", "shell", "env", "run"})
                self.assertEqual(owner["env"], {
                    "MRK_PYTHON": "${{ steps.python.outputs.python-path }}",
                    "MRK_PYTHON_312": "${{ steps.python312.outputs.python-path }}",
                    "MRK_PYTHON_313": "${{ steps.python313.outputs.python-path }}",
                    "MRK_PYTHON_314": "${{ steps.python314.outputs.python-path }}",
                })
                self.assertEqual(owner["shell"], "bash")
                self.assertEqual(owner["run"], coordinator_shell(platform))

    def test_manual_native_candidate_routing_and_protected_aggregate_remain_fail_closed(self):
        workflow = load_workflow(CI)
        linux, native, aggregate = (workflow["jobs"][name] for name in ("test-linux", "test-native-profiles", "test"))
        self.assertEqual(linux["if"], LINUX_TARGET_CONDITION)
        self.assertNotIn("if", native)
        for event, ref in (("pull_request", "refs/pull/1/merge"), ("push", "refs/heads/main"),
                           ("workflow_dispatch", "refs/heads/qa006-native-candidate")):
            for target in ("full", "macos", None, "", "unknown", "MACOS", "mAcOs", "macos "):
                with self.subTest(candidate_route=(event, target)):
                    context = {"github": {"event_name": event, "ref": ref}}
                    # For this one pinned comparison and fixed ASCII fixture,
                    # model Actions' case-insensitive string equality explicitly.
                    # The shared restricted interpreter remains unchanged.
                    compared = target.lower() if target is not None else None
                    if target is not None:
                        context["inputs"] = {"verification_target": compared}
                    omitted = event == "workflow_dispatch" and compared == "macos"
                    self.assertEqual(evaluate_condition(linux["if"], context, success=True, cancelled=False), not omitted)
                    self.assertTrue(evaluate_condition(native.get("if"), context, success=True, cancelled=False))

        # This is the existing fixed job, not a synthesized cross-run status.
        # Pin every field before the harmless shell can be executed below.
        self.assertEqual(aggregate, {
            "needs": ["test-linux", "test-native-profiles"], "if": "${{ always() }}",
            "runs-on": "ubuntu-24.04", "timeout-minutes": 5, "permissions": {},
            "steps": [{"name": "Require every verification job to succeed", "env": {
                "LINUX_RESULT": "${{ needs.test-linux.result }}",
                "NATIVE_RESULT": "${{ needs.test-native-profiles.result }}",
            }, "run": AGGREGATE_GUARD}],
        })
        self.assertTrue(evaluate_condition(aggregate["if"], {}, success=False, cancelled=True))
        states = ["failure", "cancelled", "skipped", "queued", "unavailable", "", None]
        pairs = [("success", "success")]
        for state in states:
            pairs.extend(((state, "success"), ("success", state), (state, state)))
        body = aggregate["steps"][0]["run"]
        for linux_result, native_result in pairs:
            with self.subTest(protected_results=(linux_result, native_result)):
                env = {"PATH": "/usr/bin:/bin"}
                if linux_result is not None:
                    env["LINUX_RESULT"] = linux_result
                if native_result is not None:
                    env["NATIVE_RESULT"] = native_result
                result = subprocess.run(["bash", "--noprofile", "--norc", "-c", body],
                                        env=env, capture_output=True, timeout=5)
                self.assertEqual(result.returncode == 0, linux_result == native_result == "success")
                self.assertEqual(result.stdout, b"")

        group = workflow["concurrency"]["group"]
        self.assertEqual(group, VERIFICATION_CONCURRENCY)
        self.assertIs(workflow["concurrency"]["cancel-in-progress"], True)

        def group_for(event, target):
            # Substitute only these three already-pinned literal placeholders;
            # this does not evaluate Actions syntax or query any workflow run.
            return (group.replace("${{ github.ref }}", "refs/heads/same-task-ref")
                    .replace("${{ github.event_name }}", event)
                    .replace("${{ inputs.verification_target || 'full' }}", target or "full"))

        groups = {group_for("pull_request", None), group_for("push", None),
                  group_for("workflow_dispatch", "full"), group_for("workflow_dispatch", "macos")}
        self.assertEqual(len(groups), 4)  # Partial dispatch cannot cancel any full event/target.
        self.assertTrue(all("${{" not in value for value in groups))
        for absent in (None, ""):
            self.assertEqual(group_for("workflow_dispatch", absent), group_for("workflow_dispatch", "full"))

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
            "MRK_PYTHON_312": "/fixture/python312/bin/python", "MRK_PYTHON_313": "/fixture/python313/bin/python",
            "MRK_PYTHON_314": "/fixture/python314/bin/python",
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
                "--python-312", env["MRK_PYTHON_312"], "--python-313", env["MRK_PYTHON_313"],
                "--python-314", env["MRK_PYTHON_314"],
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
            for key in ("MRK_PYTHON", "FIXTURE_RUBY", "MRK_PYTHON_312", "MRK_PYTHON_313", "MRK_PYTHON_314"):
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
    def _native_gate_fixture(self, phase="source"):
        """Only data and fake calls: no Session, product import or native work."""
        controller = controller_module()
        paths = fixture_paths(controller)
        checks = ci_module("ci_checks")
        authority = checks.NATIVE_AUTHORITY_IDS
        ordinary = ("unit.synthetic.OrdinaryTests.test_first", "unit.synthetic.OrdinaryTests.test_second")
        poison = {name: (identifier,) for name, identifier in zip(checks.PYTHON_POISON_PARTITIONS, checks.PYTHON_POISON_IDS)}
        inventories = {"authority": authority, "ordinary": ordinary,
                       **poison, "all": tuple(sorted(authority + ordinary + checks.PYTHON_POISON_IDS))}
        python = paths.source_python if phase == "source" else paths.wheel_python
        step = controller.Step("native-profile-" + phase,
            argv=(str(python), "-I", "-B", str(ROOT / "tests/workflow/run_native_profile_checks.py"),
                  *(("--installed-wheel",) if phase == "wheel" else ())), cwd=paths.work,
            env=tuple(sorted(controller.native_phase_environment(paths, "macos", phase).items())), seconds=900, parser="native")
        rig = SimpleNamespace(controller=controller, paths=paths, step=step, now=100.0,
                              inventories=inventories, events=[], captures=[], changes={},
                              prepare_error=None, idle_error=None, run_error=None,
                              prepare_advance=100.0, run_advance=1.0, parsed=[], phase=phase,
                              idle_failure_after=None)

        def identities(source, partition, *, deadline):
            self.assertEqual(source, ROOT)
            rig.events.append(("inventory", partition, deadline))
            return rig.inventories[partition]

        def package(source, root, *, deadline):
            self.assertEqual(source, ROOT)
            rig.events.append(("package", root, deadline))
            return {"bytes_match_source": True, "immutable_modes": True}

        def idle(*, deadline):
            rig.events.append(("idle", deadline))
            if (rig.idle_error is not None and rig.captures
                    and (rig.idle_failure_after is None or len(rig.captures) >= rig.idle_failure_after)):
                raise rig.idle_error

        def prepare(selected, *, deadline):
            rig.events.append(("prepare", selected, deadline))
            rig.now += rig.prepare_advance
            if rig.prepare_error is not None:
                raise rig.prepare_error

        def run(argv, **options):
            partition = ("authority" if "--authority" in argv else "ordinary" if "--ordinary" in argv else
                         next((name for name in controller.PYTHON_POISON_PARTITIONS if f"--{name}-{phase}" in argv), "healthy"))
            rig.events.append(("run", argv, options))
            if rig.run_error is not None:
                raise rig.run_error
            ids = rig.inventories[partition]
            text = "".join(f"{name.rsplit('.', 1)[1]} ({name}) ... ok\n" for name in ids)
            text += f"\nRan {len(ids)} tests in 0.01s\n\nOK\n"
            stdout = b""
            if partition in controller.PYTHON_POISON_PARTITIONS:
                package = (paths.work / "source-build/src/mobile_release" if phase == "source" else
                           paths.work / "wheel-venv/lib/python3.11/site-packages/mobile_release")
                prefix = str(paths.python.parent.parent)
                metadata = {"schema": "mrk-native-python-runtime-v1", "phase": phase, "implementation": "cpython",
                    "version": [3, 11, 1], "executable": str(python), "base_prefix": prefix, "base_exec_prefix": prefix,
                    "prefix": prefix, "exec_prefix": prefix, "isolated": True, "package_root": str(package),
                    "origins": {"mobile_release": str(package / "__init__.py"),
                                "mobile_release._native_process": str(package / "_native_process.py")}}
                stdout = (controller.NATIVE_PYTHON_RUNTIME_PREFIX + json.dumps(metadata) + "\n").encode()
            elif partition == "healthy":
                detail = {"failure_callbacks": []}
                if phase == "source":
                    detail["storage_profile"] = {"name": "linux-python-full-v1", "logical_file_bytes": 4296015872,
                        "file_data_bytes": 956301312, "tmpfs_mounts": 11, "write_controls": 11,
                        "readonly_errno": 30, "capacity_errno": 28, "capacity_bytes": 16777216, "max_user_namespaces": 0}
                stdout = ("MRK_CHECK_RESULT=" + json.dumps({"check": rig.step.id, "ok": True,
                    "tests": [{"id": identifier, "outcome": "ok"} for identifier in ids], "details": detail}) + "\n").encode()
            values = dict(ok=True, returncode=0, waited=True, stdout_eof=True, stderr_eof=True,
                          domain_finality=True, primary_error=None, cleanup_errors=(), stdout=stdout,
                          stderr=text.encode(), duration=rig.run_advance, timed_out=False,
                          cancelled=False, persisted=(len(stdout), len(text)))
            capture = SimpleNamespace(**{**values, **rig.changes.get(partition, {})})
            rig.captures.append(capture)
            rig.now += rig.run_advance
            return capture

        rig.checks = SimpleNamespace(native_partition_ids=identities, inspect_native_package=package)
        rig.session = SimpleNamespace(ensure_idle=idle, prepare_native_authority=prepare, run=run)
        return rig

    def _python_gate_fixture(self, phase="source", *, deadline=2500.0):
        rig = self._native_gate_fixture(phase)
        controller, paths = rig.controller, rig.paths
        healthy = rig.inventories["ordinary"]
        poison = {name: rig.inventories[name] for name in controller.PYTHON_POISON_PARTITIONS}
        rig.inventories = {"healthy": healthy, **poison,
            "all": tuple(sorted(healthy + tuple(identifier for ids in poison.values() for identifier in ids)))}
        name = "python-full" if phase == "source" else "python-wheel"
        python = paths.source_python if phase == "source" else paths.wheel_python
        rig.step = controller.Step(name, argv=(str(python), "-I", "-B", str(paths.checks), "--check", name,
            "--source-root", str(ROOT), "--work-root", str(paths.work / "checks"), "--deadline", repr(deadline)),
            cwd=paths.work, env=tuple(sorted(controller.native_phase_environment(paths, "linux", phase).items())),
            seconds=900, parser="check")

        def identities(source, selection, partition, *, deadline):
            self.assertEqual(source, ROOT)
            self.assertEqual(selection, "full" if phase == "source" else "wheel")
            rig.events.append(("inventory", partition, deadline))
            return rig.inventories[partition]

        rig.checks.python_capture_ids = identities
        rig.checks.linux_allowed_skips = frozenset
        return rig

    def _perform_native_fixture(self, rig, *, step=None, platform="macos", deadline=2500.0):
        original_parser = rig.controller.parse_capture

        def parse(part, captured, *args, **kwargs):
            rig.parsed.append(captured)
            return original_parser(part, captured, *args, **kwargs)

        with patch.object(rig.controller.time, "monotonic", side_effect=lambda: rig.now), \
                patch.object(rig.controller, "check_capacity"), patch.object(rig.controller, "parse_capture", side_effect=parse):
            return rig.controller.perform_step(step or rig.step, rig.paths, rig.session, rig.checks,
                                               {}, platform, deadline=deadline)

    def test_native_gate_keeps_every_original_capture_record_and_one_source_wheel_cutoff(self):
        for phase, original_deadline, cutoff in (("source", 2500.0, 1000.0), ("wheel", 800.0, 800.0)):
            with self.subTest(phase=phase):
                rig = self._native_gate_fixture(phase)
                parts = ("authority", "ordinary", *rig.controller.PYTHON_POISON_PARTITIONS)
                result = self._perform_native_fixture(rig, deadline=original_deadline)
                self.assertTrue(result.ok, result)
                self.assertEqual(result.details["stage"], "complete")
                self.assertEqual(result.details["completed"], list(rig.inventories["all"]))
                self.assertEqual(result.details["tests"], len(rig.inventories["all"]))
                self.assertNotIn("returncode", result.details)  # No invented aggregate capture.
                records = result.details["partitions"]
                self.assertEqual([row["partition"] for row in records], list(parts))
                self.assertEqual([row["status"] for row in records], ["PASS"] * len(parts))
                calls = [event for event in rig.events if event[0] == "run"]
                self.assertEqual(len(calls), len(parts))
                python = rig.paths.source_python if phase == "source" else rig.paths.wheel_python
                entry = str(ROOT / "tests/workflow/run_native_profile_checks.py")
                tail = [] if phase == "source" else ["--installed-wheel"]
                self.assertEqual(calls[0][1], [str(python), "-I", "-S", "-B", entry, "--authority", *tail])
                self.assertEqual(calls[1][1], [str(python), "-I", "-B", entry, "--ordinary", *tail])
                for index, partition in enumerate(rig.controller.PYTHON_POISON_PARTITIONS, 2):
                    self.assertEqual(calls[index][1], [str(python), "-I", "-S", "-B", entry, f"--{partition}-{phase}"])
                    self.assertEqual(calls[index][2]["profile"], "ordinary")
                    self.assertEqual(calls[index][2]["cwd"], rig.paths.work)
                    self.assertEqual(calls[index][2]["env"], dict(rig.step.env))
                    self.assertEqual(records[index]["runtime"]["phase"], phase)
                self.assertEqual(calls[0][2]["env"], {})
                self.assertEqual(calls[0][2]["cwd"], rig.paths.work / ("native-authority-" + phase))
                self.assertEqual(calls[0][2]["profile"], "native-authority-" + phase)
                self.assertEqual(calls[1][2]["env"], dict(rig.step.env))
                self.assertEqual(calls[1][2]["cwd"], rig.paths.work)
                self.assertEqual(calls[1][2]["profile"], "ordinary")
                for index, (_, _, options) in enumerate(calls):
                    self.assertEqual(options["absolute_deadline"], cutoff)
                    self.assertEqual(options["seconds"], 900)
                    self.assertEqual(options["cpu_seconds"], 180)
                    self.assertEqual(options["output_limit"], 8 * 1024**2)
                    self.assertEqual(records[index]["capture"],
                                     rig.controller.capture_observations(rig.captures[index]))
                    self.assertEqual(records[index]["completed"], list(rig.inventories[records[index]["partition"]]))
                    self.assertIs(rig.parsed[index], rig.captures[index])
                self.assertEqual([event for event in rig.events if event[0] == "prepare"], [("prepare", phase, cutoff)])
                package = (rig.paths.work / "source-build/src/mobile_release" if phase == "source"
                           else rig.paths.work / "wheel-venv/lib/python3.11/site-packages/mobile_release")
                self.assertIn(("package", package, cutoff), rig.events)
                self.assertTrue(all(event[-1] == cutoff for event in rig.events if event[0] != "run"))

    def test_native_gate_rejects_contract_or_partition_drift_without_launch(self):
        controller = controller_module()
        rig = self._native_gate_fixture()
        for changes in ({"kind": "inspection"}, {"argv": (*rig.step.argv, "--authority")},
                        {"env": ()}, {"cwd": rig.paths.source}, {"seconds": 901},
                        {"parser": "exit"}, {"native_partition": "authority"}, {"expected_tests": 5}):
            with self.subTest(changes=changes):
                result = self._perform_native_fixture(rig, step=dataclasses.replace(rig.step, **changes))
                self.assertEqual(result.error, "NATIVE_GATE_CONTRACT")
                self.assertEqual(rig.events, [])
        self.assertEqual(self._perform_native_fixture(rig, platform="linux").error, "NATIVE_GATE_CONTRACT")
        self.assertEqual(rig.events, [])
        for mutation in ("missing", "duplicate", "overlap", "expanded-authority", "pooled-poison", "missing-poison"):
            with self.subTest(mutation=mutation):
                rig = self._native_gate_fixture()
                if mutation == "missing":
                    rig.inventories["ordinary"] = rig.inventories["ordinary"][:-1]
                elif mutation == "duplicate":
                    rig.inventories["ordinary"] *= 2
                elif mutation == "overlap":
                    rig.inventories["ordinary"] += rig.inventories["authority"][:1]
                elif mutation == "expanded-authority":
                    rig.inventories["authority"] += rig.inventories["ordinary"][:1]
                elif mutation == "pooled-poison":
                    rig.inventories["poison-wait-loss"] += rig.inventories["poison-startup-error"]
                else:
                    rig.inventories["poison-startup-error"] = ()
                result = self._perform_native_fixture(rig)
                self.assertEqual(result.error, "NATIVE_PARTITION_UNION")
                self.assertFalse(any(event[0] in {"package", "prepare", "run"} for event in rig.events))
                self.assertEqual([row["status"] for row in result.details["partitions"]],
                                 ["UNEXECUTED"] * (2 + len(controller.PYTHON_POISON_PARTITIONS)))

    def test_native_gate_failure_preserves_original_capture_and_never_runs_later_partition(self):
        failure = OSError("synthetic private failure; must not be published")
        parts = ("authority", "ordinary", *controller_module().PYTHON_POISON_PARTITIONS)
        for mode in ("preparation", "launch", "exit", "wait", "stdout-eof", "stderr-eof", "finality",
                     "timeout", "cancel", "primary", "cleanup", "parser", "idle", "diagnostic", "ordinary",
                     *parts[2:], "poison-origin"):
            with self.subTest(mode=mode):
                rig = self._native_gate_fixture()
                fields = {"exit": {"returncode": 1}, "wait": {"waited": False},
                          "stdout-eof": {"stdout_eof": False}, "stderr-eof": {"stderr_eof": False},
                          "finality": {"domain_finality": False}, "timeout": {"ok": False, "timed_out": True},
                          "cancel": {"ok": False, "cancelled": True}, "primary": {"primary_error": "FIXTURE"},
                          "cleanup": {"cleanup_errors": ("FIXTURE_CLOSE",)}, "parser": {"stderr": b"OK\n"}}
                if mode == "preparation":
                    rig.prepare_error = failure
                elif mode == "launch":
                    rig.run_error = failure
                elif mode == "idle":
                    rig.idle_error = failure
                elif mode == "diagnostic":
                    rig.changes["authority"] = {"returncode": 1}
                    rig.idle_error = failure
                elif mode == "ordinary":
                    rig.changes["ordinary"] = {"returncode": 1}
                elif mode in parts[2:]:
                    rig.changes[mode] = {"returncode": 1}
                elif mode == "poison-origin":
                    rig.changes["poison-wait-loss"] = {"stdout": b"foreign metadata\n"}
                else:
                    rig.changes["authority"] = fields[mode]
                with contextlib.ExitStack() as stack:
                    if mode == "diagnostic":
                        stack.enter_context(patch.object(rig.controller, "failure_details", side_effect=failure))
                    result = self._perform_native_fixture(rig)
                self.assertFalse(result.ok)
                self.assertNotIn(str(failure), json.dumps(result.details))
                records = result.details["partitions"]
                failed_index = parts.index(mode) if mode in parts else 2 if mode == "poison-origin" else 0
                expected_count = 0 if mode in {"preparation", "launch"} else failed_index + 1
                self.assertEqual(len(rig.captures), expected_count)
                for index, row in enumerate(records):
                    self.assertEqual(row["status"], "UNEXECUTED" if mode == "preparation" or index > failed_index
                                     else "FAIL" if index == failed_index else "PASS")
                if mode == "preparation":
                    self.assertEqual(records[0]["status"], "UNEXECUTED")
                for index, capture in enumerate(rig.captures):
                    for field, value in rig.controller.capture_observations(capture).items():
                        self.assertEqual(records[index]["capture"][field], value)
                if mode == "diagnostic":
                    self.assertEqual(result.error, "COMMAND_EXIT_OR_FINALITY")
                    self.assertIn("idle_error", records[0])
                    self.assertIn("diagnostic_error", records[0])

    def test_native_gate_deadline_covers_preparation_every_original_and_final_reconciliation(self):
        parts = ("authority", "ordinary", *controller_module().PYTHON_POISON_PARTITIONS)
        for mode in ("preparation", *parts, "union"):
            with self.subTest(mode=mode):
                rig = self._native_gate_fixture()
                if mode == "preparation":
                    rig.prepare_advance = 900.0
                elif mode in parts:
                    # One original cutoff: preparation has already consumed
                    # 100s. Expire during this exact original, not a renewed one.
                    rig.run_advance = 801.0 / (parts.index(mode) + 1)
                reconciliations = []

                def late_sorted(values, *args, **kwargs):
                    result = sorted(values, *args, **kwargs)
                    if type(values) is list and tuple(result) == rig.inventories["all"]:
                        reconciliations.append(True)
                        if len(reconciliations) == 2:
                            rig.now = 1000.0
                    return result

                with contextlib.ExitStack() as stack:
                    if mode == "union":
                        stack.enter_context(patch.object(rig.controller, "sorted", create=True, side_effect=late_sorted))
                    result = self._perform_native_fixture(rig)
                self.assertFalse(result.ok)
                self.assertEqual(result.error, "AGGREGATE_DEADLINE")
                self.assertEqual(len(rig.captures), 0 if mode == "preparation" else len(parts) if mode == "union"
                                 else parts.index(mode) + 1)
                records = result.details["partitions"]
                if mode == "preparation":
                    self.assertEqual([row["status"] for row in records], ["UNEXECUTED"] * len(parts))
                elif mode == "authority":
                    self.assertEqual(records[1]["status"], "UNEXECUTED")
                elif mode == "union":
                    self.assertEqual([row["status"] for row in records], ["PASS"] * len(parts))
                    self.assertEqual(len(reconciliations), 2)
                for index, capture in enumerate(rig.captures):
                    self.assertEqual(records[index]["capture"]["persisted"], list(capture.persisted))

    def test_fixed_linux_python_storage_profile_is_selected_only_for_full_discovery(self):
        profiles = []
        for phase, original_deadline, cutoff in (("source", 2500.0, 1000.0), ("wheel", 800.0, 800.0)):
            with self.subTest(phase=phase):
                rig = self._python_gate_fixture(phase, deadline=original_deadline)
                parts = ("healthy", *rig.controller.PYTHON_POISON_PARTITIONS)
                result = self._perform_native_fixture(rig, platform="linux", deadline=original_deadline)
                self.assertTrue(result.ok, result)
                rows = result.details["partitions"]
                self.assertEqual([row["partition"] for row in rows], list(parts))
                self.assertEqual([row["status"] for row in rows], ["PASS"] * len(parts))
                self.assertEqual(result.details["completed"], list(rig.inventories["all"]))
                self.assertEqual(result.details["tests"], len(rig.inventories["all"]))
                self.assertNotIn("returncode", result.details)
                calls = [event for event in rig.events if event[0] == "run"]
                self.assertEqual(len(calls), len(parts))
                self.assertEqual(calls[0][1], list(rig.step.argv))
                self.assertEqual(calls[0][1][-2:], ["--deadline", repr(original_deadline)])
                python = rig.paths.source_python if phase == "source" else rig.paths.wheel_python
                entry = str(ROOT / "tests/workflow/run_native_profile_checks.py")
                for index, (_, argv, options) in enumerate(calls):
                    profiles.append(options["profile"])
                    self.assertEqual(options["profile"], "python-full" if index == 0 and phase == "source" else "ordinary")
                    self.assertEqual(options["cpu_seconds"], 300 if index == 0 and phase == "source" else 180)
                    self.assertEqual(options["seconds"], 900)
                    self.assertEqual(options["absolute_deadline"], cutoff)
                    self.assertEqual(options["output_limit"], 8 * 1024**2)
                    self.assertEqual(options["cwd"], rig.paths.work)
                    self.assertEqual(options["env"], dict(rig.step.env))
                    self.assertIs(rig.parsed[index], rig.captures[index])
                    self.assertEqual(rows[index]["capture"], rig.controller.capture_observations(rig.captures[index]))
                    if index:
                        self.assertEqual(argv, [str(python), "-I", "-S", "-B", entry,
                                               f"--{rows[index]['partition']}-{phase}"])
                        self.assertEqual(rows[index]["tests"], 1)
                        self.assertEqual(rows[index]["runtime"]["phase"], phase)
                self.assertEqual("storage_profile" in rows[0]["summary"]["details"], phase == "source")
                self.assertFalse(any(event[0] == "prepare" for event in rig.events))
                self.assertTrue(all(event[-1] == cutoff for event in rig.events if event[0] != "run"))
                positions = [index for index, event in enumerate(rig.events) if event[0] == "run"]
                for index, position in enumerate(positions):
                    self.assertEqual(rig.events[position - 1], ("idle", cutoff))
                    end = positions[index + 1] if index + 1 < len(positions) else len(rig.events)
                    self.assertIn(("idle", cutoff), rig.events[position + 1:end])
        self.assertEqual(profiles.count("python-full"), 1)

    def test_python_gate_rejects_contract_partition_and_singleton_origin_drift(self):
        for phase in ("source", "wheel"):
            for fault in ("argv", "profile-shape", "healthy-omission", "duplicate", "pooled", "missing", "origin"):
                with self.subTest(phase=phase, fault=fault):
                    rig = self._python_gate_fixture(phase)
                    parts = ("healthy", *rig.controller.PYTHON_POISON_PARTITIONS)
                    step = rig.step
                    if fault == "argv":
                        step = dataclasses.replace(step, argv=(*step.argv[:-1], "1000.0"))
                    elif fault == "profile-shape":
                        step = dataclasses.replace(step, seconds=899)
                    elif fault == "healthy-omission":
                        rig.inventories["healthy"] = rig.inventories["healthy"][:-1]
                    elif fault == "duplicate":
                        rig.inventories["healthy"] *= 2
                    elif fault == "pooled":
                        rig.inventories["poison-wait-loss"] += rig.inventories["poison-startup-error"]
                    elif fault == "missing":
                        rig.inventories["poison-startup-error"] = ()
                    else:
                        original_run = rig.session.run

                        def run(argv, **options):
                            value = original_run(argv, **options)
                            if "--poison-wait-loss-" + phase in argv:
                                record = json.loads(value.stdout.decode().split("=", 1)[1])
                                record["package_root"] = "/foreign/source/mobile_release"
                                value.stdout = (rig.controller.NATIVE_PYTHON_RUNTIME_PREFIX + json.dumps(record) + "\n").encode()
                            return value

                        rig.session.run = run
                    result = self._perform_native_fixture(rig, step=step, platform="linux")
                    self.assertFalse(result.ok)
                    self.assertEqual(len(rig.captures), 2 if fault == "origin" else 0)
                    if fault == "origin":
                        self.assertEqual(result.error, "NATIVE_PYTHON_RUNTIME_ORIGIN")
                        self.assertEqual([row["status"] for row in result.details["partitions"]],
                                         ["PASS", "FAIL", *(["UNEXECUTED"] * (len(parts) - 2))])
                    else:
                        self.assertEqual(result.error, "PYTHON_GATE_CONTRACT" if fault in {"argv", "profile-shape"} else "PYTHON_CAPTURE_UNION")
                        self.assertEqual([row["status"] for row in result.details["partitions"]], ["UNEXECUTED"] * len(parts))

    def test_python_gate_stops_after_each_failed_original_and_keeps_one_cutoff(self):
        parts = ("healthy", *controller_module().PYTHON_POISON_PARTITIONS)
        for phase in ("source", "wheel"):
            for failed, partition in enumerate(parts):
                for fault in ("exit", "wait", "stdout", "stderr", "domain", "timeout", "cancel", "cleanup", "idle", "deadline"):
                    with self.subTest(phase=phase, partition=partition, fault=fault):
                        rig = self._python_gate_fixture(phase)
                        fields = {"exit": {"returncode": 1}, "wait": {"waited": False},
                                  "stdout": {"stdout_eof": False}, "stderr": {"stderr_eof": False},
                                  "domain": {"domain_finality": False}, "timeout": {"timed_out": True},
                                  "cancel": {"cancelled": True}, "cleanup": {"cleanup_errors": ("CLOSE",)}}
                        if fault == "idle":
                            rig.idle_error, rig.idle_failure_after = OSError("PRIVATE_IDLE_ERROR"), failed + 1
                        elif fault == "deadline":
                            rig.run_advance = 901.0 / (failed + 1)
                        else:
                            rig.changes[partition] = fields[fault]
                        result = self._perform_native_fixture(rig, platform="linux")
                        self.assertFalse(result.ok)
                        self.assertEqual(len(rig.captures), failed + 1)
                        rows = result.details["partitions"]
                        self.assertEqual([row["status"] for row in rows],
                            ["PASS"] * failed + ["FAIL"] + ["UNEXECUTED"] * (len(parts) - failed - 1))
                        self.assertNotIn("PRIVATE_IDLE_ERROR", json.dumps(result.details))
                        for index, capture in enumerate(rig.captures):
                            for field, value in rig.controller.capture_observations(capture).items():
                                self.assertEqual(rows[index]["capture"][field], value)
                        self.assertTrue(all(event[2]["absolute_deadline"] == 1000.0
                                            for event in rig.events if event[0] == "run"))
                        if fault == "deadline":
                            self.assertEqual(result.error, "AGGREGATE_DEADLINE")

        for phase in ("source", "wheel"):
            with self.subTest(phase=phase, expiry="final-union"):
                rig = self._python_gate_fixture(phase)
                reconciliations = []

                def late_sorted(values, *args, **kwargs):
                    result = sorted(values, *args, **kwargs)
                    if type(values) is list and tuple(result) == rig.inventories["all"]:
                        reconciliations.append(True)
                        if len(reconciliations) == 2:
                            rig.now = 1000.0
                    return result

                with patch.object(rig.controller, "sorted", create=True, side_effect=late_sorted):
                    result = self._perform_native_fixture(rig, platform="linux")
                self.assertFalse(result.ok)
                self.assertEqual(result.error, "AGGREGATE_DEADLINE")
                self.assertEqual(len(reconciliations), 2)
                self.assertEqual(len(rig.captures), len(parts))
                self.assertEqual([row["status"] for row in result.details["partitions"]], ["PASS"] * len(parts))
                self.assertEqual(result.details["tests"], len(rig.inventories["all"]))

    def test_python_failure_callbacks_are_source_bound_and_keep_private_errors_out(self):
        controller = controller_module()
        self.enterContext(patch.object(controller.time, "monotonic", return_value=999.0))
        paths = fixture_paths(controller)
        identifier = "unit.synthetic.FailureContract.test_second"
        private = "synthetic-private-message-and-filename-not-for-publication"
        observed = []

        def expected(source, selection, partition, *, deadline):
            observed.append((source, selection, partition, deadline))
            return (identifier,)

        checks = SimpleNamespace(python_capture_ids=expected)
        step = controller.Step("python-full", parser="check")
        callback = {"id": identifier, "outcome": "error", "category": "os-error", "errno": 27}

        def capture(callbacks, *, check="python-full", ok=False, stderr=b""):
            report = {"check": check, "ok": ok,
                      "tests": [{"id": identifier, "outcome": "error"}],
                      "details": {"error": "TEST_OUTCOME_COUNT", "failure_callbacks": callbacks,
                                  "raw_exception": private}}
            raw = ("MRK_CHECK_RESULT=" + json.dumps(report) + "\n").encode()
            return SimpleNamespace(ok=ok, returncode=1, waited=True, stdout_eof=True, stderr_eof=True,
                                   domain_finality=True, timed_out=False, cancelled=False,
                                   stdout=raw, stderr=stderr, persisted=(len(raw), len(stderr)), duration=0.1, cleanup_errors=())

        value = controller.failure_details(capture([callback]), step, paths, checks=checks, deadline=1000.0)
        self.assertEqual(value["failure_callbacks"], [callback])
        self.assertEqual(value["helper_error"], "TEST_OUTCOME_COUNT")
        self.assertEqual(value["returncode"], 1)
        self.assertEqual(observed, [(ROOT, "full", "healthy", 1000.0)])
        self.assertNotIn(private, json.dumps(value))
        valid = [callback, {**callback, "errno": None},
                 {**callback, "outcome": "failure", "category": "assertion-error", "errno": None},
                 {**callback, "outcome": "expected-failure", "category": "exception", "errno": None},
                 *({**callback, "outcome": outcome, "category": "none", "errno": None}
                   for outcome in ("skip", "unexpected-success"))]
        for row in valid:
            self.assertEqual(controller.python_failure_callbacks([row], (identifier,)), [row])
        invalid = [None, {}, [callback] * 17, [{**callback, "id": private}], [{**callback, "message": private}]]
        invalid += [[{**callback, key: item}] for key, values in (
            ("errno", (True, False, 0, -1, 4096, "27", [])),
            ("outcome", ("ok", "incomplete", [], True)),
            ("category", (private, [], True, "assertion-error")),
        ) for item in values]
        invalid += [[{**callback, "outcome": "skip"}], [{**callback, "category": "none", "errno": None}]]
        for index, rows in enumerate(invalid):
            with self.subTest(callback_mutation=index):
                value = controller.failure_details(capture(rows), step, paths, checks=checks, deadline=1000.0)
                self.assertNotIn("failure_callbacks", value)
                self.assertEqual(value["returncode"], 1)
                self.assertNotIn(private, json.dumps(value))
        for changes in ({"check": "python-wheel"}, {"ok": True}):
            value = controller.failure_details(capture([callback], **changes), step, paths, checks=checks)
            self.assertNotIn("failure_callbacks", value)

        diagnostic = {"schema": 1, "mode": "partial-write-failure", "returncode": 1,
                      "category": "assertion-error", "locations": [
                          {"file": "tests/workflow/profile_process_fixture.py", "line": 1199}]}

        def encode(record):
            return (controller.PROFILE_FIXTURE_FAILURE_PREFIX + json.dumps(record) + "\n").encode()

        marker = encode(diagnostic)
        # A valid-looking marker attached to an unrelated known failure is not
        # a source-bound profile observation and cannot enter the report.
        self.assertNotIn("profile_fixture_failure", controller.failure_details(
            capture([callback], stderr=marker), step, paths, checks=checks, deadline=1000.0))
        identifier = controller.PROFILE_FIXTURE_FAILURE_ID
        callback = {"id": identifier, "outcome": "failure", "category": "assertion-error", "errno": None}
        value = controller.failure_details(capture([callback], stderr=marker), step, paths,
                                           checks=checks, deadline=1000.0)
        self.assertEqual(value["profile_fixture_failure"], diagnostic)
        self.assertEqual(controller.profile_fixture_failure(marker[:-1]), diagnostic)
        self.assertEqual(value["returncode"], 1)
        with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
            controller.parse_capture(step, capture([callback], stderr=marker), paths, "linux", checks)
        wheel = controller.Step("python-wheel", parser="check")
        self.assertEqual(controller.failure_details(capture([callback], check="python-wheel", stderr=marker),
            wheel, paths, checks=checks, deadline=1000.0)["profile_fixture_failure"], diagnostic)

        process_class = "workflow.test_profile_processes.ProfileProcessTests."
        group_class = "workflow.test_profile_processes.ProfileGroupCleanupTests."
        callback_modes = {
            process_class + "test_group_ownership_is_established_before_spawn_and_never_kills_someone_elses_group": (
                "before-admit-cancel", "before-run-cancel",
            ),
            process_class + "test_success_and_custom_handlers_still_reap_live_descendants_and_keep_capabilities_out": (
                "success", "custom-handler",
            ),
            process_class + "test_timeout_observes_a_real_orphaned_pipe_before_cleanup": ("pipe-timeout",),
            process_class + "test_cancellation_during_spawn_registration_and_active_native_work_is_contained": (
                "spawn-return-cancel", "payload-register-cancel", "cancel", "completion-cancel", "completion-interrupt",
            ),
            process_class + "test_parent_capture_deadline_still_overrides_a_complete_success_frame": ("committed-timeout",),
            process_class + "test_failure_overflow_and_io_failure_reject_partial_content_without_leaking_workers": (
                "failure", "read-failure", "partial-write-failure", "overflow", "partial-marker",
                "extra-frame", "concatenated-frame",
            ),
            process_class + "test_unknown_malformed_c_full_zero_retains_scratch": ("full-zero",),
            process_class + "test_unknown_malformed_c_full_failure_retains_scratch": ("full-failure",),
            process_class + "test_unknown_marker_parent_death_requires_domain_disposal": ("marker-parent-death",),
            process_class + "test_unknown_committed_parent_death_requires_domain_disposal": ("committed-parent-death",),
            process_class + "test_killed_ancestor_cannot_strand_independent_native_worker_group": ("orphan",),
            process_class + "test_independent_supervisor_deadline_and_backpressure_kill_native_workers_without_inheriting_payload": (
                "supervisor-timeout", "backpressure",
            ),
            process_class + "test_commit_follows_actual_payload_eof_and_withheld_commit_cannot_deadlock_writer_close": (
                "commit-after-eof", "withhold-commit", "short-write",
            ),
            group_class + "test_actual_zombie_is_observed_before_its_owning_keeper_consumes_the_wait": ("zombie",),
            group_class + "test_unknown_payload_writer_close_failure_retains_scratch": ("payload-writer-close-failure",),
            group_class + "test_unknown_payload_reader_close_failure_retains_scratch": ("payload-reader-close-failure",),
            group_class + "test_unknown_payload_reader_close_unresolved_retains_scratch": ("payload-reader-close-unresolved",),
        }
        self.assertEqual(controller.PROFILE_FIXTURE_FAILURE_CALLBACK_MODES, callback_modes)
        all_modes = [mode for modes in callback_modes.values() for mode in modes]
        self.assertEqual((len(callback_modes), len(all_modes), len(set(all_modes))), (17, 32, 32))
        self.assertEqual(controller.PROFILE_FIXTURE_FAILURE_MODES, frozenset(all_modes))
        supervisor_id = (process_class
                         + "test_independent_supervisor_deadline_and_backpressure_kill_native_workers_without_inheriting_payload")
        pipe_id = process_class + "test_timeout_observes_a_real_orphaned_pipe_before_cleanup"
        # All callbacks are source-known here: wrong-pair rejection must come
        # from their mode binding, not from an unrelated unknown-ID veto.
        with patch.object(checks, "python_capture_ids", return_value=tuple(callback_modes)):
            for owner, modes in callback_modes.items():
                for mode in modes:
                    record = {**diagnostic, "mode": mode}
                    for claimed in callback_modes:
                        row = {**callback, "id": claimed}
                        value = controller.failure_details(capture([row], stderr=encode(record)), step, paths,
                                                           checks=checks, deadline=1000.0)
                        if claimed == owner:
                            self.assertEqual(value["profile_fixture_failure"], record)
                        else:
                            self.assertNotIn("profile_fixture_failure", value)
                        self.assertEqual(value["returncode"], 1)
            # Repeated failing subtests legitimately retain the same parent ID.
            self.assertEqual(controller.failure_details(capture([callback, callback], stderr=marker),
                step, paths, checks=checks, deadline=1000.0)["profile_fixture_failure"], diagnostic)

        # The native lane must bind the SAME original partition inventory and
        # validated tests-phase record, not just accept a global mode name.
        native_checks = SimpleNamespace(native_partition_ids=lambda *_, **__: tuple(callback_modes))
        native_steps = (
            controller.Step("native-profile-source", parser="native"),
            controller.Step("native-profile-wheel", parser="native"),
        )
        def native_capture(records, *, phase="tests", stderr=marker):
            result = capture([], stderr=stderr)
            envelope = {"schema": 1, "phase": phase, "records": records}
            result.stdout = (controller.NATIVE_DIAGNOSTIC_PREFIX + json.dumps(envelope) + "\n").encode()
            result.persisted = (len(result.stdout), len(stderr))
            return result

        with patch.object(native_checks, "native_partition_ids", return_value=tuple(callback_modes)) as inventory:
            for native_step in native_steps:
                for owner, modes in callback_modes.items():
                    for mode in modes:
                        record = {**diagnostic, "mode": mode}
                        row = {**callback, "id": owner, "returncode": None}
                        value = controller.failure_details(native_capture([row], stderr=encode(record)),
                            native_step, paths, checks=native_checks, deadline=1000.0)
                        self.assertEqual(value["profile_fixture_failure"], record)
                        self.assertEqual(value["native_diagnostic"]["records"], [row])
                        self.assertEqual(value["returncode"], 1)
                        inventory.assert_called_with(ROOT, native_step.native_partition, deadline=1000.0)
                        wrong_owner = next(name for name in callback_modes if name != owner)
                        self.assertNotIn("profile_fixture_failure", controller.failure_details(
                            native_capture([{**row, "id": wrong_owner}], stderr=encode(record)),
                            native_step, paths, checks=native_checks, deadline=1000.0))

            poison_callbacks = [(partition, owner) for partition, owner in _PYTHON_POISON_FIXTURES
                                if owner in callback_modes]
            self.assertEqual(len(poison_callbacks), 8)
            for partition, owner in poison_callbacks:
                mode, = callback_modes[owner]
                record = {**diagnostic, "mode": mode}
                row = {**callback, "id": owner, "returncode": None}
                for gate in ("python-full", "python-wheel"):
                    poison_step = controller.Step(gate, parser="native", native_partition=partition)
                    with patch.object(native_checks, "native_partition_ids", return_value=(owner,)) as poison_inventory:
                        value = controller.failure_details(native_capture([row], stderr=encode(record)),
                            poison_step, paths, checks=native_checks, deadline=1000.0)
                    self.assertEqual(value["profile_fixture_failure"], record)
                    poison_inventory.assert_called_once_with(ROOT, partition, deadline=1000.0)

            native_step = native_steps[0]
            native_row = {**callback, "returncode": None}
            self.assertEqual(controller.failure_details(native_capture([native_row] * 2), native_step, paths,
                checks=native_checks, deadline=1000.0)["profile_fixture_failure"], diagnostic)
            for outcome, category in (("error", "exception"), ("failure", "assertion-error")):
                self.assertEqual(controller.failure_details(
                    native_capture([{**native_row, "outcome": outcome, "category": category}]), native_step, paths,
                    checks=native_checks, deadline=1000.0)["profile_fixture_failure"], diagnostic)
            for records, phase in (
                ([], "tests"),
                ([native_row], "prerequisite"),
                ([{**native_row, "id": "system-code", "outcome": "error"}], "prerequisite"),
                ([{**native_row, "id": "setUpClass (" + identifier.rsplit(".", 1)[0] + ")"}], "tests"),
                ([{**native_row, "id": private}], "tests"),
                ([{**native_row, "outcome": "expected-failure"}], "tests"),
                *(([{**native_row, "outcome": outcome, "category": "none"}], "tests")
                  for outcome in ("skip", "unexpected-success")),
            ):
                value = controller.failure_details(native_capture(records, phase=phase), native_step, paths,
                                                   checks=native_checks, deadline=1000.0)
                self.assertNotIn("profile_fixture_failure", value)
                self.assertNotIn(private, json.dumps(value))
            for wrong_step in (
                controller.Step("other", parser="native"),
                controller.Step("python-full", parser="native", native_partition="healthy"),
                controller.Step("python-wheel", parser="native", native_partition="all"),
                controller.Step("python-full", parser="check", native_partition="poison-full-zero"),
            ):
                self.assertNotIn("profile_fixture_failure", controller.failure_details(native_capture([native_row]),
                    wrong_step, paths, checks=native_checks, deadline=1000.0))
            with patch.object(native_checks, "native_partition_ids", return_value=(private,)):
                self.assertNotIn("profile_fixture_failure", controller.failure_details(native_capture([native_row]),
                    native_step, paths, checks=native_checks, deadline=1000.0))
            with patch.object(native_checks, "native_partition_ids", side_effect=OSError(private)):
                value = controller.failure_details(native_capture([native_row]), native_step, paths,
                                                   checks=native_checks, deadline=1000.0)
                self.assertTrue(value["native_diagnostics_unavailable"])
                self.assertNotIn("profile_fixture_failure", value)
                self.assertNotIn(private, json.dumps(value))
            expired = [False]
            def expired_native_inventory(*_args, **_kwargs):
                expired[0] = True
                raise OSError(private)
            with patch.object(native_checks, "native_partition_ids", side_effect=expired_native_inventory), \
                    patch.object(controller.time, "monotonic", side_effect=lambda: 1000.0 if expired[0] else 999.0), \
                    self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                controller.failure_details(native_capture([native_row]), native_step, paths,
                                           checks=native_checks, deadline=1000.0)
            for interruption in (KeyboardInterrupt(private), SystemExit(7)):
                for failed_capture, failed_step, source_checks in (
                    (capture([callback], stderr=marker), step, checks),
                    (native_capture([native_row]), native_step, native_checks),
                ):
                    with patch.object(controller, "strict_json", side_effect=interruption), \
                            self.assertRaises(type(interruption)) as raised:
                        controller.failure_details(failed_capture, failed_step, paths, checks=source_checks, deadline=1000.0)
                    self.assertIs(raised.exception, interruption)
            with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                controller.parse_capture(native_step, native_capture([native_row]), paths, "macos", native_checks)

        # Exercise the actual verbosity-2 transport boundary: startTest leaves
        # its progress line open while the real fixture publishes its record.
        # An empty emitter sink and a separately fabricated parser input cannot
        # detect a marker accidentally appended to that unfinished progress line.
        from . import profile_process_fixture as fixture
        self.assertEqual(fixture._DRIVER_FAILURE_MODES, frozenset(all_modes))
        inner_error = AssertionError(private)
        inner_stderr = ("Traceback (most recent call last):\n"
                        f'  File "/{private}/tests/workflow/profile_process_fixture.py", line 1199, in driver\n'
                        f"AssertionError: {private}\n").encode("ascii")

        for identifier, mode in ((controller.PROFILE_FIXTURE_FAILURE_ID, "partial-write-failure"),
                                 (supervisor_id, "supervisor-timeout"), (supervisor_id, "backpressure"),
                                 (pipe_id, "pipe-timeout")):
            with self.subTest(real_emitter_mode=mode):
                stream = io.StringIO()
                callback = {**callback, "id": identifier}
                record = {**diagnostic, "mode": mode}

                def emit_then_fail():
                    fixture._report_driver_failure(mode, 1, inner_stderr)
                    raise inner_error

                with patch.object(fixture.sys, "stderr", stream):
                    inner_result = unittest.TextTestRunner(stream=stream, verbosity=2, failfast=True).run(
                        unittest.FunctionTestCase(emit_then_fail))
                self.assertEqual((inner_result.testsRun, len(inner_result.failures), len(inner_result.errors)), (1, 1, 0))
                self.assertFalse(inner_result.wasSuccessful())
                transported = stream.getvalue().encode("ascii")
                self.assertIn(b" ... \n" + controller.PROFILE_FIXTURE_FAILURE_PREFIX.encode("ascii"), transported)
                transported_capture = capture([callback], stderr=transported)
                value = controller.failure_details(transported_capture, step, paths, checks=checks, deadline=1000.0)
                self.assertEqual(value["profile_fixture_failure"], record)
                self.assertEqual(value["returncode"], 1)
                self.assertNotIn(private, json.dumps(value))
                self.assertEqual(controller.failure_details(capture([callback], check="python-wheel", stderr=transported),
                    wheel, paths, checks=checks, deadline=1000.0)["profile_fixture_failure"], record)
                with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                    controller.parse_capture(step, transported_capture, paths, "linux", checks)
                # Removing the delimiter recreates the former progress-line bug.
                misframed = transported.replace(b"\n" + controller.PROFILE_FIXTURE_FAILURE_PREFIX.encode("ascii"),
                                                controller.PROFILE_FIXTURE_FAILURE_PREFIX.encode("ascii"), 1)
                self.assertNotIn("profile_fixture_failure", controller.failure_details(
                    capture([callback], stderr=misframed), step, paths, checks=checks, deadline=1000.0))
        identifier = controller.PROFILE_FIXTURE_FAILURE_ID
        callback = {**callback, "id": identifier}
        for callbacks, changes in (([], {}), ([callback], {"ok": True}),
                                   ([callback], {"check": "python-wheel"}),
                                   ([{**callback, "outcome": "expected-failure"}], {}),
                                   *(([{**callback, "outcome": outcome, "category": "none"}], {})
                                     for outcome in ("skip", "unexpected-success"))):
            self.assertNotIn("profile_fixture_failure", controller.failure_details(
                capture(callbacks, stderr=marker, **changes), step, paths, checks=checks, deadline=1000.0))
        for wrong_step in (controller.Step("python-full", parser="exit"), controller.Step("other", parser="check")):
            self.assertNotIn("profile_fixture_failure", controller.failure_details(
                capture([callback], stderr=marker), wrong_step, paths, checks=checks, deadline=1000.0))
        invalid_records = [
            {**diagnostic, "private": private}, {**diagnostic, "schema": True},
            {**diagnostic, "mode": private}, {**diagnostic, "category": private},
            *({**diagnostic, "returncode": value} for value in (True, 0, 256, -256, "1")),
            {**diagnostic, "locations": diagnostic["locations"] * 5},
            {**diagnostic, "locations": [{"file": "src/../" + private, "line": 1}]},
            *({**diagnostic, "locations": [{"file": diagnostic["locations"][0]["file"], "line": line}]}
              for line in (True, 0, 1000000)),
        ]
        malformed_marker = controller.PROFILE_FIXTURE_FAILURE_PREFIX.encode() + b"not-json\n"
        malformed = [*(encode(record) for record in invalid_records), marker + marker,
                     marker + malformed_marker, malformed_marker + marker,
                     marker.replace(b'"schema": 1', b'"schema": 1,"schema": 1'),
                     controller.PROFILE_FIXTURE_FAILURE_PREFIX.encode() + b"x" * 2048 + b"\n",
                     controller.PROFILE_FIXTURE_FAILURE_PREFIX.encode() + b"\xff\n"]
        for raw in malformed:
            value = controller.failure_details(capture([callback], stderr=raw), step, paths,
                                               checks=checks, deadline=1000.0)
            self.assertNotIn("profile_fixture_failure", value)
            self.assertEqual(value["returncode"], 1)
            self.assertNotIn(private, json.dumps(value))
        # The shared bounded reader must check the original clock even when
        # optional parsing fails after it has consumed the captured record.
        expired = [False]
        def expired_parse(_text):
            expired[0] = True
            raise ValueError(private)
        with patch.object(controller, "strict_json", side_effect=expired_parse), \
                patch.object(controller.time, "monotonic", side_effect=lambda: 1000.0 if expired[0] else 999.0):
            with self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                controller.profile_fixture_failure(marker, deadline=1000.0)
        with patch.object(checks, "python_capture_ids", side_effect=OSError(private)), \
                patch.object(controller.time, "monotonic", return_value=999.0):
            value = controller.failure_details(capture([callback]), step, paths, checks=checks, deadline=1000.0)
            self.assertTrue(value["python_diagnostics_unavailable"])
            self.assertEqual(value["returncode"], 1)
            self.assertNotIn(private, json.dumps(value))
        with patch.object(checks, "python_capture_ids", side_effect=OSError(private)), \
                patch.object(controller.time, "monotonic", return_value=1000.0):
            with self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                controller.failure_details(capture([callback]), step, paths, checks=checks, deadline=1000.0)

    def test_native_storage_observations_require_exact_profile_and_original_finality(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        identifier = "unit.synthetic.StorageContract.test_one"
        step = controller.Step("python-full", parser="check")
        checks = SimpleNamespace(python_capture_ids=lambda *_, **__: (identifier,), linux_allowed_skips=frozenset)
        profile = {"name": "linux-python-full-v1", "logical_file_bytes": 4296015872,
                   "file_data_bytes": 956301312, "tmpfs_mounts": 11, "write_controls": 11,
                   "readonly_errno": 30, "capacity_errno": 28, "capacity_bytes": 16777216,
                   "max_user_namespaces": 0}

        def capture(observation, *, ok=True, finality=True, tests=None, callbacks=()):
            summary = {"check": "python-full", "ok": ok,
                       "tests": tests if tests is not None else [{"id": identifier, "outcome": "ok"}],
                       "details": {"storage_profile": observation, "failure_callbacks": list(callbacks)}}
            raw = ("MRK_CHECK_RESULT=" + json.dumps(summary) + "\n").encode()
            return SimpleNamespace(ok=ok, returncode=0 if ok else 1, waited=True,
                                   stdout_eof=True, stderr_eof=True, domain_finality=finality,
                                   primary_error=None if ok else "command failed", cleanup_errors=(),
                                   stdout=raw, stderr=b"", persisted=(len(raw), 0), duration=0.1,
                                   timed_out=False, cancelled=False)

        result = controller.parse_capture(step, capture(profile), paths, "linux", checks)
        self.assertTrue(result.ok)
        self.assertEqual(result.details["summary"]["details"]["storage_profile"], profile)
        failed = controller.failure_details(capture(profile, ok=False), step, paths, platform="linux")
        self.assertEqual(failed["storage_profile"], profile)
        self.assertEqual(failed["returncode"], 1)
        self.assertNotIn("storage_profile", controller.failure_details(
            capture(profile, ok=False), step, paths, platform="macos"))

        bad_profiles = [None, {}, {**profile, "raw_message": "private"},
                        {**profile, "max_user_namespaces": False}, {**profile, "max_user_namespaces": 1}]
        bad_profiles.extend({key: value for key, value in profile.items() if key != missing} for missing in profile)
        bad_profiles.extend({**profile, key: str(value)} for key, value in profile.items() if type(value) is int)
        for index, bad in enumerate(bad_profiles):
            with self.subTest(mutation=index):
                with self.assertRaisesRegex(controller.VerificationError, "PYTHON_STORAGE_PROFILE_MISSING_OR_INVALID"):
                    controller.parse_capture(step, capture(bad), paths, "linux", checks)
                details = controller.failure_details(capture(bad, ok=False), step, paths, platform="linux")
                self.assertEqual(details["returncode"], 1)
                self.assertNotIn("storage_profile", details)
                self.assertNotIn("private", json.dumps(details))
        with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
            controller.parse_capture(step, capture(profile, finality=False), paths, "linux", checks)
        with self.assertRaisesRegex(controller.VerificationError, "PYTHON_COMPLETION_INVENTORY"):
            controller.parse_capture(step, capture(profile, tests=[{
                "id": identifier, "outcome": "ok", "extra": "private"}]), paths, "linux", checks)
        for callbacks in ([{"id": identifier, "outcome": "error", "category": "os-error", "errno": 27}],
                          [{"id": "private", "outcome": "error", "category": "os-error", "errno": 27}],
                          [{"id": identifier, "raw_message": "private"}], [None]):
            with self.subTest(success_failure_callbacks=callbacks):
                with self.assertRaisesRegex(controller.VerificationError, "PYTHON_FAILURE_CALLBACKS_ON_SUCCESS"):
                    controller.parse_capture(step, capture(profile, callbacks=callbacks), paths, "linux", checks)

    def test_complete_fixed_gate_inventory_cannot_omit_duplicate_or_reorder_a_step(self):
        controller = controller_module()
        before = ("source-copy", "source-environment", "source-dependencies", "bundler", "bundle-install",
                  "editable-install", "source-freeze", "source-pip-check", "bundle-check")
        ruby = ("ruby-support", "ruby-native-spawn", "ruby-native-owner", "ruby-native-capture", "ruby-native-signal-observation",
                "ruby-play_store", "ruby-play_lanes", "ruby-apple_store",
                "ruby-apple_lanes", "ruby-apple_production", "ruby-apple_production_lane", "ruby-apple_asset_upload",
                "ruby-ios_upload_validation", "ruby-android_upload_validation", "ruby-workflow-yaml", "ruby-supply-wif")
        wheel = ("wheel-copy", "wheel-build", "wheel-inspect", "wheel-environment", "wheel-pip", "wheel-install",
                 "wheel-freeze", "wheel-pip-check")
        compatibility_source = ("python-compat-312-source", "python-compat-313-source", "python-compat-314-source")
        compatibility_wheel = ("python-compat-312-wheel", "python-compat-313-wheel", "python-compat-314-wheel")
        expected = {
            "linux": (*before, "native-process-abi-source", *compatibility_source, "python-full", *ruby,
                      "ruby-packaged-capture-source", "fastfile", "actionlint", "jdk-signers", *wheel,
                      "native-process-abi-wheel", *compatibility_wheel, "wheel-smoke", "wheel-consumer",
                      "ruby-packaged-capture-wheel", "python-wheel", "source-integrity"),
            "macos": (*before, "native-tools", "native-process-abi-source", *compatibility_source,
                      "ruby-native-spawn", "ruby-native-owner", "ruby-native-capture",
                      "ruby-native-signal-observation",
                      "ruby-ios_upload_validation", "ruby-android_upload_validation", "ruby-packaged-capture-source",
                      "native-profile-source", *wheel, "native-process-abi-wheel", *compatibility_wheel,
                      "wheel-smoke", "wheel-consumer", "ruby-packaged-capture-wheel", "native-profile-wheel", "source-integrity"),
        }
        for platform in expected:
            steps = controller.catalog(fixture_paths(controller), platform, deadline=1000.0)
            with self.subTest(platform=platform):
                self.assertEqual(tuple(step.id for step in steps), expected[platform])
                self.assertEqual(controller.required_gate_ids(platform), expected[platform])
                self.assertEqual(len(steps), 51 if platform == "linux" else 39)
                if platform == "macos":
                    ids = tuple(step.id for step in steps)
                    for gate in ("ruby-native-capture", "ruby-native-signal-observation",
                                 "ruby-ios_upload_validation", "ruby-android_upload_validation"):
                        self.assertLess(ids.index("native-tools"), ids.index(gate))
                        self.assertLess(ids.index(gate), ids.index("native-profile-source"))
                    self.assertLess(ids.index("native-profile-source"), ids.index("native-profile-wheel"))
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

    def test_minitest_parser_preserves_completion_identity_across_body_logging(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        expected = ("SyntheticTests#test_first", "SyntheticTests#test_second")
        step = controller.Step("ruby-play_store", parser="minitest", expected_tests=2)
        footer = "\nFinished in 0.03s.\n2 runs, 5 assertions, 0 failures, 0 errors, 0 skips\n"
        first = expected[0] + " = 0.01 s = .\n"
        second = expected[1] + " = 0.02 s = .\n"
        clean = first + second
        noisy = (expected[0] + " = ordinary body log\ntext = .\n0.01 s = .\n"
                 + expected[1] + " = \n[fixture] still running\nmore logging\n0.02 s = .\n")

        def capture(text, **changes):
            values = dict(ok=True, returncode=0, waited=True, stdout_eof=True, stderr_eof=True,
                          domain_finality=True, primary_error=None, cleanup_errors=(), stdout=text.encode(),
                          stderr=b"", duration=0.03, timed_out=False, cancelled=False)
            values.update(changes)
            values.setdefault("persisted", (len(values["stdout"]), len(values["stderr"])))
            return SimpleNamespace(**values)

        with patch.object(controller, "ruby_expected_ids", return_value=expected):
            for transcript in (clean, noisy):
                actual = controller.parse_capture(step, capture(transcript + footer), paths, "linux", None)
                self.assertEqual(actual.details["completed"], list(expected))
                self.assertEqual(actual.details["assertions"], 5)
                completed, structure = controller.minitest_records(transcript + footer, expected)
                self.assertEqual(completed, list(expected))
                self.assertEqual(structure["reasons"], [])
                self.assertEqual(structure["start_records"], [
                    {"ordinal": index + 1, "id": identifier, "terminal": "success"}
                    for index, identifier in enumerate(expected)])
                self.assertEqual(structure["adverse_records"], [])
                self.assertEqual(structure["start_records_omitted"], 0)
                self.assertEqual(structure["adverse_records_omitted"], 0)
            cases = (
                expected[0] + " = missing terminal\n" + second + footer,
                first + expected[1] + " = missing terminal\n" + footer,
                first + first + footer,
                clean.replace("SyntheticTests#test_second", "PRIVATE_UNKNOWN#test_secret") + footer,
                clean.replace("0.01 s = .", "0.01 s = .\n0.01 s = .") + footer,
                *(clean.replace("0.01 s = .", "0.01 s = " + status) + footer for status in ("F", "E", "S", "?")),
                clean + footer + first,
                clean + footer + footer,
                "0.01 s = .\n" + clean + footer,
                clean + footer + "0.01 s = .\n",
                clean.replace("0.01 s", "nan s") + footer,
                second + footer,
            )
            for transcript in cases:
                with self.subTest(transcript=transcript), self.assertRaises(controller.VerificationError):
                    controller.parse_capture(step, capture(transcript), paths, "linux", None)
            diagnostic = controller.failure_details(capture(cases[3]), step, paths)
            structure = diagnostic["minitest_structure"]
            self.assertEqual(structure["unknown_count"], 1)
            self.assertEqual(structure["missing_ids"], [expected[1]])
            self.assertNotIn("PRIVATE_UNKNOWN", json.dumps(diagnostic))
            self.assertNotIn("test_secret", json.dumps(diagnostic))
            self.assertEqual(diagnostic["minitest_observations"], [[2, 5, 0, 0, 0]])

            interrupted = (expected[0] + " = PRIVATE_MESSAGE\n0.01 s = F\n"
                           + expected[1] + " = unfinished\n")
            stdout_locations = "/PRIVATE_ROOT/fastlane/native_upload_process.rb:70: PRIVATE_MESSAGE\n"
            stderr_locations = ("/PRIVATE_ROOT/tests/workflow/test_native_upload_process.rb:31: PRIVATE_MESSAGE\n"
                                "/PRIVATE_ROOT/fastlane/private_unknown.rb:99: PRIVATE_MESSAGE\n"
                                "/PRIVATE_ROOT/tests/workflow/private_unknown.rb:99: PRIVATE_MESSAGE\n")
            # Stderr lookalikes cannot supply stdout's missing footer or names.
            stderr_text = clean + footer + expected[0] + ":\n" + stderr_locations
            partial = capture(interrupted + stdout_locations, stderr=stderr_text.encode())
            with self.assertRaisesRegex(controller.VerificationError, "MINITEST_RESULT_MISSING"):
                controller.parse_capture(step, partial, paths, "macos", None)
            diagnostic = controller.failure_details(partial, step, paths)
            interrupted_rows = [
                {"ordinal": 1, "id": expected[0], "terminal": "failure"},
                {"ordinal": 2, "id": expected[1], "terminal": "missing"},
            ]
            self.assertEqual(diagnostic["minitest_structure"], {
                "reasons": ["footer-count", "missing-ids", "terminal-count", "terminal-status"],
                "expected_count": 2, "started_count": 2, "completed_count": 0,
                "missing_ids": list(expected), "duplicate_ids": [], "unknown_count": 0,
                "start_records": interrupted_rows, "adverse_records": interrupted_rows,
                "start_records_omitted": 0, "adverse_records_omitted": 0,
            })
            self.assertEqual(diagnostic["ruby_locations"], [
                ("fastlane/native_upload_process.rb", 70),
                ("tests/workflow/test_native_upload_process.rb", 31),
            ])
            self.assertEqual(diagnostic["failed_tests"], [])
            self.assertEqual(diagnostic["minitest_observations"], [])
            for private in ("PRIVATE_ROOT", "PRIVATE_MESSAGE", "private_unknown"):
                self.assertNotIn(private, json.dumps(diagnostic))
            with self.assertRaisesRegex(controller.VerificationError, "MINITEST_COMPLETION_INVENTORY"):
                controller.parse_capture(step, capture(first + footer, stderr=second.encode()), paths, "macos", None)

            for terminal, classification, reason in (
                ("0.01 s = .\n", "success", None),
                ("0.01 s = F\n", "failure", "terminal-status"),
                ("0.01 s = E\n", "error", "terminal-status"),
                ("0.01 s = S\n", "skip", "terminal-status"),
                ("0.01 s = ?\n", "missing", "terminal-count"),
                ("0.01 s = .\n0.01 s = .\n", "ambiguous", "terminal-count"),
            ):
                with self.subTest(classification=classification):
                    completed, structure = controller.minitest_records(
                        expected[0] + " = " + terminal + second + footer, expected)
                    row = {"ordinal": 1, "id": expected[0], "terminal": classification}
                    self.assertEqual(structure["start_records"], [
                        row, {"ordinal": 2, "id": expected[1], "terminal": "success"}])
                    self.assertEqual(structure["adverse_records"], [] if reason is None else [row])
                    self.assertEqual(completed, list(expected) if reason is None else [expected[1]])
                    self.assertEqual(structure["reasons"], [] if reason is None else ["missing-ids", reason])

            _, duplicate = controller.minitest_records(first + first + footer, expected)
            self.assertEqual(duplicate["start_records"], [
                {"ordinal": ordinal, "id": expected[0], "terminal": "success"} for ordinal in (1, 2)])
            self.assertEqual(duplicate["adverse_records"], [])
            self.assertEqual(duplicate["reasons"], ["duplicate-id", "missing-ids"])
            completed, after_footer = controller.minitest_records(clean + footer + first, expected)
            after_row = {"ordinal": 3, "id": expected[0], "terminal": "after-footer"}
            self.assertEqual(after_footer["start_records"], [
                {"ordinal": index + 1, "id": identifier, "terminal": "success"}
                for index, identifier in enumerate(expected)] + [after_row])
            self.assertEqual(after_footer["adverse_records"], [after_row])
            self.assertEqual(completed, list(expected))
            self.assertEqual(after_footer["reasons"], ["duplicate-id", "record-after-footer", "record-count"])

            private_start = "PRIVATE_UNKNOWN#test_secret = 0.01 s = F\n"
            _, unknown = controller.minitest_records(first + private_start + second + footer, expected)
            self.assertEqual(unknown["start_records"], [
                {"ordinal": 1, "id": expected[0], "terminal": "success"},
                {"ordinal": 3, "id": expected[1], "terminal": "success"},
            ])
            self.assertEqual(unknown["adverse_records"], [])
            self.assertEqual(unknown["unknown_count"], 1)
            self.assertEqual(unknown["reasons"], ["record-count", "terminal-status", "unknown-id"])
            self.assertNotIn("PRIVATE_UNKNOWN", json.dumps(unknown))
            self.assertNotIn("test_secret", json.dumps(unknown))

            many = tuple(f"SyntheticTests#test_{index:02d}" for index in range(35))
            many_text = ("".join(identifier + " = 0.01 s = .\n" for identifier in many[:16])
                         + private_start + "".join(identifier + " = 0.01 s = F\n" for identifier in many[16:]))
            completed, bounded = controller.minitest_records(many_text, many)
            self.assertEqual(completed, list(many[:16]))
            self.assertEqual(bounded["start_records"], [
                {"ordinal": index + 1, "id": identifier, "terminal": "success"}
                for index, identifier in enumerate(many[:16])])
            self.assertEqual(bounded["adverse_records"], [
                {"ordinal": index + 18, "id": identifier, "terminal": "failure"}
                for index, identifier in enumerate(many[16:32])])
            self.assertEqual(bounded["start_records_omitted"], 19)
            self.assertEqual(bounded["adverse_records_omitted"], 3)
            self.assertEqual(bounded["started_count"], 36)
            self.assertEqual(bounded["unknown_count"], 1)
            self.assertNotIn("PRIVATE_UNKNOWN", json.dumps(bounded))
            self.assertNotIn("test_secret", json.dumps(bounded))

            stdout_rows = [("fastlane/native_upload_process.rb", line) for line in range(60, 30, -1)]
            stderr_rows = [("fastlane/native_process_spawn.rb", line) for line in range(20, 0, -1)] + stdout_rows[-1:]

            def location_text(rows):
                return "".join(f"/PRIVATE_ROOT/{name}:{line}: PRIVATE_MESSAGE\n" for name, line in rows)

            diagnostic = controller.failure_details(capture(interrupted + location_text(stdout_rows),
                stderr=(location_text(stderr_rows) + stderr_locations).encode()), step, paths)
            self.assertEqual(diagnostic["ruby_locations"], sorted(set(stdout_rows + stderr_rows))[:32])
            for private in ("PRIVATE_ROOT", "PRIVATE_MESSAGE", "private_unknown"):
                self.assertNotIn(private, json.dumps(diagnostic))

            # An inner bootstrap refusal is observed only in the three fixture
            # suites and an adverse capture. The record never supplies receipts.
            bootstrap = {"schema": 1, "stage": "configuration", "condition": "directory_identity"}
            def bootstrap_bytes(record):
                return (controller.FIXTURE_BOOTSTRAP_FAILURE_PREFIX + json.dumps(record) + "\n").encode()
            marker = bootstrap_bytes(bootstrap)
            self.assertEqual(controller.fixture_bootstrap_failure(marker[:-1]), bootstrap)
            with patch.object(controller, "ruby_capture_ids", return_value=expected):
                for gate in ("ruby-native-capture", "ruby-ios_upload_validation", "ruby-android_upload_validation"):
                    native_step = controller.Step(gate, parser="minitest", expected_tests=2)
                    failed_capture = capture(interrupted, stderr=marker, ok=False, returncode=1)
                    detail = controller.failure_details(failed_capture, native_step, paths)
                    self.assertEqual(detail["fixture_bootstrap_failure"], bootstrap)
                    self.assertEqual(detail["returncode"], 1)
                    with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                        controller.parse_capture(native_step, failed_capture, paths, "macos", None)
                    self.assertNotIn("fixture_bootstrap_failure", controller.failure_details(
                        capture(clean + footer, stderr=marker), native_step, paths))
                # A semantic failure after a genuine rc0 still remains adverse.
                self.assertEqual(controller.failure_details(capture(interrupted, stderr=marker),
                    native_step, paths)["fixture_bootstrap_failure"], bootstrap)
                self.assertNotIn("fixture_bootstrap_failure", controller.failure_details(
                    failed_capture, step, paths))
                invalid_bootstraps = [
                    {**bootstrap, "pid": 123}, {**bootstrap, "private": "PRIVATE_ROOT"},
                    {**bootstrap, "schema": True}, {**bootstrap, "schema": 2},
                    {**bootstrap, "stage": "PRIVATE_ROOT"}, {**bootstrap, "stage": []},
                    {**bootstrap, "condition": "PRIVATE_MESSAGE"},
                    {**bootstrap, "condition": "fifo_open"}, {**bootstrap, "condition": False},
                ]
                invalid_markers = [*(bootstrap_bytes(record) for record in invalid_bootstraps), marker + marker,
                    marker.replace(b'"schema": 1', b'"schema": 1,"schema": 1'),
                    controller.FIXTURE_BOOTSTRAP_FAILURE_PREFIX.encode() + b"x" * 256 + b"\n",
                    controller.FIXTURE_BOOTSTRAP_FAILURE_PREFIX.encode() + b"\xff\n"]
                for raw in invalid_markers:
                    detail = controller.failure_details(capture(interrupted, stderr=raw, ok=False, returncode=1),
                                                        native_step, paths)
                    self.assertNotIn("fixture_bootstrap_failure", detail)
                    self.assertEqual(detail["returncode"], 1)
                    self.assertNotIn("PRIVATE_ROOT", json.dumps(detail))
                    self.assertNotIn("PRIVATE_MESSAGE", json.dumps(detail))
                with patch.object(controller.time, "monotonic", return_value=100.0), \
                        self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                    controller.failure_details(failed_capture, native_step, paths, deadline=100.0)

            target = "NativeUploadValidationTest#test_raw_collector_keeps_actual_failed_transcripts_status_and_first_error"
            ruby_ids = tuple(sorted((*expected, target)))
            isolated_step = controller.Step("ruby-native-capture", parser="minitest", expected_tests=3,
                                            native_partition="healthy")
            isolated_record = {"schema": 1, "stage": "capture-contract", "category": "assertion-error"}
            isolated_checkpoints = (
                "capture-primary", "capture-retained-files", "capture-retained-lifetime", "capture-retained-streams",
                "capture-record-read", "capture-record-status", "capture-record-flags", "capture-dispatch-contract",
                "capture-dispatch-environment", "capture-source-identities", "capture-stream-identities",
                "capture-child-receipt", "capture-creator", "capture-lifetime-endpoints", "capture-provenance",
                "capture-bootstrap-header", "capture-bootstrap-request", "capture-bootstrap-sources", "capture-bootstrap-directory",
                "capture-bootstrap-dispatch", "capture-bootstrap-descriptors", "capture-bootstrap-configuration",
                "capture-bootstrap-ready", "capture-bootstrap-grant", "capture-bootstrap-exec",
                "capture-bootstrap-directory-finality", "capture-error-contract", "capture-readiness", "capture-transcript",
                "capture-termination",
            )
            isolated_stages = (
                "cli-admission", "request-contract", "source-bindings", "deadline-bound", "collector-execution",
                "capture-contract", "cleanup-contract", "reporting-contract", "custody-contract", "final-recheck",
                "proof-publication", *isolated_checkpoints,
            )
            isolated_categories = (
                "assertion-error", "fixture-error", "native-lifecycle-error", "io-error", "os-error", "interrupt",
                "system-exit", "json-parser-error", "key-error", "no-method-error", "type-error", "argument-error", "runtime-error",
                "standard-error", "exception", "unknown",
            )
            self.assertEqual(controller.ISOLATED_COLLECTOR_FAILURE_STAGES, isolated_stages)
            self.assertEqual(controller.ISOLATED_COLLECTOR_FAILURE_CATEGORIES, isolated_categories)
            self.assertEqual((len(isolated_stages), len(set(isolated_stages)),
                              len(isolated_categories), len(set(isolated_categories))), (41, 41, 16, 16))
            def isolated_bytes(record):
                return (controller.ISOLATED_COLLECTOR_FAILURE_PREFIX
                        + json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
            isolated_marker = isolated_bytes(isolated_record)
            target_failure = target + " = PRIVATE_MESSAGE\n0.01 s = F\n"
            failed_footer = "\n3 runs, 5 assertions, 1 failures, 0 errors, 0 skips\n"
            isolated_stdout = clean + target_failure + failed_footer
            # Both inventory seams remain inert, including wrong-gate checks.
            # No Ruby source read, fixture entry or native operation occurs here.
            with patch.object(controller, "ruby_expected_ids", return_value=ruby_ids), \
                    patch.object(controller, "ruby_capture_ids", return_value=ruby_ids), \
                    patch.object(controller.time, "monotonic", return_value=999.0):
                for terminal in ("F", "E"):
                    transcript = isolated_stdout if terminal == "F" else isolated_stdout.replace(
                        "0.01 s = F", "0.01 s = E").replace("1 failures, 0 errors", "0 failures, 1 errors")
                    failed_capture = capture(transcript, stderr=isolated_marker, ok=False, returncode=1)
                    with patch.object(controller, "minitest_records", wraps=controller.minitest_records) as scans:
                        detail = controller.failure_details(failed_capture, isolated_step, paths, deadline=1000.0)
                    self.assertEqual([call.args for call in scans.call_args_list],
                                     [(transcript, ruby_ids), (transcript, (target,))])
                    self.assertEqual([call.kwargs for call in scans.call_args_list], [{"deadline": 1000.0}] * 2)
                    self.assertEqual(detail["isolated_collector_failure"], isolated_record)
                    self.assertEqual(detail["returncode"], 1)
                    self.assertEqual(detail["minitest_structure"]["expected_count"], len(ruby_ids))
                    self.assertEqual(detail["minitest_structure"]["unknown_count"], 0)
                    self.assertNotIn("PRIVATE_MESSAGE", json.dumps(detail))
                    with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                        controller.parse_capture(isolated_step, failed_capture, paths, "macos", None)

                # Finite refinements keep the SAME schema/cap/adverse target.
                # Class precedence belongs to the Ruby producer; these two
                # independent enums need no redundant Cartesian matrix.
                refinements = [{**isolated_record, "stage": stage, "category": "standard-error"}
                               for stage in isolated_checkpoints]
                refinements += [{**isolated_record, "stage": "capture-record-read", "category": category}
                                for category in isolated_categories[7:13]]
                for record in refinements:
                    raw = isolated_bytes(record)
                    self.assertLessEqual(len(raw), 256)
                    detail = controller.failure_details(capture(isolated_stdout, stderr=raw, ok=False, returncode=1),
                                                        isolated_step, paths, deadline=1000.0)
                    self.assertEqual(detail["isolated_collector_failure"], record)
                    self.assertEqual(detail["returncode"], 1)

                # Actual F/E structure remains adverse even after a genuine rc0;
                # a marker alone cannot relabel a clean successful callback.
                self.assertEqual(controller.failure_details(capture(isolated_stdout, stderr=isolated_marker),
                    isolated_step, paths)["isolated_collector_failure"], isolated_record)
                success_stdout = isolated_stdout.replace("0.01 s = F", "0.01 s = .").replace("1 failures", "0 failures")
                self.assertNotIn("isolated_collector_failure", controller.failure_details(
                    capture(success_stdout, stderr=isolated_marker), isolated_step, paths))
                self.assertTrue(controller.parse_capture(isolated_step, capture(success_stdout, stderr=isolated_marker),
                                                         paths, "macos", None).ok)
                self.assertNotIn("isolated_collector_failure", controller.failure_details(
                    capture(isolated_stdout + isolated_marker.decode("ascii"), ok=False, returncode=1),
                    isolated_step, paths))
                for transcript in (
                    clean + failed_footer,
                    clean + target + ":\n" + failed_footer,
                    clean + target + " = unfinished\n" + failed_footer,
                    isolated_stdout.replace("0.01 s = F", "0.01 s = S"),
                    isolated_stdout.replace("0.01 s = F", "0.01 s = .\n0.01 s = F"),
                    clean + target_failure * 2 + failed_footer,
                    clean + failed_footer + target_failure,
                    success_stdout.replace(first, first.replace("0.01 s = .", "0.01 s = F")),
                ):
                    self.assertNotIn("isolated_collector_failure", controller.failure_details(
                        capture(transcript, stderr=isolated_marker, ok=False, returncode=1), isolated_step, paths))
                with patch.object(controller, "ruby_capture_ids", return_value=expected):
                    self.assertNotIn("isolated_collector_failure", controller.failure_details(
                        capture(isolated_stdout, stderr=isolated_marker, ok=False, returncode=1), isolated_step, paths))
                for wrong_step in (
                    dataclasses.replace(isolated_step, id="ruby-native-owner"),
                    dataclasses.replace(isolated_step, id="ruby-play_store"),
                    dataclasses.replace(isolated_step, native_partition="all"),
                    dataclasses.replace(isolated_step, native_partition="native-setup-no-cleanup"),
                    dataclasses.replace(isolated_step, parser="exit"),
                ):
                    self.assertNotIn("isolated_collector_failure", controller.failure_details(
                        capture(isolated_stdout, stderr=isolated_marker, ok=False, returncode=1), wrong_step, paths))

                # Global first16 projections are not the target's complete
                # history. Reuse the full original scan, not truncated lists.
                many_ids = tuple(f"SyntheticTests#test_{index:02d}" for index in range(17))
                many_stdout = "".join(name + " = 0.01 s = .\n" for name in many_ids)
                with patch.object(controller, "ruby_capture_ids", return_value=tuple(sorted((*many_ids, target)))):
                    detail = controller.failure_details(capture(many_stdout + target_failure,
                        stderr=isolated_marker, ok=False, returncode=1), isolated_step, paths)
                    self.assertGreater(detail["minitest_structure"]["start_records_omitted"], 0)
                    self.assertEqual(detail["isolated_collector_failure"], isolated_record)
                    self.assertNotIn("isolated_collector_failure", controller.failure_details(
                        capture(target_failure + many_stdout + target_failure, stderr=isolated_marker,
                                ok=False, returncode=1), isolated_step, paths))

                invalid_isolated = [
                    {key: value for key, value in isolated_record.items() if key != "category"},
                    {**isolated_record, "private": "PRIVATE_ROOT"}, {**isolated_record, "pid": 123},
                    *({**isolated_record, "schema": value} for value in (True, 1.0, 2, "1")),
                    *({**isolated_record, "stage": value} for value in ([], "PRIVATE_ROOT", "configuration")),
                    *({**isolated_record, "category": value} for value in (False, "PRIVATE_MESSAGE", "none")),
                    {key: isolated_record[key] for key in ("category", "schema", "stage")},
                ]
                prefix = controller.ISOLATED_COLLECTOR_FAILURE_PREFIX.encode("ascii")
                malformed_marker = prefix + b"not-json\n"
                invalid_markers = [*(isolated_bytes(record) for record in invalid_isolated),
                    isolated_marker * 2, isolated_marker + malformed_marker, malformed_marker + isolated_marker,
                    isolated_marker.replace(b'"schema":1', b'"schema":1,"schema":1'),
                    isolated_marker.replace(b'"schema":1', b'"schema": 1'),
                    isolated_marker.replace(b"capture-contract", br"capture\u002dcontract"),
                    prefix + b"x" * 256 + b"\n", prefix + b"\xff\n", isolated_marker[:-1],
                    isolated_marker[:-1] + b"\r\n", b"progress " + isolated_marker,
                ]
                for raw in invalid_markers:
                    detail = controller.failure_details(capture(isolated_stdout, stderr=raw, ok=False, returncode=1),
                                                        isolated_step, paths, deadline=1000.0)
                    self.assertNotIn("isolated_collector_failure", detail)
                    self.assertEqual(detail["returncode"], 1)
                    for private in ("PRIVATE_ROOT", "PRIVATE_MESSAGE"):
                        self.assertNotIn(private, json.dumps(detail))

                # Optional malformed parsing, target scanning and cancellation
                # cannot absorb or renew the original aggregate cutoff.
                expired = [False]
                def expired_isolated_parse(_text):
                    expired[0] = True
                    raise ValueError("PRIVATE_MESSAGE")
                with patch.object(controller, "strict_json", side_effect=expired_isolated_parse), \
                        patch.object(controller.time, "monotonic", side_effect=lambda: 1000.0 if expired[0] else 999.0), \
                        self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                    controller.failure_details(capture(isolated_stdout, stderr=isolated_marker, ok=False, returncode=1),
                                               isolated_step, paths, deadline=1000.0)
                expired[0] = False
                original_scan = controller.minitest_records
                def expire_target_scan(text, identifiers, *, deadline):
                    if identifiers == (target,):
                        expired[0] = True
                    return original_scan(text, identifiers, deadline=deadline)
                with patch.object(controller, "minitest_records", side_effect=expire_target_scan), \
                        patch.object(controller.time, "monotonic", side_effect=lambda: 1000.0 if expired[0] else 999.0), \
                        self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                    controller.failure_details(capture(isolated_stdout, stderr=isolated_marker, ok=False, returncode=1),
                                               isolated_step, paths, deadline=1000.0)
                for interruption in (KeyboardInterrupt("PRIVATE_MESSAGE"), SystemExit(7)):
                    with patch.object(controller, "strict_json", side_effect=interruption), \
                            self.assertRaises(type(interruption)) as raised:
                        controller.failure_details(capture(isolated_stdout, stderr=isolated_marker, ok=False, returncode=1),
                                                   isolated_step, paths, deadline=1000.0)
                    self.assertIs(raised.exception, interruption)

            primary_class = "NativeUploadValidationTest#"
            primary_modes = {
                primary_class + "test_unexpected_pre_entry_failures_preserve_original_through_real_cleanup": tuple(
                    f"native-proof-{boundary}-{kind}-{secondary}"
                    for boundary in ("publication", "readiness", "watchdog")
                    for kind in ("standard", "io", "interrupt", "system-exit")
                    for secondary in ("none", "close")
                ),
                primary_class + "test_unexpected_primary_outlives_late_teardown_and_lookalike_diagnostics": (
                    "native-proof-late-cleanup", "native-proof-lookalike",
                ),
                primary_class + "test_first_close_requires_the_actual_intentional_error_not_redacted_lookalike": (
                    "native-proof-entered-io",
                ),
                primary_class + "test_nested_lifetime_preserves_pre_grant_ioerror_without_native_acquisition": (
                    "native-proof-frame-io", "native-proof-frame-io-close",
                ),
            }
            predicates = ("case", "proof-failures", "proof-status", "result-kind", "driver-status")
            proof_labels = (
                "actual failed native result", "one real injection/final boundary", "framePublishedBeforeFault",
                "outerPrimarySameObject", "nestedPrimarySameObject", "taskPrimarySameObject", "originalMessagePreserved",
                "originalStatusPreserved", "originalNotIntentional", "actualTaskJoins", "actualDescriptorsClosed",
                "secondary identity", "ownedDescriptorsClosed", "watchdogJoined", "tasksJoined", "injectorsJoined",
                "handlersRestored", "registryInactive", "no pending cancellation", "unchanged IOError redaction",
                "actual non-IOError return", "native cleanup without fixture fallback", "actual capture finality", "first-close boundary",
            )
            io_modes = {f"native-proof-{boundary}-io-{secondary}"
                        for boundary in ("publication", "readiness", "watchdog") for secondary in ("none", "close")}
            io_modes.update(("native-proof-entered-io", "native-proof-frame-io", "native-proof-frame-io-close"))
            all_primary_modes = [mode for modes in primary_modes.values() for mode in modes]
            self.assertEqual(controller.NATIVE_PRIMARY_FAILURE_CALLBACK_MODES, primary_modes)
            self.assertEqual((len(primary_modes), len(all_primary_modes), len(set(all_primary_modes))), (4, 29, 29))
            self.assertEqual(controller.NATIVE_PRIMARY_FAILURE_MODES, frozenset(all_primary_modes))
            self.assertEqual(controller.NATIVE_PRIMARY_IO_MODES, frozenset(io_modes))
            self.assertEqual(controller.NATIVE_PRIMARY_FAILURE_PREDICATES, predicates)
            self.assertEqual(controller.NATIVE_PRIMARY_PROOF_FAILURES, proof_labels)

            def primary_bytes(record):
                return (controller.NATIVE_PRIMARY_FAILURE_PREFIX
                        + json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")

            primary_ids = tuple(sorted((*expected, *primary_modes)))
            primary_step = controller.Step("ruby-native-capture", parser="minitest", expected_tests=len(primary_ids),
                                           native_partition="healthy")
            primary_target = next(iter(primary_modes))
            primary_record = {"schema": 1, "mode": "native-proof-publication-standard-none",
                              "failedPredicates": ["proof-failures"], "proofFailures": ["actual capture finality"]}
            primary_marker = primary_bytes(primary_record)
            primary_target_failure = primary_target + " = PRIVATE_MESSAGE\n0.01 s = F\n"
            primary_footer = "\n6 runs, 9 assertions, 1 failures, 0 errors, 0 skips\n"
            primary_stdout = clean + primary_target_failure + primary_footer
            with patch.object(controller, "ruby_expected_ids", return_value=primary_ids), \
                    patch.object(controller, "ruby_capture_ids", return_value=primary_ids), \
                    patch.object(controller.time, "monotonic", return_value=999.0):
                for owner, modes in primary_modes.items():
                    for mode in modes:
                        # The two branch labels are mutually exclusive; the
                        # actual mode admits at most23 ordered proof failures.
                        excluded = "actual non-IOError return" if mode in io_modes else "unchanged IOError redaction"
                        labels = [label for label in proof_labels if label != excluded]
                        record = {"schema": 1, "mode": mode, "failedPredicates": list(predicates), "proofFailures": labels}
                        raw = primary_bytes(record)
                        self.assertEqual(len(labels), 23)
                        self.assertLessEqual(len(raw), 2048)
                        transcript = clean + owner + " = 0.01 s = F\n" + primary_footer
                        detail = controller.failure_details(capture(transcript, stderr=raw, ok=False, returncode=1),
                                                            primary_step, paths, deadline=1000.0)
                        self.assertEqual(detail["native_primary_failure"], record)
                        self.assertEqual(detail["returncode"], 1)
                        other = next(name for name in primary_modes if name != owner)
                        wrong_pair = clean + owner + " = 0.01 s = .\n" + other + " = 0.01 s = F\n" + primary_footer
                        self.assertNotIn("native_primary_failure", controller.failure_details(
                            capture(wrong_pair, stderr=raw, ok=False, returncode=1), primary_step, paths, deadline=1000.0))
                        self.assertIsNone(controller.native_primary_failure(primary_bytes({**record,
                            "proofFailures": [excluded]}), deadline=1000.0))

                for terminal in ("F", "E"):
                    transcript = primary_stdout.replace("0.01 s = F", "0.01 s = " + terminal)
                    failed_capture = capture(transcript, stderr=primary_marker, ok=False, returncode=1)
                    with patch.object(controller, "minitest_records", wraps=controller.minitest_records) as scans:
                        detail = controller.failure_details(failed_capture, primary_step, paths, deadline=1000.0)
                    self.assertEqual([call.args for call in scans.call_args_list],
                                     [(transcript, primary_ids), (transcript, (primary_target,))])
                    self.assertEqual([call.kwargs for call in scans.call_args_list], [{"deadline": 1000.0}] * 2)
                    self.assertEqual(detail["native_primary_failure"], primary_record)
                    self.assertEqual(detail["returncode"], 1)
                    self.assertNotIn("PRIVATE_MESSAGE", json.dumps(detail))
                    with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                        controller.parse_capture(primary_step, failed_capture, paths, "macos", None)

                # These are two different original comparisons, not a numeric
                # status copied into one ambiguous or interchangeable field.
                for predicate in ("case", "proof-status", "result-kind", "driver-status"):
                    record = {**primary_record, "failedPredicates": [predicate], "proofFailures": []}
                    self.assertEqual(controller.native_primary_failure(primary_bytes(record), deadline=1000.0), record)
                self.assertEqual(controller.failure_details(capture(primary_stdout, stderr=primary_marker),
                    primary_step, paths)["native_primary_failure"], primary_record)
                primary_clean = "".join(name + " = 0.01 s = .\n" for name in primary_ids)
                primary_success = primary_clean + primary_footer.replace("1 failures", "0 failures")
                self.assertNotIn("native_primary_failure", controller.failure_details(
                    capture(primary_success, stderr=primary_marker), primary_step, paths))
                self.assertTrue(controller.parse_capture(primary_step, capture(primary_success, stderr=primary_marker),
                                                         paths, "macos", None).ok)
                self.assertNotIn("native_primary_failure", controller.failure_details(
                    capture(primary_stdout + primary_marker.decode("ascii"), ok=False, returncode=1), primary_step, paths))
                for transcript in (
                    clean + primary_footer,
                    clean + primary_target + ":\n" + primary_footer,
                    clean + primary_target + " = unfinished\n" + primary_footer,
                    primary_stdout.replace("0.01 s = F", "0.01 s = S"),
                    primary_stdout.replace("0.01 s = F", "0.01 s = .\n0.01 s = F"),
                    clean + primary_target_failure * 2 + primary_footer,
                    clean + primary_footer + primary_target_failure,
                ):
                    self.assertNotIn("native_primary_failure", controller.failure_details(
                        capture(transcript, stderr=primary_marker, ok=False, returncode=1), primary_step, paths))
                with patch.object(controller, "ruby_capture_ids", return_value=expected):
                    self.assertNotIn("native_primary_failure", controller.failure_details(
                        capture(primary_stdout, stderr=primary_marker, ok=False, returncode=1), primary_step, paths))
                for wrong_step in (
                    dataclasses.replace(primary_step, id="ruby-native-owner"),
                    dataclasses.replace(primary_step, id="ruby-play_store"),
                    dataclasses.replace(primary_step, id="ruby-ios_upload_validation"),
                    dataclasses.replace(primary_step, native_partition="all"),
                    dataclasses.replace(primary_step, native_partition="native-setup-no-cleanup"),
                    dataclasses.replace(primary_step, parser="exit"),
                ):
                    self.assertNotIn("native_primary_failure", controller.failure_details(
                        capture(primary_stdout, stderr=primary_marker, ok=False, returncode=1), wrong_step, paths))

                with patch.object(controller, "ruby_capture_ids", return_value=tuple(sorted((*many_ids, primary_target)))):
                    detail = controller.failure_details(capture(many_stdout + primary_target_failure,
                        stderr=primary_marker, ok=False, returncode=1), primary_step, paths)
                    self.assertGreater(detail["minitest_structure"]["start_records_omitted"], 0)
                    self.assertEqual(detail["native_primary_failure"], primary_record)
                    self.assertEqual(detail["minitest_observations"], [])  # No footer is not finality.
                    self.assertNotIn("native_primary_failure", controller.failure_details(
                        capture(primary_target_failure + many_stdout + primary_target_failure, stderr=primary_marker,
                                ok=False, returncode=1), primary_step, paths))

                invalid_primary = [
                    {key: value for key, value in primary_record.items() if key != "proofFailures"},
                    {**primary_record, "private": "PRIVATE_ROOT"}, {**primary_record, "pid": 123},
                    *({**primary_record, "schema": value} for value in (True, 1.0, 2, "1")),
                    *({**primary_record, "mode": value} for value in ([], False, "PRIVATE_MODE", "native-proof-readiness-io-other")),
                    *({**primary_record, "failedPredicates": value} for value in (
                        [], None, "proof-failures", [True], ["PRIVATE_PREDICATE"], ["proof-failures"] * 2,
                        ["driver-status", "proof-failures"], list(predicates) + ["case"], ["proof-status"],
                    )),
                    *({**primary_record, "proofFailures": value} for value in (
                        None, "actual capture finality", [], [True], ["PRIVATE_FAILURE"],
                        ["actual capture finality"] * 2, ["first-close boundary", "actual capture finality"],
                        list(proof_labels), ["unchanged IOError redaction"],
                    )),
                    {key: primary_record[key] for key in ("mode", "schema", "failedPredicates", "proofFailures")},
                ]
                prefix = controller.NATIVE_PRIMARY_FAILURE_PREFIX.encode("ascii")
                malformed_marker = prefix + b"not-json\n"
                invalid_markers = [*(primary_bytes(record) for record in invalid_primary),
                    primary_marker * 2, primary_marker + malformed_marker, malformed_marker + primary_marker,
                    primary_marker.replace(b'"schema":1', b'"schema":1,"schema":1'),
                    primary_marker.replace(b'"schema":1', b'"schema": 1'),
                    primary_marker.replace(b"native-proof", br"native\u002dproof"),
                    prefix + b"x" * 2048 + b"\n", prefix + b"\xff\n", primary_marker[:-1],
                    primary_marker[:-1] + b"\r\n", b"progress " + primary_marker,
                ]
                for raw in invalid_markers:
                    detail = controller.failure_details(capture(primary_stdout, stderr=raw, ok=False, returncode=1),
                                                        primary_step, paths, deadline=1000.0)
                    self.assertNotIn("native_primary_failure", detail)
                    self.assertEqual(detail["returncode"], 1)
                    self.assertNotIn("PRIVATE_", json.dumps(detail))

                expired = [False]
                def expired_primary_parse(_text):
                    expired[0] = True
                    raise ValueError("PRIVATE_MESSAGE")
                with patch.object(controller, "strict_json", side_effect=expired_primary_parse), \
                        patch.object(controller.time, "monotonic", side_effect=lambda: 1000.0 if expired[0] else 999.0), \
                        self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                    controller.failure_details(capture(primary_stdout, stderr=primary_marker, ok=False, returncode=1),
                                               primary_step, paths, deadline=1000.0)
                expired[0] = False
                original_scan = controller.minitest_records
                def expire_primary_scan(text, identifiers, *, deadline):
                    if identifiers == (primary_target,):
                        expired[0] = True
                    return original_scan(text, identifiers, deadline=deadline)
                with patch.object(controller, "minitest_records", side_effect=expire_primary_scan), \
                        patch.object(controller.time, "monotonic", side_effect=lambda: 1000.0 if expired[0] else 999.0), \
                        self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                    controller.failure_details(capture(primary_stdout, stderr=primary_marker, ok=False, returncode=1),
                                               primary_step, paths, deadline=1000.0)
                for interruption in (KeyboardInterrupt("PRIVATE_MESSAGE"), SystemExit(7)):
                    with patch.object(controller, "strict_json", side_effect=interruption), \
                            self.assertRaises(type(interruption)) as raised:
                        controller.failure_details(capture(primary_stdout, stderr=primary_marker, ok=False, returncode=1),
                                                   primary_step, paths, deadline=1000.0)
                    self.assertIs(raised.exception, interruption)

            order_modes = {
                primary_class + "test_native_task_error_precedes_later_caller_cancellation_at_the_original_latch": (
                    "native-order-task-before-caller-interrupt", "native-order-task-before-caller-system-exit",
                ),
                primary_class + "test_native_caller_cancellation_precedes_later_task_ioerror_at_the_original_latch": (
                    "native-order-caller-before-task-interrupt", "native-order-caller-before-task-system-exit",
                ),
                primary_class + "test_native_cleanup_error_precedes_later_caller_interrupt_and_retains_unknown": (
                    "native-order-cleanup-before-caller-interrupt",
                ),
                primary_class + "test_native_cleanup_error_precedes_later_caller_system_exit_and_retains_unknown": (
                    "native-order-cleanup-before-caller-system-exit",
                ),
            }
            order_predicates = (
                "proof-version", "proof-kind", "case", "source-binding", "proof-failures", "proof-status", "expected-unknown",
                "original-accepted", "result-kind", "driver-status",
            )
            order_common = (
                "original failed fixture result", "same first object through original boundaries", "unchanged original first message/status",
                "unchanged original caller message/status", "no original upload acceptance", "original shared creator/capture latch",
                "actual first and later latch returns", "actual latch released later fault", "actual caller delivery and rescue",
                "actual original stdin close", "actual capture/creator joins", "actual original native closes", "actual original native EOFs",
                "actual original C wait", "no fixture fallback or pending cancellation", "ownedDescriptorsClosed", "watchdogJoined",
                "injectorsJoined", "handlersRestored", "registryInactive", "no fixture cleanup errors", "observation restored",
                "unchanged original sources",
            )
            order_cleanup = ("actual clean body then original cleanup fault", "unknown original task/session retained",
                             "real pre-tail native success not finality")
            order_body = ("actual body error recorded", "actual settled native cancellation")
            cleanup_modes = ("native-order-cleanup-before-caller-interrupt", "native-order-cleanup-before-caller-system-exit")
            all_order_modes = [mode for modes in order_modes.values() for mode in modes]
            self.assertEqual(controller.NATIVE_ORDER_FAILURE_PREFIX, "MRK_NATIVE_ORDER_FAILURE=")
            self.assertEqual(controller.NATIVE_ORDER_FAILURE_CALLBACK_MODES, order_modes)
            self.assertEqual((len(order_modes), len(all_order_modes), len(set(all_order_modes))), (4, 6, 6))
            self.assertEqual(controller.NATIVE_ORDER_FAILURE_MODES, frozenset(all_order_modes))
            self.assertEqual(controller.NATIVE_ORDER_CLEANUP_MODES, frozenset(cleanup_modes))
            self.assertEqual(controller.NATIVE_ORDER_FAILURE_PREDICATES, order_predicates)
            self.assertEqual(controller.NATIVE_ORDER_PROOF_FAILURES, order_common + order_cleanup + order_body)
            self.assertEqual((len(order_predicates), len(order_common), len(order_cleanup), len(order_body)), (10, 23, 3, 2))

            def order_bytes(record):
                return (controller.NATIVE_ORDER_FAILURE_PREFIX
                        + json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")

            def order_transcript(identifier, terminal="F"):
                return (identifier + " = PRIVATE_MESSAGE\n0.01 s = " + terminal + "\n\n1 runs, 5 assertions, "
                        + f"{int(terminal == 'F')} failures, {int(terminal == 'E')} errors, {int(terminal == 'S')} skips\n")

            order_ids = tuple(sorted(order_modes))
            order_inventories = {
                "healthy": tuple(sorted(name for name, modes in order_modes.items() if modes[0] not in cleanup_modes)),
                **{mode: (name,) for name, modes in order_modes.items() for mode in modes if mode in cleanup_modes},
            }
            def order_inventory(_source, _gate, partition, *, deadline):
                return order_inventories.get(partition, ())

            order_target = next(iter(order_modes))
            order_record = {"schema": 1, "mode": "native-order-task-before-caller-interrupt",
                            "failedPredicates": ["proof-failures"], "proofFailures": ["actual settled native cancellation"]}
            order_marker = order_bytes(order_record)
            order_step = controller.Step("ruby-native-capture", parser="minitest", expected_tests=1, native_partition="healthy")
            order_stdout = order_transcript(order_target)
            # Both source seams are inert, including deliberately wrong gates
            # and partitions. No Ruby, fixture, catalog or native import occurs.
            with patch.object(controller, "ruby_expected_ids", return_value=order_ids), \
                    patch.object(controller, "ruby_capture_ids", side_effect=order_inventory) as inventory, \
                    patch.object(controller.time, "monotonic", return_value=999.0):
                for owner, modes in order_modes.items():
                    for mode in modes:
                        cleanup = mode in cleanup_modes
                        partition = mode if cleanup else "healthy"
                        selected_step = dataclasses.replace(order_step, native_partition=partition)
                        labels = order_common + (order_cleanup if cleanup else order_body)
                        record = {"schema": 1, "mode": mode, "failedPredicates": list(order_predicates), "proofFailures": list(labels)}
                        raw = order_bytes(record)
                        self.assertEqual(len(labels), 26 if cleanup else 25)
                        self.assertLessEqual(len(raw), 2048)
                        for terminal in ("F", "E"):
                            transcript = order_transcript(owner, terminal)
                            failed_capture = capture(transcript, stderr=raw, ok=False, returncode=1)
                            with patch.object(controller, "minitest_records", wraps=controller.minitest_records) as scans:
                                detail = controller.failure_details(failed_capture, selected_step, paths, deadline=1000.0)
                            inventory.assert_called_with(ROOT, "ruby-native-capture", partition, deadline=1000.0)
                            self.assertEqual([call.args for call in scans.call_args_list],
                                             [(transcript, order_inventories[partition]), (transcript, (owner,))])
                            self.assertEqual([call.kwargs for call in scans.call_args_list], [{"deadline": 1000.0}] * 2)
                            self.assertEqual(detail["native_order_failure"], record)
                            self.assertEqual(detail["returncode"], 1)
                            self.assertNotIn("PRIVATE_MESSAGE", json.dumps(detail))
                        with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                            controller.parse_capture(selected_step, failed_capture, paths, "macos", None)
                        rc_zero = capture(transcript, stderr=raw)
                        self.assertEqual(controller.failure_details(rc_zero, selected_step, paths, deadline=1000.0)["native_order_failure"], record)
                        with self.assertRaisesRegex(controller.VerificationError, "MINITEST_RESULT_REJECTED"):
                            controller.parse_capture(selected_step, rc_zero, paths, "macos", None, deadline=1000.0)
                        opposite = order_body if cleanup else order_cleanup
                        self.assertIsNone(controller.native_order_failure(order_bytes({**record, "proofFailures": list(opposite)})))
                        # Make every ID source-known: these vetoes must arise
                        # from the actual callback/partition pair, not discovery.
                        with patch.object(controller, "ruby_capture_ids", return_value=order_ids):
                            wrong_owner = next(name for name in order_modes if name != owner)
                            self.assertNotIn("native_order_failure", controller.failure_details(
                                capture(order_transcript(wrong_owner), stderr=raw, ok=False, returncode=1), selected_step, paths))
                            for wrong_partition in ("healthy", *cleanup_modes, "all", "native-setup-no-cleanup"):
                                if wrong_partition != partition:
                                    self.assertNotIn("native_order_failure", controller.failure_details(
                                        capture(transcript, stderr=raw, ok=False, returncode=1),
                                        dataclasses.replace(selected_step, native_partition=wrong_partition), paths))

                # Reuse the original canonical reader's existing malformed
                # JSON/framing/duplicate/byte-limit matrix, binding its options.
                with patch.object(controller, "_fixture_failure_record", wraps=controller._fixture_failure_record) as strict:
                    self.assertEqual(controller.native_order_failure(order_marker, deadline=1000.0), order_record)
                strict.assert_called_once_with(order_marker, "MRK_NATIVE_ORDER_FAILURE=", 2048, deadline=1000.0,
                                               canonical_fields=("schema", "mode", "failedPredicates", "proofFailures"))
                for predicate in order_predicates:
                    if predicate != "proof-failures":
                        record = {**order_record, "failedPredicates": [predicate], "proofFailures": []}
                        self.assertEqual(controller.native_order_failure(order_bytes(record)), record)
                invalid_order = [
                    {key: value for key, value in order_record.items() if key != "proofFailures"},
                    {**order_record, "category": "PRIVATE_CATEGORY"},
                    *({**order_record, "schema": value} for value in (True, 1.0, 2, "1")),
                    *({**order_record, "mode": value} for value in ([], False, "native-order-task-before-caller-other")),
                    *({**order_record, "failedPredicates": value} for value in (
                        [], None, [True], ["PRIVATE_PREDICATE"], ["proof-failures"] * 2,
                        ["driver-status", "proof-failures"], list(order_predicates) + ["case"], ["proof-status"],
                    )),
                    *({**order_record, "proofFailures": value} for value in (
                        None, [], [True], ["PRIVATE_FAILURE"], ["actual body error recorded"] * 2,
                        ["actual settled native cancellation", "original failed fixture result"],
                        list(order_common + order_cleanup + order_body),
                    )),
                ]
                for record in invalid_order:
                    detail = controller.failure_details(capture(order_stdout, stderr=order_bytes(record), ok=False, returncode=1),
                                                        order_step, paths, deadline=1000.0)
                    self.assertNotIn("native_order_failure", detail)
                    self.assertEqual(detail["returncode"], 1)
                    self.assertNotIn("PRIVATE_", json.dumps(detail))

                for transcript in (
                    "", order_target + ":\n", order_target + " = unfinished\n",
                    order_transcript(order_target, "."), order_transcript(order_target, "S"),
                    order_stdout.replace("0.01 s = F", "0.01 s = .\n0.01 s = F"),
                    order_stdout + order_stdout, "0 runs, 5 assertions, 0 failures, 0 errors, 0 skips\n" + order_stdout,
                ):
                    self.assertNotIn("native_order_failure", controller.failure_details(
                        capture(transcript, stderr=order_marker, ok=False, returncode=1), order_step, paths))
                self.assertNotIn("native_order_failure", controller.failure_details(
                    capture(order_stdout + order_marker.decode("ascii"), ok=False, returncode=1), order_step, paths))
                with patch.object(controller, "ruby_capture_ids", return_value=expected):
                    self.assertNotIn("native_order_failure", controller.failure_details(
                        capture(order_stdout, stderr=order_marker, ok=False, returncode=1), order_step, paths))
                for wrong_step in (
                    dataclasses.replace(order_step, id="ruby-native-owner"),
                    dataclasses.replace(order_step, id="ruby-play_store"),
                    dataclasses.replace(order_step, parser="exit"),
                ):
                    self.assertNotIn("native_order_failure", controller.failure_details(
                        capture(order_stdout, stderr=order_marker, ok=False, returncode=1), wrong_step, paths))
                with patch.object(controller, "ruby_capture_ids", return_value=tuple(sorted((*many_ids, order_target)))):
                    detail = controller.failure_details(capture(many_stdout + order_stdout, stderr=order_marker,
                        ok=False, returncode=1), order_step, paths)
                    self.assertGreater(detail["minitest_structure"]["start_records_omitted"], 0)
                    self.assertEqual(detail["native_order_failure"], order_record)
                    early_target = order_target + " = 0.01 s = F\n"
                    self.assertNotIn("native_order_failure", controller.failure_details(
                        capture(early_target + many_stdout + order_stdout, stderr=order_marker,
                                ok=False, returncode=1), order_step, paths))

                expired = [False]
                def expired_order_parse(_text):
                    expired[0] = True
                    raise ValueError("PRIVATE_MESSAGE")
                with patch.object(controller, "strict_json", side_effect=expired_order_parse), \
                        patch.object(controller.time, "monotonic", side_effect=lambda: 1000.0 if expired[0] else 999.0), \
                        self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                    controller.failure_details(capture(order_stdout, stderr=order_marker, ok=False, returncode=1),
                                               order_step, paths, deadline=1000.0)
                expired[0] = False
                original_scan = controller.minitest_records
                def expire_order_scan(text, identifiers, *, deadline):
                    if identifiers == (order_target,):
                        expired[0] = True
                    return original_scan(text, identifiers, deadline=deadline)
                with patch.object(controller, "minitest_records", side_effect=expire_order_scan), \
                        patch.object(controller.time, "monotonic", side_effect=lambda: 1000.0 if expired[0] else 999.0), \
                        self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                    controller.failure_details(capture(order_stdout, stderr=order_marker, ok=False, returncode=1),
                                               order_step, paths, deadline=1000.0)
                for interruption in (KeyboardInterrupt("PRIVATE_MESSAGE"), SystemExit(7)):
                    with patch.object(controller, "strict_json", side_effect=interruption), \
                            self.assertRaises(type(interruption)) as raised:
                        controller.failure_details(capture(order_stdout, stderr=order_marker, ok=False, returncode=1),
                                                   order_step, paths, deadline=1000.0)
                    self.assertIs(raised.exception, interruption)

            setup_target = ("NativeUploadValidationTest#"
                            "test_cancellation_or_io_error_at_first_setup_step_cleans_up_the_real_child")
            setup_modes = ("native-setup-interrupt", "native-setup-system-exit", "native-setup-io-error")
            setup_fields = ("schema", "mode", "failedPredicates", "resultKind", "driverExitStatus",
                            "errorCategory", "nativeErrorCategory", "resultChecks", "nativeChecks")
            setup_kinds = ("pass", "fixture-cleanup", "readiness", "setup-fixture-fault", "process-observation",
                           "process-ownership", "fixture-result", "unexpected", "other", "missing", "invalid")
            setup_categories = ("none", "fixture-error", "contract-error", "native-lifecycle-error", "io-error",
                                "interrupt", "system-exit", "other", "missing", "invalid")
            setup_result_checks = (
                "ready", "firstCloseEntered", "originalCloseCompleted", "nativeOriginalErrorPreserved",
                "watchdogStarted", "watchdogIntervened", "fallbackUsed", "deadBeforeFallback",
                "ownedDescriptorsClosed", "watchdogJoined", "tasksJoined", "injectorsJoined",
                "handlersRestored", "registryInactive", "pendingInterrupt", "cleanupErrorsEmpty",
            )
            setup_native_checks = ("finalized", "noProducers", "settled", "unknown", "hooksRestored")
            self.assertEqual(controller.NATIVE_SETUP_FAILURE_PREFIX, "MRK_NATIVE_SETUP_FAILURE=")
            self.assertEqual(controller.NATIVE_SETUP_FAILURE_CALLBACK_MODES, {setup_target: setup_modes})
            self.assertEqual(controller.NATIVE_SETUP_FAILURE_MODES, frozenset(setup_modes))
            self.assertEqual(controller.NATIVE_SETUP_FAILURE_FIELDS, setup_fields)
            self.assertEqual(controller.NATIVE_SETUP_FAILURE_PREDICATES, ("result-kind", "driver-status"))
            self.assertEqual(controller.NATIVE_SETUP_RESULT_KINDS, setup_kinds)
            self.assertEqual(controller.NATIVE_SETUP_ERROR_CATEGORIES, setup_categories)
            self.assertEqual(controller.NATIVE_SETUP_RESULT_CHECKS, setup_result_checks)
            self.assertEqual(controller.NATIVE_SETUP_NATIVE_CHECKS, setup_native_checks)

            def setup_bytes(record):
                return (controller.NATIVE_SETUP_FAILURE_PREFIX
                        + json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")

            setup_record = {
                "schema": 1, "mode": setup_modes[0], "failedPredicates": ["result-kind", "driver-status"],
                "resultKind": "fixture-cleanup", "driverExitStatus": 1,
                "errorCategory": "interrupt", "nativeErrorCategory": "io-error",
                "resultChecks": {name: (True, False, "missing", "invalid")[index % 4]
                                 for index, name in enumerate(setup_result_checks)},
                "nativeChecks": {name: (False, "missing", "invalid", True)[index % 4]
                                 for index, name in enumerate(setup_native_checks)},
            }
            setup_marker = setup_bytes(setup_record)
            setup_ids = tuple(sorted((*expected, setup_target)))
            setup_step = controller.Step("ruby-native-capture", parser="minitest", expected_tests=3,
                                         native_partition="healthy")
            setup_target_failure = setup_target + " = PRIVATE_MESSAGE\n0.01 s = F\n"
            setup_stdout = clean + setup_target_failure + failed_footer
            # Both discovery entrypoints stay mocked, including every wrong
            # gate/partition case: this closure reads no Ruby fixture source.
            with patch.object(controller, "ruby_expected_ids", return_value=setup_ids), \
                    patch.object(controller, "ruby_capture_ids", return_value=setup_ids), \
                    patch.object(controller.time, "monotonic", return_value=999.0):
                with patch.object(controller, "_fixture_failure_record", wraps=controller._fixture_failure_record) as strict:
                    self.assertEqual(controller.native_setup_failure(setup_marker, deadline=1000.0), setup_record)
                strict.assert_called_once_with(setup_marker, "MRK_NATIVE_SETUP_FAILURE=", 2048, deadline=1000.0,
                                               canonical_fields=setup_fields)
                for mode in setup_modes:
                    for terminal in ("F", "E"):
                        record = {**setup_record, "mode": mode}
                        raw = setup_bytes(record)
                        self.assertLessEqual(len(raw), 2048)
                        transcript = setup_stdout.replace("0.01 s = F", "0.01 s = " + terminal)
                        failed_capture = capture(transcript, stderr=raw, ok=False, returncode=1)
                        with patch.object(controller, "minitest_records", wraps=controller.minitest_records) as scans:
                            detail = controller.failure_details(failed_capture, setup_step, paths, deadline=1000.0)
                        self.assertEqual([call.args for call in scans.call_args_list],
                                         [(transcript, setup_ids), (transcript, (setup_target,))])
                        self.assertEqual([call.kwargs for call in scans.call_args_list], [{"deadline": 1000.0}] * 2)
                        self.assertEqual(detail["native_setup_failure"], record)
                        self.assertEqual(detail["returncode"], 1)
                        self.assertNotIn("PRIVATE_MESSAGE", json.dumps(detail))
                with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                    controller.parse_capture(setup_step, failed_capture, paths, "macos", None)
                rc_zero = capture(setup_stdout, stderr=setup_marker)
                self.assertEqual(controller.failure_details(rc_zero, setup_step, paths)["native_setup_failure"], setup_record)
                with self.assertRaisesRegex(controller.VerificationError, "MINITEST_RESULT_REJECTED"):
                    controller.parse_capture(setup_step, rc_zero, paths, "macos", None)

                # The two original operands determine the exact ordered
                # failures; the finite projections are independent observations.
                for kind in setup_kinds:
                    record = {**setup_record, "resultKind": kind,
                              "failedPredicates": ["driver-status"] if kind == "pass" else ["result-kind", "driver-status"]}
                    self.assertEqual(controller.native_setup_failure(setup_bytes(record)), record)
                for status in (0, 255):
                    record = {**setup_record, "driverExitStatus": status,
                              "failedPredicates": ["result-kind"] if status == 0 else ["result-kind", "driver-status"]}
                    self.assertEqual(controller.native_setup_failure(setup_bytes(record)), record)
                for key in ("errorCategory", "nativeErrorCategory"):
                    for category in setup_categories:
                        record = {**setup_record, key: category}
                        self.assertEqual(controller.native_setup_failure(setup_bytes(record)), record)
                for check_value in (True, False, "missing", "invalid"):
                    record = {**setup_record,
                              "resultChecks": dict.fromkeys(setup_result_checks, check_value),
                              "nativeChecks": dict.fromkeys(setup_native_checks, check_value)}
                    self.assertEqual(controller.native_setup_failure(setup_bytes(record)), record)

                success_stdout = setup_stdout.replace("0.01 s = F", "0.01 s = .").replace("1 failures", "0 failures")
                self.assertNotIn("native_setup_failure", controller.failure_details(
                    capture(success_stdout, stderr=setup_marker), setup_step, paths))
                self.assertTrue(controller.parse_capture(setup_step, capture(success_stdout, stderr=setup_marker),
                                                         paths, "macos", None).ok)
                for transcript in (
                    clean + failed_footer, clean + setup_target + ":\n" + failed_footer,
                    clean + setup_target + " = unfinished\n" + failed_footer,
                    setup_stdout.replace("0.01 s = F", "0.01 s = S"),
                    setup_stdout.replace("0.01 s = F", "0.01 s = .\n0.01 s = F"),
                    clean + setup_target_failure * 2 + failed_footer,
                    clean + failed_footer + setup_target_failure,
                    success_stdout.replace(first, first.replace("0.01 s = .", "0.01 s = F")),
                ):
                    self.assertNotIn("native_setup_failure", controller.failure_details(
                        capture(transcript, stderr=setup_marker, ok=False, returncode=1), setup_step, paths))
                self.assertNotIn("native_setup_failure", controller.failure_details(
                    capture(setup_stdout + setup_marker.decode("ascii"), ok=False, returncode=1), setup_step, paths))
                with patch.object(controller, "ruby_capture_ids", return_value=expected):
                    self.assertNotIn("native_setup_failure", controller.failure_details(
                        capture(setup_stdout, stderr=setup_marker, ok=False, returncode=1), setup_step, paths))
                for wrong_step in (
                    dataclasses.replace(setup_step, id="ruby-native-owner"),
                    dataclasses.replace(setup_step, id="ruby-play_store"),
                    dataclasses.replace(setup_step, id="ruby-ios_upload_validation"),
                    dataclasses.replace(setup_step, id="ruby-android_upload_validation"),
                    dataclasses.replace(setup_step, native_partition="all"),
                    dataclasses.replace(setup_step, native_partition="native-setup-no-cleanup"),
                    dataclasses.replace(setup_step, parser="exit"),
                ):
                    self.assertNotIn("native_setup_failure", controller.failure_details(
                        capture(setup_stdout, stderr=setup_marker, ok=False, returncode=1), wrong_step, paths))
                with patch.object(controller, "ruby_capture_ids", return_value=tuple(sorted((*many_ids, setup_target)))):
                    detail = controller.failure_details(capture(many_stdout + setup_target_failure, stderr=setup_marker,
                        ok=False, returncode=1), setup_step, paths)
                    self.assertGreater(detail["minitest_structure"]["start_records_omitted"], 0)
                    self.assertEqual(detail["native_setup_failure"], setup_record)
                    self.assertNotIn("native_setup_failure", controller.failure_details(
                        capture(setup_target_failure + many_stdout + setup_target_failure, stderr=setup_marker,
                                ok=False, returncode=1), setup_step, paths))

                invalid_setup = [
                    *({key: value for key, value in setup_record.items() if key != absent} for absent in setup_fields),
                    {**setup_record, "private": "PRIVATE_ROOT"}, {**setup_record, "pid": 123},
                    {key: setup_record[key] for key in reversed(setup_fields)},
                    *({**setup_record, "schema": value} for value in (True, 1.0, 2, "1")),
                    *({**setup_record, "mode": value} for value in ([], False, "PRIVATE_MODE", "native-setup-no-cleanup")),
                    *({**setup_record, "resultKind": value} for value in (None, True, 0, [], "PRIVATE_KIND")),
                    *({**setup_record, "driverExitStatus": value} for value in (None, True, False, 1.0, "1", -1, 256)),
                    *({**setup_record, key: value} for key in ("errorCategory", "nativeErrorCategory")
                      for value in (None, True, [], "PRIVATE_CLASS")),
                    *({**setup_record, "failedPredicates": value} for value in (
                        [], None, "result-kind", [True], ["PRIVATE_PREDICATE"], ["result-kind"] * 2,
                        ["driver-status", "result-kind"], ["result-kind"], ["driver-status"],
                    )),
                    {**setup_record, "resultKind": "pass", "driverExitStatus": 0, "failedPredicates": []},
                    {**setup_record, "resultKind": "pass", "driverExitStatus": 0},
                    {**setup_record, "resultKind": "pass"}, {**setup_record, "driverExitStatus": 0},
                ]
                for key in ("resultChecks", "nativeChecks"):
                    checks = setup_record[key]
                    invalid_setup.extend({**setup_record, key: value} for value in (
                        None, [], True, {}, {**checks, "PRIVATE_CHECK": False},
                        {name: value for name, value in checks.items() if name != next(iter(checks))},
                        {name: checks[name] for name in reversed(checks)},
                        *({**checks, name: 0} for name in checks),
                        *({**checks, next(iter(checks)): value} for value in (1, None, [], {}, "false", "PRIVATE_VALUE")),
                    ))
                prefix = controller.NATIVE_SETUP_FAILURE_PREFIX.encode("ascii")
                malformed_marker = prefix + b"not-json\n"
                invalid_setup_markers = [*(setup_bytes(record) for record in invalid_setup),
                    setup_marker * 2, setup_marker + malformed_marker, malformed_marker + setup_marker,
                    setup_marker.replace(b'"schema":1', b'"schema":1,"schema":1'),
                    setup_marker.replace(b'"ready":true', b'"ready":true,"ready":true'),
                    setup_marker.replace(b'"finalized":false', b'"finalized":false,"finalized":false'),
                    setup_marker.replace(b'"schema":1', b'"schema": 1'),
                    setup_marker.replace(b"native-setup", br"native\u002dsetup"),
                    prefix + b"x" * 2048 + b"\n", prefix + b"\xff\n", setup_marker[:-1],
                    setup_marker[:-1] + b"\r\n", b"progress " + setup_marker,
                ]
                for raw in invalid_setup_markers:
                    detail = controller.failure_details(capture(setup_stdout, stderr=raw, ok=False, returncode=1),
                                                        setup_step, paths, deadline=1000.0)
                    self.assertNotIn("native_setup_failure", detail)
                    self.assertEqual(detail["returncode"], 1)
                    self.assertNotIn("PRIVATE_", json.dumps(detail))

                expired = [False]
                def expired_setup_parse(_text):
                    expired[0] = True
                    raise ValueError("PRIVATE_MESSAGE")
                with patch.object(controller, "strict_json", side_effect=expired_setup_parse), \
                        patch.object(controller.time, "monotonic", side_effect=lambda: 1000.0 if expired[0] else 999.0), \
                        self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                    controller.failure_details(capture(setup_stdout, stderr=setup_marker, ok=False, returncode=1),
                                               setup_step, paths, deadline=1000.0)
                expired[0] = False
                original_scan = controller.minitest_records
                def expire_setup_scan(text, identifiers, *, deadline):
                    if identifiers == (setup_target,):
                        expired[0] = True
                    return original_scan(text, identifiers, deadline=deadline)
                with patch.object(controller, "minitest_records", side_effect=expire_setup_scan), \
                        patch.object(controller.time, "monotonic", side_effect=lambda: 1000.0 if expired[0] else 999.0), \
                        self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                    controller.failure_details(capture(setup_stdout, stderr=setup_marker, ok=False, returncode=1),
                                               setup_step, paths, deadline=1000.0)
                for interruption in (KeyboardInterrupt("PRIVATE_MESSAGE"), SystemExit(7)):
                    with patch.object(controller, "strict_json", side_effect=interruption), \
                            self.assertRaises(type(interruption)) as raised:
                        controller.failure_details(capture(setup_stdout, stderr=setup_marker, ok=False, returncode=1),
                                                   setup_step, paths, deadline=1000.0)
                    self.assertIs(raised.exception, interruption)

            adapter_contracts = {
                "real-deadline": ("test_deadline_terminates_validator_without_authorizing_upload", "pass"),
                "inherited": ("test_deadline_terminates_inherited_pipe_children_after_validator_parent_exits", "pass"),
                "delayed-start": ("test_descendant_boundary_survives_delayed_start_and_late_parent_record", "pass"),
                "late-record": ("test_descendant_boundary_survives_delayed_start_and_late_parent_record", "pass"),
                "unready": ("test_unready_fixture_fails_distinctly_and_stops_before_any_late_pid_record", "readiness"),
                "leader-only": ("test_fixture_detects_leader_only_cleanup_and_missing_deadline", "descendant-alive"),
                "no-deadline": ("test_fixture_detects_leader_only_cleanup_and_missing_deadline", "capture-watchdog"),
                "immediate-deadline": ("test_fixture_rejects_an_immediate_timeout_even_when_the_leader_is_killed", "elapsed-bound"),
                "real-deadline-slow-cleanup": ("test_slow_cleanup_cannot_supply_a_positive_deadline_wait", "pass"),
                "immediate-deadline-slow-cleanup": ("test_slow_cleanup_cannot_supply_a_positive_deadline_wait", "elapsed-bound"),
            }
            adapter_platforms = {
                "ios": ("ruby-ios_upload_validation", "IosUploadValidationTest"),
                "android": ("ruby-android_upload_validation", "AndroidUploadValidationTest"),
            }
            adapter_fields = (
                "schema", "platform", "mode", "expectedKind", "failedPredicates", "resultKind", "driverExitStatus",
                "retainedDriverErrorCategory", "retainedDriverErrorCode", "adapterErrorCategory",
                "resultChecks", "nativeChecks", "timingChecks", "nativeOutcomes", "slowChecks",
            )
            adapter_result_checks = (
                "ready", "stdinClosedAfterReady", "deadlinePrimarySameObject", "deadlineResultSameObject",
                "watchdogStarted", "watchdogIntervened", "fallbackUsed", "deadBeforeFallback", "nativeFinalityBeforeFallback",
                "adapterRejected", "adapterCallObserved", "captureEntered", "descendantLiveBeforeRelease",
                "inheritedPipeBlockObserved", "validatorReapedAfterRelease", "commitAfterDataEOF", "ownedDescriptorsClosed",
                "watchdogJoined", "tasksJoined", "injectorsJoined", "handlersRestored", "registryInactive",
                "pendingInterrupt", "cleanupErrorsEmpty",
            )
            adapter_native_checks = (
                "finalized", "noProducers", "settled", "unknown", "hooksRestored", "observerErrorsEmpty",
                "productionFinality", "retainedUnknown", "statusValid", "statusDecodedEOF", "cleanupErrorsEmpty",
                "originalWaitObserved", "tasksJoined", "leasesClosed", "allActualEOFObserved",
                "captureSettled", "captureFinished", "captureJoined", "captureActualJoinObserved",
                "creatorSettled", "creatorFinished", "creatorJoined", "creatorActualJoinObserved",
                "stdoutEOF", "stdoutActualEOFObserved", "stderrEOF", "stderrActualEOFObserved",
                "statusEOF", "statusActualEOFObserved", "groupAbsent",
            )
            adapter_timing_checks = (
                "runSpanMatchesMode", "firstTimeoutCutoff", "selectedTimeoutCutoff", "blockedDataWaitsPositive",
                "firstBlockedDataWithinRun", "captureWithinLimit", "slowCleanupAtLeastFour", "captureCoversSlowCleanup",
                "slowCleanupWithinOriginalCutoff",
            )
            adapter_native_outcomes = {
                **dict.fromkeys(("custodian", "keeper", "validator"), (
                    "missing", "invalid", "not-attempted", "unknown", "exit0", "exit1", "exit2", "other-exit", "signal",
                )),
                "finalOutcome": ("missing", "invalid", "ok", "rejected", "failed"),
                "finalCleanup": ("missing", "invalid", "confirmed", "unknown"),
                "groupState": ("missing", "invalid", "not-created", "retired", "unknown"),
                **dict.fromkeys(("captureState", "creatorState"), (
                    "missing", "invalid", "unpublished", "not-constructed", "not-started", "attempted",
                )),
            }
            adapter_slow_checks = (
                "handoffPerformed", "delayEntered", "delayGuardPassed", "delayFailed", "delayFinished",
                "originalCleanupCalled", "originalCleanupFinished",
            )
            self.assertEqual(controller.ADAPTER_FAILURE_PREFIX, "MRK_ADAPTER_FAILURE=")
            self.assertEqual(controller.ADAPTER_FAILURE_MODE_CONTRACTS, adapter_contracts)
            self.assertEqual(controller.ADAPTER_FAILURE_PLATFORMS, adapter_platforms)
            self.assertEqual(controller.ADAPTER_FAILURE_FIELDS, adapter_fields)
            self.assertEqual(controller.ADAPTER_FAILURE_RESULT_CHECKS, adapter_result_checks)
            self.assertEqual(controller.ADAPTER_FAILURE_NATIVE_CHECKS, adapter_native_checks)
            self.assertEqual(controller.ADAPTER_FAILURE_TIMING_CHECKS, adapter_timing_checks)
            self.assertEqual(tuple(controller.ADAPTER_FAILURE_NATIVE_OUTCOMES), tuple(adapter_native_outcomes))
            self.assertEqual(controller.ADAPTER_FAILURE_NATIVE_OUTCOMES,
                             {name: frozenset(values) for name, values in adapter_native_outcomes.items()})
            self.assertEqual(controller.ADAPTER_FAILURE_SLOW_CHECKS, adapter_slow_checks)

            def adapter_bytes(record):
                return ("MRK_ADAPTER_FAILURE="
                        + json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")

            adapter_record = {
                "schema": 2, "platform": "ios", "mode": "real-deadline", "expectedKind": "pass",
                "failedPredicates": ["result-kind", "driver-status"], "resultKind": "fixture-cleanup", "driverExitStatus": 1,
                "retainedDriverErrorCategory": "native-lifecycle-error", "retainedDriverErrorCode": "native-deadline",
                "adapterErrorCategory": "contract-error",
                "resultChecks": {name: (True, False, "missing", "invalid")[index % 4]
                                 for index, name in enumerate(adapter_result_checks)},
                "nativeChecks": {name: (False, "missing", "invalid", True)[index % 4]
                                 for index, name in enumerate(adapter_native_checks)},
                "timingChecks": dict(zip(adapter_timing_checks,
                    (True, "before-cutoff", "at-or-after-cutoff", True, False, True, "missing", "missing", "missing"))),
                "nativeOutcomes": dict(zip(adapter_native_outcomes,
                    ("exit2", "exit2", "signal", "failed", "unknown", "retired", "attempted", "attempted"))),
                "slowChecks": dict.fromkeys(adapter_slow_checks, "missing"),
            }
            adapter_marker = adapter_bytes(adapter_record)
            adapter_target = "IosUploadValidationTest#" + adapter_contracts["real-deadline"][0]
            adapter_ids = tuple(sorted((*expected, adapter_target)))
            adapter_step = controller.Step("ruby-ios_upload_validation", parser="minitest", expected_tests=3,
                                           native_partition="healthy")
            adapter_target_failure = adapter_target + " = PRIVATE_MESSAGE\n0.01 s = F\n"
            adapter_stdout = clean + adapter_target_failure + failed_footer
            # Use source-known adapter identities, but keep both discovery
            # functions inert. No Ruby source or actual adapter is loaded here.
            with patch.object(controller, "ruby_expected_ids", return_value=adapter_ids), \
                    patch.object(controller, "ruby_capture_ids", return_value=adapter_ids), \
                    patch.object(controller.time, "monotonic", return_value=999.0):
                with patch.object(controller, "_fixture_failure_record", wraps=controller._fixture_failure_record) as strict:
                    self.assertEqual(controller.adapter_failure(adapter_marker, deadline=1000.0), adapter_record)
                strict.assert_called_once_with(adapter_marker, "MRK_ADAPTER_FAILURE=", 4096, deadline=1000.0,
                                               canonical_fields=adapter_fields)
                # Representative ordinary, slow and negative-control cases
                # prove platform routing and mode-specific status, not a matrix
                # of every flag crossed with every callback.
                examples = (
                    adapter_record,
                    {**adapter_record, "platform": "android", "mode": "immediate-deadline-slow-cleanup",
                     "expectedKind": "elapsed-bound", "failedPredicates": ["result-kind"],
                     "timingChecks": {**adapter_record["timingChecks"], "slowCleanupAtLeastFour": True,
                                      "captureCoversSlowCleanup": True, "slowCleanupWithinOriginalCutoff": False},
                     "slowChecks": dict(zip(adapter_slow_checks, (False, True, True, True, False, True, True)))},
                    {**adapter_record, "mode": "no-deadline", "expectedKind": "capture-watchdog",
                     "resultKind": "capture-watchdog", "driverExitStatus": 0, "failedPredicates": ["driver-status"]},
                )
                for index, record in enumerate(examples):
                    gate, class_name = adapter_platforms[record["platform"]]
                    target = class_name + "#" + adapter_contracts[record["mode"]][0]
                    ids = tuple(sorted((*expected, target)))
                    selected_step = dataclasses.replace(adapter_step, id=gate)
                    terminal = "E" if index == 1 else "F"
                    transcript = clean + target + " = PRIVATE_MESSAGE\n0.01 s = " + terminal + "\n" + failed_footer
                    raw = adapter_bytes(record)
                    self.assertLessEqual(len(raw), 4096)
                    with patch.object(controller, "ruby_capture_ids", return_value=ids), \
                            patch.object(controller, "minitest_records", wraps=controller.minitest_records) as scans:
                        detail = controller.failure_details(capture(transcript, stderr=raw, ok=False, returncode=1),
                                                            selected_step, paths, deadline=1000.0)
                    self.assertEqual([call.args for call in scans.call_args_list], [(transcript, ids), (transcript, (target,))])
                    self.assertEqual([call.kwargs for call in scans.call_args_list], [{"deadline": 1000.0}] * 2)
                    self.assertEqual(detail["adapter_failure"], record)
                    self.assertEqual(detail["returncode"], 1)
                    self.assertNotIn("PRIVATE_", json.dumps(detail))
                    all_pass = {**record, "resultKind": record["expectedKind"],
                                "driverExitStatus": 0 if record["expectedKind"] == "pass" else 1, "failedPredicates": []}
                    self.assertIsNone(controller.adapter_failure(adapter_bytes(all_pass)))
                    self.assertIsNone(controller.adapter_failure(adapter_bytes({**all_pass, "failedPredicates": record["failedPredicates"]})))

                failed_capture = capture(adapter_stdout, stderr=adapter_marker, ok=False, returncode=1)
                with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                    controller.parse_capture(adapter_step, failed_capture, paths, "linux", None)
                rc_zero = capture(adapter_stdout, stderr=adapter_marker)
                self.assertEqual(controller.failure_details(rc_zero, adapter_step, paths)["adapter_failure"], adapter_record)
                with self.assertRaisesRegex(controller.VerificationError, "MINITEST_RESULT_REJECTED"):
                    controller.parse_capture(adapter_step, rc_zero, paths, "macos", None)
                success_stdout = adapter_stdout.replace("0.01 s = F", "0.01 s = .").replace("1 failures", "0 failures")
                self.assertNotIn("adapter_failure", controller.failure_details(
                    capture(success_stdout, stderr=adapter_marker), adapter_step, paths))
                self.assertTrue(controller.parse_capture(adapter_step, capture(success_stdout, stderr=adapter_marker),
                                                         paths, "linux", None).ok)

                # Class/message sentinels need not match: a missing message
                # coexists with a recognized class, and nil class + String
                # message is category=none/code=invalid, never a known cause.
                for category, code in (
                    ("missing", "missing"), ("none", "missing"), ("none", "none"), ("none", "invalid"),
                    ("invalid", "missing"), ("invalid", "invalid"), ("fixture-error", "missing"),
                    ("fixture-error", "invalid"), ("fixture-error", "elapsed-bound"), ("native-lifecycle-error", "other"),
                    ("native-error", "native-deadline"), ("native-protocol-error", "native-protocol"),
                    ("native-spawn-error", "spawn-waitability"), ("io-error", "other"), ("other", "other"),
                ):
                    record = {**adapter_record, "retainedDriverErrorCategory": category, "retainedDriverErrorCode": code}
                    self.assertEqual(controller.adapter_failure(adapter_bytes(record)), record)
                for first_cutoff, selected_cutoff in (("before-start", "before-cutoff"),
                                                     ("missing", "invalid"), ("at-or-after-cutoff", "before-start")):
                    record = {**adapter_record, "timingChecks": {**adapter_record["timingChecks"],
                              "firstTimeoutCutoff": first_cutoff, "selectedTimeoutCutoff": selected_cutoff,
                              "slowCleanupAtLeastFour": False, "captureCoversSlowCleanup": "invalid"}}
                    self.assertEqual(controller.adapter_failure(adapter_bytes(record)), record)

                # One vector per finite enum position covers every domain without
                # crossing outcomes with every mode/flag. Contradictory snapshot
                # facts stay visible; they neither repair UNKNOWN nor authorize
                # success. Missing and invalid are never coerced into false.
                for index in range(max(map(len, adapter_native_outcomes.values()))):
                    record = {**adapter_record, "nativeOutcomes": {
                        name: values[index % len(values)] for name, values in adapter_native_outcomes.items()}}
                    self.assertEqual(controller.adapter_failure(adapter_bytes(record)), record)
                for value in (True, False, "missing", "invalid"):
                    record = {**adapter_record,
                        "nativeChecks": dict.fromkeys(adapter_native_checks, value),
                        "timingChecks": {**adapter_record["timingChecks"], "slowCleanupWithinOriginalCutoff": value},
                        "slowChecks": dict.fromkeys(adapter_slow_checks, value)}
                    self.assertEqual(controller.adapter_failure(adapter_bytes(record)), record)

                # Maximize every independent finite field (and the dependent
                # mode/kind and retained-error pairs). No legal full v2 line can
                # silently disappear behind the old 2048-byte cap.
                longest_mode = max(adapter_contracts, key=lambda mode: len(mode) + len(adapter_contracts[mode][1]))
                error_category, error_code = max(
                    ((category, code) for category, codes in controller.ADAPTER_FAILURE_DRIVER_CODES.items() for code in codes),
                    key=lambda pair: len(pair[0]) + len(pair[1]))
                maximum_record = {**adapter_record,
                    "platform": "android", "mode": longest_mode, "expectedKind": adapter_contracts[longest_mode][1],
                    "resultKind": max((kind for kind in controller.ADAPTER_FAILURE_RESULT_KINDS
                                       if kind != adapter_contracts[longest_mode][1]), key=len),
                    "driverExitStatus": 255, "retainedDriverErrorCategory": error_category,
                    "retainedDriverErrorCode": error_code,
                    "adapterErrorCategory": max(controller.ADAPTER_FAILURE_DRIVER_CODES, key=len),
                    "resultChecks": dict.fromkeys(adapter_result_checks, "missing"),
                    "nativeChecks": dict.fromkeys(adapter_native_checks, "missing"),
                    "timingChecks": {name: "at-or-after-cutoff" if name in ("firstTimeoutCutoff", "selectedTimeoutCutoff")
                                     else "missing" for name in adapter_timing_checks},
                    "nativeOutcomes": {name: max(values, key=len) for name, values in adapter_native_outcomes.items()},
                    "slowChecks": dict.fromkeys(adapter_slow_checks, "missing")}
                maximum_marker = adapter_bytes(maximum_record)
                self.assertGreater(len(maximum_marker), 2048)
                self.assertLessEqual(len(maximum_marker), 4096)
                self.assertEqual(controller.adapter_failure(maximum_marker), maximum_record)
                # Padding is not canonical. At exactly 4096 bytes the bounded
                # reader may inspect JSON; at 4097 it must reject BEFORE parsing.
                # Both sizes count the prefix and the final LF, not just JSON.
                at_limit = maximum_marker[:-1] + b" " * (4096 - len(maximum_marker)) + b"\n"
                oversized = at_limit[:-1] + b" \n"
                self.assertEqual((len(at_limit), len(oversized)), (4096, 4097))
                with patch.object(controller, "strict_json", wraps=controller.strict_json) as decode:
                    self.assertIsNone(controller.adapter_failure(at_limit))
                decode.assert_called_once()
                with patch.object(controller, "strict_json", side_effect=AssertionError("oversized adapter JSON was parsed")) as decode:
                    self.assertIsNone(controller.adapter_failure(oversized))
                decode.assert_not_called()

                for transcript in (
                    clean + failed_footer, clean + adapter_target + ":\n" + failed_footer,
                    clean + adapter_target + " = unfinished\n" + failed_footer,
                    adapter_stdout.replace("0.01 s = F", "0.01 s = S"),
                    adapter_stdout.replace("0.01 s = F", "0.01 s = .\n0.01 s = F"),
                    clean + adapter_target_failure * 2 + failed_footer,
                    clean + failed_footer + adapter_target_failure,
                ):
                    self.assertNotIn("adapter_failure", controller.failure_details(
                        capture(transcript, stderr=adapter_marker, ok=False, returncode=1), adapter_step, paths))
                self.assertNotIn("adapter_failure", controller.failure_details(
                    capture(adapter_stdout + adapter_marker.decode("ascii"), ok=False, returncode=1), adapter_step, paths))
                wrong_platform = adapter_bytes({**adapter_record, "platform": "android"})
                self.assertNotIn("adapter_failure", controller.failure_details(
                    capture(adapter_stdout, stderr=wrong_platform, ok=False, returncode=1), adapter_step, paths))
                wrong_target = "IosUploadValidationTest#" + adapter_contracts["inherited"][0]
                with patch.object(controller, "ruby_capture_ids", return_value=(*adapter_ids, wrong_target)):
                    self.assertNotIn("adapter_failure", controller.failure_details(capture(adapter_stdout,
                        stderr=adapter_bytes({**adapter_record, "mode": "inherited"}), ok=False, returncode=1),
                        adapter_step, paths))
                with patch.object(controller, "ruby_capture_ids", return_value=expected):
                    self.assertNotIn("adapter_failure", controller.failure_details(failed_capture, adapter_step, paths))
                for wrong_step in (
                    dataclasses.replace(adapter_step, id="ruby-native-capture"),
                    dataclasses.replace(adapter_step, id="ruby-native-owner"),
                    dataclasses.replace(adapter_step, id="ruby-play_store"),
                    dataclasses.replace(adapter_step, id="ruby-android_upload_validation"),
                    dataclasses.replace(adapter_step, native_partition="all"),
                    dataclasses.replace(adapter_step, native_partition="ownership-unknown-capture-reap"),
                    dataclasses.replace(adapter_step, native_partition="kill-startup"),
                    dataclasses.replace(adapter_step, parser="exit"),
                ):
                    self.assertNotIn("adapter_failure", controller.failure_details(failed_capture, wrong_step, paths))
                with patch.object(controller, "ruby_capture_ids", return_value=tuple(sorted((*many_ids, adapter_target)))):
                    detail = controller.failure_details(capture(many_stdout + adapter_target_failure, stderr=adapter_marker,
                        ok=False, returncode=1), adapter_step, paths)
                    self.assertGreater(detail["minitest_structure"]["start_records_omitted"], 0)
                    self.assertEqual(detail["adapter_failure"], adapter_record)
                    self.assertNotIn("adapter_failure", controller.failure_details(capture(
                        adapter_target_failure + many_stdout + adapter_target_failure,
                        stderr=adapter_marker, ok=False, returncode=1), adapter_step, paths))

                invalid_adapter = [
                    {key: value for key, value in adapter_record.items() if key != "expectedKind"},
                    {**adapter_record, "private": "PRIVATE_ROOT"}, {key: adapter_record[key] for key in reversed(adapter_fields)},
                    *({**adapter_record, "schema": value} for value in (True, 1, 2.0, "2", 3)),
                    {**adapter_record, "platform": "PRIVATE_PLATFORM"},
                    {**adapter_record, "mode": "native-setup-interrupt"}, {**adapter_record, "expectedKind": "readiness"},
                    {**adapter_record, "resultKind": "PRIVATE_KIND"}, {**adapter_record, "resultKind": None},
                    *({**adapter_record, "driverExitStatus": value} for value in (True, 1.0, -1, 256)),
                    {**adapter_record, "retainedDriverErrorCategory": []}, {**adapter_record, "adapterErrorCategory": "PRIVATE_CLASS"},
                    {**adapter_record, "retainedDriverErrorCode": None}, {**adapter_record, "retainedDriverErrorCode": "PRIVATE_MESSAGE"},
                    *({**adapter_record, "failedPredicates": value} for value in
                      ([], ["driver-status", "result-kind"], ["result-kind"], ["result-kind", "driver-status", "driver-status"])),
                ]
                invalid_adapter.extend({**adapter_record, "retainedDriverErrorCategory": category, "retainedDriverErrorCode": code}
                    for category, code in (("missing", "invalid"), ("none", "other"), ("invalid", "none"),
                        ("native-protocol-error", "native-deadline"), ("fixture-error", "native-lifecycle"),
                        ("native-spawn-error", "elapsed-bound"), ("other", "native-unknown"), ("io-error", "none")))
                for group in ("resultChecks", "nativeChecks", "timingChecks", "nativeOutcomes", "slowChecks"):
                    group_checks = adapter_record[group]
                    invalid_adapter.extend({**adapter_record, group: value} for value in (
                        None, [], {name: value for name, value in group_checks.items() if name != next(iter(group_checks))},
                        {**group_checks, "PRIVATE_CHECK": True}, {name: group_checks[name] for name in reversed(group_checks)},
                        {**group_checks, next(iter(group_checks)): 0},
                    ))
                invalid_adapter.extend({**adapter_record, "timingChecks": {**adapter_record["timingChecks"], key: value}}
                    for key, value in (("firstTimeoutCutoff", True), ("selectedTimeoutCutoff", "PRIVATE_TIME"),
                        ("captureWithinLimit", 0.5), ("captureWithinLimit", float("nan")),
                        ("slowCleanupAtLeastFour", float("inf")), ("captureCoversSlowCleanup", None),
                        ("slowCleanupWithinOriginalCutoff", 0)))
                invalid_adapter.extend({**adapter_record, "nativeOutcomes": {**adapter_record["nativeOutcomes"], key: value}}
                    for key, value in (("custodian", "reaped"), ("keeper", "not_attempted"), ("validator", "exit3"),
                        ("finalOutcome", "confirmed"), ("finalCleanup", "failed"), ("groupState", "not_created"),
                        ("captureState", "not_constructed"), ("creatorState", "exit0"),
                        ("custodian", True), ("custodian", None), ("custodian", []), ("custodian", "PRIVATE_OUTCOME")))
                invalid_adapter.extend({**adapter_record, "slowChecks": {**adapter_record["slowChecks"], "delayFailed": value}}
                    for value in (0, None, "PRIVATE_DELAY"))
                # Common framing is already exhaustively covered above. These
                # new-shape cases prove this decoder actually uses that reader.
                invalid_markers = [*(adapter_bytes(record) for record in invalid_adapter),
                    adapter_marker * 2, adapter_marker.replace(b'"schema":2', b'"schema":2,"schema":2'),
                    adapter_marker.replace(b'"ready":true', b'"ready":true,"ready":true'),
                    adapter_marker.replace(b'"custodian":"exit2"', b'"custodian":"exit2","custodian":"exit2"'),
                    adapter_marker.replace(b'"delayFailed":"missing"', b'"delayFailed":"missing","delayFailed":"missing"'),
                    adapter_marker.replace(b'"schema":2', b'"schema": 2'), adapter_marker[:-1], oversized,
                ]
                for raw in invalid_markers:
                    detail = controller.failure_details(capture(adapter_stdout, stderr=raw, ok=False, returncode=1),
                                                        adapter_step, paths, deadline=1000.0)
                    self.assertNotIn("adapter_failure", detail)
                    self.assertEqual(detail["returncode"], 1)
                    self.assertNotIn("PRIVATE_", json.dumps(detail))

                expired = [False]
                def expired_adapter_parse(_text):
                    expired[0] = True
                    raise ValueError("PRIVATE_MESSAGE")
                with patch.object(controller, "strict_json", side_effect=expired_adapter_parse), \
                        patch.object(controller.time, "monotonic", side_effect=lambda: 1000.0 if expired[0] else 999.0), \
                        self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                    controller.failure_details(failed_capture, adapter_step, paths, deadline=1000.0)
                expired[0] = False
                original_scan = controller.minitest_records
                def expire_adapter_scan(text, identifiers, *, deadline):
                    if identifiers == (adapter_target,):
                        expired[0] = True
                    return original_scan(text, identifiers, deadline=deadline)
                with patch.object(controller, "minitest_records", side_effect=expire_adapter_scan), \
                        patch.object(controller.time, "monotonic", side_effect=lambda: 1000.0 if expired[0] else 999.0), \
                        self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                    controller.failure_details(failed_capture, adapter_step, paths, deadline=1000.0)
                for interruption in (KeyboardInterrupt("PRIVATE_MESSAGE"), SystemExit(7)):
                    with patch.object(controller, "strict_json", side_effect=interruption), \
                            self.assertRaises(type(interruption)) as raised:
                        controller.failure_details(failed_capture, adapter_step, paths, deadline=1000.0)
                    self.assertIs(raised.exception, interruption)

            for field, value in (("returncode", False), ("waited", False), ("stdout_eof", False),
                                 ("stderr_eof", False), ("domain_finality", False),
                                 ("primary_error", "fixture"), ("cleanup_errors", ("fixture",))):
                with self.subTest(field=field), self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                    controller.parse_capture(step, capture(noisy + footer, **{field: value}), paths, "linux", None)
            with patch.object(controller.time, "monotonic", return_value=100.0):
                with self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                    controller.failure_details(capture(clean + footer), step, paths, deadline=100.0)
            original_finditer = controller.re.finditer
            location_pattern = r"((?:tests/workflow|fastlane)/[A-Za-z0-9_]+\.rb):([1-9][0-9]{0,5})"
            for expiry in ("during", "after"):
                expired = [False]

                def expiring_locations(pattern, text):
                    matches = original_finditer(pattern, text)
                    if pattern != location_pattern or text != stderr_locations:
                        yield from matches
                        return
                    for match in matches:
                        if expiry == "during":
                            expired[0] = True
                        yield match
                        if expiry == "during":
                            self.fail("expired location scan continued")
                    expired[0] = True

                with self.subTest(expiry=expiry), \
                        patch.object(controller.re, "finditer", side_effect=expiring_locations), \
                        patch.object(controller.time, "monotonic", side_effect=lambda: 100.0 if expired[0] else 99.0), \
                        self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                    controller.failure_details(capture(clean + footer, stderr=stderr_locations.encode()),
                                               step, paths, deadline=100.0)

    def test_native_failure_diagnostics_are_source_bound_and_cannot_authorize_success(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        expected = ("unit.synthetic.NativeContracts.test_native",)
        checks = SimpleNamespace(native_partition_ids=lambda *_args, **_kwargs: expected)
        step = controller.Step("native-profile-source", parser="native")
        row = {"id": "system-code", "outcome": "error", "category": "nonzero-exit", "errno": None, "returncode": 1}

        def envelope(records, phase="prerequisite", **changes):
            return {"schema": 1, "phase": phase, "records": records, **changes}

        def encode(value):
            return controller.NATIVE_DIAGNOSTIC_PREFIX + json.dumps(value) + "\n"

        def capture(text, **changes):
            values = dict(ok=False, returncode=1, waited=True, stdout_eof=True, stderr_eof=True,
                          domain_finality=True, primary_error=None, cleanup_errors=(), stdout=b"",
                          stderr=text.encode(), duration=0.03, timed_out=False, cancelled=False,
                          persisted=(0, len(text)))
            return SimpleNamespace(**{**values, **changes})

        for identifier in ("openssl-version", "clang-discovery", "dsymutil-discovery", "system-code"):
            value = envelope([{**row, "id": identifier}])
            self.assertEqual(controller.native_failure_diagnostic(encode(value), expected), value)
        for identifier in (expected[0], "setUpClass (unit.synthetic.NativeContracts)",
                           "tearDownClass (unit.synthetic.NativeContracts)",
                           "setUpModule (unit.synthetic)", "tearDownModule (unit.synthetic)"):
            value = envelope([{**row, "id": identifier}], "tests")
            self.assertEqual(controller.native_failure_diagnostic(encode(value), expected), value)
        repeated = envelope([{**row, "id": expected[0]}] * 2, "tests")
        self.assertEqual(controller.native_failure_diagnostic(encode(repeated), expected), repeated)
        source = encode(envelope([row])) + "PRIVATE_PATH: Operation not permitted\ninternal error in Code Signing subsystem\n"
        result = controller.failure_details(capture(source), step, paths, checks=checks)
        self.assertEqual(result["native_diagnostic"], envelope([row]))
        self.assertEqual(result["native_error_tokens"], ["operation-not-permitted", "code-signing-internal"])
        self.assertNotIn("PRIVATE_PATH", json.dumps(result))
        self.assertEqual(result["returncode"], 1)
        self.assertTrue(result["waited"])

        invalid = [envelope([row], schema=True), envelope([row], phase="PRIVATE_PHASE"),
                   envelope([row], extra="PRIVATE_VALUE"), envelope([]), envelope([row] * 17),
                   envelope([{**row, "id": "PRIVATE_COMMAND"}]),
                   envelope([{**row, "id": "setUpClass (unit.private.Secret)"}], "tests"),
                   envelope([{**row, "message": "PRIVATE_VALUE"}]),
                   envelope([{**row, "outcome": "ok"}]), envelope([{**row, "outcome": "skip"}]),
                   envelope([{**row, "category": "PRIVATE_CATEGORY"}]),
                   envelope([{**row, "category": "os-error"}]),  # Non-null returncode on wrong category.
                   envelope([{**row, "errno": 5}]),
                   *(envelope([{**row, "returncode": bad}]) for bad in (True, 0, -256, 256, 1.0, "1")),
                   *(envelope([{**row, "category": "os-error", "returncode": None, "errno": bad}])
                     for bad in (True, 0, 4096, 1.0, "5"))]
        for value in invalid:
            with self.subTest(value=value):
                self.assertIsNone(controller.native_failure_diagnostic(encode(value), expected))
                detail = controller.failure_details(capture(encode(value)), step, paths, checks=checks)
                self.assertNotIn("native_diagnostic", detail)
                self.assertNotIn("PRIVATE_", json.dumps(detail))
        good = encode(envelope([row]))
        for malformed in (good + good, controller.NATIVE_DIAGNOSTIC_PREFIX + "x" * (16 * 1024 + 1),
                          controller.NATIVE_DIAGNOSTIC_PREFIX + '{"schema":1,"schema":1}\n',
                          controller.NATIVE_DIAGNOSTIC_PREFIX + "not-json\n"):
            detail = controller.failure_details(capture(malformed), step, paths, checks=checks)
            self.assertNotIn("native_diagnostic", detail)
        self.assertNotIn("native_diagnostic", controller.failure_details(capture(good),
                         controller.Step("ruby-native-capture", parser="minitest"), paths, checks=checks))
        full = "test_native (unit.synthetic.NativeContracts.test_native) ... ok\n\nRan 1 test in 0.01s\n\nOK\n"
        with self.assertRaisesRegex(controller.VerificationError, "NATIVE_FAILURE_DIAGNOSTIC_ON_SUCCESS"):
            controller.parse_capture(step, capture(good + full, ok=True, returncode=0), paths, "macos", checks)
        with patch.object(controller.time, "monotonic", return_value=100.0):
            with self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                controller.failure_details(capture(good), step, paths, checks=checks, deadline=100.0)

    def test_native_text_parser_normalizes_real_method_identity_and_rejects_incomplete_output(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        expected = ("unit.synthetic.NativeContracts.test_native",)

        def identities(source, selection, **_kwargs):
            self.assertEqual(source, ROOT)
            self.assertEqual(selection, "all")
            return expected

        checks = SimpleNamespace(native_partition_ids=identities)
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
    def test_fixed_poison_partitions_preserve_full_wheel_and_authority_disjoint_union(self):
        checks = ci_module("ci_checks")
        poison = tuple(identifier for _name, identifier in _PYTHON_POISON_FIXTURES)
        parts = tuple(name for name, _identifier in _PYTHON_POISON_FIXTURES)
        self.assertEqual(checks.PYTHON_POISON_CASES, _PYTHON_POISON_FIXTURES)
        self.assertEqual(checks.PYTHON_POISON_IDS, poison)
        self.assertEqual(checks.PYTHON_POISON_PARTITIONS, parts)
        self.assertEqual(controller_module().PYTHON_POISON_PARTITIONS, parts)
        self.assertEqual(len(set(parts)), len(parts))
        self.assertEqual(len(set(poison)), len(poison))
        healthy = ("unit.synthetic.Contracts.test_first", "unit.synthetic.Contracts.test_second")
        complete = tuple(sorted(healthy + poison))
        for selection in ("full", "wheel"):
            with patch.object(checks, "expected_python_ids", return_value=complete) as source:
                self.assertEqual(checks.python_capture_ids(ROOT, selection, "all", deadline=42.0), complete)
                self.assertEqual(checks.python_capture_ids(ROOT, selection, "healthy", deadline=42.0), healthy)
                selected = [checks.python_capture_ids(ROOT, selection, name, deadline=42.0) for name in parts]
                self.assertEqual(selected, [(identifier,) for identifier in poison])
                self.assertEqual(tuple(sorted(healthy + tuple(identifier for ids in selected for identifier in ids))), complete)
                self.assertTrue(all(call.args == (ROOT, selection) and call.kwargs == {"deadline": 42.0}
                                    for call in source.call_args_list))
                for invalid in ("ordinary", "authority", "all-poison", poison[0], None, True, []):
                    with self.assertRaises(checks.CheckError):
                        checks.python_capture_ids(ROOT, selection, invalid)
        authority = checks.NATIVE_AUTHORITY_IDS
        with patch.object(checks, "expected_python_ids", return_value=tuple(sorted(authority + complete))):
            self.assertEqual(checks.native_partition_ids(ROOT, "authority"), authority)
            self.assertEqual(checks.native_partition_ids(ROOT, "ordinary"), healthy)
            self.assertEqual(tuple(checks.native_partition_ids(ROOT, part) for part in parts),
                             tuple((identifier,) for identifier in poison))
        for changed in (healthy, tuple(sorted(healthy + poison[:1])), tuple(sorted(complete + poison[:1])),
                        tuple(reversed(complete)), poison, list(complete)):
            with patch.object(checks, "expected_python_ids", return_value=changed), self.assertRaises(checks.CheckError):
                checks.python_capture_ids(ROOT, "full", "healthy")
        for missing in poison:
            incomplete = tuple(identifier for identifier in complete if identifier != missing)
            for selection in ("full", "wheel", "native"):
                inventory = tuple(sorted(authority + incomplete)) if selection == "native" else incomplete
                with self.subTest(selection=selection, missing=missing), \
                        patch.object(checks, "expected_python_ids", return_value=inventory), \
                        self.assertRaisesRegex(checks.CheckError, "PYTHON_POISON_INVENTORY"):
                    if selection == "native":
                        checks.native_partition_ids(ROOT, "ordinary")
                    else:
                        checks.python_capture_ids(ROOT, selection, "healthy")
        for selection in ("native", "all", None, True, []):
            with self.assertRaises(checks.CheckError):
                checks.python_capture_ids(ROOT, selection, "healthy")

    def test_python_healthy_discovery_withholds_only_poison_and_stops_on_actual_adverse_callbacks(self):
        checks = ci_module("ci_checks")
        poison = checks.PYTHON_POISON_IDS
        healthy = tuple(f"unit.synthetic.HealthyContracts.test_{name}" for name in ("first", "subject", "third"))
        complete = tuple(sorted(healthy + poison))
        for selection in ("full", "wheel"):
            for outcome in ("success", "allowed-skip", "error", "failure", "skip", "subtest", "expected-failure", "unexpected-success",
                            "missing-poison", "duplicate-discovery"):
                with self.subTest(selection=selection, outcome=outcome):
                    events, observations, retained = [], [], []

                    class Fixture(unittest.TestCase):
                        def __init__(self, identifier):
                            super().__init__("runTest")
                            self.identifier = identifier

                        def id(self):
                            return self.identifier

                        def runTest(self):
                            events.append(self.identifier)
                            if self.identifier in poison:
                                raise AssertionError("a poison fixture must never execute in the healthy capture")
                            if self.identifier != healthy[1]:
                                return
                            if outcome in {"error", "expected-failure"}:
                                raise OSError(5, "PRIVATE_FAKE_FAILURE")
                            if outcome == "failure":
                                self.fail("PRIVATE_FAKE_FAILURE")
                            if outcome in {"skip", "allowed-skip"}:
                                self.skipTest("PRIVATE_FAKE_SKIP")
                            if outcome == "subtest":
                                for _ in range(3):
                                    with self.subTest():
                                        raise OSError(5, "PRIVATE_FAKE_SUBTEST")

                    class ExpectedFixture(Fixture):
                        @unittest.expectedFailure
                        def runTest(self):
                            super().runTest()

                    class RetainingRunner(unittest.TextTestRunner):
                        def _makeResult(self):
                            result = super()._makeResult()
                            retained.append(result)
                            return result

                    loaded = [Fixture(healthy[0]),
                              (ExpectedFixture if outcome in {"expected-failure", "unexpected-success"} else Fixture)(healthy[1]),
                              Fixture(healthy[2]), *(Fixture(identifier) for identifier in poison)]
                    if outcome == "missing-poison":
                        loaded.pop()
                    elif outcome == "duplicate-discovery":
                        loaded.append(Fixture(poison[0]))
                    suite = unittest.TestSuite(loaded)
                    framework = SimpleNamespace(TestSuite=unittest.TestSuite, TextTestResult=unittest.TextTestResult,
                        TextTestRunner=RetainingRunner,
                        TestLoader=lambda: SimpleNamespace(errors=[], discover=lambda *_args, **_kwargs: suite))
                    with patch.object(checks, "unittest", framework), \
                            patch.object(checks, "expected_python_ids", return_value=complete), \
                            patch.object(checks, "WHEEL_PATTERNS", ("test_fixed_fixture.py",)), \
                            patch.object(checks, "LINUX_MACOS_SKIPS", frozenset({healthy[1]}) if outcome == "allowed-skip" else frozenset()), \
                            patch.object(checks, "_remaining", return_value=10.0), \
                            patch.object(checks, "_python_full_profile", return_value={"fixture": "admitted"}), \
                            patch.object(checks, "inspect_installed_wheel", return_value=None) as installed, \
                            patch.object(checks, "sys", SimpleNamespace(platform="linux", stderr=io.StringIO())), \
                            patch.object(checks, "os", SimpleNamespace(environ={"MOBILE_RELEASE_REQUIRE_RUBY_CONTRACTS": "1"})):
                        if outcome in {"success", "allowed-skip"}:
                            detail = checks.run_python_tests(ROOT, selection, 1000.0, observations, work_root=Path("/fixture/checks"))
                            self.assertEqual(detail["executed"], 3)
                            self.assertEqual(detail["failure_callbacks"], [])
                            self.assertEqual(detail["skipped"], int(outcome == "allowed-skip"))
                            self.assertEqual(events, list(healthy))
                            self.assertEqual(installed.call_count, 2 if selection == "wheel" else 0)
                        else:
                            with self.assertRaises(checks.CheckError) as raised:
                                checks.run_python_tests(ROOT, selection, 1000.0, observations, work_root=Path("/fixture/checks"))
                            if outcome in {"missing-poison", "duplicate-discovery"}:
                                self.assertEqual(events, [])
                                self.assertEqual(str(raised.exception), "TEST_LOADED_INVENTORY")
                            else:
                                self.assertEqual(events, list(healthy[:2]))
                                self.assertEqual(len(raised.exception.failure_callbacks), 1)
                                self.assertTrue(retained[0].failfast)
                                self.assertTrue(retained[0].shouldStop)
                                # A caller clearing unittest's ordinary stop
                                # flag still cannot start another test body.
                                retained[0].failfast = retained[0].shouldStop = False
                                with self.assertRaisesRegex(checks.CheckError, "TEST_CONTINUED_AFTER_FAILURE"):
                                    retained[0].startTest(Fixture(healthy[2]))
                                self.assertTrue(retained[0].shouldStop)
                    self.assertFalse(set(events) & set(poison))

    def test_native_partition_authority_is_exact_and_cannot_silently_expand(self):
        checks = ci_module("ci_checks")
        deadline = time.monotonic() + 30.0
        complete = checks.expected_python_ids(ROOT, "native", deadline=deadline)
        authority = checks.native_partition_ids(ROOT, "authority", deadline=deadline)
        ordinary = checks.native_partition_ids(ROOT, "ordinary", deadline=deadline)
        poison = tuple(identifier for name, _identifier in _PYTHON_POISON_FIXTURES
                       for identifier in checks.native_partition_ids(ROOT, name, deadline=deadline))
        self.assertEqual(authority, checks.NATIVE_AUTHORITY_IDS)
        self.assertEqual(len(authority), 5)
        self.assertTrue(ordinary)
        self.assertFalse(set(authority) & set(ordinary))
        self.assertEqual(tuple(sorted(authority + ordinary + poison)), complete)
        self.assertEqual(set(poison), {identifier for _name, identifier in _PYTHON_POISON_FIXTURES})
        self.assertEqual(len(set(authority + ordinary + poison)), len(complete))
        self.assertEqual(checks.native_partition_ids(ROOT, "all", deadline=deadline), complete)
        for prefix in ("unit.test_native_process.", "unit.test_profile_process_owner.", "unit.test_inspection_budget."):
            self.assertTrue(any(identifier.startswith(prefix) for identifier in ordinary))
            self.assertFalse(any(identifier.startswith(prefix) for identifier in authority))
        self.assertEqual(checks.NATIVE_PATTERNS, (
            "test_ios_profile_authority.py", "test_ios_profile_trust.py", "test_ios_profile_installation.py",
            "test_default_cancellation.py", "test_profile_processes.py", "test_macho_native.py",
            "test_native_process.py", "test_profile_process_owner.py", "test_inspection_budget.py"))
        self.assertEqual(set(checks.WHEEL_PATTERNS), {
            "test_init_transaction.py", "test_ios_entitlements.py", "test_ios_plist_binary.py",
            "test_native_process.py", "test_profile_process_owner.py", "test_default_cancellation.py",
            "test_profile_processes.py", "test_inspection_budget.py", "test_ios_profile_installation.py",
            "test_ios_profile_trust.py"})
        for invalid in ("unknown", "Authority", "", None, True, []):
            with self.subTest(partition=invalid), self.assertRaisesRegex(checks.CheckError, "NATIVE_PARTITION"):
                checks.native_partition_ids(ROOT, invalid, deadline=deadline)
        for changed in (tuple(name for name in complete if name != authority[0]),
                        tuple(sorted(complete + (authority[0],))),
                        tuple(sorted(complete + (authority[0].rsplit(".", 1)[0] + ".test_unreviewed",))),
                        authority):
            with self.subTest(inventory=changed), \
                    patch.object(checks, "expected_python_ids", return_value=changed), \
                    self.assertRaises(checks.CheckError):
                checks.native_partition_ids(ROOT, "authority", deadline=deadline)

    def test_native_compatibility_selectors_are_exact_ordinary_three_and_no_child_one(self):
        checks = ci_module("ci_checks")
        expected = tuple(sorted("unit.test_native_process.NativeProcessCompatibilityTests." + name for name in (
            "test_native_public_api_atomic_duplication", "test_native_helper_and_validator_fd_maps",
            "test_native_exact_terminal_wait_receipts")))
        self.assertEqual(checks.native_compatibility_ids(ROOT), expected)
        public = ("unit.test_native_process.NativeProcessCompatibilityTests.test_native_public_api_atomic_duplication",)
        self.assertEqual(checks.native_compatibility_ids(ROOT, public_only=True), public)
        self.assertTrue(set(expected) <= set(checks.native_partition_ids(ROOT, "ordinary")))
        self.assertFalse(set(expected) & set(checks.NATIVE_AUTHORITY_IDS))
        for changed in (expected[:2], expected + expected[:1], tuple(sorted(expected + (
                "unit.test_native_process.NativeProcessCompatibilityTests.test_unreviewed",)))):
            with patch.object(checks, "native_partition_ids", return_value=changed), self.assertRaisesRegex(
                    checks.CheckError, "NATIVE_COMPATIBILITY_INVENTORY"):
                checks.native_compatibility_ids(ROOT)
        for invalid in (None, 0, 1, "public", [], {}):
            with self.assertRaisesRegex(checks.CheckError, "NATIVE_COMPATIBILITY_SELECTION"):
                checks.native_compatibility_ids(ROOT, public_only=invalid)

    def test_native_package_inspection_requires_complete_bytes_and_immutable_ordinary_nodes(self):
        checks = ci_module("ci_checks")
        expected = {"__init__.py": b"# inert fixture\n", "data/apple-profile-roots.pem": b"synthetic public roots\n"}
        deadline = time.monotonic() + 30.0
        actual_lstat = Path.lstat
        with tempfile.TemporaryDirectory(prefix="mrk-ci-native-package-") as temporary:
            root = Path(temporary).resolve() / "mobile_release"
            root.mkdir()
            (root / "data").mkdir()
            for relative, content in expected.items():
                (root / relative).write_bytes(content)
            changes = {}

            def metadata(path):
                info = actual_lstat(path)
                if path != root and not path.is_relative_to(root):
                    return info
                # Only metadata is modeled: byte/inventory checks read these
                # tiny actual owned files. Never chown or edit provider paths.
                directory = stat.S_ISDIR(info.st_mode)
                values = dict(st_uid=0, st_gid=0, st_nlink=info.st_nlink,
                              st_mode=(stat.S_IFDIR | 0o555) if directory else (stat.S_IFREG | 0o444))
                if path == root / "__init__.py":
                    values.update(changes)
                return SimpleNamespace(**values)

            with patch.object(checks, "_source_package", return_value=expected), patch.object(Path, "lstat", metadata):
                result = checks.inspect_native_package(ROOT, root, deadline=deadline)
                self.assertEqual(result["files"], 2)
                self.assertEqual(result["modules"], 1)
                self.assertTrue(result["bytes_match_source"])
                self.assertTrue(result["immutable_modes"])
                for changed in ({"st_uid": 60123}, {"st_gid": 60123}, {"st_nlink": 2},
                                {"st_mode": stat.S_IFREG | 0o644}, {"st_mode": stat.S_IFREG | 0o4544}):
                    changes.clear()
                    changes.update(changed)
                    with self.subTest(metadata=changed), self.assertRaisesRegex(checks.CheckError, "NATIVE_PACKAGE_MODE"):
                        checks.inspect_native_package(ROOT, root, deadline=deadline)
                changes.clear()
                for mutation in ("changed", "missing", "extra-hook", "extra-directory"):
                    with self.subTest(mutation=mutation):
                        if mutation == "changed":
                            (root / "__init__.py").write_bytes(b"# changed inert fixture\n")
                        elif mutation == "missing":
                            (root / "__init__.py").unlink()
                        elif mutation == "extra-hook":
                            (root / "unreviewed.pth").write_bytes(b"# inert; must never load\n")
                        else:
                            (root / "extra").mkdir()
                        with self.assertRaisesRegex(checks.CheckError, "NATIVE_PACKAGE_BYTES"):
                            checks.inspect_native_package(ROOT, root, deadline=deadline)
                        if mutation in {"changed", "missing"}:
                            (root / "__init__.py").write_bytes(expected["__init__.py"])
                        elif mutation == "extra-hook":
                            (root / "unreviewed.pth").unlink()
                        else:
                            (root / "extra").rmdir()

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
        names = ("test_init_transaction.py", "test_ios_entitlements.py", "test_ios_plist_binary.py",
                 "test_native_process.py", "test_profile_process_owner.py", "test_default_cancellation.py",
                 "test_profile_processes.py", "test_inspection_budget.py", "test_ios_profile_installation.py",
                 "test_ios_profile_trust.py")
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
