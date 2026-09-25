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
import errno
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
from types import MappingProxyType, SimpleNamespace
from unittest.mock import patch

from .workflow_harness import evaluate_condition, load_workflow, simulate_steps


ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github/workflows/ci.yml"
_G_LINUX_METHODS = (
    "unit.test_signing_fixture.DelegatedTests.test_alias",
    "unit.test_signing_fixture.DelegatedTests.test_variants",
)
_G_DARWIN_ONLY_METHODS = (
    "unit.test_local_signing_composition.SigningCompositionTests.test_full_preflight_shares_one_guard_through_early_authentication_signing_build_and_late_authentication",
    "unit.test_local_signing_composition.SigningCompositionTests.test_real_early_and_late_profile_cleanup_signals_under_full_preflight_never_return_cancelled_content",
)
_WHEEL_DARWIN_SKIP_IDS = frozenset((*_G_DARWIN_ONLY_METHODS,
    # The wheel inventory also retains all five native profile-authority tests.
    # This expectation is independent of the production catalog/skip constants.
    "unit.test_ios_profile_authority.NativeProfileAuthorityTests.test_actual_signature_integrity_and_exact_signer_are_checked_before_policy",
    "unit.test_ios_profile_authority.NativeProfileAuthorityTests.test_complete_two_layer_synthetic_signature_succeeds_only_with_explicit_policy_seam",
    "unit.test_ios_profile_authority.NativeProfileAuthorityTests.test_default_policy_rejects_even_valid_signature_with_production_looking_fake_issuer",
    "unit.test_ios_profile_authority.NativeProfileAuthorityTests.test_real_production_policy_accepts_apple_public_issuer_not_test_or_macos_purpose",
    "unit.test_ios_profile_authority.NativeProfileAuthorityTests.test_signed_outer_cannot_authorize_unsigned_or_substituted_inner_profile",
    "unit.test_local_signing_native.SigningDarwinABITests.test_real_header_layout_and_local_volume_match_ctypes_without_private_state",
    "unit.test_checked_files.NativeCheckedFilesTests.test_actual_tmp_var_folders_and_physical_spellings_select_identical_private_bytes",
))


def _g_metadata_fixture(operating_system):
    """Closed inert metadata only; no actual G/test/helper import or execution."""
    if operating_system not in {"ubuntu-24.04", "macos-26"}:
        raise AssertionError("unexpected fixture G platform")
    methods = tuple(sorted(_G_LINUX_METHODS + (_G_DARWIN_ONLY_METHODS if operating_system == "macos-26" else ())))
    return methods, MappingProxyType({method: tuple("G/" + method + suffix for suffix in (
        ("/semantic/C/caller/04",) if method == _G_LINUX_METHODS[0] else
        ("/variant/first", "/variant/second") if method == _G_LINUX_METHODS[1] else ("/whole",)))
        for method in methods})


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
    ("poison-signing-launcher-loss", "workflow.test_local_signing_owner_loss.SigningLauncherLossTests.test_real_launcher_death_uses_original_anchor_cleanup_and_requires_domain_disposal"),
    ("poison-command-preguard-127", "workflow.test_command_loader_loss.CommandLoaderLossTests.test_preguard_normal_127_never_becomes_a_command_result"),
    ("poison-command-guarded-import", "workflow.test_command_loader_loss.CommandLoaderLossTests.test_guarded_import_failure_requires_original_domain_disposal"),
    ("poison-command-fence-pending-create-before", "workflow.test_command_fence_failure.CommandFenceFailureTests.test_original_c_loss_pending_create_before"),
    ("poison-command-fence-pending-create-after", "workflow.test_command_fence_failure.CommandFenceFailureTests.test_original_c_loss_pending_create_after"),
    ("poison-command-fence-pending-write-partial", "workflow.test_command_fence_failure.CommandFenceFailureTests.test_original_c_loss_pending_write_partial"),
    ("poison-command-fence-pending-write-after", "workflow.test_command_fence_failure.CommandFenceFailureTests.test_original_c_loss_pending_write_after"),
    ("poison-command-fence-data-fsync-after", "workflow.test_command_fence_failure.CommandFenceFailureTests.test_original_c_loss_data_fsync_after"),
    ("poison-command-fence-pending-close-after", "workflow.test_command_fence_failure.CommandFenceFailureTests.test_original_c_loss_pending_close_after"),
    ("poison-command-fence-final-link-after", "workflow.test_command_fence_failure.CommandFenceFailureTests.test_original_c_loss_final_link_after"),
    ("poison-command-fence-directory-fsync-after", "workflow.test_command_fence_failure.CommandFenceFailureTests.test_original_c_loss_directory_fsync_after"),
    ("poison-command-fence-pending-close-lost-return", "workflow.test_command_fence_failure.CommandFenceFailureTests.test_original_c_pending_close_lost_return"),
    ("poison-command-fence-final-link-lost-return", "workflow.test_command_fence_failure.CommandFenceFailureTests.test_original_c_final_link_lost_return"),
    ("poison-command-fence-foreign-pending-collision", "workflow.test_command_fence_failure.CommandFenceFailureTests.test_original_c_foreign_pending_collision"),
    ("poison-command-prepared-prefix-input-loss", "workflow.test_command_account_lifecycle.CommandAccountLifecycleTests.test_prepared_input_withdrawal_c_loss_fresh_prefix_recovery"),
    ("poison-command-account-hold-parent-loss", "workflow.test_command_account_lifecycle.CommandAccountLifecycleTests.test_original_hold_survives_true_parent_loss_and_is_absent_from_worker_map"),
    ("poison-signing-foreign-mixed-handlers", "unit.test_local_signing_composition.SigningCompositionTests.test_foreign_and_mixed_signal_owners_are_never_silently_overwritten_or_borrowed"),
    ("poison-profile-authenticator-publication", "unit.test_ios_entitlements.SignedEntitlementInventoryTests.test_mocked_authenticator_without_owner_publication_remains_fatal"),
    ("poison-recovery-profile-cleanup", "unit.test_operation_recovery.IosOperationRecoveryTests.test_profile_cleanup_uncertainty_stops_actual_fresh_validation_before_any_store_access"),
    ("poison-recovery-inspection-deadline", "unit.test_operation_recovery.IosOperationRecoveryTests.test_shared_deadline_prevents_next_authorization_boundary_and_retains_snapshots"),
    ("poison-recovery-readback-deadline", "unit.test_operation_recovery.IosOperationRecoveryTests.test_deadline_after_readback_preserves_precondition_and_retains_snapshot"),
    ("poison-profile-authentication-order", "unit.test_ios_profile_authority.CMSFramingTests.test_profile_requires_both_authentications_in_order_then_complete_correlation"),
    ("poison-profile-setup-unlink", "unit.test_ios_profile_installation.ProfileInstallationTests.test_ambiguous_setup_stage_unlink_is_not_implicitly_retried_or_resolved"),
    ("poison-profile-collision", "unit.test_ios_profile_installation.ProfileInstallationTests.test_collision_symlink_fifo_and_invalid_input_never_overwrite_existing_state"),
    ("poison-profile-partial-handler-install", "unit.test_ios_profile_installation.ProfileInstallationTests.test_custom_handlers_worker_threads_and_partial_handler_registration_preserve_host_state"),
    ("poison-profile-cleanup-observer", "unit.test_ios_profile_installation.ProfileInstallationTests.test_fallible_cleanup_observers_never_abandon_actual_owned_handles"),
    ("poison-profile-fstat", "unit.test_ios_profile_installation.ProfileInstallationTests.test_initial_fstat_failure_recovers_only_from_owned_fd_or_reports_empty_private_residue"),
    ("poison-profile-fsync-cleanup", "unit.test_ios_profile_installation.ProfileInstallationTests.test_partial_write_flush_fsync_and_link_failures_leave_no_owned_files"),
    ("poison-profile-replacement", "unit.test_ios_profile_installation.ProfileInstallationTests.test_replacement_or_edit_is_preserved_and_failed_cleanup_cannot_report_success"),
    ("poison-profile-directory-close", "unit.test_ios_profile_installation.ProfileInstallationTests.test_retained_normal_body_cannot_hide_directory_close_uncertainty"),
    ("poison-signing-content-conflict", "unit.test_local_signing_failures.SigningFailureTests.test_ordinary_content_conflict_keeps_safe_predispatch_cleanup"),
    ("poison-signing-profile-identity-conflict", "unit.test_local_signing_profile_identity.ProfileIdentityTests.test_direct_installer_preserves_all_real_owned_and_borrowed_conflicts"),
    ("poison-command-source-close", "unit.test_owned_process.CommandSourceOwnerTests.test_failed_close_latches_before_diagnostics_and_attempts_each_independent_slot_once"),
    ("poison-command-source-profile-conflict", "unit.test_owned_process.CommandSourceOwnerTests.test_original_profile_conflict_close_revokes_even_without_session_failure_flags"),
)
_PYTHON_FRESH_FIXTURES = (
    ("fresh-command-account-prepared", "workflow.test_command_account_lifecycle.CommandAccountLifecycleTests.test_prepared_no_target_original_fence_and_same_lease_cleanup"),
    ("fresh-model-command-bridge", "unit.test_local_signing_persistent.PersistentSigningTests.test_one_real_model_command_bridge_finishes_before_success"),
)
_PYTHON_SINGLETON_FIXTURES = _PYTHON_POISON_FIXTURES + _PYTHON_FRESH_FIXTURES
HOSTED_GUARD = '''set -euo pipefail
[[ "$MOBILE_RELEASE_RUNNER_ENVIRONMENT" == github-hosted ]]
'''
LINUX_TARGET_CONDITION = "${{ github.event_name != 'workflow_dispatch' || (inputs.verification_target == 'full' || inputs.verification_target == 'linux') }}"
NATIVE_TARGET_CONDITION = "${{ github.event_name != 'workflow_dispatch' || (inputs.verification_target == 'full' || inputs.verification_target == 'macos') }}"
NATIVE_SUPPORT_TARGET_CONDITION = "${{ github.event_name != 'workflow_dispatch' || (inputs.verification_target == 'full' || inputs.verification_target == 'macos' || inputs.verification_target == 'store-lane-macos') }}"
STORE_NATIVE_SCOPE = "${{ github.event_name == 'workflow_dispatch' && inputs.verification_target == 'store-lane-macos' && 'store-lane' || 'native-support' }}"
MATRIX_TARGET_CONDITION = "${{ github.event_name != 'workflow_dispatch' || (inputs.verification_target == 'full' || inputs.verification_target == 'signing-matrix-canary') }}"
MATRIX_SHARD_SELECTION = "${{ fromJSON(github.event_name == 'workflow_dispatch' && inputs.verification_target == 'signing-matrix-canary' && '[0]' || '[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47]') }}"
MATRIX_INCLUDE_SELECTION = "${{ fromJSON(github.event_name == 'workflow_dispatch' && inputs.verification_target == 'signing-matrix-canary' && '[{\"os\":\"ubuntu-24.04\",\"shard\":20},{\"os\":\"ubuntu-24.04\",\"shard\":28},{\"os\":\"macos-26\",\"shard\":1},{\"os\":\"macos-26\",\"shard\":12},{\"os\":\"macos-26\",\"shard\":37}]' || '[]') }}"
ADAPTER_TARGET_CONDITION = "${{ github.event_name == 'workflow_dispatch' && (inputs.verification_target == 'signing-adapter' || inputs.verification_target == 'signing-adapter-linux' || inputs.verification_target == 'signing-adapter-macos') }}"
ADAPTER_OS_SELECTION = "${{ fromJSON(github.event_name == 'workflow_dispatch' && inputs.verification_target == 'signing-adapter-linux' && '[\"ubuntu-24.04\"]' || github.event_name == 'workflow_dispatch' && inputs.verification_target == 'signing-adapter-macos' && '[\"macos-26\"]' || '[\"ubuntu-24.04\",\"macos-26\"]') }}"
VERIFICATION_CONCURRENCY = "release-kit-ci-${{ github.ref }}-${{ github.event_name }}-${{ inputs.verification_target || 'full' }}"
AGGREGATE_GUARD = '''set -euo pipefail
[[ "$LINUX_RESULT" == success && "$NATIVE_RESULT" == success && "$NATIVE_SUPPORT_RESULT" == success && "$MATRIX_RESULT" == success ]]
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


def coordinator_shell(platform: str, *, scope: str | None = None) -> str:
    if platform not in {"linux", "macos"}:
        raise ValueError("unsupported CI platform")
    if platform == "linux" and scope is None:
        java = '--java-home "$JAVA_HOME_21_X64" '
    elif platform == "macos" and scope in {None, "native-python"}:
        java = '--scope native-python '
    elif platform == "macos" and scope == "native-support":
        java = '--scope "$MRK_SCOPE" '
    else:
        raise ValueError("unsupported CI scope")
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
                "description": "Full verification, Linux/macOS-only evidence, Store-native macOS, signing-adapter smoke, or fixed-shard matrix canary (partial aggregate remains incomplete)",
                "type": "choice", "required": True, "default": "full", "options": ["full", "linux", "macos", "store-lane-macos", "signing-adapter", "signing-adapter-linux", "signing-adapter-macos", "signing-matrix-canary"],
            }}},
        })
        self.assertEqual(workflow["concurrency"], {"group": VERIFICATION_CONCURRENCY, "cancel-in-progress": True})
        self.assertEqual(set(workflow["jobs"]), {"test-linux", "test-native-profiles", "test-native-support", "test-signing-matrix", "test-signing-adapter", "test"})
        text = CI.read_text(encoding="utf-8")
        self.assertNotIn("secrets.", text)
        self.assertNotIn("id-token:", text)
        for platform, name, image in (("linux", "test-linux", "ubuntu-24.04"),
                                      ("macos", "test-native-profiles", "macos-26"),
                                      ("macos", "test-native-support", "macos-26")):
            with self.subTest(job=name):
                job = workflow["jobs"][name]
                self.assertEqual(job["runs-on"], image)
                self.assertEqual(job["timeout-minutes"], 60)
                if platform == "linux":
                    self.assertEqual(job["if"], LINUX_TARGET_CONDITION)
                elif name == "test-native-support":
                    self.assertEqual(job["if"], NATIVE_SUPPORT_TARGET_CONDITION)
                else:
                    self.assertEqual(job["if"], NATIVE_TARGET_CONDITION)
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
                    **({"MRK_SCOPE": STORE_NATIVE_SCOPE} if name == "test-native-support" else {}),
                })
                self.assertEqual(owner["shell"], "bash")
                self.assertEqual(owner["run"], coordinator_shell(
                    platform, scope="native-support" if name == "test-native-support" else None))
        self.assertEqual(coordinator_shell("macos"), coordinator_shell("macos", scope="native-python"))
        for platform, scope in (("unknown", None), ("linux", "native-python"),
                                ("linux", "native-support"), ("linux", "platform"),
                                ("macos", "platform"), ("macos", "store-lane"), ("macos", "unknown")):
            with self.subTest(unsupported_coordinator=(platform, scope)), self.assertRaises(ValueError):
                coordinator_shell(platform, scope=scope)

    def test_manual_native_candidate_routing_and_protected_aggregate_remain_fail_closed(self):
        workflow = load_workflow(CI)
        linux, native, support, aggregate = (workflow["jobs"][name] for name in
                                            ("test-linux", "test-native-profiles", "test-native-support", "test"))
        self.assertEqual(linux["if"], LINUX_TARGET_CONDITION)
        self.assertEqual(native["if"], NATIVE_TARGET_CONDITION)
        self.assertEqual(support["if"], NATIVE_SUPPORT_TARGET_CONDITION)
        matrix = workflow["jobs"]["test-signing-matrix"]
        self.assertEqual(matrix["if"], MATRIX_TARGET_CONDITION)
        selection = matrix["strategy"]["matrix"]["shard"]
        self.assertEqual(selection, MATRIX_SHARD_SELECTION)
        # The exact expression above admits just two literal JSON operands.
        # Evaluate its real boolean selector with the existing restricted
        # interpreter; never interpret caller-supplied JSON or broaden it.
        left, full_literal = selection.removeprefix("${{ fromJSON(").removesuffix(") }}").rsplit(" || ", 1)
        canary_condition, canary_literal = left.rsplit(" && ", 1)
        canary_shards, full_shards = (json.loads(literal[1:-1]) for literal in (canary_literal, full_literal))
        self.assertEqual((canary_shards, full_shards), ([0], list(range(48))))
        include = matrix["strategy"]["matrix"]["include"]
        self.assertEqual(include, MATRIX_INCLUDE_SELECTION)
        include_left, full_include_literal = include.removeprefix("${{ fromJSON(").removesuffix(") }}").rsplit(" || ", 1)
        include_condition, canary_include_literal = include_left.rsplit(" && ", 1)
        self.assertEqual(include_condition, canary_condition)
        canary_include, full_include = (json.loads(literal[1:-1]) for literal in
                                        (canary_include_literal, full_include_literal))
        self.assertEqual((canary_include, full_include),
                         ([{"os": "ubuntu-24.04", "shard": 20}, {"os": "ubuntu-24.04", "shard": 28},
                           {"os": "macos-26", "shard": 1}, {"os": "macos-26", "shard": 12},
                           {"os": "macos-26", "shard": 37}], []))
        self.assertEqual(matrix["strategy"]["matrix"]["os"], ["ubuntu-24.04", "macos-26"])
        for event, ref in (("pull_request", "refs/pull/1/merge"), ("push", "refs/heads/main"),
                           ("workflow_dispatch", "refs/heads/qa006-native-candidate")):
            for target in ("full", "linux", "macos", "store-lane-macos", "signing-adapter", "signing-adapter-linux", "signing-adapter-macos", "signing-matrix-canary", None, "", "unknown",
                           "LINUX", "LiNuX", "linux ", " linux",
                           "MACOS", "mAcOs", "SIGNING-ADAPTER-MACOS", "signing-adapter-macos ",
                           "SIGNING-ADAPTER-LINUX", "signing-adapter-linux ",
                           "SIGNING-MATRIX-CANARY", "signing-matrix-canary ", "[0]", "macos "):
                with self.subTest(candidate_route=(event, target)):
                    context = {"github": {"event_name": event, "ref": ref}}
                    # For this one pinned comparison and fixed ASCII fixture,
                    # model Actions' case-insensitive string equality explicitly.
                    # The shared restricted interpreter remains unchanged.
                    compared = target.lower() if target is not None else None
                    if target is not None:
                        context["inputs"] = {"verification_target": compared}
                    dispatch = event == "workflow_dispatch"
                    expected = {"test-linux": not dispatch or compared in {"full", "linux"},
                                "test-native-profiles": not dispatch or compared in {"full", "macos"},
                                "test-native-support": not dispatch or compared in {"full", "macos", "store-lane-macos"},
                                "test-signing-matrix": not dispatch or compared in {"full", "signing-matrix-canary"},
                                "test-signing-adapter": dispatch and compared in {"signing-adapter", "signing-adapter-linux", "signing-adapter-macos"}}
                    for name, enabled in expected.items():
                        self.assertEqual(evaluate_condition(workflow["jobs"][name]["if"], context,
                                                            success=True, cancelled=False), enabled)
                    if dispatch and compared not in {"full", "linux", "macos", "store-lane-macos", "signing-adapter", "signing-adapter-linux", "signing-adapter-macos", "signing-matrix-canary"}:
                        self.assertFalse(any(expected.values()))  # Skipped prerequisites cannot pass the pinned guard.
                    selected = canary_shards if evaluate_condition(canary_condition, context,
                        success=True, cancelled=False) else full_shards
                    self.assertEqual(selected, [0] if dispatch and compared == "signing-matrix-canary" else list(range(48)))
                    included = canary_include if evaluate_condition(include_condition, context,
                        success=True, cancelled=False) else full_include
                    original_cells = {(system, shard) for system in matrix["strategy"]["matrix"]["os"]
                                      for shard in selected}
                    extra_cells = {(item["os"], item["shard"]) for item in included}
                    # Both fixed-axis values are explicit. No canary include
                    # can merge into an original shard0 combination, so Actions
                    # appends these five cells; it does not create a cross product.
                    self.assertTrue(original_cells.isdisjoint(extra_cells))
                    self.assertEqual(len(extra_cells), len(included))
                    expected_cells = ({("ubuntu-24.04", 0), ("ubuntu-24.04", 20), ("ubuntu-24.04", 28),
                                       ("macos-26", 0), ("macos-26", 1), ("macos-26", 12), ("macos-26", 37)}
                                      if dispatch and compared == "signing-matrix-canary" else
                                      {(system, shard) for system in ("ubuntu-24.04", "macos-26")
                                       for shard in range(48)})
                    self.assertEqual(original_cells | extra_cells, expected_cells)

        # This is the existing fixed job, not a synthesized cross-run status.
        # Pin every field before the harmless shell can be executed below.
        self.assertEqual({key: value for key, value in aggregate.items() if key != "steps"}, {
            "needs": ["test-linux", "test-native-profiles", "test-native-support", "test-signing-matrix"], "if": "${{ always() }}",
            "runs-on": "ubuntu-24.04", "timeout-minutes": 5, "permissions": {"contents": "read"},
        })
        self.assertEqual(aggregate["steps"][0], {"name": "Require every verification job to succeed", "env": {
            "LINUX_RESULT": "${{ needs.test-linux.result }}", "NATIVE_RESULT": "${{ needs.test-native-profiles.result }}",
            "NATIVE_SUPPORT_RESULT": "${{ needs.test-native-support.result }}",
            "MATRIX_RESULT": "${{ needs.test-signing-matrix.result }}",
        }, "run": AGGREGATE_GUARD})
        self.assertEqual(len(aggregate["steps"]), 4)
        self.assertIn("--reduce", aggregate["steps"][-1]["run"])
        self.assertEqual(workflow["jobs"]["test-signing-matrix"]["if"], MATRIX_TARGET_CONDITION)
        self.assertTrue(evaluate_condition(aggregate["if"], {}, success=False, cancelled=True))
        states = ["failure", "cancelled", "skipped", "queued", "unavailable", "", None]
        results = [("success", "success", "success", "success")]
        for state in states:
            results.extend(((state, "success", "success", "success"), ("success", state, "success", "success"),
                            ("success", "success", state, "success"), ("success", "success", "success", state),
                            (state, state, state, state)))
        body = aggregate["steps"][0]["run"]
        for linux_result, native_result, support_result, matrix_result in results:
            with self.subTest(protected_results=(linux_result, native_result, support_result, matrix_result)):
                env = {"PATH": "/usr/bin:/bin"}
                if linux_result is not None:
                    env["LINUX_RESULT"] = linux_result
                if native_result is not None:
                    env["NATIVE_RESULT"] = native_result
                if support_result is not None:
                    env["NATIVE_SUPPORT_RESULT"] = support_result
                if matrix_result is not None:
                    env["MATRIX_RESULT"] = matrix_result
                result = subprocess.run(["bash", "--noprofile", "--norc", "-c", body],
                                        env=env, capture_output=True, timeout=5)
                self.assertEqual(result.returncode == 0,
                                 linux_result == native_result == support_result == matrix_result == "success")
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
                  group_for("workflow_dispatch", "full"), group_for("workflow_dispatch", "linux"), group_for("workflow_dispatch", "macos"),
                  group_for("workflow_dispatch", "signing-adapter"), group_for("workflow_dispatch", "signing-adapter-linux"),
                  group_for("workflow_dispatch", "signing-adapter-macos"), group_for("workflow_dispatch", "store-lane-macos"),
                  group_for("workflow_dispatch", "signing-matrix-canary")}
        self.assertEqual(len(groups), 10)  # Partial dispatch cannot cancel any full event/target.
        self.assertTrue(all("${{" not in value for value in groups))
        for absent in (None, ""):
            self.assertEqual(group_for("workflow_dispatch", absent), group_for("workflow_dispatch", "full"))

    def test_signing_adapter_smoke_is_explicit_two_os_and_cannot_publish_matrix_proof(self):
        workflow = load_workflow(CI)
        job = workflow["jobs"]["test-signing-adapter"]
        self.assertEqual(job["if"], ADAPTER_TARGET_CONDITION)
        self.assertEqual(job["runs-on"], "${{ matrix.os }}")
        self.assertEqual(job["strategy"], {"fail-fast": False, "max-parallel": 2,
                                           "matrix": {"os": ADAPTER_OS_SELECTION}})
        # Pin the whole expression before interpreting its two fixed selectors.
        selection = job["strategy"]["matrix"]["os"]
        linux_branch, macos_branch, otherwise = selection.removeprefix("${{ fromJSON(").removesuffix(") }}").split(" || ")
        linux_condition, linux_selected = linux_branch.rsplit(" && ", 1)
        macos_condition, macos_selected = macos_branch.rsplit(" && ", 1)
        linux_only, macos_only, both = (json.loads(literal[1:-1]) for literal in (linux_selected, macos_selected, otherwise))
        self.assertEqual((linux_only, macos_only, both), (["ubuntu-24.04"], ["macos-26"], ["ubuntu-24.04", "macos-26"]))
        for event in ("workflow_dispatch", "pull_request", "push"):
            for target in ("signing-adapter", "signing-adapter-macos", "SIGNING-ADAPTER-MACOS",
                           "signing-adapter-linux", "SIGNING-ADAPTER-LINUX", "signing-adapter-linux ",
                           "signing-adapter-macos ", "full", "macos", "linux", "signing-matrix-canary", "unknown", ""):
                context = {"github": {"event_name": event}, "inputs": {"verification_target": target.lower()}}
                systems = (linux_only if evaluate_condition(linux_condition, context, success=True, cancelled=False)
                           else macos_only if evaluate_condition(macos_condition, context, success=True, cancelled=False) else both)
                expected = (linux_only if event == "workflow_dispatch" and target.lower() == "signing-adapter-linux"
                            else macos_only if event == "workflow_dispatch" and target.lower() == "signing-adapter-macos" else both)
                self.assertEqual(systems, expected)
        self.assertEqual(job["permissions"], {"contents": "read"})
        self.assertEqual(job["steps"][0]["run"], HOSTED_GUARD)
        self.assertFalse(any("actions/upload-artifact" in step.get("uses", "") for step in job["steps"]))
        commands = [step["run"] for step in job["steps"] if "run" in step]
        self.assertEqual(len(commands), 3)
        owner = commands[-1]
        self.assertIn("--scope signing-adapter", owner)
        self.assertIn('--job "$GITHUB_JOB")', owner)
        self.assertIn('PYTHONSAFEPATH=1 "${verifier_args[@]}"', owner)
        for forbidden in ("--shard", "--local", "run_local_signing_matrix.py", "pip wheel", "continue-on-error"):
            self.assertNotIn(forbidden, owner)
        self.assertNotIn("test-signing-adapter", workflow["jobs"]["test"]["needs"])

    def test_actual_guard_rejects_non_hosted_or_missing_runner_identity(self):
        workflow = load_workflow(CI)
        for name in ("test-linux", "test-native-profiles", "test-native-support", "test-signing-matrix", "test-signing-adapter"):
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
        for platform, job, scope in (("linux", "test-linux", None),
                                     ("macos", "test-native-profiles", "native-python"),
                                     ("macos", "test-native-support", "native-support"),
                                     ("macos", "test-native-support", "store-lane")):
            body = workflow["jobs"][job]["steps"][-1]["run"]
            self.assertEqual(body, coordinator_shell(
                platform, scope="native-support" if job == "test-native-support" else None))
            # Only support accepts the closed routing value from its fixed env;
            # the profile owner must work without any MRK_SCOPE binding.
            bound_env = {**env, **({"MRK_SCOPE": scope} if job == "test-native-support" else {})}
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
            else:
                expected += ["--scope", scope]
            expected += ["--summary", env["GITHUB_STEP_SUMMARY"]]
            for status in (0, 1, 125):
                with self.subTest(job=job, scope=scope, status=status):
                    result = subprocess.run(["bash", "--noprofile", "--norc", "-c", fixture + body],
                                            env={**bound_env, "FIXTURE_STATUS": str(status)},
                                            capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertEqual(result.stdout.decode().split("\0"), [*expected, ""])
            for key in ("MRK_PYTHON", "FIXTURE_RUBY", "MRK_PYTHON_312", "MRK_PYTHON_313", "MRK_PYTHON_314"):
                with self.subTest(job=job, scope=scope, relative_runtime=key):
                    result = subprocess.run(["bash", "--noprofile", "--norc", "-c", fixture + body],
                                            env={**bound_env, "FIXTURE_STATUS": "0", key: "relative-runtime"},
                                            capture_output=True, timeout=5)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")

    def test_failed_or_cancelled_setup_cannot_reach_the_controller(self):
        workflow = load_workflow(CI)
        for name in ("test-linux", "test-native-profiles", "test-native-support"):
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
        delegated, requirements = _g_metadata_fixture("macos-26")
        poison = {name: (identifier,) for name, identifier in zip(checks.PYTHON_SINGLETON_PARTITIONS, checks.PYTHON_SINGLETON_IDS)}
        inventories = {"authority": authority, "ordinary": ordinary, "delegated": delegated,
                       **poison, "all": tuple(sorted(authority + ordinary + checks.PYTHON_SINGLETON_IDS + delegated))}
        python = paths.source_python if phase == "source" else paths.wheel_python
        step = controller.Step("native-profile-" + phase,
            argv=(str(python), "-I", "-B", str(ROOT / "tests/workflow/run_native_profile_checks.py"),
                  *(("--installed-wheel",) if phase == "wheel" else ())), cwd=paths.work,
            env=tuple(sorted(controller.native_phase_environment(paths, "macos", phase).items())), seconds=1500, parser="native")
        rig = SimpleNamespace(controller=controller, paths=paths, step=step, now=100.0,
                              inventories=inventories, events=[], captures=[], changes={},
                              prepare_error=None, idle_error=None, run_error=None,
                              prepare_advance=100.0, run_advance=1.0, parsed=[], phase=phase,
                              idle_failure_after=None, operating_system="macos-26", metadata=(delegated, requirements))

        def identities(source, partition, *, deadline):
            self.assertEqual(source, ROOT)
            rig.events.append(("inventory", partition, deadline))
            return rig.inventories[partition]

        def package(source, root, *, deadline):
            self.assertEqual(source, ROOT)
            rig.events.append(("package", root, deadline))
            return {"bytes_match_source": True, "immutable_modes": True}

        def metadata(source, operating_system, *, deadline):
            self.assertEqual((source, operating_system), (ROOT, rig.operating_system))
            rig.events.append(("delegation", operating_system, deadline))
            return rig.metadata

        def snapshot(source, *, deadline):
            self.assertEqual(source, ROOT)
            rig.events.append(("snapshot", "native", deadline))
            captured_metadata = rig.checks.signing_regression_metadata(source, "macos-26", deadline=deadline)
            return MappingProxyType(dict(rig.inventories)), captured_metadata

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
                         next((name for name in controller.PYTHON_SINGLETON_PARTITIONS if f"--{name}-{phase}" in argv), "healthy"))
            rig.events.append(("run", argv, options))
            if rig.run_error is not None:
                raise rig.run_error
            ids = rig.inventories[partition]
            text = "".join(f"{name.rsplit('.', 1)[1]} ({name}) ... ok\n" for name in ids)
            text += f"\nRan {len(ids)} tests in 0.01s\n\nOK\n"
            stdout = b""
            if partition in controller.PYTHON_SINGLETON_PARTITIONS:
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

        rig.checks = SimpleNamespace(native_partition_ids=identities, inspect_native_package=package,
                                     signing_regression_metadata=metadata, native_capture_snapshot=snapshot,
                                     NATIVE_AUTHORITY_IDS=checks.NATIVE_AUTHORITY_IDS,
                                     PYTHON_SINGLETON_CASES=_PYTHON_SINGLETON_FIXTURES)
        def prepare_files(selected, *, deadline):
            rig.events.append(("fixture-prepare", selected, deadline))
            rig.session.persisted_bytes += 96
            if getattr(rig, "fixture_prepare_error", None) is not None:
                raise rig.fixture_prepare_error

        def verify_files(selected, *, deadline):
            rig.events.append(("fixture-reinspect", selected, deadline))
            rig.session.persisted_bytes += getattr(rig, "reinspect_added_bytes", 0)
            if getattr(rig, "fixture_verify_error", None) is not None:
                raise rig.fixture_verify_error

        rig.session = SimpleNamespace(ensure_idle=idle, prepare_native_authority=prepare, run=run,
            prepare_checked_files=prepare_files, verify_checked_files=verify_files, persisted_bytes=0)
        return rig

    def _python_gate_fixture(self, phase="source", *, deadline=2500.0):
        rig = self._native_gate_fixture(phase)
        controller, paths = rig.controller, rig.paths
        healthy = rig.inventories["ordinary"]
        rig.operating_system = "ubuntu-24.04"
        rig.metadata = _g_metadata_fixture(rig.operating_system)
        delegated = rig.metadata[0]
        poison = {name: rig.inventories[name] for name in controller.PYTHON_SINGLETON_PARTITIONS}
        rig.inventories = {"healthy": healthy, "delegated": delegated, **poison,
            "all": tuple(sorted(healthy + delegated + tuple(identifier for ids in poison.values() for identifier in ids)))}
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

        def snapshot(source, selection, *, deadline):
            self.assertEqual((source, selection), (ROOT, "full" if phase == "source" else "wheel"))
            rig.events.append(("snapshot", selection, deadline))
            metadata = rig.checks.signing_regression_metadata(source, "ubuntu-24.04", deadline=deadline)
            return MappingProxyType(dict(rig.inventories)), metadata

        rig.checks.python_capture_ids = identities
        rig.checks.python_capture_snapshot = snapshot
        rig.checks.PYTHON_SINGLETON_CASES = _PYTHON_SINGLETON_FIXTURES
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
                                               getattr(rig, "source_inventory", {}), platform, deadline=deadline)

    def test_original_capture_reason_codes_are_finite_bounded_and_never_authorize_finality(self):
        controller = controller_module()
        private = "PRIVATE_DIAGNOSTIC_CANARY"
        stdout = ("reserved-domain disposal failed\n" + private + "\n").encode()
        stderr = ("reserved identity census OSError\n" + private + "\n").encode()
        fields = dict(ok=True, returncode=0, waited=True, stdout_eof=True, stderr_eof=True,
            domain_finality=True, timed_out=False, cancelled=False, primary_error=None, cleanup_errors=(),
            stdout=stdout, stderr=stderr, persisted=(len(stdout), len(stderr)), duration=0.01)
        original = SimpleNamespace(**fields)
        observed = controller.capture_observations(original)
        self.assertIsNone(observed["primary_error_code"])  # Child text cannot supply owner reasons.
        self.assertEqual(observed["cleanup_error_codes"], [])
        self.assertEqual((observed["cleanup_error_count"], observed["cleanup_error_codes_omitted"]), (0, 0))
        controller.require_original_finality(original)

        known = (
            ("command exited 7", "COMMAND_EXIT"), ("command exited -9", "COMMAND_EXIT"),
            ("command/original aggregate deadline expired", "TIMEOUT"),
            ("command cancellation", "CANCELLATION"), ("late controller cancellation", "CANCELLATION"),
            ("finality exceeded original command cutoff", "FINALITY_TIMEOUT"),
            ("per-stream or whole-attempt persisted-output limit", "OUTPUT_LIMIT"),
            ("subject per-process RSS limit exceeded", "RSS_LIMIT"),
            ("native original-parent observation identity mismatch", "ORIGINAL_IDENTITY"),
            ("native terminal status disagrees with original wait", "ORIGINAL_WAIT_STATUS"),
            ("original wait or complete stream EOF missing", "WAIT_OR_EOF"),
            ("stream EOF unavailable at bounded cleanup cutoff", "STREAM_EOF"),
            ("late capture/cleanup/finality error", "FINALIZATION"),
            ("capture persisted length differs from returned bytes", "CAPTURE_LENGTH"),
            ("reserved identity did not reach finality", "DOMAIN_FINALITY"),
            ("reserved-domain disposal failed", "RETAINED_DOMAIN_DISPOSAL"),
            ("collection OSError", "COLLECTION"), ("collection " + private, "COLLECTION"),
            ("numerical cleanup ExceptionGroup", "NUMERICAL_CLEANUP"),
            ("reserved-domain cleanup KeyboardInterrupt", "RETAINED_DOMAIN_CLEANUP"),
            ("original child stop OSError", "ORIGINAL_STOP"),
            ("original child wait TimeoutError", "ORIGINAL_WAIT"),
            ("stream close OSError", "STREAM_CLOSE"), ("selector close OSError", "SELECTOR_CLOSE"),
            ("capture fsync OSError", "CAPTURE_FSYNC"), ("capture persist OSError", "CAPTURE_PERSIST"),
            ("capture close OSError", "CAPTURE_CLOSE"), ("reserved identity census OSError", "DOMAIN_CENSUS"),
        )
        for reason, code in known:
            for primary in (True, False):
                with self.subTest(reason=reason, primary=primary):
                    original = SimpleNamespace(**{**fields, "primary_error": reason if primary else None,
                        "cleanup_errors": () if primary else (reason,)})
                    before = dict(vars(original))
                    observed = controller.capture_observations(original)
                    self.assertEqual(observed["primary_error_code"], code if primary else None)
                    self.assertEqual(observed["cleanup_error_codes"], [] if primary else [code])
                    self.assertEqual(observed["cleanup_error_count"], 0 if primary else 1)
                    self.assertEqual(observed["cleanup_error_codes_omitted"], 0)
                    reported = controller.failure_details(original)
                    for key, value in observed.items():
                        self.assertEqual(reported[key], value)
                    self.assertNotIn(reason, json.dumps(reported))
                    self.assertNotIn(private, json.dumps(reported))
                    with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                        controller.require_original_finality(original)
                    self.assertEqual(vars(original), before)

        class Unformattable:
            def __str__(self):
                raise AssertionError("diagnostics cannot format an arbitrary reason")

        unknown = (private + " /private/secret pid=4242", "collection OSError: " + private,
            "collection OSError\n" + private, "collection \u03bbError", "collection " + "A" * 81,
            "command exited +7", "command exited 07", "command exited 12345678901",
            "command exited 7 /private/secret", "reserved-domain disposal failed " + private,
            "reserved identity census ", "x" * 65536, b"collection OSError", None, True, Unformattable())
        for index, reason in enumerate(unknown):
            with self.subTest(unclassified=index):
                original = SimpleNamespace(**{**fields, "primary_error": reason, "cleanup_errors": (reason,)})
                observed = controller.capture_observations(original)
                self.assertEqual(observed["primary_error_code"], None if reason is None else "UNCLASSIFIED")
                self.assertEqual(observed["cleanup_error_codes"], ["UNCLASSIFIED"])
                for hidden in (private, "/private/", "4242", "OSError", "\u03bbError"):
                    self.assertNotIn(hidden, json.dumps(observed))
                with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                    controller.require_original_finality(original)

        self.assertEqual(controller.CAPTURE_ERROR_CODE_LIMIT, 32)
        for count in (0, 1, 32, 33, 80):
            with self.subTest(cleanup_count=count):
                reasons = tuple("stream close OSError" if index % 2 else private for index in range(count))
                original = SimpleNamespace(**{**fields, "primary_error": "reserved-domain disposal failed",
                    "cleanup_errors": reasons})
                with patch.object(controller, "_capture_error_code", wraps=controller._capture_error_code) as classify:
                    observed = controller.capture_observations(original)
                self.assertEqual([call.args[0] for call in classify.call_args_list],
                    [*reasons[:32], original.primary_error])
                self.assertEqual(observed["cleanup_error_codes"],
                    ["STREAM_CLOSE" if index % 2 else "UNCLASSIFIED" for index in range(min(count, 32))])
                self.assertEqual((observed["cleanup_error_count"], observed["cleanup_error_codes_omitted"]),
                    (count, max(0, count - 32)))
                self.assertLess(len(json.dumps(observed)), 4096)
                self.assertNotIn(private, json.dumps(observed))
                observed["primary_error_code"] = None
                observed["cleanup_error_codes"].clear()  # Publication cannot alter the original evidence.
                self.assertEqual(original.cleanup_errors, reasons)
                self.assertEqual(original.primary_error, "reserved-domain disposal failed")
                with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                    controller.require_original_finality(original)

    def test_failed_native_entry_locations_are_exact_bounded_private_and_not_finality(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        relative = "tests/workflow/run_native_profile_checks.py"
        entry = paths.source / relative
        private = "PRIVATE_NATIVE_ENTRY_CANARY"

        def frame(filename, line, function=private):
            return f'  File "{filename}", line {line}, in {function}\n'

        rejected = (frame(entry.parent / "other.py", 81), frame("/other/" + relative, 82),
            frame(relative, 83), frame(entry, 0), frame(entry, -1), frame(entry, 1000000),
            frame(entry, "01"), frame(entry, "+1"), frame(entry, 84, "not a function"),
            frame(entry, 85, "\u03bb"), frame(entry, 86).replace("\n", " trailing\n"),
            frame(entry, 87).lstrip())
        stderr = ("Traceback (most recent call last):\n" + "".join(rejected)
            + "".join(frame(entry, line, "<module>" if line == 1 else private) for line in range(1, 13))
            + frame(entry, 999999).replace("\n", "\r\n")
            + "    private_source(" + private + ")\nAssertionError: " + private + " /private/signing\n").encode()
        stdout = ("private argv=" + private + "\n").encode()
        fields = dict(ok=False, returncode=1, waited=True, stdout_eof=True, stderr_eof=True,
            domain_finality=True, timed_out=False, cancelled=False, primary_error="command exited 1",
            cleanup_errors=(), stdout=stdout, stderr=stderr, persisted=(len(stdout), len(stderr)), duration=0.01)
        expected = [[relative, line] for line in (*range(6, 13), 999999)]
        self.assertEqual(controller._native_entry_failure_locations("".join(rejected), entry), [])
        self.assertEqual(controller._native_entry_failure_locations(frame(relative, 1), Path(relative)), [])

        for phase in ("source", "wheel"):
            for changes in ({}, {"waited": False, "stderr_eof": False, "domain_finality": False,
                    "timed_out": True, "cancelled": True, "cleanup_errors": ("stream close OSError",)}):
                with self.subTest(phase=phase, lost_finality=bool(changes)):
                    original = SimpleNamespace(**{**fields, **changes})
                    before = dict(vars(original))
                    step = controller.Step("native-profile-" + phase, parser="native")
                    reported = controller.failure_details(original, step, paths)
                    self.assertEqual(reported["native_entry_locations"], expected)
                    for key, value in controller.capture_observations(original).items():
                        self.assertEqual(reported[key], value)
                    for hidden in (private, str(entry), "/private/signing", "private_source", "private argv"):
                        self.assertNotIn(hidden, json.dumps(reported))
                    self.assertEqual(vars(original), before)
                    with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                        controller.require_original_finality(original)
                    reported["native_entry_locations"].clear()
                    self.assertEqual(vars(original), before)

        original = SimpleNamespace(**fields)
        step = controller.Step("native-profile-source", parser="native")
        for excluded_step, excluded_paths in ((None, paths), (step, None),
                (dataclasses.replace(step, id="python-full"), paths),
                (dataclasses.replace(step, parser="check"), paths),
                (dataclasses.replace(step, id="native-profile-wheel", parser="exit"), paths)):
            with self.subTest(step=excluded_step, paths_present=excluded_paths is not None), \
                    patch.object(controller, "_native_entry_failure_locations") as diagnostic:
                self.assertNotIn("native_entry_locations", controller.failure_details(original, excluded_step, excluded_paths))
                diagnostic.assert_not_called()
        for ok in (True, None, 0):
            with self.subTest(ok=ok), patch.object(controller, "_native_entry_failure_locations") as diagnostic:
                capture = SimpleNamespace(**{**fields, "ok": ok, "returncode": 0, "primary_error": None})
                self.assertNotIn("native_entry_locations", controller.failure_details(capture, step, paths))
                diagnostic.assert_not_called()
                if ok is True:
                    controller.require_original_finality(capture)

    def test_failed_native_entry_diagnostics_keep_original_deadline_and_failure(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        entry = paths.source / "tests/workflow/run_native_profile_checks.py"
        step = controller.Step("native-profile-source", parser="native")
        stderr = f'  File "{entry}", line 123, in run\n'.encode()
        original = SimpleNamespace(ok=False, returncode=1, waited=True, stdout_eof=True, stderr_eof=True,
            domain_finality=True, timed_out=False, cancelled=False, primary_error="command exited 1",
            cleanup_errors=(), stdout=b"", stderr=stderr, persisted=(0, len(stderr)), duration=0.01)
        before = dict(vars(original))
        for stage, ticks in (("before", (1000.0,)), ("during", (999.0, 1000.0)),
                             ("after", (999.0, 999.0, 1000.0))):
            clock_values = iter(ticks)
            with self.subTest(stage=stage), \
                    patch.object(controller.time, "monotonic", side_effect=lambda: next(clock_values, 1000.0)), \
                    patch.object(controller, "check_clock", wraps=controller.check_clock) as checked, \
                    self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                controller.failure_details(original, step, paths, deadline=1000.0)
            self.assertEqual([call.args for call in checked.call_args_list], [(1000.0,)] * (len(ticks) + 1))
            self.assertEqual(vars(original), before)

        private = "PRIVATE_OPTIONAL_NATIVE_DIAGNOSTIC_ERROR"
        with patch.object(controller, "_native_entry_failure_locations", side_effect=ValueError(private)) as diagnostic, \
                patch.object(controller.time, "monotonic", return_value=999.0), \
                patch.object(controller, "check_clock", wraps=controller.check_clock) as checked:
            reported = controller.failure_details(original, step, paths, deadline=1000.0)
        diagnostic.assert_called_once_with(stderr.decode(), entry, deadline=1000.0)
        checked.assert_called_once_with(1000.0)
        self.assertNotIn("native_entry_locations", reported)
        self.assertNotIn(private, json.dumps(reported))
        for key, value in controller.capture_observations(original).items():
            self.assertEqual(reported[key], value)
        self.assertEqual(vars(original), before)
        with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
            controller.require_original_finality(original)
        with patch.object(controller, "_native_entry_failure_locations", side_effect=ValueError(private)), \
                patch.object(controller.time, "monotonic", return_value=1000.0), \
                self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
            controller.failure_details(original, step, paths, deadline=1000.0)
        self.assertEqual(vars(original), before)

    def test_native_test_frame_diagnostics_are_inventory_bound_private_and_never_finality(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        private = "PRIVATE_NATIVE_TEST_FRAME_CANARY"
        native_id = ("unit.test_checked_files.NativeCheckedFilesTests."
                     "test_actual_tmp_var_folders_and_physical_spellings_select_identical_private_bytes")
        linux_id = ("unit.test_operation_recovery.IosOperationRecoveryTests."
                    "test_profile_cleanup_uncertainty_stops_actual_fresh_validation_before_any_store_access")
        source_files = ("src/mobile_release/build_inputs.py", "src/mobile_release/checked_files.py",
                        "tests/unit/test_checked_files.py", "tests/unit/test_operation_recovery.py")
        frame = lambda path, line: f'  File "{path}", line {line}, in {private}\n'

        for phase in ("source", "wheel"):
            package = paths.work / ("source-build/src/mobile_release" if phase == "source" else
                                    "wheel-venv/lib/python3.11/site-packages/mobile_release")
            opposite = paths.work / ("source-build/src/mobile_release" if phase == "wheel" else
                                     "wheel-venv/lib/python3.11/site-packages/mobile_release")
            for gate, partition, identifier, relative, module in (
                    ("native-profile-" + phase, "ordinary", native_id, source_files[2], "checked_files.py"),
                    ("python-full" if phase == "source" else "python-wheel", "poison-recovery-profile-cleanup",
                     linux_id, source_files[3], "build_inputs.py")):
                with self.subTest(phase=phase, gate=gate):
                    step = controller.Step(gate, parser="native", native_partition=partition)
                    checks = SimpleNamespace(native_partition_ids=lambda *_args, **_kwargs: (identifier,))
                    test_path = paths.source / relative
                    rejected = (frame("/other/" + relative, 81), frame(relative, 82),
                        frame(package / "unknown.py", 83), frame(opposite / module, 84),
                        frame(paths.source / "src/mobile_release" / module, 85),
                        frame(test_path, 0), frame(test_path, -1), frame(test_path, "01"),
                        frame(test_path, 1_000_000), frame(test_path, 2).lstrip(),
                        frame(test_path, 3).replace("\n", " trailing\n"),
                        frame(test_path, 4).replace(private, "not a function"))
                    headers = frame(test_path, 810) + frame(package / module, 413).replace("\n", "\r\n")
                    stderr = ("".join(rejected) + headers + "    private_source('" + private + "')\n"
                              + "FileNotFoundError: " + private + " /private/signing\n").encode()
                    callback = {"id": identifier, "outcome": "error", "category": "os-error",
                                "errno": 2, "returncode": None}

                    def capture(rows, *, ok=False, diagnostic_phase="tests"):
                        stdout = (controller.NATIVE_DIAGNOSTIC_PREFIX + json.dumps({
                            "schema": 1, "phase": diagnostic_phase, "records": rows}) + "\n").encode()
                        return SimpleNamespace(ok=ok, returncode=1, waited=True, stdout_eof=True, stderr_eof=True,
                            domain_finality=True, timed_out=False, cancelled=False, primary_error="command exited 1",
                            cleanup_errors=(), stdout=stdout, stderr=stderr, persisted=(len(stdout), len(stderr)), duration=0.01)

                    original = capture([callback])
                    before = dict(vars(original))
                    reported = controller.failure_details(original, step, paths, checks=checks, _source_files=source_files)
                    expected = [{"file": relative, "line": 810}, {"file": "src/mobile_release/" + module, "line": 413}]
                    self.assertEqual(reported["native_test_locations"], expected)
                    for key, value in controller.capture_observations(original).items():
                        self.assertEqual(reported[key], value)
                    for hidden in (private, str(paths.source), str(package), "/private/signing", "private_source"):
                        self.assertNotIn(hidden, json.dumps(reported))
                    self.assertEqual(vars(original), before)
                    with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                        controller.require_original_finality(original)
                    reported["native_test_locations"].clear()
                    self.assertEqual(vars(original), before)
                    self.assertEqual(controller._native_test_failure_locations(
                        "".join(rejected), paths, phase, source_files), [])
                    self.assertEqual(controller._native_test_failure_locations(
                        "".join(frame(test_path, line) for line in range(1, 13)), paths, phase, source_files),
                        [{"file": relative, "line": line} for line in range(5, 13)])

                    excluded = (capture([callback], ok=True), capture([]),
                        capture([{**callback, "id": "unit.foreign.Other.test_case"}]),
                        capture([{**callback, "outcome": "expected-failure"}]),
                        *(capture([{**callback, "outcome": outcome, "category": "none", "errno": None}])
                          for outcome in ("skip", "unexpected-success")),
                        capture([{**callback, "id": "openssl-version"}], diagnostic_phase="prerequisite"))
                    for omitted in excluded:
                        with patch.object(controller, "_native_test_failure_locations") as projection:
                            self.assertNotIn("native_test_locations", controller.failure_details(
                                omitted, step, paths, checks=checks, _source_files=source_files))
                            projection.assert_not_called()
        for names in (list(source_files), source_files + (source_files[0],), source_files * 129,
                      ("src/mobile_release/../private.py",), ("tests/foreign-name.py",), (False,)):
            with self.subTest(invalid_scope=repr(names)[:100]), \
                    self.assertRaisesRegex(controller.VerificationError, "NATIVE_DIAGNOSTIC_SCOPE"):
                controller._native_test_failure_locations("", paths, "source", names)

    def test_native_test_frame_diagnostics_flow_through_both_gates_and_keep_cutoff(self):
        for platform in ("macos", "linux"):
            for phase in ("source", "wheel"):
                with self.subTest(platform=platform, phase=phase):
                    rig = self._native_gate_fixture(phase) if platform == "macos" else self._python_gate_fixture(phase)
                    controller = rig.controller
                    partition = "ordinary" if platform == "macos" else "poison-recovery-profile-cleanup"
                    identifier = rig.inventories[partition][0]
                    relative = "tests/" + identifier.rsplit(".", 2)[0].replace(".", "/") + ".py"
                    rig.source_inventory = {relative: {}, "src/mobile_release/build_inputs.py": {},
                                            "README.md": {}}
                    package = rig.paths.work / ("source-build/src/mobile_release" if phase == "source" else
                                               "wheel-venv/lib/python3.11/site-packages/mobile_release")
                    stderr = (f'  File "{rig.paths.source / relative}", line 815, in test_case\n'
                              f'  File "{package / "build_inputs.py"}", line 413, in _physical_role\n').encode()
                    callback = {"id": identifier, "outcome": "error", "category": "os-error",
                                "errno": 2, "returncode": None}
                    stdout = (controller.NATIVE_DIAGNOSTIC_PREFIX + json.dumps({
                        "schema": 1, "phase": "tests", "records": [callback]}) + "\n").encode()
                    rig.changes[partition] = dict(ok=False, returncode=1, primary_error="command exited 1",
                        stdout=stdout, stderr=stderr, persisted=(len(stdout), len(stderr)))
                    result = self._perform_native_fixture(rig, platform=platform)
                    self.assertFalse(result.ok)
                    self.assertEqual(result.error, "COMMAND_EXIT_OR_FINALITY")
                    failed, = (row for row in result.details["partitions"] if row["status"] == "FAIL")
                    self.assertEqual(failed["capture"]["native_test_locations"], [
                        {"file": relative, "line": 815}, {"file": "src/mobile_release/build_inputs.py", "line": 413}])
                    self.assertEqual(failed["capture"]["returncode"], 1)
                    original = rig.captures[-1]
                    before = dict(vars(original))
                    part = dataclasses.replace(rig.step, parser="native", native_partition=partition)
                    for now in (999.0, 1000.0):
                        with patch.object(controller.time, "monotonic", return_value=now), \
                                patch.object(controller, "_native_test_failure_locations", side_effect=ValueError("PRIVATE")):
                            if now < 1000.0:
                                reported = controller.failure_details(original, part, rig.paths,
                                    checks=rig.checks, deadline=1000.0, _source_files=tuple(rig.source_inventory)[:2])
                                self.assertEqual(reported["returncode"], 1)
                                self.assertNotIn("native_test_locations", reported)
                                self.assertNotIn("PRIVATE", json.dumps(reported))
                            else:
                                with self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                                    controller.failure_details(original, part, rig.paths,
                                        checks=rig.checks, deadline=1000.0, _source_files=tuple(rig.source_inventory)[:2])
                    for ticks in ((1000.0,), (999.0, 1000.0), (999.0, 999.0, 1000.0),
                                  (999.0, 999.0, 999.0, 999.0, 1000.0)):
                        clock = iter(ticks)
                        with patch.object(controller.time, "monotonic", side_effect=lambda: next(clock, 1000.0)), \
                                self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                            controller._native_test_failure_locations(stderr.decode(), rig.paths, phase,
                                tuple(rig.source_inventory)[:2], deadline=1000.0)
                    self.assertEqual(vars(original), before)

    def test_native_gate_keeps_every_original_capture_record_and_one_source_wheel_cutoff(self):
        for phase, original_deadline, cutoff in (("source", 2500.0, 1600.0), ("wheel", 800.0, 800.0)):
            with self.subTest(phase=phase):
                rig = self._native_gate_fixture(phase)
                parts = ("authority", "ordinary", *rig.controller.PYTHON_SINGLETON_PARTITIONS)
                with patch.object(rig.checks, "native_partition_ids", side_effect=AssertionError("same-gate inventory rescan")):
                    result = self._perform_native_fixture(rig, deadline=original_deadline)
                self.assertTrue(result.ok, result)
                self.assertEqual(result.details["stage"], "complete")
                actual = sorted(set(rig.inventories["all"]) - set(rig.inventories["delegated"]))
                self.assertEqual(result.details["completed"], actual)
                self.assertEqual(result.details["tests"], len(actual))
                self.assertEqual(result.details["source_obligation_count"], len(rig.inventories["all"]))
                self.assertEqual(result.details["pending_delegation"], {"methods": list(rig.metadata[0]),
                    "requirements": {method: list(parts) for method, parts in rig.metadata[1].items()}})
                self.assertEqual(result.details["coverage"], "partial-until-layered-matrix")
                self.assertNotIn("returncode", result.details)  # No invented aggregate capture.
                records = result.details["partitions"]
                self.assertEqual([row["partition"] for row in records], list(parts))
                self.assertEqual([row["status"] for row in records], ["PASS"] * len(parts))
                calls = [event for event in rig.events if event[0] == "run"]
                self.assertEqual(len(calls), len(parts))
                self.assertEqual([event for event in rig.events if event[0] == "snapshot"], [("snapshot", "native", cutoff)])
                self.assertEqual([event for event in rig.events if event[0] == "inventory"], [])
                self.assertEqual([event for event in rig.events if event[0] == "delegation"], [("delegation", "macos-26", cutoff)])
                python = rig.paths.source_python if phase == "source" else rig.paths.wheel_python
                entry = str(ROOT / "tests/workflow/run_native_profile_checks.py")
                tail = [] if phase == "source" else ["--installed-wheel"]
                self.assertEqual(calls[0][1], [str(python), "-I", "-S", "-B", entry, "--authority", *tail])
                self.assertEqual(calls[1][1], [str(python), "-I", "-B", entry, "--ordinary", *tail])
                for index, partition in enumerate(rig.controller.PYTHON_SINGLETON_PARTITIONS, 2):
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
                    self.assertIs(options["dispose_retained_domain"], parts[index] in dict(_PYTHON_POISON_FIXTURES))
                    self.assertEqual(options["absolute_deadline"], cutoff)
                    self.assertEqual(options["seconds"], 1500 if parts[index] == "ordinary" else 900)
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

    def test_native_prebound_inventory_is_closed_to_its_original_gate_roles(self):
        for phase in ("source", "wheel"):
            rig = self._native_gate_fixture(phase)
            controller = rig.controller
            ordinary = rig.inventories["ordinary"]
            singleton = controller.PYTHON_SINGLETON_PARTITIONS[0]
            original = SimpleNamespace(ok=True, returncode=0, waited=True, stdout_eof=True, stderr_eof=True,
                domain_finality=True, primary_error=None, cleanup_errors=(), stdout=b"", stderr=b"",
                duration=0.01, timed_out=False, cancelled=False, persisted=(0, 0))
            with patch.object(rig.checks, "native_partition_ids", side_effect=AssertionError("prebound parser rescan")) as reader:
                for partition in ("authority", "ordinary", singleton):
                    expected = rig.inventories[partition]
                    step = dataclasses.replace(rig.step, native_partition=partition)
                    original.stderr = ("".join(f"{name.rsplit('.', 1)[1]} ({name}) ... ok\n" for name in expected)
                                       + f"\nRan {len(expected)} tests in 0.01s\n\nOK\n").encode()
                    parsed = controller.parse_capture(step, original, rig.paths, "macos", rig.checks,
                                                      _native_expected=expected)
                    self.assertEqual(parsed.details["completed"], list(expected))
                    callback = {"id": expected[0], "outcome": "error", "category": "os-error", "errno": 5,
                                "returncode": None}
                    failed = SimpleNamespace(**{**vars(original), "ok": False, "returncode": 1,
                        "primary_error": "command exited 1", "stderr": b"",
                        "stdout": (controller.NATIVE_DIAGNOSTIC_PREFIX + json.dumps({
                            "schema": 1, "phase": "tests", "records": [callback]}) + "\n").encode()})
                    value = controller.failure_details(failed, step, rig.paths, checks=rig.checks,
                                                       platform="macos", _native_expected=expected)
                    self.assertEqual(value["native_diagnostic"]["records"], [callback])
                    self.assertEqual(value["returncode"], 1)
                    with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                        controller.parse_capture(step, failed, rig.paths, "macos", rig.checks,
                                                 _native_expected=expected)
                reader.assert_not_called()

            step = dataclasses.replace(rig.step, native_partition="ordinary")
            cases = (({}, "linux", ordinary), ({"id": "python-full"}, "macos", ordinary),
                ({"id": "foreign"}, "macos", ordinary), ({"parser": "check"}, "macos", ordinary),
                ({"native_partition": "all"}, "macos", ordinary),
                ({"native_partition": "delegated"}, "macos", rig.inventories["delegated"]),
                ({"native_partition": "foreign"}, "macos", ordinary),
                ({}, "macos", list(ordinary)), ({}, "macos", ()), ({}, "macos", (False,)),
                ({}, "macos", tuple(reversed(ordinary))), ({}, "macos", ordinary + ordinary[:1]),
                ({"native_partition": "authority"}, "macos", ordinary),
                ({"native_partition": singleton}, "macos", ordinary[:1]),
                ({"native_partition": singleton}, "macos", rig.inventories[controller.PYTHON_SINGLETON_PARTITIONS[1]]),
                ({}, "macos", rig.inventories["authority"]), ({}, "macos", rig.inventories[singleton]))
            for changes, platform, expected in cases:
                with self.subTest(phase=phase, invalid_role=(changes, platform, expected)):
                    selected = dataclasses.replace(step, **changes)
                    with self.assertRaisesRegex(controller.VerificationError, "NATIVE_PREBOUND_EXPECTATIONS"):
                        controller.parse_capture(selected, original, rig.paths, platform, rig.checks,
                                                 _native_expected=expected)
                    with self.assertRaisesRegex(controller.VerificationError, "NATIVE_PREBOUND_EXPECTATIONS"):
                        controller.failure_details(original, selected, rig.paths, checks=rig.checks,
                                                   platform=platform, _native_expected=expected)
            with self.assertRaisesRegex(controller.VerificationError, "NATIVE_PREBOUND_EXPECTATIONS"):
                controller.parse_capture(step, original, rig.paths, "macos", rig.checks,
                                         _python_expected=ordinary, _native_expected=ordinary)
            with self.assertRaisesRegex(controller.VerificationError, "NATIVE_PREBOUND_EXPECTATIONS"):
                controller.failure_details(original, step, rig.paths, checks=rig.checks, platform="macos",
                                           _python_expected=ordinary, _native_expected=ordinary)
            with self.assertRaisesRegex(controller.VerificationError, "NATIVE_PREBOUND_EXPECTATIONS"):
                controller.failure_details(original, _native_expected=ordinary)

    def test_native_checked_file_fixtures_use_original_idle_capture_and_existing_accounting(self):
        for case in ("success", "prepare-failed", "parser-failed", "idle-failed", "reinspect-failed", "byte-bound", "failed-reinspection-byte-bound"):
            with self.subTest(checked_file_coordinator=case):
                rig = self._native_gate_fixture()
                failure = OSError("synthetic readonly fixture failure")
                if case == "prepare-failed":
                    rig.fixture_prepare_error = failure
                elif case == "parser-failed":
                    rig.changes["ordinary"] = {"stderr": b"OK\n"}
                elif case == "idle-failed":
                    rig.idle_error, rig.idle_failure_after = failure, 2
                elif case == "reinspect-failed":
                    rig.fixture_verify_error = failure
                elif case == "byte-bound":
                    rig.session.persisted_bytes = rig.controller.MATRIX_PERSISTED_LIMIT
                elif case == "failed-reinspection-byte-bound":
                    rig.fixture_verify_error = failure
                    rig.reinspect_added_bytes = rig.controller.MATRIX_PERSISTED_LIMIT
                original_total = rig.session.persisted_bytes
                result = self._perform_native_fixture(rig)
                self.assertEqual(result.ok, case == "success")
                self.assertEqual(rig.session.persisted_bytes, original_total + 96 + getattr(rig, "reinspect_added_bytes", 0),
                                 "partial or failed fixture persistence must remain charged")
                events = rig.events
                prepared = [event for event in events if event[0] == "fixture-prepare"]
                self.assertEqual(prepared, [("fixture-prepare", "source", 1600.0)])
                rechecks = [i for i, event in enumerate(events) if event[0] == "fixture-reinspect"]
                for index in rechecks:
                    self.assertEqual(events[index - 1], ("idle", 1600.0))
                    self.assertTrue(any(event[0] == "run" for event in events[:index]))
                # An original parser failure still gets independent reinspection
                # if idle was genuinely established. Unknown idle never does.
                expected = (1 + len(rig.controller.PYTHON_SINGLETON_PARTITIONS) if case == "success"
                            else 1 if case in {"parser-failed", "reinspect-failed", "failed-reinspection-byte-bound"} else 0)
                self.assertEqual(len(rechecks), expected)
                if case in {"prepare-failed", "byte-bound"}:
                    self.assertEqual(rig.captures, [])
                elif case != "success":
                    self.assertEqual(len(rig.captures), 2)
                    row = result.details["partitions"][1]
                    for field, value in rig.controller.capture_observations(rig.captures[1]).items():
                        self.assertEqual(row["capture"][field], value)
                    if case in {"reinspect-failed", "failed-reinspection-byte-bound"}:
                        self.assertNotIn("checked_file_originals_preserved", row)
                    if case == "failed-reinspection-byte-bound":
                        self.assertGreater(rig.session.persisted_bytes, rig.controller.MATRIX_PERSISTED_LIMIT)
                        self.assertEqual(result.details["failure"]["exception"], "ExceptionGroup")
                if case == "success":
                    for row in result.details["partitions"]:
                        self.assertEqual(row.get("checked_file_originals_preserved"),
                                         None if row["partition"] == "authority" else True)

    def test_native_gate_rejects_contract_or_partition_drift_without_launch(self):
        controller = controller_module()
        rig = self._native_gate_fixture()
        for changes in ({"kind": "inspection"}, {"argv": (*rig.step.argv, "--authority")},
                        {"env": ()}, {"cwd": rig.paths.source}, {"seconds": 900}, {"seconds": 901}, {"seconds": 1501},
                        {"parser": "exit"}, {"native_partition": "authority"}, {"expected_tests": 5}):
            with self.subTest(changes=changes):
                result = self._perform_native_fixture(rig, step=dataclasses.replace(rig.step, **changes))
                self.assertEqual(result.error, "NATIVE_GATE_CONTRACT")
                self.assertEqual(rig.events, [])
        self.assertEqual(self._perform_native_fixture(rig, platform="linux").error, "NATIVE_GATE_CONTRACT")
        self.assertEqual(rig.events, [])
        for mutation in ("missing", "duplicate", "overlap", "expanded-authority", "pooled-poison", "missing-poison", "pooled-fresh", "missing-fresh", "swapped-fresh",
                         "delegated-missing", "delegated-foreign", "delegated-duplicate", "delegated-overlap",
                         "delegated-poison", "delegated-wrong-os", "obligation-missing", "obligation-empty", "obligation-foreign",
                         "snapshot-mutable", "snapshot-extra", "snapshot-missing", "snapshot-list", "snapshot-metadata",
                         "snapshot-shape", "snapshot-string", "snapshot-key-subclass", "same-size-foreign-authority"):
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
                elif mutation == "same-size-foreign-authority":
                    original = rig.inventories["authority"][0]
                    foreign = "unit.synthetic.AuthorityTests.test_foreign"
                    rig.inventories["authority"] = tuple(sorted((foreign, *rig.inventories["authority"][1:])))
                    rig.inventories["all"] = tuple(sorted(foreign if name == original else name for name in rig.inventories["all"]))
                elif mutation.startswith("snapshot-"):
                    if mutation == "snapshot-extra":
                        rig.inventories["foreign"] = ("unit.synthetic.Contracts.test_foreign",)
                    elif mutation == "snapshot-missing":
                        del rig.inventories["all"]
                    elif mutation == "snapshot-list":
                        rig.inventories["ordinary"] = list(rig.inventories["ordinary"])
                    elif mutation == "snapshot-string":
                        rig.inventories["ordinary"] = (False,)
                    elif mutation == "snapshot-key-subclass":
                        class Name(str):
                            pass

                        ids = rig.inventories.pop("ordinary")
                        rig.inventories[Name("ordinary")] = ids
                    elif mutation == "snapshot-metadata":
                        rig.metadata = None
                    elif mutation == "snapshot-shape":
                        rig.checks.native_capture_snapshot = lambda *args, **kwargs: [MappingProxyType(rig.inventories), rig.metadata]
                    else:
                        rig.checks.native_capture_snapshot = lambda *args, **kwargs: (dict(rig.inventories), rig.metadata)
                elif mutation == "pooled-poison":
                    rig.inventories["poison-wait-loss"] += rig.inventories["poison-startup-error"]
                elif mutation == "missing-poison":
                    rig.inventories["poison-startup-error"] = ()
                elif mutation == "pooled-fresh":
                    rig.inventories["fresh-command-account-prepared"] += rig.inventories["fresh-model-command-bridge"]
                elif mutation == "missing-fresh":
                    rig.inventories["fresh-model-command-bridge"] = ()
                elif mutation == "swapped-fresh":
                    rig.inventories["fresh-command-account-prepared"], rig.inventories["fresh-model-command-bridge"] = (
                        rig.inventories["fresh-model-command-bridge"], rig.inventories["fresh-command-account-prepared"])
                elif mutation == "delegated-missing":
                    rig.inventories["delegated"] = rig.inventories["delegated"][:-1]
                elif mutation == "delegated-foreign":
                    rig.inventories["delegated"] += ("unit.test_foreign.Contracts.test_unknown",)
                elif mutation == "delegated-duplicate":
                    rig.inventories["delegated"] *= 2
                elif mutation == "delegated-overlap":
                    rig.inventories["ordinary"] += rig.inventories["delegated"][:1]
                elif mutation == "delegated-poison":
                    rig.inventories["delegated"] = tuple(sorted(rig.inventories["delegated"] + rig.inventories["poison-wait-loss"]))
                elif mutation == "delegated-wrong-os":
                    rig.metadata = _g_metadata_fixture("ubuntu-24.04")
                else:
                    methods, required = rig.metadata
                    altered = dict(required)
                    if mutation == "obligation-missing":
                        altered.pop(methods[0])
                    else:
                        altered[methods[0]] = () if mutation == "obligation-empty" else ("G/foreign/whole",)
                    rig.metadata = methods, MappingProxyType(altered)
                result = self._perform_native_fixture(rig)
                self.assertEqual(result.error, "NATIVE_PARTITION_UNION")
                self.assertFalse(any(event[0] in {"package", "prepare", "run"} for event in rig.events))
                self.assertEqual([row["status"] for row in result.details["partitions"]],
                                 ["UNEXECUTED"] * (2 + len(controller.PYTHON_SINGLETON_PARTITIONS)))

    def test_native_gate_failure_preserves_original_capture_and_never_runs_later_partition(self):
        failure = OSError("synthetic private failure; must not be published")
        parts = ("authority", "ordinary", *controller_module().PYTHON_SINGLETON_PARTITIONS)
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
                self.assertFalse(set(result.details.get("completed", ())) & set(rig.inventories["delegated"]))
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
        parts = ("authority", "ordinary", *controller_module().PYTHON_SINGLETON_PARTITIONS)
        for mode in ("snapshot", "preparation", *parts, "union"):
            with self.subTest(mode=mode):
                rig = self._native_gate_fixture()
                if mode == "snapshot":
                    original_snapshot = rig.checks.native_capture_snapshot

                    def late_snapshot(*args, **kwargs):
                        value = original_snapshot(*args, **kwargs)
                        rig.now = 1600.0
                        return value

                    rig.checks.native_capture_snapshot = late_snapshot
                elif mode == "preparation":
                    rig.prepare_advance = 1500.0
                elif mode in parts:
                    # One original cutoff: preparation has already consumed
                    # 100s. Expire during this exact original, not a renewed one.
                    rig.run_advance = 1401.0 / (parts.index(mode) + 1)
                reconciliations = []

                def late_sorted(values, *args, **kwargs):
                    result = sorted(values, *args, **kwargs)
                    if len(rig.captures) == len(parts) and tuple(result) == rig.inventories["all"]:
                        reconciliations.append(True)
                        rig.now = 1600.0
                    return result

                with contextlib.ExitStack() as stack:
                    if mode == "union":
                        stack.enter_context(patch.object(rig.controller, "sorted", create=True, side_effect=late_sorted))
                    result = self._perform_native_fixture(rig)
                self.assertFalse(result.ok)
                self.assertEqual(result.error, "AGGREGATE_DEADLINE")
                self.assertEqual(len(rig.captures), 0 if mode in {"snapshot", "preparation"} else len(parts) if mode == "union"
                                 else parts.index(mode) + 1)
                records = result.details["partitions"]
                if mode in {"snapshot", "preparation"}:
                    self.assertEqual([row["status"] for row in records], ["UNEXECUTED"] * len(parts))
                    if mode == "snapshot":
                        self.assertFalse(any(event[0] in {"package", "prepare", "run"} for event in rig.events))
                elif mode == "authority":
                    self.assertEqual(records[1]["status"], "UNEXECUTED")
                elif mode == "union":
                    self.assertEqual([row["status"] for row in records], ["PASS"] * len(parts))
                    self.assertEqual(len(reconciliations), 1)
                for index, capture in enumerate(rig.captures):
                    self.assertEqual(records[index]["capture"]["persisted"], list(capture.persisted))

    def test_fixed_linux_python_storage_profile_is_selected_only_for_full_discovery(self):
        profiles = []
        for phase, original_deadline, cutoff in (("source", 2500.0, 1000.0), ("wheel", 800.0, 800.0)):
            with self.subTest(phase=phase):
                rig = self._python_gate_fixture(phase, deadline=original_deadline)
                parts = (*rig.controller.PYTHON_SINGLETON_PARTITIONS, "healthy")
                result = self._perform_native_fixture(rig, platform="linux", deadline=original_deadline)
                self.assertTrue(result.ok, result)
                rows = result.details["partitions"]
                self.assertEqual([row["partition"] for row in rows], list(parts))
                self.assertEqual([row["status"] for row in rows], ["PASS"] * len(parts))
                actual = sorted(set(rig.inventories["all"]) - set(rig.inventories["delegated"]))
                self.assertEqual(result.details["completed"], actual)
                self.assertEqual(result.details["tests"], len(actual))
                self.assertEqual(result.details["source_obligation_count"], len(rig.inventories["all"]))
                self.assertEqual(result.details["pending_delegation"], {"methods": list(rig.metadata[0]),
                    "requirements": {method: list(parts) for method, parts in rig.metadata[1].items()}})
                self.assertEqual(result.details["coverage"], "partial-until-layered-matrix")
                self.assertNotIn("returncode", result.details)
                calls = [event for event in rig.events if event[0] == "run"]
                self.assertEqual(len(calls), len(parts))
                self.assertEqual([event for event in rig.events if event[0] == "snapshot"],
                                 [("snapshot", "full" if phase == "source" else "wheel", cutoff)])
                self.assertFalse(any(event[0] == "inventory" for event in rig.events))
                self.assertEqual([event for event in rig.events if event[0] == "delegation"], [("delegation", "ubuntu-24.04", cutoff)])
                healthy_index = parts.index("healthy")
                self.assertEqual(healthy_index, len(parts) - 1)
                self.assertEqual(calls[healthy_index][1], list(rig.step.argv))
                self.assertEqual(calls[healthy_index][1][-2:], ["--deadline", repr(original_deadline)])
                python = rig.paths.source_python if phase == "source" else rig.paths.wheel_python
                entry = str(ROOT / "tests/workflow/run_native_profile_checks.py")
                for index, (_, argv, options) in enumerate(calls):
                    profiles.append(options["profile"])
                    self.assertIs(options["dispose_retained_domain"], parts[index] in dict(_PYTHON_POISON_FIXTURES))
                    self.assertEqual(options["profile"], "python-full" if parts[index] == "healthy" and phase == "source" else "ordinary")
                    self.assertEqual(options["cpu_seconds"], 300 if parts[index] == "healthy" and phase == "source" else 180)
                    self.assertEqual(options["seconds"], 900)
                    self.assertEqual(options["absolute_deadline"], cutoff)
                    self.assertEqual(options["output_limit"], 8 * 1024**2)
                    self.assertEqual(options["cwd"], rig.paths.work)
                    self.assertEqual(options["env"], dict(rig.step.env))
                    self.assertIs(rig.parsed[index], rig.captures[index])
                    self.assertEqual(rows[index]["capture"], rig.controller.capture_observations(rig.captures[index]))
                    if parts[index] != "healthy":
                        self.assertEqual(argv, [str(python), "-I", "-S", "-B", entry,
                                               f"--{rows[index]['partition']}-{phase}"])
                        self.assertEqual(rows[index]["tests"], 1)
                        self.assertEqual(rows[index]["runtime"]["phase"], phase)
                self.assertEqual("storage_profile" in rows[healthy_index]["summary"]["details"], phase == "source")
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
            for fault in ("argv", "profile-shape", "healthy-omission", "duplicate", "pooled", "missing", "origin",
                          "delegated-missing", "delegated-foreign", "delegated-duplicate", "delegated-overlap",
                          "delegated-poison", "delegated-wrong-os", "obligation-missing", "obligation-empty", "obligation-foreign",
                          "snapshot-mutable", "snapshot-extra", "snapshot-missing", "snapshot-list", "snapshot-metadata",
                          "singleton-swap", "fresh-pooled", "fresh-missing", "fresh-swap"):
                with self.subTest(phase=phase, fault=fault):
                    rig = self._python_gate_fixture(phase)
                    parts = (*rig.controller.PYTHON_SINGLETON_PARTITIONS, "healthy")
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
                    elif fault == "singleton-swap":
                        rig.inventories["poison-startup-error"], rig.inventories["poison-wait-loss"] = (
                            rig.inventories["poison-wait-loss"], rig.inventories["poison-startup-error"])
                    elif fault == "fresh-pooled":
                        rig.inventories["fresh-command-account-prepared"] += rig.inventories["fresh-model-command-bridge"]
                    elif fault == "fresh-missing":
                        rig.inventories["fresh-model-command-bridge"] = ()
                    elif fault == "fresh-swap":
                        rig.inventories["fresh-command-account-prepared"], rig.inventories["fresh-model-command-bridge"] = (
                            rig.inventories["fresh-model-command-bridge"], rig.inventories["fresh-command-account-prepared"])
                    elif fault.startswith("snapshot-"):
                        if fault == "snapshot-extra":
                            rig.inventories["foreign"] = ("unit.synthetic.Contracts.test_foreign",)
                        elif fault == "snapshot-missing":
                            del rig.inventories["all"]
                        elif fault == "snapshot-list":
                            rig.inventories["healthy"] = list(rig.inventories["healthy"])
                        elif fault == "snapshot-metadata":
                            rig.metadata = None
                        else:
                            rig.checks.python_capture_snapshot = lambda *args, **kwargs: (dict(rig.inventories), rig.metadata)
                    elif fault == "delegated-missing":
                        rig.inventories["delegated"] = rig.inventories["delegated"][:-1]
                    elif fault == "delegated-foreign":
                        rig.inventories["delegated"] += ("unit.test_foreign.Contracts.test_unknown",)
                    elif fault == "delegated-duplicate":
                        rig.inventories["delegated"] *= 2
                    elif fault == "delegated-overlap":
                        rig.inventories["healthy"] += rig.inventories["delegated"][:1]
                    elif fault == "delegated-poison":
                        rig.inventories["delegated"] = tuple(sorted(rig.inventories["delegated"] + rig.inventories["poison-wait-loss"]))
                    elif fault == "delegated-wrong-os":
                        rig.metadata = _g_metadata_fixture("macos-26")
                    elif fault.startswith("obligation-"):
                        methods, required = rig.metadata
                        altered = dict(required)
                        if fault == "obligation-missing":
                            altered.pop(methods[0])
                        else:
                            altered[methods[0]] = () if fault == "obligation-empty" else ("G/foreign/whole",)
                        rig.metadata = methods, MappingProxyType(altered)
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
                    failed_index = parts.index("poison-wait-loss")
                    self.assertEqual(len(rig.captures), failed_index + 1 if fault == "origin" else 0)
                    if fault == "origin":
                        self.assertEqual(result.error, "NATIVE_PYTHON_RUNTIME_ORIGIN")
                        self.assertEqual([row["status"] for row in result.details["partitions"]],
                                         ["PASS"] * failed_index + ["FAIL"] + ["UNEXECUTED"] * (len(parts) - failed_index - 1))
                        self.assertEqual(result.details["partitions"][-1]["partition"], "healthy")
                        self.assertEqual(result.details["partitions"][-1]["status"], "UNEXECUTED")
                    else:
                        self.assertEqual(result.error, "PYTHON_GATE_CONTRACT" if fault in {"argv", "profile-shape"} else "PYTHON_CAPTURE_UNION")
                        self.assertEqual([row["status"] for row in result.details["partitions"]], ["UNEXECUTED"] * len(parts))

    def test_python_gate_stops_after_each_failed_original_and_keeps_one_cutoff(self):
        parts = (*controller_module().PYTHON_SINGLETON_PARTITIONS, "healthy")
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
                        self.assertFalse(set(result.details.get("completed", ())) & set(rig.inventories["delegated"]))
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
                    if len(rig.captures) == len(parts) and tuple(result) == rig.inventories["all"]:
                        reconciliations.append(True)
                        rig.now = 1000.0
                    return result

                with patch.object(rig.controller, "sorted", create=True, side_effect=late_sorted):
                    result = self._perform_native_fixture(rig, platform="linux")
                self.assertFalse(result.ok)
                self.assertEqual(result.error, "AGGREGATE_DEADLINE")
                self.assertEqual(len(reconciliations), 1)
                self.assertEqual(len(rig.captures), len(parts))
                self.assertEqual([row["status"] for row in result.details["partitions"]], ["PASS"] * len(parts))
                self.assertEqual(result.details["tests"], len(rig.inventories["all"]) - len(rig.inventories["delegated"]))

    def test_python_failure_progress_is_bounded_prebound_and_non_authoritative(self):
        controller = controller_module()
        parts = (*(name for name, _identifier in _PYTHON_SINGLETON_FIXTURES), "healthy")
        identifiers = ("unit.synthetic.ProgressTests.test_first", "unit.synthetic.ProgressTests.test_second")
        first, second = identifiers
        scope = controller.python_progress_scope(identifiers)
        self.assertIs(type(scope), MappingProxyType)
        with self.assertRaises(TypeError):
            scope[b"foreign"] = first

        def header(identifier, *, full=True):
            owner, method = identifier.rsplit(".", 1)
            return f"{method} ({identifier if full else owner})".encode()

        def observation(raw):
            value = controller.python_failure_progress(raw, scope)
            self.assertEqual(value["semantics"], "reported-unittest-lines-only")
            self.assertLessEqual(value["bytes_examined"], 256 * 1024)
            self.assertLessEqual(value["lines_examined"], 2048)
            return value

        for token in ("ok", "FAIL", "ERROR", "expected failure", "unexpected success"):
            with self.subTest(outcome=token):
                raw = header(first, full=False) + b" ... " + token.encode() + b"\n" + header(second) + b" ... "
                value = observation(raw)
                self.assertEqual(value["last_observed_start"], {"id": second})
                self.assertEqual(value["last_observed_outcome"], {"id": first, "outcome": token})
                self.assertFalse(value["byte_truncated"] or value["lines_truncated"])
        self.assertEqual(observation(header(first) + b" ... ok\r\n")["last_observed_outcome"],
                         {"id": first, "outcome": "ok"})
        private = b"PRIVATE_PROGRESS_CANARY /private/credentials pid=4242"
        raw = (header(first) + b" ... ok\n" + header(second, full=False) + b"\n"
               + private + b"\n... ERROR\n")
        value = observation(raw)
        self.assertEqual(value["last_observed_start"], {"id": second})
        self.assertEqual(value["last_observed_outcome"], {"id": first, "outcome": "ok"})
        self.assertNotIn(private.decode(), json.dumps(value))
        invalid = (b"test_foreign (unit.foreign.Private.test_foreign) ... ok\n",
            header(first) + b" ... ok", header(first) + b" ... o\n", header(first) + b" ... ok trailing\n",
            header(first) + b" ... skipped '" + private + b"'\n", b" " + header(first) + b" ... ok\n",
            header(first) + b" ... " + private + b"\n", b"x" * 1025 + b"\n", b"\xff\n", private)
        for raw in invalid:
            with self.subTest(invalid_rendering=invalid.index(raw)):
                value = observation(raw)
                self.assertIsNone(value["last_observed_start"])
                self.assertIsNone(value["last_observed_outcome"])
                self.assertNotIn(private.decode(), json.dumps(value))
        self.assertIsNone(controller.python_failure_progress("not original bytes", scope))
        self.assertIsNone(controller.python_failure_progress(b"", dict(scope)))
        ambiguous = first + ".test_first"
        collision = controller.python_progress_scope((first, ambiguous))
        self.assertNotIn(header(first), collision)  # Class/full-ID ambiguity cannot misattribute an observation.
        self.assertIn(header(first, full=False), collision)

        old = header(first) + b" ... ok\n"
        value = observation(old + b"x\n" * 2048 + header(second) + b" ... ")
        self.assertTrue(value["lines_truncated"])
        self.assertEqual(value["last_observed_start"], {"id": second})
        self.assertIsNone(value["last_observed_outcome"])
        value = observation(old + b"x" * (256 * 1024) + b"\n" + header(second) + b" ... ")
        self.assertTrue(value["byte_truncated"] and value["dropped_partial_line"])
        self.assertEqual(value["last_observed_start"], {"id": second})
        self.assertIsNone(value["last_observed_outcome"])
        value = observation(b"x" * (256 * 1024 + 1) + header(first) + b" ... ok")
        self.assertTrue(value["byte_truncated"] and value["dropped_partial_line"])
        self.assertIsNone(value["last_observed_start"])

        # Relative native callback timing is optional lexical information,
        # never a new pass/finality source or a replacement clock endpoint.
        timing = b"MRK_NATIVE_ELAPSED_MS="
        for milliseconds in (0, 1, 879_999, 3_600_000):
            with self.subTest(elapsed_ms=milliseconds):
                raw = (timing + str(milliseconds).encode() + b"\n" + header(first) + b" ... ok\n"
                       + timing + str(milliseconds).encode() + b"\r\n" + header(second) + b"\r\n")
                value = observation(raw)
                self.assertEqual(value["last_observed_start"], {"id": second, "elapsed_ms": milliseconds})
                self.assertEqual(value["last_observed_outcome"],
                                 {"id": first, "outcome": "ok", "elapsed_ms": milliseconds})
        for scalar in (b"", b"-1", b"+1", b"00", b"01", b"1.0", b"True", b"3600001",
                       b"9999999", b"1" * 1025, private):
            with self.subTest(invalid_elapsed=scalar[:16]):
                value = observation(timing + scalar + b"\n" + header(first) + b" ... ok\n")
                self.assertEqual(value["last_observed_start"], {"id": first})
                self.assertEqual(value["last_observed_outcome"], {"id": first, "outcome": "ok"})
                self.assertNotIn(private.decode(), json.dumps(value))
        marker = timing + b"9\n"
        for intervening in (b"\n", private + b"\n", b"x" * 1025 + b"\n",
                            b"test_foreign (unit.foreign.Private.test_foreign)\n"):
            value = observation(marker + intervening + header(first) + b"\n")
            self.assertEqual(value["last_observed_start"], {"id": first})
            self.assertNotIn(private.decode(), json.dumps(value))
        self.assertEqual(observation(marker + header(first))["last_observed_start"], {"id": first})
        self.assertIsNone(observation(timing + b"9" + header(first) + b"\n")["last_observed_start"])
        self.assertIsNone(observation(marker + b"test_foreign (unit.foreign.Private.test_foreign)\n")
                          ["last_observed_start"])
        headline = header(first) + b"\n"
        value = observation(marker + headline + b"x\n" * 2047)
        self.assertTrue(value["lines_truncated"])
        self.assertEqual(value["last_observed_start"], {"id": first})  # Preceding line fell outside the window.
        value = observation(marker + headline + b"x" * (256 * 1024 - len(marker) - len(headline)) + b"\n")
        self.assertTrue(value["byte_truncated"] and value["dropped_partial_line"])
        self.assertEqual(value["last_observed_start"], {"id": first})  # Partial marker was discarded, not adopted.

        for phase in ("source", "wheel"):
            for diagnostic_error in (False, True):
                with self.subTest(phase=phase, optional_diagnostic_error=diagnostic_error):
                    rig = self._python_gate_fixture(phase)
                    source_ids = rig.inventories["healthy"]
                    raw = header(source_ids[0]) + b" ... ok\n" + header(source_ids[1]) + b" ... "
                    # The singleton prefix must finish before the same original
                    # cutoff; only the intended healthy failure crosses it.
                    rig.run_advance = 901.0 / len(parts)
                    rig.changes["healthy"] = dict(ok=False, returncode=None, waited=False, stdout_eof=False,
                        stderr_eof=False, domain_finality=False, stdout=b"", stderr=raw,
                        persisted=(0, len(raw)), timed_out=True,
                        primary_error="command/original aggregate deadline expired", cleanup_errors=("original child wait TimeoutError",))
                    original_failure = rig.controller.failure_details

                    def failure(*args, **kwargs):
                        self.assertGreaterEqual(rig.now, kwargs["deadline"])
                        self.assertEqual(kwargs["_python_expected"], source_ids)
                        if diagnostic_error:
                            raise RuntimeError(private.decode())
                        return original_failure(*args, **kwargs)

                    with patch.object(rig.checks, "python_capture_ids", side_effect=AssertionError("late inventory")), \
                            patch.object(rig.checks, "native_partition_ids", side_effect=AssertionError("late native inventory")), \
                            patch.object(rig.controller, "failure_details", side_effect=failure):
                        result = self._perform_native_fixture(rig, platform="linux")
                    self.assertFalse(result.ok)
                    self.assertEqual(result.error, "COMMAND_EXIT_OR_FINALITY")
                    self.assertEqual(len(rig.captures), len(parts))
                    rows = result.details["partitions"]
                    self.assertEqual(tuple(row["partition"] for row in rows), parts)
                    self.assertEqual([row["status"] for row in rows],
                                     ["PASS"] * (len(parts) - 1) + ["FAIL"])
                    healthy = rows[-1]
                    self.assertEqual(healthy["python_progress"]["last_observed_start"], {"id": source_ids[1]})
                    self.assertEqual(healthy["python_progress"]["last_observed_outcome"], {"id": source_ids[0], "outcome": "ok"})
                    self.assertEqual("diagnostic_error" in healthy, diagnostic_error)
                    for key, observed in controller.capture_observations(rig.captures[-1]).items():
                        self.assertEqual(healthy["capture"][key], observed)
                    self.assertNotIn(private.decode(), json.dumps(result.details))
                    self.assertNotIn("completed", result.details)
                    run_index = max(index for index, event in enumerate(rig.events) if event[0] == "run")
                    self.assertTrue(all(event[0] == "idle" for event in rig.events[run_index + 1:]))

        for phase in ("source", "wheel"):
            for mode in ("progress", "projection-error", "outer-expired", "late-success"):
                with self.subTest(native_progress=(phase, mode)):
                    rig = self._native_gate_fixture(phase)
                    source_ids = rig.inventories["ordinary"]
                    # Complete success and complete next-entry lines are
                    # separate observations, never a receipt for the body.
                    raw = header(source_ids[0]) + b" ... ok\n" + header(source_ids[1]) + b"\n" + private + b"\n"
                    rig.run_advance = 700.5  # Original1600s endpoint expires in ordinary.
                    rig.idle_error = rig.controller.VerificationError("AGGREGATE_DEADLINE")
                    rig.idle_failure_after = 2
                    rig.changes["ordinary"] = dict(stderr=raw, persisted=(0, len(raw)))
                    if mode != "late-success":
                        rig.changes["ordinary"].update(ok=False, returncode=None, waited=False,
                            stdout_eof=False, stderr_eof=False, domain_finality=False, timed_out=True,
                            primary_error="command/original aggregate deadline expired",
                            cleanup_errors=("original child wait TimeoutError",))
                    original_ids = rig.checks.native_partition_ids

                    def identities(*args, **kwargs):
                        self.assertLess(len(rig.captures), 2, "late failed-capture inventory read")
                        return original_ids(*args, **kwargs)

                    with patch.object(rig.checks, "native_partition_ids", side_effect=identities), \
                            patch.object(rig.controller, "python_failure_progress",
                                side_effect=RuntimeError(private.decode()) if mode == "projection-error" else None,
                                wraps=rig.controller.python_failure_progress) as progress:
                        result = self._perform_native_fixture(rig,
                            deadline=1000.0 if mode == "outer-expired" else 2500.0)
                    self.assertFalse(result.ok)
                    self.assertEqual(result.error, "AGGREGATE_DEADLINE" if mode == "late-success"
                                     else "COMMAND_EXIT_OR_FINALITY")
                    rows = result.details["partitions"]
                    self.assertEqual([row["status"] for row in rows],
                                     ["PASS", "FAIL"] + ["UNEXECUTED"] * len(controller.PYTHON_SINGLETON_PARTITIONS))
                    ordinary = rows[1]
                    if mode == "progress":
                        self.assertEqual(ordinary["python_progress"]["last_observed_start"], {"id": source_ids[1]})
                        self.assertEqual(ordinary["python_progress"]["last_observed_outcome"],
                                         {"id": source_ids[0], "outcome": "ok"})
                    else:
                        self.assertNotIn("python_progress", ordinary)
                    self.assertEqual(progress.call_count, int(mode in ("progress", "projection-error")))
                    self.assertEqual("python_progress_error" in ordinary, mode in ("projection-error", "outer-expired"))
                    for key, observed in controller.capture_observations(rig.captures[-1]).items():
                        self.assertEqual(ordinary["capture"][key], observed)
                    self.assertNotIn(private.decode(), json.dumps(result.details))
                    self.assertNotIn("completed", result.details)
                    runs = [event for event in rig.events if event[0] == "run"]
                    self.assertEqual(len(runs), 2)
                    cutoff = 1000.0 if mode == "outer-expired" else 1600.0
                    self.assertTrue(all(event[2]["absolute_deadline"] == cutoff for event in runs))
                    final_run = max(index for index, event in enumerate(rig.events) if event[0] == "run")
                    self.assertTrue(all(event[0] == "idle" for event in rig.events[final_run + 1:]))

        rig = self._python_gate_fixture()
        with patch.object(rig.checks, "python_capture_ids", side_effect=AssertionError("parser rescan")), \
                patch.object(rig.checks, "native_partition_ids", side_effect=AssertionError("parser native rescan")):
            self.assertTrue(self._perform_native_fixture(rig, platform="linux").ok)
        for changes, platform, expected in (({"id": "native-profile-source"}, "linux", identifiers),
            ({"parser": "exit"}, "linux", identifiers), ({"native_partition": "healthy"}, "linux", identifiers),
            ({}, "macos", identifiers), ({}, "linux", list(identifiers)), ({}, "linux", ()),
            ({}, "linux", tuple(reversed(identifiers))), ({}, "linux", identifiers + identifiers[:1]),
            ({"parser": "native", "native_partition": "poison-wait-loss"}, "linux", (first,)),
            ({"parser": "native", "native_partition": "poison-wait-loss"}, "linux", rig.inventories["poison-startup-error"]),
            ({"parser": "native", "native_partition": "all"}, "linux", identifiers)):
            with self.subTest(prebound_role=(changes, platform, expected)), \
                    self.assertRaisesRegex(controller.VerificationError, "PYTHON_PREBOUND_EXPECTATIONS"):
                controller.parse_capture(dataclasses.replace(rig.step, **changes), rig.captures[-1], rig.paths,
                                         platform, rig.checks, _python_expected=expected)

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
                                   stdout=raw, stderr=stderr, persisted=(len(raw), len(stderr)), duration=0.1,
                                   primary_error="command exited 1", cleanup_errors=())

        value = controller.failure_details(capture([callback]), step, paths, checks=checks, deadline=1000.0)
        self.assertEqual(value["failure_callbacks"], [callback])
        self.assertEqual(value["helper_error"], "TEST_OUTCOME_COUNT")
        self.assertEqual(value["returncode"], 1)
        self.assertEqual(observed, [(ROOT, "full", "healthy", 1000.0)])
        self.assertNotIn(private, json.dumps(value))
        with patch.object(checks, "python_capture_ids", side_effect=AssertionError("prebound callback rescan")):
            reused = controller.failure_details(capture([callback]), step, paths, checks=checks,
                deadline=1000.0, platform="linux", _python_expected=(identifier,))
        self.assertEqual(reused["failure_callbacks"], [callback])
        self.assertEqual(observed, [(ROOT, "full", "healthy", 1000.0)])
        valid = [callback, {**callback, "errno": None},
                 {**callback, "outcome": "failure", "category": "assertion-error", "errno": None},
                 {**callback, "outcome": "expected-failure", "category": "exception", "errno": None},
                 *({**callback, "outcome": outcome, "category": "none", "errno": None}
                   for outcome in ("skip", "unexpected-success"))]
        for row in valid:
            self.assertEqual(controller.python_failure_callbacks([row], (identifier,)), [row])
        invalid = [None, {}, [callback] * 17, [{**callback, "id": private}],
                   [{**callback, "id": _G_LINUX_METHODS[0]}], [{**callback, "message": private}]]
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

            poison_callbacks = [(partition, owner) for partition, owner in _PYTHON_SINGLETON_FIXTURES
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

    def test_command_account_failure_is_closed_bounded_and_bound_to_failed_original_callbacks(self):
        controller = controller_module()
        self.enterContext(patch.object(controller.time, "monotonic", return_value=999.0))
        paths = fixture_paths(controller)
        identifier = ("workflow.test_command_account_lifecycle.CommandAccountLifecycleTests."
                      "test_prepared_no_target_original_fence_and_same_lease_cleanup")
        account_ids = (identifier,
            "workflow.test_command_account_lifecycle.CommandAccountLifecycleTests."
            "test_prepared_input_withdrawal_c_loss_fresh_prefix_recovery",
            "workflow.test_command_account_lifecycle.CommandAccountLifecycleTests."
            "test_original_hold_survives_true_parent_loss_and_is_absent_from_worker_map")
        unrelated = "unit.synthetic.Other.test_case"
        self.assertEqual(controller.COMMAND_ACCOUNT_FAILURE_ID, identifier)
        self.assertEqual(controller.COMMAND_ACCOUNT_FAILURE_IDS, frozenset(account_ids))
        checks = SimpleNamespace(python_capture_ids=lambda *_, **__: (*account_ids, unrelated),
                                 native_partition_ids=lambda *_, **__: (*account_ids, unrelated))
        callback = {"id": identifier, "outcome": "failure", "category": "assertion-error", "errno": None}
        packet = {"category": "AssertionError", "frames": [["command_account_lifecycle_fixture.py", 192],
                  ["contextlib.py", 144], ["PRIVATE.py", 123], ["local_signing.py", 1170]]}

        def encode(value):
            return b"\nMRK_C_FENCE_FIXTURE_FAILURE=" + json.dumps(value, separators=(",", ":")).encode("ascii") + b"\n"

        marker = encode(packet)
        expected = {"category": "assertion-error", "locations": [
            {"file": "tests/workflow/command_account_lifecycle_fixture.py", "line": 192},
            {"file": "src/mobile_release/local_signing.py", "line": 1170}]}
        self.assertEqual(controller.command_account_failure(marker, deadline=1000.0), expected)
        for category, public in (("ProcessCleanupError", "process-cleanup-error"),
                                 ("ProcessOutcomeUnknown", "process-outcome-unknown")):
            self.assertEqual(controller.command_account_failure(encode({**packet, "category": category}),
                             deadline=1000.0), {**expected, "category": public})
        malformed = [encode({**packet, "category": "PRIVATE_ERROR"}), encode({**packet, "category": True}),
                     encode({**packet, "message": "PRIVATE"}), encode({**packet, "frames": {}}),
                     encode({**packet, "frames": [["local_signing.py", 1]] * 13}),
                     *(encode({**packet, "frames": [row]}) for row in (
                         ["local_signing.py", True], ["local_signing.py", 0], ["local_signing.py", 1_000_000],
                         ["local_signing.py", 1, "PRIVATE"], [True, 1], "PRIVATE")),
                     *(encode({**packet, "frames": [[name, 1]]}) for name in (
                         "", "PRIVATE", "/PRIVATE/local_signing.py", "../local_signing.py", "dir\\local_signing.py",
                         "private\n.py", "private\x00.py", "privat\u00e9.py", "x" * 129 + ".py")),
                     marker + marker, marker[:-1], marker.replace(b'{', b'{ ', 1),
                     marker.replace(b'"category":', b'"category":"AssertionError","category":', 1),
                     b"MRK_C_FENCE_FIXTURE_FAILURE=" + b" " * 2048 + b"\n",
                     b"MRK_C_FENCE_FIXTURE_FAILURE=\xff\n", bytearray(marker)]
        for raw in malformed:
            with self.subTest(raw=repr(raw[:80])):
                self.assertIsNone(controller.command_account_failure(raw, deadline=1000.0))

        def capture(records, native, gate, *, raw=marker, ok=False, finality=True, phase="tests"):
            envelope = ({"schema": 1, "phase": phase, "records": [{**row, "returncode": None} for row in records]}
                        if native else
                        {"check": gate, "ok": False, "details": {"error": "TEST_OUTCOME_COUNT", "failure_callbacks": records}})
            prefix = controller.NATIVE_DIAGNOSTIC_PREFIX if native else "MRK_CHECK_RESULT="
            stdout = (prefix + json.dumps(envelope) + "\n").encode()
            return SimpleNamespace(ok=ok, returncode=0 if ok else 1, waited=True, stdout_eof=True, stderr_eof=True,
                domain_finality=finality, timed_out=False, cancelled=False, stdout=stdout, stderr=raw,
                persisted=(len(stdout), len(raw)), duration=0.1,
                primary_error=None if ok else "command exited 1", cleanup_errors=())

        routes = [(gate, "native" if gate.startswith("native-") else "check", "all") for gate in
                  ("python-full", "python-wheel", "native-profile-source", "native-profile-wheel")]
        routes += [(gate, "native", "poison-command-prepared-prefix-input-loss")
                   for gate in ("python-full", "python-wheel")]
        for gate, parser, partition in routes:
            step = controller.Step(gate, parser=parser, native_partition=partition)
            def details(records, **options):
                return controller.failure_details(capture(records, parser == "native", gate, **options), step, paths,
                                                  checks=checks, deadline=1000.0)
            for account_id in account_ids:
                for finality in (False, True):
                    observed = details([{**callback, "id": account_id}], finality=finality)
                    self.assertEqual(observed["command_account_failure"], expected)
                    self.assertEqual(observed["returncode"], 1)
                    self.assertIs(observed["domain_finality"], finality)
                    self.assertNotIn("PRIVATE", json.dumps(observed))
            for rows, options in (([], {}), ([callback], {"ok": True}), ([callback], {"raw": marker[:-1]}),
                                  ([{**callback, "id": unrelated}], {}), ([{**callback, "id": "PRIVATE"}], {}),
                                  ([{**callback, "outcome": "expected-failure"}], {}),
                                  ([{**callback, "outcome": "skip", "category": "none"}], {})):
                self.assertNotIn("command_account_failure", details(rows, **options))
            with patch.object(controller, "command_account_failure", side_effect=RuntimeError("PRIVATE parser")):
                observed = details([callback])
            self.assertEqual(observed["returncode"], 1)
            self.assertNotIn("command_account_failure", observed)
            self.assertNotIn("PRIVATE", json.dumps(observed))
            if parser == "native":
                self.assertNotIn("command_account_failure", details([callback], phase="prerequisite"))
        with patch.object(controller.time, "monotonic", return_value=1000.0):
            for raw in (marker, marker[:-1]):
                with self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                    controller.command_account_failure(raw, deadline=1000.0)

    def test_command_failure_context_keeps_exact_phase_paths_and_fixed_mode_prefix_only(self):
        import ast
        controller = controller_module()
        self.enterContext(patch.object(controller.time, "monotonic", return_value=999.0))
        paths = fixture_paths(controller)
        identifier = ("unit.test_owned_process.OwnedProcessTests."
                      "test_guarded_worker_tail_and_report_loss_preserve_original_outcomes")
        modes = ("body-return", "body-systemexit", "report-format-error", "reject-zero", "reject-eagain", "reject-error",
                 "reject-full", "reject-partial", "arm-missing", "arm-partial", "post-map-pre-ready")
        self.assertEqual(controller.COMMAND_CASE_FAILURE_ID, identifier)
        self.assertEqual(controller.COMMAND_CASE_MODES, modes)
        tree = ast.parse((ROOT / "tests/unit/test_owned_process.py").read_text())
        method, = (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                   and node.name == identifier.rsplit(".", 1)[1])
        literals = {node.targets[0].id: ast.literal_eval(node.value) for node in method.body
                    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)}
        loop, = (node for node in method.body if isinstance(node, ast.For))
        actual_modes = tuple(value for node in loop.iter.elts for value in
                             (literals[node.value.id] if isinstance(node, ast.Starred) else (node.value,)))
        self.assertEqual(actual_modes, modes)
        # Execute only the two exact pre-acquisition emitter statements, never
        # the native test body, against real unittest success framing.
        emitters = loop.body[:2]
        expected_emitters = ast.parse('sys.stdout.write("\\nMRK_OWNED_COMMAND_MODE=" + mode + "\\n")\nsys.stdout.flush()').body
        self.assertEqual([ast.dump(node) for node in emitters], [ast.dump(node) for node in expected_emitters])
        program = compile(ast.Module(body=emitters, type_ignores=[]), "<inert-command-mode-emitter>", "exec")
        native_stdout, native_stderr = io.StringIO(), io.StringIO()
        def emit(_test):
            for mode in modes:
                exec(program, {"sys": SimpleNamespace(stdout=native_stdout, stderr=native_stderr), "mode": mode})
        fixture = type("OwnedProcessTests", (unittest.TestCase,), {
            "__module__": "unit.test_owned_process", identifier.rsplit(".", 1)[1]: emit})
        completed = unittest.TextTestRunner(stream=native_stderr, verbosity=2, descriptions=False).run(
            unittest.TestSuite((fixture(identifier.rsplit(".", 1)[1]),)))
        self.assertTrue(completed.wasSuccessful())
        self.assertEqual(completed.testsRun, 1)
        captured = SimpleNamespace(ok=True, returncode=0, waited=True, stdout_eof=True, stderr_eof=True,
            domain_finality=True, primary_error=None, cleanup_errors=(), duration=0.01,
            stdout=native_stdout.getvalue().encode(), stderr=native_stderr.getvalue().encode())
        parsed = controller.parse_capture(controller.Step("native-profile-source", parser="native"), captured,
            paths, "macos", SimpleNamespace(native_partition_ids=lambda *_, **__: (identifier,)), deadline=1000.0)
        self.assertTrue(parsed.ok)
        self.assertEqual(parsed.details["completed"], [identifier])
        callback = {"id": identifier, "outcome": "failure", "category": "assertion-error", "errno": None}
        private = "PRIVATE_COMMAND_FAILURE_CANARY"
        marker = lambda mode: b"MRK_OWNED_COMMAND_MODE=" + mode.encode() + b"\n"
        frame = lambda path, line: f'  File "{path}", line {line}, in {private}\n'.encode()
        relative = "tests/unit/test_owned_process.py"
        for phase in ("source", "wheel"):
            package = paths.work / ("source-build/src/mobile_release" if phase == "source" else
                                    "wheel-venv/lib/python3.11/site-packages/mobile_release")
            wrong = paths.work / ("source-build/src/mobile_release" if phase == "wheel" else
                                  "wheel-venv/lib/python3.11/site-packages/mobile_release")
            headers = (frame(paths.source / relative, 1463)
                       + frame(package / "_command_process.py", 3240).replace(b"\n", b"\r\n"))
            rejected = (frame("/other/" + relative, 81), frame(relative, 82),
                        frame(package / "PRIVATE.py", 83), frame(wrong / "_command_process.py", 84),
                        frame(paths.source / relative, 0), frame(paths.source / relative, "01"),
                        frame(paths.source / relative, 1_000_000), frame(paths.source / relative, 2).lstrip(),
                        frame(paths.source / relative, 3).replace(b"\n", b" trailing\n"),
                        frame(paths.source / relative, 4)[:-1])
            expected = [{"file": relative, "line": 1463}, {"file": "src/mobile_release/_command_process.py", "line": 3240}]
            output = marker(modes[0]) + marker(modes[1])
            raw = (b"test_guarded ... \n" + headers
                   + b"    private_source('" + private.encode() + b"')\nAssertionError: /private/signing\n")
            observed = controller.command_failure_context(raw, [callback], paths, phase,
                                                          mode_output=output, deadline=1000.0)
            self.assertEqual(observed, {"command_failure_locations": expected, "command_case_mode": modes[1]})
            for hidden in (private, str(paths.source), "/private/signing", "private_source"):
                self.assertNotIn(hidden, json.dumps(observed))
            for bad in rejected:
                self.assertEqual(controller.command_failure_context(bad, [callback], paths, phase, deadline=1000.0), {})
            bounded = controller.command_failure_context(headers * 20, [callback], paths, phase, deadline=1000.0)
            self.assertEqual(bounded, {"command_failure_locations": expected * 8})
            self.assertEqual(controller.command_failure_context(raw, [], paths, phase, deadline=1000.0), {})
            for bad in (marker(modes[1]), marker(modes[0]) * 2, marker(modes[0]) + marker(modes[2]),
                        marker(modes[0])[:-1], marker(modes[0]).replace(b"\n", b"\r\n"), marker("PRIVATE"),
                        marker(modes[0]) + marker("PRIVATE"), b"".join(map(marker, modes)) + marker(modes[-1])):
                result = controller.command_failure_context(headers, [callback], paths, phase,
                                                            mode_output=bad, deadline=1000.0)
                self.assertEqual(result, {"command_failure_locations": expected})
            for count in range(1, len(modes) + 1):
                result = controller.command_failure_context(b"", [callback], paths, phase,
                    mode_output=b"".join(map(marker, modes[:count])), deadline=1000.0)
                self.assertEqual(result, {"command_case_mode": modes[count - 1]})
            self.assertEqual(controller.command_failure_context(output, [callback], paths, phase,
                mode_output=headers, deadline=1000.0), {})  # Never swap stderr/source with stdout/modes.
            for excluded in ({**callback, "id": "unit.synthetic.Other.test_case"},
                             {**callback, "outcome": "skip"}, {**callback, "outcome": "expected-failure"}):
                self.assertEqual(controller.command_failure_context(raw, [excluded], paths, phase, deadline=1000.0), {})
            account = {**callback, "id": controller.COMMAND_ACCOUNT_FAILURE_ID}
            self.assertEqual(controller.command_failure_context(raw, [account], paths, phase,
                             mode_output=output, deadline=1000.0),
                             {"command_failure_locations": expected})
        for bad in (bytearray(b""), b"x" * (8 * 1024**2 + 1)):
            self.assertEqual(controller.command_failure_context(bad, [callback], paths, "source", deadline=1000.0), {})
            self.assertEqual(controller.command_failure_context(b"", [callback], paths, "source",
                mode_output=bad, deadline=1000.0), {})

    def test_command_failure_context_never_replaces_original_result_or_cutoff(self):
        controller = controller_module()
        paths = fixture_paths(controller)
        identifier = controller.COMMAND_CASE_FAILURE_ID
        callback = {"id": identifier, "outcome": "failure", "category": "assertion-error", "errno": None, "returncode": None}
        checks = SimpleNamespace(native_partition_ids=lambda *_, **__: (identifier,))
        text = f'  File "{paths.source / "tests/unit/test_owned_process.py"}", line 1463, in test_case\n'.encode()
        stdout = ("MRK_OWNED_COMMAND_MODE=body-return\n" + controller.NATIVE_DIAGNOSTIC_PREFIX
                  + json.dumps({"schema": 1, "phase": "tests", "records": [callback]}) + "\n").encode()
        fields = dict(ok=False, returncode=1, waited=True, stdout_eof=True, stderr_eof=True, domain_finality=True,
                      timed_out=False, cancelled=False, primary_error="command exited 1", cleanup_errors=(),
                      stdout=stdout, stderr=text, persisted=(len(stdout), len(text)), duration=0.01)
        step = controller.Step("native-profile-source", parser="native")
        with patch.object(controller.time, "monotonic", return_value=999.0):
            for changes in ({}, {"waited": False, "domain_finality": False, "cleanup_errors": ("stream close OSError",)}):
                original = SimpleNamespace(**{**fields, **changes})
                before = dict(vars(original))
                result = controller.failure_details(original, step, paths, checks=checks, deadline=1000.0)
                self.assertEqual(result["command_case_mode"], "body-return")
                self.assertEqual(result["command_failure_locations"], [{"file": "tests/unit/test_owned_process.py", "line": 1463}])
                self.assertEqual(vars(original), before)
                for key, value in controller.capture_observations(original).items():
                    self.assertEqual(result[key], value)
                with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                    controller.require_original_finality(original)
            with patch.object(controller, "command_failure_context", side_effect=ValueError("PRIVATE parser")):
                result = controller.failure_details(SimpleNamespace(**fields), step, paths, checks=checks, deadline=1000.0)
            self.assertEqual(result["returncode"], 1)
            self.assertNotIn("command_failure_locations", result)
            self.assertNotIn("PRIVATE", json.dumps(result))
            with patch.object(controller, "command_failure_context") as diagnostic:
                for ok in (True, None, 0):
                    original = SimpleNamespace(**{**fields, "ok": ok, "returncode": 0, "primary_error": None})
                    result = controller.failure_details(original, step, paths, checks=checks, deadline=1000.0)
                    self.assertNotIn("command_failure_locations", result)
                diagnostic.assert_not_called()
        for ticks in ((1000.0,), (999.0, 1000.0), (999.0, 999.0, 1000.0)):
            clock = iter(ticks)
            with patch.object(controller.time, "monotonic", side_effect=lambda: next(clock, 1000.0)), \
                    self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                controller.command_failure_context(text, [callback], paths, "source", deadline=1000.0)

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
        for delegated in _G_LINUX_METHODS:
            with self.subTest(unexecuted_delegated=delegated), \
                    self.assertRaisesRegex(controller.VerificationError, "PYTHON_COMPLETION_INVENTORY"):
                controller.parse_capture(step, capture(profile, tests=[{
                    "id": delegated, "outcome": "ok"}]), paths, "linux", checks)
        for callbacks in ([{"id": identifier, "outcome": "error", "category": "os-error", "errno": 27}],
                          [{"id": "private", "outcome": "error", "category": "os-error", "errno": 27}],
                          [{"id": identifier, "raw_message": "private"}], [None]):
            with self.subTest(success_failure_callbacks=callbacks):
                with self.assertRaisesRegex(controller.VerificationError, "PYTHON_FAILURE_CALLBACKS_ON_SUCCESS"):
                    controller.parse_capture(step, capture(profile, callbacks=callbacks), paths, "linux", checks)

    def test_python_parser_allows_only_exact_linux_full_and_wheel_skip_intersections(self):
        controller = controller_module()
        permitted = ci_module("ci_checks").linux_allowed_skips()
        wheel_skips = _WHEEL_DARWIN_SKIP_IDS
        for phase, selected in (("source", permitted), ("wheel", wheel_skips)):
            rig = self._python_gate_fixture(phase)
            rig.checks.linux_allowed_skips = lambda: permitted
            healthy = rig.inventories["healthy"]
            expected = tuple(sorted(healthy + tuple(selected)))
            rig.inventories["healthy"] = expected
            original = rig.session.run(list(rig.step.argv))  # The existing inert capture rig only.
            summary = json.loads(original.stdout.decode().split("=", 1)[1])
            summary["tests"] = [{"id": identifier, "outcome": "skip" if identifier in selected else "ok"}
                                for identifier in expected]

            def capture(rows):
                data = ("MRK_CHECK_RESULT=" + json.dumps({**summary, "tests": rows}) + "\n").encode()
                return SimpleNamespace(**{**vars(original), "stdout": data})

            result = controller.parse_capture(rig.step, capture(summary["tests"]), rig.paths, "linux", rig.checks)
            self.assertTrue(result.ok)
            self.assertEqual(sum(row["outcome"] == "skip" for row in summary["tests"]), 21 if phase == "source" else 9)
            for platform in ("macos", "darwin"):
                with self.subTest(phase=phase, platform=platform), \
                        self.assertRaisesRegex(controller.VerificationError, "PYTHON_UNEXPECTED_SKIP_OR_FAILURE"):
                    controller.parse_capture(rig.step, capture(summary["tests"]), rig.paths, platform, rig.checks)
            for changed in (healthy[0], *selected):
                rows = [{**row, "outcome": "ok" if row["id"] in selected else "skip"}
                        if row["id"] == changed else row for row in summary["tests"]]
                with self.subTest(phase=phase, incorrect_skip=changed), \
                        self.assertRaisesRegex(controller.VerificationError, "PYTHON_UNEXPECTED_SKIP_OR_FAILURE"):
                    controller.parse_capture(rig.step, capture(rows), rig.paths, "linux", rig.checks)

    def test_complete_fixed_gate_inventory_cannot_omit_duplicate_or_reorder_a_step(self):
        controller = controller_module()
        before = ("source-copy", "source-environment", "source-dependencies", "bundler", "bundle-install",
                  "editable-install", "source-freeze", "source-pip-check", "bundle-check")
        ruby = ("ruby-support", "ruby-store_document", "ruby-store_lane_lifetime",
                "ruby-store_lane_nested_validation", "ruby-store_lane_resources", "ruby-store_lane_runtime",
                "ruby-native-spawn", "ruby-native-owner", "ruby-native-capture", "ruby-native-signal-observation",
                "ruby-play_store", "ruby-play_lanes", "ruby-apple_store",
                "ruby-apple_lanes", "ruby-apple_production", "ruby-apple_production_lane", "ruby-apple_asset_upload",
                "ruby-ios_upload_validation", "ruby-android_upload_validation", "ruby-workflow-yaml", "ruby-supply-wif")
        wheel = ("wheel-copy", "wheel-build", "wheel-inspect", "wheel-environment", "wheel-pip", "wheel-install",
                 "wheel-freeze", "wheel-pip-check")
        compatibility_source = ("python-compat-312-source", "python-compat-313-source", "python-compat-314-source")
        compatibility_wheel = ("python-compat-312-wheel", "python-compat-313-wheel", "python-compat-314-wheel")
        expected = {
            "linux": (*before, "native-process-abi-source", *compatibility_source, "python-full", *ruby,
                      "ruby-packaged-capture-source", "store-lane-native-source", "fastfile", "actionlint", "jdk-signers", *wheel,
                      "native-process-abi-wheel", *compatibility_wheel, "wheel-smoke", "wheel-consumer",
                      "ruby-packaged-capture-wheel", "store-lane-native-wheel", "python-wheel", "source-integrity"),
            "macos": (*before, "native-tools", "native-process-abi-source", *compatibility_source, "native-profile-source",
                      "ruby-ios_upload_validation", "ruby-native-spawn", "ruby-native-owner", "ruby-native-capture",
                      "ruby-native-signal-observation",
                      "ruby-android_upload_validation", "ruby-packaged-capture-source", "store-lane-native-source",
                      *wheel, "native-process-abi-wheel", *compatibility_wheel,
                      "wheel-smoke", "wheel-consumer", "ruby-packaged-capture-wheel", "store-lane-native-wheel", "native-profile-wheel", "source-integrity"),
        }
        native_profiles = ("native-profile-source", "native-profile-wheel")
        native_python = (*before, "native-tools", "native-process-abi-source", *compatibility_source,
                         "native-profile-source", *wheel, "native-process-abi-wheel", *compatibility_wheel,
                         "wheel-smoke", "wheel-consumer", "native-profile-wheel", "source-integrity")
        native_support = tuple(name for name in expected["macos"] if name not in native_profiles)
        self.assertEqual(set(native_python) | set(native_support), set(expected["macos"]))
        self.assertEqual(set(expected["macos"]) - set(native_support), set(native_profiles))
        self.assertEqual(set(native_python) - set(native_support), set(native_profiles))
        catalogs = {}
        for platform, scope, wanted, count in (("linux", "platform", expected["linux"], 58),
                                               ("macos", "platform", expected["macos"], 41),
                                               ("macos", "native-python", native_python, 31),
                                               ("macos", "native-support", native_support, 39)):
            steps = controller.catalog(fixture_paths(controller), platform, deadline=1000.0, scope=scope)
            catalogs[platform, scope] = steps
            with self.subTest(platform=platform, scope=scope):
                ids = tuple(step.id for step in steps)
                self.assertEqual(ids, wanted)
                self.assertEqual(controller.required_gate_ids(platform, scope), wanted)
                if scope == "platform":
                    self.assertEqual(controller.required_gate_ids(platform), wanted)
                self.assertEqual(len(steps), count)
                self.assertEqual(len(set(ids)), count)
                if platform == "macos":
                    # Each fixed owner builds its own complete prerequisites;
                    # no source/wheel ownership is supplied by the other job.
                    self.assertEqual(tuple(name for name in ids if name in before), before)
                    self.assertEqual(tuple(name for name in ids if name in wheel), wheel)
                    self.assertLess(ids.index("native-tools"), ids.index("native-process-abi-source"))
                    self.assertLess(ids.index("native-process-abi-source"), ids.index("wheel-copy"))
                    self.assertLess(ids.index("wheel-pip-check"), ids.index("native-process-abi-wheel"))
                    for prerequisite in compatibility_source:
                        self.assertLess(ids.index("native-process-abi-source"), ids.index(prerequisite))
                        self.assertLess(ids.index(prerequisite), ids.index("wheel-copy"))
                    for prerequisite in compatibility_wheel:
                        self.assertLess(ids.index("native-process-abi-wheel"), ids.index(prerequisite))
                        self.assertLess(ids.index(prerequisite), ids.index("wheel-smoke"))
                    if scope != "native-support":
                        for prerequisite in ("native-tools", "native-process-abi-source", *compatibility_source):
                            self.assertLess(ids.index(prerequisite), ids.index("native-profile-source"))
                        self.assertLess(ids.index("native-profile-source"), ids.index("wheel-copy"))
                        self.assertLess(ids.index("wheel-consumer"), ids.index("native-profile-wheel"))
                        self.assertLess(ids.index("native-profile-source"), ids.index("native-profile-wheel"))
                        self.assertEqual([step.seconds for step in steps if step.id in native_profiles], [1500, 1500])
                    if scope != "native-python":
                        self.assertLess(ids.index("ruby-ios_upload_validation"), ids.index("ruby-native-spawn"))
                        for gate in ("ruby-native-capture", "ruby-native-signal-observation",
                                     "ruby-ios_upload_validation", "ruby-android_upload_validation"):
                            self.assertLess(ids.index("native-tools"), ids.index(gate))
                            self.assertLess(ids.index("native-process-abi-source"), ids.index(gate))
                            if scope == "platform":
                                self.assertLess(ids.index("native-profile-source"), ids.index(gate))
            altered = [(), steps[:-1], (*steps, steps[-1]), (steps[1], steps[0], *steps[2:]),
                       (dataclasses.replace(steps[0], id="unknown-gate"), *steps[1:])]
            altered.extend((*steps[:index], *steps[index + 1:]) for index in range(len(steps)))
            for invalid in altered:
                with self.subTest(platform=platform, scope=scope, ids=[step.id for step in invalid]):
                    seen = []
                    with self.assertRaisesRegex(controller.VerificationError, "REQUIRED_GATE_INVENTORY"):
                        controller.execute_pipeline(invalid, lambda step: seen.append(step.id), platform=platform, scope=scope)
                    self.assertEqual(seen, [])
        for scope in ("native-python", "native-support"):
            scoped = catalogs["macos", scope]
            self.assertEqual(scoped, tuple(step for step in catalogs["macos", "platform"]
                                            if step.id in {row.id for row in scoped}))
            for method in (controller.required_gate_ids, controller.catalog):
                with self.subTest(linux_native_scope=scope, method=method.__name__), \
                     self.assertRaisesRegex(controller.VerificationError, "UNSUPPORTED_VERIFICATION_SCOPE"):
                    if method is controller.catalog:
                        method(fixture_paths(controller), "linux", deadline=1000.0, scope=scope)
                    else:
                        method("linux", scope)
        for scope in ("", "native", "native_python", "native_support", "native-python ", "native-support ",
                      "NATIVE-PYTHON", "NATIVE-SUPPORT"):
            for platform in ("linux", "macos"):
                with self.subTest(platform=platform, unknown_scope=scope), \
                     self.assertRaisesRegex(controller.VerificationError, "UNSUPPORTED_VERIFICATION_SCOPE"):
                    controller.required_gate_ids(platform, scope)
        with self.assertRaisesRegex(controller.VerificationError, "UNSUPPORTED_PLATFORM"):
            controller.required_gate_ids("windows")

        # Closed offline-input admission uses only synthetic bytes and fake
        # metadata. No fixture directory, download, chmod or freeze can escape.
        root = fixture_paths(controller).inputs
        payload = b"synthetic offline native input\n"
        names = ("inputs.json", "gems/bundler-4.0.16.gem", "gems/offline-fixture.gem",
                 *(f"python/input-{index:03d}.whl" for index in range(148)))
        files = [{"path": name, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()} for name in names]
        base = {"platform": "macos", "actionlint": None, "gems": "gems", "bundler": "gems/bundler-4.0.16.gem",
                "manifest_sha256": "1" * 64, "lock_sha256": "2" * 64, "files": files[:100]}
        for scope in ("native-python", "native-support"):
            for count in (100, 150):
                value = {**base, "files": files[:count]}
                walk_rows = [(str(root), ["gems", "python"], ["inputs.json"]),
                             (str(root / "gems"), [], ["bundler-4.0.16.gem", "offline-fixture.gem"]),
                             (str(root / "python"), [], [Path(name).name for name in names[3:count]])]
                with self.subTest(native_input_scope=scope, count=count), \
                     patch.object(controller.time, "monotonic", return_value=0.0), \
                     patch.object(controller.os, "walk", return_value=walk_rows) as walk_input, \
                     patch.object(Path, "is_symlink", return_value=False), \
                     patch.object(controller, "read_regular", return_value=payload) as reader, \
                     patch.object(controller, "freeze_tree") as freeze, \
                     patch.object(controller.os, "chmod", side_effect=AssertionError("native input may not chmod a tool")):
                    result = controller.validate_inputs(root, value, deadline=1000.0, scope=scope)
                    self.assertEqual(result, {"files": count, "bytes": count * len(payload),
                        "tools_sha256": base["manifest_sha256"], "lock_sha256": base["lock_sha256"]})
                    walk_input.assert_called_once_with(root, followlinks=False, onerror=controller.walk_error)
                    self.assertEqual([call.args for call in reader.call_args_list], [(root / name,) for name in names[:count]])
                    self.assertTrue(all(call.kwargs == {"deadline": 1000.0, "maximum": 16 * 1024**2}
                                        for call in reader.call_args_list))
                    freeze.assert_called_once_with(root, deadline=1000.0)
            invalid_inputs = (
                ({"platform": "linux"}, "UNSUPPORTED_VERIFICATION_SCOPE"),
                ({"files": files[:13]}, "INPUT_INVENTORY_BOUND"),
                ({"files": files[:99]}, "INPUT_INVENTORY_BOUND"),
                ({"files": files}, "INPUT_INVENTORY_BOUND"),
                ({"files": [*files[:99], files[0]]}, "INPUT_INVENTORY_BOUND"),
                ({"actionlint": "actionlint"}, "NATIVE_INPUT_INVENTORY"),
                ({"gems": None}, "NATIVE_INPUT_INVENTORY"),
                ({"bundler": None}, "NATIVE_INPUT_INVENTORY"),
                ({"files": [*files[:99], {**files[99], "path": "foreign/input.whl"}]}, "NATIVE_INPUT_INVENTORY"),
            )
            for index, (changes, error) in enumerate(invalid_inputs):
                with self.subTest(native_input_scope=scope, invalid=index, error=error), contextlib.ExitStack() as stack:
                    operations = [stack.enter_context(patch.object(owner, method,
                        side_effect=AssertionError("refused native inventory may not inspect or freeze inputs")))
                        for owner, method in ((controller.os, "walk"), (Path, "is_symlink"),
                                              (controller, "read_regular"), (controller, "freeze_tree"),
                                              (controller.os, "chmod"))]
                    with self.assertRaisesRegex(controller.VerificationError, error):
                        controller.validate_inputs(root, {**base, **changes}, deadline=1000.0, scope=scope)
                    for operation in operations:
                        operation.assert_not_called()

    def test_every_early_or_final_failure_is_latched_and_later_gates_are_unexecuted(self):
        controller = controller_module()
        private = "private-pipeline-diagnostic-canary"
        for platform in ("linux", "macos"):
            steps = controller.catalog(fixture_paths(controller), platform, deadline=1000.0)
            ids = [step.id for step in steps]
            for failed in (None, *ids):
                for raised in (False, True):
                    with self.subTest(platform=platform, failed=failed, raised=raised):
                        seen = []
                        original = ProcessLookupError(errno.ESRCH, private, "/private/" + private)
                        original._mrk_provider_stat = ("python", 0, 1, ("missing-target",))

                        def perform(step):
                            seen.append(step.id)
                            if step.id == failed:
                                if raised:
                                    raise original
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
                            row = report.rows[index]
                            self.assertEqual(row["error"], report.error)
                            if raised:
                                self.assertEqual(row["exception"], "ProcessLookupError")
                                self.assertEqual(row["errno"], errno.ESRCH)
                                self.assertEqual(row["location"][0], "test_ci_verification.py")
                                self.assertEqual(row["controller_location"][0], "verify_ci.py")
                                self.assertGreater(row["controller_location"][1], 0)
                                self.assertEqual(row["provider_stat"], {
                                    "operation": "provider-stat", "runtime_role": "python",
                                    "prefix_index": 0, "node_index": 1,
                                    "relative_components": ["missing-target"],
                                })
                                self.assertNotIn("details", row)  # No invented capture or check result.
                            else:
                                self.assertEqual(row["details"], {"ok": True, "status": "PASS"})
                                self.assertNotIn("errno", row)
                            self.assertNotIn(private, json.dumps(row))
                            self.assertNotIn("/private/", json.dumps(row))
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
        self.assertEqual(report.error, "CHECK_EXECUTION_FAILED")
        self.assertEqual(report.rows[0]["error"], report.error)
        self.assertEqual(report.rows[0]["exception"], "KeyboardInterrupt")
        self.assertEqual(report.rows[0]["controller_location"][0], "verify_ci.py")
        self.assertNotIn("errno", report.rows[0])
        self.assertNotIn("synthetic cancellation", json.dumps(report.rows))
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
        for platform, scope in (("linux", "platform"), ("macos", "platform"),
                                 ("macos", "native-python"), ("macos", "native-support")):
            for step in controller.catalog(fixture_paths(controller), platform, deadline=4321.5, scope=scope):
                if "--deadline" in step.argv:
                    self.assertEqual(step.argv[step.argv.index("--deadline") + 1], "4321.5")
            for invalid in (float("nan"), float("inf"), -float("inf"), "4321.5", True):
                with self.subTest(platform=platform, scope=scope, invalid_deadline=invalid), \
                     self.assertRaisesRegex(controller.VerificationError, "INVALID_DEADLINE"):
                    controller.catalog(fixture_paths(controller), platform, deadline=invalid, scope=scope)
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
                            "errorCategory", "nativeErrorCategory", "resultChecks", "nativeChecks",
                            "settlementChecks", "nativeOutcomes")
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
            setup_native_checks = (
                "finalized", "noProducers", "settled", "unknown", "hooksRestored", "observerErrorsEmpty",
                "productionFinality", "retainedUnknown", "statusValid", "statusDecodedEOF", "cleanupErrorsEmpty",
                "originalWaitObserved", "tasksJoined", "leasesClosed", "allActualEOFObserved",
                "captureSettled", "captureFinished", "captureJoined", "captureActualJoinObserved",
                "creatorSettled", "creatorFinished", "creatorJoined", "creatorActualJoinObserved",
                "stdoutEOF", "stdoutActualEOFObserved", "stderrEOF", "stderrActualEOFObserved",
                "statusEOF", "statusActualEOFObserved", "groupAbsent",
            )
            setup_settlement_checks = (
                "taskCleanupComplete", "creationSettled", "custodianWaitBroken", "acquisitionUnknown",
            )
            self.assertEqual(controller.NATIVE_SETUP_FAILURE_PREFIX, "MRK_NATIVE_SETUP_FAILURE=")
            self.assertEqual(controller.NATIVE_SETUP_FAILURE_CALLBACK_MODES, {setup_target: setup_modes})
            self.assertEqual(controller.NATIVE_SETUP_FAILURE_MODES, frozenset(setup_modes))
            self.assertEqual(controller.NATIVE_SETUP_FAILURE_FIELDS, setup_fields)
            self.assertEqual(controller.NATIVE_SETUP_FAILURE_PREDICATES, ("result-kind", "driver-status"))
            self.assertEqual(controller.NATIVE_SETUP_RESULT_KINDS, setup_kinds)
            self.assertEqual(controller.NATIVE_SETUP_ERROR_CATEGORIES, setup_categories)
            self.assertEqual(controller.NATIVE_SETUP_RESULT_CHECKS, setup_result_checks)
            self.assertEqual(controller.NATIVE_SETUP_NATIVE_CHECKS, setup_native_checks)
            self.assertEqual(controller.NATIVE_SETUP_SETTLEMENT_CHECKS, setup_settlement_checks)
            self.assertIs(controller.NATIVE_SETUP_NATIVE_CHECKS, controller.ADAPTER_FAILURE_NATIVE_CHECKS)

            def setup_bytes(record):
                return (controller.NATIVE_SETUP_FAILURE_PREFIX
                        + json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")

            setup_record = {
                "schema": 2, "mode": setup_modes[0], "failedPredicates": ["result-kind", "driver-status"],
                "resultKind": "fixture-cleanup", "driverExitStatus": 1,
                "errorCategory": "interrupt", "nativeErrorCategory": "io-error",
                "resultChecks": {name: (True, False, "missing", "invalid")[index % 4]
                                 for index, name in enumerate(setup_result_checks)},
                "nativeChecks": {name: (False, "missing", "invalid", True)[index % 4]
                                 for index, name in enumerate(setup_native_checks)},
                "settlementChecks": dict(zip(setup_settlement_checks, (True, False, "missing", "invalid"))),
                "nativeOutcomes": {"custodian": "exit2", "keeper": "exit1", "validator": "signal",
                                   "finalOutcome": "failed", "finalCleanup": "unknown", "groupState": "unknown",
                                   "captureState": "attempted", "creatorState": "attempted"},
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
                with patch.object(controller, "_fixture_failure_record", wraps=controller._fixture_failure_record) as strict, \
                        patch.object(controller, "_native_result_projection_valid",
                                     wraps=controller._native_result_projection_valid) as native_grammar:
                    self.assertEqual(controller.native_setup_failure(setup_marker, deadline=1000.0), setup_record)
                strict.assert_called_once_with(setup_marker, "MRK_NATIVE_SETUP_FAILURE=", 2048, deadline=1000.0,
                                               canonical_fields=setup_fields)
                native_grammar.assert_called_once_with(setup_record["nativeChecks"], setup_record["nativeOutcomes"])
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
                              "nativeChecks": dict.fromkeys(setup_native_checks, check_value),
                              "settlementChecks": dict.fromkeys(setup_settlement_checks, check_value)}
                    self.assertEqual(controller.native_setup_failure(setup_bytes(record)), record)

                # All native enums are exercised by the shared adapter grammar
                # below; here bind the setup wire's full finite size and source.
                setup_maximum = {**setup_record, "mode": max(setup_modes, key=len),
                    "resultKind": max(setup_kinds, key=len), "driverExitStatus": 255,
                    "errorCategory": max(setup_categories, key=len), "nativeErrorCategory": max(setup_categories, key=len),
                    "resultChecks": dict.fromkeys(setup_result_checks, "missing"),
                    "nativeChecks": dict.fromkeys(setup_native_checks, "missing"),
                    "settlementChecks": dict.fromkeys(setup_settlement_checks, "missing"),
                    "nativeOutcomes": {"custodian": "not-attempted", "keeper": "not-attempted", "validator": "not-attempted",
                                       "finalOutcome": "rejected", "finalCleanup": "confirmed", "groupState": "not-created",
                                       "captureState": "not-constructed", "creatorState": "not-constructed"}}
                maximum_marker = setup_bytes(setup_maximum)
                self.assertEqual(tuple(setup_maximum), setup_fields)
                self.assertTrue(all(len(value) == max(map(len, controller.ADAPTER_FAILURE_NATIVE_OUTCOMES[name]))
                                    for name, value in setup_maximum["nativeOutcomes"].items()))
                self.assertEqual(len(maximum_marker), 2002)
                self.assertEqual(2048 - len(maximum_marker), 46)
                self.assertEqual(controller.native_setup_failure(maximum_marker), setup_maximum)
                self.assertEqual(controller.failure_details(capture(setup_stdout, stderr=maximum_marker, ok=False, returncode=1),
                    setup_step, paths)["native_setup_failure"], setup_maximum)

                # IOError redaction deliberately changes the external object;
                # its false identity flag must neither invent a predicate nor
                # repair the original failed kind/status or native settlement.
                io_record = {**setup_record, "mode": "native-setup-io-error", "errorCategory": "fixture-error",
                    "nativeErrorCategory": "contract-error",
                    "resultChecks": {**setup_record["resultChecks"], "nativeOriginalErrorPreserved": False},
                    "nativeChecks": {**setup_record["nativeChecks"], "settled": False, "finalized": False, "unknown": True}}
                io_capture = capture(setup_stdout, stderr=setup_bytes(io_record), ok=False, returncode=1)
                self.assertEqual(controller.failure_details(io_capture, setup_step, paths)["native_setup_failure"], io_record)
                with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                    controller.parse_capture(setup_step, io_capture, paths, "macos", None)

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
                    *({**setup_record, "schema": value} for value in (True, 2.0, 1, "2")),
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
                legacy_setup = {key: value for key, value in setup_record.items()
                                if key not in ("settlementChecks", "nativeOutcomes")}
                legacy_setup.update(schema=1, nativeChecks={name: setup_record["nativeChecks"][name]
                                                           for name in setup_native_checks[:5]})
                invalid_setup.append(legacy_setup)
                for key in ("resultChecks", "nativeChecks", "settlementChecks"):
                    checks = setup_record[key]
                    invalid_setup.extend({**setup_record, key: value} for value in (
                        None, [], True, {}, {**checks, "PRIVATE_CHECK": False},
                        {name: value for name, value in checks.items() if name != next(iter(checks))},
                        {name: checks[name] for name in reversed(checks)},
                        *({**checks, name: 0} for name in checks),
                        *({**checks, next(iter(checks)): value} for value in (1, None, [], {}, "false", "PRIVATE_VALUE")),
                    ))
                outcomes = setup_record["nativeOutcomes"]
                invalid_setup.extend({**setup_record, "nativeOutcomes": value} for value in (
                    None, [], True, {}, {**outcomes, "PRIVATE_OUTCOME": "missing"},
                    {name: value for name, value in outcomes.items() if name != "custodian"},
                    {name: outcomes[name] for name in reversed(outcomes)},
                    *({**outcomes, name: "exit0" if name in ("captureState", "creatorState") else "attempted"}
                      for name in outcomes),
                    *({**outcomes, "custodian": value} for value in (None, True, 0, [], {}, "PRIVATE_VALUE")),
                ))
                prefix = controller.NATIVE_SETUP_FAILURE_PREFIX.encode("ascii")
                malformed_marker = prefix + b"not-json\n"
                invalid_setup_markers = [*(setup_bytes(record) for record in invalid_setup),
                    setup_marker * 2, setup_marker + malformed_marker, malformed_marker + setup_marker,
                    setup_marker.replace(b'"schema":2', b'"schema":2,"schema":2'),
                    setup_marker.replace(b'"ready":true', b'"ready":true,"ready":true'),
                    setup_marker.replace(b'"finalized":false', b'"finalized":false,"finalized":false'),
                    setup_marker.replace(b'"taskCleanupComplete":true', b'"taskCleanupComplete":true,"taskCleanupComplete":true'),
                    setup_marker.replace(b'"custodian":"exit2"', b'"custodian":"exit2","custodian":"exit2"'),
                    setup_marker.replace(b'"schema":2', b'"schema": 2'),
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
                "resultChecks", "nativeChecks", "timingChecks", "nativeOutcomes", "slowChecks", "captureDetail", "readinessStage",
            )
            adapter_readiness_stages = (
                "not-entered", "native-ready", "startup-marker", "validator-marker", "validator-live", "dispatch",
                "control-admission", "startup-driver-loss", "descendant-fork", "descendant-marker", "descendant-live",
                "inherited-pipes", "descendant-driver-loss", "validator-release", "owner-publication", "ready-return",
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
            owned_error_codes = {
                "control acquisition repeated": "owned-control-repeat",
                "control acquisition returned no IO": "owned-control-no-io",
                "control close is unknown": "owned-control-close",
                "partial command runtime would mix source origins": "owned-runtime-origin",
                "bootstrap record identity changed": "owned-record-identity",
                "bootstrap record exceeds bound": "owned-record-bound",
                "bootstrap record changed during read": "owned-record-changing",
                "bootstrap record write incomplete": "owned-record-write",
                "unsupported owned-child request": "owned-request",
                "owned-child cwd is not a directory": "owned-cwd",
                "child acquisition was already attempted": "owned-acquire-repeat",
                "invalid owned-child deadline": "owned-deadline-shape",
                "owned-child admission deadline expired": "owned-admission-expired",
                "owned creator was not admitted": "owned-creator-admission",
                "native child was not acquired": "owned-child-missing",
                "bootstrap admission deadline expired or cancelled": "owned-admission-cutoff",
                "bootstrap admission endpoint is invalid": "owned-admission-endpoint",
                "bootstrap admission endpoint changed": "owned-admission-identity",
                "unsupported owned-child standard stream": "owned-stdio",
                "oversized bootstrap configuration": "owned-config-bound",
                "partial bootstrap configuration": "owned-config-write",
                "native creator finish return is unknown": "owned-creator-return",
                "native creator did not join": "owned-creator-join",
                "native creator did not settle": "owned-creator-settle",
                "native child publication is unknown": "owned-child-publication",
                "bootstrap readiness is not the reserved child": "owned-ready-binding",
                "bootstrap refused admission": "owned-bootstrap-refused",
                "bootstrap grant repeated": "owned-grant-repeat",
                "bootstrap grant return is ambiguous": "owned-grant-return",
                "child wait authority is unknown": "owned-wait-authority",
                "child numeric routes were not retired": "owned-numeric-retirement",
                "child receipt is not its original wait": "owned-wait-receipt",
                "child signal authority is not reserved": "owned-signal-authority",
                "child signal deadline expired": "owned-signal-cutoff",
                "control close remains unknown": "owned-control-unknown",
                "native IO remains unknown": "owned-io-unknown",
                "creator still owns native close obligations": "owned-creator-close",
                "unknown owned stream": "owned-stream",
                "owned stream EOF deadline expired": "owned-stream-cutoff",
                "bootstrap attempt identity changed": "owned-attempt-identity",
                "child ownership remains unknown": "owned-child-unknown",
                "child cleanup deadline expired": "owned-cleanup-cutoff",
                "child cleanup is not final": "owned-cleanup-finality",
                "bootstrap directory identity changed": "owned-directory-identity",
                "bootstrap record path is invalid": "owned-record-path",
                "bootstrap record publication unavailable": "owned-publish-unavailable",
                "bootstrap record publication refused": "owned-publish-refused",
                "bootstrap record publication return is unknown": "owned-publish-return",
                "bootstrap record publication remains unresolved": "owned-publish-unresolved",
            }
            owned_codes = frozenset(owned_error_codes.values())
            self.assertEqual((len(owned_error_codes), len(owned_codes)), (49, 49))
            self.assertEqual(controller.ADAPTER_FAILURE_OWNED_CODES, owned_codes)
            self.assertLessEqual(max(map(len, owned_codes)), 26)
            adapter_entry_error_codes = {
                "adapter preparation missed original entry budget": "adapter-entry-budget",
                "adapter entry original session or clocks changed": "adapter-entry-binding",
                "adapter entry missed original one-second window": "adapter-entry-window",
                "adapter entry lacks original completion reserve": "adapter-entry-reserve",
            }
            entry_codes = frozenset(adapter_entry_error_codes.values())
            self.assertEqual((len(adapter_entry_error_codes), len(entry_codes)), (4, 4))
            for category, codes in controller.ADAPTER_FAILURE_DRIVER_CODES.items():
                self.assertEqual(frozenset(code for code in codes if code.startswith("owned-")),
                                 owned_codes if category == "fixture-error" else frozenset())
                self.assertEqual(frozenset(code for code in codes if code.startswith("adapter-entry-")),
                                 entry_codes if category == "fixture-error" else frozenset())
            self.assertEqual(controller.ADAPTER_FAILURE_PREFIX, "MRK_ADAPTER_FAILURE=")
            self.assertEqual(controller.ADAPTER_FAILURE_MODE_CONTRACTS, adapter_contracts)
            self.assertEqual(controller.ADAPTER_FAILURE_PLATFORMS, adapter_platforms)
            self.assertEqual(controller.ADAPTER_FAILURE_FIELDS, adapter_fields)
            self.assertEqual(controller.ADAPTER_READINESS_STAGES, adapter_readiness_stages)
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

            adapter_capture_detail = ["contract-error", "01mx" * 6, "1bamx01mx", "01mx", "m01",
                                      ["native-lifecycle-error", "deadline"]]
            adapter_record = {
                "schema": 3, "platform": "ios", "mode": "real-deadline", "expectedKind": "pass",
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
                "captureDetail": adapter_capture_detail,
                "readinessStage": "validator-live",
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
                with patch.object(controller, "_fixture_failure_record", wraps=controller._fixture_failure_record) as strict, \
                        patch.object(controller, "_ownership_capture_detail_valid",
                                     wraps=controller._ownership_capture_detail_valid) as shared_detail:
                    self.assertEqual(controller.adapter_failure(adapter_marker, deadline=1000.0), adapter_record)
                strict.assert_called_once_with(adapter_marker, "MRK_ADAPTER_FAILURE=", 4096, deadline=1000.0,
                                               canonical_fields=adapter_fields)
                shared_detail.assert_called_once_with(adapter_capture_detail)
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
                # Exact finite source codes add information to the retained
                # fixture error only. They are not native causes or authority.
                for code in owned_error_codes.values():
                    record = {**adapter_record, "retainedDriverErrorCategory": "fixture-error",
                              "retainedDriverErrorCode": code}
                    self.assertEqual(controller.adapter_failure(adapter_bytes(record)), record)
                for category in controller.ADAPTER_FAILURE_DRIVER_CODES:
                    if category != "fixture-error":
                        self.assertIsNone(controller.adapter_failure(adapter_bytes({**adapter_record,
                            "retainedDriverErrorCategory": category, "retainedDriverErrorCode": "owned-record-identity"})))
                for code in ("owned-record-identity-PRIVATE_MESSAGE", "owned-unmapped"):
                    self.assertIsNone(controller.adapter_failure(adapter_bytes({**adapter_record,
                        "retainedDriverErrorCategory": "fixture-error", "retainedDriverErrorCode": code})))
                # The three split guards and historical compound guard remain
                # exact fixture-error codes, not prefix matches or native causes.
                for code in (*adapter_entry_error_codes.values(), "adapter-entry-unlisted",
                             "adapter-entry-window-PRIVATE_MESSAGE"):
                    for category in controller.ADAPTER_FAILURE_DRIVER_CODES:
                        record = {**adapter_record, "resultKind": "setup-fixture-fault",
                                  "retainedDriverErrorCategory": category, "retainedDriverErrorCode": code}
                        self.assertEqual(controller.adapter_failure(adapter_bytes(record)),
                                         record if category == "fixture-error" and code in entry_codes else None)
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
                # The finite last-entered location is diagnostic, not a READY
                # receipt or a consistency gate for independently sampled facts.
                for stage in (*adapter_readiness_stages, "missing", "invalid"):
                    record = {**adapter_record, "readinessStage": stage}
                    self.assertEqual(controller.adapter_failure(adapter_bytes(record)), record)
                # Reuse the existing compact grammar rather than duplicating
                # its exhaustive alphabet/primary controls below. Missing and
                # malformed original operands remain finite, not fabricated clean.
                for sentinel, code in (("missing", "m"), ("invalid", "x")):
                    record = {**adapter_record, "captureDetail": [sentinel, code * 24, code * 9,
                              code * 4, code * 3, [sentinel, sentinel]], "readinessStage": sentinel}
                    self.assertEqual(controller.adapter_failure(adapter_bytes(record)), record)

                # Maximize every independent finite field (and the dependent
                # mode/kind and retained-error pairs). The schema3 additions
                # must fit the existing complete-line 4096-byte cap.
                longest_mode = max(adapter_contracts, key=lambda mode: len(mode) + len(adapter_contracts[mode][1]))
                error_category, error_code = max(
                    ((category, code) for category, codes in controller.ADAPTER_FAILURE_DRIVER_CODES.items() for code in codes),
                    key=lambda pair: len(pair[0]) + len(pair[1]))
                adapter_maximum_primary = max(
                    ([category, code] for category, codes in controller.OWNERSHIP_CAPTURE_PRIMARY_ERROR_KINDS.items()
                     for code in codes), key=lambda pair: len(json.dumps(pair, separators=(",", ":"))))
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
                    "slowChecks": dict.fromkeys(adapter_slow_checks, "missing"),
                    "captureDetail": [max(controller.ADAPTER_FAILURE_DRIVER_CODES, key=len), "m" * 24,
                                      "maa" + "m" * 6, "m" * 4, "m" * 3, adapter_maximum_primary],
                    "readinessStage": max((*adapter_readiness_stages, "missing", "invalid"), key=len)}
                maximum_marker = adapter_bytes(maximum_record)
                self.assertGreater(len(maximum_marker), 2048)
                self.assertLessEqual(len(maximum_marker), 4096)
                self.assertEqual(controller.adapter_failure(maximum_marker), maximum_record)
                for code in adapter_entry_error_codes.values():
                    record = {**maximum_record, "retainedDriverErrorCategory": "fixture-error",
                              "retainedDriverErrorCode": code}
                    self.assertLessEqual(len(adapter_bytes(record)), len(maximum_marker))
                    self.assertEqual(controller.adapter_failure(adapter_bytes(record)), record)
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
                    *({**adapter_record, "schema": value} for value in (True, 1, 2, 3.0, "3", 4)),
                    # Original schema2 records stay historical: no invented
                    # new operands or compatibility promotion in this parser.
                    {key: (2 if key == "schema" else value) for key, value in adapter_record.items()
                     if key not in ("captureDetail", "readinessStage")},
                    *({key: value for key, value in adapter_record.items() if key != field}
                      for field in ("captureDetail", "readinessStage")),
                    *({**adapter_record, "readinessStage": value}
                      for value in (None, False, 0, [], {}, "", "validator_live", "PRIVATE_STAGE", "ready-return\n")),
                    *({**adapter_record, "captureDetail": value} for value in (
                        None, "missing", {}, [], adapter_capture_detail[:-1], adapter_capture_detail + ["PRIVATE_VALUE"],
                        ["PRIVATE_CLASS", *adapter_capture_detail[1:]],
                        [*adapter_capture_detail[:3], "01m", *adapter_capture_detail[4:]],
                        [*adapter_capture_detail[:4], "m0a", adapter_capture_detail[5]],
                        [*adapter_capture_detail[:5], ["native-lifecycle-error", "waitability"]],
                    )),
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
                    adapter_marker * 2, adapter_marker.replace(b'"schema":3', b'"schema":3,"schema":3'),
                    adapter_marker.replace(b'"ready":true', b'"ready":true,"ready":true'),
                    adapter_marker.replace(b'"custodian":"exit2"', b'"custodian":"exit2","custodian":"exit2"'),
                    adapter_marker.replace(b'"delayFailed":"missing"', b'"delayFailed":"missing","delayFailed":"missing"'),
                    adapter_marker.replace(b'"captureDetail":', b'"captureDetail":[],"captureDetail":'),
                    adapter_marker.replace(b'"readinessStage":', b'"readinessStage":"missing","readinessStage":'),
                    adapter_marker.replace(b'"schema":3', b'"schema": 3'), adapter_marker[:-1], oversized,
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

            # Plain source constants bind this parser to the real Ruby wire.
            # These fixed bounded DATA reads do not load Ruby or a native module.
            def ruby_text(relative):
                with (ROOT / relative).open("rb") as source:
                    raw = source.read(1_048_577)
                self.assertLessEqual(len(raw), 1_048_576)
                return raw.decode("utf-8", "strict")

            def ruby_words(text, name):
                matches = controller.re.findall(r"\b" + name + r" = %w\[([A-Za-z0-9_\-\s]*)\]\s*\.freeze", text)
                self.assertEqual(len(matches), 1, name)
                return tuple(matches[0].split())

            ownership_source = ruby_text("tests/workflow/upload_process_ownership.rb")
            self.assertIn('OWNERSHIP_FAILURE_PREFIX = "MRK_OWNERSHIP_FAILURE="', ownership_source)
            self.assertEqual(controller.OWNERSHIP_FAILURE_PREFIX, "MRK_OWNERSHIP_FAILURE=")
            for suffix in ("FIELDS", "ROW_FIELDS", "PHASES", "OWNER_PHASES",
                           "CHECKS", "COMMAND_CHECKS", "FAILED_CHECKS"):
                name = "OWNERSHIP_FAILURE_" + suffix
                self.assertEqual(ruby_words(ownership_source, name), getattr(controller, name))
            for suffix in ("CLEANUP_FIELDS", "DIRECTORY_STATES", "STATUS_FIELDS", "RESULT_SOURCES", "CHECKS",
                           "NATIVE_PROOF_FIELDS", "OWNER_FINALITIES", "ERROR_STAGES", "ERROR_FIELDS", "RESULT_FIELDS",
                           "EXTENDED_RESULT_FIELDS"):
                name = "OWNERSHIP_RUN_" + suffix
                self.assertEqual(ruby_words(ownership_source, name), getattr(controller, name))
            for suffix in ("DETAIL_FIELDS", "PROTOCOL_FIELDS"):
                name = "OWNERSHIP_CAPTURE_" + suffix
                self.assertEqual(ruby_words(ownership_source, name), getattr(controller, name))
            capture_detail_fields = ("adapterErrorCategory", "resultChecks", "timingChecks", "settlementChecks", "protocolContext", "primary")
            self.assertEqual(controller.OWNERSHIP_CAPTURE_DETAIL_FIELDS, capture_detail_fields)
            self.assertEqual(controller.OWNERSHIP_CAPTURE_PROTOCOL_FIELDS, ("hello", "reserved", "ready"))
            self.assertEqual((len(adapter_result_checks), len(adapter_timing_checks),
                              len(controller.NATIVE_SETUP_SETTLEMENT_CHECKS)), (24, 9, 4))
            self.assertEqual(ruby_words(ownership_source, "SETTLEMENT_CHECKS"), controller.NATIVE_SETUP_SETTLEMENT_CHECKS)
            self.assertEqual(ruby_words(ownership_source, "OWNERSHIP_FAILURE_HELPERS"), ("capture", "run"))
            self.assertEqual(ruby_words(ownership_source, "OWNERSHIP_FAILURE_PLATFORMS"), ("ios", "android"))

            def ruby_literal_pairs(body, name, *, words=False):
                pattern = (r'"([^"\r\n]+)" => %w\[([A-Za-z0-9_\-\s]*)\]' if words else
                           r'"([^"\r\n]+)" => "([^"\r\n]+)"')
                pairs = controller.re.findall(pattern, body)
                self.assertEqual(len(pairs), len(dict(pairs)), name)
                self.assertEqual("".join(controller.re.sub(pattern + r"\s*,?", "", body).split()), "", name)
                return {key: tuple(value.split()) if words else value for key, value in pairs}

            def ruby_literal_table(text, name, *, words=False):
                bodies = controller.re.findall(r"(?ms)^\s*" + name
                    + r" = \{(.*?)^\s*\}\.(?:transform_values\(&:freeze\)\.)?freeze", text)
                self.assertEqual(len(bodies), 1, name)
                return ruby_literal_pairs(bodies[0], name, words=words)

            def ownership_literal_table(name, *, words=False):
                return ruby_literal_table(ownership_source, name, words=words)

            # Read finite declarations as DATA, never load Ruby/Fiddle/native
            # helpers. Child-only bootstrap errors become exit125 + a different
            # finite report; they are not returned adapter error literals.
            fixture_source = ruby_text("tests/workflow/upload_process_fixture.rb")
            self.assertEqual(ruby_words(fixture_source, "ADAPTER_FAILURE_FIELDS"), adapter_fields)
            self.assertEqual(ruby_words(fixture_source, "ADAPTER_READINESS_STAGES"), adapter_readiness_stages)
            self.assertEqual(ruby_literal_table(fixture_source, "ADAPTER_FAILURE_OWNED_CODES"), owned_error_codes)
            driver_literal_bodies = controller.re.findall(
                r"(?ms)^  ADAPTER_FAILURE_CODES = begin\n    literals = \{\n(.*?)^    \}\n"
                r"    literals\.merge!\(ADAPTER_FAILURE_OWNED_CODES\)\n", fixture_source)
            self.assertEqual(len(driver_literal_bodies), 1)
            driver_literals = ruby_literal_pairs(driver_literal_bodies[0], "ADAPTER_FAILURE_CODES")
            self.assertEqual({message: code for message, code in driver_literals.items()
                              if code.startswith("adapter-entry-")}, adapter_entry_error_codes)
            self.assertEqual(controller.ADAPTER_FAILURE_DRIVER_CODES["fixture-error"],
                             frozenset({"missing", "invalid", "other", *owned_codes, *driver_literals.values()}))
            owned_bodies = controller.re.findall(
                r"(?ms)^  class OwnedChild\n(.*?)^    def self\.bootstrap\(directory\)\n", ownership_source)
            self.assertEqual(len(owned_bodies), 1)
            owned_literals = controller.re.findall(
                r'Failure\.new\(\s*"process-ownership",\s*"([^"\\\r\n]+)"\s*\)', owned_bodies[0])
            self.assertEqual(set(owned_literals), set(owned_error_codes))

            self.assertEqual(ownership_literal_table("OWNERSHIP_FAILURE_CASES", words=True),
                             controller.OWNERSHIP_FAILURE_CASES)
            self.assertEqual(tuple(controller.OWNERSHIP_FAILURE_CASES), ("async", "signals", "policies"))
            self.assertEqual(tuple(map(len, controller.OWNERSHIP_FAILURE_CASES.values())), (4, 16, 10))
            self.assertEqual(ownership_literal_table("OWNERSHIP_FAILURE_CALLBACKS"), controller.OWNERSHIP_FAILURE_CALLBACKS)
            self.assertEqual(controller.OWNERSHIP_FAILURE_CALLBACKS, {family:
                f"test_process_ownership_{family}_through_both_real_fixture_callers"
                for family in ("async", "signals", "policies")})
            run_fields = ("directoryState", "driverStatus", "resultSource", "checks", "nativeProof", "cleanupErrors", "driverResult")
            run_checks = (
                "driverComplete", "dispatchRequested", "recoveryEntered", "recoveryFilesComplete", "dispatchMatched",
                "ownerValidated", "nativeFinal", "knownDead", "deathAttempted", "deathCompleted", "directoryIdentityMatched",
                "layoutAccepted", "removalAttempted", "removalCompleted",
            )
            run_proof_fields = ("versionOne", "ownerFinality", "custodianMatches", "keeperMatches", "validatorMatches",
                                "groupMatches", "noProducersMatch")
            run_result_fields = ("resultKind", "retainedDriverErrorCategory", "retainedDriverErrorCode", "nativeChecks", "nativeOutcomes")
            run_extended_result_fields = (*run_result_fields, "captureDetail")
            run_stages = ("child-stop", "transcript-out-close", "transcript-err-close", "held-writer-close",
                          "native-recovery", "death-observation", "directory-removal", "missing")
            run_conditions = {
                "recovery-dispatch-mismatch": "fixture-cleanup",
                "owner-shape": "fixture-result", "owner-unbound": "fixture-result",
                "owner-duplicate": "fixture-result", "owner-graph": "fixture-result",
                "driver-identity-changed": "fixture-cleanup", "directory-not-canonical": "fixture-cleanup",
                "directory-not-private": "fixture-cleanup", "enumeration-before-identity": "fixture-cleanup",
                "enumeration-open-identity": "fixture-cleanup", "enumeration-listing": "fixture-cleanup",
                "enumeration-after-identity": "fixture-cleanup", "enumeration-io": "fixture-cleanup",
                "observer-scratch": "fixture-cleanup", "observer-output": "process-observation",
                "observer-metadata": "process-observation", "death-cutoff": "fixture-cleanup",
            }
            self.assertEqual(controller.OWNERSHIP_RUN_CLEANUP_FIELDS, run_fields)
            self.assertEqual(controller.OWNERSHIP_RUN_DIRECTORY_STATES,
                             ("unattempted", "acquiring", "published", "canonical", "missing"))
            self.assertEqual(controller.OWNERSHIP_RUN_STATUS_FIELDS, ("kind", "code"))
            self.assertEqual(controller.OWNERSHIP_RUN_RESULT_SOURCES, ("ordinary", "recovered", "missing"))
            self.assertEqual(controller.OWNERSHIP_RUN_CHECKS, run_checks)
            self.assertEqual(controller.OWNERSHIP_RUN_NATIVE_PROOF_FIELDS, run_proof_fields)
            self.assertEqual(controller.OWNERSHIP_RUN_OWNER_FINALITIES,
                             ("active", "finalized", "no-producers", "unknown", "missing", "invalid"))
            self.assertEqual(controller.OWNERSHIP_RUN_ERROR_STAGES, run_stages)
            self.assertEqual(controller.OWNERSHIP_RUN_ERROR_FIELDS, ("stage", "errorCategory", "errorKind", "condition"))
            self.assertEqual(controller.OWNERSHIP_RUN_RESULT_FIELDS, run_result_fields)
            self.assertEqual(controller.OWNERSHIP_RUN_EXTENDED_RESULT_FIELDS, run_extended_result_fields)
            self.assertEqual(ownership_literal_table("OWNERSHIP_RUN_CONDITIONS"), run_conditions)
            self.assertEqual(controller.OWNERSHIP_RUN_CONDITIONS, run_conditions)
            labels = ownership_literal_table("OWNERSHIP_FAILURE_LABEL_CODES")
            self.assertEqual(tuple(labels.values()), controller.OWNERSHIP_FAILURE_FAILED_CHECKS[:-1])
            self.assertEqual(len(labels), 23)
            self.assertEqual(controller.OWNERSHIP_FAILURE_FAILED_CHECKS[-1], "other-failed-check")
            kind_body = controller.re.findall(
                r"(?ms)^\s*OWNERSHIP_FAILURE_ERROR_KINDS = \{(.*?)^\s*\}\.transform_values\(&:freeze\)\.freeze",
                ownership_source)
            self.assertEqual(len(kind_body), 1)
            kind_rows = controller.re.findall(r'"([a-z-]+)" => %w\[([A-Za-z0-9_\-\s]*)\]', kind_body[0])
            self.assertEqual(len(kind_rows), len(controller.OWNERSHIP_FAILURE_ERROR_KINDS))
            self.assertEqual({category: frozenset(kinds.split()) for category, kinds in kind_rows},
                             controller.OWNERSHIP_FAILURE_ERROR_KINDS)
            primary_extras = {"contract-error": ("none",), "missing": ("missing",), "invalid": ("invalid",)}
            self.assertEqual(ownership_literal_table("OWNERSHIP_CAPTURE_PRIMARY_EXTRA_KINDS", words=True), primary_extras)
            self.assertEqual(controller.OWNERSHIP_CAPTURE_PRIMARY_EXTRA_KINDS,
                             {category: frozenset(codes) for category, codes in primary_extras.items()})
            self.assertEqual(controller.OWNERSHIP_CAPTURE_PRIMARY_ERROR_KINDS,
                             {**controller.OWNERSHIP_FAILURE_ERROR_KINDS, **controller.OWNERSHIP_CAPTURE_PRIMARY_EXTRA_KINDS})
            self.assertFalse(set(primary_extras) & controller.OWNERSHIP_FAILURE_ERROR_KINDS.keys())
            for relative, name, category in (
                ("fastlane/native_upload_process.rb", "REASONS", "native-lifecycle-error"),
                ("fastlane/native_process_spawn.rb", "CODES", "native-spawn-error"),
            ):
                self.assertEqual(set(ruby_words(ruby_text(relative), name)) | {"other"},
                                 controller.OWNERSHIP_FAILURE_ERROR_KINDS[category])

            run_result = {name: adapter_record[name] for name in run_result_fields}
            run_result.update(resultKind="pass", retainedDriverErrorCategory="none", retainedDriverErrorCode="none")
            capture_detail = ["contract-error", "01mx" * 6, "1bamx01mx", "01mx", "m01", ["native-lifecycle-error", "deadline"]]
            run_result["captureDetail"] = capture_detail
            run_cleanup = {
                "directoryState": "canonical", "driverStatus": {"kind": "exit", "code": 0}, "resultSource": "recovered",
                "checks": dict(zip(run_checks, (True, True, True, True, True, True, False, False,
                                                False, False, "missing", "missing", False, False))),
                "nativeProof": dict(zip(run_proof_fields, (True, "finalized", True, False, "missing", True, False))),
                # Occurrences, not exception identities: an identical retained
                # error may escape two original cleanup calls without deduping.
                "cleanupErrors": [["native-recovery", "fixture-error", "fixture-result", "owner-shape"],
                                  ["native-recovery", "fixture-error", "fixture-result", "owner-shape"]],
                "driverResult": run_result,
            }
            ownership_row = {
                "ownerPhase": "unknown", "firstErrorCategory": "interrupt", "firstErrorKind": "none",
                "operationErrorCategory": "interrupt", "operationErrorKind": "none",
                "failedChecks": ["numeric-route-veto", "command-not-finalized"],
                "checks": {name: (True, False, "missing")[index % 3]
                           for index, name in enumerate(controller.OWNERSHIP_FAILURE_CHECKS)},
                "commandChecks": {name: ("missing", True, False)[index % 3]
                                  for index, name in enumerate(controller.OWNERSHIP_FAILURE_COMMAND_CHECKS)},
                "runCleanup": "missing",
            }
            ownership_record = {
                "schema": 4, "platform": "ios", "family": "async", "helper": "capture", "case": "async-spawn",
                "phase": "row-rejection", "errorCategory": "fixture-error", "errorKind": "ownership-probe",
                "row": ownership_row,
            }

            def ownership_bytes(record):
                return ("MRK_OWNERSHIP_FAILURE="
                        + json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")

            # Independent finite model of the original one() branches. The
            # cancellation cases cannot lend their check labels to policies.
            policy_code_cases = {
                "normal-command-not-finalized": ("normal", "ignored-INT", "ignored-TERM"),
                "policy-not-fail-closed": ("custom-INT", "custom-TERM", "custom-pending-INT", "partial-install",
                                          "changed-handler", "finalize-report", "finalize-drain"),
                "policy-native-creation": ("custom-INT", "custom-TERM", "custom-pending-INT", "partial-install"),
                "custom-pending-lost": ("custom-pending-INT",),
                "partial-install-not-exercised": ("partial-install",),
                "finalization-cleanup": ("finalize-report", "finalize-drain"),
                "finalization-outer-lifetime": ("finalize-report", "finalize-drain"),
            }
            cancellation_codes = {"cancellation-not-propagated", "injection-boundary-missing", "wrong-signal",
                                  "command-not-finalized"}

            def ownership_case_codes(family, helper, case):
                allowed = {"numeric-route-veto", "handlers-not-restored", "registry-active", "hooks-not-restored",
                    "injector-cleanup", "primary-not-preserved", "injectors-not-joined", "injector-custody",
                    "pending-interrupt", "fixture-retained", "other-failed-check"}
                if family in {"async", "signals"}:
                    allowed.update(cancellation_codes)
                    if case in {"async-spawn", "INT-spawn", "TERM-spawn"}:
                        allowed.add("pre-go-barrier-missing")
                    if (family, helper, case) == ("async", "run", "repeated"):
                        allowed.add("nested-cancellation-missing")
                else:
                    allowed.update(code for code, cases in policy_code_cases.items() if case in cases)
                return [code for code in controller.OWNERSHIP_FAILURE_FAILED_CHECKS if code in allowed]

            ownership_marker = ownership_bytes(ownership_record)
            ownership_target = "IosUploadValidationTest#" + controller.OWNERSHIP_FAILURE_CALLBACKS["async"]
            ownership_ids = tuple(sorted((*expected, ownership_target)))
            ownership_step = controller.Step("ruby-ios_upload_validation", parser="minitest", expected_tests=3,
                                             native_partition="healthy")
            ownership_failed = ownership_target + " = PRIVATE_MESSAGE\n0.01 s = E\n"
            ownership_footer = "\n3 runs, 5 assertions, 0 failures, 1 errors, 0 skips\n"
            ownership_stdout = clean + ownership_failed + ownership_footer
            with patch.object(controller, "ruby_capture_ids", return_value=ownership_ids), \
                    patch.object(controller.time, "monotonic", return_value=999.0):
                with patch.object(controller, "_fixture_failure_record", wraps=controller._fixture_failure_record) as strict:
                    self.assertEqual(controller.ownership_failure(ownership_marker, deadline=1000.0), ownership_record)
                strict.assert_called_once_with(ownership_marker, "MRK_OWNERSHIP_FAILURE=", 4096,
                                               deadline=1000.0, canonical_fields=controller.OWNERSHIP_FAILURE_FIELDS)
                run_record = {**ownership_record, "helper": "run", "case": "async-reap", "row": {
                    **ownership_row, "ownerPhase": "reaped", "failedChecks": ["fixture-retained"], "runCleanup": run_cleanup}}
                run_marker = ownership_bytes(run_record)
                # Both envelopes reuse detail outside the common five-field
                # parser; ownership schema4 does not acquire readinessStage.
                self.assertTrue(controller._adapter_result_projection_valid(
                    {name: run_result[name] for name in run_result_fields}))
                self.assertFalse(controller._adapter_result_projection_valid(run_result))
                self.assertEqual(controller.adapter_failure(adapter_bytes(adapter_record)), adapter_record)
                self.assertFalse(controller._ownership_run_driver_result_valid(
                    {name: run_result[name] for name in run_result_fields}))
                self.assertFalse(controller._ownership_capture_detail_valid(tuple(capture_detail)))
                # Ownership schema4 uses the same closed retained-error pair,
                # without adding detail or admitting it as a native error code.
                for category in ("fixture-error", "native-lifecycle-error"):
                    owned_record = {**run_record, "row": {**run_record["row"], "runCleanup": {
                        **run_cleanup, "driverResult": {**run_result, "retainedDriverErrorCategory": category,
                            "retainedDriverErrorCode": "owned-publish-return"}}}}
                    self.assertEqual(controller.ownership_failure(ownership_bytes(owned_record)),
                                     owned_record if category == "fixture-error" else None)
                for code in (*adapter_entry_error_codes.values(), "adapter-entry-unlisted",
                             "adapter-entry-window-PRIVATE_MESSAGE"):
                    for category in ("fixture-error", "native-lifecycle-error"):
                        entry_record = {**run_record, "row": {**run_record["row"], "runCleanup": {
                            **run_cleanup, "driverResult": {**run_result, "resultKind": "setup-fixture-fault",
                                "retainedDriverErrorCategory": category, "retainedDriverErrorCode": code}}}}
                        self.assertEqual(controller.ownership_failure(ownership_bytes(entry_record)),
                                         entry_record if category == "fixture-error" and code in entry_codes else None)

                def record_with_detail(detail):
                    return {**run_record, "row": {**run_record["row"], "runCleanup": {
                        **run_cleanup, "driverResult": {**run_result, "captureDetail": detail}}}}

                # Rotate/broadcast finite values, not a Cartesian matrix. Typed
                # protocol presence can disagree with original ready/finality;
                # the diagnostic preserves both, never repairs the failed case.
                for index, cutoff in enumerate("sbamx"):
                    code = "01mx"[index % 4]
                    detail = [capture_detail[0], code * 24, code + cutoff * 2 + code * 6,
                              code * 4, code * 3, capture_detail[5]]
                    record = record_with_detail(detail)
                    self.assertEqual(controller.ownership_failure(ownership_bytes(record)), record)
                for category in controller.ADAPTER_FAILURE_DRIVER_CODES:
                    record = record_with_detail([category, *capture_detail[1:]])
                    self.assertEqual(controller.ownership_failure(ownership_bytes(record)), record)
                for category, codes in controller.OWNERSHIP_CAPTURE_PRIMARY_ERROR_KINDS.items():
                    for code in codes:
                        record = record_with_detail([*capture_detail[:5], [category, code]])
                        self.assertEqual(controller.ownership_failure(ownership_bytes(record)), record)
                        if category in primary_extras:
                            # Additional capture-only sentinels/categories cannot
                            # broaden the independent outer ownership error grammar.
                            self.assertIsNone(controller.ownership_failure(ownership_bytes({**ownership_record,
                                "phase": "restoration", "errorCategory": category, "errorKind": code, "row": "missing"})))
                # Inner pass/status0 is not adapter_failure eligibility. The
                # original outer failed ownership callback remains mandatory.
                with patch.object(controller, "adapter_failure", side_effect=AssertionError("borrowed adapter rejection gate")):
                    self.assertEqual(controller.ownership_failure(run_marker, deadline=1000.0), run_record)
                run_detail = controller.failure_details(capture(ownership_stdout, stderr=run_marker, ok=False, returncode=1),
                                                        ownership_step, paths, deadline=1000.0)
                self.assertEqual(run_detail["ownership_failure"], run_record)
                self.assertEqual(len(run_detail["ownership_failure"]["row"]["runCleanup"]["cleanupErrors"]), 2)
                self.assertNotIn("adapter_failure", run_detail)
                run_success = ownership_stdout.replace("0.01 s = E", "0.01 s = .").replace("1 errors", "0 errors")
                self.assertNotIn("ownership_failure", controller.failure_details(
                    capture(run_success, stderr=run_marker), ownership_step, paths))
                self.assertTrue(controller.parse_capture(ownership_step, capture(run_success, stderr=run_marker),
                                                         paths, "linux", None).ok)
                for status in ({"kind": "missing", "code": "missing"}, {"kind": "exit", "code": 0},
                               {"kind": "exit", "code": 255}, {"kind": "signal", "code": 1}, {"kind": "signal", "code": 255}):
                    record = {**run_record, "row": {**run_record["row"], "runCleanup": {**run_cleanup, "driverStatus": status}}}
                    self.assertEqual(controller.ownership_failure(ownership_bytes(record)), record)
                # Broadcast finite values instead of a redundant Cartesian
                # matrix; failed-snapshot contradictions remain observations.
                for index, owner in enumerate(controller.OWNERSHIP_RUN_OWNER_FINALITIES):
                    value = (True, False, "missing")[index % 3]
                    projection = {**run_cleanup,
                        "directoryState": controller.OWNERSHIP_RUN_DIRECTORY_STATES[index % 5],
                        "resultSource": controller.OWNERSHIP_RUN_RESULT_SOURCES[index % 3],
                        "checks": dict.fromkeys(run_checks, value),
                        "nativeProof": {name: owner if name == "ownerFinality" else value for name in run_proof_fields}}
                    record = {**run_record, "row": {**run_record["row"], "runCleanup": projection}}
                    self.assertEqual(controller.ownership_failure(ownership_bytes(record)), record)
                for condition, kind in run_conditions.items():
                    projection = {**run_cleanup, "cleanupErrors": [["native-recovery", "fixture-error", kind, condition]]}
                    record = {**run_record, "row": {**run_record["row"], "runCleanup": projection}}
                    self.assertEqual(controller.ownership_failure(ownership_bytes(record)), record)
                for errors in ([], [[stage, "native-spawn-error", "unknown", "other"] for stage in run_stages[:7]],
                               [["missing", "os-error", "echild", "missing"]]):
                    record = {**run_record, "row": {**run_record["row"], "runCleanup": {**run_cleanup, "cleanupErrors": errors}}}
                    self.assertEqual(controller.ownership_failure(ownership_bytes(record)), record)
                for result in ("missing", "invalid", *({**run_result, "nativeChecks": dict.fromkeys(adapter_native_checks, value)}
                                                     for value in (True, False, "missing", "invalid"))):
                    record = {**run_record, "row": {**run_record["row"], "runCleanup": {**run_cleanup, "driverResult": result}}}
                    self.assertEqual(controller.ownership_failure(ownership_bytes(record)), record)
                # Every source-defined helper/case routes only to its actual
                # platform/family callback, never a neighboring healthy family.
                for platform, (gate, class_name) in adapter_platforms.items():
                    for family, cases in controller.OWNERSHIP_FAILURE_CASES.items():
                        target = class_name + "#" + controller.OWNERSHIP_FAILURE_CALLBACKS[family]
                        for helper in ("capture", "run"):
                            for case in cases:
                                record = {**ownership_record, "platform": platform, "family": family,
                                    "helper": helper, "case": case,
                                    "row": {**ownership_row, "failedChecks": ownership_case_codes(family, helper, case),
                                            "runCleanup": run_cleanup if helper == "run" else "missing"}}
                                transcript = clean + target + " = 0.01 s = F\n" + failed_footer
                                with patch.object(controller, "ruby_capture_ids", return_value=tuple(sorted((*expected, target)))):
                                    detail = controller.failure_details(capture(transcript, stderr=ownership_bytes(record),
                                        ok=False, returncode=1), dataclasses.replace(ownership_step, id=gate), paths,
                                        deadline=1000.0)
                                self.assertEqual(detail["ownership_failure"], record)
                                self.assertEqual(detail["returncode"], 1)
                                self.assertNotIn("PRIVATE_", json.dumps(detail))
                for family, cases in controller.OWNERSHIP_FAILURE_CASES.items():
                    for helper in ("capture", "run"):
                        for case in cases:
                            record = {**ownership_record, "family": family, "helper": helper, "case": case}
                            allowed = ownership_case_codes(family, helper, case)
                            for code in controller.OWNERSHIP_FAILURE_FAILED_CHECKS:
                                if code not in allowed:
                                    self.assertIsNone(controller.ownership_failure(ownership_bytes({**record,
                                        "row": {**ownership_row, "failedChecks": [code]}})), (family, helper, case, code))
                            # A literal adverse sentinel is valid, but it never
                            # claims which check ran or creates a success result.
                            sentinel = {**record, "row": {**ownership_row, "failedChecks": ["other-failed-check"]}}
                            self.assertEqual(controller.ownership_failure(ownership_bytes(sentinel)), sentinel)
                    callbacks = tuple("IosUploadValidationTest#" + name for name in controller.OWNERSHIP_FAILURE_CALLBACKS.values())
                    target = "IosUploadValidationTest#" + controller.OWNERSHIP_FAILURE_CALLBACKS[family]
                    for other_family, other_cases in controller.OWNERSHIP_FAILURE_CASES.items():
                        if other_family == family:
                            continue
                        record = {**ownership_record, "family": other_family, "case": other_cases[0],
                                  "row": {**ownership_row, "failedChecks": ["other-failed-check"]}}
                        with patch.object(controller, "ruby_capture_ids", return_value=tuple(sorted((*expected, *callbacks)))):
                            self.assertNotIn("ownership_failure", controller.failure_details(capture(
                                clean + target + " = 0.01 s = E\n" + ownership_footer,
                                stderr=ownership_bytes(record), ok=False, returncode=1), ownership_step, paths))
                for phase in controller.OWNERSHIP_FAILURE_PHASES:
                    record = {**ownership_record, "phase": phase, "row": "missing"}
                    self.assertEqual(controller.ownership_failure(ownership_bytes(record)), record)
                for category, kind in (("native-lifecycle-error", "parent_lost"), ("native-spawn-error", "waitability"),
                                       ("os-error", "echild"), ("signal", "none"), ("other", "none")):
                    fallback = {**ownership_record, "phase": "restoration", "errorCategory": category,
                                "errorKind": kind, "row": "missing"}
                    self.assertEqual(controller.ownership_failure(ownership_bytes(fallback)), fallback)
                    record = {**ownership_record, "row": {**ownership_row,
                        "firstErrorCategory": "none", "firstErrorKind": "none",
                        "operationErrorCategory": category, "operationErrorKind": kind}}
                    self.assertEqual(controller.ownership_failure(ownership_bytes(record)), record)
                    # A different actually escaping exception cannot borrow
                    # the completed row belonging to the ownership-probe rejection.
                    self.assertIsNone(controller.ownership_failure(ownership_bytes(
                        {**ownership_record, "errorCategory": category, "errorKind": kind})))
                for value in (True, False, "missing"):
                    record = {**ownership_record, "row": {**ownership_row, "ownerPhase": "missing",
                        "checks": dict.fromkeys(controller.OWNERSHIP_FAILURE_CHECKS, value),
                        "commandChecks": dict.fromkeys(controller.OWNERSHIP_FAILURE_COMMAND_CHECKS, value)}}
                    # Even contradictory projection facts do not recompute or
                    # erase the actual original nonempty failed-check list.
                    self.assertEqual(controller.ownership_failure(ownership_bytes(record)), record)

                failed_capture = capture(ownership_stdout, stderr=ownership_marker, ok=False, returncode=1)
                with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                    controller.parse_capture(ownership_step, failed_capture, paths, "linux", None)
                zero_capture = capture(ownership_stdout, stderr=ownership_marker)
                self.assertEqual(controller.failure_details(zero_capture, ownership_step, paths)["ownership_failure"],
                                 ownership_record)
                with self.assertRaisesRegex(controller.VerificationError, "MINITEST_RESULT_REJECTED"):
                    controller.parse_capture(ownership_step, zero_capture, paths, "macos", None)
                success_stdout = ownership_stdout.replace("0.01 s = E", "0.01 s = .").replace("1 errors", "0 errors")
                successful = capture(success_stdout, stderr=ownership_marker)
                self.assertNotIn("ownership_failure", controller.failure_details(successful, ownership_step, paths))
                self.assertTrue(controller.parse_capture(ownership_step, successful, paths, "linux", None).ok)
                # A marker neither creates a missing callback nor heals its
                # duplicate/ambiguous/skipped terminal or wrong healthy scope.
                for transcript in (
                    clean + ownership_footer, clean + ownership_target + ":\n" + ownership_footer,
                    clean + ownership_target + " = unfinished\n" + ownership_footer,
                    ownership_stdout.replace("0.01 s = E", "0.01 s = S"),
                    ownership_stdout.replace("0.01 s = E", "0.01 s = .\n0.01 s = E"),
                    clean + ownership_failed * 2 + ownership_footer,
                    clean + ownership_footer + ownership_failed,
                ):
                    self.assertNotIn("ownership_failure", controller.failure_details(
                        capture(transcript, stderr=ownership_marker, ok=False, returncode=1), ownership_step, paths))
                self.assertNotIn("ownership_failure", controller.failure_details(capture(
                    ownership_stdout + ownership_marker.decode("ascii"), ok=False, returncode=1), ownership_step, paths))
                self.assertNotIn("ownership_failure", controller.failure_details(capture(ownership_stdout,
                    stderr=ownership_bytes({**ownership_record, "platform": "android"}), ok=False, returncode=1),
                    ownership_step, paths))
                with patch.object(controller, "ruby_capture_ids", return_value=expected):
                    self.assertNotIn("ownership_failure", controller.failure_details(failed_capture, ownership_step, paths))
                for wrong_step in (
                    dataclasses.replace(ownership_step, id="ruby-native-owner"),
                    dataclasses.replace(ownership_step, id="ruby-native-capture"),
                    dataclasses.replace(ownership_step, id="ruby-android_upload_validation"),
                    dataclasses.replace(ownership_step, native_partition="all"),
                    dataclasses.replace(ownership_step, native_partition="ownership-unknown-capture-reap"),
                    dataclasses.replace(ownership_step, parser="exit"),
                ):
                    self.assertNotIn("ownership_failure", controller.failure_details(failed_capture, wrong_step, paths))
                with patch.object(controller, "ruby_capture_ids", return_value=tuple(sorted((*many_ids, ownership_target)))):
                    detail = controller.failure_details(capture(many_stdout + ownership_failed, stderr=ownership_marker,
                        ok=False, returncode=1), ownership_step, paths)
                    self.assertGreater(detail["minitest_structure"]["start_records_omitted"], 0)
                    self.assertEqual(detail["ownership_failure"], ownership_record)
                    self.assertNotIn("ownership_failure", controller.failure_details(capture(
                        ownership_failed + many_stdout + ownership_failed, stderr=ownership_marker,
                        ok=False, returncode=1), ownership_step, paths))

                invalid_ownership = [
                    {key: value for key, value in ownership_record.items() if key != "row"},
                    {**ownership_record, "private": "PRIVATE_VALUE"},
                    {key: ownership_record[key] for key in reversed(ownership_record)},
                    *({**ownership_record, "schema": value} for value in (True, 4.0, "4", 3, 2, 1)),
                    *({**ownership_record, key: value} for key, value in (
                        ("platform", "PRIVATE_PLATFORM"), ("family", "signals"), ("helper", "PRIVATE_HELPER"),
                        ("family", "unknown"), ("family", "setup"), ("family", "observation"), ("family", False),
                        ("case", "unknown-reap"), ("phase", "PRIVATE_PHASE"), ("phase", "restoration"),
                        ("errorCategory", None), ("errorKind", "PRIVATE_KIND"), ("row", None), ("row", False),
                    )),
                    {**ownership_record, "errorCategory": "none", "errorKind": "none"},
                    {**ownership_record, "errorCategory": "native-spawn-error", "errorKind": "parent_lost"},
                    {**ownership_record, "errorCategory": "os-error", "errorKind": "none"},
                ]
                invalid_rows = [
                    {}, {key: value for key, value in ownership_row.items() if key != "ownerPhase"},
                    {**ownership_row, "private": "PRIVATE_ROW"}, {key: ownership_row[key] for key in reversed(ownership_row)},
                    {**ownership_row, "ownerPhase": "PRIVATE_PHASE"}, {**ownership_row, "ownerPhase": False},
                    {**ownership_row, "firstErrorCategory": "missing"}, {**ownership_row, "firstErrorKind": "PRIVATE_KIND"},
                    {**ownership_row, "operationErrorCategory": "os-error"},
                    *({**ownership_row, "failedChecks": value} for value in
                      ([], ["PRIVATE_CHECK"], [True], ["numeric-route-veto", "numeric-route-veto"],
                       list(reversed(ownership_row["failedChecks"])), ["nested-cancellation-missing"])),
                ]
                for group in ("checks", "commandChecks"):
                    original = ownership_row[group]
                    invalid_rows.extend({**ownership_row, group: value} for value in (
                        None, [], {key: value for key, value in original.items() if key != next(iter(original))},
                        {**original, "PRIVATE_CHECK": True}, {key: original[key] for key in reversed(original)},
                        *({**original, next(iter(original)): value} for value in (None, 0, 1.0, "invalid", "PRIVATE_VALUE")),
                    ))
                invalid_ownership.extend({**ownership_record, "row": row} for row in invalid_rows)
                invalid_ownership.append({**ownership_record, "case": "async-reap",
                    "row": {**ownership_row, "failedChecks": ["pre-go-barrier-missing"]}})
                invalid_run_cleanup = [None, False, "invalid", {},
                    *({key: value for key, value in run_cleanup.items() if key != field} for field in run_fields),
                    {**run_cleanup, "private": "PRIVATE_PATH"}, {key: run_cleanup[key] for key in reversed(run_cleanup)},
                    *({**run_cleanup, key: value} for key, value in (
                        ("directoryState", "PRIVATE_DIRECTORY"), ("directoryState", False),
                        ("resultSource", "PRIVATE_SOURCE"), ("resultSource", None),
                        ("cleanupErrors", None), ("cleanupErrors", {}),
                        ("cleanupErrors", run_cleanup["cleanupErrors"] * 4),
                        ("driverResult", None), ("driverResult", False), ("driverResult", "PRIVATE_RESULT"),
                        ("driverResult", adapter_record),
                    )),
                ]
                for status in (None, [], {}, {"code": 0, "kind": "exit"}, {"kind": "exit", "code": 0, "pid": 123},
                               {"kind": "missing", "code": 0}, {"kind": "exit", "code": "missing"},
                               {"kind": "signal", "code": 0}, {"kind": "signal", "code": -1},
                               *({"kind": "exit", "code": value} for value in (True, 0.0, None, -1, 256, "0")),
                               {"kind": False, "code": 0}, {"kind": "PRIVATE_STATUS", "code": 0}):
                    invalid_run_cleanup.append({**run_cleanup, "driverStatus": status})
                for group in ("checks", "nativeProof"):
                    original = run_cleanup[group]
                    invalid_run_cleanup.extend({**run_cleanup, group: value} for value in (
                        None, [], {key: value for key, value in original.items() if key != next(iter(original))},
                        {**original, "PRIVATE_FIELD": True}, {key: original[key] for key in reversed(original)},
                        *({**original, next(iter(original)): value} for value in (None, 0, 1.0, "invalid", "PRIVATE_VALUE")),
                    ))
                invalid_run_cleanup.extend({**run_cleanup, "nativeProof": {**run_cleanup["nativeProof"], "ownerFinality": value}}
                                           for value in (True, None, "other", "no_producers", "PRIVATE_FINALITY"))
                valid_error = ["native-recovery", "fixture-error", "fixture-result", "owner-shape"]
                invalid_errors = [None, False, {}, [], valid_error[:-1], valid_error + ["PRIVATE_MESSAGE"],
                    *([*valid_error[:index], value, *valid_error[index + 1:]] for index, value in (
                        (0, "PRIVATE_STAGE"), (0, False), (1, "PRIVATE_CATEGORY"), (1, None),
                        (2, "PRIVATE_KIND"), (2, False), (3, "PRIVATE_MESSAGE"), (3, None),
                    )),
                    ["missing", "none", "none", "other"], ["missing", "io-error", "none", "owner-shape"],
                    ["missing", "native-spawn-error", "parent_lost", "other"],
                    *(["native-recovery", "fixture-error",
                       "fixture-cleanup" if kind == "fixture-result" else "fixture-result", condition]
                      for condition, kind in run_conditions.items()),
                ]
                invalid_run_cleanup.extend({**run_cleanup, "cleanupErrors": [error]} for error in invalid_errors)
                invalid_results = [
                    *({key: value for key, value in run_result.items() if key != field} for field in run_extended_result_fields),
                    {**run_result, "private": "PRIVATE_RECORD"}, {key: run_result[key] for key in reversed(run_result)},
                    *({**run_result, key: value} for key, value in (
                        ("resultKind", "PRIVATE_KIND"), ("resultKind", False),
                        ("retainedDriverErrorCategory", None), ("retainedDriverErrorCode", "PRIVATE_CODE"),
                    )),
                    {**run_result, "retainedDriverErrorCategory": "native-spawn-error", "retainedDriverErrorCode": "native-deadline"},
                ]
                invalid_details = [None, False, "missing", "invalid", {}, [], capture_detail[:-1],
                    capture_detail + ["PRIVATE_VALUE"], list(reversed(capture_detail))]
                for index, invalid_values in (
                    (0, (None, False, 0, [], {}, "PRIVATE_CATEGORY")),
                    (5, (None, False, "missing", {}, [], ["none"], ["none", "none", "PRIVATE_VALUE"],
                         ["missing", "none"], ["invalid", "missing"], ["contract-error", "deadline"],
                         ["native-spawn-error", "parent_lost"], ["native-lifecycle-error", "waitability"],
                         ["fixture-error", "PRIVATE_KIND"], ["PRIVATE_CATEGORY", "none"],
                         [True, "none"], ["none", False])),
                ):
                    invalid_details.extend([*capture_detail[:index], value, *capture_detail[index + 1:]]
                                           for value in invalid_values)
                for index, length in ((1, 24), (2, 9), (3, 4), (4, 3)):
                    original = capture_detail[index]
                    invalid_details.extend([*capture_detail[:index], value, *capture_detail[index + 1:]] for value in (
                        None, False, 0, 1.0, [], {}, "", original[:-1], original + "m",
                        original + "\n", original + "\r\n", "m" * (length - 1) + "\u03bc",
                        "m" * (length - 1) + "\uff10", "m" * (length - 1) + "\0",
                    ))
                    # At each position use a code from the WRONG domain. Timing
                    # offsets1/2 reject bool codes; other positions reject cutoff
                    # codes. No off-by-one alphabet shift can remain unnoticed.
                    for offset in range(length):
                        wrong = "0" if index == 2 and offset in (1, 2) else "a"
                        value = original[:offset] + wrong + original[offset + 1:]
                        invalid_details.append([*capture_detail[:index], value, *capture_detail[index + 1:]])
                self.assertFalse(controller._ownership_capture_detail_valid(
                    [*capture_detail[:5], tuple(capture_detail[5])]))
                invalid_results.extend({**run_result, "captureDetail": detail} for detail in invalid_details)
                for group in ("nativeChecks", "nativeOutcomes"):
                    original = run_result[group]
                    invalid_results.extend({**run_result, group: value} for value in (
                        None, [], {key: value for key, value in original.items() if key != next(iter(original))},
                        {**original, "PRIVATE_FIELD": "missing"}, {key: original[key] for key in reversed(original)},
                        {**original, next(iter(original)): 0}, {**original, next(iter(original)): "PRIVATE_VALUE"},
                    ))
                invalid_run_cleanup.extend({**run_cleanup, "driverResult": result} for result in invalid_results)
                invalid_ownership.extend({**run_record, "row": {**run_record["row"], "runCleanup": projection}}
                                         for projection in invalid_run_cleanup)
                invalid_ownership.extend((
                    {**run_record, "helper": "capture"},
                    {**run_record, "row": {**run_record["row"], "operationErrorCategory": "none", "operationErrorKind": "none"}},
                    {**run_record, "phase": "restoration"},
                    {**run_record, "errorCategory": "interrupt", "errorKind": "none"},
                ))
                invalid_markers = [*(ownership_bytes(record) for record in invalid_ownership),
                    ownership_marker * 2,
                    ownership_marker.replace(b'"schema":4', b'"schema":4,"schema":4'),
                    ownership_marker.replace(b'"ownerPhase":"unknown"', b'"ownerPhase":"unknown","ownerPhase":"unknown"'),
                    ownership_marker.replace(b'"firstExceptionPreserved":true', b'"firstExceptionPreserved":true,"firstExceptionPreserved":true'),
                    ownership_marker.replace(b'"schema":4', b'"schema": 4'),
                    run_marker.replace(b'"driverStatus":', b'"driverStatus":null,"driverStatus":'),
                    run_marker.replace(b'"nativeFinal":false', b'"nativeFinal":false,"nativeFinal":false'),
                    run_marker.replace(b'"resultKind":"pass"', b'"resultKind":"pass","resultKind":"pass"'),
                    run_marker.replace(b'"captureDetail":', b'"captureDetail":[],"captureDetail":'),
                    run_marker.replace(b'"01mx"', br'"01m\u0078"'),
                    ownership_marker.replace(b'"async"', br'"\u0061sync"'),
                    ownership_marker[:-1], ownership_marker[:-1] + b"\r\n",
                    b"MRK_OWNERSHIP_FAILURE=\xff\n", b"progress " + ownership_marker,
                    ownership_marker.replace(b"MRK_OWNERSHIP_FAILURE=", b"MRK_OWNERSHIP_ASYNC_FAILURE="),
                    ownership_bytes({**ownership_record, "schema": 1}).replace(
                        b"MRK_OWNERSHIP_FAILURE=", b"MRK_OWNERSHIP_ASYNC_FAILURE="),
                ]
                for raw in invalid_markers:
                    detail = controller.failure_details(capture(ownership_stdout, stderr=raw, ok=False, returncode=1),
                                                        ownership_step, paths, deadline=1000.0)
                    self.assertNotIn("ownership_failure", detail)
                    self.assertEqual(detail["returncode"], 1)
                    self.assertNotIn("PRIVATE_", json.dumps(detail))
                # Enumerate the finite family/case/helper domain with every
                # applicable code and each field's longest allowed encoding.
                # This is a complete-line bound, including prefix and LF; an
                # impossible mixture of all24 codes is not a valid maximum.
                driver_category, driver_code = max(
                    ((category, code) for category, values in controller.ADAPTER_FAILURE_DRIVER_CODES.items() for code in values),
                    key=lambda pair: len(pair[0]) + len(pair[1]))
                primary_pairs = [[category, code]
                    for category, codes in controller.OWNERSHIP_CAPTURE_PRIMARY_ERROR_KINDS.items() for code in codes]
                maximum_primary = max(primary_pairs, key=lambda item: len(json.dumps(item, separators=(",", ":"))))
                self.assertEqual(maximum_primary, ["native-lifecycle-error", "parent_lost"])
                self.assertEqual(len(json.dumps(maximum_primary, separators=(",", ":"))), 40)
                maximum_capture_detail = [max(controller.ADAPTER_FAILURE_DRIVER_CODES, key=len),
                    "m" * 24, "maa" + "m" * 6, "m" * 4, "m" * 3, maximum_primary]
                self.assertEqual(len(json.dumps(maximum_capture_detail, separators=(",", ":"))), 119)
                self.assertEqual(len(',"captureDetail":'), 17)
                maximum_run_result = {
                    "resultKind": max(controller.ADAPTER_FAILURE_RESULT_KINDS, key=len),
                    "retainedDriverErrorCategory": driver_category, "retainedDriverErrorCode": driver_code,
                    "nativeChecks": dict.fromkeys(adapter_native_checks, "missing"),
                    "nativeOutcomes": {name: max(values, key=len) for name, values in adapter_native_outcomes.items()},
                    "captureDetail": maximum_capture_detail,
                }
                error_tuples = [[max(run_stages, key=len), category, kind, condition]
                    for category, kinds in controller.OWNERSHIP_FAILURE_ERROR_KINDS.items() if category != "none"
                    for kind in kinds for condition in ("other", "missing", *run_conditions)
                    if condition in ("other", "missing") or category == "fixture-error" and kind == run_conditions[condition]]
                maximum_error = max(error_tuples, key=lambda item: len(json.dumps(item, separators=(",", ":"))))
                self.assertEqual(maximum_error,
                    ["transcript-out-close", "fixture-error", "fixture-cleanup", "enumeration-before-identity"])
                self.assertEqual(len(json.dumps(maximum_error, separators=(",", ":"))), 88)
                self.assertEqual(len(json.dumps(maximum_run_result, separators=(",", ":"))), 1375)
                maximum_run_cleanup = {
                    "directoryState": max(controller.OWNERSHIP_RUN_DIRECTORY_STATES, key=len),
                    "driverStatus": {"kind": "missing", "code": "missing"},
                    "resultSource": max(controller.OWNERSHIP_RUN_RESULT_SOURCES, key=len),
                    "checks": dict.fromkeys(run_checks, "missing"),
                    "nativeProof": {name: max(controller.OWNERSHIP_RUN_OWNER_FINALITIES, key=len) if name == "ownerFinality"
                                    else "missing" for name in run_proof_fields},
                    "cleanupErrors": [maximum_error] * 7, "driverResult": maximum_run_result,
                }
                self.assertEqual(len(json.dumps(maximum_run_cleanup, separators=(",", ":"))), 2757)
                maximum_records = [{**ownership_record, "platform": "android", "family": family,
                    "helper": helper, "case": case, "row": {
                        **ownership_row, "ownerPhase": "unstarted",
                        "firstErrorCategory": "native-lifecycle-error", "firstErrorKind": "parent_lost",
                        "operationErrorCategory": "native-lifecycle-error", "operationErrorKind": "parent_lost",
                        "failedChecks": ownership_case_codes(family, helper, case),
                        "checks": dict.fromkeys(controller.OWNERSHIP_FAILURE_CHECKS, "missing"),
                        "commandChecks": dict.fromkeys(controller.OWNERSHIP_FAILURE_COMMAND_CHECKS, "missing"),
                        "runCleanup": maximum_run_cleanup if helper == "run" else "missing",
                    }} for family, cases in controller.OWNERSHIP_FAILURE_CASES.items()
                    for helper in ("capture", "run") for case in cases]
                maximum_record = max(maximum_records, key=lambda record: len(ownership_bytes(record)))
                self.assertEqual([maximum_record[key] for key in ("family", "helper", "case")],
                                 ["async", "run", "repeated"])
                self.assertEqual(len(ownership_bytes(maximum_record)), 3983)
                self.assertLessEqual(len(ownership_bytes(maximum_record)), 4096)
                self.assertEqual(controller.ownership_failure(ownership_bytes(maximum_record)), maximum_record)
                for code in adapter_entry_error_codes.values():
                    record = {**maximum_record, "row": {**maximum_record["row"], "runCleanup": {
                        **maximum_run_cleanup, "driverResult": {**maximum_run_result,
                            "retainedDriverErrorCategory": "fixture-error", "retainedDriverErrorCode": code}}}}
                    self.assertLessEqual(len(ownership_bytes(record)), 3983)
                    self.assertEqual(controller.ownership_failure(ownership_bytes(record)), record)
                largest_missing = {**maximum_record, "family": "signals", "helper": "capture",
                    "case": "install-published-TERM", "phase": "proof-publication",
                    "errorCategory": "native-lifecycle-error", "errorKind": "parent_lost", "row": "missing"}
                self.assertEqual(len(ownership_bytes(largest_missing)), 237)
                self.assertEqual(controller.ownership_failure(ownership_bytes(largest_missing)), largest_missing)
                oversized = ownership_marker[:-1] + b" " * (4097 - len(ownership_marker)) + b"\n"
                self.assertEqual(len(oversized), 4097)
                with patch.object(controller, "strict_json", side_effect=AssertionError("oversized ownership JSON was parsed")) as decode:
                    self.assertIsNone(controller.ownership_failure(oversized))
                decode.assert_not_called()

                expired = [False]
                def expired_ownership_parse(_text):
                    expired[0] = True
                    raise ValueError("PRIVATE_MESSAGE")
                with patch.object(controller, "strict_json", side_effect=expired_ownership_parse), \
                        patch.object(controller.time, "monotonic", side_effect=lambda: 1000.0 if expired[0] else 999.0), \
                        self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                    controller.failure_details(failed_capture, ownership_step, paths, deadline=1000.0)
                expired[0] = False
                original_scan = controller.minitest_records
                def expire_ownership_scan(text, identifiers, *, deadline):
                    if identifiers == (ownership_target,):
                        expired[0] = True
                    return original_scan(text, identifiers, deadline=deadline)
                with patch.object(controller, "minitest_records", side_effect=expire_ownership_scan), \
                        patch.object(controller.time, "monotonic", side_effect=lambda: 1000.0 if expired[0] else 999.0), \
                        self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                    controller.failure_details(failed_capture, ownership_step, paths, deadline=1000.0)
                for interruption in (KeyboardInterrupt("PRIVATE_MESSAGE"), SystemExit(7)):
                    with patch.object(controller, "strict_json", side_effect=interruption), \
                            self.assertRaises(type(interruption)) as raised:
                        controller.failure_details(failed_capture, ownership_step, paths, deadline=1000.0)
                    self.assertIs(raised.exception, interruption)

            # One additional literal DATA file, not the native observation test
            # class or any Ruby execution. Masks must mean the same on both sides.
            signal_source = ruby_text("tests/workflow/upload_process_fixture.rb")
            for suffix in ("FIELDS", "MODES", "GUARD_FIELDS", "RESULT_FIELDS", "ROW_FIELDS", "ROLES",
                           "STATES", "FAILURES_STATES", "IDENTITY_FIELDS", "CHECK_FIELDS", "STAGES",
                           "CATEGORIES", "ROUTES", "REFUSALS", "SIGNALS", "ERRNOS", "NATIVE_OUTCOME_FIELDS"):
                name = "NATIVE_SIGNAL_FAILURE_" + suffix
                self.assertEqual(ruby_words(signal_source, name), getattr(controller, name))
            self.assertEqual(controller.NATIVE_SIGNAL_FAILURE_PREFIX, "MRK_NATIVE_SIGNAL_FAILURE=")
            self.assertEqual(controller.NATIVE_SIGNAL_FAILURE_MAX_BYTES, 4096)
            self.assertEqual(controller.NATIVE_SIGNAL_FAILURE_MAX_REQUESTS, 64)
            self.assertEqual(controller.NATIVE_SIGNAL_FAILURE_MAX_ERROR_CODE, 360)
            signal_target = controller.NATIVE_SIGNAL_FAILURE_CALLBACK
            self.assertEqual(signal_target,
                "NativeSignalObservationTest#test_native_first_close_and_post_reap_signals_with_safe_veto_controls")
            for name, value in (("PREFIX", controller.NATIVE_SIGNAL_FAILURE_PREFIX), ("CALLBACK", signal_target)):
                self.assertIn(f'NATIVE_SIGNAL_FAILURE_{name} = "{value}"', signal_source)
            self.assertIn("NATIVE_SIGNAL_FAILURE_MAX_BYTES = 4096", signal_source)
            self.assertIn("NATIVE_SIGNAL_FAILURE_MAX_REQUESTS = 64", signal_source)
            self.assertIn("NATIVE_SIGNAL_FAILURE_MAX_ERROR_CODE = 360", signal_source)
            self.assertEqual(controller.NATIVE_SIGNAL_FAILURE_RESULT_KINDS,
                             (*ruby_words(signal_source, "ADAPTER_FAILURE_KINDS"), "other", "missing"))

            def signal_literal_pairs(name):
                bodies = controller.re.findall(r"(?ms)^\s*" + name + r" = \{(.*?)^\s*\}\.freeze", signal_source)
                self.assertEqual(len(bodies), 1, name)
                pattern = r'"([^"\r\n]+)" => "([^"\r\n]+)"'
                pairs = controller.re.findall(pattern, bodies[0])
                self.assertEqual(len(pairs), len(dict(pairs)))
                residue = controller.re.sub(pattern + r"\s*,?", "", bodies[0])
                self.assertEqual("".join(residue.split()), "")
                return dict(pairs)

            labels = signal_literal_pairs("NATIVE_SIGNAL_FAILURE_LABEL_CODES")
            self.assertEqual(tuple(labels.values()), controller.NATIVE_SIGNAL_FAILURE_CHECK_CODES)
            self.assertEqual(len(set(labels.values())), 50)
            self.assertEqual(signal_literal_pairs("NATIVE_SIGNAL_FAILURE_STAGE_PREFIXES"), dict(zip(
                controller.NATIVE_SIGNAL_FAILURE_STAGES,
                ("request observation:", "signal syscall:", "observation body:", "observation finalization:",
                 "driver proof:", "helper proof:", "parent proof publication:", "hook:", "hook:entry:"))))
            classes = ("Interrupt", "SignalException", "SystemExit", "UploadProcessFixture::Failure",
                "MobileReleaseKit::ContractError", "MobileReleaseKit::NativeUploadProcess::Error",
                "MobileReleaseKit::NativeUploadProcess::LifecycleError", "MobileReleaseKit::NativeUploadProcess::ProtocolError",
                "MobileReleaseKit::NativeProcessSpawn::Error", "IOError", "SystemCallError", "JSON::ParserError", "KeyError",
                "NoMethodError", "TypeError", "ArgumentError", "RuntimeError", "StandardError", "Exception")
            class_categories = dict(zip(classes, controller.NATIVE_SIGNAL_FAILURE_CATEGORIES[:-1]))
            signal_errnos = ("ECHILD", "ESRCH", "EINTR", "EBADF", "EINVAL", "EIO", "EPERM", "EACCES", "EAGAIN", "ENOMEM",
                            "EMFILE", "ENFILE", "ENOENT", "EPIPE")
            class_categories.update(("Errno::" + name, "os-error") for name in signal_errnos)
            self.assertEqual(signal_literal_pairs("NATIVE_SIGNAL_FAILURE_CLASS_CATEGORIES"), class_categories)
            self.assertEqual(controller.NATIVE_SIGNAL_FAILURE_SIGNALS, ("0", "KILL", "INT", "other"))
            self.assertEqual(controller.NATIVE_SIGNAL_FAILURE_ERRNOS, (*signal_errnos, "other"))
            self.assertEqual(controller.NATIVE_SIGNAL_FAILURE_NATIVE_OUTCOME_FIELDS,
                             ("custodian", "finalOutcome", "finalCleanup", "groupState"))
            self.assertEqual(len(controller.NATIVE_SIGNAL_FAILURE_ROUTES)
                             * len(controller.NATIVE_SIGNAL_FAILURE_SIGNALS)
                             * len(controller.NATIVE_SIGNAL_FAILURE_ERRNOS), 360)
            self.assertEqual(tuple(len(getattr(controller, "NATIVE_SIGNAL_FAILURE_" + name))
                                   for name in ("CHECK_CODES", "STAGES", "CATEGORIES", "ROUTES", "REFUSALS")),
                             (50, 9, 20, 6, 9))

            def signal_row(role, state="present"):
                identity_na = {"helperRoleMatches", "helperCopyMatches"} if role == "driver" else set()
                check_na = ({"originalWaitBound", "creatorJoined", "taskJoinsObserved"} if role == "driver" else
                            {"actualOriginalPrimary", "actualCustodianReceiptBound", "actualNativeDescriptorsClosed"})
                return {"role": role, "state": state, "mode": "missing",
                    "identities": {name: "not-applicable" if name in identity_na else "missing"
                                   for name in controller.NATIVE_SIGNAL_FAILURE_IDENTITY_FIELDS},
                    "returnCode": "missing",
                    "checks": {name: "not-applicable" if name in check_na else "missing"
                               for name in controller.NATIVE_SIGNAL_FAILURE_CHECK_FIELDS},
                    "failuresState": "missing", "failedCheckMask": 0, "causeMasks": [0] * 9,
                    "refusalMasks": [0] * 6, "unknownFailure": False,
                    "observedHelperReturn": "not-applicable" if role == "driver" else "missing",
                    "backendErrorCodes": "missing"}

            signal_record = {"schema": 2, "mode": "native-setup-interrupt",
                "guard": {name: name != "failuresEmpty" for name in controller.NATIVE_SIGNAL_FAILURE_GUARD_FIELDS},
                "result": {"kind": "pass", "mode": "native-setup-interrupt", "driverExitStatus": 1},
                "rows": [signal_row(role) for role in controller.NATIVE_SIGNAL_FAILURE_ROLES],
                "nativeOutcomes": {"custodian": "exit1", "finalOutcome": "failed",
                                   "finalCleanup": "confirmed", "groupState": "retired"}}
            signal_record["rows"][0].update(failuresState="nonempty", failedCheckMask=1 << 20,
                causeMasks=[0, 0, 0, 0, (1 << 3) | (1 << 19), 0, 0, 0, 0],
                refusalMasks=[(1 << 1) | (1 << 2), 0, 0, 0, 0, 0], unknownFailure=True)
            signal_record["rows"][0]["checks"]["hooksRestored"] = True
            # The original helper return can survive an aggregate observation
            # failure while helper_facts remains absent and the wrapper exits 1.
            signal_record["rows"][1].update(observedHelperReturn=2, backendErrorCodes=[7, 0, 18, 7, 360])

            def signal_bytes(record):
                return (controller.NATIVE_SIGNAL_FAILURE_PREFIX
                        + json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")

            def signal_with_row(index, row):
                return {**signal_record, "rows": [row if i == index else value
                                                  for i, value in enumerate(signal_record["rows"])]}

            signal_marker = signal_bytes(signal_record)
            signal_step = controller.Step("ruby-native-signal-observation", parser="minitest", expected_tests=1)
            signal_failed = signal_target + " = PRIVATE_MESSAGE\n0.01 s = E\n"
            signal_footer = "\nFinished in 0.03s.\n1 runs, 606 assertions, 0 failures, 1 errors, 0 skips\n"
            signal_stdout = signal_failed + signal_footer
            with patch.object(controller, "ruby_expected_ids", return_value=(signal_target,)), \
                    patch.object(controller, "ruby_capture_ids", return_value=(signal_target,)), \
                    patch.object(controller.time, "monotonic", return_value=999.0):
                with patch.object(controller, "_fixture_failure_record", wraps=controller._fixture_failure_record) as strict:
                    self.assertEqual(controller.native_signal_failure(signal_marker, deadline=1000.0), signal_record)
                strict.assert_called_once_with(signal_marker, "MRK_NATIVE_SIGNAL_FAILURE=", 4096,
                                               deadline=1000.0, canonical_fields=controller.NATIVE_SIGNAL_FAILURE_FIELDS)
                for mode in controller.NATIVE_SIGNAL_FAILURE_MODES:
                    record = {**signal_record, "mode": mode}
                    for terminal in ("E", "F"):
                        transcript = signal_stdout if terminal == "E" else signal_stdout.replace(
                            "0.01 s = E", "0.01 s = F").replace("0 failures, 1 errors", "1 failures, 0 errors")
                        original = capture(transcript, stderr=signal_bytes(record), ok=False, returncode=1)
                        detail = controller.failure_details(original, signal_step, paths, deadline=1000.0)
                        self.assertEqual(detail["signal_failure"], record)
                        self.assertEqual(detail["returncode"], 1)
                        self.assertEqual(detail["persisted"], list(original.persisted))
                        self.assertNotIn("PRIVATE_", json.dumps(detail))
                # Each original comparison alone can explain the rejection.
                # Missing helpers/empty labels or contradictory facts are not
                # promoted to a new acceptance rule or silently normalized.
                for name in controller.NATIVE_SIGNAL_FAILURE_GUARD_FIELDS:
                    for adverse in (False, "missing"):
                        record = {**signal_record, "guard": dict.fromkeys(controller.NATIVE_SIGNAL_FAILURE_GUARD_FIELDS, True)}
                        record["guard"][name] = adverse
                        self.assertEqual(controller.native_signal_failure(signal_bytes(record)), record)
                for index, role in enumerate(controller.NATIVE_SIGNAL_FAILURE_ROLES):
                    for state in controller.NATIVE_SIGNAL_FAILURE_STATES:
                        record = signal_with_row(index, signal_row(role, state))
                        self.assertEqual(controller.native_signal_failure(signal_bytes(record)), record)
                    for failure_state, unknown, bits in (("empty", False, 0), ("missing", False, 0),
                                                        ("invalid", True, 0), ("nonempty", True, 0),
                                                        ("nonempty", False, 1)):
                        row = signal_row(role)
                        row.update(failuresState=failure_state, unknownFailure=unknown, failedCheckMask=bits)
                        record = signal_with_row(index, row)
                        self.assertEqual(controller.native_signal_failure(signal_bytes(record)), record)
                    # Preserve request chronology, repetition and non-error
                    # slots even without labels; zero is not a success receipt.
                    for codes in ("missing", "invalid", [], [0, 1, 360], [7, 0, 18, 7, 360], [0] * 64, [360] * 64):
                        row = {**signal_row(role), "backendErrorCodes": codes}
                        record = signal_with_row(index, row)
                        self.assertEqual(controller.native_signal_failure(signal_bytes(record)), record)
                    if role != "driver":
                        for observed_return in (0, 1, 2, 255, "missing"):
                            row = {**signal_row(role), "observedHelperReturn": observed_return}
                            record = signal_with_row(index, row)
                            self.assertEqual(controller.native_signal_failure(signal_bytes(record)), record)
                for name in controller.NATIVE_SIGNAL_FAILURE_NATIVE_OUTCOME_FIELDS:
                    for outcome in controller.ADAPTER_FAILURE_NATIVE_OUTCOMES[name]:
                        record = {**signal_record, "nativeOutcomes": {**signal_record["nativeOutcomes"], name: outcome}}
                        self.assertEqual(controller.native_signal_failure(signal_bytes(record)), record)
                # Exact complete worst-case format bound, including prefix/LF,
                # longest actual kind and all 64 maximum-width codes per row.
                longest_mode = max(controller.NATIVE_SIGNAL_FAILURE_MODES, key=len)
                maximum = {**signal_record, "mode": longest_mode,
                    "guard": dict.fromkeys(controller.NATIVE_SIGNAL_FAILURE_GUARD_FIELDS, "missing"),
                    "result": {"kind": max(controller.NATIVE_SIGNAL_FAILURE_RESULT_KINDS, key=len),
                               "mode": longest_mode, "driverExitStatus": "missing"},
                    "rows": [signal_row(role) for role in controller.NATIVE_SIGNAL_FAILURE_ROLES],
                    "nativeOutcomes": {"custodian": "not-attempted", "finalOutcome": "rejected",
                                       "finalCleanup": "confirmed", "groupState": "not-created"}}
                for row in maximum["rows"]:
                    row.update(mode=longest_mode, failuresState="nonempty", failedCheckMask=(1 << 50) - 1,
                               causeMasks=[(1 << 20) - 1] * 9, refusalMasks=[511] * 6, backendErrorCodes=[360] * 64)
                compact_json = lambda value: json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")
                self.assertEqual(len(controller.NATIVE_SIGNAL_FAILURE_PREFIX.encode("ascii")), 26)
                self.assertEqual(len(compact_json(maximum["guard"])), 193)
                self.assertEqual([len(compact_json(row)) for row in maximum["rows"]], [1051, 1033, 1030])
                self.assertEqual(len(compact_json(maximum["nativeOutcomes"])), 109)
                self.assertTrue(all(len(value) == max(map(len, controller.ADAPTER_FAILURE_NATIVE_OUTCOMES[name]))
                                    for name, value in maximum["nativeOutcomes"].items()))
                self.assertEqual(len(signal_bytes(maximum)), 3641)
                self.assertEqual(controller.NATIVE_SIGNAL_FAILURE_MAX_BYTES - len(signal_bytes(maximum)), 455)
                self.assertLessEqual(len(signal_bytes(maximum)), controller.NATIVE_SIGNAL_FAILURE_MAX_BYTES)
                self.assertEqual(controller.native_signal_failure(signal_bytes(maximum)), maximum)

                failed_capture = capture(signal_stdout, stderr=signal_marker, ok=False, returncode=1)
                with self.assertRaisesRegex(controller.VerificationError, "COMMAND_EXIT_OR_FINALITY"):
                    controller.parse_capture(signal_step, failed_capture, paths, "linux", None)
                zero_capture = capture(signal_stdout, stderr=signal_marker)
                self.assertEqual(controller.failure_details(zero_capture, signal_step, paths)["signal_failure"], signal_record)
                with self.assertRaisesRegex(controller.VerificationError, "MINITEST_RESULT_REJECTED"):
                    controller.parse_capture(signal_step, zero_capture, paths, "macos", None)
                success_stdout = signal_stdout.replace("0.01 s = E", "0.01 s = .").replace("1 errors", "0 errors")
                successful = capture(success_stdout, stderr=signal_marker)
                self.assertNotIn("signal_failure", controller.failure_details(successful, signal_step, paths))
                self.assertTrue(controller.parse_capture(signal_step, successful, paths, "linux", None).ok)
                for transcript in (signal_footer, signal_target + ":\n" + signal_footer,
                    signal_target + " = unfinished\n" + signal_footer,
                    signal_stdout.replace("0.01 s = E", "0.01 s = S"),
                    signal_stdout.replace("0.01 s = E", "0.01 s = .\n0.01 s = E"),
                    signal_failed * 2 + signal_footer, signal_footer + signal_failed):
                    self.assertNotIn("signal_failure", controller.failure_details(
                        capture(transcript, stderr=signal_marker, ok=False, returncode=1), signal_step, paths))
                self.assertNotIn("signal_failure", controller.failure_details(capture(
                    signal_stdout + signal_marker.decode("ascii"), ok=False, returncode=1), signal_step, paths))
                with patch.object(controller, "ruby_expected_ids", return_value=expected):
                    self.assertNotIn("signal_failure", controller.failure_details(failed_capture, signal_step, paths))
                for wrong_step in (dataclasses.replace(signal_step, id="ruby-native-capture"),
                    dataclasses.replace(signal_step, id="ruby-native-owner"),
                    dataclasses.replace(signal_step, native_partition="healthy"),
                    dataclasses.replace(signal_step, native_partition="native-setup-interrupt"),
                    dataclasses.replace(signal_step, parser="exit")):
                    self.assertNotIn("signal_failure", controller.failure_details(failed_capture, wrong_step, paths))

                invalid_signal = [
                    {**signal_record, "guard": dict.fromkeys(controller.NATIVE_SIGNAL_FAILURE_GUARD_FIELDS, True)},
                    *({**signal_record, "schema": value} for value in (True, 2.0, "2", 1, 3)),
                    *({**signal_record, "mode": value} for value in (None, "missing", "PRIVATE_MODE")),
                    *({**signal_record, "rows": value} for value in (None, [], signal_record["rows"][:2],
                        signal_record["rows"] + [signal_record["rows"][0]], list(reversed(signal_record["rows"])))),
                ]
                # Every ordered container is closed; every row has fixed-role
                # applicability, and no bool can become an integer mask/status.
                containers = [(signal_record, lambda value: value),
                    (signal_record["guard"], lambda value: {**signal_record, "guard": value}),
                    (signal_record["result"], lambda value: {**signal_record, "result": value}),
                    (signal_record["nativeOutcomes"], lambda value: {**signal_record, "nativeOutcomes": value})]
                for index, row in enumerate(signal_record["rows"]):
                    containers.append((row, lambda value, index=index: signal_with_row(index, value)))
                    for group in ("identities", "checks"):
                        containers.append((row[group], lambda value, index=index, row=row, group=group:
                                           signal_with_row(index, {**row, group: value})))
                for original, replace in containers:
                    invalid_signal.extend(replace(value) for value in (None, [],
                        {key: value for key, value in original.items() if key != next(iter(original))},
                        {**original, "PRIVATE_FIELD": "PRIVATE_VALUE"},
                        {key: original[key] for key in reversed(original)}))
                invalid_signal.extend({**signal_record, "guard": {**signal_record["guard"], "caseMatches": value}}
                                      for value in (None, 0, 1.0, "invalid", "not-applicable", "PRIVATE_VALUE"))
                invalid_signal.extend({**signal_record, "result": {**signal_record["result"], key: value}}
                    for key, value in (("kind", "invalid"), ("kind", "PRIVATE_KIND"), ("mode", "invalid"),
                                       *(("driverExitStatus", value) for value in (True, 1.0, -1, 256, "invalid"))))
                invalid_signal.extend({**signal_record, "nativeOutcomes": {**signal_record["nativeOutcomes"], key: value}}
                    for key in controller.NATIVE_SIGNAL_FAILURE_NATIVE_OUTCOME_FIELDS
                    for value in (None, True, 1, "PRIVATE_OUTCOME", "other"))
                for index, row in enumerate(signal_record["rows"]):
                    for key, values in (("role", ("PRIVATE_ROLE", None)), ("state", ("PRIVATE_STATE", None)),
                        ("mode", ("PRIVATE_MODE", None)), ("returnCode", (True, 1.0, -1, 256, "invalid")),
                        ("observedHelperReturn", (None, True, 2.0, -1, 256, "invalid", "PRIVATE_RETURN",
                                                 "missing" if index == 0 else "not-applicable",
                                                 2 if index == 0 else "2")),
                        ("backendErrorCodes", (None, True, 0, {}, "not-applicable", "PRIVATE_REQUEST",
                            [0] * 65, [360] * 65, *([value] for value in (True, 1.0, -1, 361, "7", None, {}, [])))),
                        ("failuresState", ("PRIVATE_FAILURES", None)), ("unknownFailure", (0, 1, "false")),
                        ("failedCheckMask", (True, 1.0, -1, 1 << 50)),
                        ("causeMasks", (None, [0] * 8, [0] * 10, *([value] * 9 for value in (True, 1.0, -1, 1 << 20)))),
                        ("refusalMasks", (None, [0] * 5, [0] * 7, *([value] * 6 for value in (True, 1.0, -1, 512))))):
                        invalid_signal.extend(signal_with_row(index, {**row, key: value}) for value in values)
                    for group in ("identities", "checks"):
                        for key, current in row[group].items():
                            wrong = "missing" if current == "not-applicable" else "not-applicable"
                            invalid_signal.append(signal_with_row(index, {**row, group: {**row[group], key: wrong}}))
                        invalid_signal.append(signal_with_row(index,
                            {**row, group: {**row[group], "hooksRestored" if group == "checks" else "kindMatches": 1}}))
                    for state in ("missing", "invalid"):
                        missing = signal_row(row["role"], state)
                        for key, value in (("mode", "other"), ("returnCode", 0), ("failuresState", "empty"),
                                           ("failedCheckMask", 1), ("unknownFailure", True),
                                           ("backendErrorCodes", []), ("backendErrorCodes", "invalid"),
                                           ("observedHelperReturn", "missing" if index == 0 else 2),
                                           ("checks", {**missing["checks"], "hooksRestored": False})):
                            invalid_signal.append(signal_with_row(index, {**missing, key: value}))
                    for failure_state, unknown, bits in (("empty", False, 1), ("empty", True, 0),
                        ("missing", False, 1), ("missing", True, 0), ("invalid", False, 0),
                        ("invalid", True, 1), ("nonempty", False, 0)):
                        missing = signal_row(row["role"])
                        missing.update(failuresState=failure_state, unknownFailure=unknown, failedCheckMask=bits)
                        invalid_signal.append(signal_with_row(index, missing))
                    for absent in ("observedHelperReturn", "backendErrorCodes"):
                        invalid_signal.append(signal_with_row(index, {key: value for key, value in row.items() if key != absent}))
                historical_signal = {key: value for key, value in signal_record.items() if key != "nativeOutcomes"}
                historical_signal["rows"] = [{key: value for key, value in row.items()
                                               if key not in {"observedHelperReturn", "backendErrorCodes"}}
                                              for row in signal_record["rows"]]
                # The current decoder never promotes an old shape (or a
                # mixed old/new shape) into evidence for this source.
                invalid_signal.extend({**historical_signal, "schema": schema} for schema in (1, 2))
                invalid_markers = [*(signal_bytes(record) for record in invalid_signal), signal_marker * 2,
                    signal_marker.replace(b'"schema":2', b'"schema":2,"schema":2'),
                    signal_marker.replace(b'"caseMatches":true', b'"caseMatches":true,"caseMatches":true'),
                    signal_marker.replace(b'"failedCheckMask":1048576', b'"failedCheckMask":1048576,"failedCheckMask":1048576'),
                    signal_marker.replace(b'"schema":2', b'"schema": 2'),
                    signal_marker.replace(b'"native-setup-interrupt"', br'"\u006eative-setup-interrupt"'),
                    signal_marker[:-1], signal_marker[:-1] + b"\r\n",
                    b"MRK_NATIVE_SIGNAL_FAILURE=\xff\n", b"progress " + signal_marker]
                for raw in invalid_markers:
                    detail = controller.failure_details(capture(signal_stdout, stderr=raw, ok=False, returncode=1),
                                                        signal_step, paths, deadline=1000.0)
                    self.assertNotIn("signal_failure", detail)
                    self.assertEqual(detail["returncode"], 1)
                    self.assertNotIn("PRIVATE_", json.dumps(detail))
                oversized = signal_marker[:-1] + b" " * (4097 - len(signal_marker)) + b"\n"
                self.assertEqual(len(oversized), 4097)
                with patch.object(controller, "strict_json", side_effect=AssertionError("oversized signal JSON was parsed")) as decode:
                    self.assertIsNone(controller.native_signal_failure(oversized))
                decode.assert_not_called()
                expired = [False]
                def expired_signal_parse(_text):
                    expired[0] = True
                    raise ValueError("PRIVATE_MESSAGE")
                with patch.object(controller, "strict_json", side_effect=expired_signal_parse), \
                        patch.object(controller.time, "monotonic", side_effect=lambda: 1000.0 if expired[0] else 999.0), \
                        self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                    controller.failure_details(failed_capture, signal_step, paths, deadline=1000.0)
                expired[0] = False
                original_scan = controller.minitest_records
                def expire_signal_scan(text, identifiers, *, deadline):
                    if identifiers == (signal_target,):
                        expired[0] = True
                    return original_scan(text, identifiers, deadline=deadline)
                # Initial source inventory differs; expire specifically during
                # the later singleton target rescan, not the first parse.
                with patch.object(controller, "ruby_expected_ids", return_value=(*expected, signal_target)), \
                        patch.object(controller, "minitest_records", side_effect=expire_signal_scan), \
                        patch.object(controller.time, "monotonic", side_effect=lambda: 1000.0 if expired[0] else 999.0), \
                        self.assertRaisesRegex(controller.VerificationError, "AGGREGATE_DEADLINE"):
                    controller.failure_details(failed_capture, signal_step, paths, deadline=1000.0)
                for interruption in (KeyboardInterrupt("PRIVATE_MESSAGE"), SystemExit(7)):
                    with patch.object(controller, "strict_json", side_effect=interruption), \
                            self.assertRaises(type(interruption)) as raised:
                        controller.failure_details(failed_capture, signal_step, paths, deadline=1000.0)
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
            self.assertEqual(selection, "ordinary")
            return expected

        checks = SimpleNamespace(native_partition_ids=identities)
        step = controller.Step("native-profile-source", parser="native", native_partition="ordinary")
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
        for delegated in _G_LINUX_METHODS:
            forged = f"{delegated.rsplit('.', 1)[1]} ({delegated}) ... ok\n"
            with self.subTest(unexecuted_delegated=delegated), \
                    self.assertRaisesRegex(controller.VerificationError, "NATIVE_PYTHON_INVENTORY"):
                controller.parse_capture(step, capture(forged + footer), paths, "macos", checks)
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
    def test_signing_metadata_is_fixed_pure_source_and_leaves_no_import_or_path_authority(self):
        checks = ci_module("ci_checks")
        alias = "_mrk_ci_signing_regression_catalog"
        prefixes = ("workflow", "unit", "mobile_release")

        def protected_modules():
            return {name: module for name, module in sys.modules.items()
                    if any(name == prefix or name.startswith(prefix + ".") for prefix in prefixes)}

        modules = protected_modules()
        paths, hooks, finders = list(sys.path), list(sys.path_hooks), list(sys.meta_path)
        self.assertNotIn(alias, sys.modules)
        for operating_system in ("ubuntu-24.04", "macos-26"):
            methods, required = checks.signing_regression_metadata(ROOT, operating_system)
            self.assertIs(type(methods), tuple)
            self.assertEqual(tuple(sorted(set(methods))), methods)
            self.assertIs(type(required), MappingProxyType)
            self.assertEqual(tuple(required), methods)
            for method, identifiers in required.items():
                self.assertIs(type(identifiers), tuple)
                self.assertTrue(identifiers)
                self.assertEqual(tuple(sorted(set(identifiers))), identifiers)
                self.assertTrue(all(identifier.startswith("G/" + method + "/") for identifier in identifiers))
            with self.assertRaises(TypeError):
                required[methods[0]] = ()
            self.assertNotIn(alias, sys.modules)
            self.assertEqual(protected_modules(), modules)
            self.assertEqual((sys.path, sys.path_hooks, sys.meta_path), (paths, hooks, finders))

    def test_signing_metadata_rejects_collision_drift_bad_tables_and_original_deadline_without_alias_cleanup_retry(self):
        checks = ci_module("ci_checks")
        alias = "_mrk_ci_signing_regression_catalog"
        methods, required = _g_metadata_fixture("ubuntu-24.04")
        cases = ("success", "occupied", "read-collision", "read-error", "foreign-import", "execute-error",
                 "execute-replacement", "late-replacement", "removed-alias", "expired-entry", "expired-read", "expired-exec", "expired-return",
                 "empty-methods", "list-methods", "duplicate-methods", "unsorted-methods", "foreign-method",
                 "wrong-keys", "mutable-map", "empty-parts", "list-parts", "duplicate-parts", "unsorted-parts", "foreign-parts",
                 "empty-suffix-parts", "control-parts")
        for case in cases:
            with self.subTest(case=case):
                foreign, protected = object(), object()
                runtime = SimpleNamespace(modules={"workflow": protected, "unit": protected, "mobile_release": protected},
                                          path=["/fixed/stdlib"])
                original = OSError(5, "PRIVATE_METADATA_ERROR")
                clock = SimpleNamespace(now=10.0 if case == "expired-entry" else 1.0)
                if case == "occupied":
                    runtime.modules[alias] = foreign

                def read(path, *, deadline):
                    self.assertEqual(path, ROOT / "tests/workflow/local_signing_regression_catalog.py")
                    self.assertEqual(deadline, 10.0)
                    if case == "read-error":
                        raise original
                    if case == "read-collision":
                        runtime.modules[alias] = foreign
                    if case == "expired-read":
                        clock.now = 10.0
                    return b"from workflow import forbidden\n" if case == "foreign-import" else b"from types import MappingProxyType\n"

                def execute(code, namespace):
                    self.assertEqual(code.co_filename, str(ROOT / "tests/workflow/local_signing_regression_catalog.py"))
                    self.assertIs(runtime.modules[alias].__dict__, namespace)
                    if case == "execute-error":
                        raise original
                    selected = (() if case == "empty-methods" else list(methods) if case == "list-methods" else
                                methods + methods[:1] if case == "duplicate-methods" else
                                tuple(reversed(methods)) if case == "unsorted-methods" else
                                ("unit.test_fixture.Contracts.test_other PRIVATE",) if case == "foreign-method" else methods)
                    obligations = dict(required)
                    if case == "wrong-keys":
                        obligations.pop(methods[0])
                    elif case.endswith("-parts"):
                        first = obligations[methods[0]][0]
                        obligations[methods[0]] = (() if case == "empty-parts" else [first] if case == "list-parts" else
                            (first, first) if case == "duplicate-parts" else (first + "z", first) if case == "unsorted-parts" else
                            ("G/" + methods[0] + "/",) if case == "empty-suffix-parts" else (first + "\0",) if case == "control-parts" else
                            ("G/" + methods[1] + "/whole",))

                    def obligation_table(operating_system):
                        self.assertEqual(operating_system, "ubuntu-24.04")
                        if case == "late-replacement":
                            runtime.modules[alias] = foreign
                        if case == "expired-return":
                            clock.now = 10.0
                        return obligations if case == "mutable-map" else MappingProxyType(obligations)

                    namespace["delegated_methods"] = lambda operating_system: selected
                    namespace["obligations"] = obligation_table
                    if case == "execute-replacement":
                        runtime.modules[alias] = foreign
                    elif case == "removed-alias":
                        del runtime.modules[alias]
                    if case == "expired-exec":
                        clock.now = 10.0

                with patch.object(checks, "sys", runtime), patch.object(checks, "_read_regular", side_effect=read) as reader, \
                        patch.object(checks, "exec", create=True, side_effect=execute) as executor, \
                        patch.object(checks, "time", SimpleNamespace(monotonic=lambda: clock.now)):
                    if case == "success":
                        self.assertEqual(checks.signing_regression_metadata(ROOT, "ubuntu-24.04", deadline=10.0),
                                         (methods, required))
                    else:
                        with self.assertRaises(OSError if case in {"read-error", "execute-error"} else checks.CheckError) as raised:
                            checks.signing_regression_metadata(ROOT, "ubuntu-24.04", deadline=10.0)
                        if case in {"read-error", "execute-error"}:
                            self.assertIs(raised.exception, original)
                        if case.startswith("expired-"):
                            self.assertEqual(str(raised.exception), "DEADLINE_EXPIRED")
                foreign_retained = case in {"occupied", "read-collision", "execute-replacement", "late-replacement"}
                self.assertEqual(runtime.modules, {"workflow": protected, "unit": protected, "mobile_release": protected,
                                                   **({alias: foreign} if foreign_retained else {})})
                self.assertEqual(runtime.path, ["/fixed/stdlib"])
                self.assertEqual(reader.call_count, 0 if case in {"occupied", "expired-entry"} else 1)
                self.assertEqual(executor.call_count, 0 if case in {"occupied", "expired-entry", "expired-read", "read-collision", "read-error", "foreign-import"} else 1)
        with patch.object(checks, "_read_regular") as reader:
            for operating_system in ("linux", "darwin", "macos", None, True, [], "ubuntu-24.04 "):
                with self.subTest(platform=operating_system), self.assertRaisesRegex(checks.CheckError, "SIGNING_REGRESSION_PLATFORM"):
                    checks.signing_regression_metadata(ROOT, operating_system)
            reader.assert_not_called()

    def test_python_capture_snapshot_reads_inventory_and_delegation_once_per_invocation(self):
        checks = ci_module("ci_checks")
        healthy = ("unit.synthetic.SnapshotTests.test_first", "unit.synthetic.SnapshotTests.test_second")
        for selection in ("full", "wheel", "native"):
            native = selection == "native"
            operating_system = "macos-26" if native else "ubuntu-24.04"
            metadata = _g_metadata_fixture(operating_system)
            delegated = metadata[0]
            authority = checks.NATIVE_AUTHORITY_IDS if native else ()
            complete = tuple(sorted(healthy + authority + checks.PYTHON_SINGLETON_IDS + delegated))
            parts = (("all", "ordinary", "authority", "delegated", *checks.PYTHON_SINGLETON_PARTITIONS) if native else
                     ("all", "delegated", "healthy", *checks.PYTHON_SINGLETON_PARTITIONS))
            active = "ordinary" if native else "healthy"

            def acquire():
                return (checks.native_capture_snapshot(ROOT, deadline=42.0) if native else
                        checks.python_capture_snapshot(ROOT, selection, deadline=42.0))

            with self.subTest(selection=selection), \
                    patch.object(checks, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                    patch.object(checks, "expected_python_ids", return_value=complete) as source, \
                    patch.object(checks, "signing_regression_metadata", return_value=metadata) as catalog:
                snapshot = acquire()
                self.assertIs(type(snapshot), tuple)
                inventories, captured_metadata = snapshot
                self.assertIs(type(inventories), MappingProxyType)
                self.assertIs(captured_metadata, metadata)
                self.assertEqual(tuple(inventories), parts)
                self.assertEqual(inventories["all"], complete)
                self.assertEqual(inventories[active], healthy)
                if native:
                    self.assertEqual(inventories["authority"], authority)
                self.assertEqual(inventories["delegated"], delegated)
                self.assertEqual(tuple(inventories[name] for name in checks.PYTHON_SINGLETON_PARTITIONS),
                                 tuple((identifier,) for identifier in checks.PYTHON_SINGLETON_IDS))
                self.assertTrue(all(type(ids) is tuple and ids and tuple(sorted(set(ids))) == ids
                                    for ids in inventories.values()))
                joined = authority + tuple(identifier for part in (active, *checks.PYTHON_SINGLETON_PARTITIONS, "delegated")
                               for identifier in inventories[part])
                self.assertEqual(tuple(sorted(joined)), complete)
                self.assertEqual(len(joined), len(set(joined)))
                source.assert_called_once_with(ROOT, selection, deadline=42.0)
                catalog.assert_called_once_with(ROOT, operating_system, deadline=42.0)
                for mapping, key in ((inventories, active), (captured_metadata[1], delegated[0])):
                    with self.assertRaises(TypeError):
                        mapping[key] = ()
                fresh = "unit.synthetic.SnapshotTests.test_third"
                source.return_value = tuple(sorted(complete + (fresh,)))
                second, second_metadata = acquire()
                self.assertIsNot(second, inventories)
                self.assertIs(second_metadata, metadata)
                self.assertEqual(second[active], healthy + (fresh,))
                self.assertEqual(inventories[active], healthy)
                self.assertEqual(source.call_count, 2)
                self.assertEqual(catalog.call_count, 2)

            for expired_at, expected_calls in (("before", (0, 0)), ("inventory", (1, 0)), ("metadata", (1, 1))):
                clock = [42.0 if expired_at == "before" else 10.0]

                def acquire_source(*args, **kwargs):
                    if expired_at == "inventory":
                        clock[0] = 42.0
                    return complete

                def acquire_metadata(*args, **kwargs):
                    if expired_at == "metadata":
                        clock[0] = 42.0
                    return metadata

                with self.subTest(selection=selection, expired_at=expired_at), \
                        patch.object(checks, "time", SimpleNamespace(monotonic=lambda: clock[0])), \
                        patch.object(checks, "expected_python_ids", side_effect=acquire_source) as source, \
                        patch.object(checks, "signing_regression_metadata", side_effect=acquire_metadata) as catalog, \
                        patch.object(checks, "_python_capture_partition", side_effect=AssertionError("partition after acquisition expiry")):
                    with self.assertRaisesRegex(checks.CheckError, "DEADLINE_EXPIRED"):
                        acquire()
                    self.assertEqual((source.call_count, catalog.call_count), expected_calls)
        for selection in ("native", "healthy", "all", None, True, []):
            with self.subTest(invalid_selection=selection), \
                    patch.object(checks, "expected_python_ids", side_effect=AssertionError("invalid acquisition")), \
                    self.assertRaisesRegex(checks.CheckError, "PYTHON_CAPTURE_SELECTION"):
                checks.python_capture_snapshot(ROOT, selection, deadline=42.0)

    def test_fixed_poison_partitions_preserve_full_wheel_and_authority_disjoint_union(self):
        checks = ci_module("ci_checks")
        # Extending the neutral singleton union cannot expand UNKNOWN disposal.
        self.assertEqual(checks.PYTHON_POISON_CASES, _PYTHON_POISON_FIXTURES)
        self.assertEqual(checks.PYTHON_FRESH_CASES, _PYTHON_FRESH_FIXTURES)
        self.assertEqual(checks.PYTHON_POISON_PARTITIONS, tuple(name for name, _ in _PYTHON_POISON_FIXTURES))
        self.assertEqual(checks.PYTHON_FRESH_PARTITIONS, tuple(name for name, _ in _PYTHON_FRESH_FIXTURES))
        self.assertEqual(checks.PYTHON_POISON_IDS, tuple(identifier for _, identifier in _PYTHON_POISON_FIXTURES))
        self.assertEqual(checks.PYTHON_FRESH_IDS, tuple(identifier for _, identifier in _PYTHON_FRESH_FIXTURES))
        self.assertEqual(controller_module().PYTHON_POISON_PARTITIONS, checks.PYTHON_POISON_PARTITIONS)
        self.assertEqual(controller_module().PYTHON_FRESH_PARTITIONS, checks.PYTHON_FRESH_PARTITIONS)
        self.assertFalse(set(checks.PYTHON_POISON_PARTITIONS) & set(checks.PYTHON_FRESH_PARTITIONS))
        self.assertFalse(set(checks.PYTHON_POISON_IDS) & set(checks.PYTHON_FRESH_IDS))
        poison = tuple(identifier for _name, identifier in _PYTHON_SINGLETON_FIXTURES)
        parts = tuple(name for name, _identifier in _PYTHON_SINGLETON_FIXTURES)
        self.assertEqual(checks.PYTHON_SINGLETON_CASES, _PYTHON_SINGLETON_FIXTURES)
        self.assertEqual(checks.PYTHON_SINGLETON_IDS, poison)
        self.assertEqual(checks.PYTHON_SINGLETON_PARTITIONS, parts)
        self.assertEqual(controller_module().PYTHON_SINGLETON_PARTITIONS, parts)
        self.assertEqual(len(set(parts)), len(parts))
        self.assertEqual(len(set(poison)), len(poison))
        healthy = ("unit.synthetic.Contracts.test_first", "unit.synthetic.Contracts.test_second")
        delegated, requirements = _g_metadata_fixture("ubuntu-24.04")
        complete = tuple(sorted(healthy + poison + delegated))
        for selection in ("full", "wheel"):
            with patch.object(checks, "expected_python_ids", return_value=complete) as source, \
                    patch.object(checks, "signing_regression_metadata", return_value=(delegated, requirements)) as metadata:
                self.assertEqual(checks.python_capture_ids(ROOT, selection, "all", deadline=42.0), complete)
                self.assertEqual(checks.python_capture_ids(ROOT, selection, "healthy", deadline=42.0), healthy)
                self.assertEqual(checks.python_capture_ids(ROOT, selection, "delegated", deadline=42.0), delegated)
                selected = [checks.python_capture_ids(ROOT, selection, name, deadline=42.0) for name in parts]
                self.assertEqual(selected, [(identifier,) for identifier in poison])
                self.assertEqual(tuple(sorted(healthy + delegated + tuple(identifier for ids in selected for identifier in ids))), complete)
                self.assertTrue(all(call.args == (ROOT, selection) and call.kwargs == {"deadline": 42.0}
                                    for call in source.call_args_list))
                self.assertTrue(all(call.args == (ROOT, "ubuntu-24.04") and call.kwargs == {"deadline": 42.0}
                                    for call in metadata.call_args_list))
                for invalid in ("ordinary", "authority", "all-poison", poison[0], None, True, []):
                    with self.assertRaises(checks.CheckError):
                        checks.python_capture_ids(ROOT, selection, invalid)
        authority = checks.NATIVE_AUTHORITY_IDS
        with patch.object(checks, "expected_python_ids", return_value=tuple(sorted(authority + complete))), \
                patch.object(checks, "signing_regression_metadata", return_value=(delegated, requirements)) as metadata:
            self.assertEqual(checks.native_partition_ids(ROOT, "authority"), authority)
            metadata.assert_called_once_with(ROOT, "macos-26", deadline=None)
            self.assertEqual(checks.native_partition_ids(ROOT, "ordinary"), healthy)
            self.assertEqual(checks.native_partition_ids(ROOT, "delegated"), delegated)
            self.assertEqual(tuple(checks.native_partition_ids(ROOT, part) for part in parts),
                             tuple((identifier,) for identifier in poison))
        for changed in (healthy, tuple(sorted(healthy + poison[:1])), tuple(sorted(complete + poison[:1])),
                        tuple(reversed(complete)), poison, list(complete)):
            with patch.object(checks, "expected_python_ids", return_value=changed), \
                    patch.object(checks, "signing_regression_metadata", return_value=(delegated, requirements)), \
                    self.assertRaises(checks.CheckError):
                checks.python_capture_ids(ROOT, "full", "healthy")
        for changed in ((), list(delegated), tuple(reversed(delegated)), delegated + delegated[:1],
                        (True,), delegated + ("unit.test_foreign.Contracts.test_unknown",),
                        tuple(sorted(delegated + poison[:1])), tuple(sorted(delegated + authority[:1]))):
            with self.subTest(delegated=changed), \
                    self.assertRaisesRegex(checks.CheckError, "PYTHON_DELEGATED_INVENTORY"):
                checks._python_capture_partition(complete, "healthy", changed)
        for missing in delegated:
            with self.subTest(missing_delegated=missing), \
                    self.assertRaisesRegex(checks.CheckError, "PYTHON_DELEGATED_INVENTORY"):
                checks._python_capture_partition(tuple(identifier for identifier in complete if identifier != missing),
                                                 "all", delegated)
        with self.assertRaisesRegex(checks.CheckError, "PYTHON_CAPTURE_UNION"):
            checks._python_capture_partition(tuple(sorted(poison + delegated)), "healthy", delegated)
        for missing in poison:
            incomplete = tuple(identifier for identifier in complete if identifier != missing)
            for selection in ("full", "wheel", "native"):
                inventory = tuple(sorted(authority + incomplete)) if selection == "native" else incomplete
                with self.subTest(selection=selection, missing=missing), \
                        patch.object(checks, "expected_python_ids", return_value=inventory), \
                        patch.object(checks, "signing_regression_metadata", return_value=(delegated, requirements)), \
                        self.assertRaisesRegex(checks.CheckError, "PYTHON_POISON_INVENTORY"):
                    if selection == "native":
                        checks.native_partition_ids(ROOT, "ordinary")
                    else:
                        checks.python_capture_ids(ROOT, selection, "healthy")
        for selection in ("native", "all", None, True, []):
            with self.assertRaises(checks.CheckError):
                checks.python_capture_ids(ROOT, selection, "healthy")

    def test_python_healthy_discovery_withholds_poison_and_delegated_and_stops_on_actual_adverse_callbacks(self):
        checks = ci_module("ci_checks")
        poison = checks.PYTHON_SINGLETON_IDS
        delegated, requirements = _g_metadata_fixture("ubuntu-24.04")
        store_rows = tuple((subcase, checks.STORE_NATIVE_PREFIX + method)
                           for subcase, method in checks.STORE_NATIVE_ROWS)
        store_ids = tuple(sorted({identifier for _, identifier in store_rows}))
        self.assertEqual((len(store_rows), len(store_ids)), (15, 7))
        healthy = tuple(f"unit.synthetic.HealthyContracts.test_{name}" for name in ("first", "subject", "third"))
        complete = tuple(sorted(healthy + poison + delegated))
        for selection in ("full", "wheel"):
            native_store = store_ids if selection == "full" else ()
            outcomes = ("success", "allowed-skip", "error", "failure", "skip", "subtest", "expected-failure", "unexpected-success",
                        "missing-poison", "missing-delegated", "duplicate-discovery")
            outcomes += ("missing-store", "duplicate-store") if selection == "full" else ("unexpected-store",)
            for outcome in outcomes:
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
                            if self.identifier in poison + delegated + store_ids:
                                raise AssertionError("a poison/delegated/Store fixture must never execute in the healthy capture")
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
                              Fixture(healthy[2]), *(Fixture(identifier) for identifier in poison + delegated + native_store)]
                    if outcome == "missing-poison":
                        loaded = [test for test in loaded if test.id() != poison[0]]
                    elif outcome == "missing-delegated":
                        loaded = [test for test in loaded if test.id() != delegated[-1]]
                    elif outcome == "duplicate-discovery":
                        loaded.append(Fixture(poison[0]))
                    elif outcome == "missing-store":
                        loaded = [test for test in loaded if test.id() != store_ids[0]]
                    elif outcome in {"duplicate-store", "unexpected-store"}:
                        loaded.append(Fixture(store_ids[0]))
                    suite = unittest.TestSuite(loaded)
                    framework = SimpleNamespace(TestSuite=unittest.TestSuite, TextTestResult=unittest.TextTestResult,
                        TextTestRunner=RetainingRunner,
                        TestLoader=lambda: SimpleNamespace(errors=[], discover=lambda *_args, **_kwargs: suite))

                    def store_catalog(source_root, phase, *, deadline):
                        self.assertEqual((source_root, phase, deadline), (ROOT, "source", 1000.0))
                        return store_rows  # Fixed DATA only; no Store test/helper is imported or executed.

                    with patch.object(checks, "unittest", framework), \
                            patch.object(checks, "expected_python_ids", return_value=complete), \
                            patch.object(checks, "signing_regression_metadata", return_value=(delegated, requirements)), \
                            patch.object(checks, "store_lane_native_rows", side_effect=store_catalog) as observed_store, \
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
                            if outcome in {"missing-poison", "missing-delegated", "duplicate-discovery",
                                           "missing-store", "duplicate-store", "unexpected-store"}:
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
                    if selection == "full":
                        observed_store.assert_called_once_with(ROOT, "source", deadline=1000.0)
                    else:
                        observed_store.assert_not_called()
                    self.assertFalse(set(events) & set(poison + delegated))
                    self.assertFalse({row["id"] for row in observations} & set(poison + delegated))
                    self.assertFalse(set(events) & set(store_ids))
                    self.assertFalse({row["id"] for row in observations} & set(store_ids))

    def test_native_partition_authority_is_exact_and_cannot_silently_expand(self):
        checks = ci_module("ci_checks")
        deadline = time.monotonic() + 30.0
        complete = checks.expected_python_ids(ROOT, "native", deadline=deadline)
        authority = checks.native_partition_ids(ROOT, "authority", deadline=deadline)
        ordinary = checks.native_partition_ids(ROOT, "ordinary", deadline=deadline)
        delegated = checks.native_partition_ids(ROOT, "delegated", deadline=deadline)
        native_metadata = checks.signing_regression_metadata(ROOT, "macos-26", deadline=deadline)

        def observed_inventory(source_root, selection, *, deadline):
            self.assertEqual((source_root, selection, deadline), (ROOT, "native", original_deadline))
            checks._remaining(deadline, 3300)
            return complete

        def observed_metadata(source_root, platform, *, deadline):
            self.assertEqual((source_root, platform, deadline), (ROOT, "macos-26", original_deadline))
            checks._remaining(deadline, 3300)
            return native_metadata

        # Source acquisition is exercised above and below. Reuse those actual
        # immutable observations for the classification matrix instead of parsing
        # the same entire checkout and metadata once for every singleton.
        original_deadline = deadline
        poison = []
        with patch.object(checks, "expected_python_ids", side_effect=observed_inventory) as inventory, \
                patch.object(checks, "signing_regression_metadata", side_effect=observed_metadata) as metadata:
            for name, identifier in _PYTHON_SINGLETON_FIXTURES:
                selected = checks.native_partition_ids(ROOT, name, deadline=deadline)
                self.assertEqual(selected, (identifier,))
                poison.extend(selected)
            self.assertEqual(inventory.call_count, 76)
            self.assertEqual(metadata.call_count, 76)
        poison = tuple(poison)
        self.assertEqual(authority, checks.NATIVE_AUTHORITY_IDS)
        self.assertEqual(len(authority), 5)
        self.assertTrue(ordinary)
        self.assertFalse(set(authority) & set(ordinary))
        self.assertEqual(tuple(sorted(authority + ordinary + poison + delegated)), complete)
        self.assertEqual(set(poison), {identifier for _name, identifier in _PYTHON_SINGLETON_FIXTURES})
        self.assertEqual(len(set(authority + ordinary + poison + delegated)), len(complete))
        self.assertEqual(delegated, native_metadata[0])
        linux_delegated = checks.signing_regression_metadata(ROOT, "ubuntu-24.04", deadline=deadline)[0]
        self.assertEqual(len(delegated), 86)
        self.assertEqual(len(linux_delegated), 84)
        self.assertEqual(set(delegated) - set(linux_delegated), set(_G_DARWIN_ONLY_METHODS))
        self.assertTrue(set(linux_delegated) <= set(delegated))
        for selection in ("full", "wheel"):
            linux, metadata = checks.python_capture_snapshot(ROOT, selection, deadline=deadline)
            self.assertEqual(linux["delegated"], linux_delegated)
            self.assertEqual(metadata[0], linux_delegated)
            self.assertTrue(set(_G_DARWIN_ONLY_METHODS) <= set(linux["healthy"]))
        self.assertEqual(checks.native_partition_ids(ROOT, "all", deadline=deadline), complete)
        for prefix in ("unit.test_native_process.", "unit.test_profile_process_owner.", "unit.test_inspection_budget."):
            self.assertTrue(any(identifier.startswith(prefix) for identifier in ordinary))
            self.assertFalse(any(identifier.startswith(prefix) for identifier in authority))
        self.assertEqual(checks.NATIVE_PATTERNS, (
            "test_ios_profile_authority.py", "test_ios_profile_trust.py", "test_ios_profile_installation.py",
            "test_ios_entitlements.py", "test_operation_recovery.py", "test_default_cancellation.py",
            "test_profile_processes.py", "test_macho_native.py",
            "test_native_process.py", "test_profile_process_owner.py", "test_inspection_budget.py",
            "test_local_signing.py", "test_local_signing_recovery.py", "test_local_signing_native.py",
            "test_local_signing_composition.py", "test_owned_process.py", "test_owned_process_callers.py",
            "test_owned_process_failures.py", "test_local_signing_failures.py", "test_local_signing_profile_identity.py",
            "test_local_signing_persistent.py", "test_local_signing_matrix.py", "test_local_signing_owner_loss.py",
            "test_command_loader_loss.py", "test_command_fence_failure.py", "test_local_signing_attempts.py", "test_command_account_lifecycle.py",
            "test_build_inputs.py", "test_checked_files.py", "test_source_observation.py",
            "test_credentials_metadata.py", "test_cli_and_build.py", "test_app_private.py"))
        self.assertEqual(set(checks.WHEEL_PATTERNS), {
            "test_init_transaction.py", "test_ios_entitlements.py", "test_ios_plist_binary.py",
            "test_native_process.py", "test_profile_process_owner.py", "test_default_cancellation.py",
            "test_profile_processes.py", "test_inspection_budget.py", "test_ios_profile_installation.py",
            "test_ios_profile_trust.py", "test_ios_profile_authority.py", "test_operation_recovery.py",
            "test_local_signing.py", "test_local_signing_recovery.py", "test_local_signing_native.py",
            "test_local_signing_composition.py", "test_owned_process.py", "test_owned_process_callers.py",
            "test_owned_process_failures.py", "test_local_signing_failures.py", "test_local_signing_profile_identity.py",
            "test_local_signing_persistent.py", "test_local_signing_matrix.py", "test_local_signing_owner_loss.py",
            "test_command_loader_loss.py", "test_command_fence_failure.py", "test_local_signing_attempts.py", "test_command_account_lifecycle.py",
            "test_build_inputs.py", "test_build_inputs_cli.py", "test_checked_files.py", "test_source_observation.py",
            "test_ios_correspondence.py", "test_credentials_metadata.py", "test_cli_and_build.py"})
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
            "unit.test_local_signing_composition.SigningCompositionTests": (
                "full_preflight_shares_one_guard_through_early_authentication_signing_build_and_late_authentication",
                "real_early_and_late_profile_cleanup_signals_under_full_preflight_never_return_cancelled_content",
            ),
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
        native.add("unit.test_local_signing_native.SigningDarwinABITests.test_real_header_layout_and_local_volume_match_ctypes_without_private_state")
        native.add("unit.test_checked_files.NativeCheckedFilesTests.test_actual_tmp_var_folders_and_physical_spellings_select_identical_private_bytes")
        self.assertEqual(checks.linux_allowed_skips(), frozenset(native))
        self.assertEqual(len(native), 21)
        wheel = checks.expected_python_ids(ROOT, "wheel")
        wheel_skips = set(wheel) & native
        self.assertEqual(wheel_skips, _WHEEL_DARWIN_SKIP_IDS)
        self.assertEqual(len(wheel_skips), 9)
        checks.validate_test_outcomes(wheel, [{"id": identifier, "outcome": "skip" if identifier in wheel_skips else "ok"}
                                             for identifier in wheel], "linux")
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
        # The separate partition-authority contract pins the exact catalog.
        # This fixture tests static discovery, duplicate methods and omissions.
        names = checks.WHEEL_PATTERNS
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
            ".gitignore": (b".mobile-release/\n.mobile-release-init-prepare/\n.mobile-release-init/\n.mobile-release-init-cleanup/\n"
                           b".mobile-release-metadata-text-prepare/\n.mobile-release-metadata-text/\n"
                           b".mobile-release-metadata-text-cleanup/\n"
                        b".mobile-release-version-prepare/\n.mobile-release-version/\n.mobile-release-version-cleanup/\n"),
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

    def test_jdk_policy_transport_reaches_owned_callers_and_restores_original_binding(self):
        """Actual Android policy callers, inert transport; no native/owner proof."""
        from mobile_release import android, owned_process

        checks = ci_module("ci_checks")
        original, original_module, original_run = android.run_owned, android.subprocess, subprocess.run
        scenarios = ("outside-warning-window", "inside-warning-window", "expired", "not-yet-valid")
        warnings_by_case = (
            "", "This jar contains entries whose signer certificate will expire within six months.\n",
            "This jar contains entries whose signer certificate has expired.\n",
            "This jar contains entries whose signer certificate is not yet valid.\n",
        )
        options = ["-Xms32m", "-Xmx256m", "-XX:MaxMetaspaceSize=256m",
                   "-XX:CompressedClassSpaceSize=128m", "-XX:ReservedCodeCacheSize=128m"]

        def deny_original(*_args, **_kwargs):
            self.fail("the policy fixture must never invoke the native command owner")

        for variant in ("success", "transport-failure", "custody-drift"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory(prefix="mrk-jdk-policy-contract-") as temporary:
                root = Path(temporary).resolve()
                home, work = root / "jdk", root / "work"
                (home / "bin").mkdir(parents=True)
                work.mkdir()
                tools = {name: str(home / "bin" / name) for name in ("java", "keytool", "jarsigner")}
                for path in tools.values():
                    Path(path).write_bytes(b"Non-executable tool-location fixture.\n")
                environment = {"JAVA_HOME": str(home), "PATH": str(home / "bin"), "LANG": "ambient", "LC_ALL": "ambient",
                               "JAVA_TOOL_OPTIONS": "inert excluded setting", "MOBILE_RELEASE_DEPENDENCY_TOKEN": "synthetic-only"}
                inspection = {name: environment[name] for name in ("JAVA_HOME", "PATH")}
                inspection.update(LANG="C", LC_ALL="C")
                deadline, calls, product_calls = time.monotonic() + 30.0, [], []
                failure = checks.CheckError("JDK_INERT_TRANSPORT_FAILURE")

                def child(argv, **kwargs):
                    # Every possible process boundary is replaced before entry.
                    self.assertIs(android.subprocess, original_module)
                    self.assertIs(subprocess.run, original_run)
                    self.assertEqual(set(kwargs), {"cwd", "deadline", "seconds", "environment", "status", "echo"})
                    self.assertEqual(kwargs["deadline"], deadline)
                    name = Path(argv[0]).name
                    self.assertEqual(argv[0], tools[name])
                    flags = options if name == "java" else ["-J" + option for option in options]
                    self.assertEqual(argv[1:1 + len(flags)], flags)
                    arguments = argv[1 + len(flags):]
                    if not calls:
                        self.assertEqual((name, arguments), ("java", ["-version"]))
                        self.assertEqual(kwargs, {"cwd": work / "jdk-signers", "deadline": deadline,
                            "seconds": 30, "environment": inspection, "status": 0, "echo": True})
                        calls.append((name, arguments))
                        return subprocess.CompletedProcess(argv, 0, b"", b'openjdk version "21.0.9"\n')
                    index, step = divmod(len(calls) - 1, 6)
                    scenario = scenarios[index]
                    self.assertEqual(kwargs["cwd"], work / "jdk-signers" / scenario)
                    self.assertEqual(name, ("keytool", "jarsigner", "jarsigner", "keytool", "jarsigner", "keytool")[step])
                    self.assertEqual(arguments[0], ("-genkeypair", "-keystore", "-verify", "-exportcert", "-verify", "-printcert")[step])
                    expected_env = dict(inspection)
                    if step in {0, 1, 3}:
                        expected_env["MRK_SYNTHETIC_PASSWORD"] = "disposable-test-password"
                    self.assertEqual(kwargs["environment"], expected_env)
                    self.assertEqual(kwargs["seconds"], 30 if step == 5 else 120)
                    self.assertEqual(kwargs["status"], 4 if step in {2, 4} else 0)
                    self.assertIs(kwargs["echo"], step != 3)
                    calls.append((name, arguments))
                    if step >= 4:
                        self.assertIsNot(android.run_owned, deny_original)
                        self.assertIs(owned_process.run_owned, deny_original)
                        product_calls.append(name)
                        expected_args = (["-verify", "-strict"] if step == 4 else ["-printcert", "-jarfile"])
                        self.assertEqual(arguments, [*expected_args, str(kwargs["cwd"] / "synthetic.jar")])
                    else:
                        self.assertIs(android.run_owned, deny_original)
                    if step == 5 and variant == "transport-failure":
                        raise failure
                    if step == 5 and variant == "custody-drift":
                        android.run_owned = object()
                    certificate = b"\x30synthetic-policy-contract:" + scenario.encode("ascii")
                    stdout, stderr = b"", b""
                    if step in {2, 4}:
                        stdout = b"jar verified, with signer errors.\n"
                        stderr = (
                            "This jar contains entries whose certificate chain is invalid. Reason: "
                            "PKIX path building failed: synthetic: unable to find valid certification path to requested target\n"
                            "This jar contains entries whose signer certificate is self-signed.\n" + warnings_by_case[index]
                        ).encode("ascii")
                    elif step == 3:
                        stdout = certificate
                    elif step == 5:
                        stdout = ("Signer #1:\n\nCertificate #1:\n SHA256: "
                                  + hashlib.sha256(certificate).hexdigest() + "\n").encode("ascii")
                    return subprocess.CompletedProcess(argv, kwargs["status"], stdout, stderr)

                with patch.object(checks, "sys", SimpleNamespace(platform="linux", flags=SimpleNamespace(isolated=1, dont_write_bytecode=1))), \
                        patch.object(checks, "os", SimpleNamespace(**{**vars(os), "getuid": lambda: 1000, "environ": environment})), \
                        patch.object(checks, "shutil", SimpleNamespace(which=tools.get)), \
                        patch.object(android, "os", SimpleNamespace(environ=environment)), \
                        patch.object(owned_process, "run_owned", deny_original), \
                        patch.object(android, "run_owned", deny_original), patch.object(checks, "_run_child", child):
                    if variant == "success":
                        result = checks.jdk_signers(ROOT, work, deadline)
                        self.assertEqual(result["version"], "21.0.9")
                        self.assertEqual(len(result["native_calls"]), 25)
                        self.assertEqual([row["id"] for row in result["cases"]], list(scenarios))
                        self.assertEqual([row["accepted"] for row in result["cases"]], [True, False, False, False])
                        self.assertEqual(len({row["fingerprint"] for row in result["cases"]}), 4)
                    else:
                        expected = "JDK_INERT_TRANSPORT_FAILURE" if variant == "transport-failure" else "JDK_BINDING_CUSTODY"
                        with self.assertRaisesRegex(checks.CheckError, "^" + expected + "$") as caught:
                            checks.jdk_signers(ROOT, work, deadline)
                        if variant == "transport-failure":
                            self.assertIs(caught.exception, failure)
                    self.assertIs(android.run_owned, deny_original)
                    self.assertIs(owned_process.run_owned, deny_original)
                self.assertEqual(len(calls), 25 if variant == "success" else 7)
                self.assertEqual(product_calls, ["jarsigner", "keytool"] * (4 if variant == "success" else 1))
                self.assertIs(android.run_owned, original)
                self.assertIs(android.subprocess, original_module)
                self.assertIs(subprocess.run, original_run)

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
