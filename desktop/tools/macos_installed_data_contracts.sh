set -euo pipefail
set -o noclobber
umask 077
"$MRK_PYTHON" -I -S -B - <<'PY_DATA_CONTRACTS'
import hashlib, json, os, plistlib, re, selectors, stat, subprocess, sys, time
from pathlib import Path
build_target = os.environ["MRK_MACOS_TARGET"]
machines = {"aarch64-apple-darwin": "arm64", "x86_64-apple-darwin": "x86_64"}
if build_target not in machines: raise ValueError("native-data-target")
native_machine = machines[build_target]
rust_bin = "/Users/runner/.rustup/toolchains/stable-" + build_target + "/bin"

def sig(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
def read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 <= before.st_size <= limit:
            raise ValueError("fixed DATA input shape")
        body = bytearray()
        while len(body) <= before.st_size:
            part = os.read(fd, min(65536, before.st_size + 1 - len(body)))
            if not part: break
            body.extend(part)
        if len(body) != before.st_size or sig(before) != sig(os.fstat(fd)) or sig(before) != sig(os.lstat(path)):
            raise ValueError("original DATA input changed")
        return bytes(body)
    finally:
        os.close(fd)
def put(name, body):
    if not re.fullmatch(r"[a-z0-9.-]+", name) or len(body) > 4 * 1024 * 1024:
        raise ValueError("fixed output bound")
    path = data / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(body)
        while view:
            count = os.write(fd, view)
            if count <= 0: raise OSError("output write refused")
            view = view[count:]
        os.fsync(fd)
        saved = sig(os.fstat(fd))
        if saved != sig(os.lstat(path)) or saved[6] != len(body): raise ValueError("output original changed")
    finally:
        os.close(fd)
    return {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(), "identity": saved}
def digest_original(fd, path, before):
    if before != sig(os.fstat(fd)) or before != sig(os.lstat(path)):
        raise ValueError("original test artifact changed")
    digest = hashlib.sha256()
    offset = 0
    while offset < before[6]:
        part = os.pread(fd, min(65536, before[6] - offset), offset)
        if not part: raise ValueError("artifact EOF")
        digest.update(part); offset += len(part)
    if os.pread(fd, 1, offset) or before != sig(os.fstat(fd)) or before != sig(os.lstat(path)):
        raise ValueError("original test artifact changed")
    return digest.hexdigest()

if (sys.platform != "darwin" or os.name != "posix" or os.uname().sysname != "Darwin"
        or os.uname().machine != native_machine or os.getuid() == 0 or os.geteuid() != os.getuid()
        or sys.version_info[:3] != (3, 14, 7) or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode):
    raise ValueError("actual selected native Darwin LP64 isolated Python required")
root = Path(os.environ["MRK_MACOS_WORK"])
checkout = Path(os.environ["GITHUB_WORKSPACE"])
if (root.parent != Path("/Users/runner/work/_temp") or not root.name.startswith("mrk-macos-installed.")
        or checkout != Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
        or os.environ["CARGO_TARGET_DIR"] != str(root / "cargo-target")):
    raise ValueError("same original job/source/Cargo cache required")
root_before = sig(os.lstat(root))
if not stat.S_ISDIR(root_before[2]) or root_before[3] != os.getuid() or root_before[2] & 0o077:
    raise ValueError("original private work root required")
binding = json.loads(read(root / "source-binding.json", 65536))
inventory_bytes = read(root / "source-inventory.json", 2 * 1024 * 1024)
inventory = json.loads(inventory_bytes)
if (binding["source"] != os.environ["GITHUB_SHA"] or binding["workflowSource"] != os.environ["GITHUB_WORKFLOW_SHA"]
        or binding["source"] != binding["workflowSource"] or inventory["source"] != binding["source"]
        or binding.get("target") != build_target
        or inventory["tree"] != binding["tree"] or binding["workDirectory"] != [root_before[0], root_before[1], root_before[3]]):
    raise ValueError("original checkout/source binding")
rust_binding = json.loads(read(root / "effective-rust-toolchain.json", 16384))
if (rust_binding["source"] != binding["source"] or rust_binding["workflowSource"] != binding["workflowSource"]
        or rust_binding["runId"] != os.environ["GITHUB_RUN_ID"]
        or rust_binding["runAttempt"] != os.environ["GITHUB_RUN_ATTEMPT"]
        or rust_binding.get("target") != build_target
        or rust_binding["cwd"] != "desktop/src-tauri" or rust_binding["autoInstall"] is not False):
    raise ValueError("effective Rust toolchain is not bound to this original build")
source_rows = {row["path"]: row for row in inventory["files"]}
if len(source_rows) != len(inventory["files"]): raise ValueError("duplicate source row")
source_names = (
    ".github/workflows/desktop-macos-installed.yml", "desktop/src-tauri/Cargo.toml",
    "desktop/src-tauri/tests/installed_shell_observation.rs", "desktop/src-tauri/src/installed_shell_observation_macos.rs",
    "desktop/src-tauri/src/runtime.rs", "desktop/src-tauri/src/supervisor.rs",
    "desktop/src-tauri/src/vault_format.rs", "desktop/src-tauri/src/vault_crypto.rs", "desktop/src-tauri/src/vault_store.rs",
    "src/mobile_release/api/_candidate_evidence.py", "tests/desktop/test_workflow_transaction_profile.py",
    "tests/desktop/test_candidate_evidence.py", "tests/desktop/test_lifecycle_evidence.py",
    "tests/desktop/test_metadata_images.py", "tests/desktop/test_metadata_images_edit.py",
    "tests/desktop/test_metadata_images_recovery.py", "tests/desktop/test_metadata_text.py",
    "src/mobile_release/metadata_images.py", "src/mobile_release/metadata_images_edit.py",
    "src/mobile_release/metadata_images_recovery.py", "src/mobile_release/init_workspace_custody.py",
    "desktop/src-tauri/build.rs",
    "desktop/src-tauri/src/installed_runtime_macos.rs",
    "desktop/src-tauri/src/edit_owner.rs",
    "desktop/src-tauri/src/saved_command_owner.rs",
    "desktop/src-tauri/src/asset_source_macos.rs",
    "desktop/src-tauri/src/shell_macos_dialog.rs",
    "desktop/src-tauri/src/android_build_wiring_tests.rs",
    "desktop/github_preflight_bootstrap.py",
    "desktop/github_release_bootstrap.py",
    "tests/desktop/test_github_preflight_frames.py",
    "tests/desktop/test_github_preflight.py",
    "tests/desktop/test_github_release.py",
    "src/mobile_release/_desktop_github_preflight_engine.py",
    "src/mobile_release/_desktop_github_engine.py",
    "src/mobile_release/_github_action_family.py",
    "src/mobile_release/_github_connection_transport.py",
    "src/mobile_release/_github_preflight_journal.py",
    "src/mobile_release/github_preflight.py",
    "src/mobile_release/github_release.py",
    "src/mobile_release/api/_github_connection.py",
    "src/mobile_release/api/_github_setup.py",
    "src/mobile_release/workflow_payloads.py",
    "templates/workflows/mobile-preflight.yml",
    "templates/workflows/mobile-candidate.yml",
    "templates/workflows/mobile-external-testing.yml",
    "templates/workflows/mobile-production-submit.yml",
    "tests/desktop/test_macos_normal_diagnostics_source.py",
    "desktop/native/macos-normal-ui/MRKNormalAppUITests/NormalAppUITests.swift",
    "desktop/native/macos-normal-ui/MRKNormalAppUITests/Fixtures/normal-project-v1.json",
    "desktop/src/components/EnvironmentDiagnostics.tsx",
    "desktop/src/environmentDiagnosticsController.ts",
    "desktop/src-tauri/src/environment_diagnostics_owner.rs",
    "desktop/src/components/OfflinePreflight.tsx",
    "desktop/src/components/ProjectRecovery.tsx",
    "desktop/src/components/Common.tsx",
    "desktop/src/offlinePreflight.ts",
    "desktop/src/projectRecoveryController.ts",
    "desktop/src/offlinePreflightProtocol.ts",
    "desktop/src/projectRecoveryProtocol.ts",
    "src/mobile_release/desktop_preflight.py",
    "src/mobile_release/desktop_project_recovery.py",
    "src/mobile_release/build_inputs.py",
    "src/mobile_release/discovery.py",
    "desktop/macos-installed-inputs/build-release.json",
    "desktop/src-tauri/src/macos_build_release.rs",
    "desktop/src-tauri/src/macos_install_fixed_paths.rs",
    "desktop/src-tauri/src/macos_install_paths.rs",
    "desktop/src-tauri/tauri.conf.json",
    "tests/desktop/test_android_build_tools.py",
    "src/mobile_release/android_build_tools.py",
    "src/mobile_release/android_build_tools_macos.py",
    "src/mobile_release/android_build_operation.py",
    "src/mobile_release/_desktop_android_build_files.py",
    "src/mobile_release/android.py",
    "src/mobile_release/credentials.py",
    "src/mobile_release/local_signing.py",
    "desktop/tools/macos_installed_data_contracts.sh",
)
source_bodies = {}
for name in source_names:
    row = source_rows[name]
    body = read(checkout / name, 2 * 1024 * 1024)
    if len(body) != row["size"] or hashlib.sha256(body).hexdigest() != row["sha256"]:
        raise ValueError("selected source changed since original inventory")
    source_bodies[name] = body
observer = source_bodies["desktop/src-tauri/src/installed_shell_observation_macos.rs"].decode("utf-8", "strict")
start = "fn observer_data_checks() -> bool {"
stop = "\nfn observe("
if observer.count(start) != 1 or observer.count(stop) != 1: raise ValueError("fixed aggregate source boundary")
aggregate = observer.split(start, 1)[1].split(stop, 1)[0]
# These are direct SOURCE call names, not invented libtest counts.
contract_calls = re.findall(r"\b((?:[A-Za-z_]\w*::)*(?:assert_\w+|[A-Za-z_]\w*data_checks?|data_checks|macos_\w+_contract))\(", aggregate)
names = [
    "test_workflow_transaction_profile.WorkflowUpdateFilesystemTests.test_failure_after_first_real_replacement_restores_originals_and_primary",
    "test_workflow_transaction_profile.WorkflowUpdateFilesystemTests.test_mixed_update_create_preserve_commits_and_cleans_original_backups",
    "test_candidate_evidence.CandidateEvidenceAdmissionTests.test_platform_and_posix_prerequisites_control_both_methods_without_io",
    "test_candidate_evidence.CandidateEvidenceAdmissionTests.test_darwin_requires_every_original_posix_descriptor_primitive",
    "test_candidate_evidence.CandidateEvidenceAdmissionTests.test_unsupported_profiles_are_closed_without_io",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_darwin_route_uses_the_original_host_reader_without_more_authority",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_android_and_ios_use_real_validators_and_exact_redacted_contract",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_declared_decimal_precision_and_distinct_manifest_run_roles",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_forged_self_consistency_never_claims_provenance_or_artifact_authority",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_artifact_projection_has_stable_role_order_not_document_order",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_only_three_fixed_documents_are_opened_no_publishers_or_payloads",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_missing_is_incomplete_and_present_invalid_dominates_missing",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_malformed_json_duplicates_floats_nonfinite_and_schema_stage_self_digest",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_actual_candidate_intent_receipt_cross_bindings_not_only_self_digests",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_private_or_legacy_validator_messages_are_never_forwarded",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_byte_integer_node_depth_and_projection_limits_are_not_policy_invalid",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_exact_two_mib_each_and_six_mib_total_are_admitted_without_extra_files",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_unrepresentable_valid_identifiers_and_large_run_text_are_limits",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_utf8_and_unsafe_root_refusals_are_constant",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_read_io_refusal_does_not_reflect_path_or_native_exception",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_original_root_identity_is_checked_before_any_document_read",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_root_parent_leaf_links_and_portable_aliases_are_not_followed",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_special_foreign_owner_and_foreign_device_refuse_before_leaf_open",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_changed_leaf_absence_and_ancestor_veto_even_nonconsistent_results",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_one_cooperative_deadline_includes_pure_validation_and_final_checks",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_descriptor_close_uncertainty_attempts_all_original_closes_once",
    "test_candidate_evidence.CandidateEvidenceObservationTests.test_original_iterator_close_uncertainty_is_not_incomplete",
    "test_lifecycle_evidence.LifecycleLayoutTests.test_closed_params_and_platform_before_io",
    "test_lifecycle_evidence.LifecycleEvidenceTests.test_darwin_routes_every_stage_through_the_original_shared_reader",
    "test_lifecycle_evidence.LifecycleEvidenceTests.test_three_real_layouts_reuse_policy_and_never_upgrade_authority",
    "test_lifecycle_evidence.LifecycleEvidenceTests.test_shared_fixtures_and_core_blocker_parity",
    "test_lifecycle_evidence.LifecycleEvidenceTests.test_platform_stage_intent_and_predecessor_disagreement_export_no_partial_history",
    "test_lifecycle_evidence.LifecycleEvidenceTests.test_missing_invalid_and_inconsistent_never_export_history",
    "test_lifecycle_evidence.LifecycleEvidenceTests.test_repeated_candidate_bytes_must_match_without_claiming_bundle_inventory",
    "test_lifecycle_evidence.LifecycleEvidenceTests.test_exact_document_and_aggregate_limits_require_real_eof",
    "test_lifecycle_evidence.LifecycleEvidenceTests.test_zero_remaining_refuses_next_nonempty_file_even_after_invalid_values",
    "test_lifecycle_evidence.LifecycleEvidenceTests.test_rejected_arrays_are_charged_before_top_level_kind_rejection",
    "test_lifecycle_evidence.LifecycleEvidenceTests.test_symlink_changed_and_original_cleanup_failures_withhold_results",
    "test_lifecycle_evidence.LifecycleEvidenceTests.test_observation_does_not_write_launch_or_contact_services",
    "test_metadata_images_edit.MetadataImagesEditTests.test_changed_sibling_target_or_saved_configuration_is_not_a_second_preview_or_write",
    "test_metadata_images_edit.MetadataImagesEditTests.test_directory_move_lost_return_preserves_owned_transition_for_original_and_restart_rollback",
    "test_metadata_images_edit.MetadataImagesEditTests.test_failure_after_committed_marker_never_retries_import_or_claims_false_success",
    "test_metadata_images_edit.MetadataImagesEditTests.test_image_only_limit_accepts_a_header_checked_image_larger_than_unchanged_global_limit",
    "test_metadata_images_edit.MetadataImagesEditTests.test_new_directory_import_is_one_shot_and_preserves_original_sources_and_saved_inputs",
    "test_metadata_images_edit.MetadataImagesEditTests.test_private_original_object_exclusions_protect_a_target_even_without_a_relative_source_name",
    "test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_00_actual_mixed_ready_rollback_preserves_old_identity_and_readonly_facts",
    "test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_actual_committed_target_is_checked_again_before_last_backup_cleanup",
    "test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_changed_saved_dependencies_targets_and_portable_alias_refuse_without_public_effects",
    "test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_cleanup_failure_after_owned_deletion_is_not_retried_and_new_inspection_can_finish",
    "test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_committed_and_rolled_back_cleanup_accept_only_complete_controls_and_admitted_data_subset",
    "test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_complete_preparing_between_and_owned_new_directory_states",
    "test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_current_revision_rechecks_config_siblings_targets_and_journal_identity_before_apply",
    "test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_idle_and_unreadable_configuration_never_manufacture_usable_baseline_or_recovery",
    "test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_incomplete_contradictory_or_foreign_control_proof_is_conflict_not_cleanup_authority",
    "test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_one_shot_consent_immutable_authority_and_discard_do_not_erase_inspected_commit",
    "test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_original_stop_after_owned_rollback_move_preserves_failure_and_requires_new_recovery",
    "test_metadata_images_recovery.MetadataImagesRecoveryFilesystemTests.test_terminal_fsync_failure_keeps_rolled_back_fact_without_cleanup_or_false_success",
    "test_github_preflight_frames.GitHubPreflightBootstrapTests.test_exact_linux_and_darwin_admit_only_the_fixed_engine_family",
    "test_github_preflight_frames.GitHubPreflightBootstrapTests.test_other_platforms_flags_and_unbound_paths_refuse_before_engine_entry",
    "test_github_release.GitHubReleaseBootstrapTests.test_exact_linux_and_darwin_admit_only_the_fixed_engine_family",
    "test_github_release.GitHubReleaseBootstrapTests.test_other_platforms_flags_and_unbound_paths_refuse_before_engine_entry",
    "test_github_preflight_frames.GitHubPreflightFrameTests.test_intent_and_run_are_exact_canonical_noncredential_records",
    "test_github_preflight_frames.GitHubPreflightFrameTests.test_intent_rejects_broadened_authority_and_modified_caller",
    "test_github_preflight_frames.GitHubPreflightFrameTests.test_initial_contains_no_credential_and_binds_exact_ready_digest",
    "test_github_preflight_frames.GitHubPreflightFrameTests.test_initial_and_go_frames_reject_extra_pipelined_duplicate_or_unbound_input",
    "test_github_preflight_frames.GitHubPreflightFrameTests.test_pending_is_fresh_native_scope_only_and_go_contains_no_token",
    "test_github_preflight_frames.GitHubPreflightFrameTests.test_final_result_preserves_accepted_uncertain_and_observed_distinctions",
    "test_github_release.GitHubReleaseFrameTests.test_full64_maximum_retained_records_fit_the_private_result_without_truncation",
    "test_github_release.GitHubReleaseFrameTests.test_protocol_journal_and_go_cannot_cross_preflight_family",
    "test_github_release.GitHubReleaseFrameTests.test_original_helper_waits_for_durable_intent_and_closes_before_final",
    "test_github_release.GitHubReleaseTransportTests.test_only_release_config_role_can_read_base64_overhead_in_all_framing_modes",
    "test_github_release.GitHubReleaseTransportTests.test_release_aggregate_and_original_deadline_are_never_renewed",
    "test_github_preflight.GitHubPreflightPolicyTests.test_caller_source_and_identity_fail_before_any_dispatch",
    "test_github_preflight.GitHubPreflightPolicyTests.test_dispatch_is_one_post_and_returned_id_is_not_workflow_success",
    "test_github_preflight.GitHubPreflightPolicyTests.test_changed_branch_during_consent_is_not_sent",
    "test_github_preflight.GitHubPreflightPolicyTests.test_lost_response_204_and_invalid_run_url_never_retry_or_claim_no_effect",
    "test_github_release.GitHubReleasePolicyTests.test_selection_is_closed_original_data_never_current_version_substitution",
    "test_github_release.GitHubReleasePolicyTests.test_single_dispatch_latches_uncertainty_and_refuses_replacement_source",
    "test_github_release.GitHubReleasePolicyTests.test_original_attempt_observation_requires_stage_jobs_not_build_repetition",
    "test_macos_normal_diagnostics_source.NormalDiagnosticsSourceTests.test_normal_diagnostics_observes_original_complete_report_and_settled_projection",
    "test_macos_normal_diagnostics_source.NormalDiagnosticsSourceTests.test_normal_diagnostics_workflow_has_one_bounded_original_result",
    "test_macos_normal_diagnostics_source.NormalDiagnosticsSourceTests.test_normal_saved_offline_and_empty_recovery_use_original_gui_only",
    "test_android_build_tools.MacToolAdmissionDataTests.test_mac_commands_use_exact_contents_home_private_environment_and_inspection_only",
    "test_android_build_tools.OwnerAndCommandDataTests.test_bundletool_requires_original_native_borrow_and_exact_snapshot",
]
if len(names) != 84 or len(set(names)) != 84: raise ValueError("fixed selection")
if hashlib.sha256(json.dumps(names, separators=(",", ":")).encode()).hexdigest() != "0fd968d2c78e233df8cc344ae3ff27d417bd3c76fb5bde42b3ea8d393f8e7a94":
    raise ValueError("fixed selected IDs digest")
data = root / "data-contracts"
os.mkdir(data, 0o700)
temporary = data / "tmp"
os.mkdir(temporary, 0o700)
temporary_fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
temporary_before = sig(os.fstat(temporary_fd))
clean = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/Users/runner", "USER": "runner", "LOGNAME": "runner",
         "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TZ": "UTC", "TMPDIR": str(temporary) + "/"}
# A fixed inline selection only; no discovery, generic CLI, Linux host spoof or project subprocess suite.
child_code = ("NAMES = " + repr(names) + "\nNATIVE_TARGET = " + repr(build_target)
              + "\nNATIVE_MACHINE = " + repr(native_machine) + "\n") + r'''
import importlib, json, os, stat, sys, tempfile, unittest
from pathlib import Path
checkout = Path(sys.argv[1])
temporary = Path(sys.argv[2])
expected = [int(value) for value in sys.argv[3:]]
def original_host():
    s = os.lstat(temporary)
    return (sys.platform == "darwin" and os.name == "posix" and os.uname().sysname == "Darwin"
            and NATIVE_TARGET in ("aarch64-apple-darwin", "x86_64-apple-darwin")
            and NATIVE_MACHINE == {"aarch64-apple-darwin": "arm64", "x86_64-apple-darwin": "x86_64"}[NATIVE_TARGET]
            and os.uname().machine == NATIVE_MACHINE and os.getuid() != 0 and os.geteuid() == os.getuid()
            and sys.version_info[:3] == (3, 14, 7) and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid] == expected
            and stat.S_ISDIR(s.st_mode) and not s.st_mode & 0o077
            and Path(tempfile.gettempdir()) == temporary)
if not original_host(): raise ValueError("actual native host and original private TMPDIR required")
sys.path[:0] = [str(checkout / "src"), str(checkout / "tests/desktop"), str(checkout / "tests")]
suite = unittest.TestSuite()
for name in NAMES:
    module, cls, method = name.split(".")
    if module not in ("test_workflow_transaction_profile", "test_candidate_evidence", "test_lifecycle_evidence",
                      "test_metadata_images_edit", "test_metadata_images_recovery",
                      "test_github_preflight_frames", "test_github_preflight", "test_github_release",
                      "test_macos_normal_diagnostics_source", "test_android_build_tools") or not method.startswith("test_"):
        raise ValueError("fixed selected method required")
    suite.addTest(getattr(importlib.import_module(module), cls)(method))
if suite.countTestCases() != 84 or [case.id() for case in suite] != NAMES:
    raise ValueError("exact original test IDs/count required")
result = unittest.TextTestRunner(verbosity=2, failfast=False).run(suite)
facts = {"testsRun": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
         "skipped": len(result.skipped), "expectedFailures": len(result.expectedFailures),
         "unexpectedSuccesses": len(result.unexpectedSuccesses), "testIds": NAMES, "actualHostBeforeAndAfter": bool(original_host())}
print(json.dumps(facts, sort_keys=True, separators=(",", ":")), flush=True)
raise SystemExit(0 if result.wasSuccessful() and facts["testsRun"] == 84 and facts["actualHostBeforeAndAfter"]
                 and not any(facts[key] for key in ("failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses")) else 1)
'''
receipt = {"schemaVersion": 1, "scope": "fixed-native-data-contracts-and-selected-host-python-regressions",
           "sourceCommit": binding["source"], "sourceTree": binding["tree"],
           "sourceInventorySha256": hashlib.sha256(inventory_bytes).hexdigest(),
           "sourceRows": [source_rows[name] for name in source_names], "toolBindings": binding["tools"], "effectiveRustToolchain": rust_binding,
           "python": {"executable": sys.executable, "version": sys.version, "actualPlatform": sys.platform, "actualMachine": os.uname().machine, "target": build_target},
           "cargoTargetDir": os.environ["CARGO_TARGET_DIR"], "temporaryOriginal": temporary_before,
           "buildBindings": {key: os.environ[key] for key in ("CARGO_TARGET_DIR", "MRK_BUNDLED_RUNTIME_MANIFEST_SHA256",
                             "MRK_BUNDLED_RUNTIME_SOURCE_SHA256", "MRK_BUNDLED_PROTOCOL_SHA256",
                             "MRK_MACOS_INSTALL_SOURCE_COMMIT", "MRK_GITHUB_PREFLIGHT_TOOLING_SHA",
                             "MRK_GITHUB_RELEASE_TOOLING_SHA", "MACOSX_DEPLOYMENT_TARGET", "DEVELOPER_DIR")},
           "pythonTestIds": names, "pythonExpectedCount": 84, "workflowFilesystemCount": 2, "imageFilesystemCount": 18, "evidenceReaderCount": 37,
           "githubActionCount": 22, "normalDiagnosticsSourceCount": 3, "androidBuildToolsCallerCount": 2,
           "frozenSelectionSha256": "0fd968d2c78e233df8cc344ae3ff27d417bd3c76fb5bde42b3ea8d393f8e7a94",
           "aggregate": {"name": "observer_data_checks", "count": 1, "harness": False, "libtestCount": None,
                         "sourceSha256": hashlib.sha256((start + aggregate).encode()).hexdigest(), "directSourceContractCalls": contract_calls},
           "commands": [], "passed": False, "nativeVaultTestsExecuted": False, "uiExecutedByThisBatch": False,
           "nativeTlsQualified": False, "allWorkerFinalityEstablished": False}
artifact_fd = None
failure = None
def filesystem_device(raw):
    # Apple df(path) resolves the containing filesystem. diskutil info
    # accepts its device/mountpoint, not an arbitrary subdirectory.
    lines = raw.decode("utf-8", "strict").splitlines()
    if (len(lines) != 2 or not raw.endswith(b"\n") or b"\r" in raw
            or lines[0].split() not in (
                ["Filesystem", "1024-blocks", "Used", "Available", "Capacity", "Mounted", "on"],
                ["Filesystem", "1024-blocks", "Used", "Avail", "Capacity", "Mounted", "on"])):
        raise ValueError("one fixed df header and filesystem row required")
    row = lines[1].split(None, 5)
    if (len(row) != 6 or not re.fullmatch(r"/dev/disk[0-9]+s[0-9]+(?:s[0-9]+)?", row[0])
            or any(not re.fullmatch(r"-?[0-9]{1,20}", number) for number in row[1:4])
            or not re.fullmatch(r"[0-9]{1,4}%", row[4]) or not row[5].startswith("/")
            or any(ord(character) < 32 or ord(character) == 127 for character in row[5])):
        raise ValueError("one local disk device and bounded mountpoint required")
    return {"device": row[0], "reportedMountPoint": row[5]}
def filesystem_volume(raw, selected):
    # diskutil's plist names positive volume writability explicitly.
    # A missing key is not a writable volume, and media writability
    # alone is not sufficient for a writable mounted filesystem.
    volume = plistlib.loads(raw)
    if not isinstance(volume, dict):
        raise ValueError("one diskutil volume dictionary required")
    mount = volume.get("MountPoint")
    if (volume.get("FilesystemType") != "apfs" or volume.get("GlobalPermissionsEnabled") is not True
            or volume.get("WritableVolume") is not True
            or not isinstance(mount, str) or not mount.startswith("/") or len(mount.encode("utf-8")) > 4096
            or any(ord(character) < 32 or ord(character) == 127 for character in mount)
            or volume.get("DeviceIdentifier") != selected["device"][5:]):
        raise ValueError("actual writable ownership-aware local APFS volume required")
    return {key: volume[key] for key in ("FilesystemType", "GlobalPermissionsEnabled", "WritableVolume", "MountPoint", "DeviceIdentifier")}
try:
    # A closed five-command batch, not a configurable execution helper.
    for phase in ("mount", "apfs", "build", "rust", "python"):
        if phase == "mount":
            # -P alone does not suppress inode columns in modern Darwin
            # mode. Explicit -k and -I fix units and the documented shape.
            argv = ["/bin/df", "-P", "-k", "-I", str(temporary)]
            cwd, environment, seconds, limit = temporary, clean, 15, 65536
        elif phase == "apfs":
            argv = ["/usr/sbin/diskutil", "info", "-plist", receipt["filesystemSelection"]["device"]]
            cwd, environment, seconds, limit = temporary, clean, 15, 65536
        elif phase == "build":
            argv = [rust_bin + "/cargo", "test", "--locked", "--no-default-features",
                    "--features", "desktop-shell,custom-protocol,macos-installed-observation",
                    "--target", build_target, "--test", "installed-shell-observation", "--no-run", "--message-format=json"]
            environment = dict(os.environ, PATH=rust_bin + ":/usr/bin:/bin:/usr/sbin:/sbin", HOME="/Users/runner", CARGO_HOME="/Users/runner/.cargo", RUSTUP_HOME="/Users/runner/.rustup", RUSTC=rust_bin + "/rustc", RUSTUP_AUTO_INSTALL="0")
            cwd, seconds, limit = checkout / "desktop/src-tauri", 1440, 4 * 1024 * 1024
        elif phase == "rust":
            argv = [str(artifact), "data-contracts"]
            cwd, environment, seconds, limit = temporary, clean, 30, 65536
        else:
            argv = [sys.executable, "-I", "-S", "-B", "-c", child_code, str(checkout), str(temporary), *map(str, temporary_before[:5])]
            cwd, environment, seconds, limit = temporary, clean, 120, 1024 * 1024
        command = {"phase": phase, "argv": argv, "cwd": str(cwd), "seconds": seconds, "bytesPerStream": limit,
                   "environmentPolicy": "original-job-build" if phase == "build" else "fixed-clean-noncredential",
                   "originalReturned": False, "returnCode": None, "outputComplete": False, "captureClosed": False,
                   "timedOut": False, "outputOverflow": False}
        receipt["commands"].append(command)
        process = None
        selector = selectors.DefaultSelector()
        output = {"stdout": bytearray(), "stderr": bytearray()}
        capture_error = None
        deadline = time.monotonic() + seconds
        stop_at = None
        try:
            process = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
            for label, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ, label)
            while selector.get_map() or process.poll() is None:
                now = time.monotonic()
                if now >= deadline and stop_at is None: command["timedOut"] = True
                if (command["timedOut"] or command["outputOverflow"]) and stop_at is None:
                    # Containment of this original child only. Never call it successful cleanup.
                    if process.poll() is None: process.kill()
                    stop_at = now + 5
                if stop_at is not None and now >= stop_at: break
                for key, _ in selector.select(0.1):
                    try: part = os.read(key.fileobj.fileno(), 65536)
                    except BlockingIOError: continue
                    if not part:
                        selector.unregister(key.fileobj); continue
                    room = limit - len(output[key.data])
                    output[key.data].extend(part[:room])
                    if len(part) > room: command["outputOverflow"] = True
            command["returnCode"] = process.wait(timeout=5)
            command["originalReturned"] = True
            command["outputComplete"] = not selector.get_map() and not command["outputOverflow"]
            if time.monotonic() > deadline: command["timedOut"] = True
        except BaseException as exc:
            capture_error = type(exc).__name__
        finally:
            close_errors = []
            if process is not None:
                if process.poll() is None:
                    try:
                        process.kill(); command["returnCode"] = process.wait(timeout=5); command["originalReturned"] = True
                    except BaseException as exc: close_errors.append("original-child-" + type(exc).__name__)
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        try: stream.close()
                        except BaseException as exc: close_errors.append("capture-pipe-" + type(exc).__name__)
            try: selector.close()
            except BaseException as exc: close_errors.append("capture-selector-" + type(exc).__name__)
            command["captureClosed"] = not close_errors
            command["captureError"] = capture_error
            command["closeErrors"] = close_errors
            command["stdout"] = put(phase + ".stdout", bytes(output["stdout"]))
            command["stderr"] = put(phase + ".stderr", bytes(output["stderr"]))
            code = str(command["returnCode"]) if command["originalReturned"] else "unavailable"
            command["status"] = put(phase + ".status", (code + "\n").encode("ascii"))
        if (capture_error or not command["originalReturned"] or command["returnCode"] != 0 or not command["outputComplete"]
                or not command["captureClosed"] or command["timedOut"] or command["outputOverflow"]):
            raise ValueError("original fixed command did not completely pass: " + phase)
        raw = bytes(output["stdout"])
        if phase == "mount":
            receipt["filesystemSelection"] = filesystem_device(raw)
        elif phase == "apfs":
            volume = filesystem_volume(raw, receipt["filesystemSelection"])
            mount = volume["MountPoint"]
            if (os.stat(mount).st_dev != temporary_before[0]
                    or os.stat(receipt["filesystemSelection"]["reportedMountPoint"]).st_dev != temporary_before[0]
                    or sig(os.fstat(temporary_fd))[:5] != temporary_before[:5]
                    or sig(os.fstat(temporary_fd)) != sig(os.lstat(temporary))):
                raise ValueError("actual writable ownership-aware local APFS required")
            receipt["actualFilesystem"] = volume
        elif phase == "build":
            rows = [json.loads(line) for line in raw.splitlines()]
            if [row.get("success") for row in rows if row.get("reason") == "build-finished"] != [True]:
                raise ValueError("original Cargo build-finished")
            targets = [row for row in rows if row.get("reason") == "compiler-artifact"
                       and row.get("target", {}).get("name") == "installed-shell-observation"
                       and row["target"].get("kind") == ["test"] and row.get("executable")]
            if (len(targets) != 1 or targets[0].get("profile", {}).get("test") is not True
                    or targets[0]["profile"].get("debug_assertions") is not True
                    or targets[0]["target"].get("src_path") != str(checkout / "desktop/src-tauri/tests/installed_shell_observation.rs")):
                raise ValueError("one original debug actual-main test artifact")
            artifact = Path(targets[0]["executable"])
            if (artifact.parent != root / "cargo-target" / build_target / "debug/deps"
                    or not re.fullmatch(r"installed_shell_observation-[0-9a-f]+", artifact.name)):
                raise ValueError("fixed original test artifact path")
            artifact_fd = os.open(artifact, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            artifact_before = sig(os.fstat(artifact_fd))
            if (not stat.S_ISREG(artifact_before[2]) or artifact_before[3] != os.getuid() or artifact_before[5] != 1
                    or not artifact_before[2] & 0o111 or not 0 < artifact_before[6] <= 1024 * 1024 * 1024):
                raise ValueError("original artifact type/owner/bound")
            artifact_digest = digest_original(artifact_fd, artifact, artifact_before)
            receipt["artifact"] = {"path": str(artifact), "identity": artifact_before, "sha256": artifact_digest,
                                   "unchangedAfterRun": False, "originalClosed": False}
        elif phase == "rust":
            if raw != b"MRK_MACOS_DATA_CONTRACTS=passed\n" or output["stderr"]:
                raise ValueError("one closed aggregate success marker required")
            if digest_original(artifact_fd, artifact, artifact_before) != artifact_digest:
                raise ValueError("original artifact postimage")
            receipt["artifact"]["unchangedAfterRun"] = True
            fd, artifact_fd = artifact_fd, None
            os.close(fd)
            receipt["artifact"]["originalClosed"] = True
        else:
            counts = json.loads(raw)
            if (counts.get("testsRun") != 84 or counts.get("testIds") != names or counts.get("actualHostBeforeAndAfter") is not True
                    or any(type(counts.get(key)) is not int or counts[key] != 0
                           for key in ("failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses"))):
                raise ValueError("exact native Python original counts required")
            receipt["pythonCounts"] = counts
    for name in source_names:
        if read(checkout / name, 2 * 1024 * 1024) != source_bodies[name]:
            raise ValueError("selected source changed during batch")
    temporary_after = sig(os.fstat(temporary_fd))
    if temporary_before[:5] != temporary_after[:5] or temporary_after != sig(os.lstat(temporary)):
        raise ValueError("original temporary root changed")
    with os.scandir(temporary_fd) as children:
        if next(children, None) is not None: raise ValueError("selected tests did not retire disposable fixtures")
    receipt["temporaryAfter"] = temporary_after
except BaseException as exc:
    failure = type(exc).__name__ + ": " + str(exc)[:200]
finally:
    if artifact_fd is not None:
        fd, artifact_fd = artifact_fd, None
        try: os.close(fd)
        except BaseException as exc: failure = failure or "artifact-close-" + type(exc).__name__
    try: os.close(temporary_fd)
    except BaseException as exc: failure = failure or "temporary-close-" + type(exc).__name__
    receipt["passed"] = failure is None
    receipt["failure"] = failure
    put("result.json", (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
if failure is not None: raise SystemExit(1)
print("One native aggregate and 84 exact host-Python tests passed; no UI, TLS or ignored vault-test qualification.")
PY_DATA_CONTRACTS
