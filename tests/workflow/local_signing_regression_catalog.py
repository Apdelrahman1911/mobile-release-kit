"""Finite original-regression obligations, never execution/custody receipts.

This pure-data catalog may be inspected before native admission.  It defines
coverage; measured packing/cost authority belongs to the central matrix contract.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from types import MappingProxyType

OPERATING_SYSTEMS = ("ubuntu-24.04", "macos-26")

HANDOFF_MODES = ("lease-open", "session-open", "native-open", "profile-directory", "profile-stage", "profile-read")
INHERITED_MODES = ("explicit-exit", "gc-exit", "child-reentry", "profile-read")
NATIVE_FAILURE_COMMANDS = ("create-keychain", "set-keychain-settings", "unlock-keychain", "import",
                           "set-key-partition-list", "list-keychains", "default-keychain", "delete-keychain")
HANDLER_RESTORATION_VARIANTS = tuple(
    (boundary, masking) for boundary in ("read", "lease", "installer", "signing")
    for masking in ("OSError", "FileNotFoundError", "CredentialError", "KeyboardInterrupt")
)
PREFLIGHT_CANCELLATION_VARIANTS = tuple(
    (stage, edge, signum) for stage in ("early", "late")
    for edge in ("read-cleanup", "cms-cleanup") for signum in ("INT", "TERM")
)

# Native tuples moved unchanged from the original test modules. Their direct
# algorithm sibling tuples stay there; neither route duplicates this authority.
SPECIAL_PROFILE_NATIVE_VARIANTS = (
    ("owned-symlink", False, "symlink"),
    ("borrowed-fifo", True, "fifo"),
)
PROFILE_OWNER_NATIVE_VARIANTS = (
    ("owned-after-close-same", False, "after-close", "same"),
    ("owned-during-read-metadata", False, "during-read", "metadata"),
    ("borrowed-before-open-same", True, "before-open", "same"),
    ("borrowed-after-close-metadata", True, "after-close", "metadata"),
)
PROFILE_BORROWED_NATIVE_VARIANTS = (
    ("active-during-read-metadata", False, "during-read", "metadata"),
    ("active-after-close-same", False, "after-close", "same"),
    ("terminal-during-read-metadata", True, "during-read", "metadata"),
    ("terminal-after-close-same", True, "after-close", "same"),
)

SIGNAL_METHOD_VARIANTS = MappingProxyType({
    "test_real_pending_signals_during_native_open_fstat_fdopen_and_close_are_owned":
        ("open-home", "open-child", "open-stage", "fstat", "fdopen", "close"),
    "test_original_unmocked_open_and_initial_fstat_interruptions_cannot_leak_files_or_descriptors":
        ("assigned-open", "before-fstat"),
    "test_actual_caller_handoff_and_repeated_cleanup_signals_do_not_rely_on_generator_gc":
        ("handoff", "body-repeat", "unexpected-cleanup"),
    "test_successful_native_mutation_is_registered_before_deferred_cancellation":
        ("mutation-create", "mutation-search", "mutation-default"),
    "test_first_signal_at_cleanup_entry_and_before_exit_dispatch_cannot_skip_ownership": tuple(
        prefix + phase + ":" + signum for prefix in ("", "standalone-")
        for phase in ("cleanup-entry", "cleanup-dispatch", "restore-entry", "restore-active")
        for signum in ("INT", "TERM")),
    "test_handler_restoration_and_partial_installation_cannot_swallow_or_abandon_cancellation": tuple(
        prefix + phase for prefix in ("", "standalone-") for phase in ("restore-term", "restore-int", "partial-install")),
    "test_late_setup_and_actual_materialized_body_cancellation_never_execute_following_build_code": tuple(
        prefix + phase + ":" + signum for prefix in ("", "standalone-", "material-")
        for phase in ("pre-yield", "body") for signum in ("INT", "TERM")),
    "test_cleanup_failure_is_not_masked_by_deferred_cancellation_and_remaining_cleanup_runs":
        ("cleanup-error-signal:INT", "cleanup-error-signal:TERM"),
})
assert len([mode for modes in SIGNAL_METHOD_VARIANTS.values() for mode in modes]) == 50
SIGNAL_MODES = frozenset(mode for modes in SIGNAL_METHOD_VARIANTS.values() for mode in modes)
assert len(SIGNAL_MODES) == 50  # Runtime/inert contract also checks PB3's timeout authority.


def inherited_modes(operating_system):
    assert operating_system in OPERATING_SYSTEMS, "unknown G platform"
    return INHERITED_MODES + (("profile-scratch",) if operating_system == "macos-26" else ())


def signal_modes(method):
    assert type(method) is str and method in SIGNAL_METHOD_VARIANTS, "unknown original signal obligation"
    return SIGNAL_METHOD_VARIANTS[method]

# Original literal unittest IDs remain the discovery/coverage obligation.
METHODS = MappingProxyType({
    'unit.test_local_signing.LocalSigningTests': (
        'test_normal_context_round_trips_entire_native_state_and_account_inode',
        'test_overlapping_context_refuses_before_profile_authentication_or_native_work',
        'test_same_lease_cannot_nest_a_second_signing_owner',
        'test_pre_native_invalid_request_settles_original_no_dispatch_without_fabricated_result',
        'test_external_preference_edits_preserved_and_conflict_clears_for_fresh_admission',
        'test_empty_search_list_round_trip_preserves_literal_paths',
        'test_rc_zero_partial_native_display_error_never_mutates',
        'test_native_nonzero_after_effect_reconciles_without_repeating_setup',
        'test_real_checkpoint_collision_after_effect_retained_and_explicit_original_recovery',
        'test_reused_profile_conflicts_require_explicit_original_recovery',
        'test_owned_destination_replacement_preserved_but_same_inode_edit_requires_recovery',
        'test_native_replacement_outside_operation_is_never_adopted_or_deleted',
        'test_every_completed_native_failure_after_effect_is_cleaned_without_repeating_setup',
        'test_failed_create_without_effect_does_not_invent_native_ownership',
        'test_recovery_preserves_special_foreign_replacements_of_borrowed_and_owned_profiles',
    ),
    'unit.test_local_signing_profile_identity.ProfileIdentityTests': (
        'test_owned_recovery_preserves_same_byte_foreign_inode_at_both_boundaries',
        'test_owned_recovery_disappearance_is_safe_without_type_error',
        'test_owned_metadata_changes_require_fresh_explicit_recovery',
        'test_borrowed_active_and_terminal_observations_report_all_conflicts',
        'test_full_owner_preserves_conflicted_profiles_without_implicit_outer_retry',
        'test_initial_and_real_eexist_admission_bind_the_actual_read_inode',
        'test_final_admission_detects_changes_after_link_or_stage_removal',
        'test_final_admission_close_failure_keeps_fatal_ownership_and_original_session',
        'test_owned_final_admission_snapshot_is_rechecked_after_its_close',
        'test_one_shot_cleanup_stat_and_unlink_errors_are_not_retried_by_outer_owner',
        'test_setup_stage_errors_keep_original_authority_without_same_name_retry',
        'test_setup_stage_absence_preserves_its_boundary_specific_semantics',
        'test_real_eexist_borrower_has_one_validated_last_cleanup_observation',
        'test_own_inode_eexist_and_interrupted_link_keep_owned_cleanup_authority',
        'test_stable_hardlinks_and_own_unlink_metadata_are_valid',
        'test_stable_initial_rejection_and_owned_disappearance_do_not_invent_conflicts',
        'test_original_preexisting_snapshot_and_later_owned_identity_both_survive',
        'test_manual_recheck_is_explicit_new_observation_not_implicit_retry',
        'test_private_control_reader_and_profile_evidence_keep_their_contracts',
    ),
    'unit.test_local_signing_failures.SigningFailureTests': (
        'test_actual_query_resource_failure_never_authorizes_manual_or_automatic_recovery',
        'test_profile_read_and_directory_close_failures_cannot_be_successful_conflicts',
        'test_installer_cleanup_fatal_preserves_pending_and_all_independent_handles',
        'test_initial_and_link_race_fatal_snapshots_are_never_retried_or_marked_resolved',
        'test_session_and_lease_close_errors_attempt_every_handle_without_fd_retry',
        'test_terminal_close_error_is_not_success_and_does_not_recreate_journals',
        'test_fatal_body_quarantines_all_further_commands_regardless_of_public_dispatch_flags',
        'test_actual_fatal_local_resource_in_body_cannot_finalize_or_release_signing_resources',
        'test_detached_exitstack_callback_retains_nonfatal_body_dispatch_before_later_fatal',
        'test_genuine_nonzero_command_result_cannot_hide_later_independent_fatal_close',
        'test_actual_handler_restoration_cannot_mask_retained_resource_failure',
        'test_actual_cli_pure_cancellation_stays_130_and_preserves_original_session',
        'test_actual_cli_reports_fatal_status_and_recovery_without_success_json',
        'test_multiple_close_errors_preserve_nonfatal_entry_dispatch_and_all_other_closes',
        'test_even_settled_missing_executable_query_revokes_this_manual_recovery_attempt',
        'test_ordinary_changed_borrowed_profile_remains_preserved_conflict_not_fatal',
    ),
    'unit.test_local_signing_recovery.SigningRecoveryTests': (
        'test_initial_stage_prefixes_are_not_misclassified_as_committed_authority',
        'test_old_committed_state_not_staged_bytes_controls_recovery',
        'test_duplicate_unknown_types_binding_and_version_in_committed_controls_refuse_without_native_work',
        'test_completed_marker_is_self_contained_and_never_restores_later_preferences',
        'test_manual_recheck_holds_lease_and_removes_no_unknown_resource_itself',
        'test_legacy_worker_fields_are_read_only_and_never_authorize_process_operations',
        'test_snapshot_is_immutable_and_reload_never_renews_original_failure_or_recovery_authority',
        'test_prepared_without_any_command_dispatch_needs_a_fresh_attempt_before_cleanup',
        'test_failed_real_recovery_query_revokes_manual_recheck_without_journalling_a_new_operation',
        'test_armed_recovery_requires_unchanged_original_c_fence_before_any_new_query',
        'test_settled_fence_retirement_resumes_only_its_original_final_inode',
        'test_retry_stage_observation_failed_real_borrowed_checkpoint_closes_handles_and_recovers',
        'test_status_has_no_native_effect_and_unknown_links_remain_untouched',
        'test_link_intent_retains_original_identity_through_installer_and_recovery_finalization',
        'test_interrupted_recovery_and_refused_manual_recheck_preserve_authority',
    ),
    'unit.test_local_signing_recovery.SigningCrashMatrixTests': (
        'test_seven_bare_home_parent_and_empty_native_prefix_cuts_recover_automatically',
    ),
    'unit.test_local_signing_native.SigningAccountNativeTests': (
        'test_real_fork_during_resource_handoff_never_mutates_or_retains_parent_resources',
        'test_inherited_fork_exit_gc_and_new_child_admission_cannot_cleanup_parent',
    ),
    'unit.test_local_signing_composition.SigningCompositionTests': (
        'test_full_preflight_shares_one_guard_through_early_authentication_signing_build_and_late_authentication',
        'test_real_early_and_late_profile_cleanup_signals_under_full_preflight_never_return_cancelled_content',
    ),
    'unit.test_ios_profile_installation.ProfileInstallationSignalTests': (
        'test_real_pending_signals_during_native_open_fstat_fdopen_and_close_are_owned',
        'test_original_unmocked_open_and_initial_fstat_interruptions_cannot_leak_files_or_descriptors',
        'test_actual_caller_handoff_and_repeated_cleanup_signals_do_not_rely_on_generator_gc',
        'test_successful_native_mutation_is_registered_before_deferred_cancellation',
        'test_first_signal_at_cleanup_entry_and_before_exit_dispatch_cannot_skip_ownership',
        'test_handler_restoration_and_partial_installation_cannot_swallow_or_abandon_cancellation',
        'test_late_setup_and_actual_materialized_body_cancellation_never_execute_following_build_code',
        'test_cleanup_failure_is_not_masked_by_deferred_cancellation_and_remaining_cleanup_runs',
    ),
    'unit.test_ios_profile_installation.ProfileCredentialFlowTests': (
        'test_install_uses_authenticated_snapshot_even_when_original_path_is_replaced',
    ),
    'unit.test_local_signing_attempts.RecoveryAttemptTests': (
        'test_precommit_recovery_write_revokes_original_attempt_without_reload_revival',
        'test_committed_recovery_write_late_failure_revokes_even_without_journal_failure',
        'test_second_initial_query_failure_revokes_manual_recovery_without_new_journal',
        'test_completed_hold_only_query_failure_preserves_original_terminal_authority',
    ),
    'unit.test_local_signing_persistent.PersistentSigningTests': (
        'test_original_c_prefix_cut_uses_real_fence_and_fresh_recovery',
        'test_genuine_model_inventory_active_build_pending_contrast',
        'test_genuine_model_inventory_and_foreign_manual_cases',
    ),
})

_splits = {
    "test_every_completed_native_failure_after_effect_is_cleaned_without_repeating_setup":
        ("native-effect", NATIVE_FAILURE_COMMANDS),
    "test_recovery_preserves_special_foreign_replacements_of_borrowed_and_owned_profiles":
        ("special-profile", tuple(value[0] for value in SPECIAL_PROFILE_NATIVE_VARIANTS)),
    "test_full_owner_preserves_conflicted_profiles_without_implicit_outer_retry":
        ("profile-owner", tuple(value[0] for value in PROFILE_OWNER_NATIVE_VARIANTS)),
    "test_borrowed_active_and_terminal_observations_report_all_conflicts":
        ("profile-borrowed", tuple(value[0] for value in PROFILE_BORROWED_NATIVE_VARIANTS)),
    "test_actual_handler_restoration_cannot_mask_retained_resource_failure":
        ("handler-restoration", tuple("/".join(value) for value in HANDLER_RESTORATION_VARIANTS)),
    "test_real_fork_during_resource_handoff_never_mutates_or_retains_parent_resources":
        ("handoff", HANDOFF_MODES),
    "test_inherited_fork_exit_gc_and_new_child_admission_cannot_cleanup_parent":
        ("inherited", inherited_modes("macos-26")),
    "test_full_preflight_shares_one_guard_through_early_authentication_signing_build_and_late_authentication":
        ("preflight", ("healthy",)),
    "test_real_early_and_late_profile_cleanup_signals_under_full_preflight_never_return_cancelled_content":
        ("preflight", tuple("/".join(value) for value in PREFLIGHT_CANCELLATION_VARIANTS)),
    **{method: ("profile-signal", modes) for method, modes in SIGNAL_METHOD_VARIANTS.items()},
}
SPLITS = MappingProxyType(_splits)
HELPER_METHODS = MappingProxyType({
    "native-effect": ("run_native_failure_variant",),
    "special-profile": ("run_native_special_profile_variant",),
    "profile-owner": ("run_native_owner_variant",),
    "profile-borrowed": ("run_native_borrowed_variant",),
    "handler-restoration": ("run_handler_restoration_variant",),
    "handoff": ("run_handoff_variant",),
    "inherited": ("run_inherited_variant",),
    "preflight": ("exercise_full_preflight", "run_preflight_cancellation_variant"),
    "profile-signal": ("run_regression_boundary", "run_boundary"),
})
assert set(HELPER_METHODS) == {value[0] for value in SPLITS.values()}
SEMANTIC_METHODS = MappingProxyType({
    "test_original_c_prefix_cut_uses_real_fence_and_fresh_recovery": ("C/fence/04",),
    "test_genuine_model_inventory_active_build_pending_contrast": ("S/active-build-pending/none",),
    "test_genuine_model_inventory_and_foreign_manual_cases": ("H/full-context", *(f"F/{number:02}" for number in range(1, 16))),
})
_methods = {cls + "." + method for cls, methods in METHODS.items() for method in methods}
assert len(_methods) == 86 and len({method.rsplit(".", 1)[1] for method in _methods}) == 86
assert set(SPLITS) | set(SEMANTIC_METHODS) <= {method.rsplit(".", 1)[1] for method in _methods}
assert not set(SPLITS) & set(SEMANTIC_METHODS)

# Explicit source-path planning allowances, NOT measured durations/maxima.
# Each row counts its actual independent lifetimes and optional original fresh
# recovery launches. Keep difficult paths conservative until admitted timing
# qualifies the complete packing; an absent row never receives a tiny default.
WHOLE_WORKLOADS = MappingProxyType({
    "test_normal_context_round_trips_entire_native_state_and_account_inode": (49, 0, "one-full-signing49"),
    "test_overlapping_context_refuses_before_profile_authentication_or_native_work": (98, 0, "two-full-signing49"),
    "test_same_lease_cannot_nest_a_second_signing_owner": (49, 0, "one-full-signing49"),
    "test_pre_native_invalid_request_settles_original_no_dispatch_without_fabricated_result": (53, 0, "full49-plus-two-query-pairs"),
    "test_external_preference_edits_preserved_and_conflict_clears_for_fresh_admission": (98, 0, "two-full-signing49-plan"),
    "test_empty_search_list_round_trip_preserves_literal_paths": (49, 0, "one-full-signing49"),
    "test_rc_zero_partial_native_display_error_never_mutates": (18, 0, "query2-plus-empty-recovery16"),
    "test_native_nonzero_after_effect_reconciles_without_repeating_setup": (64, 0, "failed-create-original-reconciliation-plan64"),
    "test_real_checkpoint_collision_after_effect_retained_and_explicit_original_recovery": (75, 0, "original-plus-fresh-native-recovery-plan75"),
    "test_reused_profile_conflicts_require_explicit_original_recovery": (195, 0, "three-original49-plus-fresh16-plan"),
    "test_owned_destination_replacement_preserved_but_same_inode_edit_requires_recovery": (162, 0, "two-original49-plus-recovery-attempt32-plan"),
    "test_native_replacement_outside_operation_is_never_adopted_or_deleted": (80, 0, "original-and-refusal-and-resolved-recovery-plan80"),
    "test_failed_create_without_effect_does_not_invent_native_ownership": (32, 0, "no-effect-creation-and-reconciliation-plan32"),
    "test_owned_recovery_preserves_same_byte_foreign_inode_at_both_boundaries": (136, 2, "four-seed2-recovery16-plus-stage-fresh16-plan"),
    "test_owned_recovery_disappearance_is_safe_without_type_error": (72, 0, "four-prepare2-plus-recovery16"),
    "test_owned_metadata_changes_require_fresh_explicit_recovery": (204, 6, "six-prepare2-failed-observation16-fresh16-plan"),
    "test_initial_and_real_eexist_admission_bind_the_actual_read_inode": (108, 6, "six-before-native-prepare2-fresh16-plan"),
    "test_final_admission_detects_changes_after_link_or_stage_removal": (108, 6, "six-before-native-prepare2-fresh16-plan"),
    "test_final_admission_close_failure_keeps_fatal_ownership_and_original_session": (36, 2, "two-before-native-prepare2-fresh16-plan"),
    "test_owned_final_admission_snapshot_is_rechecked_after_its_close": (54, 3, "three-before-native-prepare2-fresh16-plan"),
    "test_one_shot_cleanup_stat_and_unlink_errors_are_not_retried_by_outer_owner": (195, 3, "three-original49-plus-fresh16-plan"),
    "test_setup_stage_errors_keep_original_authority_without_same_name_retry": (216, 12, "twelve-before-native-prepare2-fresh16-plan"),
    "test_setup_stage_absence_preserves_its_boundary_specific_semantics": (162, 9, "nine-before-native-prepare2-fresh16-plan"),
    "test_real_eexist_borrower_has_one_validated_last_cleanup_observation": (325, 4, "five-original49-plus-possible-fresh16-plan"),
    "test_own_inode_eexist_and_interrupted_link_keep_owned_cleanup_authority": (98, 0, "one-full49-plus-two-early-reconciliation24-plan"),
    "test_stable_hardlinks_and_own_unlink_metadata_are_valid": (98, 0, "two-full-signing49"),
    "test_stable_initial_rejection_and_owned_disappearance_do_not_invent_conflicts": (64, 0, "one-full49-plus-rejection-plan64"),
    "test_original_preexisting_snapshot_and_later_owned_identity_both_survive": (65, 1, "original49-plus-fresh16-plan"),
    "test_manual_recheck_is_explicit_new_observation_not_implicit_retry": (50, 0, "prepare2-and-three-recovery-observation16-plan"),
    "test_private_control_reader_and_profile_evidence_keep_their_contracts": (18, 1, "prepare2-plus-fresh16"),
    "test_actual_query_resource_failure_never_authorizes_manual_or_automatic_recovery": (120, 10, "five-prepare-failed-query-fresh-absent-plan24"),
    "test_profile_read_and_directory_close_failures_cannot_be_successful_conflicts": (144, 8, "eight-prepare2-fresh16-plan"),
    "test_installer_cleanup_fatal_preserves_pending_and_all_independent_handles": (260, 4, "four-original49-plus-fresh16-plan"),
    "test_initial_and_link_race_fatal_snapshots_are_never_retried_or_marked_resolved": (72, 4, "four-before-native-prepare2-fresh16-plan"),
    "test_session_and_lease_close_errors_attempt_every_handle_without_fd_retry": (192, 8, "eight-prepare-close-failure-fresh-plan24"),
    "test_terminal_close_error_is_not_success_and_does_not_recreate_journals": (44, 2, "two-prepare2-recovery16-terminal4-plan"),
    "test_fatal_body_quarantines_all_further_commands_regardless_of_public_dispatch_flags": (49, 1, "entry26-plus-full-native-fresh23"),
    "test_actual_fatal_local_resource_in_body_cannot_finalize_or_release_signing_resources": (49, 1, "entry26-plus-full-native-fresh23"),
    "test_detached_exitstack_callback_retains_nonfatal_body_dispatch_before_later_fatal": (144, 2, "two-original49-plus-fresh23-plan"),
    "test_genuine_nonzero_command_result_cannot_hide_later_independent_fatal_close": (50, 1, "entry26-body1-plus-full-native-fresh23-plan"),
    "test_actual_cli_pure_cancellation_stays_130_and_preserves_original_session": (18, 1, "prepare2-cancel-before-target-plus-fresh16"),
    "test_actual_cli_reports_fatal_status_and_recovery_without_success_json": (48, 2, "two-prepare2-recovery-close-fresh-plan24"),
    "test_multiple_close_errors_preserve_nonfatal_entry_dispatch_and_all_other_closes": (48, 2, "two-prepare-close-failure-fresh-plan24"),
    "test_even_settled_missing_executable_query_revokes_this_manual_recovery_attempt": (18, 1, "prepare2-no-model-missing-executable-fresh16"),
    "test_ordinary_changed_borrowed_profile_remains_preserved_conflict_not_fatal": (18, 0, "prepare2-plus-recovery16"),
    "test_initial_stage_prefixes_are_not_misclassified_as_committed_authority": (72, 0, "four-prepare2-plus-recovery16-plan"),
    "test_old_committed_state_not_staged_bytes_controls_recovery": (18, 0, "prepare2-plus-recovery16-plan"),
    "test_duplicate_unknown_types_binding_and_version_in_committed_controls_refuse_without_native_work": (18, 0, "one-seed-and-final-recovery-invalid-controls-no-target"),
    "test_completed_marker_is_self_contained_and_never_restores_later_preferences": (66, 0, "three-prepare2-recovery16-terminal-observation4-plan"),
    "test_manual_recheck_holds_lease_and_removes_no_unknown_resource_itself": (34, 0, "prepare2-plus-two-observation-recovery16-plan"),
    "test_legacy_worker_fields_are_read_only_and_never_authorize_process_operations": (18, 0, "prepare2-plus-recovery16-plan"),
    "test_snapshot_is_immutable_and_reload_never_renews_original_failure_or_recovery_authority": (40, 0, "original-and-failed-snapshot-plus-fresh-plan40"),
    "test_prepared_without_any_command_dispatch_needs_a_fresh_attempt_before_cleanup": (24, 0, "original-predispatch-error-plus-fresh-plan24"),
    "test_failed_real_recovery_query_revokes_manual_recheck_without_journalling_a_new_operation": (19, 0, "prepare2-failed-query1-fresh16"),
    "test_armed_recovery_requires_unchanged_original_c_fence_before_any_new_query": (34, 0, "prepare-and-original-command-and-final-recovery-plan34"),
    "test_settled_fence_retirement_resumes_only_its_original_final_inode": (40, 0, "prepare-original-query-retirement-contrasts-fresh-plan40"),
    "test_retry_stage_observation_failed_real_borrowed_checkpoint_closes_handles_and_recovers": (40, 0, "original-borrowed-checkpoint-and-fresh-plan40"),
    "test_status_has_no_native_effect_and_unknown_links_remain_untouched": (18, 0, "prepare2-plus-final-recovery16-plan"),
    "test_link_intent_retains_original_identity_through_installer_and_recovery_finalization": (68, 0, "two-prepare2-and-recovery-attempt32-plan"),
    "test_interrupted_recovery_and_refused_manual_recheck_preserve_authority": (36, 0, "prepare-and-failed-recovery-manual-refusal-fresh-plan36"),
    "test_seven_bare_home_parent_and_empty_native_prefix_cuts_recover_automatically": (142, 15, "inventory16-plus-seven-seed2-recovery16-fifteen-workers"),
    "test_install_uses_authenticated_snapshot_even_when_original_path_is_replaced": (49, 0, "one-full-signing49"),
    "test_precommit_recovery_write_revokes_original_attempt_without_reload_revival": (32, 0, "initializing-seed-revoked-attempt-fresh-plan32"),
    "test_committed_recovery_write_late_failure_revokes_even_without_journal_failure": (32, 0, "initializing-seed-late-revocation-fresh-plan32"),
    "test_second_initial_query_failure_revokes_manual_recovery_without_new_journal": (20, 0, "prepare2-failed-query2-fresh16"),
    "test_completed_hold_only_query_failure_preserves_original_terminal_authority": (24, 0, "prepare2-recovery16-terminal-failure1-terminal4-plan"),
})
assert set(WHOLE_WORKLOADS) == {method for names in METHODS.values() for method in names} - set(SPLITS) - set(SEMANTIC_METHODS)


def _workload(method, helper, variant):
    if helper == "whole":
        return WHOLE_WORKLOADS[method]
    if helper in {"handoff", "inherited"}:
        return 49, 1, "one-full-signing49-plus-original-outer-worker"
    if helper == "profile-owner":
        return 59, 1, "entry26-cleanup17-fresh16-plus-original-cli"
    if helper == "profile-borrowed":
        return (20 if variant.startswith("terminal-") else 18), 0, "prepare-and-active-or-terminal-recovery"
    if helper == "native-effect":
        return 64, 0, "one-selected-native-error-original-reconciliation-plan64"
    if helper == "special-profile":
        return 75, 0, "one-original-ambiguous-activation-and-fresh-plan75"
    if helper == "handler-restoration":
        return (65, 1, "one-signing49-and-fresh16-plan") if variant.startswith("signing/") else \
            (0, 0, "explicit-read-lease-installer-no-session-no-native-direct-filesystem")
    if helper == "preflight":
        return (0, 4, "early-real-profile-owners-before-signing-plan") if variant.startswith("early/") else \
            (50, 8, "full-preflight-model50-plus-real-profile-owners-plan")
    assert helper == "profile-signal" and variant in SIGNAL_MODES
    zero_model = variant.startswith("standalone-") or variant in {"open-home", "partial-install"}
    recovery16 = variant in {"open-child", "open-stage", "fstat", "fdopen", "close", "assigned-open", "before-fstat", "handoff"}
    commands = (0 if zero_model else 16 if recovery16 else
                {"mutation-create": 20, "mutation-search": 39, "mutation-default": 47}.get(variant,
                    53 if variant in {"unexpected-cleanup", "cleanup-error-signal:INT", "cleanup-error-signal:TERM"} else 49))
    return commands, 1, "PB3-finite-original-signal-path-plan-plus-outer-worker"


@dataclass(frozen=True)
class Case:
    identifier: str
    kind: str
    original_method: str
    helper: str | None
    variant: str | None
    semantic: str | None
    platforms: tuple[str, ...]
    estimated_commands: int
    owned_workers: int
    planning_basis: str

    def __post_init__(self):
        assert self.kind in {"execution", "semantic-contribution"} and self.original_method in _methods
        assert type(self.platforms) is tuple and self.platforms and len(set(self.platforms)) == len(self.platforms)
        assert self.platforms == tuple(value for value in OPERATING_SYSTEMS if value in self.platforms)
        if self.kind == "execution":
            assert self.semantic is None and type(self.helper) is str
            assert (self.helper == "whole") == (self.variant is None)
            assert self.helper == "whole" or self.helper in HELPER_METHODS
            assert type(self.estimated_commands) is int and self.estimated_commands >= 0
            assert type(self.owned_workers) is int and self.owned_workers >= 0
            assert type(self.planning_basis) is str and self.planning_basis and self.scheduling_units > 0
        else:
            assert self.helper is self.variant is None and type(self.semantic) is str
            assert (self.estimated_commands, self.owned_workers, self.planning_basis) == (0, 0, "derived-no-execution")

    @property
    def scheduling_units(self):
        return self.estimated_commands + 4 * self.owned_workers + 1 if self.kind == "execution" else 0

    def record(self):
        return {**asdict(self), "platforms": list(self.platforms), "scheduling_units": self.scheduling_units,
                "helper_methods": list(HELPER_METHODS[self.helper]) if self.kind == "execution" and self.helper != "whole" else []}


_cases = []
for _class, _names in METHODS.items():
    for _method in _names:
        _original = _class + "." + _method
        _prefix = "G/" + _original + "/"
        _platforms = ("macos-26",) if _class.endswith(".SigningCompositionTests") else OPERATING_SYSTEMS
        if _method in SEMANTIC_METHODS:
            for _semantic in SEMANTIC_METHODS[_method]:
                _cases.append(Case(_prefix + "semantic/" + _semantic, "semantic-contribution", _original,
                                   None, None, _semantic, _platforms, 0, 0, "derived-no-execution"))
        elif _method in SPLITS:
            _helper, _variants = SPLITS[_method]
            assert len(_variants) == len(set(_variants)) and _variants
            for _variant in _variants:
                _active = ("macos-26",) if _helper == "inherited" and _variant == "profile-scratch" else _platforms
                _cases.append(Case(_prefix + "variant/" + _variant, "execution", _original,
                                   _helper, _variant, None, _active, *_workload(_method, _helper, _variant)))
        else:
            _cases.append(Case(_prefix + "whole", "execution", _original, "whole", None, None, _platforms,
                               *_workload(_method, "whole", None)))
assert len({item.identifier for item in _cases}) == len(_cases)
CASES = MappingProxyType({item.identifier: item for item in sorted(_cases, key=lambda item: item.identifier)})


def case(identifier):
    assert type(identifier) is str and identifier in CASES, "unknown original regression case"
    return CASES[identifier]


def cases_for(operating_system):
    assert type(operating_system) is str and operating_system in OPERATING_SYSTEMS, "unknown G platform"
    return tuple(value for value in CASES.values() if operating_system in value.platforms)


def obligations(operating_system):
    selected = cases_for(operating_system)
    return MappingProxyType({method: tuple(value.identifier for value in selected if value.original_method == method)
                             for method in sorted({value.original_method for value in selected})})


def delegated_methods(operating_system):
    return tuple(obligations(operating_system))


def semantic_contributions(identifier):
    assert type(identifier) is str, "canonical semantic ID required"
    return tuple(value.identifier for value in CASES.values()
                 if value.kind == "semantic-contribution" and value.semantic == identifier)


def definition():
    return {"schema": "mrk-signing-regression-v1", "cases": [value.record() for value in CASES.values()],
            "obligations": {platform: dict(obligations(platform)) for platform in OPERATING_SYSTEMS}}
