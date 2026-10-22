set -euo pipefail
set -o noclobber
umask 077
[[ "$GITHUB_REF" == refs/heads/verify/desktop-macos-candidate && "$MRK_MACOS_NATIVE_SCOPE" == tool-setup && "$MRK_MACOS_PACKAGE_ROLE" == installed-shell-observation ]] || exit 1
[[ "$MRK_MACOS_TARGET" == aarch64-apple-darwin && "$RUSTUP_TOOLCHAIN" == 1.98.1 && "$(/usr/bin/id -u)" != 0 ]] || exit 1
[[ "$CARGO_TARGET_DIR" == "$MRK_MACOS_WORK/cargo-target" ]] || exit 1
# The canonical harness=false observer build/JSON remains untouched.
# This ONE ordinary libtest links against the same debug feature graph
# and same original source/release environment. No release/profile switch.
# Current composed Git2/Remote2/Workflow4/Service9 risks: 52 new tests,
# 32 distinct affected tests and the prior Initialization failure.
# Rerun 19 affected prior successes plus that failure; reuse the other
# 615 source-applicable successes rather than repeating all635.
# One exact APFS backup component below reuses this same test binary/cache.
# These use DATA and existing bounded private State/Service/path fixtures.
# No native provider, tool, credential or Git operation/qualification.
rust_bin="/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin"
export PATH="$rust_bin:/usr/bin:/bin:/usr/sbin:/sbin" RUSTC="$rust_bin/rustc"
export CARGO_HOME=/Users/runner/.cargo RUSTUP_HOME=/Users/runner/.rustup RUSTUP_AUTO_INSTALL=0
# This gate now precedes the observer's online build. Populate the locked
# dependency cache explicitly; list/run below remain offline and reuse one
# test binary. The embedded frontend has already been built for Tauri.
"$rust_bin/cargo" fetch --locked --target "$MRK_MACOS_TARGET" --manifest-path desktop/src-tauri/Cargo.toml
selected_tests=(
  shell::installed_observation::git_cli::tests::git_cli_cases_keep_exact_local_actions_and_combined_image_only
  shell::installed_observation::git_cli::tests::git_cli_readback_compares_original_context_and_exact_delta_not_ready_data
  shell::installed_observation::git_cli::tests::git_cli_fixed_phase_projection_and_comparison_debt_stay_bounded
  service_git_requests::tests::installed_cli_comparison_requires_each_original_and_exact_history_return
  service_github_action_protocol::remote_setup::tests::remote_settings_compact_data_preserves_no_change_readback_and_uncertainty
  service_github_action_protocol::remote_setup::tests::remote_settings_wire_has_required_nulls_no_secret_fields_and_fixed_backing
  asset_session::github_remote_delegation::tests::remote_variable_pins_compare_actual_original_allocations_not_identical_values
  asset_session::github_remote_delegation::tests::remote_main_uses_full_document_with_retained_payloads_evidence_and_failure_refusal
  github_connection_session::action_delegation::dispatch::tests::remote_settings_four_closed_inputs_hash_native_field_order_and_reject_secret_or_extra_material
  github_connection_session::action_delegation::dispatch::tests::remote_original_permission_precedes_take_and_completed_prepare_withdrawal_preserves_only_its_consent
  service_github_action_requests::dispatch::tests::remote_settings_same_entry_preserves_three_returns_readback_and_known_204_uncertainty
  service_github_action_requests::dispatch::tests::remote_settings_original_read_after_stop_lost_claim_and_same_thirty_two_rows
  asset_session::agent_github_action::tests::remote_settings_main_uses_distinct_consent_early_revision_and_closed_non_secret_decode
  service_workflow_edit_protocol::tests::workflow_edit_wire_is_closed_required_null_and_never_an_arbitrary_editor
  service_workflow_edit_protocol::tests::four_fixed_summaries_do_not_mint_a_preview_and_cross_instance_or_newline_refuse
  service_workflow_edit_requests::tests::same_workflow_edit_rows_and_all_return_cuts_remain_in_the_original_book
  service_workflow_edit_requests::tests::original_call_return_is_distinct_from_early_opened_or_prepared_data
  service_workflow_edit_requests::tests::check_revision_is_consumed_before_wait_and_revoke_or_duplicate_cannot_rearm
  service_workflow_edit_requests::tests::native_control_imports_earlier_read_even_after_stop_and_poison_is_absorbing
  service_workflow_edit_requests::tests::known_unclaimed_refusal_waits_for_history_and_thirty_two_tombstones_are_not_evicted
  service_workflow_edit_requests::tests::full_entry_capacity_is_bounded_without_borrowing_another_family_or_worker_slot
  service_workflow_edit_requests::tests::workflow_edit_and_existing_configuration_share_exactly_thirty_two_retained_slots
  application_service::agent_workflow_edit::tests::missing_or_invalid_configuration_queues_only_original_preparation_and_history_requires_real_ack
  application_service::agent_workflow_edit::tests::workflow_edit_keeps_actual_read_scope_alias_and_unobserved_poison_not_saved_preferences
  installed_cli::workflow_edit::tests::workflow_edit_cli_has_only_id_prepare_and_explicit_exact_apply
  installed_cli::workflow_edit::tests::workflow_edit_output_keeps_original_ids_unknown_and_missing_ack_no_replay
  installed_cli::workflow_edit::tests::complete_capabilities_and_help_disclose_real_desktop_input_and_recovery_boundary
  asset_session::agent_workflow_edit::tests::workflow_edit_raw_is_closed_current_main_input_and_never_recovery_or_ipc_draft
  asset_session::agent_workflow_edit::tests::workflow_edit_default_document_includes_complete_edit_future_and_retained_capacity
  asset_session::agent_workflow_edit::tests::workflow_edit_first_peer_cut_has_no_publisher_or_saved_input_side_effect
  edit_owner::agent_workflow_edit::tests::workflow_seven_original_publications_do_not_skip_repeat_or_rebase
  edit_owner::agent_workflow_edit::tests::exact_four_file_summary_comes_from_original_full_preview_never_recovery_or_public_ids
  edit_owner::agent_workflow_edit::tests::workflow_positive_attribution_needs_original_chain_and_real_finality_preserving_core_first_reason
  edit_owner::agent_workflow_edit::tests::workflow_edit_code_census_borrows_only_the_same_live_slot_and_refuses_busy_or_lost
  edit_owner::agent_configuration::memory::workflow_edit::tests::workflow_maximum_before_after_inventory_and_all_overlapping_frames_are_counted
  edit_owner::agent_configuration::memory::workflow_edit::tests::workflow_keeps_actual_old_inventory_and_refuses_overbound_without_clearing_it
  installed_runtime::workflow_edit_agent::tests::workflow_edit_agent_code_quote_uses_actual_target_records_and_native_frame
  installed_runtime::workflow_edit_agent::tests::workflow_edit_agent_slot_binding_is_once_before_entry_and_failed_capacity_is_not_zero
  github_connection_session::action_delegation::operation::tests::nine_operation_inputs_keep_native_commands_hashes_and_closed_old_forms
  github_connection_session::action_delegation::operation::tests::maximum_private_pr_shares_one_real_allocation_and_keeps_native_modes_and_capacity_checks
  github_connection_session::action_delegation::operation::tests::original_capture_preserves_account_only_repository_and_exact_retry_witness_requirement
  github_connection_session::action_delegation::operation::tests::all_three_origin_checks_precede_retirement_and_claim_once_on_same_private_input
  github_connection_session::repository_create::operation::tests::original_prepared_permission_withdrawal_requires_three_facts_and_preserves_later_consent
  github_connection_session::repository_create::operation::tests::original_full_pending_witness_requires_same_roster_source_and_returned_producer
  service_github_action_protocol::operation::tests::full_operation_pending_wire_keeps_all_rows_actual_backing_and_id_strings
  service_github_action_protocol::operation::tests::operation_producer_needs_go_original_caller_and_latest_history_not_progress
  service_github_action_protocol::operation::tests::known_unattributed_reconcile_is_retained_data_but_earlier_read_stop_removes_attribution
  service_github_action_protocol::operation::tests::old_mutations_and_three_pending_families_share_same_full_book_and_failed_claim
  asset_session::agent_github_action::operation::tests::original_main_phase_and_maximum_private_pr_decode_fit_without_changing_old_bounds
  asset_session::agent_github_action::operation::tests::operations_use_complete_current_document_and_private_pr_and_original_future
  asset_session::agent_github_action::operation::tests::main_quota_refuses_dense_escaped_and_deep_input_before_any_deserializer
  asset_session::agent_github_action::operation::tests::main_quota_keeps_maximum_unicode_pr_and_full_old_release_prepare
  shell::installed_observation::final_fixture_readback_requires_matching_verified_case
  service_github_action_requests::memory::tests::full_retained_row_and_ancillary_have_real_typed_bounds_not_response_size
  service_github_action_requests::memory::tests::retained_ceiling_failure_never_borrows_a_retired_row_or_worker_credit
  asset_session::agent_github_action::tests::native_main_capture_abi_fits_same_named_phase_not_a_new_document_or_ipc_quote
  asset_session::agent_github_action::tests::only_new_prepare_main_input_gets_four_kib_and_physical_capacity_is_bounded
  service_github_action_protocol::tests::all_closed_metadata_fits_status_with_wrapper_and_never_contains_material
  service_github_action_protocol::dispatch::tests::full_sixty_four_record_capacity_and_outer_access_fit_without_truncation
  service_github_action_requests::dispatch::tests::producer_positive_requires_same_native_relay_and_latest_history_returns
  service_github_action_requests::dispatch::tests::missing_go_result_or_history_return_never_makes_a_positive_producer
  service_github_action_requests::dispatch::tests::completed_producer_cancel_cannot_revoke_a_different_successor_scope
  github_connection_session::action_delegation::dispatch::tests::twelve_native_inputs_map_only_to_existing_typed_commands_and_hash_exact_fields
  github_connection_session::action_delegation::dispatch::tests::actual_capture_requires_selected_account_repo_generation_and_original_clock
  supervisor::macos_github_actions_original_data_contract
  edit_owner::workflow_domain_tests::only_exact_already_submitted_domain_session_generation_and_token_are_observation
  edit_owner::workflow_domain_tests::workflow_unchanged_and_created_results_require_the_original_action_set
  edit_owner::workflow_domain_tests::recovery_attention_clears_only_for_explicit_clean_original_final_without_any_failure
  github_repository_create_protocol::tests::repository_create_raw_commands_require_exact_small_original_inputs
  github_repository_create_protocol::tests::repository_create_pending_and_ready_cannot_change_original_scope_or_fabricate_go
  github_pull_request_protocol::tests::pull_request_raw_requires_exact_explicit_draft_and_never_merge_or_token
  github_pull_request_protocol::tests::pull_request_private_text_is_bound_but_not_in_initial_or_public_review
  github_pull_request_protocol::tests::pull_request_pending_is_scope_only_and_never_restores_consent_or_write
  github_actions_retry_protocol::tests::actions_retry_raw_never_supplies_account_source_path_or_provider_cas
  github_actions_retry_protocol::tests::actions_retry_pending_bounds_duplicate_attempts_and_prepare_cannot_restore_permission
  asset_session::agent_github_action::tests::fixed_main_decoder_accepts_only_the_original_closed_three_selections
  asset_session::agent_github_action::tests::empty_main_revoke_invalidates_delayed_allow_before_first_off_document_cut
  asset_session::agent_github_action::tests::same_doc_permission_is_spent_before_actual_inbox_error_or_later_install_failure
  service_github_action_requests::tests::three_kinds_require_caller_native_and_same_history_in_either_order
  service_github_action_requests::tests::progress_history_ack_cannot_settle_later_final
  service_github_action_requests::tests::history_failure_and_drop_are_absorbing_even_after_native_return
  service_github_action_requests::tests::same_id_reconnect_is_not_a_second_submit_or_claim
  service_github_action_requests::tests::old_read_revoke_keeps_earlier_failure_after_later_stop
  service_github_action_requests::tests::publication_read_go_and_return_stay_read_only_until_original_caller_and_history_return
  application_service::agent_initialization::tests::missing_or_invalid_configuration_queues_only_original_preparation_and_history_requires_real_ack
)
[[ "${#selected_tests[@]}" == 85 ]] || exit 1
list_log="$MRK_MACOS_WORK/git-selected-contracts-list.log"
run_log="$MRK_MACOS_WORK/git-selected-contracts.log"
[[ ! -e "$list_log" && ! -L "$list_log" && ! -e "$run_log" && ! -L "$run_log" ]] || exit 1
cargo=("$rust_bin/cargo" test --locked --offline --jobs 1 --no-default-features
  --features desktop-shell,custom-protocol,macos-installed-observation
  --target "$MRK_MACOS_TARGET" --manifest-path desktop/src-tauri/Cargo.toml --lib --)
# Ordinary Cargo list+run reuse the same one test binary. Exact count
# and each-once checks prevent absent/renamed cfg tests passing as zero.
"${cargo[@]}" "${selected_tests[@]}" --exact --list --color=never | /usr/bin/tee "$list_log"
missing=0
for test_name in "${selected_tests[@]}"; do
  if [[ "$(/usr/bin/grep -Fxc "$test_name: test" "$list_log")" != 1 ]]; then
    printf 'Required test is missing or duplicated: %s\n' "$test_name" >&2
    missing=1
  fi
done
(( missing == 0 )) || exit 1
/usr/bin/grep -Fx '85 tests, 0 benchmarks' "$list_log"
"${cargo[@]}" "${selected_tests[@]}" --exact --test-threads=1 --color=never --format=pretty | /usr/bin/tee "$run_log"
/usr/bin/grep -Eq '^test result: ok\. 85 passed; 0 failed; 0 ignored;' "$run_log"

# Real synthetic-record APFS backup, separate from the selected DATA checks.
# Same compiled libtest/cache; no picker, Keychain or Desktop qualification.
# The component retains its injected uncertain original until process exit.
(
  umask 077
  test_name=asset_session::vault::backup_native::component_tests::native_apfs_backup_roundtrip_wrong_code_and_lost_close_receipt
  backup_log="$MRK_MACOS_WORK/vault-backup-component.log"
  [[ ! -e "$backup_log" && ! -L "$backup_log" ]] || exit 1
  temp_root="$(cd -P -- "$RUNNER_TEMP" && pwd -P)"
  fixture="$(/usr/bin/mktemp -d "$temp_root/mrk-backup-component.XXXXXX")"
  fixture_identity=''
  backup_returned=0
  cleanup_backup_fixture() {
    status=$?
    trap - EXIT
    cleanup_status=0
    if [[ "$backup_returned" == 1 && -n "$fixture_identity" && -d "$fixture" && ! -L "$fixture" &&
          "$(cd -P -- "$fixture" && pwd -P)" == "$fixture" &&
          "$(/usr/bin/stat -f '%d:%i:%u:%Lp' "$fixture")" == "$fixture_identity" ]]; then
      /bin/rm -rf -- "$fixture" || cleanup_status=$?
    else
      printf '%s\n' 'Backup caller return or private fixture identity is unconfirmed; leave it for disposable-host teardown.' >&2
      cleanup_status=1
    fi
    if (( status == 0 )); then status=$cleanup_status; fi
    exit "$status"
  }
  trap cleanup_backup_fixture EXIT
  trap 'backup_returned=0; exit 130' INT
  trap 'backup_returned=0; exit 143' TERM
  [[ -d "$fixture" && ! -L "$fixture" && "$(cd -P -- "$fixture" && pwd -P)" == "$fixture" ]]
  [[ "$(/usr/bin/stat -f '%u:%Lp' "$fixture")" == "$(/usr/bin/id -u):700" ]]
  fixture_identity="$(/usr/bin/stat -f '%d:%i:%u:%Lp' "$fixture")"
  # Both foreground pipeline members must return. Save their actual statuses
  # before any grep; signal exits do not authorize fixture cleanup.
  if MRK_MACOS_VAULT_FIXTURE_ROOT="$fixture" "${cargo[@]}" "$test_name" \
      --exact --ignored --test-threads=1 --color=never --format=pretty | /usr/bin/tee "$backup_log"; then
    backup_status=0 backup_pipeline=("${PIPESTATUS[@]}")
  else
    backup_status=$? backup_pipeline=("${PIPESTATUS[@]}")
  fi
  if (( ${#backup_pipeline[@]} == 2 && backup_pipeline[0] < 128 && backup_pipeline[1] < 128 )); then
    backup_returned=1
  fi
  (( backup_status == 0 )) || exit "$backup_status"
  (( backup_returned == 1 )) || exit 1
  /usr/bin/grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "$backup_log"
)
