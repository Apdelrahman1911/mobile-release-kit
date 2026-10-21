set -euo pipefail
set -o noclobber
umask 077
[[ "$GITHUB_REF" == refs/heads/verify/desktop-macos-candidate && "$MRK_MACOS_NATIVE_SCOPE" == tool-setup && "$MRK_MACOS_PACKAGE_ROLE" == installed-shell-observation ]] || exit 1
[[ "$MRK_MACOS_TARGET" == aarch64-apple-darwin && "$RUSTUP_TOOLCHAIN" == 1.98.1 && "$(/usr/bin/id -u)" != 0 ]] || exit 1
[[ "$CARGO_TARGET_DIR" == "$MRK_MACOS_WORK/cargo-target" ]] || exit 1
# The canonical harness=false observer build/JSON remains untouched.
# This ONE ordinary libtest links against the same debug feature graph
# and same original source/release environment. No release/profile switch.
# One focused140-case union: all five actual prior failures, 40 affected
# prior successes, and 95 cases not in run39630318617's old136 roster.
# Reuse91 unaffected successful cases instead of repeating that full run.
# Covers reviewed A+B+C memory accounting, Version Prepare, Apple recovery,
# Tool Prepare, ready-for-review PR and credential backup boundaries.
# Three cases use original private State/Service fixtures (one bounded local
# socket); others are DATA/in-memory/codec checks. No native provider, tool,
# credential or Git operation/qualification. Preserve original closes/joins.
rust_bin="/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin"
export PATH="$rust_bin:/usr/bin:/bin:/usr/sbin:/sbin" RUSTC="$rust_bin/rustc"
export CARGO_HOME=/Users/runner/.cargo RUSTUP_HOME=/Users/runner/.rustup RUSTUP_AUTO_INSTALL=0
# This gate now precedes the observer's online build. Populate the locked
# dependency cache explicitly; list/run below remain offline and reuse one
# test binary. The embedded frontend has already been built for Tauri.
"$rust_bin/cargo" fetch --locked --target "$MRK_MACOS_TARGET" --manifest-path desktop/src-tauri/Cargo.toml
selected_tests=(
  agent_build_requests::tests::all32_mixed_family_failed_claims_share_terminal_and_public_copies_cannot_mutate_them
  agent_build_requests::tests::earlier_failed_progress_is_preserved_beside_one_full_immutable_terminal
  agent_build_requests::tests::ios_historical_report_has_real_counts_and_rejects_paths_synthetic_digests_or_signing
  agent_build_requests::tests::ios_unknown_absorbs_and_lost_ack_blocks_both_families_without_native_receipt
  agent_build_requests::tests::private_scope_and_incoming_report_capacity_refuse_without_rebinding_either_family
  agent_build_requests::tests::typed_row_public_and_ancillary_bounds_keep_all32_and_four_nonipc_reports
  agent_local_checks::tests::all32_failed_history_claims_share_exact_terminal_without_replay_or_public_mutation
  agent_local_checks::tests::coalesced_latest_never_overwrites_retained_original_history_claim
  agent_local_checks::tests::codes_only_report_and_config_must_match_without_turning_failures_into_passes
  agent_local_checks::tests::duplicate_projection_is_noop_and_quote_covers_bounded_typed_rows_not_rss
  agent_local_checks::tests::exact_native_ids_and_progress_order_and_terminal_immutability
  agent_local_checks::tests::native_unknown_absorbs_later_terminal_and_history_never_changes_it
  agent_local_checks::tests::older_failed_progress_claim_and_terminal_are_retained_without_two_full_reports
  agent_local_checks::tests::oversized_native_scope_or_projection_capacity_cannot_replace_original_storage
  apple_provisioning_journal::data::key_recovery::tests::armed_written_unknown_and_foreign_scope_do_not_gain_an_association
  apple_provisioning_journal::data::key_recovery::tests::exact_durable_reference_is_required_and_old_pending_never_changes
  apple_provisioning_journal::key_recovery::tests::recovery_records_share_the_original_operation_domain_and_32_row_capacity
  apple_provisioning_journal::key_recovery::tests::recovery_store_write_retains_lost_ack_without_replay_or_old_row_rewrite
  apple_provisioning_journal::key_recovery::tests::recovery_v5_preserves_legacy_rows_and_only_the_exact_key_fence
  apple_provisioning_protocol::certificate_recovery::tests::durable_recovery_selection_keeps_pending_and_has_a_distinct_certificate_origin
  apple_provisioning_protocol::certificate_recovery::tests::key_saved_history_is_extra_fullref_gate_not_current_loan_or_restored_authority
  apple_provisioning_protocol::tests::key_contract::local_key_modes_keep_old_grammar_and_consent_closed_and_future_modes_unavailable
  apple_provisioning_protocol::tests::key_contract::recovery_actual_decoder_requires_exact_original_comparison_before_terminal
  apple_provisioning_protocol::tests::key_contract::recovery_decoder_rejects_crossref_both_hash_mismatches_foreign_mode_and_partial_frame
  apple_provisioning_protocol::tests::key_contract::review_without_complete_inventory_cannot_mint_local_preparation_selection
  apple_provisioning_protocol::tests::profile_contract::identity_phase_bound_and_unsupported_base64_are_not_silently_truncated
  application_service::agent_version_edit::tests::combined_prepare_uses_saved_config_freshness_but_no_cached_version_proof
  application_service::ipc_response_memory::tests::actual_typed_routes_and_inline_enum_cells_fit_the_closed_worker_quote
  application_service::ipc_response_memory::tests::layout_growth_and_checked_overflow_refuse_instead_of_clamping_or_dropping_cells
  application_service::ipc_response_memory::tests::only_the_named_old_worker_allocations_are_replaced_by_the_mixed_maximum
  application_service::ipc_response_memory::tests::same_eight_workers_allow_one_metadata_not_a_ninth_or_second_large_exchange
  application_service::ipc_response_memory::tests::transferred_ipc_terms_leave_metadata_active_rows_and_github_tombstones_charged
  asset_commands::apple_distribution_key_fields::tests::recovery_frame_comparison_includes_private_scalar_not_only_csr_and_spki
  asset_session::agent_configuration::configuration_storage_tests::actual_default_document_fits_configuration_quote_and_retained_capacity_refuses
  asset_session::agent_github_action::tests::fixed_main_decoder_accepts_only_the_original_closed_three_selections
  asset_session::agent_metadata_text::metadata_storage_tests::actual_default_document_fits_metadata_quote_and_retained_capacity_refuses
  asset_session::agent_tool_setup::inspect::tests::current_service_saved_config_must_equal_the_original_allow_context
  asset_session::agent_tool_setup::tests::actual_default_document_and_near_limit_copied_doctor_input_fit
  asset_session::agent_tool_setup::tests::document_limit_is_checked_not_inferred_from_a_successful_census
  asset_session::agent_version_edit::tests::real_document_and_original_edit_future_include_retained_buffer_and_overflow
  asset_session::agent_version_prepare::tests::actual_main_variants_accept_only_origin_and_bounded_ui_counters
  asset_session::agent_version_prepare::tests::real_document_preopen_future_keeps_payload_and_additional_original_debts
  asset_session::apple_provisioning::agent::tests::apple_cli_uses_actual_default_document_plus_two_profile_payload_quotes
  asset_session::apple_provisioning::memory_fixture::input_census_never_treats_contended_poisoned_or_dual_assets_as_absence
  asset_session::lookup_memory::apple_memory::tests::active_same_original_live_and_pending_census_keep_borrowed_source_and_retirement
  asset_session::lookup_memory::apple_memory::tests::old_review_original_without_return_is_refused_not_credited
  asset_session::lookup_memory::apple_memory::tests::retained_review_material_is_counted_after_current_document_replacement
  asset_session::lookup_memory::apple_memory::tests::same_ready_context_payloads_and_distinct_material_wrapper_are_deduplicated
  asset_session::play_cleanup::tests::actual_document_growth_preserves_separate_cleanup_and_document_limits
  asset_session::shared_memory_tests::actual_document_and_retained_capacity_obey_shared_admission
  asset_session::shared_memory_tests::actual_document_plus_apple_future_fits_original_session_limit
  asset_session::shared_memory_tests::actual_mac_native_quotes_fit_current_document_before_any_runtime_is_opened
  asset_session::vault::backup_delegation::tests::authenticated_kind_policy_has_no_wrong_link_fallback_before_new
  asset_session::vault::backup_delegation::tests::original_picker_import_is_android_only_without_narrowing_the_backend
  asset_session::vault::backup_desktop::tests::android_upload_key_scope_does_not_qualify_other_desktop_contexts
  asset_session::vault::backup_desktop::tests::idle_known_is_not_a_backup_publication_or_native_qualification
  asset_session::vault::key_sources::p12::census_tests::selected_p12_census_distinguishes_real_none_contention_and_poison
  edit_owner::agent_configuration::memory::tests::version_preparation_retains_original_last_backing_without_snapshot_credit
  edit_owner::agent_configuration::memory::tests::version_preparation_whole_active_plus_incoming_frame_is_bounded_before_adoption
  edit_owner::agent_version_prepare::tests::compact_opened_uses_actual_present_baselines_and_never_constructs_a_handoff
  edit_owner::agent_version_prepare::tests::manual_publication_chain_has_only_the_original_seven_successors
  github_connection_session::pull_request::pull_request_control_tests::pull_request_completion_never_invents_disconnect_or_another_stop_identity
  github_pull_request_protocol::mode::tests::absent_only_defaults_to_draft_while_null_bool_object_unknown_and_duplicate_refuse
  github_pull_request_protocol::mode::tests::both_modes_share_existing_record_response_and_heap_bounds_without_an_extra_pool
  github_pull_request_protocol::mode::tests::legacy_draft_omits_mode_and_preserves_old_canonical_confirmation_and_digest
  github_pull_request_protocol::mode::tests::original_private_go_and_prepare_input_require_the_same_mode
  github_pull_request_protocol::mode::tests::ready_and_draft_cli_consents_match_the_native_prepared_not_the_shared_prefix
  github_pull_request_protocol::mode::tests::ready_requires_explicit_retained_mode_and_correlated_boolean_not_false_alone
  github_pull_request_protocol::pull_request_data_tests::pull_request_acknowledgement_and_unattributed_observation_are_distinct
  github_pull_request_protocol::pull_request_data_tests::pull_request_pending_is_scope_only_and_never_restores_consent_or_write
  github_pull_request_protocol::pull_request_data_tests::pull_request_private_text_is_bound_but_not_in_initial_or_public_review
  github_pull_request_protocol::pull_request_data_tests::pull_request_raw_requires_exact_explicit_draft_and_never_merge_or_token
  installed_cli::github_action::tests::real_local_catalogue_keeps_one_closed_mutation_family_and_finite_output
  installed_cli::tests::capabilities_keep_read_grants_separate_from_desktop_reviewed_proposals
  installed_cli::tool_setup::tests::lost_tools_request_receipt_is_id_only_no_replay
  installed_cli::tool_setup::tests::three_tools_cli_verbs_admit_only_reviewed_ids
  installed_cli::version_edit::tests::actual_collector_accepts_only_manual_values_or_original_reservation
  installed_cli::version_edit::tests::actual_collector_preserves_three_id_only_verbs_and_explicit_review
  installed_cli::version_edit::tests::compiled_capabilities_disclose_prepared_only_scope_and_same_catalogue
  installed_cli::version_edit::tests::output_matches_same_original_and_unknown_never_claims_new_save_permission
  installed_cli::version_edit::tests::preparation_output_is_exact_kind_original_and_never_an_apply_receipt
  installed_cli_ipc::tests::metadata_exchange_admission_is_fixed_fail_fast_and_reuses_only_its_original_lease
  installed_cli_ipc::tests::metadata_stalled_large_frame_keeps_lease_until_original_stop_close_and_return
  release_version_edit_protocol::tests::agent_prepare_frame_bound_precedes_same_closed_version_decoder
  saved_command_owner::apple_key::recovery::tests::recovery_normal_terminal_pipe_stop_never_substitutes_for_original_source_ack_and_joins
  saved_command_owner::apple_provisioning::memory::tests::active_census_requires_same_parent_and_asset_including_key_recover
  saved_command_owner::apple_provisioning::memory::tests::empty_registry_census_is_try_only_and_does_not_poison_or_publish
  saved_command_owner::apple_provisioning::memory::tests::prepared_and_consumed_review_keep_two_exact_inputs_after_registry_unlock
  saved_command_owner::apple_provisioning::memory::tests::retained_quote_keeps_original_buffers_and_only_replaces_absent_material_reservation
  saved_command_owner::apple_provisioning::memory::tests::third_distinct_retained_input_is_refused_not_omitted
  saved_command_owner::apple_provisioning::tests::apple_original_clock_and_finite_representation_quote_are_not_renewed
  saved_command_owner::apple_provisioning::tests::apple_original_store_closure_keeps_mode_and_owner_gates
  saved_command_owner::apple_provisioning::tests::apple_start_parent_dispatch_matches_actual_initialized_modes
  saved_command_owner::tool_acquisition::agent::inspect::tests::later_preparation_cannot_renew_original_allow_read_or_first_failure
  saved_command_owner::tool_acquisition::agent::inspect::tests::prepared_retirement_keeps_identity_before_start_and_waits_caller_and_history
  saved_command_owner::tool_acquisition::agent::inspect::tests::saved_inspect_wire_keeps_required_nulls_and_cannot_request_acquisition
  saved_command_owner::tool_acquisition::tests::fixed_acquisition_deadline_and_buffers_are_not_renewed_by_later_phases
  saved_command_owner::tool_acquisition::tests::unqualified_prepare_census_is_not_a_resumable_missing_prerequisite
  service_github_action_requests::memory::tests::full_retained_row_and_ancillary_have_real_typed_bounds_not_response_size
  service_github_action_requests::memory::tests::retained_ceiling_failure_never_borrows_a_retired_row_or_worker_credit
  service_github_action_requests::tests::metadata_census_includes_rows_and_all_eight_worker_copies
  service_github_action_requests::tests::one_32_row_pool_retains_old_three_kind_tombstones_and_refuses_the_33rd
  service_github_action_requests::tests::short_metadata_with_overbound_physical_capacity_is_not_admitted
  service_github_action_requests::tests::three_kinds_require_caller_native_and_same_history_in_either_order
  service_metadata_text_protocol::tests::bounded_encoder_counts_real_escaping_before_allocation_and_names_same_eight_callers
  service_protocol::ipc_response_tests::largest_closed_generic_lists_fit_the_source_derived_wire_and_typed_roster
  service_protocol::ipc_response_tests::metadata_full_text_keeps_the_same_fixed_encoder_and_never_changes_frame_limits
  service_protocol::ipc_response_tests::outer_fixed_encoder_preserves_old_envelopes_bytes_and_exact_capacity
  service_protocol::ipc_response_tests::validation_and_oversize_errors_are_identical_without_growable_outer_output
  service_request_catalogue::tests::combined_build_capacity_and_id_namespace_are_not_per_family
  service_tool_setup_protocol::tests::exact_struct_report_and_global_frame_bounds
  service_tool_setup_protocol::tests::five_closed_reviews_require_exact_pairs_and_no_extra_fields
  service_tool_setup_protocol::tests::summaries_do_not_upgrade_completion_or_foreign_original
  service_tool_setup_requests::tests::bounded_consent_exhaustion_and_document_loss_do_not_reset
  service_tool_setup_requests::tests::cancelled_unentered_still_needs_actual_caller_and_history
  service_tool_setup_requests::tests::exact_duplicate_nonce_and_foreign_cancel_do_not_replay_or_stop
  service_tool_setup_requests::tests::lost_caller_history_and_contradictory_callback_stay_unknown
  service_tool_setup_requests::tests::quiet_read_facet_preserves_earliest_failure_and_absolute_permission
  service_tool_setup_requests::tests::three_real_return_slots_required_in_both_callback_orders
  service_version_edit_prepare_protocol::tests::compact_status_requires_nulls_and_exact_original_checkout_review
  service_version_edit_prepare_protocol::tests::preparation_is_one_closed_manual_or_original_reservation_selection
  service_version_edit_prepare_requests::tests::actual_call_returns_not_opened_or_prepared_events_enable_next_phase
  service_version_edit_prepare_requests::tests::cancelled_unknown_foreign_or_unreturned_preparation_cannot_exempt_another_lease
  service_version_edit_prepare_requests::tests::gui_winner_stops_only_delegation_and_keeps_later_original_read_revoke_out
  service_version_edit_prepare_requests::tests::original_read_first_failure_and_lost_caller_never_rearm_or_become_final
  service_version_edit_prepare_requests::tests::revision_overflow_and_exact_old_discovery_do_not_adopt_latest_preparation
  service_version_edit_prepare_requests::tests::same_preparation_exemption_is_required_at_both_install_and_normal_submit
  service_version_edit_prepare_requests::tests::shared_thirty_two_rows_include_preparation_and_apply_without_eviction
  service_version_edit_prepare_requests::tests::unentered_return_claim_failure_and_late_final_data_have_distinct_custody
  service_version_edit_requests::tests::actual_retained_enum_and_preparation_weak_lease_cells_keep_the_old_scope_allowance
  service_version_edit_requests::tests::failed_native_retirement_and_exact_old_query_cannot_be_relabelled_current
  service_version_edit_requests::tests::final_seal_serializes_submit_without_a_dropped_unobserved_entry
  service_version_edit_requests::tests::gui_winner_spends_unused_lease_without_borrowing_its_later_stop
  service_version_edit_requests::tests::install_precedes_public_allow_and_revoke_before_allow_is_not_rearmed
  service_version_edit_requests::tests::known_cleanup_poll_keeps_original_cutoff_and_resamples_earlier_read_revocation
  service_version_edit_requests::tests::missing_original_or_unknown_is_absorbing_and_counter_overflow_never_rearms
  service_version_edit_requests::tests::original_read_clock_and_earliest_stop_survive_unavailable_renderer_or_renewal
  service_version_edit_requests::tests::permanent_submit_binds_same_lease_and_duplicate_never_enters_twice
  service_version_edit_requests::tests::revoke_nonce_capacity_preserves_other_live_original_and_never_evicts
  service_version_edit_requests::tests::single_book_mixed_row_census_keeps_both_non_row_allowances
)
[[ "${#selected_tests[@]}" == 140 ]] || exit 1
list_log="$MRK_MACOS_WORK/git-selected-contracts-list.log"
run_log="$MRK_MACOS_WORK/git-selected-contracts.log"
[[ ! -e "$list_log" && ! -L "$list_log" && ! -e "$run_log" && ! -L "$run_log" ]] || exit 1
cargo=("$rust_bin/cargo" test --locked --offline --jobs 1 --no-default-features
  --features desktop-shell,custom-protocol,macos-installed-observation
  --target "$MRK_MACOS_TARGET" --manifest-path desktop/src-tauri/Cargo.toml --lib --)
# Ordinary Cargo list+run reuse the same one test binary. Exact count
# and each-once checks prevent absent/renamed cfg tests passing as zero.
"${cargo[@]}" "${selected_tests[@]}" --exact --list --color=never | /usr/bin/tee "$list_log"
/usr/bin/grep -Fx '140 tests, 0 benchmarks' "$list_log"
for test_name in "${selected_tests[@]}"; do
  [[ "$(/usr/bin/grep -Fxc "$test_name: test" "$list_log")" == 1 ]]
done
"${cargo[@]}" "${selected_tests[@]}" --exact --test-threads=1 --color=never --format=pretty | /usr/bin/tee "$run_log"
/usr/bin/grep -Eq '^test result: ok\. 140 passed; 0 failed; 0 ignored;' "$run_log"
