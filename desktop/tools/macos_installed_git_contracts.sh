set -euo pipefail
set -o noclobber
umask 077
[[ "$GITHUB_REF" == refs/heads/verify/desktop-macos-candidate && "$MRK_MACOS_NATIVE_SCOPE" == tool-setup && "$MRK_MACOS_PACKAGE_ROLE" == installed-shell-observation ]] || exit 1
[[ "$MRK_MACOS_TARGET" == aarch64-apple-darwin && "$RUSTUP_TOOLCHAIN" == 1.98.1 && "$(/usr/bin/id -u)" != 0 ]] || exit 1
[[ "$CARGO_TARGET_DIR" == "$MRK_MACOS_WORK/cargo-target" ]] || exit 1
# The canonical harness=false observer build/JSON remains untouched.
# This ONE ordinary libtest links against the same debug feature graph
# and same original source/release environment. No release/profile switch.
# Keep the previous140 pending/affected cases: run39653966833 failed while
# compiling, so none executed. Add the bounded-reader and stored-key reuse
# changes plus their six materially affected old-action lifecycle regressions.
# Include eighteen new image cases plus six affected Config/Text pool cases.
# Include eleven new candidate-download contracts plus three affected History cases.
# Include Store Prepare/inventory and Apple Prepare contracts plus affected original paths.
# Reuse unaffected earlier successes instead of repeating a full suite.
# One exact APFS backup component below reuses this same test binary/cache.
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
  application_service::agent_apple_provisioning::tests::apple_cli_history_only_front_refuses_all_live_methods
  application_service::agent_version_edit::tests::combined_prepare_uses_saved_config_freshness_but_no_cached_version_proof
  application_service::agent_version_reserve::tests::reserve_response_project_and_alias_guards_survive_reconnect_and_pre_send_revoke
  application_service::ipc_response_memory::tests::actual_typed_routes_and_inline_enum_cells_fit_the_closed_worker_quote
  application_service::ipc_response_memory::tests::layout_growth_and_checked_overflow_refuse_instead_of_clamping_or_dropping_cells
  application_service::ipc_response_memory::tests::only_the_named_old_worker_allocations_are_replaced_by_the_mixed_maximum
  application_service::ipc_response_memory::tests::same_eight_workers_allow_one_metadata_not_a_ninth_or_second_large_exchange
  application_service::ipc_response_memory::tests::transferred_ipc_terms_leave_metadata_active_rows_and_github_tombstones_charged
  asset_commands::apple_distribution_key_fields::tests::recovery_frame_comparison_includes_private_scalar_not_only_csr_and_spki
  asset_session::agent_configuration::configuration_storage_tests::actual_default_document_fits_configuration_quote_and_retained_capacity_refuses
  asset_session::agent_github_action::tests::fixed_main_decoder_accepts_only_the_original_closed_three_selections
  asset_session::agent_metadata_images::tests::actual_default_document_image_quote_fits_and_keeps_retained_capacity_charged
  asset_session::agent_metadata_images::tests::image_main_request_grammar_is_scalar_and_requires_the_original_apply_arm
  asset_session::agent_metadata_text::metadata_storage_tests::actual_default_document_fits_metadata_quote_and_retained_capacity_refuses
  asset_session::agent_store::preparation::tests::store_preparation_native_grant_and_input_fit_existing_fixed_backing
  asset_session::agent_store::preparation::tests::store_preparation_raw_uses_original_closed_input_and_bounded_nodes
  asset_session::agent_tool_setup::inspect::tests::current_service_saved_config_must_equal_the_original_allow_context
  asset_session::agent_tool_setup::tests::actual_default_document_and_near_limit_copied_doctor_input_fit
  asset_session::agent_tool_setup::tests::document_limit_is_checked_not_inferred_from_a_successful_census
  asset_session::agent_upload_key::tests::main_requests_are_small_explicit_action_and_consent_pairs_not_status_authority
  asset_session::agent_version_edit::tests::real_document_and_original_edit_future_include_retained_buffer_and_overflow
  asset_session::agent_version_prepare::tests::actual_main_variants_accept_only_origin_and_bounded_ui_counters
  asset_session::agent_version_prepare::tests::real_document_preopen_future_keeps_payload_and_additional_original_debts
  asset_session::apple_provisioning::agent::prepare::tests::preparation_actual_caller_drop_and_unknown_cannot_be_replaced_by_status
  asset_session::apple_provisioning::agent::prepare::tests::preparation_actual_single_grant_call_and_context_metadata_fit_original_ancillary
  asset_session::apple_provisioning::agent::prepare::tests::preparation_fixed_raw_ids_and_shared_nonce_tombstone_do_not_grant_start
  asset_session::apple_provisioning::agent::tests::apple_cli_uses_actual_default_document_plus_two_profile_payload_quotes
  asset_session::apple_provisioning::memory_fixture::input_census_never_treats_contended_poisoned_or_dual_assets_as_absence
  asset_session::lookup_memory::apple_memory::tests::active_same_original_live_and_pending_census_keep_borrowed_source_and_retirement
  asset_session::lookup_memory::apple_memory::tests::old_review_original_without_return_is_refused_not_credited
  asset_session::lookup_memory::apple_memory::tests::retained_review_material_is_counted_after_current_document_replacement
  asset_session::lookup_memory::apple_memory::tests::same_ready_context_payloads_and_distinct_material_wrapper_are_deduplicated
  asset_session::play_cleanup::tests::actual_document_growth_preserves_separate_cleanup_and_document_limits
  asset_session::prepared_reply::tests::one_prepared_wait_and_compact_reply_fit_the_named_relay_not_a_second_task
  asset_session::shared_memory_tests::actual_document_and_retained_capacity_obey_shared_admission
  asset_session::shared_memory_tests::actual_document_plus_apple_future_fits_original_session_limit
  asset_session::shared_memory_tests::actual_mac_native_quotes_fit_current_document_before_any_runtime_is_opened
  asset_session::store_material::apple_prepare::tests::preparation_comparison_never_keeps_retired_private_material_alive
  asset_session::vault::backup_delegation::tests::authenticated_kind_policy_has_no_wrong_link_fallback_before_new
  asset_session::vault::backup_delegation::tests::original_picker_import_is_android_only_without_narrowing_the_backend
  asset_session::vault::backup_desktop::tests::android_upload_key_scope_does_not_qualify_other_desktop_contexts
  asset_session::vault::backup_desktop::tests::idle_known_is_not_a_backup_publication_or_native_qualification
  asset_session::vault::backup_native::tests::allocation_quotes_refuse_before_full_record_or_output_allocation
  asset_session::vault::key_sources::p12::census_tests::selected_p12_census_distinguishes_real_none_contention_and_poison
  asset_session::vault::upload_key::controls::delegation::reuse::tests::original_weak_body_and_one_reply_token_are_reserved_before_attachment
  asset_session::vault::upload_key::controls::delegation::reuse::tests::selected_row_is_exact_full_reference_and_never_an_inert_return_receipt
  asset_source::macos::history_sources::download_sources::tests::download_output_comparison_never_adopts_replaced_inode_mode_owner_or_link
  asset_source::macos::history_sources::download_sources::tests::download_source_reserve_keeps_four_actual_slots_and_complete_state
  edit_owner::agent_configuration::memory::images::tests::retained_image_private_view_capacity_and_foreign_last_are_not_buffer_credit
  edit_owner::agent_configuration::memory::tests::version_preparation_retains_original_last_backing_without_snapshot_credit
  edit_owner::agent_configuration::memory::tests::version_preparation_whole_active_plus_incoming_frame_is_bounded_before_adoption
  edit_owner::agent_metadata_images::tests::completed_image_data_needs_exact_import_effect_and_actual_retirement_axes
  edit_owner::agent_metadata_images::tests::image_original_buffer_helper_advances_only_after_owned_buffer_return
  edit_owner::agent_metadata_images::tests::no_actual_image_original_or_retained_status_can_mint_private_apply_lease
  edit_owner::agent_version_prepare::tests::compact_opened_uses_actual_present_baselines_and_never_constructs_a_handoff
  edit_owner::agent_version_prepare::tests::manual_publication_chain_has_only_the_original_seven_successors
  github_connection_session::pull_request::pull_request_control_tests::pull_request_completion_never_invents_disconnect_or_another_stop_identity
  github_history_protocol::download::tests::download_candidate_and_complete_control_quote_are_bounded
  github_history_protocol::download::tests::download_cleanup_window_cannot_authorize_new_publication
  github_history_protocol::download::tests::download_consent_cannot_upgrade_old_read_or_other_stage
  github_history_protocol::download::tests::download_diagnostic_is_not_publication_or_finality
  github_history_protocol::download::tests::download_private_terminal_presence_cannot_upgrade_old_initial_or_missing_lifetime
  github_history_protocol::download::tests::download_receipt_parser_requires_exact_historical_binding_and_bounded_nodes
  github_history_protocol::download::tests::download_unknown_durability_retains_positive_rename_without_success
  github_history_protocol::download::tests::download_unknown_state_keeps_diagnostics_without_minting_any_ticket
  github_history_protocol::tests::closed_history_commands_frames_and_original_context
  github_history_protocol::tests::complete_history_result_shapes_and_retained_status_are_bounded
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
  installed_cli::apple_provisioning::tests::apple_cli_cli_lost_ack_has_only_original_status_cancel_and_no_replay
  installed_cli::apple_provisioning::tests::apple_cli_cli_output_correlates_actual_response_and_pending_is_not_completion
  installed_cli::apple_provisioning::tests::apple_cli_cli_requires_fixed_id_only_consent_and_closed_commands
  installed_cli::apple_provisioning::tests::apple_prepare_cli_only_addresses_and_separate_consent_no_context_or_material
  installed_cli::apple_provisioning::tests::apple_prepare_cli_reply_must_match_exact_kind_scope_and_original_query
  installed_cli::github_action::tests::real_local_catalogue_keeps_one_closed_mutation_family_and_finite_output
  installed_cli::metadata_images::tests::image_cli_actual_collector_and_capabilities_admit_only_scalar_prepared_import
  installed_cli::metadata_images::tests::image_cli_same_response_binding_and_lost_ack_never_claim_upload_or_replay
  installed_cli::store::tests::preparation_tests::store_prepare_cli_has_two_fixed_separately_reviewed_id_only_commands
  installed_cli::store::tests::preparation_tests::store_prepare_cli_original_response_and_start_grants_cannot_cross_use
  installed_cli::store::tests::preparation_tests::store_prepare_cli_unknown_keeps_ids_and_catalogue_discloses_query_effects
  installed_cli::store::tests::store_cli_lost_ack_has_only_original_status_cancel_and_no_replay
  installed_cli::tests::capabilities_keep_read_grants_separate_from_desktop_reviewed_proposals
  installed_cli::tool_setup::tests::lost_tools_request_receipt_is_id_only_no_replay
  installed_cli::tool_setup::tests::three_tools_cli_verbs_admit_only_reviewed_ids
  installed_cli::upload_key::tests::existing_prepare_output_is_review_only_and_has_no_cli_record_selector
  installed_cli::version_edit::tests::actual_collector_accepts_only_manual_values_or_original_reservation
  installed_cli::version_edit::tests::actual_collector_preserves_three_id_only_verbs_and_explicit_review
  installed_cli::version_edit::tests::compiled_capabilities_disclose_prepared_only_scope_and_same_catalogue
  installed_cli::version_edit::tests::output_matches_same_original_and_unknown_never_claims_new_save_permission
  installed_cli::version_edit::tests::preparation_output_is_exact_kind_original_and_never_an_apply_receipt
  installed_cli_ipc::tests::metadata_exchange_admission_is_fixed_fail_fast_and_reuses_only_its_original_lease
  installed_cli_ipc::tests::metadata_stalled_large_frame_keeps_lease_until_original_stop_close_and_return
  release_version_edit_protocol::tests::agent_prepare_frame_bound_precedes_same_closed_version_decoder
  saved_command_owner::agent_store::preparation::tests::store_preparation_actual_core_decoder_projects_required_inconclusive_inventory
  saved_command_owner::agent_store::preparation::tests::store_preparation_losing_gui_start_checks_link_before_any_retirement_or_take
  saved_command_owner::agent_store::preparation::tests::store_preparation_read_end_and_delayed_earlier_revoke_keep_original_clock
  saved_command_owner::agent_store::tests::store_facet_never_delegates_both_query_or_later_context
  saved_command_owner::agent_store::tests::store_same_original_entry_and_witness_required_before_one_consumption
  saved_command_owner::agent_store::tests::store_watchdog_samples_renewed_old_read_after_stop_and_keeps_earliest_f
  saved_command_owner::apple_key::recovery::tests::recovery_normal_terminal_pipe_stop_never_substitutes_for_original_source_ack_and_joins
  saved_command_owner::apple_provisioning::memory::tests::active_census_requires_same_parent_and_asset_including_key_recover
  saved_command_owner::apple_provisioning::memory::tests::empty_registry_census_is_try_only_and_does_not_poison_or_publish
  saved_command_owner::apple_provisioning::memory::tests::prepared_and_consumed_review_keep_two_exact_inputs_after_registry_unlock
  saved_command_owner::apple_provisioning::memory::tests::retained_quote_keeps_original_buffers_and_only_replaces_absent_material_reservation
  saved_command_owner::apple_provisioning::memory::tests::third_distinct_retained_input_is_refused_not_omitted
  saved_command_owner::apple_provisioning::preparation::tests::delegated_common_commit_foreign_intent_or_lost_history_cannot_enable_start
  saved_command_owner::apple_provisioning::preparation::tests::delegated_common_prepared_commit_never_publishes_before_real_caller_and_history
  saved_command_owner::apple_provisioning::preparation::tests::delegated_gui_start_uses_actual_before_take_handoff_but_inert_material_still_refuses
  saved_command_owner::apple_provisioning::preparation::tests::delegated_prepare_rejects_desktop_only_key_recover_without_changing_context
  saved_command_owner::apple_provisioning::tests::apple_original_clock_and_finite_representation_quote_are_not_renewed
  saved_command_owner::apple_provisioning::tests::apple_original_store_closure_keeps_mode_and_owner_gates
  saved_command_owner::apple_provisioning::tests::apple_start_parent_dispatch_matches_actual_initialized_modes
  saved_command_owner::tool_acquisition::agent::inspect::tests::later_preparation_cannot_renew_original_allow_read_or_first_failure
  saved_command_owner::tool_acquisition::agent::inspect::tests::prepared_retirement_keeps_identity_before_start_and_waits_caller_and_history
  saved_command_owner::tool_acquisition::agent::inspect::tests::saved_inspect_wire_keeps_required_nulls_and_cannot_request_acquisition
  saved_command_owner::tool_acquisition::tests::fixed_acquisition_deadline_and_buffers_are_not_renewed_by_later_phases
  saved_command_owner::tool_acquisition::tests::unqualified_prepare_census_is_not_a_resumable_missing_prerequisite
  service_apple_provisioning_prepare_protocol::tests::prepare_wire_is_only_scalar_addresses_not_context_or_start_permission
  service_apple_provisioning_requests::preparation::tests::prepare_actual_row_metadata_and_two_snapshots_fit_existing_not_new_pool
  service_apple_provisioning_requests::preparation::tests::prepare_and_start_share_original_thirty_two_rows_and_id_domain
  service_apple_provisioning_requests::preparation::tests::prepare_exact_gui_or_separate_start_handoff_rejects_late_old_cancel
  service_apple_provisioning_requests::preparation::tests::prepare_failed_start_install_never_reopens_original_gui_claim
  service_apple_provisioning_requests::preparation::tests::prepare_lost_original_or_history_is_unknown_and_never_replayable
  service_apple_provisioning_requests::preparation::tests::prepare_only_genuine_no_host_refusal_can_finish_without_prepared
  service_apple_provisioning_requests::preparation::tests::prepare_original_construction_caller_and_history_are_three_distinct_cuts
  service_apple_provisioning_requests::preparation::tests::prepare_original_receipt_read_and_scope_expiries_are_not_renewed
  service_apple_provisioning_requests::preparation::tests::prepare_scope_rejects_foreign_or_unbounded_metadata_before_retention
  service_apple_provisioning_requests::tests::apple_cli_exact_modes_and_status_payloads_remain_small_and_closed
  service_apple_provisioning_requests::tests::apple_cli_finite_roster_never_reclaims_terminal_or_unknown_rows
  service_configuration_requests::images::tests::exact_old_image_origin_survives_next_grant_and_cross_family_collision_refuses
  service_configuration_requests::images::tests::image_nonce_tombstones_and_config_rows_share_original32_without_fake_origins
  service_configuration_requests::tests::duplicate_read_is_same_data_and_other_request_cannot_replace_live_or_unknown_original
  service_configuration_requests::tests::exact_desktop_query_keeps_old_refusal_after_latest_row_without_fallback
  service_configuration_requests::tests::exactly_thirty_two_cancelled_metadata_rows_stay_discoverable_without_history_eviction
  service_configuration_requests::tests::wrong_origin_close_and_poison_cannot_rearm_a_prior_request
  service_github_action_requests::memory::tests::full_retained_row_and_ancillary_have_real_typed_bounds_not_response_size
  service_github_action_requests::memory::tests::retained_ceiling_failure_never_borrows_a_retired_row_or_worker_credit
  service_github_action_requests::tests::metadata_census_includes_rows_and_all_eight_worker_copies
  service_github_action_requests::tests::one_32_row_pool_retains_old_three_kind_tombstones_and_refuses_the_33rd
  service_github_action_requests::tests::short_metadata_with_overbound_physical_capacity_is_not_admitted
  service_github_action_requests::tests::three_kinds_require_caller_native_and_same_history_in_either_order
  service_metadata_images_protocol::tests::closed_image_submit_contains_no_source_bytes_paths_choices_or_recovery
  service_metadata_images_protocol::tests::image_access_requires_exact_nullable_group_and_same_original_review
  service_metadata_images_protocol::tests::original_image_effect_and_finality_cannot_be_manufactured_from_display_counts
  service_metadata_images_requests::tests::image_entry_needs_original_raw_native_and_history_returns_once
  service_metadata_images_requests::tests::image_lost_raw_or_history_failure_remains_unknown_never_replayed
  service_metadata_images_requests::tests::image_original_earliest_read_stop_and_expired_grant_never_renew
  service_metadata_images_requests::tests::image_preapply_native_cancel_can_settle_but_missing_retirement_cannot
  service_metadata_images_requests::tests::unused_image_lease_gui_winner_does_not_inherit_read_or_revoke_stop
  service_metadata_text_protocol::tests::bounded_encoder_counts_real_escaping_before_allocation_and_names_same_eight_callers
  service_metadata_text_requests::tests::original_unknown_or_lost_caller_is_absorbing_and_cannot_release_the_shared_queue
  service_metadata_text_requests::tests::same_thirty_two_combined_rows_have_closed_family_ids_and_original_query_after_coalescing
  service_protocol::ipc_response_tests::largest_closed_generic_lists_fit_the_source_derived_wire_and_typed_roster
  service_protocol::ipc_response_tests::metadata_full_text_keeps_the_same_fixed_encoder_and_never_changes_frame_limits
  service_protocol::ipc_response_tests::outer_fixed_encoder_preserves_old_envelopes_bytes_and_exact_capacity
  service_protocol::ipc_response_tests::validation_and_oversize_errors_are_identical_without_growable_outer_output
  service_request_catalogue::tests::combined_build_capacity_and_id_namespace_are_not_per_family
  service_store_requests::tests::preparation_tests::prepare_and_original_rows_share_all_32_slots_and_keep_last_failed_history
  service_store_requests::tests::preparation_tests::prepare_attachment_fact_and_actual_return_are_both_required_before_start
  service_store_requests::tests::preparation_tests::prepare_complete_2mib_quote_includes_mixed_rows_native_history_and_all_copies
  service_store_requests::tests::preparation_tests::prepare_complete_requires_actual_start_claim_and_original_status_is_correlated
  service_store_requests::tests::preparation_tests::prepare_inventory_is_closed_owned_data_and_excess_capacity_is_refused
  service_store_requests::tests::preparation_tests::prepare_progress_history_is_not_terminal_ack_and_failed_claim_is_retained
  service_store_requests::tests::preparation_tests::prepare_start_native_and_history_returns_keep_same_original_in_both_orders
  service_store_requests::tests::preparation_tests::prepare_stop_before_start_is_not_retirement_and_original_read_tightens_first_f
  service_store_requests::tests::preparation_tests::prepare_wrong_phase_ids_retries_and_dropped_original_call_never_reexecute
  service_store_requests::tests::store_finite_roster_never_reclaims_terminal_or_unknown_rows
  service_store_requests::tests::store_triple_cut_in_both_native_caller_orders
  service_tool_setup_protocol::tests::exact_struct_report_and_global_frame_bounds
  service_tool_setup_protocol::tests::five_closed_reviews_require_exact_pairs_and_no_extra_fields
  service_tool_setup_protocol::tests::summaries_do_not_upgrade_completion_or_foreign_original
  service_tool_setup_requests::tests::bounded_consent_exhaustion_and_document_loss_do_not_reset
  service_tool_setup_requests::tests::cancelled_unentered_still_needs_actual_caller_and_history
  service_tool_setup_requests::tests::exact_duplicate_nonce_and_foreign_cancel_do_not_replay_or_stop
  service_tool_setup_requests::tests::lost_caller_history_and_contradictory_callback_stay_unknown
  service_tool_setup_requests::tests::quiet_read_facet_preserves_earliest_failure_and_absolute_permission
  service_tool_setup_requests::tests::three_real_return_slots_required_in_both_callback_orders
  service_upload_key_protocol::preparation::tests::prepared_comparison_is_bounded_and_never_a_grant_for_other_actions
  service_upload_key_requests::tests::attempted_preparation_without_install_and_lost_original_return_are_absorbing_unknown
  service_upload_key_requests::tests::backup::both_backup_kinds_keep_the_same_three_original_return_barriers_in_all_orders
  service_upload_key_requests::tests::backup::late_original_stop_suppresses_delivery_and_new_reference_without_replaying
  service_upload_key_requests::tests::backup::lost_caller_or_continuation_and_wrong_native_kind_are_absorbing_unknown
  service_upload_key_requests::tests::every_order_requires_actual_caller_native_and_continuation_returns
  service_upload_key_requests::tests::read_revoke_and_original_end_never_renew_or_infer_success_on_stop
  service_upload_key_requests::tests::reuse::existing_prepare_is_a_closed_selection_with_its_own_consent_and_no_fields
  service_upload_key_requests::tests::reuse::prepare_and_old_actions_share_exactly_the_original_thirty_two_rows
  service_upload_key_requests::tests::reuse::prepare_loss_or_late_stop_cannot_publish_a_usable_review_or_replay
  service_upload_key_requests::tests::reuse::review_ready_needs_all_three_original_returns_and_never_becomes_assignment
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
  supervisor::history::download_tests::download_requires_each_original_driver_return_and_no_prior_failure
  supervisor::macos_github_actions_original_data_contract
  vault_store::macos::bound_read_tests::new_record_read_matches_reserved_intent_and_exact_sealed_length
  vault_store::macos::bound_read_tests::read_refusal_and_stop_never_erase_already_known_new_effect
  vault_store::macos::bound_read_tests::stored_record_read_checks_original_witness_and_allowance_before_body
  vault_store::macos::tests::apple_key_full_read_is_bound_before_body_allocation
)
[[ "${#selected_tests[@]}" == 249 ]] || exit 1
list_log="$MRK_MACOS_WORK/git-selected-contracts-list.log"
run_log="$MRK_MACOS_WORK/git-selected-contracts.log"
[[ ! -e "$list_log" && ! -L "$list_log" && ! -e "$run_log" && ! -L "$run_log" ]] || exit 1
cargo=("$rust_bin/cargo" test --locked --offline --jobs 1 --no-default-features
  --features desktop-shell,custom-protocol,macos-installed-observation
  --target "$MRK_MACOS_TARGET" --manifest-path desktop/src-tauri/Cargo.toml --lib --)
# Ordinary Cargo list+run reuse the same one test binary. Exact count
# and each-once checks prevent absent/renamed cfg tests passing as zero.
"${cargo[@]}" "${selected_tests[@]}" --exact --list --color=never | /usr/bin/tee "$list_log"
/usr/bin/grep -Fx '249 tests, 0 benchmarks' "$list_log"
for test_name in "${selected_tests[@]}"; do
  [[ "$(/usr/bin/grep -Fxc "$test_name: test" "$list_log")" == 1 ]]
done
"${cargo[@]}" "${selected_tests[@]}" --exact --test-threads=1 --color=never --format=pretty | /usr/bin/tee "$run_log"
/usr/bin/grep -Eq '^test result: ok\. 249 passed; 0 failed; 0 ignored;' "$run_log"

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
