set -euo pipefail
set -o noclobber
umask 077
[[ "$GITHUB_REF" == refs/heads/verify/desktop-macos-candidate && "$MRK_MACOS_NATIVE_SCOPE" == tool-setup && "$MRK_MACOS_PACKAGE_ROLE" == installed-shell-observation ]] || exit 1
[[ "$MRK_MACOS_TARGET" == aarch64-apple-darwin && "$RUSTUP_TOOLCHAIN" == 1.98.1 && "$(/usr/bin/id -u)" != 0 ]] || exit 1
[[ "$CARGO_TARGET_DIR" == "$MRK_MACOS_WORK/cargo-target" ]] || exit 1
# The canonical harness=false observer build/JSON remains untouched.
# This ONE ordinary libtest links against the same debug feature graph
# and same original source/release environment. No release/profile switch.
# Replace the completed 77 roster, not the original owner or native observer.
# 19 VersionEdit + 11 FutureTag + 28 GitHub3 + 28 Metadata + 16 ToolSetup
# + 5 Apple admission + 1 Config fit + 3 catalogue + 3 older affected checks;
# the FutureTag alias method is counted once (113 total).
# Reuse 73 of 76 prior successes; the two catalogue methods, CLI discovery
# and the prior failed Apple fit remain selected. Publication CLI is not added.
# Six tests use private StatePort/Service fixtures; one more uses bounded local
# Unix IPC. Two Tool tests join inert tasks/threads; all others are memory DATA.
# Preserve their original closes/joins. No native/provider/product operation.
rust_bin="/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin"
export PATH="$rust_bin:/usr/bin:/bin:/usr/sbin:/sbin" RUSTC="$rust_bin/rustc"
export CARGO_HOME=/Users/runner/.cargo RUSTUP_HOME=/Users/runner/.rustup RUSTUP_AUTO_INSTALL=0
# This gate now precedes the observer's online build. Populate the locked
# dependency cache explicitly; list/run below remain offline and reuse one
# test binary. The embedded frontend has already been built for Tauri.
"$rust_bin/cargo" fetch --locked --target "$MRK_MACOS_TARGET" --manifest-path desktop/src-tauri/Cargo.toml
selected_tests=(
  service_version_edit_protocol::tests::exact_submit_cannot_supply_path_values_or_borrow_other_consent
  service_version_edit_protocol::tests::access_requires_exact_nulls_and_bound_result_never_empty_success
  service_version_edit_requests::tests::install_precedes_public_allow_and_revoke_before_allow_is_not_rearmed
  service_version_edit_requests::tests::permanent_submit_binds_same_lease_and_duplicate_never_enters_twice
  service_version_edit_requests::tests::gui_winner_spends_unused_lease_without_borrowing_its_later_stop
  service_version_edit_requests::tests::final_seal_serializes_submit_without_a_dropped_unobserved_entry
  service_version_edit_requests::tests::original_read_clock_and_earliest_stop_survive_unavailable_renderer_or_renewal
  service_version_edit_requests::tests::missing_original_or_unknown_is_absorbing_and_counter_overflow_never_rearms
  service_version_edit_requests::tests::failed_native_retirement_and_exact_old_query_cannot_be_relabelled_current
  service_version_edit_requests::tests::revoke_nonce_capacity_preserves_other_live_original_and_never_evicts
  application_service::agent_version_edit::tests::genuine_service_read_reconnect_revoke_and_alias_never_mint_prepared_apply
  edit_owner::agent_version_edit::tests::real_owner_without_original_prepared_cannot_mint_or_claim_lease
  edit_owner::agent_version_edit::tests::borrowed_original_version_and_foreign_last_capacities_are_never_free_credit
  asset_session::agent_version_edit::tests::actual_raw_variant_requires_only_exact_original_not_values_or_window
  asset_session::agent_version_edit::tests::real_document_and_original_edit_future_include_retained_buffer_and_overflow
  installed_cli::version_edit::tests::actual_collector_preserves_three_id_only_verbs_and_explicit_review
  installed_cli::version_edit::tests::output_matches_same_original_and_unknown_never_claims_new_save_permission
  installed_cli::version_edit::tests::compiled_capabilities_disclose_prepared_only_scope_and_same_catalogue
  service_version_edit_requests::tests::known_cleanup_poll_keeps_original_cutoff_and_resamples_earlier_read_revocation
  version_allocation_state_native::future_tag::tests::future_tag_shapes_do_not_relabel_branch_or_accept_null
  version_allocation_state_native::future_tag::tests::future_wire_domain_is_separate_from_real_inventory_policy
  version_allocation_state_native::future_tag::tests::v5_pending_uses_the_same_retained_port_and_never_relabels_inventory_or_source
  github_play_cleanup_protocol::version_tag::tests::selection_has_no_tag_command_path_token_or_platform_authority
  github_play_cleanup_protocol::version_tag::tests::prepared_tag_is_exact_branch_bound_body_and_once_key_excludes_final_commit
  github_play_cleanup_protocol::version_tag::tests::pending_discovery_is_typed_but_has_no_prepare_or_dispatch_selection
  github_play_cleanup_protocol::version_tag::tests::automatic_tag_versions_keep_two_or_three_components_and_platform_ceilings
  service_play_cleanup_protocol::tests::typed_tag_wire_never_widens_old_default_or_accepts_free_provider_arguments
  service_play_cleanup_requests::tests::tag_and_cleanup_share_one_grant_and_namespace_but_never_each_others_consent
  service_request_catalogue::tests::future_tag_discovery_shares_cleanup_namespace_and_routes_exact_status
  installed_cli::play_cleanup::tests::original_collector_routes_tag_ids_and_lost_ack_to_exact_typed_status_only
  service_github_action_protocol::tests::exact_three_kinds_and_original_operation_ids_do_not_upgrade_another_grant
  service_github_action_protocol::tests::strict_request_framing_refuses_private_fields_and_omitted_required_nulls
  service_github_action_protocol::tests::effect_and_never_admitted_are_not_interchangeable_with_native_success
  service_github_action_protocol::tests::all_closed_metadata_fits_status_with_wrapper_and_never_contains_material
  service_github_action_requests::tests::three_kinds_require_caller_native_and_same_history_in_either_order
  service_github_action_requests::tests::known_pre_registration_refusal_has_no_native_receipt
  service_github_action_requests::tests::entered_failure_or_lost_caller_is_unknown_not_never_admitted
  service_github_action_requests::tests::progress_history_ack_cannot_settle_later_final
  service_github_action_requests::tests::history_failure_and_drop_are_absorbing_even_after_native_return
  service_github_action_requests::tests::same_id_reconnect_is_not_a_second_submit_or_claim
  service_github_action_requests::tests::exact_scope_and_service_ids_are_required
  service_github_action_requests::tests::old_read_revoke_keeps_earlier_failure_after_later_stop
  service_github_action_requests::tests::wrong_kind_id_and_foreign_effect_do_not_supply_completion
  service_github_action_requests::tests::go_fact_is_monotone_and_does_not_imply_http_success
  service_github_action_requests::tests::metadata_census_includes_rows_and_all_eight_worker_copies
  service_github_action_requests::tests::short_metadata_with_overbound_physical_capacity_is_not_admitted
  service_github_action_requests::tests::one_32_row_pool_retains_old_three_kind_tombstones_and_refuses_the_33rd
  service_github_action_requests::tests::same_original_stop_advances_once_and_earlier_read_refines_without_finality
  service_github_action_requests::tests::exact_document_query_survives_new_lease_without_adopting_another_doc
  installed_cli::github_action::tests::three_fixed_verbs_use_only_ids_and_submit_requires_reviewed_confirmation
  installed_cli::github_action::tests::returned_status_and_lost_reply_keep_exact_original_ids_and_no_replay
  installed_cli::github_action::tests::real_local_catalogue_keeps_one_closed_mutation_family_and_finite_output
  github_connection_session::action_delegation::tests::streamed_review_binds_private_input_and_actual_original_edit_stamp
  github_connection_session::action_delegation::tests::optional_origin_requires_same_claimed_live_scope_not_equal_metadata
  github_connection_session::action_delegation::tests::typed_native_refusal_mapping_cannot_clear_unknown_or_supply_other_returns
  asset_session::agent_github_action::tests::fixed_main_decoder_accepts_only_the_original_closed_three_selections
  asset_session::agent_github_action::tests::request_byte_bound_precedes_typed_parse_without_a_generic_value_tree
  application_service::agent_github_action::tests::copied_status_presend_rechecks_project_alias_and_same_read_grant
  service_request_catalogue::tests::combined_build_capacity_and_id_namespace_are_not_per_family
  service_request_catalogue::tests::additional_ids_have_strict_schema_presence_privacy_and_original_commands
  service_metadata_text_protocol::tests::conventional_complete_ios_and_android_unicode_bundles_cross_old_limit_without_truncation
  service_metadata_text_protocol::tests::strict_large_entry_refuses_old_methods_duplicates_extras_and_unbounded_containers
  service_metadata_text_protocol::tests::ordinary_four_kib_and_complete_field_order_limits_remain_exact
  service_metadata_text_protocol::tests::bounded_encoder_counts_real_escaping_before_allocation_and_names_same_eight_callers
  service_metadata_text_protocol::tests::native_load_data_requires_all_paths_hashes_baseline_and_empty_absent_distinction
  service_metadata_text_requests::tests::load_visibility_waits_both_original_returns_in_either_order
  service_metadata_text_requests::tests::original_unknown_or_lost_caller_is_absorbing_and_cannot_release_the_shared_queue
  service_metadata_text_requests::tests::same_loaded_arc_and_prepare_digest_are_not_reloaded_or_retargeted
  service_metadata_text_requests::tests::exact_revoke_before_allow_and_read_expiry_never_rearm_the_review
  service_metadata_text_requests::tests::apply_consumes_once_and_final_waits_return_while_cancelled_effect_is_not_saved
  service_metadata_text_requests::tests::same_thirty_two_combined_rows_have_closed_family_ids_and_original_query_after_coalescing
  service_metadata_text_requests::tests::public_load_lifetime_ends_at_original_read_stop_not_a_later_status
  application_service::agent_metadata_text::tests::current_read_enqueues_without_store_mutation_and_does_not_authorize_apply
  application_service::agent_metadata_text::tests::renewal_observes_and_stops_old_request_but_never_revives_original_facet
  application_service::agent_metadata_text::tests::wrong_project_stale_alias_and_unobserved_poison_are_not_read_or_native_authority
  edit_owner::agent_metadata_text::tests::exact_metadata_publications_cannot_skip_repeat_or_rebase
  edit_owner::agent_metadata_text::tests::metadata_agent_commands_accept_only_original_ids_and_separate_consent
  edit_owner::agent_metadata_text::tests::fresh_open_comparison_retains_all_config_field_and_root_witnesses
  edit_owner::agent_metadata_text::tests::missing_metadata_retirement_chain_never_changes_resource_facts_into_saved
  edit_owner::agent_configuration::memory::metadata_tests::metadata_borrowed_census_keeps_original_other_domain_last_and_actual_capacity
  edit_owner::agent_configuration::memory::metadata_tests::complete_metadata_submission_and_frame_are_bounded_before_adopting_or_cloning
  installed_cli::metadata_text::tests::actual_collector_keeps_five_fixed_verbs_and_explicit_apply_review
  installed_cli::metadata_text::tests::stdin_accepts_complete_long_public_fields_but_not_sparse_or_oversize_inputs
  installed_cli::metadata_text::tests::capability_output_preserves_old_request_bound_and_names_new_only_limits
  installed_cli::metadata_text::tests::missing_ack_output_retains_only_original_ids_and_never_invites_replay
  asset_session::agent_metadata_text::metadata_storage_tests::actual_default_document_fits_metadata_quote_and_retained_capacity_refuses
  installed_cli_ipc::tests::metadata_exchange_admission_is_fixed_fail_fast_and_reuses_only_its_original_lease
  installed_cli_ipc::tests::metadata_stalled_large_frame_keeps_lease_until_original_stop_close_and_return
  asset_session::agent_configuration::configuration_storage_tests::actual_default_document_fits_configuration_quote_and_retained_capacity_refuses
  service_tool_setup_protocol::tests::five_closed_reviews_require_exact_pairs_and_no_extra_fields
  service_tool_setup_protocol::tests::summaries_do_not_upgrade_completion_or_foreign_original
  service_tool_setup_protocol::tests::exact_struct_report_and_global_frame_bounds
  service_tool_setup_requests::tests::three_real_return_slots_required_in_both_callback_orders
  service_tool_setup_requests::tests::exact_duplicate_nonce_and_foreign_cancel_do_not_replay_or_stop
  service_tool_setup_requests::tests::lost_caller_history_and_contradictory_callback_stay_unknown
  service_tool_setup_requests::tests::quiet_read_facet_preserves_earliest_failure_and_absolute_permission
  service_tool_setup_requests::tests::cancelled_unentered_still_needs_actual_caller_and_history
  service_tool_setup_requests::tests::bounded_consent_exhaustion_and_document_loss_do_not_reset
  installed_cli::tool_setup::tests::three_tools_cli_verbs_admit_only_reviewed_ids
  installed_cli::tool_setup::tests::lost_tools_request_receipt_is_id_only_no_replay
  asset_session::agent_tool_setup::tests::document_limit_is_checked_not_inferred_from_a_successful_census
  asset_session::agent_tool_setup::tests::actual_default_document_and_near_limit_copied_doctor_input_fit
  environment_diagnostics_owner::agent::tests::quiet_read_revoke_reaches_original_doctor_join_and_keeps_earlier_f
  environment_diagnostics_owner::agent::tests::doctor_quote_counts_real_value_heap_not_only_encoded_draft
  saved_command_owner::android_registration::agent::tests::quiet_read_revocation_interrupts_original_registration_wait_without_relay
  asset_session::shared_memory_tests::actual_document_plus_apple_future_fits_original_session_limit
  asset_session::shared_memory_tests::actual_document_and_retained_capacity_obey_shared_admission
  asset_session::shared_memory_tests::actual_mac_native_quotes_fit_current_document_before_any_runtime_is_opened
  asset_session::apple_provisioning::agent::tests::apple_cli_uses_actual_default_document_plus_two_profile_payload_quotes
  saved_command_owner::apple_provisioning::tests::apple_original_clock_and_finite_representation_quote_are_not_renewed
  asset_session::play_cleanup::tests::actual_document_growth_preserves_separate_cleanup_and_document_limits
  installed_cli::tests::capabilities_keep_read_grants_separate_from_desktop_reviewed_proposals
  installed_cli::tests::requests_is_discovery_only_and_rejects_action_parameters_and_foreign_instance
)
[[ "${#selected_tests[@]}" == 113 ]] || exit 1
list_log="$MRK_MACOS_WORK/git-selected-contracts-list.log"
run_log="$MRK_MACOS_WORK/git-selected-contracts.log"
[[ ! -e "$list_log" && ! -L "$list_log" && ! -e "$run_log" && ! -L "$run_log" ]] || exit 1
cargo=("$rust_bin/cargo" test --locked --offline --jobs 1 --no-default-features
  --features desktop-shell,custom-protocol,macos-installed-observation
  --target "$MRK_MACOS_TARGET" --manifest-path desktop/src-tauri/Cargo.toml --lib --)
# Ordinary Cargo list+run reuse the same one test binary. Exact count
# and each-once checks prevent absent/renamed cfg tests passing as zero.
"${cargo[@]}" "${selected_tests[@]}" --exact --list --color=never | /usr/bin/tee "$list_log"
/usr/bin/grep -Fx '113 tests, 0 benchmarks' "$list_log"
for test_name in "${selected_tests[@]}"; do
  [[ "$(/usr/bin/grep -Fxc "$test_name: test" "$list_log")" == 1 ]]
done
"${cargo[@]}" "${selected_tests[@]}" --exact --test-threads=1 --color=never --format=pretty | /usr/bin/tee "$run_log"
/usr/bin/grep -Eq '^test result: ok\. 113 passed; 0 failed; 0 ignored;' "$run_log"
