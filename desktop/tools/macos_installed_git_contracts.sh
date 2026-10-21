set -euo pipefail
set -o noclobber
umask 077
[[ "$GITHUB_REF" == refs/heads/verify/desktop-macos-candidate && "$MRK_MACOS_NATIVE_SCOPE" == tool-setup && "$MRK_MACOS_PACKAGE_ROLE" == installed-shell-observation ]] || exit 1
[[ "$MRK_MACOS_TARGET" == aarch64-apple-darwin && "$RUSTUP_TOOLCHAIN" == 1.98.1 && "$(/usr/bin/id -u)" != 0 ]] || exit 1
[[ "$CARGO_TARGET_DIR" == "$MRK_MACOS_WORK/cargo-target" ]] || exit 1
# The canonical harness=false observer build/JSON remains untouched.
# This ONE ordinary libtest links against the same debug feature graph
# and same original source/release environment. No release/profile switch.
# Activate this 31-only next roster only after Root verifies the preceding
# Git46 gate actually passed; otherwise the new backup11 remain due.
# 18 Store + 5 paired-version + 1 P12-parent + 7 request-discovery cases.
# Six methods use existing disposable private Store/Service fixtures with
# their original close/drop paths; the rest are memory/codec/constructor DATA.
# No provider access, live credentials, tool download or product execution.
rust_bin="/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin"
export PATH="$rust_bin:/usr/bin:/bin:/usr/sbin:/sbin" RUSTC="$rust_bin/rustc"
export CARGO_HOME=/Users/runner/.cargo RUSTUP_HOME=/Users/runner/.rustup RUSTUP_AUTO_INSTALL=0
selected_tests=(
  service_store_protocol::release::tests::store_release_exact_ten_pairs_have_distinct_non_upgrading_consent
  service_store_protocol::release::tests::store_release_old_eight_fields_stay_exact_without_nullable_upgrade
  service_store_protocol::release::tests::store_release_review_requires_exact_candidate_intent_and_lineage
  service_store_protocol::release::tests::store_release_receipts_preserve_mode_state_and_non_finality_limitations
  service_store_protocol::release::tests::store_release_ios_review_states_never_become_tester_or_public_readiness
  service_store_protocol::release::tests::store_release_worst_valid_metadata_fits_unchanged_retained_copy_quotes
  service_store_requests::tests::release_tests::store_release_all_modes_need_same_caller_native_and_history_returns
  service_store_requests::tests::release_tests::store_release_same_request_reconnect_never_consumes_second_grant_or_mode
  service_store_requests::tests::release_tests::store_release_cross_mode_result_or_lost_history_keeps_unknown_fence
  service_store_requests::tests::release_tests::store_release_earliest_read_revocation_is_not_renewed_by_mode_or_status
  saved_command_owner::agent_store::tests::release_tests::store_release_saved_reviews_bind_all_actual_native_modes_and_private_contexts
  saved_command_owner::agent_store::tests::release_tests::store_release_native_consent_is_distinct_from_every_agent_token
  saved_command_owner::agent_store::tests::release_tests::store_release_validated_native_results_redact_private_receipt_and_preserve_real_mode
  saved_command_owner::agent_store::tests::release_tests::store_release_decoded_terminal_is_not_positive_native_retirement
  saved_command_owner::agent_store::tests::release_tests::store_release_old_link_or_missing_execute_budget_refuses_before_take
  installed_cli::store::tests::release_tests::store_release_cli_all_modes_report_only_exact_sanitized_original
  installed_cli::store::tests::release_tests::store_release_cli_permission_metadata_does_not_add_material_or_mode_arguments
  installed_cli::store::tests::store_cli_lost_ack_has_only_original_status_cancel_and_no_replay
  edit_owner::version_reserve::tests::reserved_handoff_data_admits_only_exact_current_inventory_platform_policies
  edit_owner::version_reserve::tests::paired_handoff_retains_original_envelope_provider_and_byte_bound
  version_allocation_state_native::dialogue::tests::native_source_admits_paired_v4_without_changing_original_v2_v3_selection
  version_allocation_state_native::dialogue::tests::paired_native_source_refuses_foreign_source_provider_or_partial_observations
  version_allocation_state_native::dialogue::tests::paired_native_selection_rejects_mixed_policy_platforms_without_replacing_candidate
  saved_command_owner::apple_provisioning::tests::apple_start_parent_dispatch_matches_actual_initialized_modes
  service_play_cleanup_requests::tests::retained_ids_are_project_bound_and_never_expire_claim_or_forget_an_original
  service_request_catalogue::tests::combined_build_capacity_and_id_namespace_are_not_per_family
  service_request_catalogue::tests::additional_ids_have_strict_schema_presence_privacy_and_original_commands
  application_service::request_catalogue::tests::lost_ack_reconnect_discovers_git_identity_and_reservation_without_private_data_or_replay
  application_service::request_catalogue::tests::unavailable_additional_inbox_is_not_successful_empty_discovery
  application_service::request_catalogue::tests::project_filter_alias_and_pre_send_revoke_do_not_leak_other_requests
  installed_cli::tests::requests_is_discovery_only_and_rejects_action_parameters_and_foreign_instance
)
[[ "${#selected_tests[@]}" == 31 ]] || exit 1
list_log="$MRK_MACOS_WORK/git-selected-contracts-list.log"
run_log="$MRK_MACOS_WORK/git-selected-contracts.log"
[[ ! -e "$list_log" && ! -L "$list_log" && ! -e "$run_log" && ! -L "$run_log" ]] || exit 1
cargo=("$rust_bin/cargo" test --locked --offline --jobs 1 --no-default-features
  --features desktop-shell,custom-protocol,macos-installed-observation
  --target "$MRK_MACOS_TARGET" --manifest-path desktop/src-tauri/Cargo.toml --lib --)
# Ordinary Cargo list+run reuse the same one test binary. Exact count
# and each-once checks prevent absent/renamed cfg tests passing as zero.
"${cargo[@]}" "${selected_tests[@]}" --exact --list --color=never | /usr/bin/tee "$list_log"
/usr/bin/grep -Fx '31 tests, 0 benchmarks' "$list_log"
for test_name in "${selected_tests[@]}"; do
  [[ "$(/usr/bin/grep -Fxc "$test_name: test" "$list_log")" == 1 ]]
done
"${cargo[@]}" "${selected_tests[@]}" --exact --test-threads=1 --color=never --format=pretty | /usr/bin/tee "$run_log"
/usr/bin/grep -Eq '^test result: ok\. 31 passed; 0 failed; 0 ignored;' "$run_log"
