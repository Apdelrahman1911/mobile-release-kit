set -euo pipefail
set -o noclobber
umask 077
[[ "$GITHUB_REF" == refs/heads/verify/desktop-macos-candidate && "$MRK_MACOS_NATIVE_SCOPE" == git-native && "$MRK_MACOS_PACKAGE_ROLE" == installed-shell-observation ]] || exit 1
[[ "$MRK_MACOS_TARGET" == aarch64-apple-darwin && "$RUSTUP_TOOLCHAIN" == 1.98.1 && "$(/usr/bin/id -u)" != 0 ]] || exit 1
[[ "$CARGO_TARGET_DIR" == "$MRK_MACOS_WORK/cargo-target" ]] || exit 1
# The canonical harness=false observer build/JSON remains untouched.
# This ONE ordinary libtest links against the same debug feature graph
# and same original source/release environment. No release/profile switch.
# 34 DATA cases plus one existing private Service/Store fixture; that
# fixture stops/closes/drops its own directory. No native Git or account.
rust_bin="/Users/runner/.rustup/toolchains/${RUSTUP_TOOLCHAIN}-$MRK_MACOS_TARGET/bin"
export PATH="$rust_bin:/usr/bin:/bin:/usr/sbin:/sbin" RUSTC="$rust_bin/rustc"
export CARGO_HOME=/Users/runner/.cargo RUSTUP_HOME=/Users/runner/.rustup RUSTUP_AUTO_INSTALL=0
selected_tests=(
  service_git_remote_protocol::tests::new_branch_is_explicit_required_null_and_never_an_ordinary_grant
  service_git_remote_protocol::tests::adding_new_kind_preserves_old_selection_bytes_and_digest_domain
  service_git_remote_protocol::tests::create_only_review_and_result_cannot_launder_kind_basis_or_effect
  service_git_remote_protocol::tests::create_only_escaped_summary_keeps_existing_encoded_bound
  asset_session::agent_git_index::remote::tests::first_publication_needs_current_born_attached_unconfigured_observe_not_an_alias
  asset_session::agent_git_index::remote::tests::new_branch_allow_cannot_borrow_old_consent_or_missing_remote_field
  asset_session::agent_git_index::remote::native::tests::fixed_native_adapter_preserves_new_kind_and_exact_review_not_ordinary_push
  asset_session::agent_git_index::remote::native::tests::new_branch_effect_conversion_checks_original_kind_intent_and_id
  service_git_requests::remote_requests::tests::new_branch_prepare_and_apply_keep_same_three_returns_and_single_consumed_kind
  service_git_requests::remote_requests::tests::new_branch_lost_finish_caller_or_expired_review_never_rearms_from_status
  service_git_requests::remote_requests::tests::an_existing_fetch_or_push_grant_cannot_be_upgraded_to_new_branch_review
  application_service::git_index::remote::tests::actual_service_new_branch_grant_reconnect_keeps_ids_kind_and_no_replay
  installed_cli::git_index::remote_tests::new_branch_scope_uses_existing_id_only_commands_and_explains_no_upstream
  installed_cli::git_index::remote_tests::new_branch_ready_and_returned_failure_keep_exact_kind_without_retry_command
  shell::installed_observation::git_push::create::tests::create_case_kind_never_qualifies_an_ordinary_push_control
  shell::installed_observation::git_push::create::tests::prepare_only_requires_actual_refusal_without_review_or_apply_claim
  shell::installed_observation::git_push::create::tests::create_review_keeps_both_reachable_commits_and_absent_upstream
  shell::installed_observation::git_push::create::tests::rejected_zero_precondition_is_not_success_or_pre_send_refusal
  shell::installed_observation::git_push::create::tests::fresh_apply_refusal_keeps_recovery_paths_and_held_stop_is_not_returned
  git_upstream_protocol::tests::exact_local_action_keeps_initialize_and_other_wire_shapes_closed
  git_upstream_protocol::tests::source_absence_requires_exact_parent_entries_not_none_as_an_observation
  git_upstream_protocol::tests::additions_preserve_original_prefix_identity_and_existing_config_limit
  git_upstream_protocol::tests::directory_ack_is_candidate_bound_under_original_512_bytes
  git_upstream_protocol::tests::public_result_omits_working_paths_and_stats_but_retains_uncertain_custody
  git_upstream_protocol::tests::local_cli_selection_uses_same_closed_action_not_remote_permission
  git_upstream_protocol::tests::unchanged_upstream_is_close_only_at_actual_shared_cli_start_predicate
  git_local_state::upstream_tests::schema_nine_is_only_explicit_upstream_write_and_preserves_old_rows
  git_local_state::upstream_tests::upstream_candidate_and_partial_directories_never_allow_no_effect_or_retry
  asset_source::macos::git_local_sources::upstream_sources::tests::attempted_or_ambiguous_directory_creation_is_not_retirement_or_retry
  asset_source::macos::git_local_sources::upstream_sources::tests::upstream_roster_charges_both_full_chains_and_working_originals_without_close_credit
  apple_provisioning_protocol::certificate_recovery::tests::restored_key_history_compares_both_hashes_without_rewriting_old_rows_or_key_saved
  apple_provisioning_protocol::certificate_recovery::tests::restored_key_hashes_cannot_disclose_foreign_project_root_or_target
  apple_provisioning_protocol::certificate_recovery::tests::restored_prior_stays_reconcile_only_and_both_key_hashes_are_rechecked
  saved_command_owner::apple_provisioning::tests::certificate_history_requires_original_entered_returned_key_ack_not_completed_data
  shell::installed_observation::git_upstream::tests::configured_without_tracking_is_not_remote_or_commit_publication
)
[[ "${#selected_tests[@]}" == 35 ]] || exit 1
list_log="$MRK_MACOS_WORK/git-selected-contracts-list.log"
run_log="$MRK_MACOS_WORK/git-selected-contracts.log"
[[ ! -e "$list_log" && ! -L "$list_log" && ! -e "$run_log" && ! -L "$run_log" ]] || exit 1
cargo=("$rust_bin/cargo" test --locked --offline --jobs 1 --no-default-features
  --features desktop-shell,custom-protocol,macos-installed-observation
  --target "$MRK_MACOS_TARGET" --manifest-path desktop/src-tauri/Cargo.toml --lib --)
# Ordinary Cargo list+run reuse the same one test binary. Exact count
# and each-once checks prevent absent/renamed cfg tests passing as zero.
"${cargo[@]}" "${selected_tests[@]}" --exact --list --color=never | /usr/bin/tee "$list_log"
/usr/bin/grep -Fx '35 tests, 0 benchmarks' "$list_log"
for test_name in "${selected_tests[@]}"; do
  [[ "$(/usr/bin/grep -Fxc "$test_name: test" "$list_log")" == 1 ]]
done
"${cargo[@]}" "${selected_tests[@]}" --exact --test-threads=1 --color=never --format=pretty | /usr/bin/tee "$run_log"
/usr/bin/grep -Eq '^test result: ok\. 35 passed; 0 failed; 0 ignored;' "$run_log"
