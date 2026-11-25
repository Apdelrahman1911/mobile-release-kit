# Genuine local-history CLI Prepare — 2026-10-22

## Scope and original owner

This adds `mrk local-history-prepare PROJECT_ID SERVICE_INSTANCE KIND [UUID [--android|--ios]] [--json]` to the existing four History commands. It prepares a comparison through the real registered-project LocalHistory/Saved owner; **Prepare does not enroll, execute, grant Start, read Keychain, or open the journal**. The existing installed runtime must still be qualified. A running Desktop and its original project READ permission are required. No saved config, version, Store material, provider query, new transport, new service, or unattended/headless owner is added.

The independent plan is `.task-local-history-prepare/plan.md`, SHA `db148b83f60127b7cbdac44126cdadb1ee1737201ee2e654e292a3832a06a47f` (Cleanup; Root GO). Root integrates the detached hook, not copies of unrelated parent files. Implementation worktree base is `546209847d9c787cd7db7b886b08c63cc4582ed7`; final shared images target current `324ada874bb5ef3213c60ea339e31590d8e45b8e`.

### Closed selection table (16 contexts)

| Kind | Selection |
|---|---|
| `enroll`, `verify` | No UUID or platform (2) |
| `review-inputs`, `review-prepared`, `review-execution`, `review-reconcile` | Candidate UUID; Android has no flag, iOS uses `--ios` (8) |
| `review-recovery` | Candidate UUID, Android/no flag only (1) |
| `review-stage-prepared`, `review-stage-execution` | Stage UUID and explicit `--android` or `--ios` (4) |
| `review-external-readiness` | Stage UUID and `--ios` only (1) |

UUIDs use the original canonical v4 grammar. These reviews read existing current local files when separately started; they do not reconcile a provider, settle recovery, promote a release, or establish historical finality. **AbandonInputs remains excluded**. Old absent-field Enroll/Verify/ReviewInputs bytes and old Start commands remain unchanged.

## Authority and lifetime cuts

* Service captures `identity_point` plus the same `reserve_read` Arc under its original lock. Stable `origin.projectId` and registered `runtimeProjectId` are separate values, both bound to original root/device/inode/revision. No fresh config observation is invented.
* The Store relay obtains only the already-listening Host off Doc and pins its existing weak service slot; it cannot start/renew/replace the Host. Revoke advances the original epoch and sends STOP even if that lookup fails. Status and query use the same retained entry, never newest-row fallback.
* Store Start, Store Prepare, History Start and History Prepare share the same total32 book/lease. A preparation is permanently claimed before the native call. The actual common Saved Prepared assignment installs its original `LocalHistoryConsent` and separate preparation link **before** publication. Failure after assignment stops/retains that original rather than calling it unadmitted.
* A usable preparation needs actual constructor return, the retained Prepare caller return, and the same service-history writer ACK; the history row uses its preparation request ID with ObserveProject, not invented native execution. Cold status cannot install a Prepared. Unknown/lost caller/writer is absorbing.
* Prepared expiry is bounded by original enqueue+300s and original READ end. Explicit MAIN Check exposes the exact retained/native comparison. Its approval window is bounded by the first usable Check **start**, native remainder and every prior ceiling (at most60s); queued zero is not treated as expired authority. Every later Check consumes ACK.
* MAIN Allow is separate, unchecked one-use Start consent with the existing permission revision plus optional exact `preparationOrigin`. Both Doc/Book cuts rematch actual Prepared and entry. The sole overlap is that ready preparation's one-use handoff to its new Start lease; failed installation is fenced, never rearmed. Start retains the old native-return + caller-return + history-ACK barrier, original60/62s clocks and first-STOP2s cleanup.
* Ordinary GUI Start gets an early private-origin guard **before** destructive stale-context tails. The permission controller does not fabricate an ordinary GUI Attempt or auto-Start. Late cancellation of an already-handed-off preparation cannot stop another successor; current Start/Revoke/original READ remain authoritative. Pending Allow/Check and independent Revoke retain their original ports/promises across drift and coalescing.

## Public results and bounds

New read-kind `reviewedFiles` is a closed sanitized current-file/lineage summary projected only from the actual native validated, retired result. It preserves custom external Android track DATA and `not-established` labels; it excludes private authorization, raw journal, paths and provider tokens. Old result shapes still serialize five keys. The new boxed summary's checked2KiB is **inside** the existing8KiB report; it and `candidateInputs` are exclusive.

No existing cap is raised: Store2MiB, History512KiB, joint32, History24KiB status and shared8 IPC remain. New Entry/root/scalar/READ/weak cells have a checked8KiB row quote; native links and MAIN comparisons have named bounded terms in the original quote. Real-type capacity/overflow tests are authored but **not executed**. Document/installed native fit is not established by this packet.

Discovery still uses `AdditionalFamily::LocalHistory`, namespace5 and `local-history-status`, counted once. The formerly missing `local-history` capabilities discovery family is added. `cliPrepare:true`, `prepareIsStart:false`,16contexts and `abandonInputs:false` describe the compiled interface, not native availability.

## Checks and evidence (no native qualification)

**28 distinct Node cases passed, zero skips:**10 new actual permission/ordinary-controller/codec cases plus18 old History permission cases. The first new run had8PASS/2FAIL: the two failures expected ordinary objects rather than the existing getter-free decoder's null-prototype query. Only those two assertions were changed (copying the compared DATA); only those2 were rerun and passed. The other8 results and18 old cases are reused. Production TS was unchanged by that fixture correction.

Evidence under `.task-local-history-prepare/evidence/`:

* `node-history-new-v1.{log,exit,json}`:10 cases,8PASS/2 fixture FAIL, actual Node exit1,192.083ms.
* `node-history-fixture-v2.{log,exit,json}`:exact2 corrected cases PASS/exit0,157.974ms.
* `node-history-v1.{log,exit,json}`:18 existing cases PASS/exit0,224.701ms.

All three actual callers joined. Their JSON records pin the public source projection, command, exit and removed private scratch. Nonroot UID/GID65534, network namespace, clean environment/HOME/TMP, Node384MiB,60s whole/10s per-case and original finite resource limits were used. No install/cache modification or pending caller remains. The same imported permission/History TS bytes are unchanged in the final current-Root composition; App and test-list union is source-only.

Rust syntax only: initial4 owned leaves and30 captured Rust parents; final10 genuinely changed current images/imports parsed separately (unchanged checks not repeated). A source-only full common Prepared field census covers21 definitions/literals, including the newly integrated Tool fixture. Final hook apply-check and added-line whitespace checks are recorded in `source-checks.json`.

**Rust34 selected cases (15 new), whole composed TS, actual CLI/native/Mac/journal/Keychain/provider operation are UNRUN.** The three Saved tests use inert real owner/Consent/Prepared allocations at the common commit boundary; their test-only consent has no bound document and explicitly fails `current()`. They create no Profile, Session, GO, FD, native receipt or physical finality. No fake runtime qualification is added. Root batches compilation/execution; the table below is a source selector handoff, not a pass list.

## Integration packet

Owned leaves (stage only these plus this guide and the patch):

```
desktop/src-tauri/src/service_local_history_prepare_protocol.rs
desktop/src-tauri/src/service_local_history_prepare_requests.rs
desktop/src-tauri/src/saved_command_agent_local_history_prepare.rs
desktop/src-tauri/src/asset_session_agent_local_history_prepare.rs
desktop/src/agentLocalHistoryPreparation.ts
desktop/tests/agent-local-history-prepare.test.mjs
docs/service-local-history-prepare-20261022.md
docs/service-local-history-prepare-hooks-20261022.patch
```

Final38 shared before/after images and pins are `.task-local-history-prepare/current/{before,after}` and `current/merge.json`; original546 images are retained in `parents/{before,after}`. Only two current merge conflicts were mechanical: keep current Tool `prepareReviewedAcquireOnSubmit` with new History metadata, and keep every current package test plus the new History test. One additional neutral Tool Prepared fixture gets `agent_history_preparation:None`. Current Store candidate `Selection.execute:None` is preserved. Service's later lifecycle `Selection.release:None` is a separate additive Root union, not replaced here. No source changes to the native journal/protocol/Python/Keychain implementation, `asset_session.rs`, Store material/execute preparation leaves, or Root are in this packet.

Review successor: the six implementation/test leaves and all original37 hooks are unchanged. The only code addition is the same pure protocol module declaration in the independent `tests/installed_shell_observation.rs` crate (38th hook). Original freeze/evidence remain in `.task-local-history-prepare/review-v1`. The three current service-bearing roots (library, installed CLI, installed observer) now all declare the protocol; child request/native modules follow their existing parents. The separate development-only GTK qualification crate lacks the old service modules already and is not qualified or repaired here. Root's later lifecycle8 App/CLI/`Selection.release:None` changes need additive composition; the37 old after-images are not refreshed over them. No tests or wholeTS are rerun for this neutral graph fix.

Shared targets:

```
desktop/src-tauri/src/service_local_history_protocol.rs
desktop/src-tauri/src/service_local_history_requests.rs
desktop/src-tauri/src/service_local_history_application.rs
desktop/src-tauri/src/service_store_requests.rs
desktop/src-tauri/src/service_store_prepare_requests.rs
desktop/src-tauri/src/saved_command_owner.rs
desktop/src-tauri/src/saved_command_local_history.rs
desktop/src-tauri/src/saved_command_agent_local_history.rs
desktop/src-tauri/src/asset_session_local_history.rs
desktop/src-tauri/src/asset_session_agent_local_history.rs
desktop/src-tauri/src/asset_session_agent_store.rs
desktop/src-tauri/src/service_protocol.rs
desktop/src-tauri/src/application_service.rs
desktop/src-tauri/src/installed_cli_ipc.rs
desktop/src-tauri/src/installed_cli_main.rs
desktop/src-tauri/src/lib.rs
desktop/src-tauri/src/installed_cli.rs
desktop/src-tauri/src/installed_cli_local_history.rs
desktop/src-tauri/src/shell.rs
desktop/src/agentLocalHistoryProtocol.ts
desktop/src/agentLocalHistoryController.ts
desktop/src/localReleaseHistory.ts
desktop/src/components/AgentLocalHistory.tsx
desktop/src/App.tsx
desktop/tests/agent-local-history.test.mjs
desktop/package.json
desktop/src-tauri/src/saved_command_agent_local_checks.rs
desktop/src-tauri/src/saved_command_owner_tests.rs
desktop/src-tauri/src/offline_preflight_owner_tests.rs
desktop/src-tauri/src/saved_command_agent_store_tests.rs
desktop/src-tauri/src/saved_command_agent_apple_prepare.rs
desktop/src-tauri/src/saved_command_agent_ios_recovery.rs
desktop/src-tauri/src/saved_command_agent_ios_archive.rs
desktop/src-tauri/src/saved_command_agent_android_build.rs
desktop/src-tauri/src/saved_command_apple_memory_tests.rs
desktop/src-tauri/src/service_local_history_tests.rs
desktop/src-tauri/src/saved_command_agent_tool_inspect_tests.rs
desktop/src-tauri/tests/installed_shell_observation.rs
```

## Focused Rust selectors (all UNRUN)

Ordinary `#[cfg(test)]` DATA tests for Linux/macOS; installed layout/native proof still needs Root's actual selected graph. No case invokes Store/Keychain/child execution or live history. Full path/line/source pins and new/affected classification: `.task-local-history-prepare/rust-selectors.json`.

```text
service_local_history_prepare_protocol::tests::sixteen_native_contexts_are_closed_without_abandon_or_platform_inference
service_local_history_prepare_protocol::tests::old_selection_bytes_and_new_pending_are_not_start_or_native_retirement
service_store_requests::history::preparation::tests::original_prepare_caller_and_history_ack_are_both_required_before_ready
service_store_requests::history::preparation::tests::lost_prepare_caller_history_or_witness_never_releases_original_or_rearms
service_store_requests::history::preparation::tests::read_context_is_original_configless_and_first_stop_is_never_renewed
service_store_requests::history::preparation::tests::exact_preparation_to_start_handoff_and_late_old_cancel_keep_same_joint_book
service_store_requests::history::preparation::tests::cancelled_original_exact_lookup_survives_later_row_without_fallback
service_store_requests::history::preparation::tests::original_preparation_cells_use_real_types_and_checked_existing_row_budget
saved_command_owner::history_preparation::tests::common_prepared_commit_keeps_consent_and_waits_actual_prepare_and_history_returns
saved_command_owner::history_preparation::tests::genuine_preparation_binding_handoff_uses_old_submit_and_cannot_replay_gui_or_old_cancel
saved_command_owner::history_preparation::tests::failed_install_and_lost_prepare_return_never_reissue_or_clear_the_original
asset_session::agent_local_history::preparation::tests::sixteen_selected_shapes_enter_only_actual_registered_runtime_history_contexts
asset_session::agent_local_history::preparation::tests::existing_main_lookup_accepts_only_empty_or_complete_exact_origin_and_no_material
service_local_history_protocol::tests::local_history_codec_closes_platformless_null_and_candidate_grammar
service_local_history_protocol::tests::local_history_max_report_fits_typed_and_full_response_caps_without_authority
service_local_history_protocol::tests::local_history_partial_and_unknown_results_never_smuggle_completed_report
saved_command_owner::agent_history::tests::local_history_native_review_never_relabels_other_history_actions
saved_command_owner::agent_history::tests::local_history_terminal_projection_requires_actual_retirement_and_original_ids
saved_command_owner::agent_history::tests::local_history_actual_original_result_projects_only_public_current_history
saved_command_owner::agent_history::tests::actual_native_prepared_file_decoder_projects_only_bounded_current_file_summary
service_store_requests::tests::local_history_tests::local_history_triple_returns_and_progress_ack_never_settle_early
service_store_requests::tests::local_history_tests::local_history_lost_caller_writer_or_invalid_native_retains_unknown
service_store_requests::tests::local_history_tests::local_history_same_request_reconnect_is_not_replay_and_exact_query_is_retained
service_store_requests::tests::local_history_tests::local_history_read_stop_and_weak_context_keep_earliest_cut_no_saved_config
service_store_requests::tests::local_history_tests::local_history_shared32_and_discovery_use_one_namespace_without_reading_or_expiring_rows
service_store_requests::tests::local_history_tests::local_history_and_existing_store_preparation_exclude_only_live_originals
service_store_requests::tests::local_history_tests::local_history_quote_keeps_entire_old_store_debit_and_shared_eight_peak
asset_session::agent_local_history::tests::local_history_allow_raw_is_original_scalar_only_and_native_backing_bounded
asset_session::local_history::tests::local_stage_history_consent_cannot_switch_stage_or_platform_or_mint_document
asset_session::local_history::tests::local_release_history_needs_registered_project_not_credential_context
installed_cli::local_history::tests::local_history_cli_scalar_codec_closed_and_lost_ack_keeps_same_request
installed_cli::local_history::tests::local_history_cli_status_never_accepts_foreign_family_origin_or_scope
installed_cli::local_history::tests::local_history_prepare_cli_has_sixteen_closed_contexts_and_no_start_or_origin_fallback
installed_cli::tests::capabilities_keep_read_grants_separate_from_desktop_reviewed_proposals
```
