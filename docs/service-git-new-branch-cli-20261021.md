# Create-only branch publication through the existing Remote CLI

## Scope and dependency

This is the explicit `push-new-branch` variant of the existing shared Remote
facade, not a new transport, owner, queue, permission endpoint, or tracking
operation. It depends on Service's accepted native implementation
`da5edb12be362286226c6b32a6ea706cd2133a94` and its 39 hooks, integrated at Root
`5174096599b64a88eb5159b9d8e566b2da457772`. Native nomination remains unavailable;
source integration and inert tests do not qualify a real GitHub operation.

The worktree starts at `413cf8fd6166ff927976331f984764cc41bc7b99`. Its sole
overlap with the Service packet is the identical ordinary native Push
`remote: Some(remote.clone())` conversion. Current Root parent bytes are
retained under `.task-git-new-branch-cli/current-parent/`; no unrelated parent
changes are part of this packet.

## Actual path

1. Desktop chooses **Publish this committed branch for the first time** in
   its existing Remote permission panel. Selection requires the actual joined
   current Observe, born attached branch, current selected Connection/account/
   repository with reported Push access, and no configured tracking pair.
   `not-configured` is eligibility DATA, not proof of remote absence.
2. A separate unchecked consent uses
   `agent-git-push-new-branch-once-v1`. The native Allow decoder requires the
   new explicit kind, a present `remote: null`, equal local/target refs, zero
   old OID, nonzero new OID, and exact source/reference/Connection revisions.
   Neither old Fetch nor old Push consent accepts this kind. Old action bytes,
   selection digest domain, nonzero Push predicate, and grants are unchanged.
3. The same two Doc cuts retain/rematch genuine Observe and PushPins around
   the existing off-Doc service lookup. PushPins include the exact new action.
   The original native owner still checks both absent branch configuration
   keys, all bounded reachable history, and fresh provider advertisement.
   The advertisement must not show the target; this is not global absence
   proof. The server's create-only update must reject any existing target,
   including a hidden branch or a tip equal to the selected new OID.
4. The agent uses the same five ID-only commands:
   `git-remote-scope`, `git-remote-prepare`, `git-remote-start`,
   `git-remote-status`, `git-remote-cancel`. It cannot supply the kind, URL,
   token, account, target ref, force option, or arbitrary command to Prepare.
5. The actual native Review is converted to a distinct `push-new-branch`
   preview with `targetRef`, zero expected old OID, bounded count/digest, and
   `first-publication-no-upstream` basis. There is no invented remote alias or
   tracking ref. An ordinary Push review cannot become this preview.
6. Existing Inbox/Entry/Lease/NativeLink publication is unchanged: native
   retirement, actual original caller return, and known same-Doc
   `Connection.finish` must all return before Ready/finality/history. The
   original grant/review expiry, 45/55 clock and first failure remain intact.
   Unknown/lost/withdrawn/expired originals cannot rearm or auto-retry.
7. Apply uses the existing Push owner with its explicit create-only kind.
   Mutation/intent/result conversion preserves that kind, and shared history
   records `GitPushNewBranch`, never an ordinary Push or successful absence.
   CLI output preserves failed/recovery-required effect and original IDs.
   Fresh Desktop Activity remains a separate explicit read, not repair,
   retry, native finality, or CLI recovery authority.

No remote/upstream is configured. A subsequent ordinary Push still needs its
own actual configured source and separate permission. No force, replacement,
automatic permission on mount, or private material was added.

## Owned files and Root-only composition

Ten existing Remote leaves are changed:

- `desktop/src-tauri/src/service_git_remote_protocol.rs`
- `desktop/src-tauri/src/service_git_remote_document.rs`
- `desktop/src-tauri/src/service_git_remote_native.rs`
- `desktop/src-tauri/src/installed_cli_git_remote.rs`
- `desktop/src-tauri/src/service_git_remote_requests_tests.rs`
- `desktop/src-tauri/src/service_git_remote_application_tests.rs`
- `desktop/src-tauri/src/installed_cli_git_remote_tests.rs`
- `desktop/src/service_git_remote_permission.ts`
- `desktop/src/components/ServiceGitRemoteAccess.tsx`
- `desktop/tests/service-git-remote-permission.test.mjs`

The accompanying `service-git-new-branch-cli-hooks-20261021.patch` changes
only two literals: the shared history Action enum and CLI capability action
list. SHA-256:
`82026eab4805a110ea446aff2a994fc6a30dab785abc2bcb7269490d80fb4a8f`.
The existing App maps Fetch to its own peer and all Push variants to the same
Push peer already; it needs no extra hook. No command registration, ACL,
native caller, workflow, flag, journal, or generic Permission change is made.

The same 32-row/one-grant memory accounting, 24 KiB Remote row, 4 KiB Pins,
8 KiB response and 12 KiB CLI capabilities caps remain. Full commit history
stays with the native owner; public count/digest is not a secret-safety proof.

## Verification and exact pending Rust tests

- **98 distinct inert Node cases passed:** 16 Remote (8 new, 8 existing) plus
  82 existing/dependency Fetch, Push, create-only, and local permission cases.
  Remote first run passed 14/16; two test-only corrections supplied valid
  unborn/detached tracking states and stopped treating a deliberately renewed
  checkbox as automatic consent. The two impacted cases then passed. No
  product lifecycle was changed to satisfy these assertions.
- Whole composed frontend TypeScript **PASS**, 17.731 s, peak 748180 KiB.
  Projection uses actual Service frozen source plus these leaves and actual
  core JSON data, not interface stubs. Initial missing `/usr/bin/time` and
  omitted seven public JSON projection inputs are retained diagnostic logs;
  final check ran the complete source graph. Dependency link was removed
  after its original checker returned.
- Rust syntax/format only, seven owned files; **14 new Rust tests UNRUN**.
  Distinct review refined the new CLI scope copy to separate unadvertised
  target DATA from the server's create-only rejection of existing targets;
  its existing pending Rust output assertion now protects that distinction.
  No Cargo, native process, provider, installed runtime, credential, or CI
  execution was performed. Thirteen new tests are memory/DATA only. The one
  application test reuses the genuine exclusive temporary Service/Store
  fixture with real stop/close/drop, but never arms a native owner, creates
  Connection Pins, runs Git, or fabricates a native receipt.
- Current Root two-hook apply-check and exact external scratch replay passed.
  The first nested-worktree replay skipped paths; it failed the byte check,
  changed no tracked source, and remains retained beside the corrected check.

Actual logs, frozen dependencies, original/after files, and full selector
names are in `.task-git-new-branch-cli/`. New test selectors (all `cfg(test)`;
Doc routes additionally require Linux or macOS):

```text
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
```

The full native create-only path and this CLI's actual IPC/native execution
remain unqualified. Existing nomination and external authorization
prerequisites are not replaced by these passing tests.
