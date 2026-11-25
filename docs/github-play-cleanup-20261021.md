# Explicit hosted Play cleanup: Desktop and installed CLI

This packet adds a closed cleanup facet to the existing GitHub
Connection/Supervisor/Setup worker and the existing authenticated service. It
does not publish, reserve a version, decrypt an edit ID, or claim that a GitHub
dispatch acknowledgement means cleanup succeeded. Native/provider execution
is **not qualified by this packet**.

## Integration

- Own source: four Python implementation leaves, their test, fifteen Rust
  implementation/test leaves, and these two documents (22 paths).
- `github-play-cleanup-hooks-20261021.patch`: 25 existing Root targets against
  `4db17d94fd2d31db7d9af68d820f32507ccdb899`. `asset_session.rs` and `shell.rs`
  required ordinary three-way composition; current census cfg and original
  CLI-observer shutdown additions are preserved. No shared source is edited
  in the author worktree.
- Canonical caller dependency is the accepted Project resource/helper,
  integrated at `27431288`; resource SHA-256
  `b0c2b54af743bafd1296cda605fb77d5437c3cfd8a2ba0fe37bae9e84c0717f6`.
  No new workflow input or Desktop correlation marker is introduced.
- Pair with separately authored/reviewed frontend `2aaa4f36` and its five-target
  hook `1e846ead`. That frontend retains original calls, including lost Allow
  replies and equal-revision access countdowns; its tests are not backend proof.
- Config CLI may share the two narrow original `ReadPermission` accessors
  (`end()` and crate-visible `stop(now)`); merge those once. Its protocol and
  actions remain separate. Keep the installed capability output cap at 12 KiB.

Exact owned/shared hashes and complete current before/after images are retained
in `.task-play-cleanup-hooks/frozen.json` and `current-v2-{before,after}`.

## Authority and effects

Prepare performs 19 fixed GETs on the selected original Connection. It validates
the current protected counter C and its full Genesis/Ledger/Envelope, a single
unclaimed recoverable candidate/attempt, and the original source A's commit,
configuration, version and identity. The configured current branch B is checked
separately, including its canonical caller and A-to-B reachability. A displayed
candidate, stored status, or renderer-supplied ID is never this authority.

The retained native review binds account/repository IDs, root/registration,
saved Edit stamp and Connection. Its one-use consent expires within 120 seconds
and the original Connection expiry. The confirmation explicitly warns that B is
mutable: GitHub does not atomically dispatch at the reviewed commit. The hosted
workflow checks its actual B and separately validates retained A; this route
does not reset a checkout, invent a supported arbitrary ref, or fetch missing A.

Start revalidates the original review and C/full candidate tuple. Its actual
schedule is 11 GETs plus one POST (closed dispatch cap 13). It retains and fully
reads back an immutable local intent and one-use claim **before** attempting:

```json
{"ref":"configured-branch","inputs":{"operation":"recover-play-edit","platform":"android-or-both","confirmation":"recover-play-edit:CANDIDATE_UUID:ORIGINAL_ATTEMPT_UUID"}}
```

The local custodian's once key binds actual repository, authority project and
ledger, genesis SHA, candidate and attempt, independent of local aliases. A
successful 204 still excludes that tuple. Lost create/claim/POST/receipt
acknowledgements do not allow replacement or replay. Hosted cleanup retains its
independent protected one-use claim and clear-CAS rules unchanged.

Only empty 204 after the original reader completes is acknowledged-unconfirmed.
No run ID is inferred or searched for. Explicit later journal reads are DATA:
absent, claimed, changed or inaccessible state never proves cleanup, clears a
claim or enables retry. Capsule bytes, encryption keys and raw edit IDs never
enter Desktop/CLI status, arguments, public logs or the local dispatch journal.

## Original owner, service and cancellation

Eight fixed RAW commands provide Status, Prepare, Start, Pending, Observe,
Discard, Cancel and Allow agent. They retain existing main-window, Connection,
peer, runtime and publisher gates. The original Setup bootstrap/IO slots,
Supervisor driver/watchdog/management and consuming receipts are reused.
There is no new runner, remote HTTP owner, or native qualification flag.

Allow captures a genuine private consent, performs Service/Host IO off Doc,
then rematches the same native review under Doc. It returns that exact installed
snapshot under Doc; a racing CLI consume cannot rewrite the original reply.
Delegation does not restore GUI Start permission when withdrawn. The existing
service holds one live consent and 32 metadata requests, not 32 native owners.

The shell's existing relay claims a request; the exact private link arms under
the original Supervisor owners lock immediately before insertion/spawn. Only
the actual ticket/receipt and original IO/management joins can settle it.
Status/relay completion flags cannot supply native finality. The event producer
uses `play_cleanup_status()` after reconciliation, including availability.
Actual original GO records conservative `potentially-applied` on the same CLI
link before returning GO bytes, not proof that POST occurred. Original native
Unknown publication immediately records absorbing CLI Unknown; it does not wait
for a later settlement. The same ticket covers containing-Connection Unknown.
OwnerState and receipt locks are released before Entry mutation. A later STOP,
permission loss or refused reply cannot erase GO or renew the earliest failure;
neither observation supplies a join, acknowledgement or retry permission.

READ grant expiry/revoke uses the same `ReadPermission` Arc and earliest time.
Only agent-linked cleanup bounds the **existing** watchdog's next check to
100 ms; it neither starts another timer nor renews the original 60-second work
deadline or first-failure +2-second cleanup endpoint. Its checks touch only
short memory locks/facets and service poison/history atomics, never Doc,
Service/Host IO or a lock across an await. OwnerState is taken after these checks.
Stop/Unknown retains original work; quit follows existing native join gates.

The pure-DATA service protocol compiles independently of native adapters. CLI:

```text
mrk play-cleanup-submit PROJECT_ID SERVICE_INSTANCE CONSENT_ID --reviewed [--json]
mrk play-cleanup-status PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]
mrk play-cleanup-cancel PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]
```

Submit reports its original request IDs before the first transport. The same
live READ/project/alias guards apply to submission, query/cancel and pre-send.
Unknown transport replies retain those IDs, never remint or resend.

## Bounded backing, not an RSS claim

Admission is checked `actual retained whole Document + 16 MiB original saved
configuration reader + 16 MiB remote DATA work + 8 MiB native framing <= 64 MiB`.
The existing cap is unchanged. Whole-Doc census includes old owners/history,
the new bounded inbox and IPC copies; unknown/active work provides no release
credit. Active cleanup also enters the existing reciprocal asset-allocation
gate, so another credential/context allocation cannot spend its reserved space.

HTTP bodies are sequential, not 19 retained responses: each ordinary body is
at most 256 KiB, historical configuration at most 768 KiB encoded, and total wire
bytes at most 2 MiB. The fixed profile runs the original prospective 8,000-token,
depth-28 guard **before** outer and embedded JSON decoding, on the same clock.
The 16 MiB quote accounts for original raw/chunk/Unicode copies, token/container
DATA, bounded ledger/envelope and the 32 local immutable records. Prepare drops
its fully parsed ledger/envelope DATA before the large historical config decode;
it does not retire any IO/owner based on that. The original saved-config 16 MiB
allowance is separate, not hidden inside the 8 MiB framing allowance.

The real default-Document test measures the existing census and requires it to
fit. Two real retained 8 MiB source capacities plus their two 1 MiB metadata
allowances must refuse without a quota change; unknown retirement must refuse.
That Rust test is authored **unrun**, so default admission is not yet verified.
Source-only scalar reservations already give a lower bound of 22,997,096 bytes
(21.932 MiB) for D, before actual native structs and remaining heap. The guard
requires D <= 24 MiB. Concurrent Config's proposed additional 8 MiB would exceed
that before those omitted terms; Root is reviewing shared census accounting.
This packet does not raise the limit or claim the unresolved default fit.

## Evidence and remaining checks

- Fourteen Python obligations resolved with inert original HTTP/journal seams:
  v3 had 13 passes and one test-fixture error; the corrected late-Observe fixture
  alone passed in 0.033 s. Production inputs for the other 13 were unchanged and
  rematched. Earlier failure logs/source snapshots remain; no hidden rerun claim.
- Fifteen own and 22 complete parent Rust files passed syntax parsing only.
  Current 25-target patch forward/reverse replay and production whitespace are
  checked. **No Cargo, native, provider, encrypted-key or installed CLI run.**
- Twenty-seven new Rust tests below are uncompiled/unrun. Root must run the real
  library and thin-CLI graphs, these selectors, the existing capability test,
  and native qualification before claiming the installed route works.
- Existing affected selector:
  `installed_cli::tests::capabilities_keep_read_grants_separate_from_desktop_reviewed_proposals`.
  No capability/output safety limit is increased for concurrent Config work.

### Exact new Rust selectors (27; Linux/macOS data tests, no native calls)

```text
github_play_cleanup_protocol::tests::advanced_dispatch_head_is_separate_from_original_source_and_alias_safe_once_key
github_play_cleanup_protocol::tests::acknowledgement_and_absent_later_journal_are_never_cleanup_success
github_play_cleanup_protocol::tests::worker_refusal_has_exact_correlation_and_no_public_consent_or_private_field
github_play_cleanup_protocol::tests::explicit_closed_command_does_not_accept_desktop_release_markers_or_auto_confirm
github_play_cleanup_protocol::tests::exact_fixed_allowances_use_checked_remaining_document_budget
service_play_cleanup_protocol::tests::closed_request_accepts_only_three_ids_and_consent_not_provider_material
service_play_cleanup_protocol::tests::nullable_fields_and_acknowledgement_cannot_fabricate_cleanup_finality
service_play_cleanup_protocol::tests::response_rematches_instance_and_fixed_small_bound
service_play_cleanup_requests::tests::consumed_access_is_not_revoked_scope_and_exact_retry_never_remints_claim
service_play_cleanup_requests::tests::original_earliest_stop_and_later_unknown_do_not_renew_watchdog_or_revisions
service_play_cleanup_requests::tests::original_native_go_and_unknown_are_immediate_monotone_facts_not_join_or_retry_authority
service_play_cleanup_requests::tests::known_refusal_without_go_is_not_sent_and_a_later_reply_cannot_erase_original_go
service_play_cleanup_requests::tests::prearm_review_expiry_uses_original_end_and_postarm_does_not_renew_read_permission
service_play_cleanup_requests::tests::dropped_claim_close_and_context_loss_are_not_native_settlement
service_play_cleanup_requests::tests::known_preinsertion_refusal_keeps_tombstone_and_capacity_does_not_evict_it
service_play_cleanup_requests::tests::poisoned_or_fenced_original_inbox_invalidates_already_claimed_link
application_service::agent_play_cleanup::tests::actual_read_and_cleanup_scopes_both_required_reconnect_and_presend_rematch
application_service::agent_play_cleanup::tests::original_grant_clone_drop_and_renewal_do_not_rebind_old_cleanup_scope
application_service::agent_play_cleanup::tests::before_allow_revocation_and_claim_watchdog_do_not_wait_for_service_io_mutex
application_service::agent_play_cleanup::tests::unobserved_service_poison_fences_claim_without_second_service_lock
asset_session::play_cleanup::tests::default_document_fits_cleanup_but_real_retained_buffers_refuse_without_quota_change
github_connection_session::play_cleanup::tests::access_countdown_is_data_but_disable_or_replacement_advances_original_revision
github_connection_session::play_cleanup::tests::stale_or_unknown_data_without_original_consent_never_gains_agent_review
supervisor::play_cleanup::tests::delayed_agent_stop_uses_original_failure_plus_two_and_never_supplies_management_join
installed_cli::play_cleanup::tests::original_argument_collector_accepts_exact_reviewed_submit_and_rejects_extras
installed_cli::play_cleanup::tests::lost_reply_preserves_original_ids_and_ack_is_not_cleanup_in_human_or_json
installed_cli::play_cleanup::tests::actual_capability_catalogue_keeps_fixed_limit_and_separate_mutating_consent
```
