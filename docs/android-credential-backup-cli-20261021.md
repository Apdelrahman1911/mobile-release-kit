# Android encrypted-backup CLI delegation

Source base: `5e061ca34d984daed17a20cfe56e25c01a07a142`.
Author lane: `credential-service-cli`, branch
`task/automation-credential-service-cli-20261021`.
Service independently accepted the retained plan
`.task-credential-service-cli/plan.md` (`545c53e4…`); Root authorized implementation.

## Scope and honest availability

Extend the **existing Android upload-key facade**, not a new credential API,
service, queue, process owner, or cryptographic implementation. The same four
installed commands remain IDs-only:

* `mrk upload-key-scope PROJECT_ID [--json]`
* `mrk upload-key-submit PROJECT_ID SERVICE_INSTANCE GRANT_ID --reviewed [--json]`
* `mrk upload-key-status PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]`
* `mrk upload-key-cancel PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]`

Desktop alone adds two closed selections and separate one-use consent versions:

| Selection | Consent |
| --- | --- |
| `backup-encrypted {recordId, expectedRevision}` | `agent-android-upload-key-backup-once-v1` |
| `restore-encrypted {declaration:"restore-as-new-unassigned"}` | `agent-android-upload-key-restore-once-v1` |

The native **`NATIVE_BACKUP_QUALIFIED=false` remains unchanged**. Both Allow and
the existing native chooser refuse without genuine route qualification. The UI
also requires the current native backup capability; the installed catalogue
describes compiled routes, not runtime availability. These source changes do
not qualify either the shipping two-picker flow or a real CLI invocation.

Only an encrypted, unlocked, writable **Android/local** vault is in scope.
The shared backup codec can represent other kinds; this facade cannot delegate
their authority. Its current native proof, consent, assignment and context are
Android-specific. This is incremental key-lifecycle parity, **not** general
credential or full headless parity. No implicit generation, rotation, replace,
Bind, Remember, journal/no-GO/recovery acknowledgment, retry, or plaintext export.

## Original owner and permission cuts

`credential_upload_key_delegation::Proof` retains its existing Weak context,
StoreBook and VaultKey. Its fixed new child stores only export's exact native
`StoredRef` (including the original read witness), or restore's target vault
identity. Both existing Allow Doc cuts and the actual consume/install cut
rematch these originals, current saved project/Edit scope, row/kind/revision,
registry, vault/key identity, capacity and all existing lifecycle gates.

The existing Shell relay supplies its genuine `AppHandle` to the **same named
Call**, not a synthesized window or new executor. Consume precedes preparation;
the same NativeLink is retained on the actual OriginalWork before install/GO.
Ordinary chooser calls pass `None`; their existing behavior is unchanged.

The real `credential_backup_selection` coordinator reserves both original GUI
calls before GO. Both actual dialog destroy/release returns are still required
before it obtains the private pair and starts the sole I/O deadline. The same
Job runs the same Backup child. There is no post-picker pause, picker-result
DTO, fake SelectedPair, arbitrary path API, or replacement confirmation bypass.

Original `run_job` retains its execution future while the existing 25ms tick
forwards Read expiry/revoke/context STOP. Grant/read lifetime is at most the
existing 300 seconds and cannot renew picker/WORK/cleanup clocks. Exact unseen
nonce withdrawal, one active request, lost replies, original-ID lookup and
absorbing Unknown remain unchanged. Returned withdrawal can remove only the
permission gate; it never proves native completion or clears Unknown.

## Real export, NEW import, and finality

Export reuses existing full read/AEAD and real BackupDestinations. Success
`backup-delivered` requires the same concrete two-file publication, normal
original joins, current source/vault comparison and returned private retirement
via `backup_desktop::delivered_current`. No key/path/code/file body is returned.

Import still captures and authenticates both selected files. Immediately after
that authentication and **before `seal_new`/NEW**, the fixed attached-link guard
admits only `RestoreEncrypted + AndroidKeystore`. A wrong attached kind is a
refusal, **never** an ordinary unlinked import. Truly ordinary `None` imports
retain all their prior kind behavior.

The existing random NEW/None, counter 1, latched mutation outcome, full AEAD
readback equality, source/target postchecks, closes and row publication remain
unchanged. At that same accepted publication, the SlotData stores one fixed
comparison stamp `(context revision, StoredRef)` before private retirement.
`restored-unassigned` uses **that exact stamp**, the same current authenticated
row/target/known outcome and actual retirement. It cannot reconstruct a new
reference from a later status/list, or treat backup metadata as a grant.

Neither success is public until all three existing independent returns arrive:
native Asset retirement, initiating Document caller, and relay continuation.
Late STOP suppresses both successes and their reference. A genuine declined
picker can close a failed action after both original GUI/control returns and a
never-entered I/O child; this creates no delivery, NEW or generation no-GO proof.
Failed joins, pending private data or uncertain close cannot take that path.

A known restore leaves the NEW record unassigned. After its original permission
is withdrawn and all work is settled, use the ordinary Desktop Select/Assess
and current Assign preview. The already implemented **separate** `bind-reviewed`
consent can consume that real preview. Restore output/list DATA cannot create it.
Failures warn that files or a NEW record may already exist; never auto-replay.

## Bounded accounting and hooks

Four new leaves:

* `desktop/src-tauri/src/credential_backup_delegation.rs`
* `desktop/src-tauri/src/service_upload_key_backup_tests.rs`
* `desktop/src/agentUploadKeyBackup.ts`
* `desktop/tests/agent-upload-key-backup.test.mjs`

The adjacent `android-credential-backup-cli-hooks-20261021.patch` contains the
18 exact existing-file deltas. Their parent copies preserve Root’s independently
accepted names-only shipping corrections (`crate::vault_store::RESIDENT_BYTES`
and the existing `durable_gate` visibility); those fixes are not this patch.
Complete original/after copies and their pins
are retained in `.task-credential-service-cli/parents/`. They include existing
protocol/request/proof/relay/picker/native-publication/CLI/UI arms and one literal
entry in the existing Node test script; no workflow/flags or Root source edits.

All previous bounds remain: 32 rows/consents, one active proof/continuation,
8 existing IPC calls, RAW 1 KiB and view 4 KiB. New variants carry fixed bounded
comparison data only. Actual `size_of<Proof/Selected>` and same Slot/Document
layout charge the comparison and stamp. The three common Weak tombstone debits
remain; old Generate/Bind keep their original fourth Weak header and pointee
debit, now expressed per arm. Backup adds no new Weak/private payload.
The actual `Call` layout includes its original AppHandle in the existing
`TASK_STAGE/TASK_CELL/BACKING` quote; no extra task, scheduler pool or runtime
body is created. Original picker/source/cipher/store debits remain unchanged.
These source/layout derivations are not a measured-RSS or compiled-size claim.

## Evidence and remaining qualification

* **28 inert Node tests PASS**, zero skips/cancellations: 12 new plus all 16
  existing upload-key permission/controller cases, 236.744ms reported by Node.
  Log and tested source hashes: `results/node-v1.*` under the task directory.
  Real controller/strict parser/promise paths are used; native availability in
  test DATA is not an actual native grant. Original callers joined and the
  test projection was removed (`node-v1-cleanup.json`).
* Whole projected frontend TypeScript: final receipt is recorded separately in
  `results/tsc-v2.*`: **PASS (exit 0), 16.786s**, minimum available memory
  7.464 GiB; original caller and own projection/dependency-link cleanup returned.
  Initial `tsc-v1` had only seven missing existing JSON imports
  from the author projection, not product diagnostics; that failed receipt is
  preserved. No production source changed for the projection correction.
* Rust syntax: `rustfmt --edition 2021 --config skip_children=true --emit stdout`
  on 16 owned/after Rust files. This is **not** compile or test execution.
* **10 new Rust DATA tests authored, UNRUN**, plus one existing MAIN Allow test
  extended for both new consent pairs. Exact selectors are retained in
  `.task-credential-service-cli/rust-selectors.txt` and listed below.

No Rust/Cargo build, key generation, encryption, native picker, keyring,
filesystem fixture, installed CLI IPC, provider, CI or signing execution here.
The old generated-key backend/component tests do not qualify these genuine
shipping picker+CLI paths. Root must compile the matching graph and schedule
meaningful native verification before any separate availability decision.

New Rust tests use existing Inbox/Entry/Claim fixtures, actual codecs/output and
inert zero-mode reference predicates. No test constructs a native delivery,
saved-key publication or retirement token. They do not touch files, sockets,
Keychain, accounts, tools, processes or native dialogs.

```text
service_upload_key_requests::tests::backup::backup_selections_are_distinct_closed_consents_without_file_or_password_inputs
service_upload_key_requests::tests::backup::delivery_and_restored_reference_cannot_cross_kind_or_settlement
service_upload_key_requests::tests::backup::both_backup_kinds_keep_the_same_three_original_return_barriers_in_all_orders
service_upload_key_requests::tests::backup::lost_caller_or_continuation_and_wrong_native_kind_are_absorbing_unknown
service_upload_key_requests::tests::backup::late_original_stop_suppresses_delivery_and_new_reference_without_replaying
asset_session::vault::backup_delegation::tests::authenticated_kind_policy_has_no_wrong_link_fallback_before_new
asset_session::vault::backup_delegation::tests::full_reference_comparison_keeps_random_revision_and_original_read_witness
asset_session::vault::backup_delegation::tests::untouched_original_cannot_supply_backup_retirement_or_an_import_stamp
installed_cli::upload_key::tests::backup_and_restore_output_keep_delivery_new_reference_and_assignment_distinct
installed_cli::upload_key::tests::backup_cli_still_accepts_only_ids_not_a_file_pair_or_restore_override
```

The first five and last two are ordinary `cfg(test)` DATA. The vault child is
on the existing Linux GNU x86_64 / supported Mac64 vault graph; its original
read-witness comparison test additionally requires `debug_assertions`. All ten
fit Root's ordinary debug Mac/libtest graph, not a harness-false app execution.
The strengthened existing selector is
`asset_session::agent_upload_key::tests::main_requests_are_small_explicit_action_and_consent_pairs_not_status_authority`.
