# Known-durable Apple key recovery

Base: `817f82279b200c2c931864f0bdec570905e40a66`, isolated
`apple-key-recovery`. Credentials independently accepted the bounded plan;
Root authorized implementation and is the distinct actual reviewer.

## Supported action and limits

Desktop **Recover a durably saved key after interrupted setup** uses the
existing Apple controller, explicit current encrypted key selection, native
Prepare, unchecked one-use consent, and original Start/Read/Cancel. The new
operation requires `reference:null`; it does not renew an old review. The CLI
deliberately remains its accepted fifteen modes.

The current full vault reference must equal the unique original destination
and saved reference. Only valid Returned + ReadBack rows with an output and
Prepared/Cancelled/Failed disposition qualify. Pending permits one new local
verification record; Known/already-associated permits comparison only. Missing
keys, Armed/Written/Unknown saves and backup-restored NEW references refuse.
There is no generator, provider call, NEW record, Bind, private export or
substitute key. P8 still supplies the actual selected issuer/account binding.

## Original order and proof boundaries

1. Existing native Prepare/Start retains the same Input, Asset, source roster,
   vault key/Store and fresh key Loan. The real initial source check and
   original NativeStateReady/NativeUse are required before INITIAL. An active
   old native use or Asset cannot be reopened or discarded by recovery.
2. Native validates the entire immutable row/recovery relation and projects
   only its exact selection. Command 6 is the existing bundled key verifier
   on the same Runtime/Invocation and private six-part input (seven commands
   total). Both CSR/full-SPKI and canonical private-frame hash/length must
   match. `key-compared-ack` is only a provisional comparison; the original
   writer must actually enter and return it.
3. The normal complete Terminal only closes the input pipe. The new fixed
   post-worker gate distinguishes that signal from actual first failure,
   context loss, STOP or Unknown. Actual worker/IO joins, a repeated original
   source check, and the existing no-save Asset child/coordinator join precede
   the sole constructor of `AppleKeyRecoveryVerified`.
4. Existing job 9 performs the one journal CAS, using the same lease and
   expected revision. The journal retains its original write claim before
   mutation, verifies the returned revision/full bytes, and never retries a
   lost/late CAS or ACK. It does not relabel the old row or manufacture either
   native use's finality. Known/already-associated does not append.
5. Existing job 10 actually retires NativeUse. All original jobs, UseJoined,
   loan/source/Asset private retirement and clock completion still precede
   public success. A parsed comparison or stored recovery row is insufficient.

Schema 5 adds only `keyRecoveries`; canonical schemas 1–4 stay unchanged on
read. All families share the existing 32-row/operation domain, 16 KiB row and
1 MiB state bounds. Validation precedes effective-fence projection. Only the
matched eligible old key fence is discharged; raw Pending/receipt bytes and
all other-family uncertainty remain. The private Python adapter checks exact
account/action/operation linkage, not eligibility from digest-shaped DATA.

Later certificate work still obtains its own fresh key loan/verifier/review
and separate explicit POST consent. Normal `keySavedAckSha256` and recovered
`keyRecoverySha256` are mutually exclusive at native ACK, private reply,
worker, Ruby carrier and returned-frame checks. Normal carrier shape is
unchanged; a recovered origin never pretends an old keySaved ACK returned.
Recovered verification also repeats the actual private-frame comparison
before the first GET. No trust policy, signing assignment or readiness gate
changes.

## Packet and integration

Seven owned source/test leaves:

- `desktop/src-tauri/src/apple_provisioning_key_recovery_data.rs`
- `desktop/src-tauri/src/apple_provisioning_key_recovery_journal.rs`
- `desktop/src-tauri/src/apple_provisioning_key_recovery_protocol.rs`
- `desktop/src-tauri/src/saved_command_apple_key_recovery.rs`
- `desktop/src-tauri/src/saved_command_apple_key_recovery_native.rs`
- `src/mobile_release/_desktop_apple_key_recovery.py`
- `tests/unit/test_desktop_apple_key_recovery.py`

This guide and `apple-key-recovery-hooks-20261021.patch` complete the scoped
commit. The patch contains 46 Root-only parent targets; exact full current
before/after copies, roster and pins are under `.task-key-recovery/`. The only
parent differing from the implementation base was `saved_command_owner.rs`;
the final projection preserves Root's ToolSavedInspect additions. No shared
file is replaced by an old after-image. Existing module roots bring in the
five new Rust children, including no-shell refusal closure; there is no new
root executor, IPC service, runtime resource filename or availability flag.

All old retained/journal/review/Ready/Seen debits remain. Only KeyRecover adds
its finite comparison/record/proof scratch to the existing key-parent quote.
No memory-cap correction is part of this packet. Root's latest actual
whole-Document admission failures remain a separate unresolved dependency.

## Evidence, not native qualification

- Final focused Python **36 passed** (21.604 s): nine new recovery tests,
  nineteen affected certificate tests, eight existing P12-owner tests. Same
  actual inert engine/finite-files fixture; commands, crypto and provider are
  fakes, with UID 65534 and no network. Thirteen unchanged key/carrier tests
  from the earlier 21-pass run are reused: **49 unique Python tests** total.
- Existing key-controller test file: **20 passed** (541.738 ms), including
  four new recovery groups, actual Prepare/Start/Read/current-source handling,
  pending/event/unknown/ABA/lost-Start refusal and unchanged CLI exclusion.
- Whole composed TypeScript passed. Two real mode-table type omissions were
  corrected; missing JSON inputs/permissions in the disposable projection
  were corrected separately. Original failed receipts are retained.
- Two added inert Ruby carrier methods: **2 runs / 26 assertions passed**.
  No SDK load, crypto or provider execution. Neither/both/foreign origin and
  failed one-shot claim are covered.
- **26 Rust syntax parses passed only. Ten new Rust tests are UNRUN**:
  nine DATA/original inert-session tests and one existing task-owned Store
  fixture exercising actual CAS/lost ACK/close. Exact selectors and affected
  original cases are in `.task-key-recovery/rust-selectors.json`.

No Cargo, native Apple/macOS, live issuance, Keychain, new runtime nomination
or shipping qualification was performed. The stopped/missing-source cases
are not made successful for tests. All author workers returned; private
disposable fixture output is not exported. Full-source actual review and
Root's compiled/native graph remain required.
