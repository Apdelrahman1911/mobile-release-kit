# Explicit Android signing-key recovery (source, not native qualification)

## What the user does

1. Open/unlock the same encrypted vault and check Android signing setup.
2. If the **actual prior original proved that GO was never sent**, its normal
   cancellation cleanup now saves a bounded `generation-stopped-no-go` journal
   entry. Choose **Clear stopped attempt**. That explicit action archives the
   old operation/record IDs; it creates no key, never deletes one and does not
   check the new-app declaration. Close/reopen the vault and explicitly check
   setup before any separate new-key decision. The old `PreparedSetup.attempted`
   is deliberately not reset by an acknowledgement.
3. If a key was durably saved, use the identified existing item through the
   unchanged Load/authenticate → Assess → explicit Bind controls. Then choose
   **Remember this assigned key**. This reconciles the old intent with the
   actual current Bind and preserves signer constraints. It is not retrospective
   generation success, proof of signing/Play acceptance, or backup completion.
4. Save an encrypted backup separately; keep its recovery code separately.

An old schema1 Reserved entry plus an absent record is **not** no-GO proof.
Partial/uncertain GO, failed original joins, unknown store effects, lost action
acknowledgements and corrupt/capped history never allow reset or regeneration.
Those states remain recovery-required; this packet does not invent a manual
history override or recovery authority after an unrecorded crash.

## Production path

Three new children reuse existing originals, not another owner/runner:

- `credential_setup_recovery.rs`: strict journal transitions and history rules.
  Schema1 reads remain byte-preserving until an explicit transition. Schema2
  requires `cancelledGenerations` (array, never null), at most128 history rows,
  the unchanged128 active slots and whole256KiB bound. Decode AND reserve
  protect stopped/history operation and reserved-record IDs. Related native
  project/root identities remain conflict-checked. Legitimate multi-project
  Assigned references to the same real key are still valid. No eviction/reset.
- `credential_assignment_recovery_store.rs`: same held
  `PrivateStateDirectory::CredentialReferences` namespace, expected-u64 CAS,
  actual durable readback and one retained attempt/result. The proposal is
  retained before IO, actual applied/unknown facts before a late-return check.
  No new state namespace, file/path API, generic callback or IO worker.
- `credential_upload_key_recovery.rs`: a closed new `RecoverUploadKey` job in
  the SAME AssetSession `OriginalWork`, ordinary existing10s work clock and
  unchanged first-failure cleanup. Captures the actual current BoundLoan's
  full StoredRef, random revision, physical read witness, payload/key/store
  Arcs **before** replacing the Bind slot. Calls original `Child::Check` for
  that exact reference, or fixed `RecoveryRoot` root/exclusion/key check for
  no-GO ACK (record absence is only a consistency veto, never no-GO authority).
  Ready/root/context and actual live census rematch before authoritative IO.
  State IO is OFF Doc/Edit/Host locks. The original job retains NativeUse before
  the first journal read and the exact Change before its single CAS.

Positive publication requires the original coordinator and native child joins,
current originals/full bound reference and actual CAS result. Private holding
moves through the existing off-lock Retirement; real NativeUse retirement is
one-shot, with an original deadline/STOP check **after** its blocking return.
Only then is the nonsecret completion marked disposed. Unknown custody/result
blocks private-empty/reuse/quit; temporary healthy retirement remains Pending.
No `Drop` grants successful cleanup or finality.

### Proven no-GO append in the existing cancellation original

`CancellationRetirement.stopped_write` exists only when the already accepted
non-Clone cancellation disposition is `NoGo`. The same original first disposes
its real native private book and proves all coordinator/child/source/native/
Store joins. While its original NativeUse is still live and its exact original
cleanup cutoff has not expired, `persist_stopped` retains and attempts one
StoppedNoGo CAS. Only a known on-time result permits the existing NativeUse
retirement. Late/failed/unknown IO keeps the original/proof/results and does not
renew the clock, retry, claim successful generation, Bind, or delete a key.
DurableNew cancellation is unchanged: its real key survives and reconciliation
requires the ordinary current authenticated Bind described above.

## Closed Desktop interface

Adds only `upload_key_recover`, through the existing original AssetSession
controller, window/document gate and qualification predicate:

```
{ contextRevision, expectedStatusRevision,
  expectedPreferenceRevision: "canonical u64 decimal",
  action: "acknowledge-unstarted" | "remember-bound" }
```

No renderer path, record choice, scalar/private bytes, `noGo` flag, operation-ID
claim or new-app declaration is accepted. Native derives the actual project,
intent and full bound record. `expectedPreferenceRevision` is the last genuine
read only; the actual read/CAS decides freshness. Missing optional frontend API
or `recovery` DTO remains unavailable on older hosts.

`UploadKeyStatus.recovery` gives safe guidance (`none`, `recovery-required`,
`acknowledge-unstarted`, `check-saved-key`, `remember-bound`), actual observed
preference revision, optional public full reference and a separate original
recovery operation projection. Completed requires the actual original
publication/disposal/joins/current context, not Idle, a row count, a producer
return or generated-key marker. The controller also requires the command's own
ACK and exact next preference revision; lost ACK/Unknown remains sticky. A
reentrant subscriber changing project/ABA/context/peer before invoke sends
nothing. No status read initializes state, ACKs, generates, assesses, Binds,
replaces or backs up.

## Root-only integration

`credential-upload-key-recovery-hooks-20261020.patch` contains16 existing-file
hooks against preserved4f28cbdd (the two fixed ACL hooks use589b33f1); apply-check also passed against current shared
Root before this freeze. No shared file in the author worktree was edited.

- `credential_setup.rs`: child + schema2/history and generation replay checks.
- `credential_assignment_store.rs`: fixed recovery child.
- `credential_upload_key.rs`: bounded same-parent recovery IO reservation.
- `credential_upload_key_cancellation.rs`: exact post-private-disposal no-GO
  append before NativeUse retirement, unchanged cancellation origin/cutoff.
- `credential_upload_key_controls.rs`: child, closed request reexport and
  fresh-read recovery projection; qualification stays unchanged/false.
- `asset_session_vault.rs`: original Job/Child/Staged/Work/Retired/SlotData
  additions, retained holding/private-empty/unknown/current publication gates.
- `asset_session.rs` + `asset_session_installation_memory.rs`: new operation and
  actual retained completion census. Existing reuse/private-empty predicates
  already consume the combined upload-key holder; no busy bypass.
- `credential_assignment_native_tests.rs`: test-only visibility of the existing
  synthetic BoundLoan fixture (no new production privilege/receipt constructor).
- `shell.rs`: one fixed ordinary command + handler; no fixture bypass/enable.
- `build.rs` AppManifest COMMANDS + `capabilities/main.json`: exact existing
  main-window `upload_key_recover`/`allow-upload-key-recover` entries only. This
  missing invocation permission was caught in independent actual review; no
  other capability or qualification was added.
- `assetSession{Types,Protocol,Controller}.ts` + `bridge.ts`: optional closed
  adapter, exact original/context handoff and read-only status correlation.

Root must preserve later ServiceAndroid/Git/Apple/tool shared hooks when
composing. No dependency/schema/lockfile/workflow/runtime/qualification edits or broader grants.

## Actual evidence and remaining limits

- Actual focused Node: **31/31 PASS**, zero skips,334.184ms. This source file had
  19 inherited tests plus12 new recovery tests (not35 inherited). Exact complete
  public-source projection used the frontend portion of the16-hook patch + owned modules:
  `/opt/node/current/bin/node --experimental-strip-types --test
  --test-isolation=none --test-concurrency=1
  .task-recovery-node/desktop/tests/credential-upload-key.test.mjs`.
  Its original process joined; exact228-file/3.87MiB task projection was removed.
  Compact log/exit retained in `.task-recovery-results/node-recovery-v1.*`.
  Test ports/records/results are synthetic; no filesystem vault, key or native
  operation ran. Node does not qualify the Rust original or React rendering.
- **16 new Rust tests authored, NOT RUN here**:8 journal,3 real reference-store
  fixtures (references only),5 request/uncertainty/current-Bind/retirement-window
  tests. Reuse the actual existing fixture/key/loan functions with explicitly
  synthetic assessment/join DATA. They do not mint native producer evidence.
- Own Rust rustfmt parse and shared-hook syntax parse PASS; diff/apply checks
  PASS. Full crate compile/selected Rust tests and integrated TypeScript remain
  Root's next combined batch. No separate/extracted test harness was created.
- `NATIVE_UPLOAD_KEY_QUALIFIED` remains false. No actual Mac generation,
  cancellation, new recovery operation, provider, signing, account or installed
  usability proof is claimed; those remain genuinely pending qualification.
