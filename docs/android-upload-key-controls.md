# Android upload-key Desktop controls

This is the closed Desktop entry for the reviewed upload-key producer and vault
parent, not another producer. **Native generation remains qualification-disabled.**
No real key, account, keystore, native dialog, tool or signing operation was used
to implement/test this controls packet. A writable/qualified vault does not by
itself qualify key generation.

## User flow

1. Select the Android project and its current signing context; explicitly open
   and unlock encrypted storage using the existing controls.
2. **Set up Android signing** checks existing native state and key references.
   Read-only status never initializes the Host or creates anything. Existing
   keys, assignments, saved generation intent, identity mismatch or uncertain
   history take the existing-key/recovery path instead of generation.
3. Only a current native `confirm-application-history` result shows an unchecked
   declaration: “This is a new app and I have never used an upload key for it.”
   This is the user's declaration, not an inferred Play Console observation.
   **Create and save upload key** spends that current declaration before invoke.
4. The existing original creates the key, performs fixed NEW/None vault storage,
   full authenticated readback, durable `record_saved`, real publication and
   private disposal after original joins. No assignment/backup happens here.
5. Only that current original's fully checked stored reference displays **Upload
   key saved**. The user then assesses/assigns the exact saved item using existing
   controls and separately saves an encrypted backup/recovery code. Native
   producer completion, an Idle status, a row count or a persisted fingerprint
   alone can never display this completion.

Unknown/lost acknowledgement and cancellation never rearm generation. Navigation
does not own/cancel the native producer. Existing explicit Cancel targets only
the acknowledged original; during grantless Host setup it cannot cancel some
previous credential operation. Existing import/assessment/backup remains intact.

## Three closed commands

| Command | Exact request |
| --- | --- |
| `upload_key_status` | `{contextRevision}` |
| `upload_key_prepare` | `{contextRevision}` |
| `upload_key_create` | `{contextRevision, expectedStatusRevision, declaration: "new-application-no-existing-upload-key"}` |

Revisions are positive native u32 values below exhaustion. Unknown fields are
refused. No renderer root, app identity, key/password/scalar, native tool, vault
path, output path, replacement record or “already published” guess is accepted.
These methods are optional on older frontend APIs; missing methods are
unavailable, not inherited vault capability.

The separate schema-1 result contains the existing schema-3 asset status, the
single native availability predicate, safe setup/plan/progress, and an optional
full five-field vault reference. The Rust type is the only successful shell
serialization source. Those fields are comparison DATA, never a material loan,
tool grant, service grant or finality receipt.

## Actual native ownership

`credential_upload_key_controls.rs` is a child of the accepted vault generation
parent. The one private Session setup retains its real NativeContext, native
root/registration/input facts and SavedEditStamp. Explicit prepare uses:

1. The original Document/idle/writable-vault gates and existing live census.
2. `service_project_locked`, `saved_registration_guard`, and the existing
   `upload_key_saved_input` check. No draft is promoted into saved-file evidence.
3. The fixed native app-local-data path and original root roster, passed to
   **`reserve_native_state_location` (TRY-only)** and `begin_native_state`.
4. The same retained flight/ticket while `prepare_native_state` runs off the
   Document/Edit guards. No generic subprocess/startup controller is introduced.
5. Exact same flight/context + `service_allow_current_locked` rematch;
   `finish_native_state` once; wrap its private Ready once in an Arc, retain it in
   the private prepared setup, and compare that Arc/prepared owner before start.

`application_service_upload_key.rs` supplies only
`Host::native_state_service(&NativeStateReady, &NativeProject)`. It validates
owner, source epoch, full native registration/input, Ready/Listening phase and
exact store/service while holding **one TRY-only Host guard**, then clones that
same service. It neither starts the agent socket nor enables CLI access. There
is no new Host “latest Ready” generation policy.

The same child provides `NativeStateReady::retained_bytes() -> Option<usize>`
for its actual retained metadata. The document census adds Arc control cells
and counts a shared Ready Arc once; the original store/source owners remain
separately accounted. This metadata method grants no readiness or native use.

The prepare/status preference snapshot is reference-only comparison DATA. The
existing generation OriginalWork coordinator retains `NativeStateLease` before
its authoritative reservation re-read/CAS and before private password CSPRNG or
GO. The pre-existing nonsecret random record-ID mint remains before native
preparation. Store-use checks occur off the Document lock and recheck the same
original clock before and after waiting; none renew it. `NativeUse` is retired
only after the parent's genuine publication/all-jobs/private-disposal edge, not
by Drop, a producer-shaped result or before the last journal write. Failed or
uncertain originals remain retained; no retry/rollback permission is added.
The actual token-retirement return is remembered separately from completion.
Its blocking Store wait must return within the same original clock before the
Holding is dropped; a late return preserves the retired-token fact, latches
the immutable original deadline/minimum failure and cannot erase that clock.

The native generation producer, private binary reader, original tool lease,
fixed keytool arguments/password channel, shared 180/190-second clock,
NEW/readback/journal and explicit assessment/Bind remain the reviewed existing
implementations. This packet does not modify or requalify them.

The nonsecret `SlotData.upload_key_context` stamp is captured only by the real
generated-row publisher, before ordinary working-reference retirement. Showing
success additionally requires the full current StoredRef/witness, current app
and native root/context, current key/book fingerprint provenance, known durable
outcome, all original joins and actual private-disposal clock retirement. Prior
failed joins, a borrowed retirement lock, same-counter/different-random-revision
rows and stale/new contexts refuse it. The stamp is not disposal authority.
Temporary progress contention or the normal transfer into Retirement is only
pending presentation, never an invented failure or a Saved marker. Actual
STOP, failed clock, failed progress and Unknown remain absorbing. Both upload
invocation closures also rematch the original API, project/local revision,
context/status and peer gate after synchronous busy subscribers have run;
reentrant retirement/ABA cannot dispatch a spent old declaration.

## Root integration and Apple handoff

Apply `android-upload-key-controls-root-hooks.patch` (ten existing central
files) on the committed `0356f163` ancestor, preserving later unrelated Root
changes. The owned new children/components/tests accompany it. Root alone edits
the shared shell/Host/asset-session/controller/protocol/bridge files.

**Additional Root-owned dependency:** the existing blocking
`reserve_native_location` is NOT used under Document. Root supplies the agreed
`reserve_native_state_location(app_data, roots)` with identical closed location
validation and `try_native_lock`; ordinary old-role reservation is unchanged.

For Apple's approved explicit account/setup action, reuse those same existing
capture → native reservation/begin → off-lock prepare → exact current finish
primitives. Retain Apple's own context/source-domain flight and the Ready Arc in
its existing private document slot before publishing `apple_provisioning_ready`.
The shared `native_state_service` accessor can consume that actual Ready. No
public generic prepare command, CLI grant, status-triggered initialization,
network request or Apple mutation is introduced by this helper.

## Focused evidence and limits

- Node: **35/35 pass**, zero skips (new controls19 + existing backup16), on the
  actual public-source projection plus the exact central frontend changes.
  Tests cover closed requests, distinct references, old APIs/qualification,
  read-only status, explicit preparation/consent, stale/double clicks, current
  project/other-owner vetoes, overtaking events, lost/unknown acknowledgement,
  full marker versus Idle/count, foreign records, no automatic Bind/backup, and
  navigation/original cancellation, reentrant pre-invoke retirement/ABA and
  healthy pending retirement followed by the same original's saved result.
- Actual pinned TypeScript project check: **pass** on that same projection.
  The original processes joined and exact task projection/dependency symlink
  were removed; compact logs remain task-local.
- Eleven new Rust tests are authored but **not yet run/compiled**: eight fixed
  request/working-reference/clock/join/full-ref/pending predicate regressions and three
  same-guard Host/real reference-Store NativeUse tests. They use synthetic native
  facts/fixed codec material only, not native startup or key generation.
- Root must compile the combined real graph, including the macOS shell-gated
  methods and the TRY-only reservation hook. Linux/Node/source results do not
  qualify macOS leases, private keytool IO, generated JKS, NEW/readback,
  cancellation, use-token retirement or installed generation. The separate
  real-native verification plan remains required; flags remain false.
