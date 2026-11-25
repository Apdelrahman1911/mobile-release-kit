# Apple Bundle-ID reference journal

Apply the accompanying **one-file `lib.rs` packet** after the accepted Store
upgrade/native-use packet (`a73e0499`). Four new Rust files implement the closed
reference schema, actual Store port and tests. This adds no service, process,
directory writer, public route, agent grant or availability flag. The thin CLI
does not import this native journal or its SavedCommand owner.

The other compile dependency is Apple's separate
`saved_command_apple_provisioning.rs` child of the original `saved_command_owner`,
which Root reexports as `AppleProvisioningNativeJoined` and
`AppleProvisioningAllJobsJoined`. This packet does not duplicate those types or
give them a constructor. Actual witness minting and native routes remain blocked
until the original parent's resource/join gates are integrated.

## Same-original native handoff

1. A separately explicit Desktop action obtains Root's `NativeStateReady` from
   the same Host, original registered roots, saved inputs and real
   `ProjectBinding`. Opening/reusing `ApplicationService` here is local state
   ownership: it must **not** open an IPC endpoint, manufacture an agent session
   or grant agent read/request access. No runtime `project-N` alias is used as
   the durable project ID.
2. Off Doc/Edit/Host/Service guards, consume Ready into `NativeStateLease`; retain
   its same Store and `Arc<NativeUse>` in the existing finite native owner before
   any job GO. A different explicit schema opt-in permits the original Store's
   `enable_apple_provisioning` job. Ordinary reads do not upgrade v1. Map v1
   `Unavailable` to native Apple-state setup, **not** “enable CLI access.”
3. `AppleProvisioningJournal::new(store, native_use)` performs zero IO. Retain the
   port in that same owner. Its calls run only as the original finite jobs,
   outside parent/Host/service locks; STOP must remain independently callable.
   A timeout, task cancellation or result-shaped child message is not a join.
4. The actual selected-P8 owner derives `AccountRef::from_selected_issuer` from
   its authenticated decoded issuer UUID. Inspect the full account roster before
   preparing a new operation. Build/recheck the closed intent from the genuine
   lease binding, native saved context and fresh complete empty Bundle-ID GET;
   do not retain an old operation's context/hash when recontextualizing a review.
5. Before the **single** POST, the same parent's actual reserve job must return
   and join successfully. Bind its ACK to the original waiting operation/job,
   immutable intent, sequence and namespace revision. Recheck current original
   key/consent/source/context/STOP and consume the ACK once in Apple's fixed POST
   permit. This port supplies persistence, not send authority or an executable.

## Exact port and DATA types

`AppleProvisioningJournal` has no serializer/Clone/Debug. Its native methods are:

```text
new(Arc<PrivateStateDirectory>, Arc<NativeUse>) -> Self       // no IO
is_for(&Arc<PrivateStateDirectory>, &Arc<NativeUse>) -> bool // identity only
inspect_account(&mut self, &AccountRef) -> AccountSnapshot
reserve(&mut self, Revision, BundleRegistrationIntent, AttemptUpdate) -> JournalAck
record_attempt(&mut self, Revision, &OriginalReservation, AttemptUpdate) -> JournalAck
finish_native(&mut self, Revision, &OriginalReservation,
              &AppleProvisioningNativeJoined) -> JournalAck
failure(&self) -> Option<StateError>
retained_reservation(&self) -> Option<&Arc<OriginalReservation>>
```

IO methods return `Result<_, StateError>`. The first entered storage/read/decode
failure latches the port; it cannot recover by rereading a matching row. Stale
expected revision detected before CAS is a refusal, not an automatic retry.

`AccountSnapshot { revision, account, rows }` contains **all** matching rows.
`JournalAck { revision, row, original: Arc<OriginalReservation> }` is the actual
Store call's result; the last sequence is `row.attempt.sequence`. Neither is a
renderer/worker deserializable ACK. The original reservation has only a
comparison-data `intent()` accessor and is retained **before** the first CAS.
It remains reachable after a lost ACK for census/cleanup, never resend/adoption.
A new port, lease, process or identical JSON cannot reconstruct that original.

`BundleRegistrationIntent` is closed camelCase DATA:

- existing `ProvisioningContext` fields (runtime project/client/operation,
  observation revision, account and selected record/context revisions);
- `NativeProvenance`: real durable `ProjectBinding`, operation and owner
  generation, registration generation, full registered root facts, draft and
  baseline revisions, existing saved-config and saved-version descriptors;
- `BundleTarget`: Bundle ID, team, app-ID prefix, display name and
  `existingApplication: false`;
- exact UTC `observedAt` / `validUntil` (five minutes apart), `beforeSha256`,
  `planSha256`, `requestBodySha256`.

Validation reconstructs only complete/available/**empty**,
`scope: bundle-identifiers` before DATA and the fixed IOS Bundle-ID POST. It
checks the actual Python canonical hashes, including empty `{}` entitlements.
No arbitrary plan/resources/credential material blob is representable. Paths
and root facts here are comparison DATA, never filesystem admission. Current
time, native source identity and selected key authenticity remain parent checks.

`AttemptUpdate { sequence, record }` contains the closed actual AttemptRecord
fields and reason/status enums. Sequence starts at 1 with armed possible-send;
updates are exact increments, preserve cancellation/response identities and
never restart terminal/uncertain work. `JournalRow` adds irreversible
`sendArmed: true` and independent `nativeSettlement: pending | known | unknown`.
All nullable response/observed fields and the native axis are required, not
silently restored with optimistic defaults. No Debug/secret logging is added.

## Durability, restart and the two join boundaries

The existing tag4 namespace stores canonical schema1, protocol
`mrk-apple-provisioning-journal/1` and sorted rows. Only native-initialized
revision0/empty bytes mean no rows. Missing, invalid, duplicate, unsupported or
nonzero/empty state is never an empty account. No row removal, reset, rebind,
eviction, adopt or retry endpoint exists. An unresolved row blocks **the entire
account**, including other projects and rotated keys; operation IDs stay unique.

Successful reserve requires the actual original Store replace, exact next
revision and exact returned bytes. An entered failure or lost ACK retains the
original reservation and pending state, poisons the port and vetoes POST.
Readback is DATA, not a substitute ACK. A fresh GET after restart may describe a
resource for manual review but cannot update an old reservation or invent its
native joins.

`finish_native` requires Apple's opaque witness matching **both** the original
NativeUse and OriginalReservation by identity. It changes only the native axis,
not the helper status. The witness is minted after the worker/provider/source/
material/driver/manager and pre-final journal jobs have genuinely joined.
Unknown provider outcome remains unresolved even if those resources are closed.

The final CAS is itself still an original job. Only the later, separately
opaque **AllJobsJoined** receipt, after its join/known-not-entered branch and a
sealed writer roster, may allow `retire_native_use`. Merely dropping an Arc,
observing a terminal child, receiving a CAS result, or reading a `known` history
row cannot retire a live lease. Root must join the actual domain owners before
Host shutdown. Failed storage can close after known joins without clearing its
pending/error diagnosis. Complete valid state after restart describes current
durable history; it never reconstructs a lost final job's old receipt.

## Bounds, tests and remaining qualification

Exported fixed bounds are `STATE_LIMIT = 1MiB`, `ROWS = 32`,
`ROW_LIMIT = 16KiB`, `ATTEMPT_LIMIT = 64`. These bound representations, **not RSS**.
The existing native job admission/census must include concurrent raw snapshot,
strict JSON Value, typed state, canonical output, Store encode/readback and
retained original/ACK rows. Calls create no jobs and take no parent locks here.

Sixteen authored Rust methods cover closed cross-language hashes/Unicode, exact
UTC, invalid/omitted/foreign fields, monotonic uncertain/cancelled/terminal
transitions and native-finality separation; actual isolated Store tests cover
v1 refusal, durable CAS/update, same-account exclusion, stale revisions,
committed-write/lost-ACK retention/restart, wrong or retired native use, corrupt
state and full-journal refusal without eviction. No test manufactures a native
join witness. The synthetic fixed hash vector was computed using the actual
Python core/helper with inert data only.

Author evidence: source parser/format and Root packet apply-check only.
**Rust tests/Cargo/native/provider/credentials/installed availability remain
unrun and unqualified.** Root batches the real library graph. This module must
not activate Bundle-ID registration before the real original parent, grantless
state start, joined ACK/POST permit and final all-jobs gates are wired/reviewed.
