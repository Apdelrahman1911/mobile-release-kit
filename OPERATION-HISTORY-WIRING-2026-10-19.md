# Original identity-operation history — narrow Root integration

Versions independently accepted the plan; Root is the distinct implementation
reviewer after finding the original blocking-lock defect. The corrected packet
adds one producer to the **existing** read-only service. It
does not add CLI mutations, a new operation owner, a store, an endpoint or authority
derived from renderer records. No prior unobserved operation is backfilled.

## Owned source and exact central hooks

New children and tests:

- `desktop/src-tauri/src/application_service_identity_history.rs`
- `desktop/src-tauri/src/application_service_identity_history_tests.rs`
- `desktop/src-tauri/src/edit_owner_identity_history.rs`
- `desktop/src-tauri/src/edit_owner_identity_history_tests.rs`

`OPERATION-HISTORY-WIRING-2026-10-19.patch` is an unapplied Root-only patch against
the current integration source, not this branch's older central files:

1. `application_service.rs`: atomic `begin_operation` uses the existing private
   validation/CAS/save path but refuses **any** existing operation ID under the
   same service mutex. Subsequent original-capture updates use the unchanged
   `publish_operation` API. A collision is refused, never reminted or adopted.
   An original-service atomic read fence is permanent for that instance and is
   checked before/after reads and authorizations, including the existing IPC
   `client_current` pre-send check. Allow never clears it; stop/revoke still work.
   One test-only helper holds the real service mutex for the lock regressions.
2. `application_service_host.rs`: declare the child and one fixed 32-row inbox
   under a **separate memory-only mutex**, never the IO-bearing Host control.
   Capture pins the existing initialized Host/service, original native SID and
   native registered project/root/Document identity using **try-lock only**.
   Contended, Dormant, unregistered or unrepresentable capture is skipped without
   starting the Host, delaying native STOP or backfilling it later. Captured
   updates retain the inbox/original key and never lock the Host or Service.
   Retirement closes memory admission before existing Host/Service shutdown work.
3. `edit_owner.rs`: one weak Host binding and a link on the original ActiveOwner,
   not its Session. Initial native admission is the only capture opportunity.
   Native revision bumps supply memory-only progress. The original final observer
   supplies terminal state **after** its actual resource/join checks and atomic
   `active -> last` publication, still under the same registry lock and correlated
   with the same original Session and generation. No full projection is retained.
4. `asset_session.rs`: bind from the genuine Document constructor after existing
   registration binding; charge the fixed bounded history reservation once in
   the existing global Document census.
5. `shell.rs`: the original retained relay flushes one claimed update outside
   Document/Edit/Host-control locks. After all original work is finished and that
   same relay is positively joined, the original exit observer drains final rows
   **before** Host shutdown. History errors never skip original cleanup.

The global picker generation is provenance, not project identity: unrelated
roster/input changes do not erase a capture. The exact runtime alias, physical
root and original Document/service remain pinned; no account mapping is needed
for this local edit family. No app ID, source, path, credential, raw reason or
account identifier enters the public operation record.

## State and lifetime

- Running, reviewed/prepared and cancellation requested remain `pending`.
- Settled success requires genuine applied/valid identity details and no native
  or core failure, or the existing exact identity-recovery predicate. Close alone
  is not success; committed work followed by cancellation is not labelled cancelled.
- Native/late/core unknown wins; known recovery-required journal is next. Known
  failure and cancelled-after-settlement remain distinct. No core terminal frame
  or public status by itself settles an operation.
- Latest progress may coalesce: the existing service is a latest-record cache,
  not an event log. A claimed update and its later pending update are separate;
  acknowledging a slow write cannot discard a final observation that arrived
  during it. Original native IDs remain stable; the service owns durable revisions.
- Failed, uncertain or unreturned publication retains the original claim, fences
  service reads and is never retried. It does not change native edit finality.
  Retiring forbids new capture but permits final publication of captured originals.
- A lost/failed observation sets the service's permanent atomic fence without
  waiting for its IO-bearing mutex; the UI gets an error, not a fabricated Off.
  Only the off-native relay/drain records the Host failure. It claims memory,
  releases the inbox, validates the Host, releases it, performs the original
  service write, then acknowledges under the memory lock. No inbox scope calls
  a Host/Service owner or performs IO. Native STOP itself is unchanged.
- Restart keeps the existing service's stale-history semantics. This adds neither
  Store evidence nor a current-source/readiness assertion.

## Validation and limits

There are **24 focused Rust tests** (15 Host/store metadata tests, 9 pure native
projection mapping tests). They cover require-new collision, original project
binding, late final during claim/ack, no lock over publication, unchanged-progress
coalescing, unknown absorption, failed/unreturned write retention, capacity,
revoke/retire/final drain, restart staleness, actual-retirement-only settlement,
recovery, failed open and post-Apply cancellation/unknown priority. The two lock
regressions hold the **real Host and Service mutexes** while a separate finite
test thread (a) skips new capture and retains a captured final, or (b) sets the
atomic error fence and verifies read/admission/pre-send/Allow refusals. Both
holders and workers are released/joined before asserting the bounded result,
including on failure; they are not simulated write callbacks.

**No Cargo or Rust tests were run by this lane.** Root owns the combined graph
and focused `identity_history::tests` batch after applying the mandatory hooks.
Formatter syntax checks and patch applicability do not qualify the native route,
process/resource joins, installed CLI or Mac delivery. The synthetic fixtures use
only fresh ordinary test directories and the original service store; they launch
no engine, listener, native edit or provider operation.
