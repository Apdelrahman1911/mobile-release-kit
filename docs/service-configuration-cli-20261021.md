# Configuration CLI: the original Desktop editor

This is a bounded, Desktop-assisted settings interface, **not a headless writer**.
Existing live project READ permits source read and preparation. Saving requires
an explicit, one-use permission for the exact native preview in the real main
window. No permission, native availability, successful cleanup or installed
runtime qualification is inferred from these source changes.

## Included and excluded settings

The closed change selects one complete group:

- `source`: candidate and production branch names;
- `android`: module and variant, only when Android is already enabled;
- `ios`: relative project/workspace choice, scheme and archive configuration,
  only when iOS is already enabled.

Unselected settings are preserved in the original native checkout. The service
does not export the full configuration. Identity, versions, platform enablement,
commands, credentials, signing and recovery remain outside this interface.
Relative iOS container names are settings, not arbitrary filesystem operations.
Native schema validation and ordinary configuration recovery remain authoritative.

## End-to-end interface

```
mrk configuration-read PROJECT_ID OBSERVATION_REVISION [--json]
mrk configuration-prepare PROJECT_ID SERVICE_INSTANCE REQUEST_ID SESSION_ID OWNER_GENERATION REVISION --stdin [--json]
mrk configuration-apply PROJECT_ID SERVICE_INSTANCE REQUEST_ID SESSION_ID OWNER_GENERATION REVISION PLAN_TOKEN --reviewed [--json]
mrk configuration-status PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]
mrk configuration-cancel PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]
```

`--stdin` accepts one closed change object, at most 2 KiB. IDs are the actual
service/request/session/revision IDs, not caller-selected source authority. Read
prints the freshly generated request ID before submitting it. Missing replies
are discovered with the same status/cancel IDs; identical requests do not replay.
The existing eleven-word collector retains the longest command plus a rejection
sentinel. The installed client imports only DATA/protocol code, not EditOwner.

Three exact main-window RAW commands are added:
`agent_configuration_status`, `allow_agent_configuration_apply`, and
`revoke_agent_configuration`. Allow binds origin, original session, plan token,
native status revision and `agent-exact-configuration-preview-v1`. Open/Prepare/
Apply travel through closed variants of the existing configuration bridge from
the **actual Webview**. IPC only enqueues; it never invents a window or calls the
native editor itself. The existing relay event is `mrk:agent-configuration`.
Foreground history service remains cached/read-only and rejects this family.
Status accepts exactly `{}` for the latest row or the complete existing flat
`{serviceInstance, projectId, requestId}` for one retained row. Exact inspection
never falls back to the latest request; the same main-window gate and reply
bounds apply. No additional command, authority or read owner is introduced.

## Original ownership and finality

1. Capture the SAME Service READ facet off Document, including its original
   expiry/revocation. Under Document, check actual peers idle **before** the
   existing invalidation publisher. No Service/Host IO lock enters the native
   currentness/GO gate.
2. Claim the request permanently; install the original ActiveOwner, then bind
   the Entry to that same Session before bump/publication/queue. Bind failure
   retains the installed original as unknown rather than dropping it.
3. Open the real checkout and derive only the selected change. Retain the exact
   native preview, including `.gitignore` additions, formatting rewrite and all
   original file effects. A seven-publication chain prevents skip, repeat or
   rebasing. Ordinary endpoints cannot bypass the linked request's Apply grant.
4. Allow is one-use, bounded by the original review and READ deadlines (at most
   fifteen minutes). Apply consumes it before enqueue. Original watchdog polling
   also samples READ/revoke/STOP without renderer cooperation, forwarding the
   earliest captured instant; UI loss cannot renew a deadline.
5. Only original startup, IO, runtime, driver, watchdog and manager returns feed
   native finality. An event or terminal DATA never joins a pending invoke.
   Unknown/lost acknowledgement is absorbing; no automatic retry or retirement
   credit comes from revocation, expiry or an absent review.
   A failed positive Configuration retirement chain fences attribution before
   the native final projection is published; actual core/cleanup facts and any
   earlier native reason remain intact. Ordinary and known cancelled cleanup
   paths are not changed.

One inbox retains at most 32 metadata rows and one active original—not 32 full
configurations. Existing acknowledged history publication is off Document and
attempted once. Generic request discovery includes Configuration's 32 rows and
remains bounded (192 total rows with the current families).

## Desktop form continuity

The new controller is a child of the existing ConfigEditController and reuses
its API, original calls and form session. Every post-notification pre-invoke cut
rechecks API/project/epoch/checkout/draft, including Allow and Apply. There is no
automatic Allow or Apply, and Check/Stop remain reachable after project drift.

Completed CLI save adoption requires the original Apply return, genuine native
finality **and the matching retired service Entry result**. A native event alone
cannot outrun an unverified service retirement. Only the exact same clean session,
draft, baseline and revision are replaced together. Dirty, newer or ABA-edited
forms preserve their values and record the completed save as a conflict. Ordinary
`snapshot-done` semantics are unchanged; no repeated save refreshes the GUI.

The same issued permission's observed countdown never increases or revives from
a delayed reply; first Allow advances the row revision, so a pre-Allow zero does
not expire a new grant. After known pre-Apply cancellation, the old UI approval is
retired only after matching native/service finals and both original Allow/STOP
promises return. Pending, unmatched, Unknown or lost acknowledgements remain
retained. One bounded final Entry DATA object survives a later request while the
original calls return; it does not replace a native receipt or authorize replay.
If the coalesced relay skips that old final, explicit Check uses its one original
Work to read latest, query the captured old origin, and inspect the existing
native status. The old reply is never passed to the latest-selection reducer.
Only the still-identical approval/API may retain it. A valid pending old row
stays pending; missing, foreign or Unknown responses cannot unblock a new request.

## New-slice memory admission (ordinary editor unchanged)

The aggregate guard uses the existing `SESSION_BYTES` 64 MiB limit with **all**
existing Document census debits, original Edit registry backing and this slice's
future/derivation quote. It changes no other operation/private/code cap and
does not clear retained work to fit. Concurrent ordinary Edit work is refused.

- Before new CLI frame growth/parse/clone: 272 KiB raw frame, 4,160 nodes and
  depth 24 using the existing strict Seed. Checkout base is additionally limited
  to 256 KiB, 4,096 nodes and depth 20 before clone/derivation. Ordinary decoding
  and recovery retain their original limits.
- The original reader enforces **three total frames before decode**, not merely
  three queued frames. Frames move into the current projection. Its entire
  checkout-plus-prepared backing is checked before adoption.
- `R = 4160*512 + 2*272KiB = 2,686,976` bytes. Future backing is `6R` for the
  three frames, parse/typed overlap and two independent whole native Status
  projections, plus two original 1 MiB command buffers, two encoded 2 MiB status
  buffers and 1 MiB raw/IO/cell backing: 23,461,888 bytes. A separate 8 MiB
  derivation allowance is unchanged.
- The closed borrowed registry census counts actual String/Vec capacities and
  conservative BTree/Value backing. The original last Config projection and its
  two possible Status clones are charged separately. Other-domain last data,
  including private submissions, stays counted even though filtered from Config
  status. No status serialization, IO, receipt or owner is created by this census.

Oversized/complex configurations preserve the draft/original and give the
ordinary-editor fallback only after original work settles; Unknown still needs
its existing recovery. This is backing arithmetic, not a process-RSS claim.

## Delivery and evidence

Sixteen owned code/test leaves plus this guide and
`service-configuration-cli-hooks-20261021.patch`. The patch contains 25 nonempty
shared targets against Root `78c91de8` plus its staged local catalogue bound
(the earlier `49fb7a55` headless/memory union and already-applied thirty-description
compression). It preserves those changes.
The shared READ `stop/end` accessors already landed with Play cleanup, so require
no second hook. No shared files were edited in this worktree.
Later Root Device/credential hooks are not overwritten: Root will mechanically
union the captured preimages, including the Device census and package test list.

The catalogue uses Root's existing local-only `CAPABILITIES_BYTES` 32 KiB bound;
IPC, native and request limits are unchanged. All arguments, grants, exclusions
and commands remain. Its Repository actions also list the already implemented
`set-upstream`. The prior source-only 11,912-byte JSON calculation includes
Configuration, cleanup and foreground history; it is **not** compiled CLI proof.

Retained author evidence in `.task-configuration-hooks/`:

- Narrow review successor: 19 real-controller/inert-API Node tests PASS, zero
  skips (the prior 15 plus four grouped regressions), 258.046 ms. The original
  caller returned zero; all 211 public projection files were rematched and retired.
- Exact-old-status successor: 22 distinct Node cases pass across the affected
  runs. The first run passed 20 and failed two new strict assertions comparing
  intentional null-prototype parser objects to plain test objects. Only those
  comparisons changed; the two affected cases then passed, zero skips, 204.070 ms.
  Production bytes stayed identical between runs. Both callers returned; the
  failed evidence/projection is retained and the passing 211-file projection
  was rematched and retired. New tests cover a skipped old Final, pending/wrong/
  missing/Unknown exact replies, and disposal while the original Check returns.
- 81 affected existing Node cases: 80 PASS, one unchanged baseline copy/assertion
  mismatch (`config-edit.test.mjs:1193`, expecting `destructive in-memory`). This
  is not reported as a full passing suite. Root removed only that obsolete
  assertion separately; the single affected named privacy/help test then passed
  through the original standard Node route. No 80-case reassurance rerun.
- Whole composed frontend noEmit: PASS for the initial packet, **not rerun for
  this narrow controller successor**; Root's final composition still needs its
  integration check. The initial projection-only missing
  inputs/type import failure was corrected; logs retained. Original caller joined
  and only its exact disposable projection/link/scratch were retired.
- 12 owned and 18 projected Rust files: syntax parsed only. **24 new Rust tests
  initially UNRUN**; the successor adds one negative retirement-attribution DATA
  test and one exact retained-Inbox lookup test, so **26 are UNRUN**. The final
  correction's four Rust leaves and two parent images parse only. Library and
  transport-only CLI compilation remain Root's batch.

Rust selectors: `service_configuration_protocol::tests` (5),
`service_configuration_requests::tests` (7), `application_service::agent_configuration::tests`
(3), `edit_owner::agent_configuration::tests` (5),
`edit_owner::agent_configuration::memory::tests` (2),
`asset_session::agent_configuration::configuration_storage_tests` (1), and
`installed_cli::configuration::tests` (3). These include actual Service/Grant
fixtures, original registry capacities and real default-Document/overbound
arithmetic; none fabricates a native owner/join receipt. Root must also run the
existing capability and Play cleanup capability tests against the composed CLI.

The initial exact 18-file freeze and all 25 parent before/after images are
preserved under `.task-configuration-hooks/review-correction-v1/before`.
The first corrected freeze is retained in `review-correction-v2/before`.
The narrow successor changes only the reviewed countdown/retirement/approval
cuts and exact-old status inspection, their tests, this guide and the
corresponding hook images; no new census, quota or authority change is included.

No native operation, installed CLI execution, provider call, GUI automation,
availability activation or platform qualification was performed by this author.
