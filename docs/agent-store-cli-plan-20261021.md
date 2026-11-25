# Installed CLI: delegate one prepared, nonpublishing Store step

Accepted implementation plan. Base `1bb859381ce7473020f92c3775904b864c623639`
(isolated `git-store-cli` worktree). SetupUI independently reviewed the plan
and the explicit cuts below; Root authorizes this source implementation only.
No provider request, build, native execution, or eligibility change is included.
The implementation's shared-file packet is based on current integration
`78c91de83f3e85a113d878d58d427817b72b7b18`, not a replacement of the older
worktree's complete shared files.

## 1. Small useful scope and existing source

One closed Store delegation family, one finite metadata inbox, three CLI calls.
The user first uses the **existing Desktop Review**; the CLI can run that exact
prepared step once. It cannot construct a context or prepare its replacement.

| Fixed kind | Existing native owner | Permitted effect |
| --- | --- | --- |
| `access-check` | `LocalStorePreflightOwner` | Basic Android or iOS access check only: `query=None`, not Both. iOS reads; Play creates/reads/deletes its existing temporary uncommitted edit. This is explicitly **not** zero-write or release readiness. |
| `candidate-prepare` | `LocalStorePrepareOwner` | Android/internal or iOS/TestFlight-internal candidate only, `later=None`. Existing provider snapshot and local release snapshot/intent journal; no upload, track commit, submission or publishing. |

No new core commands, Store client, credential source, journal, runtime, binary,
transport, workflow, or provider retry. Query variants, stage promotion,
Execute, Reconcile, recovery settlement, signing/builds and credential assignment
are excluded. Those already have separate consent and potentially mutating
semantics; an `Action::Release` service label is not their authority. This first
family makes two existing safe steps reachable without a subsystem per step.

Source anchors at the base:

* `asset_session_store_{preflight,prepare}.rs`: genuine material/root/budget
  review; Start rechecks the original material under Doc and releases GO only
  after unlocking. `local_store_*_owner.rs` are typed adapters only.
* `saved_command_store{,_prepare}.rs` and `saved_command_owner.rs`: actual
  Prepared/Session, private material, same driver/watchdog/native resources and
  retirement. Prepared intent lasts 300s; Store work/finality are 1200/1210s,
  first failure clamps cleanup to the existing original cutoff.
* `asset_session_store_material.rs`: exact local context, assignment/record
  revision, original credential loan and full root. Candidate preparation also
  has the actual Doc/local-history claim and helper claim; these stay unchanged.
* `service_version_reserve_*`, `agent_build_requests.rs`,
  `saved_command_agent_*`, `asset_session_agent_android_build.rs`: existing
  finite request, original native link, STOP/retirement and same relay patterns.
* `components/LocalStore{Preflight,Prepare}.tsx`: existing Review/consent/status/
  original Cancel and release-history recovery guidance stay in place.

## 2. Closed user/CLI contract

Desktop gains one small shared optional **Allow CLI once** control for the
current prepared step. It shows the exact kind/platform/version/candidate and
the existing effect warning; the candidate case also says it saves a local
journal. It requires its own explicit checkbox, never inherits ordinary Start
or read-access consent. Keep the already-listening Desktop service and separate
project read permission; Allow cannot initialize a Host or credentials.
There is ONE retained permission controller across both Store panels, not one
permission per panel. Pending/lost Allow or Revoke retains its original promise
and blocks replacement. A native revoke epoch is captured before off-Doc Allow
work and advanced even when no lease exists. Late Allow cannot resurrect it.
The empty Revoke request means the sole current original; the controller never
reissues an old callback against a replacement, and native replacement is
blocked while that original call/request is pending or uncertain.

Three main-window RAW commands, each <=1024B, duplicate/extra fields rejected:

* `agent_store_access {}`: bounded original lease/request metadata only.
* `allow_agent_store {kind,operationId,ownerGeneration,expectedStatusRevision,
  consentVersion}`. Consent is fixed per kind/platform. IDs/revision are
  comparisons; native derives project, original context and private inputs.
* `revoke_agent_store {}`: revoke the one retained grant/request and request
  original STOP. It does not undo a journal or prove cleanup.

The existing bundled `mrk` adds only:

```
mrk store-submit PROJECT INSTANCE GRANT REVIEW --reviewed [--json]
mrk store-status PROJECT INSTANCE REQUEST [--json]
mrk store-cancel PROJECT INSTANCE REQUEST [--json]
```

Same protocol/version1, fixed `store.submit/status/cancel`; Submit is
`{origin:{projectId,serviceInstance,requestId},grantId,reviewId}`, queries are
the exact origin. All IDs use the existing 32-lower-hex nonzero grammar. No
kind, credentials/IDs, path, URL, command, candidate, consent token, draft or
provider options come from the CLI. It prints a fresh request ID before its
sole Submit. Lost ACK is **check/cancel that ID**, never automatic replay.

Access/Status use required-nullable fields and strict kind-tagged metadata.
Status retains service/project/request/grant/review IDs, native operation and
generation when admitted, revision, queued/running/stopping/finishing/terminal/
unknown, settlement and fixed reason. Result is redacted from the *existing
validated* result: access finding enums/status and limitations; candidate
version/digests/checkpoint/intent IDs and limitations. No raw provider errors,
credential IDs, key material, local paths, arbitrary response bodies or raw
journal are serialized. `complete` does not mean every finding passed or
authorize execution. A CLI0/pending response never claims native completion.

## 3. Genuine prepared custody, consent, clocks and locking

Add ONE optional Store-link facet to the existing SavedCommand Prepared and
Session, not a separate operation owner. A small comparison-only native
witness is held by the genuine supported Prepared. Approval captures a Weak
original Saved owner/witness and bounded review DATA, never a long-lived
credential/runtime/Session Arc. Equal decoded IDs cannot replace that witness.

Allow follows existing two-phase Doc/Service ordering:

1. Under Doc and the original Saved registry, match exact AwaitingConsent,
   status revision, usable unexpired Prepared, closed kind/context, physical
   registration/root, saved edit stamp/epoch, and original material; count the
   complete retained backing. Capture the original weak witness and expiry.
2. Off Doc/Edit/Saved locks, use the already-listening Host and actual Service
   ProjectBinding/read grant/saved snapshot. This may do existing Store IO.
   No pending socket worker calls a native owner. Reuse the actual current
   read-grant facet (its Drop/expiry revokes); never mint a read permission.
3. Re-enter Doc and original registry; rematch witness, every original binding,
   gate, expiry and revoke epoch. Bind the one Store lease before returning
   Allow. There is no reverse Inbox -> Doc callback. Once bound, ordinary GUI
   Start cannot consume the agent-linked Prepared. Revocation/expiry retires
   it; ordinary execution needs a fresh explicit Review, not an unbind/retry.

The same service grant lock linearizes one Submit with read revoke. Its first
entry timestamp **T is captured before service locking/queue/relay** and is
passed unchanged into existing Store Start (1200/1210 from T, no relay reset).
The delegation cannot outlive the original Prepared's 300s admission expiry;
after genuine admission that expiry is not a new running timer. Earlier read
permission expiry/revoke, Doc/context loss and cancellation remain tighter
original STOP/failure bounds.

The Saved endpoint includes that **same immutable Read end** before STOP.
The existing watchdog control-select slot samples only the Store-linked
facet every5ms (the ordinary slot behavior is unchanged), even while its
relay is blocked or the worker is quiet. Renewal/Grant Drop cannot replace
the retained old facet or depend on new output to be noticed. Sampling
continues after STOP so a later-observed earlier original revoke tightens F;
the original Unknown/finality endpoint disables the slot. This scheduling
check is not a new work/cleanup clock, task, owner or grant.

The separately reviewed GUI handoff is monotone on the **same Attempt**. At
Allow call entry, `delegatePrepared` requires the original Prepare promise has
actually returned, exact identity/revision/context and no pending/read/unknown
state. It clears only that Attempt's 60s GUI consent timer/Start selection and
excludes it from unstarted tab-hide cancellation; it never sets `started` or
changes native expiry. After synchronous listeners the permission controller
rechecks its private Attempt pin, API/context/epoch, revoke generation and
peers before the one RAW Allow. A failed/lost or pre-send-refused handoff never
restores GUI consent. Explicit context changes, original Cancel and Quit still
stop the same original. Clearing `consentUntil` removes the ordinary selectable
review, not the private delegated pin.

The existing retained Shell relay claims the sole queued Entry. Before Start,
it uses the actual saved-project writer off Doc to stale the prior observation
conservatively, then under Doc rematches service identity, full native project,
edit/epoch, Prepared witness, original material and unchanged domain budget.
It calls a closed agent Start arm of the **same** typed Store owner. Shared
`start_bound_requests` checks the Store Entry/link before `Prepared.take`,
consumes once before effects, and retains the link in the same Session.
Native consent comes from the reviewed original context/closed constants, not
the CLI. Existing GO is released only after Doc/Edit/registry locks drop.

No additional task, executor, timer, HTTP client or original source capture.
The existing Session listens to the Entry's original STOP watch and forwards
the earliest captured timestamp through its existing first-F logic. Add the
closed Store facet at the same changed/retired-prepared/retired callbacks used
by agent builds. Ordinary routes pass None and retain their existing behavior.

## 4. Finality, reconnect, recovery and bounded backing

One Inbox across both kinds, max32 request tombstones and ONE grant/pending
operation. No pruning/reusing an unknown row to make capacity. Status/reconnect
reads the same Entry; another client/instance/project/kind cannot adopt it.
Cancel before native take is known not-admitted only after original claim
return; cancel after take requests the real Session STOP. Terminal-looking
worker JSON is not a joined result. Known request terminal requires ALL THREE:
actual relay/claim caller return, actual Saved owner positive retirement after
driver/watchdog/native material/history/resource settlement, and the genuine
Service operation-history publication return. These can arrive in either
order; retirement alone cannot settle a still-running relay. Missing
relay/retirement/history/close evidence stays Unknown and blocks new
Allow/Submit. Pending and Unknown preserve original status and controls.
There is no coalescing latest-request event that can erase a final result:
Desktop Status reads the same lease/Entry, and a second request cannot queue
through its one-use grant. A new explicit Allow requires all older rows known
settled. Their exact request IDs remain queryable after that later lease, so a
new queued row is never evidence that the previous request finished.

Use existing Service operation-history begin/publish (Observe for access,
Release for candidate preparation), not a new durable request journal. Failure
of that original history publication remains fenced/unconfirmed. Candidate
core snapshot/intent ACK/NativeUse/history ownership are untouched. Restart
does not restore a grant or automatically resubmit: same-service request
correlation is gone; existing service history and native Release history are
historical evidence, with their existing explicit Inspect/Reconcile UI. A
partial preparation may have left a pending checkpoint; never delete/re-enroll
or infer retry permission from a missing CLI row.

Fixed native DATA reservation: **2MiB inside the existing shared Document
allowance**, no cap increase or retired/prepared credit. Root owns the separate
aggregate-budget migration; this is not an additional quota above that allowance
and is not presumed to fit the old16MiB cap. The checked table is:

| Retained/working DATA, all coexistence charged | Bytes |
| --- | ---: |
| 32 rows × (8KiB complete Entry/Scope/IDs/root/record backing + two8KiB native/history copies) | 786,432 |
| 8 original IPC workers × (4KiB original request + two8KiB outputs) | 163,840 |
| Two64KiB bounded result conversions +32KiB projected transient copies | 163,840 |
| Current Doc grant/Approval/Binding/latest copy, weak links, relay and fixed parser/list bookkeeping | 131,072 |
| Subtotal | 1,245,184 |
| Fixed charged amount, including remaining conservative backing headroom | 2,097,152 |

`NativeScope.root` is at most4096B; runtime name64B, all IDs/digests/version
strings are closed/bounded. Native reports contain at most16 enum findings or
the fixed candidate fields, not a raw response. The old validated result is
bounded again before the one redacted conversion. Struct/list/Arc/Mutex/watch
backing and all retained copies are included; the size test is a supporting
check, not the whole quote. `Binding.latest` belongs to the sole current grant,
not an unbounded history. Old Saved runtime/private material/candidate/history
and every other service inbox remain separately charged in the existing Doc
census. Overflow refuses before Allow/IO. History rows hold no strong runtime,
material, Session or source Arc; Approval has only weak original links.

## 5. Exact authoring and shared-hook footprint

New owned leaves (one family, not one copy per platform/action):

* `src-tauri/src/service_store_protocol.rs`, `service_store_requests.rs`,
  `service_store_application.rs`: closed DATA/inbox and existing service adapter.
* `src-tauri/src/asset_session_agent_store.rs`, `saved_command_agent_store.rs`:
  actual Doc approval/relay and original Saved owner facet.
* `src-tauri/src/installed_cli_store.rs`: three ordinary CLI calls.
* `src/agentStoreAccess.ts`, `agentStoreAccessController.ts`,
  `src/components/AgentStoreAccess.tsx`: one control shared by both existing
  panels, retained original promises, no mount query/Start or renewal.
* Focused `service_store_tests.rs`, `saved_command_agent_store_tests.rs`,
  `installed_cli_store_tests.rs`, `tests/agent-store-access.test.mjs`, plus this
  guide and `agent-store-cli-hooks-20261021.patch`.

All existing-file changes are Root-only patch:

* Native graph/ABI: `lib.rs`, `installed_cli_main.rs`,
  `tests/installed_shell_observation.rs`, `service_protocol.rs`,
  `application_service.rs`, `service_request_catalogue.rs`,
  `application_service_request_catalogue.rs` (one additional Store family;
  fixed32 IDs only, original64KiB request-list cap unchanged). The existing
  ReadPermission stop facet is already accessible and requires no hook.
* Native entry/lifetime: `asset_session.rs`, `shell.rs`,
  `saved_command_owner.rs`, `local_store_preflight_owner.rs`,
  `local_store_prepare_owner.rs`, `asset_session_store_preflight.rs`,
  `asset_session_store_prepare.rs`. Narrow agent arms call existing material/
  currentness/budget/GO helpers; no provider/core/body changes.
* Neutral constructor fields only in `saved_command_agent_android_build.rs`,
  `saved_command_agent_ios_archive.rs`, `saved_command_agent_local_checks.rs`
  and `saved_command_owner_tests.rs`, `offline_preflight_owner_tests.rs`,
  `android_build_wiring_tests.rs`, `asset_session_installation_memory.rs`;
  no new authority in those old fixtures. The four inline DocumentState
  initializers and the three external test initializers retain every existing
  peer field and add only the neutral Store grant.
* Three main-window commands/permissions: `build.rs`, `capabilities/main.json`.
* CLI reachability: `installed_cli.rs` (parser dispatch/help only; static
  capabilities must not claim a grant or runtime check).
* Renderer: `types.ts`, `bridge.ts`, `App.tsx`, existing two Store components
  and controllers for optional control/reciprocal pending/unknown gates;
  `package.json` only the selected test entry. Original Store result grammar,
  ordinary consent and status/Cancel remain unchanged.

No packaging/workflow, native primitive, runtime eligibility, Python/Fastlane,
Execute/Reconcile, service binary or credential-owner changes.

## 6. Meaningful validation, not provider/native qualification

Focused evidence for the frozen packet, not provider/native qualification:

* **27 Rust cases authored, unrun**:14 in `service_store_requests::tests`,10 in
  `saved_command_owner::agent_store::tests`,3 in `installed_cli::store::tests`.
  They use bounded DATA, real Mutex/Arc/watch, unentered Saved/Runtime
  constructors and original parsers; no filesystem/Store/provider/process
  execution. All9 owned Rust files and23 Rust parent projections were syntax
  parsed only. Root must compile the actual library/CLI/observer graphs.
* **18 new inert Node cases passed**,377.102ms. The last actual-two-controller
  case was then strengthened to exercise failed raw Allow as well as reentrant
  Revoke for both kinds: that exact selected case passed343.170ms. The unchanged
  remainder's prior evidence is reused, not reported as a fresh full rerun.
* **23 affected old Store controller cases passed**,1.265s (8 basic-access,
  15 candidate-prepare), no unrelated old suite.
* **Full composed strict TypeScript noEmit passed**,19.649s, heap768MiB,
  minimum available memory7,654,048KiB, guard not triggered. The original
  caller joined; its own dependency link and public source projection were
  removed. The first check failed only because seven existing public JSON
  imports were omitted from the projection; that failure is retained.
* Initial new Node results12/3 then14/1 remain recorded: one genuine missing
  immutable-copy freeze was fixed, alongside two test-fixture comparison
  mistakes. No failure was relabeled as a pass. No new dependency install.
* Distinct source review found one native lifetime omission before execution:
  Store's old-read expiry/renewal was not scheduled by the Saved watchdog.
  The narrow endpoint/control-slot successor and two new DATA cases above
  correct that source gap; no actual native run is claimed.

The test bodies cover:

* Strict RAW/CLI/response table: unknown keys, duplicate fields, wrong kind,
  query/Both/later-stage, omitted nullable, wrong IDs, overbounds, private
  path/credential/provider fields, and never a silent CLI replay.
* Original Saved facet guards: exact same Entry/witness and one consumption,
  unsupported contexts and missing material refuse, early actual-callback DATA
  survives a late relay. These inert tests do not claim native material/GO.
* One-use/reconnect/STOP inbox tests: wrong Read/Doc refuses, same request does
  not resubmit, final DATA survives a later queued request, first STOP is not
  renewed, and unknown claims/history remain fenced. The two-phase actual
  Doc/material/Service integration is source-reviewed, not executed here.
* Two actual-method, unentered Saved DATA regressions exercise the immutable
  Read endpoint and old-facet renewal while relay/worker are quiet, continued
  sampling after STOP, earlier-F cleanup tightening and retained Unknown.
  They construct no runtime task, timer, native admission or retirement.
* Retirement mapper tests: terminal-shaped DATA before original callback is
  pending, late close/retirement/history uncertainty cannot become complete;
  only existing validated findings/intent redactions pass. No new live provider
  fixture, generated native receipt or qualification bypass.
* One React-free controller suite: explicit Allow only; stale review, changed
  context, lost Allow/Submit/status, late native completion, failed revoke,
  absorbing Unknown and retained original Check/Stop; no automatic Start or
  refreshed observation, and existing Store controls remain reachable.
* Checked census boundary/overflow/full32+eightIPC/retained-original cases.

Evidence and exact selector/source pins are in `.task-store-cli/results`;
the final manifest pins all15 owned paths plus32 before/after parents. Root
must compose narrow hunks with its ongoing device-auth/capability/census work,
not overwrite current shared files. Shipping/default/headless request policy
and all native availability gates are unchanged.

Source support is not installed execution evidence. Actual Mac Store runtime,
credential assignment/persistence, candidate/history and original native gates
must already be valid; Linux/data tests cannot make them available. A future
installed credential-free transcript journey would need separate reviewed
observer seams; it is not part of this small delivery or an excuse to enable
live providers now.
