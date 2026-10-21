# Installed CLI: existing Store Execute / Reconcile delegation

PLAN ONLY. Base `5e061ca34d984daed17a20cfe56e25c01a07a142`, isolated
`store-release-cli` / `task/automation-store-release-cli-20261021`.
Project is the independent plan reviewer; Root authorizes implementation only
after acceptance. No provider, native, build, installer or workflow action.

## 1. Deliverable and exact existing modes

Extend the **same** reviewed Store permission/inbox/CLI family. The user first
obtains the existing Desktop native Prepared review, then separately allows a
local CLI to start that exact original once. CLI cannot construct or prepare
another action. No new release engine, journal, transport, binary or owner.

| New kind / closed mode | Platforms | Existing effect / required warning |
| --- | --- | --- |
| `execute` / `candidate-upload` | Android, iOS | Upload the existing validated signed AAB and commit the internal Play release, or upload the existing signed IPA for TestFlight internal processing. No rebuilding/re-signing or public release. |
| `execute` / `external-testing` | Android, iOS | Execute the already-prepared promotion using the original binary and exact destination. Preserve existing tester-availability versus Apple review-state distinctions. |
| `execute` / `production-submit` | Android, iOS | Execute the already-prepared production draft / App Store submission. Draft, submitted, in-review, approved and pending manual release are not public availability. |
| `reconcile` / `current-internal` | Android, iOS | Observe the exact previous internal target/build. Play uses its temporary uncommitted edit and cleanup; this is not a zero-write claim. No upload/resend, repair or prior-finality proof. |
| `reconcile` / `recovery-settlement` | Android only | Existing check plus one explicit local recovery checkpoint. Preserve old files/journal/Keychain evidence; cannot clear a live unknown owner or authorize a retry. |
| `reconcile` / `external-readiness` | iOS only | Existing external TestFlight target readback plus separate local readiness record. No upload, notification or resubmission; not earlier execution finality. |

These modes already share `LocalStoreExecuteOwner` or
`LocalStoreReconcileOwner`, `SelectedStoreMaterial`, Saved Prepared/Session,
and mode-specific native consent. Excluding them would create a needless
second identical delegation round. Unsupported cross-platform/mixed modes
refuse. Existing `access-check` and `candidate-prepare` remain byte/behavior
compatible, including basic-only access and CandidatePrepare `later=None`.

Actual source anchors:

* `asset_session_store_{execute,reconcile}.rs`: exact original material and
  saved/root checks; Execute's borrowed `ExecuteMemoryAdmission`; GO after Doc.
* `asset_session_store_material.rs`: `execute_document_matches`,
  `reconcile_document_matches`, original credential/tool/supplemental loans,
  `accepts_execute_consent`, `reconcile_accepts_consent`, and existing native
  history/helper claims. No new private-material constructor or copied loan.
* `local_store_{execute,reconcile}_protocol.rs`: `Context::consent`, `later`,
  `settling`, `refreshing`, full terminal/result validation and original modes.
* `saved_command_agent_store.rs` and `saved_command_owner.rs`: original weak
  Approval/witness, same Prepared/Session link, `start_bound_requests_store`,
  immutable READ-end watchdog, native retirement and no-replay tombstones.
* `asset_session_agent_store.rs`, `service_store_requests.rs`,
  `service_store_application.rs`: same main-window Allow, service/read facet,
  off-Doc saved observation consumption, original relay and history return.

## 2. Closed public contract and scope separation

Keep existing three main-window RAW commands and their 1KiB input limit:
`agent_store_access`, `allow_agent_store`, `revoke_agent_store`. Keep the same
three bundled CLI commands and Submit/Query fields unchanged:

```
mrk store-submit PROJECT INSTANCE GRANT REVIEW --reviewed [--json]
mrk store-status PROJECT INSTANCE REQUEST [--json]
mrk store-cancel PROJECT INSTANCE REQUEST [--json]
```

The opaque grant/review selects exactly one retained native action. Neither
CLI strings, the service `Action::Release` history label nor an old access /
prepare grant can select an Execute/Reconcile mode. Submit still emits its new
request ID before its sole send; lost reply means check/cancel **that** ID.
No CLI paths, credentials, assignment IDs, draft, arbitrary target or raw
material. No automatic Prepare, renewal, re-Allow, resend or recovery.

Add `Kind::{Execute,Reconcile}`. Old Review fields/serialization remain exact.
Only new kinds require a closed `release` field derived from actual Context:

* `mode`: exactly one table value above;
* `intentSha256`: exact retained intent digest;
* `stageOperationId`: required nullable, populated only for existing later
  Execute or external-readiness;
* `basis`: required nullable `{operationId,receiptSha256}`, matching the
  native later predecessor or readiness execution receipt when present.

Existing Review candidate UUID/digest, saved config/version, original native
operation/generation/status revision remain required. Native Scope/Approval
still compares the **full original Context**, material identity, registration,
physical root, edit stamp and epoch, including private supplemental assignments
and actual tool selection. These small public fields are comparison DATA only.

New fixed one-use consent is `agent-<platform>-store-<kind>-<mode>-once-v1`;
native derives the expected string from its original Review, not request mode.
Old consent strings stay unchanged. The separate original native Start token
is obtained from `c.consent()` and checked against the **same material**.

New report variants project only validated result metadata: exact mode,
candidate/intent/receipt/lineage digests and operation IDs, bounded checkpoint
sequence, a closed **semantic target label**, accepted/reconciled/ready result
and applicable fixed Store state. The label is not an actual channel name:
Android external testing uses the exact configured bounded track accepted by
`stage_android_destination`, including custom names such as `qa-beta`; never
coerce it to an invented `external-testing` channel. The full native config,
Context and validated receipt retain that exact track, and the public text
says "configured external-testing track". Preserve internal/external/draft/review/manual-release
distinctions and fixed limitations. Do not print authorization/credential IDs,
raw provider errors, material, paths, contact data or raw receipts/journal.
Unknown/noncomplete native results expose no fabricated positive receipt.

## 3. Actual original admission, consent and clocks

One global Store grant and one finite inbox across **all four kinds**; no new
Doc grant/registry/permission controller. Existing main-window Allow ordering
and pre-off-Doc revoke epoch apply unchanged. Full original weak witness and
material are rematched after service IO; old pending/unknown/unreturned Allow
or Entry blocks replacement. Decoded equal IDs never replace the original.

The retained service relay attaches Entry before possibly blocking IO, consumes
the SAME service saved observation off Doc, then re-enters the original Doc /
saved edit guard and rechecks the exact native project, stamp, epoch, Prepared,
credentials, candidate/history/provenance and mode. No Host or Store IO under
Doc. Native history/helper admission rechecks the original local state again.

Add only closed release dispatch helpers inside the existing agent Store facet:

* Execute reuses `recheck_store_execute_material` and `store_execute_budget`.
  The same locked Doc/material supplies its borrowed `ExecuteMemoryAdmission`;
  `start_agent_store_release` verifies full linked Context and
  `material.accepts_execute_consent(execute::start(...c.consent()))`, then
  passes **Some(original budget)** into `start_bound_requests_store`.
* Reconcile reuses `recheck_store_reconcile_material`,
  `store_reconcile_budget`, exact valid mode and
  `material.reconcile_accepts_consent(c.consent())`, passing no Execute budget.
* The existing common start checks exact Entry/link before Prepared.take,
  consumes once, retains it in the same Session and releases GO only after
  Doc/Edit/registry guards are dropped. Ordinary GUI Start cannot consume an
  agent-linked Prepared. No "generic agent Start" bypass of native consent.

Prepared's 300s expiry remains admission-only. Original Submit T is captured
before service lock/queue and remains the existing 1200s work /1210s hard clock.
Same immutable READ end and Store-only existing watchdog sampling enforce
expiry/revocation even with quiet worker or blocked relay; an earlier retained
revoke can tighten first F after STOP. No reset, new task or new clock.

## 4. Completion, recovery, UI and retained capacity

Keep the exact existing three-way known-terminal cut: **relay/claim returned,
same Saved original positively retired, and service history publish returned**,
in either order. Child terminal/report, local checkpoint, current target match
or a newer event is not a substitute. Unknown stays absorbing; same-ID status
and Stop remain usable. Reconcile/settlement cannot bypass a still-live unknown
Execute owner or unresolved shared request. Fresh explicit recovery after
restart uses the existing native review of retained evidence, never replays.

Extend the one mounted `AgentStoreAccessController` to show the existing four
native review sources. Add exact Execute/Reconcile Attempt delegation matching
the already-reviewed Preflight/Prepare handoff: original Prepare promise must
have returned; no pending/read/unknown/historical source; set only the monotone
delegated flag; clear GUI60s consent/Start and tab-hide cancellation for that
exact original. Never set `started`. After synchronous listeners, recheck the
private Attempt/API/context/epoch/revoke/peer pin before the sole RAW Allow.
Failure/loss never restores its timer or reusable consent. Original Check,
Cancel, context invalidation and Quit remain available. Other GUI controls
cannot replace the shared permission, even when another panel is displayed.

The current App peer predicate includes Execute/Reconcile's own awaiting-
consent owners. Exempt **only the exact selected, genuinely returned Prepared
Attempt** while that same original is being delegated, not either whole kind
or all awaiting-consent owners. Its private pin survives clearing selectable
GUI consent; it never becomes another reusable review or status-derived
authority. Every other/pending/reading/running/unknown/conflicting original
still blocks Allow. App reads the existing early-declared controller refs
(initially null), never later Execute/Reconcile `const`s during the shared
controller constructor's synchronous `syncContext`. Recheck the exact pin
and all remaining peers after synchronous delegation listeners before Allow.

The permission card explicitly displays the selected mode/target and its
mutating/checkpoint warning before a fresh checkbox. Existing native panel
review/credentials/history/recovery remains intact; no background operation.

Reuse current **2MiB** Store DATA reservation,32 rows and8 IPC workers; no cap
or Doc allowance increase. New compact review/report still fit the existing
8KiB per-copy quote; sole current full Context/tool-selection copies fit the
already charged grant/relay allowance. Keep both bounded64KiB native-result
conversions and all32 history/latest copies charged. Add worst-valid mode /
serialization/copy-bound tests and source-backed size table; if arithmetic
does not fit, report before changing a bound. Do not infer headroom from
retirement or omit existing owners. Old ordinary native resource quotes remain.

## 5. Minimal ownership and Root-only hooks

New authored leaves (private extensions, not separate owners):

* `desktop/src-tauri/src/service_store_release_protocol.rs`: closed mode,
  lineage, report/consent helpers under existing Store protocol.
* `desktop/src-tauri/src/saved_command_agent_store_release.rs`: full Context /
  material/consent checks and original Start/report extension.
* `desktop/src-tauri/src/asset_session_agent_store_release.rs`: existing
  Execute/Reconcile owner/gate/material/budget dispatch only.
* `desktop/src/agentStoreRelease.ts`: bounded mode/review/result/consent mapping
  and effect text; no new permission controller or native port.
* Focused Rust release protocol/original-facet tests, one Node release test
  file, this guide and exact Root integration patch.

Root-only hooks against this exact base: existing
`service_store_protocol.rs`, `saved_command_agent_store.rs`,
`asset_session_agent_store.rs`; Execute/Reconcile typed owner accessors and
budget visibility; existing CLI/capability help only where text falsely says
these modes are unsupported; `agentStoreAccess.ts`, its one controller/card,
`localStoreExecute.ts`, `localStoreReconcile.ts`, their existing components,
`App.tsx`, and package test roster. No new endpoint, shell relay, process,
Store namespace, Document field or native/runtime/qualification flag. New
helpers are private modules/includes in those existing parents; Root composes
all hooks, never replaces its current files wholesale.

## 6. Meaningful bounded tests and handoff

* Actual closed parser/table: all10 valid platform/mode pairs; invalid mixed
  readiness/settlement/stage, old-kind release field, wrong lineage/digest/
  receipt/state and each cross-mode consent refuse. Old two Review bytes stay.
* Actual Scope/Entry and Saved helper methods: old access/prepare or wrong
  Prepared/material witness cannot start either new kind; exact Execute needs
  same borrowed budget and consent, Reconcile cannot consume Execute budget or
  generic consent. All callback-order permutations still require the three
  returns; cancellation/expiry/earlier READ revoke, stale context, duplicate
  Submit, history failure and unknown original retain the fence. Inert only.
* Result redaction tests use genuine already-validated terminal variants for
  candidate/later Execute, plain/settling/readiness Reconcile. Injected private
  fields/provider text cannot enter public output; state/limitations preserved.
  A valid custom Android external track remains native-bound while the public
  summary is explicitly semantic; no fabricated/coerced track is reported.
* Real existing frontend controllers with fake ports/timers: full mode/consent
  selection, delegation only after original Prepare return, actual one Allow,
  timer/hide versus ordinary cancellation, callback reentry/revoke/context
  race, failed/lost Allow nonrearm, cross-panel original status and Stop, exact
  selected returned Prepared can actually Allow while a conflicting peer
  refuses (including after delegation removed selectable consent), safe early
  ref initialization, no
  automatic Execute/Reconcile/renew/retry. Worst-valid DATA under current caps.
* CLI existing output/request helpers accept bounded new result variants but
  still send only tokens, print request before sole send and retain no-replay.

No provider/shell/Git/native execution in tests. Focused Node and composed
strict TypeScript only under Root resource coordination; Rust source parsing
locally, actual graph/tests in Root's later batch. Distinct implementation
reviewer must differ from Project. Current native/installer work is independent;
neither source/test success nor grants enable an unqualified native runtime.
