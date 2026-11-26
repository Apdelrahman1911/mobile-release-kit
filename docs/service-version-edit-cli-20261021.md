# Installed CLI: save an already reviewed release version

## Scope

Desktop still Opens the saved version source, keeps the two-value draft, and
Prepares its existing complete file comparison. The normal Save remains the
default. The collapsed **Advanced: allow installed CLI to save this review**
section lets a user explicitly allow one exact prepared Save. A current Desktop
READ allowance is also required.

```
mrk version-edit-submit PROJECT_ID SERVICE_INSTANCE GRANT_ID SESSION_ID PLAN_TOKEN --reviewed [--json]
mrk version-edit-status PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]
mrk version-edit-cancel PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]
```

The first command prints its immutable instance/request IDs before the original
IPC call. Preserve them after a lost response; inspect/cancel that original, not
a replacement Submit. Cancel does not undo a submitted Save. An expired,
withdrawn or spent allowance cannot be renewed on that same native Prepared.

Both manual values and a genuine reserved version are supported by the same
existing editor. A reserved candidate reaches this route only through the real
consume-once Reserve→Edit handoff (including ordered Both/schema4), never from
its public scalar result. This route neither allocates again nor changes the
candidate, Store witness, source binding or original publication chain.

This is **Prepared→Apply delegation, not full CLI version parity**. CLI-driven
Open/draft/Prepare, enrollment, hosted-result import and saved-text recovery are
not added. No source path, version values, credential token or native proof is
accepted from the CLI. `PLAN_TOKEN` is the original edit-plan comparison ID, not
a credential. No Git commit, workflow dispatch, build or Store action is added.
The existing Play-cleanup discovery family is preserved; these three commands
do not perform Play cleanup.

## Original custody, consent and finality

* One native Session `OnceLock` holds the exact already-Prepared lease, original
  project/root/registration comparison, old READ facet and original review end.
  The original weak application-service identity remains required. One Inbox
  retains at most 32 immutable request rows and 32 revoked-nonce tombstones; no
  row contains a Session, full config or full version-file view.
* Native lease installation precedes public Allow. Submit permanently links the
  Entry to that same lease before notification. A same-ID/same-body retry reads
  the original; changed IDs/body cannot consume the allowance again. Native
  final/Unknown publication seals that same lease against late Submit.
* A GUI Save winning before Submit spends the unused lease. Later revocation or
  expiry of that unused READ/allowance must not STOP the ordinary GUI winner.
  Only an actually claimed delegated Entry supplies the new cancellation cut.
* The real main Webview handles the closed RAW-only agent variant of the
  **existing** `release_version_edit_apply`. Same-origin checks and losing
  duplicates return before any publisher or common retirement error tail. The
  successful private claim then uses the existing registered publisher, source,
  writer, journals, native jobs and final observer. Ordinary JSON Apply and
  recovery contracts are not widened.
* Original READ expiry/revocation and explicit STOP feed the same EditOwner
  watchdog/minimum first-failure instant, even without the renderer/relay. Known
  cleanup also polls that claimed old READ facet at <=100ms, so a later facet
  replacement can publish its earlier original revoke instant. The original
  soft/hard cutoffs remain absolute; Unknown and unused GUI allowances get no new
  poll or deadline. The
  existing 30-second phase/15-minute review and 8–10-second cleanup rules stay;
  reserved work remains additionally clamped by its original control. No new
  runtime, timer, executor or cleanup authority exists here.
* Synchronous subscriber, navigation, peer and save-boundary changes are checked
  before actual Apply invocation. A claimed request refused there still retains
  its Entry and original STOP/finality obligation. The small UI facet holds the
  **actual API Promise** and exact native final independently. An event, `.apply()`
  boolean, CLI status or later unrelated `last` cannot substitute either return.
* Native compact result comes only from the original final observer after its
  original retirement cuts. Unknown/lost joins remain Unknown. Existing draft
  adoption keeps newer/dirty drafts; no remote response supplies a new draft.

## Bounded accounting

Existing 4KiB IPC input, 64KiB response and eight-client limits remain. The new
closed request is <=1KiB before strict RAW parsing; compact status is <=8KiB.
Source text is not copied into CLI replies. The additional fixed Inbox/IPC
backing is explicitly debited in the real whole-Document census.

Admission uses the unchanged 64MiB shared-state bound: real Document backing
plus the existing installation-memory additional census (returned saved
observations, evidence, maintenance and control cells), then borrowed actual
Edit registry/active/last capacities and its remaining
future. No old last, private submission, reserved handoff, material metadata or
source debit is discarded. Release-version projections include the two possible
whole-Status clones. Other-domain last data remains retained and charged.
The existing borrowed heap visitor is reused; it does not clone or serialize.

The additional future is **34,144,256 bytes**:
`2*20_000*512 + 4*2MiB + 2*16KiB + 2*2MiB + 1MiB`.
Opened+Prepared consume two of the original three TOTAL frames. An invalid third
Prepared is still decoded before sequence rejection, so its Seed plus typed
nested Value/string backing is reserved, not just an expected small terminal.
The actual fixed version encoder bounds command+writer at 16KiB each. All adds
and borrowed growth are checked. This is named backing accounting, not RSS.
The real default-Document, retained-buffer and overbound regressions are authored
but Rust-unrun; source-fit must still be confirmed by Root's actual compiled test.

## Packet and composition

Author worktree: `automation-20261019/version-editor-cli`, base
`9a2cfc323730874f2ac02c81c5d3afa1c23b7088`.
Eleven new source/test leaves plus this guide and
`docs/service-version-edit-cli-hooks-20261021.patch` form the owned packet.
The 25 modified shared files in the author worktree are **test copies only** and
must not be cherry-picked wholesale.

The detached patch is composed against Root
`76c62c5223683c72d35e2df997694557cf7c1fb7`.
It preserves the integrated counter and Apple additions. Only ordinary hook
unions were needed: package test list, Service fields/init/dispatch/fences,
protocol rows and request catalogue. Root reserved **VersionEdit namespace8**,
after Apple7: nine 32-row metadata namespaces plus 64 detailed rows = **352**;
the existing 64KiB output limit is unchanged. The two actual full-catalogue tests
and existing capability assertion include both families. No new catalogue owner.

Complete before/after/author-base/author-after images and pins are under
`.task-version-editor-cli/hooks/`; frozen manifest and exact staged diff are in
`.task-version-editor-cli/`. The patch also contains the original-controller test
additions and all lib/CLI/observer/main-window closed command declarations.

## Actual evidence and remaining qualification

* **54 Node tests passed, zero failed/skipped**, 1.3376s:
  `.task-version-editor-cli/node-final.log`, original caller 83504 joined0.
  These are the existing release-version editor suite plus the new fixed facet
  suite: 43 unchanged tests and 11 new grouped regressions. They exercise real
  controller Reserve/manual→review→delegation, explicit Save, event-before-call
  return, lost ACK, coalesced old final, newer drafts, GUI winner, old API retention,
  synchronous reentrancy and closed/bounded protocol; native responses are inert
  fixture data, not real receipts.
* Whole authored composed frontend **TypeScript noEmit passed**, 21.778s,
  caller55010 joined0; `typescript-v1.json` and source hashes retained. It used the
  existing original `run_owned`, one networkless Node/tsc process, 768MiB heap,
  90s/256KiB output limits and existing dependencies. Actual imported JSON resources
  were included. Its task-only projection/link were removed after joined return;
  shared dependencies were untouched. This was not a nonroot run. No second TS run
  was performed for the later literal Root/Apple hook union; Root owns that check.
* Seven owned Rust format/syntax checks and 18 composed shared Rust syntax parses
  passed; JSON/whitespace/apply checks are source checks, **not compilation**.
* **19 new Rust tests AUTHORED / UNRUN**. Exact filters, source lines, hashes and
  effects are in `.task-version-editor-cli/rust-selectors.txt` and
  `rust-selector-source.json`. Eighteen are DATA/unentered-original only. One
  uses the existing real private Service/Store fixture, no socket/process/provider.
  It does not mint a Prepared, lease or NativeUse. No tests forge joined finality.

| New test module prefix | Count |
| --- | ---: |
| `service_version_edit_protocol::tests` | 2 |
| `service_version_edit_requests::tests` | 9 |
| `application_service::agent_version_edit::tests` | 1 |
| `edit_owner::agent_version_edit::tests` | 2 |
| `asset_session::agent_version_edit::tests` | 2 |
| `installed_cli::version_edit::tests` | 3 |

The distinct source review found two real omissions, corrected in the narrow
successor: the additional Document census above and polling the old READ facet
through known cleanup. The real-D regression retains an actual evidence-buffer
allocation invisible to the old lookup census, proves the old omitted-extra sum
would fit while the complete sum refuses, and keeps all original buffers. The
new actual Lease endpoint/READ test preserves earliest F without a relay wake or
forged native Session/join. Previous freeze and correction diff are retained in
`.task-version-editor-cli/review-v1/` and `review-correction.patch`. No Node/TS
source changed and no suite was rerun for these native-only corrections.

Also affected (not run here): existing two `service_request_catalogue::tests`
maximum/namespace/privacy cases and
`installed_cli::tests::requests_is_discovery_only_and_rejects_action_parameters_and_foreign_instance`.
No Cargo, native execution, Store/GitHub call, credentials, build, signing, CI or
provider qualification was performed. The inherited native qualification gates
are unchanged. Independent implementation review is required separately from the
Credentials-accepted plan; Root owns actual combined compilation and native gates.
