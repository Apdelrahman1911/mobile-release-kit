# Installed CLI: one explicitly approved iOS archive

Source slice only. Existing macOS/native eligibility is unchanged; nothing here
qualifies Xcode, an archive, signing, or installed IPC execution.

## Closed scope and original ownership

- `ios-archive-prepare PROJECT_ID OBSERVATION_REVISION [--json]`
- `ios-archive-start PROJECT_ID SERVICE_INSTANCE REQUEST_ID OPERATION_ID OWNER_GENERATION [--json]`
- `ios-archive-status PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]`
- `ios-archive-cancel PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]`

These fixed verbs use the existing authenticated local socket, running Desktop,
live project read grant, and a **separate default-off one-use** Desktop approval
(`agent-saved-ios-unsigned-archive-v1`). Read access alone cannot prepare/start.
The real main Webview grants only its exact returned saved config/version,
Document, registered root, edit stamp and observation. No path, tool, material,
window, native ID or executable comes from CLI arguments.

The first view explains Allow / Stop / Refresh, the maximum 15-minute START
window, no MRK signing credentials or Store permission, and project-script
program/file/network/signing risks. Technical IDs/CLI details are collapsed.
Unsigned is the MRK operation scope, **not a sandbox or a promise that arbitrary
project scripts cannot sign**. It does not create candidate inputs or an IPA.

`agent_build_requests.rs` extracts Android's existing memory bookkeeping into
one closed AndroidInspect/IosArchive inbox: **one grant, 32 total permanent
per-launch tombstones, one occupied request**. Explicit Allow can replace the
other family's *unused* grant; Refresh/Status cannot. Any occupied or unconfirmed
original blocks both families. Family is checked before claim/query/cancel,
native binding, shared Start and typed public conversion; native projection keeps
its closed family tag. Android public requests/results remain unchanged.

`SavedCommandOwner` retains its **single** optional build link through the same
Prepared → Session, watchdog, STOP and original final callbacks. A closed router
chooses the existing Android facet or the iOS facet. There is no second owner,
process runner, observer, timer, input reader, service, journal or filesystem
writer. The iOS facet calls the original IOSArchive Prepare/Start. GUI Start
cannot consume agent Prepared, even with matching public IDs and ordinary GUI
consent. Start uses the original pre-take guard; GO is released after Doc/Edit
are dropped. All peers/currentness/native availability checks remain in place.

The original returned saved-input lane supplies iOS comparison directly (no
fake Android request/catalogue). Host/service/store calls are outside Doc/Edit;
bounded inbox/registry comparison is memory-only inside those guards. The same
Projects writer makes the old observation stale before possible build effects.
No vault or Store/provider action is introduced. The existing single 4MiB
Document backing reservation covers the shared inbox, reports/claims/copies and
two small fixed comparison grants; it is not doubled or called an RSS bound.

## Correlation, expiry, shutdown

Prepare obtains genuine original IDs before Prepared is published, without GO.
CLI prints and flushes its stable request correlation **before** sending Prepare
or Start. Unknown/lost replies say do not replay and give exact Status/Cancel
commands. Reconnect can inspect the same request, never requeue or reset it.
Caller/host restart cannot reconstruct permission, originals or native finality.

The 15 minutes is START authorization, limited further by the existing Prepared
expiry. Prepare/Status never renew it. The first Start timestamp is retained;
iOS keeps the original **5400/5410** work/hard clock, Android its original
3000/3010. Revocation, invalidation, relay loss and quit request original STOP.
Native Unknown absorbs; history, weak-reference loss or process replies cannot
clear it. Final history drain runs only after the same relay and original domain
owners join, before Host close. Shared history is optional acknowledged DATA,
not the native settlement source.

The existing iOS controller observes an agent origin and offers STOP only after
any prior original settles and every original GUI Prepare/Start promise returns.
A terminal event cannot drop a still-pending GUI invocation or mint GUI consent.
The retained deferred observation is bounded to one original identity.

The CLI report copies only actual unsigned result counts and saved comparisons:
entries and bytes. **The existing archive result has no digest**; none is
invented. Paths, scheme/container, Bundle ID, certificate and signing data are
not projected into it.

## Root composition

Apply `agent-ios-archive-hooks-20261020.patch` after the new leaves. Its 36 exact
shared paths include:

- Existing service, Android extraction adapters, SavedCommand link/router hooks,
  original IOS owner and saved-input comparison, shell relay/final drain.
- Exactly three main/local GUI permission commands + generated capability list.
- Library, thin CLI and installed observer declarations; fixed CLI verbs/help.
- Existing iOS projection/controller/API/App; Android permission UI bookkeeping
  extraction and simpler text; one new Node test in the existing package roster.
- Mechanical `agent_build: None` or `agent_ios_archive: None` updates to existing
  original fixtures (including offline-preflight and Mac observer fixtures).

Most before sources are base `64205ef9`; the Android facet before source includes
Root's `4894c761` explicit `serde_json::Value` fix, and the package roster was
refreshed from current Root without removing its added tests. Exact current-Root
apply-check passed. All shared edits are an unapplied packet, not lane edits.

## Focused evidence and limits

**150/150 Node tests passed**, one joined command, 0 skipped (1.060s): new 9
`agent-ios-archive`, existing 95 Android, 37 iOS archive and 9 signing-reuse cases.
Executed actual TS modules in a task-owned source projection, no stubs/installs.
Initial new fixture assumed draft revision zero; corrected to compare the actual
saved snapshot revision. Initial broader projection missed one current literal
import; copied that exact public dependency. Both failed runs remain in task logs.

**16 new Rust tests authored, UNRUN**. Root should run these actual library paths:

- `agent_build_requests::tests` (6): cross-family refusal, shared grant/limit,
  one-use Start, lost ACK/Unknown, exact no-digest report bounds.
- `saved_command_owner::agent_ios_archive::tests` (5): closed mode, real shared
  pre-take Start refusal, original retirement, typed native origin, real protocol
  result redaction. Runtime forced unqualified; no native execution.
- `asset_session::agent_ios_archive::tests` (2): dormant/foreign document and
  closed consent; no host opening or filesystem execution.
- `application_service::agent_ios_archive::tests` (1): existing small private
  Store fixture + actual service grant/reconnect/cross-family/revocation paths.
- `installed_cli::ios_archive::tests` (2): finite verbs and lost-ACK/frame bounds.

Also rerun the **23 affected Android tests** in `agent_android_build::tests`,
`application_service::agent_android_build::tests`,
`asset_session::agent_android_build::tests`,
`saved_command_owner::agent_android_build::tests`,
`installed_cli::android_build::tests`, and the existing static CLI capabilities
test. No replacement harness. Rust syntax-only parsing passed; it is not a
compiler/test result. Root still owns actual full graph/TS/App/thin-CLI compile
and separately approved installed/native testing. Manual safe-project runbook
can reuse the previous original IPC procedure with these fixed iOS verbs and
real Desktop approval; it remains unverified, not a new automated fixture.
