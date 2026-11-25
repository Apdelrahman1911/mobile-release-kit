# One Desktop-approved CLI Android build

## Scope and original owners

This slice adds four installed-client verbs, not another engine:

```
mrk android-build-prepare PROJECT_ID OBSERVATION_REVISION [--json]
mrk android-build-start PROJECT_ID SERVICE_INSTANCE REQUEST_ID OPERATION_ID OWNER_GENERATION [--json]
mrk android-build-status PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]
mrk android-build-cancel PROJECT_ID SERVICE_INSTANCE REQUEST_ID [--json]
```

It uses the existing `AndroidBuildInspect` / `StructureAndVersion` owner and
worker. It supplies no signing material, upload-signature selection, candidate
retention, Store operation or installer. **Project Gradle/configured code can
execute programs, read/write files, use the network and sign through its own
configuration. This is not an unsigned guarantee, offline sandbox or readiness
check.** Existing runtime/tool qualification remains mandatory and unchanged.

The ordinary Desktop saved-input reader and protected tool catalogue must
already have returned. The real main WebView can approve one START for exactly
that saved configuration, version and selected catalogue original. The approval
holds the actual saved binding/edit stamp and a weak comparison to the original
catalogue Selection, not a second reader or native resource owner. The UI derives
its request from the same Android controller; native code independently rematches
the full original document, root, generation, saved inputs and selected tools.

The permission defaults off and is separate from read access and local-check
permission. It lasts at most 15 minutes to START. Prepare does not renew it; the
ordinary prepared intent still expires after five minutes. After the actual
common Start consumes the permission, the original native 3000/3010-second
work/finality clocks remain unchanged. Explicit execution Revoke, cancellation,
document loss or input/catalogue drift use the original first-STOP and cleanup.

## Lifecycle and no replay

- UID/capability authentication and current project read scope are the existing
  socket owners. Their guard stays held through each bounded memory Inbox call.
  A read grant alone can never submit Prepare or authorize Start.
- Prepare prints the client-generated instance/request correlation **before any
  possible action send**. It consumes the one request slot/permission, then the
  existing retained relay calls the original Prepare. Native operation/generation
  IDs bind the same Entry before the original Prepared is published. No GO occurs.
- Start is a separate explicit verb for those exact IDs. It retains first Start T
  before relay/Doc/IO, claims once, marks the former saved observation stale using
  the existing Projects writer off Doc/Edit, and rematches all originals. The
  shared original Start checks the same Entry/context before Prepared.take. Even
  matching public IDs and ordinary GUI consent cannot adopt an agent Prepared.
  The same admitted GO is released only after Doc/Edit guards drop.
- The Inbox keeps 32 non-evicted per-launch requests and one occupied operation.
  Reconnect and duplicate same-body messages return the same request, never another
  preparation/Start. Changed bodies/IDs fail. Lost IPC replies, errors after native
  binding, abandoned admission claims and disappearing weak links are not replay
  permission or evidence of settlement. A new Desktop instance cannot adopt them.
- The native-only `agentAndroidBuild` GUI marker permits observation and exact
  STOP, not reconstructed GUI Start consent. A different operation is adopted only
  after the prior native original is terminal and every original GUI Prepare/Start
  invocation has returned. Unknown originals cannot be replaced by new DTOs.
- Prepared retirement and the original active-to-last callback publish DATA into
  the same Entry. Only actual native retirement permits settled results; worker
  terminal shape, status reads, history writes and socket exit do not. Native
  Unknown remains absorbing. Grant expiry/revoke never disables original cleanup.
- The same retained relay publishes redacted `Action::Build` history off owner/Doc
  locks. Latest and claimed revisions remain distinct. Failed/unreturned history
  writes fence shared reads and never alter the core's actual outcome. Final drain
  runs after original domain owners and that relay joined, before Host close.

Reports preserve closed finding/count codes and historical artifact size/SHA256.
No configuration path/content, native application identifiers, commands, tool
paths, artifact filename or credential material is projected in the report.
The envelope keeps the stable project/request/operation IDs. Completion can contain FAIL
findings and never means PASS, source freshness, signing approval or release ready.

## Integration packet

New leaves: `agent_android_build{,_tests}.rs`,
`application_service_agent_android_build.rs`,
`asset_session_agent_android_build.rs`, `saved_command_agent_android_build.rs`,
`installed_cli_android_build.rs`, `agentAndroidBuild.ts`,
`agentAndroidBuildOrigin.ts`, `components/AgentAndroidBuildAccess.tsx`, and one
Node test file. No existing file is edited in this lane.

`agent-android-build-hooks-20261020.patch` contains 27 Root-only shared hooks:
protocol/service; existing owner/wrapper and inert initializer fields; Doc census
and same relay/exit hooks; three genuine main-WebView RAW commands and their
exact build/capability permissions; library/thin-client/installed-observer module
declarations; the existing controller/protocol/UI/bridge and static CLI help.
All ordinary non-agent paths pass `None` through the shared owner methods.

The patch is based on `f812a5d0`; only the package test-list before-image uses
Root `9a723876` to preserve later test registrations. It applies to that current
Root tree. The 4MiB fixed additional document backing covers the finite 32
scope/request/latest/claimed records, current approval, eight existing IPC
copies and redaction scratch. It is an explicit existing-census charge, not an
RSS estimate or an expansion of the document quota. No new state namespace,
job framework, task/runner, listener, reader or native availability flag is added.

## Checks and remaining qualification

- 15 new controlled-promise/schema/controller Node tests PASS.
- 32 existing Android protocol and 48 existing Android controller tests PASS on
  complete source copies with these exact hooks. No native/process/tool calls.
- The first run had two test-only null-prototype comparisons; those now compare
  the copied values. One controller collection initially lacked seven existing
  public JSON imports in the source copy; the corrected controller-only run
  passed. Original logs are retained; no product guard was relaxed.
- 23 focused Rust tests are authored **not run**: filter `agent_android_build`
  (21) and `installed_cli::android_build::tests` (2). They include actual shared
  Start refusal before take, original validated result redaction, genuine Store
  fixtures/read-scope refusal, first Start time, revoke/expiry, no replay,
  lost admission/ACK, stale scope and absorbing Unknown. Store fixtures require
  the existing protected-ancestor-compatible task temp directory, not `/tmp`.
- All six new Rust leaves plus 18 composed Rust files syntax-parse. This is not
  compilation. Root must compile the real library, thin client, shipping graph
  and TypeScript; actual Mac execution is not claimed by this packet.

### Manual native verification (not executed)

Use the existing installed observer/ordinary Desktop and packaged `mrk`; do not
invent a WebView, permit, fake runtime or alternate harness. On an explicitly
approved synthetic project with qualified selected tools and no private inputs:

1. Observe the saved config/version in Desktop; enable scoped agent **read** access.
   Prepare without the new execution permission must refuse.
2. In the ordinary Android panel select structure/version without toolkit signing,
   explicitly Allow one CLI build. Copy its stable project/observation IDs.
3. Run Prepare once, retain its printed instance/request IDs and query until the
   native operation IDs appear. Confirm no build started; GUI observes that same
   Prepared but cannot start it. Review the exact saved pair before explicit Start.
4. Start once. Verify the same native operation, original status/STOP and shared
   history, with no GUI redoing the action. Completion/negative findings stay DATA.
5. Separately, with new explicit consent, test cancellation/revoke and lost-client
   reply: query/cancel the printed request, not a new Prepare/Start. Confirm real
   original joins/cleanup before treating it as settled. Unknown stays blocked;
   preserve private recovery state rather than cleaning it manually.

This runbook is guidance, not a pass or authorization to execute a real build.
