# Run-specific GitHub Actions retry

## Delivered source and limits

This slice adds **Review retry for selected run → explicit confirmation → Retry
failed and dependent jobs** beside the existing Activity view. It uses the same
native Document, selected-account `ConnectionState`, GitHub Setup runtime,
Supervisor and HTTP transport. It adds no scheduler, runner, token broker,
database, shell command or workflow-dispatch facility.

It is not native qualification. No GitHub request, workflow retry, credential
read, installation or native operation was executed while authoring this slice.
The installed CLI has no new retry authority. Existing native availability,
runtime and platform gates are unchanged; preview supplies no writer.

### Exact provider semantics

The only write is the supported endpoint
`POST /repos/{owner}/{repo}/actions/runs/{run_id}/rerun-failed-jobs`, with fixed
`{"enable_debug_logging":false}`. GitHub can rerun **dependent** jobs too, including
jobs that publish or change external services with the original workflow's
privileges. This action is neither a sandbox nor a toolkit release approval.

GitHub offers no expected-attempt CAS or idempotency key for this endpoint.
Approval is for the exact immutable repository ID, run ID, workflow and source.
The observed attempt is shown, and the confirmation explicitly says that GitHub
may select its latest attempt when the request arrives. Fresh checks reduce
staleness but cannot promise atomic execution of a particular attempt. An
acknowledged `201` means request acceptance, **not** successful jobs or a release.

## Ownership and source binding

- Native Prepare accepts only current session/revisions and run ID/attempt from
  an actual settled Activity run detail. The original Activity state checks
  its own target, selected attempt, revision, project, complete result grammar
  and failure/timed-out conclusion. Its actual head SHA is retained natively;
  renderer arguments cannot supply a root, account, repository, hash, marker,
  token or prepared plan.
- The ordinary Document and registry retain the current registered root,
  generation and original `SavedEditStamp`. The existing selected-account
  private session supplies account/repository IDs and credentials. Currentness
  is checked at admission, original GO and observation/retirement; copied status
  is never a source, grant, worker or join receipt.
- A read-only Prepare checks `/user`, immutable repository ID and latest run.
  The full workflow ID/path, event, source repository/branch/SHA and observed
  attempt are shown. A push permission bit is only a conservative prerequisite;
  it does not prove Actions-write scope, SSO approval or workflow privileges.
- The original settled Prepare creates a one-use native consent, at most 120
  seconds and bounded by the existing connection's deadline. Checkbox approval
  is separate. Retry consumes this exact consent before native launch, including
  a later refused launch. No poll, refresh, rejected response or navigation
  renews it. Original source/account/context loss retires it.
- Retry performs the same account/repository/run checks again, writes a durable
  intent, immediately rechecks the latest run, durably claims its sole POST,
  then attempts that POST once. A received `201` is remembered before receipt
  persistence and final readback. A later failure cannot rewrite it as unsent.
- Same Supervisor READY/GO, private writer, original process/IO/native-runtime
  joins, stop and two-second cleanup remain in use. Public response DATA is
  accepted only via the original settled receipt. Unknown is retained; another
  status or process exit alone cannot dismiss it. Status and Stop remain usable.
- All operation modes use the original 60-second/native-connection deadline;
  the custodian and HTTP exchange share the same original budget. There is no
  new per-request timer, automatic retry or child started on a UI notification.

## Journal and recovery

The fixed directory is
`<native HOME>/.local/share/mobile-release-kit/github-actions-retry` using the
existing `_github_preflight_journal.Journal` directory/flock/fsync/close owner.
This is a fixed sibling purpose, not a second storage framework. It contains
only bounded public target/review DATA and fixed intent/claim/receipt files.
It stores no token, source file, log, artifact, private key or credential.

There are at most 32 retained rows (96 fixed files, 192 KiB aggregate journal
bytes). The duplicate key is immutable repository ID + run ID + observed
attempt, independent of marker/account/project aliases. An acknowledged older
attempt permits a genuinely newer explicitly reviewed retry. Any unresolved
prior attempt for the run remains fenced. Intent/claim publication ambiguity
does not authorize a new marker, replay or deletion.

Pending reads retained rows. Reconcile is provider-GET-only: current identity,
repository and latest run. A newer attempt without a durable acceptance receipt
is **unattributed**, not proof that this request caused it; an unchanged attempt
is not proof that no request was sent. Reconcile never clears the journal fence,
replays POST or repairs files. Capacity exhaustion is actionable in the UI:
preserve records, inspect the original run on GitHub and use an explicitly
chosen external workflow if necessary. No automatic evidence eviction is added.

## Bounds and UI

- Seven closed native RAW commands, each at most 1 KiB:
  `github_actions_retry_{status,prepare,start,pending,reconcile,discard,cancel}`.
- Same Setup private initial/GO channels, each at most 8 KiB. The selected token
  is copied only into the existing private GO buffer, with bounded zeroizing
  serialization; no argv, project files, public status or logging.
- At most eight HTTP requests, 256 KiB/body and 2 MiB aggregate bodies; public
  response/status is at most 192 KiB. Native retained-heap admission accounts for
  request/consent/status/receipt copies and finite buffers under a 2 MiB facet
  quote, in addition to the existing original owner census. This is not an RSS
  claim or a widened global quota.
- The application-held controller retains exact promises, listener, original
  port, pending identity and unknown outcomes across navigation/rebinding.
  Events cannot release unresolved invocation promises. Known typed
  pre-admission refusal is different from a lost reply; known Close expiry
  requires a fresh original Check rather than fabricating successful Close.
- Preparing natively retires the preceding Activity result. The retry component
  is a sibling of that replaceable result and retains the exact original review
  rather than treating this self-transition as external source loss. All peers
  and file/account/context changes still retire consent at real native and UI
  admissions. The App's new-action gate excludes only the retry owner itself.

## Integration packet

Own new source:

- `src/mobile_release/github_actions_retry.py`
- `src/mobile_release/_github_actions_retry_journal.py`
- `src/mobile_release/_github_actions_retry_transport.py`
- `src/mobile_release/_desktop_github_actions_retry.py`
- `desktop/src-tauri/src/github_actions_retry_protocol.rs`
- `desktop/src-tauri/src/github_actions_retry_session.rs`
- `desktop/src-tauri/src/asset_session_github_actions_retry.rs`
- `desktop/src-tauri/src/supervisor_github_actions_retry.rs`
- `desktop/src/githubActionsRetryProtocol.ts`
- `desktop/src/githubActionsRetryController.ts`
- `desktop/src/components/GitHubActionsRetry.tsx`
- focused Python and Node tests named `test_github_actions_retry.py` and
  `github-actions-retry.test.mjs`.

`github-actions-retry-hooks-20261020.patch` is **Root-only**. Its 20 existing-file
hooks add the closed Setup/HTTP profile, original Connection/Supervisor/Document
arms and census/retirement, exact Activity-selection accessor, seven native
local-main ACL grants/commands/event, existing Rust fixture fields/module declaration,
optional TS bridge/type, App controller/reciprocal gates/component, Activity help
and one test in the existing Node roster. No new workflow or dependency.

Base is `3aed5f83`; the package test-roster hunk preserves current `d5e83cef`.
Apply-check against current Root `d5e83cef` passed. Full original and composed
parents are in `.task-actions-retry-hooks/{base,post}`; that task directory is
not shipped or committed. Root must preserve later unrelated shared changes.

## Verification

Executed with real source modules but only fake/data fixtures:

- **15 Python tests passed**, including fixed schedule/body, no-CAS warning,
  account/repository/run drift, lost POST/read-only reconciliation, persisted
  acceptance, newer explicit attempts, capacity/claim fences, strict framing
  and actual existing HTTP body decoder over `BytesIO`.
- **7 existing affected HTTP transport tests passed**, exercising original
  bounded Content-Length/EOF/chunked metadata, deadlines and publication roles.
- **18 Node tests passed**, including the actual composed bridge, exact selected
  Activity identity, self-retirement, explicit one-use approval, response/event
  ordering, reentrancy/ABA, lost replies, Close expiry, protected attempts and
  retained old-port disposal. No DOM/native/GitHub execution.
- Actual full TypeScript `--noEmit` over the private shared composition passed
  using existing dependency files. The first check found a narrowed-unknown
  typing error and omitted projection JSON inputs; both were fixed. Its failed
  log remains. Only the task-owned dependency symlink was removed afterward.
- Sixteen composed/own Rust files parsed with the existing rustfmt; seven
  Python files passed AST parsing. These are **not compilation** claims.
- The existing `GitHubNativeWiringTests.test_closed_commands_match_handler_build_and_local_capability`
  source regression passed against the actual composed shell/build/local-main
  capability files: all handlers and manifest commands have exactly their
  explicit grants, no duplicates, extra permissions or remote windows. The
  successor adds only the seven retry grants; no native invocation was run.
- **Seven Rust DATA tests are authored but UNRUN**: four protocol tests, two
  original Connection state tests, and one exact original Activity-selection
  test. No native receipt, positive process join or provider operation is
  fabricated by these tests. Root owns actual graph compilation/tests.

Evidence: `.task-actions-retry-hooks/results/{python-v1.log,
python-transport-affected.log,node-v2.log,typescript-v2.log,acl-existing-contract.log}`. Source review,
integrated Rust checks and relevant supported native qualification remain
separate. No operation is advertised as provider-tested or release-ready.
