# CLI version preparation through the existing Desktop editor

This increment adds one command to the existing VersionEdit family. It does not
allocate, enroll, commit, upload, restore a handoff, or replace the version writer.
A running, selected Desktop project and its ordinary READ allowance are required.

```text
mrk version-edit-prepare PROJECT_ID SERVICE_INSTANCE --manual NAME BUILD --json
mrk version-edit-prepare PROJECT_ID SERVICE_INSTANCE --reserved RESERVATION_ID --json
mrk version-edit-status PROJECT_ID SERVICE_INSTANCE REQUEST_ID --json
mrk version-edit-cancel PROJECT_ID SERVICE_INSTANCE REQUEST_ID --json
```

Prepare emits its generated request ID **before** its first IPC request. Keep that
ID after an uncertain response; status/cancel address the same original, not a
new preparation. An initial queued reply is not a prepared preview or a saved file.
Desktop performs the genuine Open and Prepare without re-entering the proposed
values. Inspect the actual file preview there, then explicitly choose the existing
collapsed Advanced **Allow this Save once** control. The existing ID-only
`version-edit-submit ... --reviewed` consumes that allowance. Ordinary explicit
Desktop Save is also possible; only one wins. READ does not authorize Save.

Manual input is exactly `{name,build}`; policy is still the existing core's job.
Reserved input is the original native reservation-operation ID from this running
Desktop—not its candidate UUID, copied values, workflow output, or historical
status. The original returned Reserve lane, consume-once CAS/take, private handoff,
schemas 2/3/4, source/config/version checks and original clock remain mandatory.
There is no re-reservation or fallback to manual values.

## Original boundaries

- Same service VersionEdit Inbox, namespace and 32 metadata rows. A preparation
  and its separately submitted Apply occupy two rows. Only its exact associated
  Session/Prepared/lease is exempt from occupancy at **both install and Submit**.
  Cross-kind IDs, unrelated rows, cancellation, Unknown and GUI winners are not.
- Initial manual admission uses the existing fresh saved-configuration observation,
  not a fabricated version checkout. The real Opened decoder establishes a present
  controlling version, original values and both baseline hashes before Prepare.
- Same App-owned controller and actual MAIN Webview invoke existing RAW Open and
  Prepare entrypoints. Service/relay only notify; neither starts an executor.
  The original ActiveOwner is installed before its Entry/weak Session link,
  publication and GO. A postclaim failure retains that original/Unknown.
- Manual uses the existing registration publisher through its seven exact
  Open/Opened/Prepare/Prepared/Apply/Terminal/Retired cuts. Reserved uses only its
  existing handoff publisher—no second chain or scalar proof.
- The actual Open and Prepare API promises remain retained. An early event or
  coalesced later status cannot replace a missing caller return. New Allow or
  replacement waits for the same caller/native cuts; public Status is not a join.
  After an exact old-request read confirms the same settled original and its
  callers/native cuts are complete, that retained read may make one fresh latest
  query. Null/error/pending/Unknown cannot select the next request, and the same
  original/API is checked again before consuming the fresh reply.
- Exact project/API/service/draft pointer, revision, baseline and publication
  checks bracket each notification and send. Dirty/newer/ABA drafts survive.
  Once GUI Save wins, the unused agent READ/cancel cannot STOP it. Source/window
  loss remains authoritative. The old READ's earliest revoke is sampled by the
  same watchdog through known cleanup, never after Unknown or on a new clock.
- CLI-only frames are bounded **before growth/decode**: 784 KiB, 1024 Seed nodes,
  depth 16, and the existing three-total-frame count. A whole active projection
  is bounded before adoption. The checked quote retains six representations,
  command/status/IO/channel backing, Session/link, prospective reserved Sources,
  the actual old Edit projection and all lookup plus installation-extra Document
  debt. The existing 64 MiB aggregate and private/code/source limits do not change.
  Large sources/retained histories refuse; nothing is discarded to fit.

Missing/invalid initial version sources, unsaved Settings, source drift, a foreign
or spent reservation, initialization, enrollment, imported hosted-result DATA and
recovery are outside this command. Use their existing explicit Desktop flows.
Native availability, tool/runtime installation and provider/Store prerequisites
are unchanged. This is not headless parity or evidence of a native/provider run.

## Frozen delivery

Author worktree: `version-editor-prepare-cli`, base
`817f82279b200c2c931864f0bdec570905e40a66`.
Seven new source/test leaves plus this guide and the detached hook are the only
owned/staged files. Shared test/implementation working copies stay unstaged.

Owned leaves:
- `desktop/src-tauri/src/service_version_edit_prepare_protocol.rs`
- `desktop/src-tauri/src/service_version_edit_prepare_requests.rs`
- `desktop/src-tauri/src/service_version_edit_prepare_requests_tests.rs`
- `desktop/src-tauri/src/edit_owner_service_version_prepare.rs`
- `desktop/src-tauri/src/asset_session_service_version_prepare.rs`
- `desktop/src/serviceVersionPrepareProtocol.ts`
- `desktop/tests/service-version-prepare.test.mjs`

`docs/service-version-prepare-cli-hooks-20261021.patch` has 26 existing targets.
Complete original and after images are `.task-version-prepare/hooks/{before,after}`;
`hooks/pins.json` pins them against Root
`024c0d77ed085c0165bea58e6b0f8e85dbe0d28f`. This preserves the accepted PR and
ToolSavedInspect additions. Only package.json needed a mechanical test-list union;
installed_cli/service_protocol merged additively. No App handler changes are needed.
The author/test before/after copies are retained separately under `author/`.
The first frozen packet remains under `review-v1/`; its successor adds only the
observer's two missing module declarations and the bounded coalesced-next fix.

## Evidence and pending qualification

All logs below are in the task-owned `.task-version-prepare` directory. No Cargo,
Rust test, native process, provider call, credential operation or CI was run here.

- Original Node v1: 72 passes, 3 failures (two nested fixture assertions and their
  group); pending-Open fixtures incorrectly reused the previous final Session ID.
  The controller correctly refused that ABA. The corrected fixtures use a distinct
  original and explicit opening state; no production guard was weakened.
- Node v2: **75 passed, zero failures/skips**, 1.340 s test time (2.622 s owned
  caller). Actual release-version editor, delegated Apply and new preparation
  protocol/controller suites. Manual/build-only plus Android/iOS/paired reserved
  flows; separate Save, dirty/ABA, all three presend publications, bad baseline
  refusal, lost caller and coalesced old-final cases. `node-v{1,2}.{log,json}`.
- Whole composed noEmit v1: two TS2339 errors at one alias of a previously checked
  present-file union. Fixed using the existing `state === 'present'` discriminant,
  no assertion/cast. v2 **PASS**, 21.495 s; `typescript-v{1,2}.{log,json}`. Root
  approved reuse of Node results because this duplicated type-narrowing guard
  changes neither the type contract nor reachable behavior.
- Actual review found two source defects: the standalone observer needed the two
  new crate-root modules, and a coalesced next preparation could remain hidden
  after the old caller returned. The extended controller tests reproduce the old
  liveness cut (4 passes/3 failures). The first corrected run retained the same
  counts because its Cancel fixture was returning after later final/next records;
  it now awaits that original return before those records. Final focused run:
  **7 passed, zero failures/skips**, 0.449 s. Both caller-last and native-final-last
  reach exactly one new Open after an exact-old then fresh-latest read;
  Unknown/null/error stay fenced. `node-review-{old,new,final}.{log,json}`.
  The unchanged original 75-test and noEmit evidence is reused, not rerun. Root's
  next composed typecheck must cover the narrow successor callback addition.
- Both used the existing `run_owned`, fixed cached Node/dependencies, networkless
  namespace and captured source hashes. These runs were **root**, not nonroot.
  Their original callers joined before only their own public projection/link was
  removed. Shared dependencies and prior failed logs remain untouched.
- Twenty new Rust tests are **AUTHORED, UNRUN**. Exact names, source pins and
  effects are `rust-selectors.{txt,json}`. One uses the existing private
  Service/StatePort fixture; the rest are DATA, actual unentered Document/registry
  backing, original READ/Call, or parser tests. None creates a NativeUse, source
  loan, successful native finality or provider response.
- `rust-affected-selectors.txt` names twelve affected existing Inbox/CLI tests,
  including the established three CLI selector names. They also remain unrun in
  this lane. Source syntax alone is not a Rust or native qualification.

Root owns the final integrated Rust/CLI/Mac graph and real admission-fit runs,
including its independent shared Document memory repair. The ordinary already-
Prepared quote and all old debts are retained, not silently relaxed here.
