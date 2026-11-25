# Passive saved-file change checks — Root integration

Source/controller tests only. These files do not connect a window, add an IPC
endpoint, execute project code, install a watcher, or establish release readiness.
Root owns App wiring, integrated TypeScript/build and native/installed acceptance.

## Actual behavior

- One retained controller per App/native session. Visible-idle timer: 30 seconds.
  Focus/visibility can request a check, throttled for 5 seconds after settlement.
- Only `api.snapshot(registeredProjectId)` and, when a current accepted saved
  version baseline exists, **sequential** `api.observeReleaseVersion(projectId)`.
  No path override, CLI invocation, source execution, credentials or writes.
- Unchanged facts mean **no workspace dispatch and no owner/consent retirement**.
  The top-level observation time is ignored; nested configuration/hint fields
  and exact saved configuration/version byte comparisons are not ignored.
- Different observations supply the actual validated snapshot for the existing
  refresh reducer. A version-only difference does **not** supply or construct a
  `ReleaseVersionState`: the old owner is invalidated by the snapshot batch and
  its existing explicit read is the next action.
- The reads are non-atomic. Disagreeing configuration hashes, root mismatch,
  malformed/partial/invalid observations and read failures supply a fixed
  failure, not a successful snapshot. Root must invalidate saved freshness.
- This is bounded static change detection, not monitoring every filesystem
  byte. Equal observed facts are not a project lock or evidence that arbitrary
  source files stayed unchanged. Native expected-revision/apply checks remain
  authority. Optional Store/version reservation results are not involved.

## One synchronous busy hook, both directions

Retain `externalObserverRef` like existing controller refs. Define one hook:

```ts
const externalBusy = () => externalObserverRef.current?.passiveBusyReason() ?? null;
```

Add it to **both** `savedCommandBusy` and `savedCommandPrerequisiteReason` so
controllers using either path refuse new reads/preparations/actions while the
original passive query is still owned. Add an `excludeExternal` argument or
extract otherwise-identical private helpers for this observer's own gate.
All normal callers keep the default (included); the observer's
`otherOperationReason()` excludes **only itself**, not another owner.
Do not derive this busy hook from React's rendered state or clear it in a
project/connection effect. Retirement and disposal retain the original Promise
until actual settlement; `cleanup_unknown` additionally retains a lifetime pause.

Full **observer → existing owners** checklist, read synchronously from refs:

1. Current snapshot capability, native API, selected registered project;
   `bootstrapPending`, `connectionPicking`, original project-path picker.
2. All saved command owners: local history; all four local Store operations;
   artifact inspection; offline preflight; Android build **including its tool
   catalog/source/registration/service owners**; iOS archive; project recovery.
3. Initialization, configuration, workflow, public-text, saved-version and
   metadata-image owners; native diagnostics. Preserve nativeBlocked,
   integrity/generation loss, uncertain/unknown, original unconfirmed replies,
   active/prepared/cancelling/closing/recovery states and native journal attention.
   Use original owner helpers, not just the selected project's displayed task.
4. Retained asset session via `metadataImagesAssetSessionReason(assets)` with
   **no** `open-held-selection` exemption: blocked/observationFailed,
   originPending/busy/updatingContext and non-idle or unknown-settlement operation.
5. Lifecycle evidence: integrityFailed/uncertain/pending/cancelling or native
   phase choosing/observing/stopping/unknown.
6. GitHub publication, remote setup, preflight, release and history owners;
   original GitHub connection blocked/uncertain/busy/retirementPending or retained
   session. Also check **`githubPreflight.status?.prepared` and
   `githubRelease.status?.prepared`**: their ordinary owner-reason functions do
   not alone report an idle retained preparation. Do not retire a consent merely
   because an automatic timer fired.
7. `passivePending.current`, and snapshot/validation/review/suggestion requests
   for **any** loaded project. Both `.getSnapshot().pending` and original
   `.passiveBusyReason()` for environment, saved version, release inputs and
   GitHub setup; original passive reasons for public text and metadata images.
   Include any additional integrated native identity/tools/credentials/version
   owner/passive admission; do not infer it from public readiness DATA.
8. The selected session's saveRecoveryRequired/saveRecoveryNeedsReload and
   recoveryReloadRequest. The controller defensively checks these plus its
   selected session requests; it does not replace the cross-project/global gate.

Full **existing starts → observer** checklist:

- New initialization/configuration/workflow/text/version/image preparations and
  saves; diagnostics; project picker and project-field pickers; asset and
  evidence selections; GitHub connection/history/preparation/dispatch;
  artifact/preflight/build/archive/new recovery/local history/Store operations.
- Manual `loadSnapshot`, validate, review, suggest, all environment/version/input/
  GitHub/text/image saved reads; bootstrap/reconnect and new native setup lanes.
- Configuration `recoveryUnavailable` presently checks passivePending directly;
  add `externalBusy()` there too for **starting a new** recovery inspection.
- Preserve original Status, Cancel, close, cancellation settlement and recovery
  cleanup controls. Do **not** gate an original owner's settlement behind a new
  observer admission check or block its local native Status reads. There is no
  observer cancellation API, and no replacement native owner.

## Context and event hooks

Construct with synchronous `current()` reading `pathService.current.api`,
`workspaceRef.current` and `releaseVersionControllerRef.current?.getSnapshot()`.
Do not capture the initial React `api`/session/version values in its constructor.

- Call `beforeWorkspaceAction()` at the beginning of App dispatch, **before**
  reducer/early return; then `syncContext()` after the normal workspace sync.
- Call it before explicit snapshot/version read/save/picker intent, navigation,
  repository/context changes and service begin/unavailable/shutdown, including
  paths that later return early. This is passive UI retirement, not native
  cancellation. It detects selection/API away-and-back ABA.
- Call `syncContext()` after accepted connection/context updates. Poll admission
  always calls the live full gate; no global native owner subscriptions are
  needed to restart a timer.
- Only add `window.focus` and `document.visibilitychange` listeners; visibility
  calls `setVisible(!document.hidden)`, focus calls `focus()`. The controller owns
  its one timer. Hidden windows do not check. Unmount removes those listeners and
  calls `dispose()`; it does not pretend an in-flight native query was cancelled.
- `useSyncExternalStore(subscribe, getSnapshot, getSnapshot)` can show notices.
  `checking` is transient file-check progress, not release readiness. A retained
  `recovery` is a separate original-project/global notice, never current-project
  status; show the original native service error/recovery rather than a new retry.

## Accepting a result (synchronous, no second API request)

Factor **the existing `loadSnapshot` intent list** into a helper without a read:
GitHub history; initialization; config/image/version/text editors; path picker;
artifact/offline/Store preparation/execution/reconcile/history; Android;
project recovery; iOS. Existing dispatch also retires all current read owners.
Do not invoke this helper at automatic check start or for unchanged data.

```ts
onObservation: (outcome, stillCurrent) => {
  if (!stillCurrent()) return false; // AFTER original passive scope released
  snapshotIntentBatch(outcome.projectId); // existing intents, no await
  const requestId = ++requests.current;
  dispatch({ type: 'snapshot-start', projectId: outcome.projectId, requestId });
  if (outcome.kind === 'observed') {
    dispatch({ type: 'snapshot-done', projectId: outcome.projectId, requestId,
      snapshot: outcome.snapshot, observedAt: outcome.observedAt });
  } else {
    dispatch({ type: 'snapshot-failed', projectId: outcome.projectId, requestId,
      error: outcome.error });
  }
  return true;
}
```

The guard expires after the callback. No await/deferred action may reuse it.
The batch legitimately retires its own scope/changes the session; no global
"observer-origin" exemption is needed. Do not recheck the old scope between
these own synchronous reducer actions. An owner/context change **before** the
callback vetoes it; no stale reply may close/retire a newly admitted owner.

`snapshot-start/failed` clears eligible saved comparison data while preserving
the draft, baseline and last snapshot. `snapshot-start/done` likewise preserves
**even a clean existing draft** and its baseline. Never call reset/discard,
save/apply, recoveryReload or rerun a completed action from this callback.

Notice action mapping: `review-settings` → existing settings/draft review;
`read-saved-version` → existing explicit version read with all normal guards;
`refresh-project` → existing guarded refresh; `original-recovery` → original
service error/retained recovery controls, not an automatic retry. Dismiss an
ordinary notice after a successful explicit refresh/review as appropriate;
`dismissNotice()` never clears the retained unknown owner. A file change need
not discard any unsaved settings to become visible.

Service coordination: native `project_snapshot` can publish its existing safe
redacted saved observation to the running-desktop service after its original
read settles. This renderer does not generate stable service IDs, publish draft
data, call DocumentBinding or add a CLI endpoint.

## Focused verification

```sh
node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 \
  tests/external-project-observation.test.mjs
```

20 inert Node tests pass (182.906178 ms initial run). The harness calls the real
controller, retires it inside the accepted callback and applies the real
`workspaceReducer` start/done-or-failed batch. Named coverage includes clean and
dirty draft preservation; unchanged/no retirement; exact byte comparisons;
snapshot/version non-atomic mismatch; singleflight through both sequential
Promises, context ABA and disposal; owner arrival on busy release and context
change inside the callback; fixed malformed/partial/error freshness invalidation;
and original foreign cleanup-unknown retention. No native/installed acceptance,
live files, DOM, source execution, Store or account access is claimed.
