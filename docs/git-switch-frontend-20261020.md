# Review and switch a clean local branch

This renderer increment completes the controls for the accepted bounded switch
core/worker and the separately reviewed native packet `e99114f1`. It does not
enable an unqualified native route or add another command, operation owner,
transport, timer, filesystem reader or Git implementation.

## User flow

1. Explicitly refresh the existing repository view and read local branches.
2. Select an existing local branch. Selection is a project-local draft only;
   it neither switches branches nor sends a review request.
3. Request **Review branch switch**. Only the existing GitLocal owner's joined
   Prepare may supply the review. The current project, document revision,
   original observation, complete branch-list object and selected draft remain
   captured. A target OID differing from the captured list is refused.
4. Inspect the exact original/target branches, commit IDs and up to8 changed
   file names. Confirm explicitly, then **Switch to this local branch**.

The clean-tree display check is a precondition hint, not permission to bypass
the core's actual checks. The native review still requires the same names and
modes on both branches, ordinary regular files, bounded content, supported
ownership and repository policy. Ignored/untracked files, hooks, LFS, filters
and other unsupported layouts are not silently discarded or executed. There
is no force, reset, stash, rename, fetch, push or automatic refresh.

Same-tree switches are real branch/metadata changes requiring the same review
and Apply. File bodies are not displayed; the UI does not promise that path or
diff sensitivity heuristics prove an absence of secrets.

## Reused original controller

The same GitRead/GitLocal/Repository controllers retain all actual promises.
The exact existing five RAW commands are unchanged. Public request context is
still `document-<expectedDocumentRevision>`. Only the native retained review ID
is supplied to Apply; the renderer never submits candidate OIDs, file bodies,
private source projections, locks or serialized plans.

The switch selection is separate from the existing commit and branch-create
drafts. Changed-and-restored selection creates a new capture and invalidates a
review. Replacing the list, observation, project, session or original port
also invalidates eligibility. A review seen only through Status is close-only;
historical review-shaped data cannot authorize Apply.

Original Start, Status, Stop and Discard promises are not discarded after an
early status or context change. Apply call entry—including a synchronous throw
or lost acknowledgement—invalidates dependent read eligibility while retaining
drafts. No result manufactures a fresh observation or automatically retries.
Known partial recovery and cleanup Unknown remain absorbing. The existing
global original-action controls remain reachable across navigation.

The bounded public result validates the exact switch action, source/target and
index/log comparisons, completed effect phase and at most5 relative candidate
paths. Exact symbolic-HEAD hashing, source authority, publication and finality
remain native responsibilities, not renderer-generated proofs. A successful
result requires the target observation and index-returned phase with no retained
candidate paths. Known partial effects show the last reported step and paths to
preserve; no matching ref read means "safe to retry".

The same native schema3 final CAS may persist genuine joined recovery detail.
This panel renders the original public result; it does not create a new restart
recovery reader or reconstruct native authority from a journal row. If native
settlement/CAS is unknown, it does not claim recovery detail was durably saved.

## Exact Root-only hooks

`git-switch-frontend-hooks-20261020.patch` changes six shared paths:

- `gitLocalProtocol.ts`: finite switch union/dispatch and existing help wrapper;
  original file/branch-create shapes remain exact.
- `gitLocalController.ts`: switch eligibility, captured original list/selection,
  and review target matching; original send/finality/retirement code unchanged.
- `gitRepositoryController.ts`: one separate immutable project-local draft.
- `GitBranches.tsx`: mounts the new subscriber once; positively narrows the
  existing branch-create review so switch reviews cannot appear as creation.
- `GitLocalChanges.tsx`: success title and known partial-recovery details in the
  existing original-action controls.
- `package.json`: adds only the focused test to the existing roster.

New leaves are `gitSwitchProtocol.ts`, `GitBranchSwitch.tsx`, and
`git-switch.test.mjs`. No App/bridge/shell/event/availability hook is needed.

## Verification scope

Seventeen new tests exercise the actual existing controllers through inert
ports: exact requests, finite reviews/results, original target binding, dirty
refusals, one-use approval, pending promises, stale drafts, context retirement,
same-tree Apply, missing ACK, partial/Unknown pinning and close-only observations.
No native/Git/repository/provider/credential/DOM operation is performed.

Initial execution reached5 passes and then awaited an invalid test-only dirty
fixture (`index:'.'` instead of the unchanged core's literal space). The real
reader correctly kept its malformed response uncertain. The fixture was fixed,
and now validates every fake read using the actual parser before awaiting it.
The initial evidence is retained and is not a suite pass. Root matched the
exact original runner/child metadata and used a checked pidfd to terminate only
that inert worker; the original runner reaped it and returned1. Its65 public
projection files were then individually rematched and retired.

After the fixture correction, all17 new tests passed (306.691ms), with the
standard10-second test timeout and zero failures/skips. The37 affected existing
GitLocal/branch tests also passed (463.928ms). Their original callers returned0.
The projected actual seven-entry TypeScript graph (99 unchanged/new sources)
passed strict noEmit with the existing dependency cache, a768MiB heap ceiling
and compile cache disabled. This is not a full App/Vite/DOM check. An initial
missing JSX fragment close was corrected; the next typecheck found missing
type-import files in the temporary projection only, which were supplied
unchanged before the successful check. All earlier logs are retained.

Known finished public-source projections and the task-only dependency link
were retired after their returned results. Compact logs, exit codes, source
hashes and cleanup receipts are under `.task-git-local/switch-ui-*`.

Native22 test definitions remain Root's coordinated Rust/Mac batch. Core28,
real disposable Linux4 and worker16 results are reused unchanged. None of this
is installed Mac switching, UI-delivery or native qualification evidence.
