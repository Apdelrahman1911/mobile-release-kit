# Local branch list/create — Desktop integration

This adds **list local branches and create at reviewed HEAD**, not switch,
rename, checkout, fetch, pull or push. It uses the already retained GitRead and
GitLocal controllers and native owners. There is no alternate Git executable,
generic command API, new controller lifetime, availability override or account
requirement. Native policy, currentness, durable intent and original settlement
remain mandatory; frontend DATA is not a permission or cleanup receipt.

## Root hooks

`git-branches-frontend-hooks-2026-10-20.patch` contains exactly eight targets,
prepared against integration `4894c761` and apply-checked against `589b33f1`:

* `gitReadProtocol.ts`: the existing three RAW commands add only the fixed
  `branches` action. Its current revision, empty paths and `staged: false` are
  required. Bounded sorted complete names/OIDs come from the native local-ref
  result, explicitly **no fetch**.
* `gitReadController.ts`: explicit `readBranches` uses its existing single
  Attempt, original promises and status/Stop. Only a genuinely joined current
  result becomes current list DATA. Refresh or context intent retires list
  eligibility; cached names are labelled as previously read, not current.
* `gitLocalProtocol.ts`: the existing five RAW commands keep old file actions
  exact, including required nullable message/identity fields. New branch action,
  review and intent have their exact explicit tag and fields. A branch review
  has no `diff`, paths or fabricated file result. Native status still uses schema
  1; the separate durable journal schema-2 hook is in the native packet.
* `gitLocalController.ts`: the same single Prepare/Apply/review/Close/Check/Stop
  owner accepts the new action. It retains the actual repository observation,
  actual reader's current list, reference revision and immutable local name
  draft. A changed-and-restored name, changed observation/list, session or
  project retires approval. Unrelated file checkboxes and commit-message drafts
  do not change a branch-only review. Apply retains original request revision
  correlation and the full expected index/HEAD/ref/candidate comparison.
* `gitRepositoryController.ts`: one bounded name draft per existing repository
  controller; no new registry or persistence/authority. Refresh, navigation and
  other actions do not overwrite the user's name draft.
* `GitLocalChanges.tsx`: preserve ordinary stage/unstage/whole-index commit UI;
  explicitly narrow file reviews. The existing global/original controls also
  show branch outcome and actionable fixed branch refusals.
* `App.tsx`: provide the same retained reader in the local binding; mount the
  new rendering-only `GitBranches` next to local changes. Existing peer gates,
  epoch retirement, Apply-entry invalidation and original polling are unchanged.
* `package.json`: append only the new inert test file to the existing test
  roster. No dependency or lockfile change.

Owned new leaves are `gitBranchesProtocol.ts`, `components/GitBranches.tsx` and
`tests/git-branches.test.mjs`. Apply the accepted native branch hooks first so
the installed protocol understands the new tags. No shell or bridge command
is added by this UI packet.

## User flow and safety

1. Check existing native Git availability and explicitly refresh changes.
2. Open **Local branches** and explicitly read local names. No online account
   discovery or fetch occurs on mounting, navigation, typing or status checks.
3. Enter an unused branch name and request a review. The native owner checks
   actual references, required hook/filter/signing policy, logging identity,
   fixed provider and supported parent layout. Use an existing namespace or a
   top-level name; missing parent folders are not created by this increment.
4. Review the exact starting commit, name and original project. Approve and
   create. The current branch/checkout/index/worktree do not change. Detached
   HEAD remains detached; a branch without a first commit cannot create a new
   starting point.
5. Keep original Check/Stop/Close controls. Actual Apply entry invalidates read
   eligibility even if its reply throws or is lost; drafts are kept. Explicitly
   refresh after settlement rather than adopting the write result as a new
   observation. No retry, fresh review, branch read or other action is automatic.

Only native `Status.review` after original Prepare/status promises have joined
can become applicable. Historical prepare results and reattached reviews are
not new permissions; the latter are close-only. Exact no-admission refusal does
not re-arm consent. Missing acknowledgement retains its original request;
cleanup Unknown and recovery remain absorbing against later ordinary success.
Neither a matching ref nor a nested successful Git result settles an unknown
native operation. Original controls remain usable after context changes.

The list contains local ref names/OIDs, not commit messages, identities, reflog
contents, URLs or credentials. This is not a claim that arbitrary user-chosen
branch names cannot contain sensitive information. Existing file-diff sensitive
content handling is unchanged and remains bounded detection, not a proof of
secret absence.

## Verification scope

In a finite 268,961-byte source-only projection of these exact hooks and actual
existing protocol/controller dependencies:

* New `git-branches.test.mjs`: **17 passed**, 0 failed/skipped, 0.303 seconds.
  Actual controllers with inert RAW ports exercise strict tags/limits,
  current-list binding, original Promise ordering, explicit one-use approval,
  Apply invalidation, name ABA, context changes, listener veto, lost replies,
  Unknown/recovery, close-only reattachment, full intent comparison, unborn
  refusal and detached creation.
* Directly affected original `git-local.test.mjs`, `git-read-native.test.mjs`
  and `git-repository.test.mjs`: **70 passed**, 0 failed/skipped, 0.661 seconds.
  No duplicate full suite or real Git test was run for this UI increment.

The test ports never invoke native code, processes, provider APIs, credentials
or real repositories. These are behavior/codec tests, not DOM, typecheck, native
or installed-Mac qualification. Root schedules integrated TypeScript and native
checks. Prior accepted real core Git fixtures and native source review remain
separate evidence; this UI cannot enable an unqualified route.
