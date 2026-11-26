# Local Git changes — frontend integration

Source implementation, **not native activation or installed qualification**.
Frontend base: `4fd07ee590be`; Root hook base: `cb6e7c46`. Git's separate
`git-local` lane owns the original native/worker/core packet and its shell hooks.

## User flow and reused controls

The existing GitRead controller and repository table still supply the actual
file list, selection, bounded differences and local history. The same retained
`GitRepositoryController` owns the commit message/author draft. Nothing installs
its older `GitMutationPort` or manufactures `git-plan-*` identifiers.

The optional `localActions` rendering slot replaces only the old unavailable
write form. Without a slot the old behavior is unchanged. One new form offers:

1. Check the installed local-action availability explicitly.
2. Review staging or unstaging the selected **whole files**.
3. Review a commit of **every staged change**, including externally staged files.
4. Separately check the review confirmation and apply exactly that review once.

Commit author/message remain local drafts and explicit native Prepare input;
they are absent from public native status. No branch mutation, push, reset,
arbitrary command, executable/path selection or fallback is added. Private or
non-text content withheld by the existing diff policy is not silently approved.
Closing a review keeps the draft. The original Check/Stop/Close controls remain
reachable on other pages and for previously selected projects. No component
mount, navigation, status check or completion starts a new write or file read.

## Exact native boundary

`createGitLocalApi` is available only for the real native bridge and forwards
five fixed RAW UTF-8 JSON calls, with no object-argument fallback:

- `git_local_prepare`: `{projectId, expectedDocumentRevision, action}`. Action
  has exactly `kind`, `expectedRevision`, `paths`, `message`, `identity`.
  Stage/unstage use sorted 1–64 paths and null message/identity. Commit uses an
  empty path selection plus the literal bounded message and `{name,email}`.
- `git_local_apply`: `{projectId, expectedDocumentRevision, reviewId}` only.
- `git_local_discard`: `{reviewId}` only.
- `git_local_status`: `{}` only.
- `git_local_cancel`: `{operationId}` only.

Prepare is bounded at 96 KiB; the others at 1 KiB, including the native
command-name plus 32-byte overhead. Native independently binds the registered
root, private retained review, source, journal and original process owner.
Public comparison revisions, digests or sizes are not those authorities.

Prepare/Apply return the exact native StartResult admitted/refused envelope.
Only a matching typed pre-admission refusal can discharge that attempted call;
a generic error, malformed value or lost reply cannot. Refused stale reads mark
the existing repository observation stale and require explicit refresh/review.
Only `Status.review` supplies a review identifier after native joins. A nested
successful Prepare result, a historical terminal, or an observed-only review
cannot approve a change. An observed-only review is close-only.

The controller retains each actual Start, Status, Cancel and Discard Promise.
Terminal DATA arriving before the original Promise returns does not retire it.
Historical Start replies cannot replace newer original terminal/review evidence.
Transport uncertainty needs exact original status; native cleanup Unknown,
contradictory terminal evidence and recovery-required remain latched. Stop is
independent of a pending Start/Status and remains bound to the original port.
There is no automatic replay, status-triggered write, or fictional recovery action.

## Mandatory Root hooks

Apply `git-local-frontend-hooks-20261020.patch` only after the new frontend files
are integrated. It changes seven existing files, not native qualification:

- App retains one GitLocal controller. The original `gitReadBusy` helper becomes
  `gitBusy`, so every existing peer/reconnect/passive gate includes both owners,
  including a prepared review or an unfinished Status read. GitRead admission
  includes GitLocal; GitLocal admission includes GitRead but excludes itself.
- Current binding uses the actual immutable service/project repository entry,
  checked read epoch and native API. Existing workspace/service/scope invalidation
  retires local consent too. Navigation retires consent, not original work.
- After actual Apply entry, including a synchronous throw/non-Promise, the
  original callback calls `snapshotIntentBatch`, dispatches `git-local-intent`,
  retires release-version/input eligibility and invalidates the matching asset
  context. The actual Promise is retained first when returned. Asset context's
  existing reciprocal owner gate prevents an automatic context submission here.
- The closed reducer alias shares the existing identity/initialization
  preservation arm. It invalidates saved observations/validation, never replaces
  a clean or dirty draft, baseline, version, or native original.
- Bridge/types install only the five closed methods. Two small rendering slots
  reuse the original table/form owner without duplicate draft controls.

Native five-command registration, permissions, same-Document peer admission and
actual Stop/finality remain Git/Root responsibilities. This patch enables no
native flag, profile, process, Store or runtime by itself. Actual native refusal
or unavailability stays visible; a read-only Git view cannot enable writes.

## Focused verification

```sh
/opt/node/current/bin/node --experimental-strip-types --test --test-isolation=none \
  --test-concurrency=1 desktop/tests/git-local.test.mjs
```

Author: **20 passed, 0 skipped**, 168.893332 ms. Tests use inert fake ports and the
real existing repository controller: wire/privacy limits, original Promise
ordering, historical replies, full-index review, stale/ABA/navigation and
reentrant consent, lost/refused acknowledgement, absorbing Unknown/recovery,
original cross-project Stop/Close and draft/read preservation.

The single affected existing draft test table, with the Root patch applied to a
disposable source projection, passed **1 case, 0 skipped** (115.523278 ms), covering
both intent names and both clean/dirty drafts. The complete projected frontend
TypeScript graph with these seven hooks passed using the already shared
dependencies. Initial checks found an explicit type-root/projection dependency
omission and one array-index narrowing error; these were corrected, not suppressed.
All compiler/test calls joined and the temporary dependency link was removed.

No React/DOM rendering, native invocation, actual Git mutation, provider/network,
Cargo, installed app or macOS qualification was run for this frontend packet.
Root still applies/reviews the shared hooks and verifies the real combined graph.
