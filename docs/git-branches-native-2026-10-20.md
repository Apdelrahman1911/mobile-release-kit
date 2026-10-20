# Local branch list/create — native composition

This extends the existing GitRead/GitLocal owners. It does not enable an
unqualified provider, create another process or journal owner, or implement
switch/rename/checkout/pull/push. List is cached **local refs, no fetch**. Create
points one previously absent local ref at the reviewed HEAD and leaves HEAD,
the current branch, index, worktree and repository configuration unchanged.

## Applied source and Root hooks

Prerequisites: accepted branch core `e768e086` (Root `9a723876`) and worker
`626bcca4` plus its four Python hooks. New leaves:

* `desktop/src-tauri/src/git_branch_protocol.rs`
* `git_branch_protocol_tests.rs`, `git_branch_state_tests.rs`,
  `git_branch_source_tests.rs` in the same directory.

`git-branches-native-hooks-2026-10-20.patch` contains exactly ten Root targets:
the existing GitRead/GitLocal protocols, GitLocal journal and SourceBook child,
one Prepared projection line, their three existing test files, and module
declarations in `lib.rs` and the manually composed installed observer. It was
generated from `3041db37` copies and apply-checked against Root `643110ff`.
There are no Supervisor/Host/job/runtime/clock/roster changes. Root's accepted
`Arc::as_ref()` and runtime reservation `?` corrections remain untouched.

## Closed public and private DATA

* `git_read_start` adds `kind: "branches"`, current `expectedRevision`, empty
  `paths`, and `staged: false`. Its result is exactly `{revision,
  referenceRevision, head, branch, branches:[{ref,oid}], basis}`. Up to 256
  sorted, unique local refs; current branch must agree with HEAD; incomplete or
  malformed lists refuse. No identities, messages, reflogs or remote URLs.
* `git_local_prepare` adds the exact branch action `{kind:"branch-create",
  expectedRevision, expectedReferenceRevision, name}`. Old file actions retain
  **all five required fields**; they do not become optional-field bags.
* The branch review is exactly `{action, name, targetRef, expectedRevision,
  expectedReferenceRevision, head, branch, expectedIndex, reviewDigest}`.
  `head` must be a commit OID; `branch` may be null for detached HEAD. A branch
  Prepare success contains `{review}` only, and public Prepared omits `diff`.
  Existing file Prepare results still require their exact actual diff.
* Candidate intent is exactly `{action, expectedRevision,
  expectedReferenceRevision, expectedRef, expectedHead, expectedIndex,
  targetRef, expectedTargetAbsent:true, candidateRefOid}`. The candidate OID
  equals the reviewed HEAD. No arbitrary start point, force, ref namespace,
  upstream, caller identity or reflog message is accepted.
* Positive child publication uses only `branch-ref-returned`, distinct from
  commit/index publication. Success must retain the original HEAD/current
  branch. A matching readback or child terminal still cannot mint native
  finality, an ACK or a source replacement witness.

The same Apply/discard/status/cancel inputs, status schema1, original public
request `document-N`, pending/review semantics, process deadline and Stop remain.
New branch refusal codes are finite and accepted only for branch-create:
`branch-exists`, `branch-parent-missing`, `branch-identity-required`, `unborn-head`.
Existing core policy/sensitive-path errors remain fixed. Name/content filters
are bounded safety heuristics, not a proof that all repository text is public.

## One journal, exact source successor

The **existing GitOperations document**, not the Store namespace reservation,
gains schema2. Existing schema1 bytes are decoded against their exact canonical
shape and are not rewritten on read. Only an explicit branch Apply's original
Preparing CAS upgrades the document, preserving every other project row and
its pending/recovery fence. There is no status-side initialization or replay.

The same compact row adds a branch field with referenceRevision, targetRef,
expectedTargetAbsent and initially null candidateRefOid. Only its original
candidate CAS fills that OID, once. A Preparing row cannot fabricate an intent;
candidate/recovery rows cannot be replaced or declared failed-with-no-effect
from negative readback. Known Finished replacement still needs a fresh explicit
request, the current native project, exact snapshot CAS and original NativeUse.
No message, author, diff, path list, credential or runtime grant is persisted.

The original SourceBook still holds HEAD/config/index/tool descriptors, account
and ACL observations. For branch Apply it compares the actual original HEAD
bytes with the reviewed **source**, retains existing physical destination
parents, and requires destination absence before work. It never attaches HEAD.
The core's complete frozen inventory/expected-zero Git CAS governs packed refs;
native loose-path absence is not a substitute ref resolver.

After genuine candidate ACK and returned positive publication, only the same
operation/review/native-bound `GitLocalPublication` may admit the new target FD
with exact candidate OID bytes. Index remains unchanged and its original FD
must still receive the original sole close. No source inventory reset, generic
"changed is okay", or early-published flag is introduced. All existing child,
pipe, source, runtime, job, watchdog, final journal and NativeUse joins remain
mandatory. Required hooks/signing/filter/ref-log policy refusal is enforced by
the accepted core; this composition does not silently bypass it.

## Evidence and remaining work

Sixteen new Rust tests are **defined but unexecuted**: eight protocol, six
journal DATA, two Mac source-selection DATA. Old constructor-only test updates
preserve old assertions. Fourteen changed/new Rust files passed formatter
syntax parsing; this is not typechecking, a test pass, or native qualification.
No Cargo, native operation, provider, credential or process test was run for
this packet. Prior 16 core/11 worker passive passes and four actual nonroot
local Git passes remain separate, source-scoped evidence and were not rerun.

Root must apply the exact hooks, compile the actual graphs, run the selected
new/affected tests, and qualify the original native execution path. Renderer
list/name/review integration is a separate successor packet, not implied by
these native DATA types. Existing qualification gates remain unchanged.
