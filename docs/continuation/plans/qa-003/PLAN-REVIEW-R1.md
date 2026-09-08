# QA-003 independent plan review — R1

**Verdict: REQUIRES CHANGES. Do not implement R1.**

Reviewer: `/root/qa003_plan_review`. This is a distinct independent plan review,
not implementation approval or production readiness. Original finding is still
confirmed; none of its manifestations is waived.

## Exact scope and verification

Main/HEAD `2beb37336fa8002b69f598fe431082606368310d`, tree
`00f3acee00c994e6e81470cc76e42f1f2108fcdb`, branch
`fix/qa-003-local-signing-lease`, version 0.3.0. R1 SHA256:
`310be78a678cf4160df67667b3ce602a824de0cc123ed01b8ca4de61a8d3aae7`.

Read AGENTS.md, SECURITY.md; applicable production-readiness, provenance and
native-signing skills; original FINDING, reanalysis/probe/results, complete R1;
actual signing/profile/cancellation consumers; preflight/build runners; affected
unit/signal/workflow/native-gate assertions; credential documentation and QA-004.
Inspected pinned public Apple keychain create/list/delete/StorageManager code.
Independently traced additional pinned Apple DB transaction implementation.

Executed the supplied current-source credential-free overlap probe again:

```sh
.mobile-release/remediation/MRK-002/venv/bin/python \
  .mobile-release/remediation/QA-003/reanalysis-current.py \
  > .mobile-release/remediation/QA-003/plan-review-reproduction-r1.json
```

Exit 0. Actual current profile filesystem plus explicitly synthetic CMS/native
seam reconfirms overlap, foreign-edit overwrite and after-effect activation failure.
Result is byte-identical to author reanalysis. All probe-owned temporary resources
were removed. No real keychain, credential, profile, Store or build was accessed.

`PLAN-REVIEW-R1-EVIDENCE.json` records input/output hashes and exact source state.
Downloaded files prefixed `plan-review-apple-` are third-party public source
research, not first-party implementation or executed input. Their URLs/hashes are
in `plan-review-apple-additional.json`. No live macOS private state was inspected;
source research is not a claim that native account behavior was executed.

## Sound foundations to retain

- Account-global nonblocking persistent-directory flock is the correct scope for
  cooperating toolkit sessions across projects. Per-project locking or profile
  inode ownership alone is insufficient.
- Obtain ownership before shared inspection/mutation; never adopt by dead PID.
- Journal intent before mutation, clear only after confirmed cleanup, and retain
  uncertain state outside auto-deleted materialization scratch.
- Snapshot/compare both complete search order and default; preserve observed
  foreign edits; detach owned references before native deletion.
- Explicit shared cancellation and two-level registered cleanup are required.
  R1 correctly avoids broad generator-wide signal deferral and direct changes to
  the separately confirmed QA-004 outer cleanup owner.
- Store authorization, uploaded candidates, receipts and public-release boundaries
  do not need to change to repair this local signing owner.

## Mandatory corrections before approval

### R1-M1 — specify a complete recovery/clearance protocol, not an inspection promise

R1 promises an internal recovery/inspection context and “precise steps,” but no
actual interface, state table or clearance predicates. This is critical after
SIGKILL or failed post-mutation journaling: future signing will otherwise remain
blocked with no demonstrated safe way forward.

The revision must identify the supported callable/command, exact lock ownership,
strict record validation, observation/confirmation format, allowed transitions,
and conditions for each native mutation and final record removal. Cover:

- record staged but not installed; session created but no complete record;
- keychain create/import succeeded but its new identity was not journaled;
- profile stage creation, hardlink and observer/journal failures at each point;
- native timeout/nonzero result after effect, failed readback, record write/fsync/
  replace/unlink failures, cleanup cancellation and interrupted recovery itself;
- preexisting reused profiles versus files actually installed by this session;
- foreign replacements/unknown entries, missing owned files and incomplete schema;
- original owner/descendants still alive and the case where process liveness
  cannot be proven;
- absence of the random keychain password after a crash.

A PID or user confirmation is not, by itself, inode ownership or proof of process
absence. Do not provide a generic force-delete/reset, use adjacent record hashes
as independent authority, or recursively erase unknown session contents.
Where automatic safe completion is genuinely impossible, the owner procedure
must name exact protected/manual actions and recheckable completion criteria;
“inspect then delete the record” is not adequate. Retry must preserve subsequent
foreign preference edits. Tests must actually recover staged/incomplete states
using the proposed production interface, not merely prove admission refuses them.

### R1-M2 — model native DB atomic replacement and sidecars

R1's “require owned path/inode identity” is incomplete for a keychain database
that legitimately changes its inode during native writes. Pinned Apple sources:

- `plan-review-apple-AppleDatabase.cpp:1529–1539,1683–1719`:
  DB modifications write through an AtomicTempFile and commit it.
- `plan-review-apple-AtomicFile.cpp:782–822`: commit fsyncs/closes and
  `rename(oldPath, newPath)` replaces the original final path.
- `plan-review-apple-AtomicFile.cpp:61–85,895–938`: native local locking uses
  a persistent `.fl<hash>` sibling file.
- `plan-review-apple-AtomicFile.cpp:597–653,833–857`: native staging and rollback
  can leave additional state on failure; deletion at95–109 also removes the
  lock-file path.

An in-place synthetic keychain file will miss this compatibility failure.
Specify immutable directory/session authority separately from evolving DB file
identity, which completed native steps may legitimately advance that identity,
how those transitions are durably recorded, and what remains quarantined after
ambiguous replacement. Do not “refresh ownership” over arbitrary later foreign
replacement. Enumerate safe sidecar cleanup/admission rules instead of assuming
one file or recursively deleting every entry.

Required tests use actual temp-file+rename DB transactions, old/new inode
assertions, native lock/staging sidecars, failed after-rename responses/journal
updates and foreign replacement outside authorized transition boundaries.
Success-path signing must still complete and clean normally.

Also correct the reanalysis attribution: pinned
`apple-StorageManager.cpp:119–134` adds newly created keychains to the search
list only for login/System paths. Implicit addition for this nonce-owned
`signing.keychain-db` path is a conservative compatibility simulation, not
observed behavior established by this exact source. Retain defensive handling,
but distinguish evidence from modeled possibility.

### R1-M3 — define actual process lifetime and native ambiguity containment

`credentials.py:826–840` and `ios.py:1011–1033` use `subprocess.run`.
It may kill/reap the direct process on failure, but provides no descendant
completion/containment proof. `run_ios_build` executes application preparation,
archive and export through this runner. A worker can outlive successful parent
return as well as timeout/cancellation. Releasing a lease and deleting profiles
after direct-parent completion does not prove the complete signing lifetime ended.

Specify owned worker/process-group or stronger containment and parent-death
behavior, success/failure/cancellation/retry semantics and group-absence proof.
Keep the lock/record/resource lifetime bound to unfinished workers, or quarantine
durably where absence cannot be established. A current successful readback after
an ambiguous native timeout must not authorize clearing state while a late worker
or request can still mutate it. Avoid killing unrelated global services/workers.
Application background services intentionally outside supported containment need
an explicit contract and must not be mistaken for finished signing consumers.

Tests must use real fictional subprocesses, a deterministic rendezvous, and late
use/mutation after parent return; timeout, KeyboardInterrupt, descendant survival
and parent death; assertions must precede fixture cleanup. Require bounded output
capture at the runner boundary (not only a bound checked after unbounded PIPE
collection), finite cleanup deadlines and explicit unresolved-state errors.
Retain QA-002's isolated authenticated-profile worker requirements.

### R1-M4 — reconcile busy admission with the real preflight entry path

R1 promises rejection before profile authentication/P12 processing, but merely
adding a lease inside the temporary signing context cannot enforce it for CLI
preflight:

- `preflight.py:939–944` invokes `validate_signing_material` first.
- `credentials.py:1497,1510–1539` authenticates profiles and extracts P12
  material there.
- Only later does `preflight.py:1036–1061` enter materialization/signing.

Define the actual admission boundary and explicit borrowed lease/cancellation
propagation to avoid self-deadlock or a check-then-release race. Distinguish
read-only signing validation without a build from sessions needing global state;
do not unnecessarily serialize Android or Store-only operations. Keep all
existing validity/fingerprint/entitlement checks; removing duplicate validation
without proving equivalent checks is not an acceptable solution.

Add a real preflight caller test with an already-held same-account lease and
assert no denied invocation reaches the prohibited native/authentication work.
Direct-context-only tests do not prove the promised consumer behavior. This
change must not quietly waive the original finding's rejected-busy requirements
or claim QA-004's independent outer owner has been fixed.

### R1-M5 — make native/account assumptions explicit in implementation tests

The revised model should cover the source-backed native state transitions above,
literal newline-delimited quoted output (including spaces, backslashes,
non-ASCII and rejected embedded quotes/control syntax), initial empty search
lists where supported, and full before/after default/search state. Verify every
failed/skipped setup path performs no unauthorized activation and every cleanup
conflict remains an error, even if independent safe cleanup succeeds.

Account-home/UID validation must apply to both admission and recovery. Explicitly
state root/mismatched account-domain and nonlocal-filesystem support policy:
Apple `defaultPreferenceDomain` at StorageManager80–100 may select the system
domain for a root security session, unlike explicitly observed `-d user`.
Do not assume a successful flock syscall proves arbitrary network filesystem
semantics. Noninheritable FDs prevent exec inheritance, not raw fork inheritance;
include a forked-holder case or an explicit tested host restriction.

Borrow only exact active toolkit cancellation ownership, never a handler name
or a foreign custom callback. Tests should compose the actual broadened consumer
with nested read/authentication/installer owners and real INT/TERM at acquisition,
body, cleanup entry/dispatch, phase journaling and restoration. The current
standalone helpers' passing tests are not evidence that new outer composition is
safe.

## Verification and delivery implications

The next revision should be independently reviewed again before any production
edit. Once approved, a distinct actual-diff implementation review and the complete
frozen verification suite remain mandatory. No test, new module or documentation
was edited by this reviewer. No Git index/branch/ref was changed. AGENTS.md retains
SHA256 `7a520b569d674ad637be886c400f88d38c294b36f925595ca1f3b479526757eb`
and remains the sole untracked user file. Reviewer started no build/background
workers and removed all synchronous probe scratch.

QA-003 remains open. QA-004 and all remaining original findings remain separate,
unwaived blockers; the mandatory fresh whole-repository audit still follows.
