# Shared version reservation → existing saved-version editor

## Scope and delivery

This packet connects the previously implemented allocator to the existing native
Source, selected-account HTTP, application-state, and ReleaseVersion edit owners.
Manual version editing remains the default. Nothing reserves or writes on mount,
navigation, status, or changing the policy form.

Initial automatic admission is deliberately limited to an iOS-only saved project,
its current checked-out `refs/heads/*` branch, a connected repository counter, and
the original current-visible App Store inventory receipt. Build/patch/minor/major
use the existing v2 policy and allocator. The whole-number iOS build range remains
1–9999. Android, tags, a missing Store connection, incomplete inventory, dotted
build numbers, or expired/foreign receipts are not counter-only fallbacks.

The UI separately asks to read choices, reserve a number, open the reserved
version, and review/apply through the existing editor. Current inventory is not an
atomic snapshot or all historical uploads. The shared ledger coordinates clients
that use that ledger; it cannot prevent a separate uploader from using a number.
Those limitations require explicit acknowledgement and remain visible in the UI.

The owned commit contains six Rust leaves, two Python leaves, their two Python
test files, the three frontend leaves and one Node test file, this guide, and two
Root-only integration patches. Shared files are **not** silently included in the
owned commit:

* `version-reserve-native-hooks-20261020.patch`: 36 native/frontend targets.
* `version-reserve-python-hooks-20261020.patch`: 13 Python targets.

Both patches must be integrated with the leaves. They were composed in isolated
copies against Root `9a4a44b2adb83d12d5f7591ff8486034eee10e0e`, retaining the
current identity, repository, PR/activity, Git-switch, and enrollment additions.
Both also passed read-only `git apply --check` against Root
`8f4ea7a2ecfa8a545272f949650f65bc9b3804a3`. Root files were not edited. Apply each
patch once; the 13 Python hooks were tested as actual own-worktree edits, not
shadow modules, and remain separate from the leaf commit.

## Original lifetime and durable effects

```
read/review: original Source observation and original Store/P8 receipt
    |
explicit Reserve: one original 60s work / 70s hard endpoint
    same Host ProjectBinding + NativeUse + retained native state jobs
    durable exact candidate selection (OS-random once, never on retry)
    original Source/CLT and selected-account HTTP invocation
    Pending -> actual durable state ACK -> source check -> sole conditional PUT
    final source check -> state ACK -> worker FIN/EOF
    actual IO/child/native Source/runtime/management/final-observer joins
    actual NativeUse retirement; original StateError/cutoff retained
    |
Reserve Source has actually CLOSED; its snapshot is comparison DATA only
    |
explicit Open: consume-once NativeReservedVersionHandoff -> same Edit Session
    fresh own GitReadSources in the EXISTING Edit inspection job
    existing acquisition job postchecks and original publisher GO
    actual Python LocalSource lock held for this edit invocation
    explicit Preview -> explicit Apply through the transactional version writer
    source postchecks -> existing consuming-close job -> actual Edit retirement
```

There is no second executor, copied allocation algorithm, generic namespace
writer, or renewed per-stage deadline. User review time after Reserve consumes the
same remaining original window. Expiry refuses the edit, retaining the reservation
rather than minting another number. The existing candidate/request/checkpoint and
pending semantics remain authoritative after restart. A retry never silently
renumbers; explicitly choosing another candidate requires the retained previous
request identity and cannot replace an unresolved pending allocation.

Every HTTP write follows its genuine durable Pending ACK. State-job installation,
joins, pure same-Document currentness, and ACK release reuse the original finite
dialogue. A source change after a possible write suppresses publication without
recycling the row. Lost ACK, conditional conflict, cancellation, incomplete joins,
or uncertain state durability are not automatic retry loops. Original errors and
minimum first-failure/cleanup endpoints are retained, including successful token
retirement followed by a late return; retirement is not retried. A refusal before
any original Source/state entry may finish only with the exact untouched custody
and no joined Source; it is not mistaken for an unretired NativeUse. A state step
rejected before any job is registered releases its original reply with error so
the reader/channel can drain. Registered or partially entered jobs are retained
through their actual join; this path never manufactures an ACK.

## Reserved edit is not renderer authority

`NativeReservedVersionHandoff` is neither cloneable nor serializable. It moves
once from the actual reserved native ticket into the actual ReleaseVersion
Session. It binds the exact candidate, source, ledger/counter, allocated values,
root, Store/P8 context, account, original clock, and saved registration. The new
RAW commands accept UI intent/opaque original IDs only, never a source, floor,
candidate, token, arbitrary executable, or namespace path.

The only intentional invalidation exception is the original authorized
publisher chain:

`Open → Opened → Prepare → Prepared → Apply → Terminal → Retired`.

Each phase matches that original publisher's serial and exact pre-epoch, then
accepts its returned post-epoch (+1). Foreign interleaving, a replaced/failed
publisher, duplicate phase, or poisoning fails the chain permanently. It never
rebases to whichever epoch happens to be current. Global observations remain
invalidated normally. Credential/material/account/Document/root/branch/time and
cancellation checks are never waived by the chain.

Reserve's closed native descriptors grant no Edit access. A distinct retained
instance of the existing `GitReadSources` inspects the actual current sources in
the editor's existing job, compares to the previous DATA, postchecks before GO,
and closes under the same editor's consuming-close custody. Source postcheck
failure does not skip original close. A normal successful terminal's input-close
STOP is not mistaken for a user cancellation; genuine first-failure, uncertainty,
and actual join checks still govern finality.

Python's `BorrowedReservedVersionInput` supplies a flock borrower only to the
same live `LocalSource`/Invocation and the actual `LockedInitScope` with the
ReleaseVersion profile, exact registered root/phase, and retained original FD.
The scope opens and closes its own descriptor; it never unlocks the borrowed
source description. Ordinary init/editor locking is unchanged. After the actual
transaction, only the exact owned version-file successor and its expected Git
status are allowed. Other paths/control bytes/parents still have to match. The
actual committed effect remains retained if source closure later fails; that
failure cannot admit a second Apply or manufacture a settled result.

## Central hooks and bounded custody

The five main-window RAW commands are `version_reserve_status`,
`version_reserve_review`, `version_reserve_start`, `version_reserve_cancel`, and
`version_reserve_edit`, each at most 8192 bytes. Fixture rejection, lifetime/window
checks, native app-data selection, and supported-target refusal remain native.
Build/handler/capability and installed-observer module declarations are included.
There are no public bytes/credentials/state RPCs and no extra relay task.

The native Source code reserve remains 128 MiB, separate from the existing
16 MiB retained Document/non-code admission. Reserve's finite quote includes the
8 MiB bounded-state reservation, actual GO/output backing, and fresh Edit-source
and handoff backing; actual retained census/admission remains required. State
uses the existing enrollment-only 256 KiB/4096-node limits, preserving the full
original failed snapshot rather than resetting/truncating it. These are retained
data/frame bounds, not an OS RSS or Python-heap guarantee. Existing FD/reader and
runtime ownership checks remain separate; no new whole-process FD credit is
inferred from a single reader's cap.

Reciprocal admission/GO checks cover existing Source/Git, enrollment,
repository/PR/activity/publication, saved operations, edits, and other native
owners. Connected idle GitHub is allowed only for this reserved edit path;
manual editor and every unrelated-owner veto remain unchanged. The UI retains
old promises/status/STOP controls across context or API changes, checks again
after subscriber notifications, and never replaces a pending/unknown owner.
Manual dirty drafts are not overwritten by an unrelated reservation. The final
handoff opens only through the native original and adopts its exact checkout.

## Focused evidence and remaining qualification

Actually joined own-worktree tests (fake provider/ACK and synthetic private files,
no real Git/Store/provider processes or credentials):

* `PYTHONPATH=src:tests/unit python3 -B -m unittest test_version_allocation_source`:
  36 passed (1.903s).
* Same command for `test_desktop_version_allocation_runtime`: 13 passed (0.350s).
* Same command for `test_desktop_version_reserve`: 6 passed (1.277s).
* Same command for `test_reserved_version_edit`: 6 passed (1.855s).

The writer tests include synthetic Reserve followed by the real temporary-file
preview/apply transaction, persisted retry with the same candidate and one PUT,
real foreign-root descriptor refusal, original-source closure before borrowing,
unrelated source drift, and committed-effect retention after a close failure.

Node's inert `--experimental-strip-types --test --test-concurrency=1` run:

* `desktop/tests/version-reserve.test.mjs`: 13 passed (189.369ms).
* The six `^reserved handoff` cases in the isolated projected existing
  `release-version-edit.test.mjs`: 6 passed (481.192ms).

Logs are retained in the task-owned `.task-version-reserve-hooks/` directory,
not packaged. Six new Rust leaves passed `rustfmt --check`; all 28 projected
shared Rust targets parsed with `rustfmt --emit stdout`. Shared Python AST,
capability JSON, whitespace, and both Root patch apply checks passed. These are
syntax/source checks, not a compiled graph or runtime proof.

Nine new Rust tests are defined but **not executed in this lane**:

* `reserve_intents_never_accept_renderer_source_floor_candidate_or_token`
* `reserve_first_failure_and_original_cutoff_only_contract`
* `uncertain_state_facts_and_late_return_never_release_reserve`
* `native_namespace_selection_retries_exact_request_without_renumber_or_reset`
* `native_enrollment_repository_substitution_preserves_full_snapshot_before_refusal`
* `reserved_version_publications_are_exact_original_phase_successors`
* `foreign_or_failed_reserved_publisher_never_rebases_the_chain`
* `unentered_reserve_state_is_not_confused_with_entered_or_unknown_custody`
* `stopped_unregistered_state_request_releases_error_reply_and_drains_channel`

Root still must compile the composed Rust/TypeScript graph and qualify the actual
Mac runtime, Store/HTTP custody, original publishers and full Reserve→Edit path.
No real provider mutation, credential use, native run, Cargo build, or package
qualification was performed here. CLI/CI do not yet consume this native route;
they must use the same enrolled ledger/candidate and their genuine source/Store
owners, not treat Desktop DATA as transferable authority. The existing v1 strict
Store contract and immutable mixed-version ledger replay are not weakened.
