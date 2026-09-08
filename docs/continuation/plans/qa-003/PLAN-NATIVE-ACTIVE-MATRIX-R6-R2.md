# QA-003 R6-R2 — explicit recovery-seed coverage amendment

Proposed with the complete original `PLAN-NATIVE-ACTIVE-MATRIX-R6.md`
(SHA256 42453510769e130136e91d522ce0bdeb54ee866f8b9ac6ab79182cce4927a39d).
No R6 plan approval or implementation exists. An earlier reviewer stopped
without a verdict; its preliminary coverage objection is valid and addressed
here, not represented as an approved plan. R5-R2 is now approved/partially
implemented; its online-phase amendment is separately under review.

## Recovery inventory is an explicit seed set, not one active checkpoint

The original section 2 active-build recovery seed cannot exercise preparation,
initialization, every interrupted control-stage deletion or manual recheck.
Replace that single-seed requirement with the following bounded, explicit seed
set. Each seed is obtained by running the original production flow and cutting
at an actually inventoried boundary/effect. Do not construct/edit JSON, move
session trees or change their identities. Stable seed selectors assert the
production phase and observed real layout before invoking recovery.

| Required seed class | Branch/effect to cover |
| --- | --- |
| Empty newly created session, native directory absent/present | `load=preparing`, `cleanup_preparation`, empty-session teardown |
| Incomplete/present `intent.pending` before immutable commit | Removal of pending intent without treating it as authority |
| Committed intent with no `state.json`, with/without partial `state.pending` | `load=initializing`, absence checks, initial state checkpoint, stages cleanup |
| Active known-inode native state before and after build dispatch | Worker-absence predicate, inflight clearing, native restoration/deletion |
| Active profile stage before inode checkpoint and after complete link | Conservatively refused unrecorded stage; observed original-stage/link cleanup |
| Post-native-effect/pre-checkpoint changed DB or native transaction stage | Refused unknown inode/stage, locked manual owner resolution/recheck |
| Partially restored default/search state | Independent complete preference observation/conditional restoration |
| Interrupted terminal marker write/commit and terminal teardown | Pending terminal stage removal; completed authority with/without state/intent/native directory; final empty session |

Derive the precise selected edge list from the actual successful/native-effect
trace and its concrete on-disk results. All three production pending-control
removal paths (`intent.pending`, `state.pending`, `completed.pending`) must be
executed with a stage actually present, not only FileNotFoundError fallthrough.
If a seed overlaps another seed's complete branch/control/effect set, deduplicate
only with a recorded equivalence table. Do not claim equivalence merely because
the top-level phase names match.

Inventory every real production I/O/native edge of each distinct automatic
recovery seed. Replay each before/after/partial-write cut via a separate actual
recovery child and recover again with a fresh adapter reloading durable state.
Use the original plan's independent resource/foreign-sentinel oracle. Inventory
both manual recheck refusal (no owner action) and successful owner action/recheck
for the unknown-inode and unrecorded-profile seeds. These also require actual
recovery cut replay through the post-input `load`/`recover`/terminal paths. Wrong
input, EOF and cancellation are focused retained-authority regressions.

Record, assert and report the selected seed class, producing boundary, observed
phase, present controls, native/profile state, automatic/manual branch set and
covered cut counts. Missing seed/branch coverage is a failed test, not skipped
proof. Existing targeted recovery tests remain complementary; they cannot erase
an omitted persistent-state class. No additional production authority or manual
force-cleanup option is introduced.

## Verification budget and honest claims

Measure normal flow, full original-cut matrix and each recovery-seed group before
final gate registration. Keep sequential bounded fork workers, exact child wait,
per-case cleanup and strict outer deadlines. If the full required source/native/
wheel matrix cannot fit current gate deadlines, stop for a reviewed gate
partition preserving every edge rather than reducing cases or labeling a timeout
PASS. Preserve sanitized failure state before fixture cleanup. Bind success to
the actual imported package root and tree; real credential/native Store behavior
remains an external non-public activation gate.

All other original R6 plan requirements (complete production signing context,
durable independent modeled native state, discrete native effects, accurate
dispatch, unknown-resource preservation, unrelated state sentinels, installed
wheel, distinct implementation approval and frozen complete gates) still apply.

## Mandatory buffered-write and harness-lifetime requirements

Independent actual-writer inspection proves the profile installer's `fdopen`
buffered writes do not pass through Python `os.write`. Intercept that real
writer's `write` and `flush` as distinct required boundaries. A selected partial
write must write/flush the selected nonempty prefix through the actual owned
buffer/raw writer and verify it reached the real file before `os._exit`. A prefix
left only in a user-space buffer is not a partial on-disk-write test. Do not patch
profile checkpoint/observer results or pretend a Python syscall wrapper covers
buffered native I/O.

Every sequential case child needs a bounded independent self-deadline and a
parent-liveness check (or equivalent lifetime supervisor), including time spent
in a blocked filesystem operation. The launcher must hold exact child/group
ownership until reaped and ensure descendants cannot survive a launcher timeout
or termination. A plain `subprocess.run` timeout that kills only the launcher is
insufficient. Outer unittest timeout cleanup must reconcile its owned launcher
and exact case worker, and verify absence BEFORE removing fixture paths. Never
signal by a recovery-journal PID or broad executable name. Exercise the harness's
own timeout and parent-loss paths with fictional workers so these protections
are behavioral tests rather than reassuring comments.
