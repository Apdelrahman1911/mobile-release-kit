# QA-003 R6-R3 — bounded complete source/native/wheel matrix gates

## Measured cause and scope

This is the gate-partition review explicitly required by approved R6/R6-R2 when
the complete matrix cannot fit existing 900-second gates/20-minute CI jobs. Do
not reduce cases, replace production fsync/validation, skip tests, or increase
deadlines to disguise incomplete verification.

The development base matrix inventoried 1,399 actual production/native-effect
boundaries and passed 2,961 before/after/partial cuts in **541.955 seconds**
(`development-r6-original-r1.log`). All exact case children/groups were absent
before per-case disposal. That early run kept target/outcome records but not the
now-required compressed complete before/after snapshots; it is development
evidence, not final acceptance. The later harness retains complete actual
snapshots/control contents/unknown-resource observations before disposal.

Actual recovery inventories contain 21,116 further cuts (35 distinct representatives
and seven observed equivalents) across explicit
preparing/initializing/profile/native/active/partial-restoration/terminal/manual
seeds, after exact ordered-IO/visited-line/disposition equivalence checks. The
additional known-active pending-control seed is included in the latest inventory.
One complete representative, `active-before-build/none`, passed 1,308 cuts in
**163.848 seconds**, including real third-child reconciliation and compressed
before/after evidence (`development-r6-recovery-active-r1.log`). The combined
matrix cannot fit one existing gate, much less both source and wheel in one native
job. R6 remains under implementation; no final matrix/implementation approval.

## Concrete partition and unchanged coverage contract

1. Add a test-only runner `tests/workflow/run_local_signing_matrix.py`, using
   the warm sequential supervised fixture already being implemented. Define
   exactly **16 shards** in one inspected test constant; each selects by SHA256
   of canonical logical case identity modulo 16. Identity includes seed/manual
   mode, operation, normalized slot/destination, origin, phase, occurrence and
   edge, but not ephemeral paths/PIDs/inodes or global event index. Index remains
   mandatory for verifying the selected edge within that launch's inventory.
   This avoids Python hash-randomized set iteration moving logical cases between
   shards across isolated source/wheel/CI processes. Reject out-of-range,
   malformed, duplicate, empty, or unknown selections. No environment skip flag.
2. Every shard independently inventories all required original/recovery seeds,
   verifies real pending-slot removals, exact equivalences and mandatory manual
   branches, computes the complete expected case-ID set, then executes EVERY
   assigned before/after/partial/native/recovery cut. Assert selected IDs and
   result IDs match exactly; all 16 sets must be disjoint and cover the full set.
   Record complete-inventory digest, package hashes, selected IDs/digest, counts
   by edge/seed/disposition, exact child/group cleanup and raw compressed
   before/after evidence. Any missing cut, mismatch, timeout or unexplained
   refusal fails; manual/conflict/refusal are not silently called automatic PASS.
3. Add focused unittest coverage for canonical partition stability across event
   reorder, disjoint union/no omissions, invalid arguments, package selection,
   group timeout/parent-loss behavior, full happy flow, real TTY manual paths,
   borrowed profiles, auto-add and foreign/edited/reappeared resources. Existing
   exhaustive protocol-only tests remain in unittest. Register the new focused
   group in required native/wheel patterns with zero skips. The expensive full
   persistent matrix is an explicit separate REQUIRED gate, not a skipped test
   hidden inside ordinary unittest discovery.
4. Add one credential-free matrix job to `.github/workflows/ci.yml` with
   `os: [ubuntu-24.04, macos-26]` and `shard: [0..15]`; retain 20-minute timeout,
   `contents: read`, no secrets/environment/OIDC/Store authority, full Action
   pins and the pinned Python/Xcode baseline. `fail-fast: false` ensures sibling
   partitions still produce their evidence. Bound CI matrix concurrency using
   `max-parallel: 4` (local fixture workers remain sequential).
   Each VM executes its complete assigned shard against BOTH explicit checkout
   source and an isolated wheel installed outside the checkout. Compare complete
   inventory/selected IDs and production-file hashes between source/wheel. Wheel
   imports cannot shadow checkout modules. No real keychain/signing/Store tool
   runs in this modeled job; existing native ABI/authority jobs remain mandatory.
5. Preserve protected aggregate `test`; add the new matrix job as a mandatory
   dependency. Its always-running shell gate requires Linux, native and entire
   signing-matrix job results all exactly `success`. Failure/cancellation/skip of
   ANY partition blocks merge. Add behavioral result-combination tests and
   contracts proving the full OS/shard product, source+wheel execution, no
   permissive conditions, required timeouts/permissions and pins. Use only fixed
   matrix values in shell, never untrusted application/ref interpolation.
   A success-only aggregate is NOT sufficient: every matrix VM must upload a
   mandatory compact proof containing expected logical IDs, actual source/wheel
   executed IDs, package/test-definition hashes and repository/run/commit/attempt/
   OS/shard scope, only after both executions and their equality check succeed.
   Use pinned artifact Actions and immutable fixed-prefix names including OS,
   shard and the actual producing attempt. Missing proof upload fails its cell.
   The aggregate downloads ONLY this workflow run's matching proof artifacts,
   runs a strict bounded-schema reducer from its pinned checkout, and requires
   exactly two OS ×16 shards ×source/wheel. Per OS, expected inventories must
   agree; all executed sets must be disjoint, complete, equal to the expected
   IDs and match the deterministic assignment. Package and test-definition hashes
   must agree with the aggregate checkout and source/wheel contents. Reject missing,
   duplicate, extra, wrong-scope, malformed or mismatched summaries. Never use a
   matrix job output (last writer wins) as a complete execution proof.
   Preserve legitimate partial reruns: use the latest valid complete proof for
   each OS/shard within this same run/commit (older successful cells can retain
   their own producing attempt). Do not compare every cell against the latest
   global attempt or silently choose an invalid later proof. Duplicate proofs
   for the same cell/attempt are invalid. All candidate proofs are validated
   before selection; aggregate dependency results must still all be success.
   The reducer has only `contents: read`/`actions: read`; no OIDC, credentials,
   elevated Git token or Store-authority boundary is introduced. These are CI
   execution records, not release attestations. Add missing/duplicate/tampered
   ID, mismatched package/scope, stale unrelated run and legitimate partial-rerun
   reducer tests. Large raw snapshots may be optional uploads; compact complete
   execution proofs and final reconciliation are mandatory.
6. A local `--all` mode runs all 16 shards sequentially with bounded individual
   subprocess lifetimes and proves the disjoint complete union. `--shard N`
   records partial scope explicitly and cannot label itself the full matrix.
   The ordinary documented unittest command continues to run all unit/workflow
   tests; documentation must also list this separate mandatory exhaustive gate.
   Final verification helpers add explicit bounded source/wheel shard commands
   and union reconciliation; do not run an hour-long hidden gate under a 900s
   timeout. Local Darwin verification is not a claim that hosted Linux ran.

## Harness, security, retries, compatibility and cleanup

No production, Store, schema, signing policy or recovery authority change is
needed by this amendment. Its only public changes are test/CI/documentation
gates. Preserve the complete original R6 obligations and raw failed development
logs. Seed deduplication must be justified by concrete complete observations;
partitioning cannot excuse missing focused variants or any edge.

Two inherited R6 acceptance obligations are explicit prerequisites, not waived
by equal trace hashes: (a) every retained equivalence must also establish the
initial and intermediate semantic resource/control relations, native effects,
and refusal/owner-authority consequences, with concrete per-equivalent rationale
and observed facts. Equal phase labels, ordered events or visited lines alone
are insufficient; execute a separate representative whenever equivalence cannot
be established. (b) the independent owner must validate current native resource
identity/content BEFORE any preference edit. A keychain replaced at a recorded
pathname is foreign, including when that replacement is the unknown inode that
caused refusal. Add an explicit replaced-DB/unknown-inode adversarial variant;
both automatic recovery and locked owner resolution must preserve that foreign
DB and all preferences referencing it. No fixture owner may turn a production
refusal into a false pass by detaching/replacing a foreign keychain.

Keep independent per-case self-deadline and launcher-loss watchdog, reserved
child/group ownership, actual wait/absence before recovery/deletion and exact
worker-PID handoffs. The outer runner must handle timeout/termination by ending
only its own launcher, letting the independent watchdog end its owned case group,
then checking group absence before disposable cleanup. No global kill, recorded
recovery-PID kill, shared cache deletion, or real private data. Retain failing raw
sanitized facts before cleanup. CI cleanup traps cover wheel/venv/evidence scratch
only after mandatory compact proof upload; optional large raw uploads include only
test evidence, never real credentials. This proof is not GitHub attestation authority
and cannot authorize release actions or compensate for a failed matrix cell.

Retry starts a fresh private fixture and replays the same logical assigned IDs;
it cannot adopt a previous failed case as passed. The immutable original profile,
control and resource oracles remain untouched. Main regression risks are shard
identity instability, empty partitions, source/wheel import leakage, accidentally
omitted gate dependency, timeout or evidence cleanup masking leaked workers, and
calling a subset a complete suite. Tests and reconciliation must prove these.

## Validation and acceptance

Obtain independent approval before runner/partition/CI implementation. Then run
all source and installed-wheel shards locally, measure EACH wall time within the
unchanged bound, run focused/regression/full tests and workflow/actionlint/pin
checks, and obtain DISTINCT whole-diff implementation review. Re-freeze for all
final gates. Normal protected PR CI must execute Linux and native matrix products
before merge; do not bypass unavailable/failed partitions. User AGENTS stays
untouched. QA-003 delivery, other findings and the fresh full audit remain pending.
