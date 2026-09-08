# QA-003 — continue an interrupted frozen verification, without changing code

## Reanalysis and observed cause

The execution controller disappeared while a new user progress/continue message
was delivered. Original tool session77486 is unavailable; its shell did not
persist an exit status. Do not invent one. The actual shard02 runner log records
SIGTERM/KeyboardInterrupt. This is an interrupted verification invocation, not
evidence of a newly confirmed production defect or permission to waive a gate.

`FINAL-CONTROLLER-INTERRUPTION-R1.json` records the actual facts. All37 completed
gate rows are the exact contiguous prefix of the inspected58-command runner,
with exit0/PASS and matching original log hashes. Shards00/01 each have complete
source+wheel proofs. Shard02 has no complete proof or package result and must be
redone in its entirety. Its recorded launcher, case worker and watchdog processes
AND groups are currently absent (non-mutating observations only). No stale PID
was signaled. All19 partial files and original error/log observations remain.

The171-file source, HEAD, user AGENTS and all7 approved verification helpers are
unchanged; `freeze.py --check` passed after interruption. The proposed Git tree
is still `c6319b556696f89b8cea08fb7d95e1d5f09439df`. R3 implementation approval
is unchanged. The retained original wheel and exact outside-checkout installation
remain required and are not disposable until the remaining matrix completes.

## Concrete plan and authority

1. Make no repository implementation/test/workflow/doc/lockfile changes and no
   changes to the seven approved helpers or original freeze. This is only an
   ignored, single-continuation execution adapter plus local evidence.
2. Before resumption, validate the reviewed source/helper freeze, exact original
   runner hash, prior ledger hash, every prefix command/name/exit/log hash, and
   the original interruption inventory. Require exactly37 contiguous completed
   rows, no recorded original controller exit, complete original proof00/01 and
   no proof02. Reuse only completed verified gates, never an interrupted case.
3. Validate the original wheel/installation via the existing `load_owner` checks;
   verify both current package and test-definition byte inventories. Validate
   both completed proofs with the actual existing contract under this local
   scope. Retain all earlier artifacts and all source/wheel original identities.
4. Recheck only recorded task-owned process/group absence without signaling;
   refuse if uncertain. Check the partial tree contains only the recorded real
   directories/regular files, no symlinks or changed bytes. Preserve its entire
   tree by an exclusive no-destination rename into a new ignored
   `interrupted-final-r1/` evidence directory. Preserve copies of the original
   freeze,37-row ledger, runner log and interruption record there. Move the
   interrupted shard02 gate log there without altering bytes. Reconcile hashes
   after moves. Do not delete partial observations or the original wheel/env.
   A staging failure stops; do not silently replace an existing archive.
5. The adapter must execute the actual reviewed `verify-all.py` AST, not a
   rewritten gate implementation. Verify its exact hash first. Change only two
   top-level data assignments: `commands` becomes the original command list
   sliced after the verified prefix; `results` becomes that verified prefix.
   The complete original for-loop (commands,900s bounds, process cleanup, logging,
   fail-fast behavior, exit codes and ledger updates) and terminal summary remain
   byte/AST-equivalent. Assert exactly these two transformations; pass the
   original `__file__` so root/evidence paths are unchanged. No command text,
   deadline, gate, fixture predicate, result or absence check is modified.
6. Record the continuation adapter hash and approved plan/review bindings in a
   new ignored execution record; retain its exact source. Check that hash at
   dispatch. Independent implementation review covers its ACTUAL content before
   use, distinct from plan review. Existing source/helper freeze still applies;
   the additional executor is explicitly separately bound, not misrepresented
   as part of the original seven-helper freeze or shipped toolkit.
7. Start from fresh shard02, running every assigned source AND wheel case.
   Continue all remaining commands03..15, complete-union reconciliation, exact
   owned wheel/build cleanup, pip/JDK/diff/freeze gates. Current final ledger must
   end with exactly the original58 commands, every one actually passed, each
   unchanged prefix row preserved and all new log hashes verified. Original
   controller outcome remains INTERRUPTED/unknown exit; the resumed run has its
   own log and exit evidence. Local coverage is not hosted Linux/macOS coverage.

## Failure, retry, security and compatibility

No Store, credentials, signing authority, candidate, configuration, release
workflow or public-release behavior changes. No real keychain/credential access.
Never move source/user changes, reviewer resources, shared caches or live case
data. The continuation accepts only this explicit original freeze/37-row prefix;
it is not a generic adoption/recovery mechanism. No stale numeric PID mutation.

If any ownership/hash/command/proof check fails, stop and investigate instead of
guessing or bypassing it. A partial evidence move is recoverable from the retained
original hash inventory and must be reconciled explicitly before another attempt.
If the new controller is interrupted, retain its partial gate and recorded prefix;
do not run this one-time adapter blindly against a different state. A failing
test remains FAIL. Any required source/helper correction invalidates this
continuation approval and requires review/re-freeze and complete verification.

## Validation and remaining delivery

Before execution obtain separate plan approval and actual-adapter review. Verify
the transformed module statically: same full58 original commands, exact37 prefix,
21 remaining commands beginning matrix02, identical gate loop/deadlines/cleanup,
separate binding and no Store calls. Exercise adapter preflight read-only before
moving evidence; refusal must not mutate anything. After execution reconcile all
logs, all16 complete source/wheel proofs and actual union, source/helper/wheel
identities, approved tree, cleanup and AGENTS. Preserve negative evidence.

This continuation does not close QA-003, authorize premature commit/merge, waive
protected hosted CI, change delivered counts9/14, or replace QA-004/QA-005/
MRK-008/MRK-009 and the mandatory fresh comprehensive audit/feature report.
