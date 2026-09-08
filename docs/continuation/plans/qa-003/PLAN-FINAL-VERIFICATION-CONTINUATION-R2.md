# QA-003 — frozen verification continuation R2 (fresh identical wheel installation)

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
is unchanged. The retained original wheel remains hash-valid. However, the original recorded
outside-checkout installation is absent: the actual existing `load_owner` check
raised FileNotFoundError before any write or worker launch. No removal by this
continuation or completed cleanup gate is recorded; the disappearance's cause
is unknown. Do not claim that absent environment is still validated. The wheel
SHA256 is `196af66f6ecf8af9981a24b33f21acb4f84ef404f8f64c2fe4b80db8d13c2f11`.
`FINAL-PREFIX-PROOF-RECONCILIATION-R1.json` independently validates current
source/test hashes, exact wheel payload bytes, both complete proofs and all
retained actual compressed result records (1689/1682 cases per package). Those
prior executions remain valid; they are not evidence of a current installation.
Recreate only an isolated installation from that exact retained wheel, not a
new wheel/build. This R2 supersedes the R1 retained-environment assumption.

## Concrete plan and authority

1. Make no repository implementation/test/workflow/doc/lockfile changes and no
   changes to the seven approved helpers or original freeze. This is only an
   ignored, single-continuation execution adapter plus local evidence.
2. Before resumption, validate the reviewed source/helper freeze, exact original
   runner hash, prior ledger hash, every prefix command/name/exit/log hash, and
   the original interruption inventory. Require exactly37 contiguous completed
   rows, no recorded original controller exit, complete original proof00/01 and
   no proof02. Reuse only completed verified gates, never an interrupted case.
3. Validate the original wheel SHA and current source/test byte inventories,
   original owner record, current absence of its exact old path, both completed
   proofs and all their actual compressed executions with the existing contract.
   Record the failed old-installation probe explicitly; do not claim an old
   `load_owner` pass. Both valid original local-scope proofs retain their original
   identities and are not rewritten to refer to the later installation.
4. Recheck only recorded task-owned process/group absence without signaling;
   refuse if uncertain. Check the partial tree against the complete explicit
   `FINAL-INTERRUPTED-NAMESPACE-R1.json` inventory, including root and EVERY
   empty/nonempty directory (not merely file-derived parents), exact types,
   device/inode/mode/uid/gid and file hashes. Reject missing/extra/type-swapped
   entries, links and any changed bytes. Preserve its entire
   tree by an exclusive no-destination rename into a new ignored
   `interrupted-final-r1/` evidence directory. Preserve copies of the original
   freeze,37-row ledger, runner log and interruption record there. Move the
   interrupted shard02 gate log and original `final-matrix-owner.json` there
   without altering bytes; copy the original matrix-prepare log too. Use the
   existing native exclusive-rename primitive (not overwrite-capable os.rename).
   Reconcile hashes after moves. Never delete partial observations or the wheel.
   A staging failure stops; do not silently replace an existing archive.
5. Recreate a new mode0700 installation owner directory outside the checkout
   using mkdtemp under the exact repository PARENT, not the disappeared temporary
   location. Record its exact path/device/inode and the unchanged original
   tree/wheel/package/test hashes before installation, including the canonical
   `owner.json`. Create the venv from the same pinned Python and install only the
   retained exact wheel with --no-deps; run pip check. Use the original bounded
   installation timeouts (venv60s, pip120s, check30s), exact owned process-group
   cleanup and isolated imported-package discovery. Validate the complete actual
   installed package bytes against the frozen source, then `load_owner` must
   pass for the new record. No wheel rebuild or import from checkout is allowed.
   Retain new preparation logs/exit/hash/owner evidence separately; the original
   successful matrix-prepare row stays historical truth, not a present-environment
   claim. This additional verified recreation is required, not a skipped gate.
   Installation failure stops with owned state retained for explicit cleanup;
   no blind retry/adoption of a partial new environment. Final existing
   matrix-owned-cleanup handles only this newly recorded exact directory.
6. The adapter must execute the actual reviewed `verify-all.py` AST, not a
   rewritten gate implementation. Verify its exact hash first. Change only two
   top-level data assignments: `commands` becomes the original command list
   sliced after the verified prefix; `results` becomes that verified prefix.
   The complete original for-loop (commands,900s bounds, process cleanup, logging,
   fail-fast behavior, exit codes and ledger updates) and terminal summary remain
   byte/AST-equivalent. Assert exactly these two transformations; pass the
   original `__file__` so root/evidence paths are unchanged. No command text,
   deadline, gate, fixture predicate, result or absence check is modified.
7. Record the continuation adapter hash and approved plan/review bindings in a
   new ignored execution record; retain its exact source. Check that hash at
   dispatch. Independent implementation review covers its ACTUAL content before
   use, distinct from plan review. Existing source/helper freeze still applies;
   the additional executor is explicitly separately bound, not misrepresented
   as part of the original seven-helper freeze or shipped toolkit.
8. Start from fresh shard02, running every assigned source AND wheel case.
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

Before execution obtain separate plan approval and actual-adapter review. A
read-only --check mode must validate current preconditions and produce its plan
without creating an installation, moving/writing source or rewriting evidence.
Validate its real --check pass and fail-closed paths with fabricated mismatches
in memory, never changes to original records; it must not dispatch gates. Verify
the transformed module statically: same full58 original commands, exact37 prefix,
21 remaining commands beginning matrix02, identical gate loop/deadlines/cleanup,
separate binding and no Store calls. Review native exclusive archival, complete
old-path absence, fresh wheel-install ownership and failure preservation too.
Exercise adapter preflight read-only before moving evidence; refusal must not
mutate anything. After execution reconcile all
logs, all16 complete source/wheel proofs and actual union, source/helper/wheel
identities, approved tree, cleanup and AGENTS. Preserve negative evidence.

This continuation does not close QA-003, authorize premature commit/merge, waive
protected hosted CI, change delivered counts9/14, or replace QA-004/QA-005/
MRK-008/MRK-009 and the mandatory fresh comprehensive audit/feature report.
