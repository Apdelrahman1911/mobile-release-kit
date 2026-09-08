# QA-006 final-verifier preparation correction plan

Scope: ignored verification tooling ONLY, never the six-path first-party R4 diff.
No final gate/freeze/dispatch or delivery is authorized by this plan. Original
prepared scripts and all failed/historical evidence remain retained. Current
R4 implementation review proceeds independently on tree76ee6d092cd256da0fb6228792dff544b68c7aaf.

## Causes and exact corrections

1. Safe-path startup excludes sibling imports. Bootstrap only the exact trusted
   evidence directory before importing process_gate/bindings; protect every
   invoked helper and owner/tool record in the freeze. Test with actual -P and
   PYTHONSAFEPATH=1, not a developer-shell assumption.
2. The gate controller accepts a reaped exit0 without rechecking its deadline.
   Check the same monotonic deadline immediately after actual completion; a late
   observation is failure even if exit0. Maintain one actual unreaped-child
   reservation as sole signal authority. Synchronous spawn/reap ambiguity remains
   UNKNOWN/failure, with no marker/PID-based or post-reap signal.
3. Direct-child exit does not prove group cleanup. After actual reap perform
   bounded, read-only, numeric /bin/ps group observations (no arguments/env/private
   process data). Validate output/status/identity syntax; only absent or definite
   Z rows permit same-group-clear. Indeterminate/live/foreign/unknown state cannot
   pass; one fixed cleanup cutoff may await transient exit, never reset. No
   observation grants signal rights. Bound query time/output and join query child.
   Session-changing/escaped descendants remain outside this generic proof and
   require the existing first-party test-owned lifecycle assertions. Do not claim
   arbitrary descendant containment or use broad pkill/process-name cleanup.
4. Keep cancellation handling through ledger finalization and recheck the flag
   after restoration. A late signal after the last gate must fail the controller;
   nonzero actual wrapper exit is mandatory failure even if a ledger write was
   interrupted. Always record attempted log/open/child/cleanup errors where
   evidence storage permits; preserve unresolved evidence, never adopt partial
   passes. Final ledger status requires all required rows PASS.
5. Replace broad argument-substring worker inspection with validation of explicit
   per-gate ownership/readback records and bounded numeric re-observation only.
   Separate that scoped proof from the complete native fixture-owned proofs.
   A reused or unknown historical group can only fail/retain, never be signaled.
6. Freeze/check the exact CONFIG, all invoked verifier helpers, accepted source
   snapshot/review, owner markers and toolchain identities. Verify QA-006 parent,
   source, final tmp and user-root ancestry/dev/inode, exact root QA-003 snapshot,
   empty real indexes, and unchanged user AGENTS. Recheck resolved executable
   paths/bytes and exact Ruby/Python/Java/CLI/Xcode versions. Record local Xcode
   26.5 versus required hosted26.3 as an explicit external verification difference.
7. Require no existing final dispatch/log/proof/wheel installation or disposable
   build root. Exclusively create an owned empty build root and record its actual
   identity before any build. Cleanup refuses a symlink/replaced root, any unknown
   entry/content, changed source or live/unknown workers. Record exact inventories
   before unlinking only owned byte-proven generated files; never shared caches,
   source, preserved EEXIST installation, other-task outputs or required wheels.
8. Set PYTHONDONTWRITEBYTECODE and explicit -B for verifier-owned -I/-E Python
   invocations (which ignore the environment). Do not change first-party runtime
   bootstrap semantics merely to suppress caches. Any generated cache/egg-info
   cleanup must be explicitly owned, source-bound and after all users complete.

## Verification and failure behavior

Before final dispatch, independently review the actual corrected verifier diff
against this plan, then run preparation-only proofs in an exclusive new namespace:
normal success; actual deadline timeout/owned stop; cancellation after real reap
with zero stale signal requests; exit0 observed after the original deadline;
pipe-controlled live same-group descendant (FAIL/retain, independent EOF cleanup);
unknown spawn/reap fault (FAIL/no signals); log collision; supported/indeterminate/
malformed numeric state; actual SIGINT after last returned gate before finalization.
Use safe static children only; retain hashes/raw observations and join all own
children/injectors. Never direct a stop at a historical group.

Rehearse binding checks/read-only freeze preparation, not final tests, and have
the independent reviewer approve corrected tooling/bindings. Then, only after
DISTINCT first-party implementation acceptance, create one source/tooling freeze
and execute ALL baseline-applicable gates from zero in the unused final namespace.
Any failure stops acceptance; no retry/adoption/new namespace to erase a failure.
The QA-003-only matrix is absent on this baseline and remains mandatory later.
Actual protected PR/main CI and complete final audit remain required. No live Store
mutations, signing account access, Gradle or public release are authorized.
