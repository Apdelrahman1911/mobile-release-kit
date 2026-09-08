# QA-003 R6 persistent native-active verification plan — proposed

This fulfills required R2/final-R3 verification and QA003-IR1-G01. It is not a
separate confirmed production defect, permission to weaken recovery, or approval
of the current implementation. R4 is development-tested; R5-R2 remains under
review. No R6 implementation has started. Baseline HEAD2beb373/tree00f3acee,
with the pending scoped QA-003 diff; user AGENTS remains unchanged/excluded.

## Reanalysis and actual missing proof

The current exhaustive local_signing_crash_fixture.py covers real protocol I/O,
but never creates/activates a native keychain or executes a build. Its recovery
constructs NativeSigningModel anew, resetting preferences/keychain to baseline.
Thus it cannot prove that original actual active preferences/resources survive
process death and are conditionally reconciled. Retain that useful protocol test;
it cannot substitute for the missing active matrix.

The independent implementation review's native_probe.py persists fictional native
state across48 native-result cuts. It observed42 fully reconciled baselines and6
correctly pending unrecorded DB transaction identities. This is useful positive
evidence, not an exhaustive control-I/O matrix. Neither probe establishes actual
credentialed Security/Xcode compatibility.

Root reanalysis inventory author-native-matrix-inventory-r1.py/json executes the
complete production signing context with modeled native tools plus an actual
session.run(kind=build). It measures1276 control/resource boundaries in0.040s:
327open,312fsync,323close,150write,150replace,6mkdir,1link,5unlink,2rmdir;
572setup,264active,440cleanup;49 native calls. This was only inventory, not crash
verification. Its synthetic tree was removed and no child/native tool ran.
The volume motivates a warm isolated sequential fork harness, not skipping cuts
or weakening fsync/ownership checks to fit CI.

## Exact behavioral change: verification only

Add a persistent fictional-native adapter and isolated crash harness under tests.
Do not change production recovery or schemas just to satisfy the model. Any newly
reproduced production defect must be recorded, separately planned/reviewed and
fixed before this verification can pass. Public docs will distinguish the new
test coverage from real Store/signing suitability, not strengthen unsupported
platform claims.

### 1. Durable native state independent from recovery authority

The adapter persists observed complete default/search preferences, original
fictional baseline, exact keychain location and transaction revision outside the
production lease/session namespace. A fresh adapter MUST reload them on recovery;
if its state exists it cannot reset to baseline. Production never reads this
test state or uses it as journal authority. Persist only fictional information,
event labels and owned-resource identities/hashes; never record actual native
password argv or read a real user home/keychain.

Execute actual _temporary_apple_signing_environment, actual lease/session/profile
installer, durable intent/checkpoint/completion and production cleanup. Patch only
the external credential-authority/native tool boundary with the existing known
fictional profile and private tool adapter. Include create/settings/unlock, P12
extraction and key/certificate/chain imports, partition-list, activation, at least
one actual session.run build transaction, restoration and deletion. Include both
observed preference fields before/after every production mutation. R5's separate
actual run_ios_build tests cover prepare/archive/export caller dispatch; this
matrix tests persistent native lifetime, not artifact-signature acceptance.

Native transactions create actual0600 DB/staging/sidecar files in the fixture's
owned directory and actually replace DB inodes. Model create/lock, transaction
staging/write/rename, each preference update, and DB/sidecar deletion as discrete
effects. Persist observations after each effect before cutting, so recovery sees
the effect that really happened. Include optional create auto-add to search as a
focused model variant, alongside current supported non-auto-add behavior.
No security, codesign, openssl, Gradle, Xcode, network or Store command executes.
The adapter must reject every unmodeled command and reject setup/build during
recovery; it may only observe, conditionally restore preferences or delete a
resource that production proved owned.

### 2. Enumerate real boundaries without test-journal fabrication

Inventory a complete successful active context, recording stable operation,
caller/phase/slot and occurrence. Wrap actual production open/write/fsync/replace/
unlink/rmdir/mkdir/link/close syscalls (plus buffered profile write/flush if needed
to expose its byte-write cut). Ignore test-oracle/log I/O by explicit frame/source
classification, not broad temporary path assumptions. Do not replace production
checkpoint or mutate the JSON to simulate cuts.

For EVERY inventoried production boundary replay from a new fixture at both
before and after effect; at each write add a partial-write cut (first nonempty
prefix then abrupt exit) and preserve the zero-length layout at before-write.
An expected failing syscall also has a recorded after-attempt edge, accurately
distinguished from an effect. Check the selected stable descriptor matches the
inventory; a changed path/ordering must fail the harness, not silently test a
different boundary. Include native-before/native-after boundaries and intermediate
native filesystem/preference effects to exercise result/checkpoint ambiguity.

Crash with os._exit in a child executing the actual production flow, so Python
cleanup does NOT run. Parent waits for that exact child before touching resources;
kernel closure releases descriptors/lease. Verify the actual recorded fixture
process/group is absent. Then construct a NEW adapter from disk and invoke the
production status/recover entry. Do not transplant session trees into another
path/inode or forge intent/worker controls. The adapter's worker handoff may use
the actual fixture process identity; it performs no real native child operation.

Also inventory an actual recovery run from a retained known-inode active-build
checkpoint. For EVERY recovery control-I/O/native-result edge reconstruct that
original live layout, crash a separate recovery child at the edge, and use a third
fresh adapter/recovery invocation. This proves interrupted recovery and terminal
cleanup, not only original-context cleanup. Never create a new baseline from the
current active preferences. Bind all cut results to the package under test.

### 3. Precise success and conservative manual-recovery oracles

Before any fixture fallback record: model preferences, native/profile identities,
committed/pending/completed controls, status, automatic recovery result, and fresh
admission result. A successful automatic recovery must have no owned DB/stage/
sidecar/profile/reference left, complete expected preference state, idle/absent
session and renewed account admission. No journal editing/deletion outside the
production API is allowed. Completion-marker-only/final-empty states must neither
restore historical preferences nor repeat native setup.

For a refused automatic recovery accept ONLY independently established documented
uncertainty: an actual unrecorded/different native inode or native staging, or
unrecorded/incomplete profile ownership/content. Assert pending/busy admission
and that production did not delete/adopt that unknown resource. Do not treat an
arbitrary CredentialError as expected, or clear everything to hide a production
bug. Intact original authority must remain until real resources are reconciled.

The test has a separate owner oracle obtained from actual fixture creation/effect
observations, not journal claims. Exceptional interactive recovery uses real TTY
test streams and production --manual-equivalent API holding the account lease.
Before resolving, assert another admission reports busy. The fictional owner can
detach ONLY a preference still exactly pointing to its proven keychain, preserve
foreign search order/deletions, and move/delete ONLY a resource whose observed
inode and fictional content agree with the independent owner record. Never edit
controls or remove a resource merely because its name is reserved. Recheck uses
production recovery; recovered-with-conflict is reported distinctly from success.
Assert known uncertainty actually occurs, rather than relaxing all cases into
manual success. This does not grant a real CLI force-cleanup facility.

### 4. Adversarial persistent-state cases

Keep unrelated fictional keychain/profile/files as sentinels across the base
matrix and assert full identity/bytes/permissions unchanged. Add focused crash/
recovery cases at active, post-native-result, partial restoration and terminal
phases with: foreign default, modified/reordered/deleted search entries, borrowed
same-UUID profile, foreign profile replacement, same-inode edited owned bytes,
unknown native stage/replaced DB and terminally reappeared resource.

Expected before/after state is computed from independent fixture actions and
original baseline, not production helper return values. Foreign edits must be
preserved, conflict status must be accurate, unknown resources must stay pending,
and a manual recheck WITHOUT owner resolution must still refuse. The harness must
not relabel unresolved or conflicted cleanup PASS. Corrupted committed authority
is a refusal case, not an invitation to manual-delete journals; existing malformed
control tests remain mandatory.

## Harness reliability, portability and cleanup

Use one isolated `python -I -S -B` fixture launcher with the explicitly selected
source or installed package root. Import/warm once, then sequentially fork
single-threaded workers before acquiring production resources. Each case has a
fresh private root and no other task's handles/processes. The parent never owns
an active production lease at fork. Each fixture child owns its new process group;
record/wait the exact child and use deadline/owned cleanup on harness failure,
never a global pkill or journal PID. Preserve evidence BEFORE cleanup.

No concurrent cut workers: bounded RAM, no load-dependent scheduling oracle.
The parent verifies worker/thread/FD disposition and removes only its disposable
fixture after every case. Any failure emits full sanitized cut identity/state;
the outer unittest and final gate cannot falsely pass a timeout, skipped group,
unexpected return code or missing result. Recovery parent worker handoff records
must not accidentally point at the still-running test driver on a later retry.
Use a fresh recovery child where needed to prove death, not a fake missing PID.

Mac/Linux POSIX are supported for modeled recovery; required macOS/native and
installed-wheel groups must run without skips. Test fixture imports may come from
tests, but production module paths must match the supplied installed package.
Do not use macOS private data/native APIs for the model. Existing separate ABI,
CMS and real-process native tests remain required and cannot be replaced.

## Files, regression/security concerns and documentation

Expected files: a separate persistent helper in tests/unit, a native-active crash
fixture in tests/workflow, test_local_signing_recovery.py (or a new matching
test_local_signing_native_recovery.py), and explicit required native/wheel pattern
inventory if a new test file is used. docs/local-signing.md and implementation
notes state protocol-only versus persistent native-active test coverage. No
product/config/schema/Store behavior change; no extra runtime dependency.

Principal risks: a model that resets state or assumes the intended result,
unobserved missing branches, error swallowing into manual acceptance, journal
fabrication, inherited FD/lock/finalizer authority, fixture-created process leaks,
source imports shadowing wheel tests and excessive CI time. Verify trace coverage
and independent oracles; measure actual development execution time. Optimize
test setup/import/log work only, not production fsync/validation or cut count.
If required CI deadlines cannot fit the complete matrix, propose a separately
reviewed gate partition preserving all cuts/source+wheel coverage instead of
silently skipping/time-relaxing validation. Current37-gate runner has900s per gate;
CI Linux/native jobs20min. Unavailable/timeout is FAIL, not passed.

## Verification and acceptance

Obtain independent plan approval before writing the test implementation. Run the
new fixture/matrix with result counts for before/after/partial/native/recovery,
normal versus conflict/manual/refused outcomes, full retained before/after state,
no setup/upload in recovery, final renewed admission and per-case cleanup. Preserve
the original deficient and partial-positive evidence honestly.

Require distinct actual-diff reviewer to inspect both production recovery and the
independent model/assertions, actively challenge ownership/manual fallback, and
verify the intended matrix is exhaustive for its inventoried paths. Rebind the
complete QA-003 file inventory, obtain whole implementation approval, freeze and
run the entire project gates plus source/native/installed-wheel checks. A further
source/test change invalidates the freeze. Only then scoped protected QA-003
delivery/main CI. QA-004/005, MRK-008/009 and the mandatory fresh entire-repository
audit remain required; native/Store credential suitability stays an explicit
external non-public rehearsal requirement, not a modeled PASS or READY shortcut.
