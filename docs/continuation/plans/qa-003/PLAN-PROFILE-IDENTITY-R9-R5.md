# QA-003 R9-R5 — complete setup-stage conflicts and exclusive borrowed cleanup

## Status, scope and original evidence

PROPOSED amendment to the independently approved R9-R4 plan, not permission to
implement. R9-R4 remains the base contract; this amendment closes two omissions
in its implementation. No finding is waived or counted as a separate delivery.
Original QA-003/FINDING.md, FINDING-IDENTITY-R9.md, R9-R4 sections B4/B6/B7 and
both composing owners were reread. Independent R9 implementation review rejects
candidate tree `415abe54359828f9244eabac112754267935825d` (173 first-party files,
55 intended changes). HEAD/main `2beb37336fa8002b69f598fe431082606368310d`, branch
`fix/qa-003-local-signing-lease`, version 0.3.0. Real index is unchanged/empty;
user AGENTS.md is unchanged and excluded. No final R9 freeze or gate exists.

Independent negative evidence in `implementation-review-r9/`:

- `probe-setup-stage-errors.py`, `SETUP-STAGE-ERROR-RESULT.json`: initial setup
  stage stat and setup-stage unlink are outside the conflict latch. A one-shot
  ordinary OSError after an actual same-inode chmod causes implicit cleanup to
  stat/unlink the same name again, emit resolved and finalize controls/status
  idle. After-effect unlink also discards original recovery controls. All three
  cases reject signing admission; do not claim successful signing or Store use.
- `probe-reused-ignored-observation.py`, `REUSED-OBSERVATION-RESULT.json`: after
  actual link-EEXIST reuse, `attempted=True`, stage `identity` is set and
  `reused_identity` is set. Borrowed cleanup runs, then the owned-destination
  loop runs too. Its extra stat observes a real same-inode chmod and ignores it
  because `linked=False`. Full context returns normally/status idle. A same-byte
  foreign inode is also ignored by the installer; outer cleanup reports an error
  but finalizes instead of retaining the failed observation. No file deletion
  or Store acceptance is demonstrated. Stable actual-EEXIST control succeeds.

Root replayed both scripts byte-identically in NEW `reanalysis-profile-r9-r4/`.
Five negative cases and the stable control reproduced; these are NOT product
passes. Real files/stat/link/unlink, owners, journals and status execute; only
fictional CMS/native results are used. Original evidence remains untouched and
both exact probe scratch trees were removed; no workers or live Store calls.
Complete development discovery just completed: 707 tests, zero skips, 489.426s,
exit 0 (`development-r9-r1/python-full-development.*`). That pass does not
override these independently reproduced defects and is not final acceptance.

## Root cause and exact runtime corrections

Runtime scope is only `src/mobile_release/credentials.py` unless review proves
another affected path. No new journal fields, schema, native command, dependency,
signing identity, configuration, CLI option or Store interaction is introduced.

### 1. Cover the entire conditional setup-stage removal

The actual stage-removal setup at current lines 1167-1172 must latch the original
stage name when its first pathname stat or its unlink raises an ambiguous ordinary
OSError. Existing identity/metadata mismatches already latch via conflict() and
require_current(); retain those guards. Enclose this narrow stat/identity/check/
unlink block in OSError handling, not the wider event/native/snapshot scope.

- Keep safe FileNotFoundError separate: missing original-owned files require no
  unlink authority. First setup-stage stat or final unlink absence still aborts
  admission as now, but does not invent an ambiguous profile lifetime. Ordinary
  absent-file cleanup remains supported. A disappearance observed by an existing
  require_current comparison retains that comparison's existing conflict behavior.
- For any other ordinary OSError, call conflict(stage) before rethrowing. This
  updates the per-name set and the already-registered outer boolean before
  installer unwind; an entry failure is covered even without ExitStack registration.
- No subsequent implicit read/stat/unlink of that stage name; no resolved event
  or outer cleanup_profile/recover/finish. The original intent/checkpoint stays
  pending for a separate explicit recovery invocation, even if unlink took effect.
- Independently safe cleanup of the other owned destination, native resources,
  and all raw handles still runs. Do not turn this into blanket retention or
  weaken the stronger fatal lifetime/quarantine rules. Direct typed fatal errors
  and cancellation keep their current classification/propagation.
- Keep the stage variable until unlink returns successfully, so an after-effect
  error cannot pretend the operation was observed complete. Keep fsync and the
  stage-removed event after successful unlink, with existing error semantics.

### 2. Use one destination cleanup role per admitted observation

At current cleanup lines 1033-1058, once reused_identity is non-None the
destination is borrowed, not the installer's original-owned stage link. Prevent
the subsequent owned-destination branch from inspecting it again. The borrowed
branch remains responsible for its initial stat, bounded read, full initial/read
comparison and final post-close pathname comparison, including metadata.

- Gate owned-attempt cleanup on reused_identity being None (or equivalently make
  the branches role-exclusive without skipping independent stage cleanup).
- Keep the owned branch when a real link succeeded but reported an interruption,
  or an EEXIST result refers to the original writer inode: no borrowed identity
  is recorded then. Do not gate only on linked=True, which would strand a link
  that succeeded before its syscall outcome became ambiguous.
- Preserve initial-existing borrowed cleanup (attempted=False), real foreign
  EEXIST reuse, partial-stage cleanup and all no-clobber/identity checks.
- The LAST borrowed destination observation must actually be validated. Remove
  the unused observation rather than introducing a later unchecked stat. Tests
  must inject a real change at the new final boundary, not silently stop firing
  because the old fourth observation no longer exists.
- Do not persist ephemeral metadata. Fresh explicit original-session recovery
  can re-observe stable original inode/hash. Borrowed foreign/missing state is a
  conflict, never ownership; native-preference-only handling is unchanged.

## Affected callers, compatibility, security, retry and recovery

The only runtime installer caller is the composing local Apple signing owner;
the raw helper also has fixture/test consumers. Both normal and failed entry
must be exercised. The new behavior applies to local signed preflight on a
shared account, not hosted Store authorization or promotion. QA-004 outer
materialization and QA-005 source validation remain separately required.

The current direct installer test asserting every stage-unlink error leaves no
files encodes the unsafe implicit retry. Update ONLY that row to require a
reported error, no same-name retry and exact retained owned stage before fixture
fallback; keep all partial-write/flush/fsync/link cleanup expectations intact.
Composing callers additionally retain original recovery controls and reject new
signing admission until explicit original-session recovery. Legitimate stable
borrowers/owned links, safe missing owned paths and repeated resolved recovery
must not regress. No public candidate version or artifact changes are required.

No real credential material or keychains may be inspected/modified during
verification. Use actual isolated filesystem resources and fictional native/CMS
responses. This correction cannot damage unrelated Store releases because no
Store client or mutation path is changed/invoked. Preserve exact original-profile
ownership, authenticated bytes, account locking and fatal cleanup precedence.

## Regression tests and dangerous-case coverage

Update `tests/unit/test_local_signing_profile_identity.py` and
`tests/unit/test_ios_profile_installation.py`. Existing source/wheel/native
PATTERNS already require these modules; do not bypass or mock the owner away.

1. Setup-stage first stat, final stat, pre-effect unlink and after-effect unlink:
   use one-shot ordinary failures and actual chmod/identity observations. Exercise
   original-owned link and real EEXIST borrower. Assert no signing/native-create/
   import/build admission, no stage observation or unlink after failure, no
   resolved/terminal controls, original intent/checkpoint retained, independent
   safe destination/native cleanup and all acquired FDs closed BEFORE fallback.
2. For each ambiguous setup failure, run actual fresh-process CLI recovery with
   exact original controls and fictional native model. Prove stable original
   remaining stage is removed, borrowed file preserved and status becomes idle
   only after explicit recovery. Preserve original intent bytes/identity and no
   replacement session creation. Include after-effect unlink with no stage left.
3. Known-owned first stat/final unlink FileNotFoundError: actually remove the
   stage through the fixture, not fabricate a value. Admission fails, safe other
   cleanup completes, no false pending requirement. Keep initial destination
   absence, partial stage writes and other R9 safe absence controls.
4. Real-EEXIST borrowed cleanup must have no unused owned-loop observation.
   Track actual reads/stats/unlink names for stable control; inject same-inode
   metadata, same-byte and different-byte foreign replacement, and disappearance
   at the actual LAST remaining post-close borrowed observation. Each changed
   case must fire, preserve the borrowed/foreign result, raise controlled error,
   retain pending controls and complete independent native cleanup. Then exercise
   original-session recovery with correct recovered/recovered-with-conflict.
5. Real link-after-effect EEXIST/interruption owned control must still clean the
   original writer's destination and stage safely, including stage-error paths.
   Stable borrowed hardlinks and owned post-stage-unlink ctime/nlink remain valid.
6. Retain all 20 R8 fatal tests and 16 existing identity methods. Re-run original
   reviewer/root probes to a new corrected-expectation namespace. Explicitly
   document the borrowed probe's boundary adaptation; unchanged negative results
   remain. Count actual cases, not inferred snapshot or historic matrix totals.

Main regression risks: overbroad catch swallowing fatal errors, mistaking known
absence for ambiguity, forgetting registration-before-entry, excluding ambiguous
owned-link cleanup, poisoning independent stage/native cleanup, or a test that
passes only because its old injection hook disappeared.

## Documentation and verification/delivery

Clarify `docs/local-signing.md` (and concise credential/troubleshooting/changelog
notes only where needed): ordinary setup-stage inspection/removal uncertainty
also leaves original pending controls; later automatic re-observation does not
authorize cleanup. Stable EEXIST borrowing remains supported. Do not advertise
an atomic compare-and-unlink primitive or protection against non-cooperating
same-UID writes after the final validated observation.

1. Independent plan reviewer re-reads both findings/probes/implementation and
   approves this exact amendment BEFORE implementation. Revise if gaps are found.
2. Implement focused changes and regression tests/docs. Replay negative cases
   with corrected assertions; preserve every failure and clean exact resources.
3. The distinct implementation reviewer inspects the actual whole QA-003 diff
   and amendment delta, independently tests all two-boundary cases and related
   failure/recovery/ownership paths, and binds approval to the new proposed tree.
4. Prepare independently reviewed NEW final namespace/freeze only after approval;
   preserve the seven previously reviewed helper semantics and run all 58 gates
   from zero, all 16 source/wheel shard pairs, and the actual complete union.
   Full Python/Ruby/Workflow/Supply-WIF/Fastlane/actionlint/Bundler/pins/wheel/
   runtime dependencies/native/JDK21/diff/cleanup gates remain mandatory.
5. Preserve the historic unexplained wheel-shard EEXIST FAIL and complete forensic
   installation. These new defects are NOT its established cause. No rerun-until-
   green, acceptance from development passes, prior-gate adoption or lowered bounds.
6. Only then scoped QA-003 commit/protected delivery/main CI. Continue QA-004,
   QA-005, MRK-008, MRK-009, the mandatory fresh all-file/all-release-path audit
   and further confirmed-blocker remediation, then justified READY/feature report.
