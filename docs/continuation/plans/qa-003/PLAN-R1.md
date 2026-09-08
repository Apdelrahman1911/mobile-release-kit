# QA-003 implementation plan — R1 (proposed; NOT approved)

Original finding: FINDING.md. Updated evidence/callers/native side effects:
REANALYSIS.md and reanalysis-current.py/.json. Baseline2beb373/tree00f3acee;
no production edits before independent approval.

## Root cause and invariant

User-global keychain preferences and temporarily installed profiles have no
shared lifetime owner. Invocation-local snapshots/booleans are mistaken for
ongoing authority. Atomic profile installation solves neither borrowing nor
preference restoration, and native create/delete also change global preferences.

Exactly one cooperating toolkit signing session may use a macOS account at a
time, regardless of project, profile UUID, source directory, process or thread.
The lease lasts from BEFORE profile/native preparation through observed cleanup.
Rejected competitors never borrow/remove the active holder's resources. No
blind original-state replacement, stale-PID takeover or automatic force option.

## Components and exact behavior

### 1. Private per-user lifetime lease (`local_signing.py`, new)

- Determine the real account home from the UID/password database, not the project,
  TMPDIR or an arbitrary HOME override. Reject a default invocation with a HOME
  resolving to a different account directory or mismatched effective/real UID.
  The existing explicit private `home=` test seam remains available for entirely
  synthetic native tests; it is not a CLI/configuration option.
- Use one persistent mode0700, same-UID, no-symlink directory
  `<account-home>/.mobile-release-signing/`. Open/validate it descriptor-relatively
  and take exclusive nonblocking flock on its directory FD. Never unlink/recreate
  that lock directory during normal operation. Validate path/FD identity after
  acquisition and before state writes; reject unsafe permissions, non-directories,
  changed namespace, unsupported filesystem locking and unknown entries.
- Allocate the lease object before acquisition and register its cleanup with the
  existing claimed-once CleanupScope BEFORE any FD/lock/temporary allocation.
  Every FD acquisition/handoff/close has explicit ownership and shared deferral.
  Busy entry gives an actionable CredentialError immediately; no sleep/timeout
  queue, profile authentication, P12 native extraction, or keychain call occurs.
- Held FDs are noninheritable. Cooperating children with distinct opens cannot
  accidentally share the lease; tested same-process and cross-process exclusion.

### 2. Durable private recovery record; no automatic crash adoption

- After authentication, snapshot the complete original native default/search
  settings, then durably write a strict bounded private record BEFORE the first
  profile/keychain mutation. Include format/version, UID, session nonce, canonical
  account/lease identity, original settings, intended owned session/keychain and
  profile paths, profile hash/UUID and subsequently observed ownership/phase.
  No P12/profile/key/certificate contents, password, Store token or secret hash.
- One nonce-named mode0700 session directory under the leased directory contains
  the ephemeral keychain. It must NOT live in the independently auto-deleted outer
  materialization scratch: a failed cleanup must be able to preserve its exact
  owned keychain and recovery metadata without deleting foreign state indirectly.
  Extracted certificate/private-key files remain in the existing private scratch
  (QA-004 separately owns that lifetime).
- Write/update records using exclusive private stages, complete bounded writes,
  fsync and inode-checked atomic replacement under the lock. Never replace unknown
  active state. Register intended profile stage/link names BEFORE mutation and
  observed inode ownership after acquisition through an optional private installer
  observer; ordinary standalone installer behavior remains unchanged.
- Existing record, unknown record version, partial record stage or orphan session
  directory means pending recovery: acquire/release only the lock, then FAIL before
  credential/native work. A dead PID is informational, never removal authority.
- Normal cleanup clears the record last, only after observed native/profile/owned
  filesystem cleanup succeeds. Do not retry an ambiguous descriptor close or call
  native delete on an unknown/replaced keychain.
- Hard termination/power loss and unconfirmed native mutation retain the private
  record and fail closed on future signing. Recovery is owner-mediated inspection
  of the exact record/resources, not automatic replay: document precise steps to
  restore only still-owned preferences, preserve intervening edits, remove only
  verified owned resources and then clear the record under the same lease.
  Provide a protected internal recovery/inspection context using the same lock
  for the documented procedure; no Store action, rebuild or re-sign is involved.
  This retains QA-002's genuine hard-kill limit rather than claiming impossible
  cleanup. No incomplete session can silently become a fresh baseline.

### 3. Observed keychain state, not success flags (`credentials.py` + new module)

- Parse actual `security ... -d user` output as bounded full quoted lines;
  preserve order and literal path values. Require one nonempty default, bounded
  distinct absolute paths, no embedded quote/control/ambiguous syntax. Reject
  invalid/unavailable observations before any shared mutation. No shell parsing.
- Register every native mutation attempt before dispatch. Creation may add only
  the owned keychain to the original search list (preserving every original entry
  and order); nonempty original default must remain unchanged. Accept native
  creation with/without this documented implicit list addition, then record the
  actual complete state. Require safe observed owned keychain identity before import.
- Before explicit activation require current complete state to equal the previously
  observed expected state; fail rather than overwrite an intervening change.
  Retain the existing isolated `[owned keychain]` active search list and owned
  default required by the supported archive/export flow. Read back both fields
  after each setting and immediately before yielding the build environment.
- Cleanup re-reads state even after a native failure. Restore original search only
  when current search is exactly this session's activated list; for an implicit
  creation-only list remove only the owned keychain. For a changed foreign list,
  preserve its other entries/order and remove only an unambiguously owned entry,
  never reinsert historical entries a user removed. Preserve any foreign default;
  restore the original default only while current default is still owned.
- Observed foreign edits cause an explicit conflict/error, not an assertion that
  original settings were restored. Attempt independent safe cleanup nevertheless.
  A retry after complete safe cleanup snapshots the new user state afresh.
- Restore/detach default/search before `delete-keychain` so that native delete's
  implicit preference effects cannot remove another default/search member.
  Require owned path/inode identity, full post-delete settings equality and actual
  owned keychain absence. Readback disagreement never reports cleanup success.
- Nonzero/ambiguous native outcomes are reconciled before any second mutation;
  no blind retries. Catchable cancellation is deferred across mutation ownership
  registration, not across the entire setup/build body. Timeouts/termination where
  completion cannot be established leave pending recovery rather than recycling
  a potentially still-used signing session.
- Native preferences expose no compare-and-swap for unrelated applications.
  The lease serializes toolkit peers and preserves observed edits; it cannot
  exclude an uncooperating same-user tool racing between read and native write.
  Document that concrete external limitation without using it to waive any
  reproducible toolkit-to-toolkit overlap or observed-edit case.

### 4. Cancellation composition and ownership

- `_temporary_apple_signing_environment` remains the registered complete signing
  owner, gains optional explicit borrowed cancellation for future QA-004, and
  acquires its lease before authenticating. Cleanup order: reconcile keychain,
  close installed-profile owner, finalize confirmed session files/record, release
  lease FD, then restore only handlers actually owned by this root.
- Pass the SAME cancellation instance explicitly through `read_profile_bytes`,
  `decode_authenticated_profile`, `authenticate_cms`, `load_authenticated_profile`
  and existing `_capture_profile`/installer borrowing. Defaults preserve current
  standalone/current-upload behavior. Do not blindly nest independent guards.
- Same-main-thread nested independent signing entry must safely reject busy even
  with the first toolkit guard installed. Add a narrow internal acquisition helper
  to borrow an already-installed exact DefaultCancellation handler owned by this
  runtime/thread, or create a new guard when none exists. Reject mixed toolkit
  owners. Do not recognize names/foreign custom handlers as borrowing authority;
  worker-thread/custom-host semantics remain unchanged. Test this composition
  with actual signals at acquisition and cleanup, not only identity mocks.
- Preserve two-level `try/with/finally` cleanup entry/dispatch protection,
  claimed-once ambiguous-close semantics, setup/build interruptibility, primary
  error precedence and independent cleanup attempts. No broad generator deferral.
- Do not fold QA-004 into this issue: materialize_build_inputs and
  _restore_build_targets remain a separately analyzed next owner. New signing
  lease/record/session resources must all be protected now, not excused as QA-004.

## Tests and adversarial verification

1. Stateful synthetic native adapter faithfully implements explicit and implicit
   create/delete/default/search mutations plus actual fictional keychain/profile
   filesystem operations. Reject unexpected argv; never fall through to native
   credentials. Existing signing fixtures change to this honest adapter.
2. Original A/B interleaving, reverse entry, same/different UUIDs, preexisting
   identical/different profiles, same process/thread and separate processes/
   project paths. Busy admission must produce zero authentication/native calls;
   holder resources/handlers remain intact; retry after exit succeeds.
3. Actual flock exclusion/release and hard-killed holder in a wholly synthetic
   home. A persistent record prevents later admission after automatic OS unlock;
   recovery inspection also takes the lock and cannot conflict with a live holder.
4. External default/search edits (add/remove/reorder), edits during setup/cleanup,
   nonexistent/unreadable/ambiguous output, duplicate and escaped-looking paths,
   implicit create side effects, and post-delete readback disagreement. Full
   before/after state assertions include every unrelated entry, not just target.
5. Every setup/native mutation boundary: fail before effect, after effect, timeout,
   termination, unsuccessful response with changed state, failed readback and
   cleanup. No cancelled/failed setup yields a build. No blind repeated mutation.
6. Real default INT/TERM at lease open/flock/handoff, journal/session acquisition,
   initial/after-claim/dispatch cleanup, borrowed raw profile acquisition/capture,
   body and handler restoration. Retain references and prove resource state before
   fixture fallback. Repeated signals/cleanup faults cannot release a lease early
   or mask unresolved cleanup; custom handlers and worker threads unchanged.
7. Path/inode/mode/UID replacement, symlink/FIFO/hardlink, malformed/pending/orphan
   records, record write/fsync/replace/unlink failure, owned-keychain replacement,
   profile-stage/link ownership, snapshot substitution and old evidence recovery.
8. Mutation controls removing the lease/current-state guard/borrowed cancellation
   must fail behavioral regressions. Existing QA-002 issuer, entitlement,
   upload/recovery, process and native correspondence suites remain enforced.
9. Add lease/consumer tests to required macOS and installed-wheel native runner.
   Imports/resources must work installed outside checkout without runtime deps.

## Expected files and compatibility/security review

- New `src/mobile_release/local_signing.py`; focused integration in credentials.py,
  ios_profiles.py and cancellation.py. No app build/version/Store/public-evidence
  schema change; existing direct artifact consumers retain defaults.
- New `tests/unit/test_local_signing.py`, stateful helper and separate actual
  process/signal fixture(s); update only affected old signing fixtures/assertions
  and native runner coverage contract. Preserve all previous dangerous cases.
- Docs: dedicated local-signing recovery guidance, credentials/profile-authority,
  troubleshooting/upgrading/security/integration notes and changelog. Remove only
  QA-003's open-blocker statements after the fix is reviewed; retain QA-004/MRK
  obligations. No claim of general external-tool locking or hard-kill cleanup.
- New busy/pending/conflict errors are intentional fail-closed changes. Normal
  single-session CLI/configuration/Store behavior and build-once recovery remain
  compatible; existing caller templates/reusable release workflows need no new
  input or authority. Preserve manual public-release and credential isolation.

## Execution and delivery

Independent plan approval first. Then focused implementation/tests/docs; distinct
whole-diff implementation review with independent dangerous-case probes. Re-freeze
the complete proposed tree and run every existing35 QA-002 gate plus the new
regressions: full Python/Ruby/Fastlane/WIF/workflow/actionlint/Bundler/wheel/runtime
deps/pins/native/whitespace checks. Record failures honestly. No live credential
or Store operation. Clean only owned workers/temporary outputs after each completed
task; retain required evidence/wheel/healthy venv and AGENTS.md.

Only after exact source/approval/gate/scope reconciliation: one QA-003 commit,
normal protected PR with required hosted CI, squash merge matching verified head,
main tree equality/main CI, then QA-004. Final all-file/all-path audit remains
mandatory after every remaining original/confirmed issue; no READY yet.
