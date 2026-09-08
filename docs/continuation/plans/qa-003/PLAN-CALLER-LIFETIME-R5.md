# QA-003 R5 caller-lifetime correction — PROPOSED

Read with approved R2/final R3 and R4-R2. R1 source remains unchanged; original
40-file inventory still applies. This is a connected actual-caller correction,
not permission to skip QA-004 or the final fresh audit. No implementation yet.

## Reanalysis and concrete evidence

1. ios.run_ios_build1041,1052 calls discover_project, which unconditionally calls
   git_context → discovery._run → direct subprocess.run. Real git status invokes
   a locally configured fsmonitor helper. Its synchronous helper can survive the
   direct Git timeout while profile/keychain resources are active; no session
   inflight/worker record exists. Subsequent signing cleanup deletes those resources
   and reports idle. Independent discovery_hook_probe.py/result plus root replay
   author-discovery-lifetime-r1.json prove this with a fictional local Git repo/home.
   The exact helper exits cooperatively before its isolated fixture is deleted.
2. Android's build runner still uses direct subprocess.run504–514. The actual
   preflight loop1048–1092 proceeds to the next platform after its failure. Root
   author-android-lifetime-r2.py/json proves both nonzero and actual shortened
   timeout leave a synchronous fixture worker alive; it observes the profile of
   the later modeled iOS signing context and survives its cleanup/status idle.
   Both fixture workers were confirmed gone before deletion. No real Gradle ran.
   Initial r1 Python3.11 probe syntax failure is preserved separately, not PASS.
3. The Android build-time final-copy jarsigner call (_canonicalize_aab_signature)
   is another direct subprocess before the next platform. It is NOT the independent
   final-artifact/Store upload validator excluded by R3. Include this build-time
   command in the same lifetime correction; never move or repeat its signing stage.
4. discovery calls also occur before signing in doctor/effective identity/client
   materialization. A process that started before signing must finish (including
   its owned descendants) before signing resources are admitted. Merely suppressing
   Git inside active iOS leaves this before-active path unsolved.

Root cause: platform filesystem selection was coupled to optional Git metadata,
and the caller audit stopped at direct preflight/private/iOS run sites. Nested
Git and Android build-time subprocesses missed the owned-command boundary; the
platform loop also continued after a potentially incomplete build/cleanup failure.

## Exact behavior/components

### A. Separate platform selection from Git metadata

Add an internal keyword include_git=True to discover_project. Its default output
and all public init/doctor JSON fields remain compatible. False performs only
existing bounded/static project discovery and returns no Git context; it cannot
start Git or another command. Select False at BOTH run_ios_build calls, Android
build selection, materialize_build_inputs' Android module selection, and pure
preflight effective-identity/container selection calls. Doctor still requests Git
context for its report. Remove its duplicate Git query by reusing the same observed
context for report.context['git']; do not mix two source observations.

### B. Bound actually needed Git context commands

Replace discovery._run's direct subprocess call with the existing owned_process
runner, same10-second command timeout, explicit root cwd, captured output bounded
at16MiB, same native exit handling. Git context remains a read-only optional
observation: missing tool/nonzero/proven-contained execution failure returns None,
not a successful or clean source assertion. Unconfirmed containment MUST propagate
ProcessError; cancellation MUST propagate, never become optional metadata absence.
Use scrub_credential_capabilities on the command environment so Git/helper children
receive no Store/OIDC/signing capabilities. Keep the environ parameter's existing
metadata role; no arbitrary command/runner/home override is added to consumer config.

Preserve Git arguments/source identity and do not disable dirty-file checks or
change version/commit/tree fallback policy. This plan is command-lifetime repair,
not a claim that arbitrary local Git configuration is authenticated release evidence.
The existing fresh pinned Store-workflow checkout/authority rules stay intact:
no new application command or Store permission is introduced. Review CLI _ci and
workflow consumers to prove changed error handling cannot proceed to mutation on
unknown/mismatched/dirty context; a killed helper/None result is not clean provenance.

### C. Complete the before-active Android build command boundary

Use run_owned for run_android_build's Gradle wrapper and only the build-time final
jarsigner in _canonicalize_aab_signature. Preserve argv, --no-daemon, cwd, explicit
committed version/build env, existing signing capability subset,45-minute/120-second
limits, output discard for Gradle, bounded2MiB private signing capture, native nonzero
failures and final output normalization/signing ordering. All command requests stay
private IPC; no passwords/output in exceptions or new argv/log diagnostics.

No new session/native-DB authority for Android: actual preflight materializes one
platform at a time, before iOS activation. Confirmed complete owned-group exit is
required before another platform. Do not change independent Android validators,
Store upload validation, artifact checksums, credentials, receipts or workflows.

### D. Fail closed across platform transitions

After ANY platform build/materialization/cleanup exception, append its failing
finding and an actionable remaining-work SKIP, then return the failing local
preflight report. Do not start another platform or artifact/project-check/native
work after potentially incomplete cleanup. Previously produced output remains
retained; never delete it or report it authenticated merely because another build
failed. This intentionally replaces permissive local continuation. It is not a
change to Store partial-success/recovery or candidate promotion semantics.

Public preflight should distinguish an unconfirmed early owned command from lease
admission failure where appropriate: fixed actionable error, no secret output, no
signing/private/application work after refusal. Existing complete native failures,
cancellation130, lease pending/recovery and no-build/Android-only exclusions remain.
QA-004's independent outer scratch/client owner is still open and will be reanalyzed
next; do not claim it safe just because this repair stops later platform work.

## Tests (actual callers/resources, not string contracts)

- Active iOS run_ios_build both before and after prepare: isolated real Git repo
  with a harmless fixture fsmonitor command. Pure selection must never invoke it;
  real journaled prepare/archive/export command boundaries still operate. Test
  configured and discovered/ambiguous container/scheme cases, preserve failures.
- Direct Git-context and actual doctor/preflight needed-Git paths: real started
  fixture descendants, startup rendezvous, success/nonzero/timeout/cancellation,
  output bound and missing tool; prove descendants gone BEFORE later signing can
  create a profile. Separate unconfirmed-cleanup injection must halt admission,
  not be swallowed as None. Test explicit credential-capability scrubbing.
- Real run_android_build and final-copy jarsigner caller fixtures, no real Gradle
  or signing asset. Success/nonzero/timeout/cancellation (startup synchronized),
  observed child gone before return/fallback. Keep actual command argv/env assertions
  for committed version, signing subset, no-daemon and output normalization. Failure
  never adopts/changes a candidate or calls Store APIs. Recheck parent-death and
  inherited-fork behavior through the existing shared runner tests.
- Full two-platform preflight composition: failures in first build/materialization/
  cleanup (both platform orders), normal second-platform success, and unconfirmed
  containment. Assert exactly intended caller graph, no subsequent app/native or
  artifact-check command after failure, pending iOS resources still recoverable and
  any completed first output preserved. Do not synthesize a passing artifact result.
- Keep public discover_project/init/doctor context compatibility and provenance
  regressions; unknown Git observation must not authorize any Store mutation.
- Add to existing test_owned_process_callers/local_signing_composition groups (already
  required in source/native/wheel gate) or extend required pattern list if new files.
  Update obsolete subprocess mocks only at the changed call boundary; real dangerous
  cases must not mock away containment, pure discovery or transition predicates.

## Files, compatibility/security/retry and verification

Expected production files: discovery.py, android.py, ios.py, preflight.py,
credentials.py (pure module selection only; R4 own cleanup changes separate).
Expected tests: discovery/build/credential tests plus actual caller/composition
fixtures; native/source/wheel list if needed. Docs: local-signing, integration,
troubleshooting/README/changelog as needed for fail-fast local preflight and Git
lifetime scope. No configuration/schema/Store destination/public-release change.

Principal risks: changing Git context shape/errors, cycles from credential scrubber
imports (use a local import, inspect module graph), loss of version/signing env,
returning optional None after unconfirmed cleanup, proceeding after a wrapped iOS
cleanup error, and regressions in Android-only/offline/skip-builds. New tests above
must target each. Retry after a confirmed contained failure can select the failed
platform; pending iOS ownership requires original local recovery. Never kill shared
services/daemons or recorded/recycled PIDs; all real fixtures own their children.

Obtain independent plan approval before implementation. Bind full revised inventory,
obtain distinct actual-diff review (including active-native crash gap correction),
freeze and run all37+ gates (Python/Ruby/WIF/Fastlane/actionlint/pins/wheel/native/
dependencies/whitespace), then scoped protected QA-003 commit/merge/main CI.
No deployment/Store authorization is granted by any development test or plan.
