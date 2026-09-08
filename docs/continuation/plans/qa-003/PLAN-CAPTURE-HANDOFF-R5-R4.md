# QA-003 R5-R4 — preserve dispatch without deferring the capture loop

## Reanalysis

The broadened R5 development run (`development-r5-complete-targeted-r1.log`)
ran 180 tests with seven failures. Six assertions still require the earlier
resource-specific cleanup message. One is a genuine implementation regression:
`authenticate_cms` now wraps the complete `_capture_profile` call in
`cancellation.deferred()`. Although explicit loop checks still cancel, this
unnecessarily defers immediate interruption while native/selector I/O is blocked.
It violates R5's narrow acquisition-only deferral and an existing depth-zero
behavior test. The purpose was to preserve successful worker dispatch when a
signal lands between capture return and the caller's `dispatched=True` store.

## Proposed correction (not implemented yet)

- Add a private optional `on_start: Callable[[], None]` observer to
  `_capture_profile`, invoked immediately after successful `Popen` assignment
  inside its existing acquisition deferral. `authenticate_cms` supplies a local
  observer which only sets its dispatch flag. Remove the outer full-call deferral.
  The callback records actual dispatch before capture proceeds or pending signals
  are delivered; pre-spawn failure remains undispatched. No new native authority,
  public option or asynchronous worker is introduced.
- Preserve the typed metadata across callback/capture/cleanup errors. Add an
  explicit `KeyboardInterrupt` conversion in authentication using the recorded
  flag, preserving earlier typed context if present. Resource cleanup/restoration
  errors retain precedence and fatality. Move the terminal `cancellation.check()`
  and result return INSIDE that conversion boundary: a borrowed guard may receive
  its first signal during scratch cleanup and its CleanupScope deliberately does
  not check on exit. This must still become a dispatched ProcessInterrupted,
  not an unclassified KeyboardInterrupt. There is no automatic retry.
- Keep consolidated resource-cleanup errors (multiple independent resources may
  fail). Replace obsolete selector-only textual assumptions with assertions of
  `ProcessCleanupError`, actual dispatch, `contained`, `cleanup_complete=False`,
  fatality, redaction, and the already-existing actual stream/group/handler/scratch
  observations. Do not merely relax the assertions to any exception.
- Update the one short-write mocked capture signature; it must still assert
  depth zero and now explicitly simulate the dispatch callback for its synthetic
  success. Other production capture callers remain source compatible via an
  optional private argument.

## Tests and verification

Keep the historical failing log. Add actual fictional child tests for successful
dispatch followed by interruption at return-to-caller, interruption while blocked
in capture (depth zero), pre-spawn interruption, and cleanup/handler errors after
completed capture. Test a first default signal during completed scratch cleanup
with BOTH a borrowed and an owned cancellation guard. Check typed dispatch/
containment and all actual owned-resource
cleanup; no real native signing/tool or Store call. Re-run all seven failures and
the broad R5 set, including fork/profile/lease composition tests, then whole-diff
implementation review, frozen complete source/native/wheel/project gates.

Compatibility/security: no signature/profile acceptance, schema, Store workflow
or evidence changes. Failure diagnostics remain fixed/redacted. Main regression
risks are recording dispatch before real spawn, losing it at handoff, accidentally
running callback after cleanup, or reintroducing broad cancellation deferral.
Tests must prove these boundaries. Existing no-session/active-session recovery
guidance is unchanged; no documentation behavior change beyond the approved R5.

Request independent plan approval before this correction. R6 verification work
can continue independently under its already-approved plan.
