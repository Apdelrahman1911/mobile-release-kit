# Ordinary macOS application: external UI scenario

This is one **external XCTest UI test**, not a second application engine or an
in-process observer. It does not change the ordinary Rust app, its core,
runtime profile, confirmations, owner or cleanup policy.

## Admitted environment

Only the existing reviewed normal-package job on a **fresh exclusive
GitHub-hosted macOS 26 ARM64 runner** is supported. The same job must first
bind the ordinary Cargo binary, package it, install through the standard
Installer and pass the independent nonroot byte/mode readback. Never point
this scenario at a shared/personal desktop: XCTest launch may terminate an
already-running application. A non-running precondition is mandatory.

The tiny target has no package dependencies and no app-under-test build target.
It uses ad-hoc local signing for its test runner only; no signing account,
provisioning profile or production credential is needed. The workflow selects
Xcode only for these steps; it does not change the machine-wide developer
directory. Missing Xcode/UI broker/GUI/permission support is a failure, not
permission to modify TCC, Accessibility, Gatekeeper or user credentials.

The selected application URL is fixed:
`/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app`.
The bundle ID check is a routing check, not a substitute for the original
Installer/readback and normal-binary source receipts.

## Exact scenario and claim

`MRKNormalAppUITests/NormalAppUITests/testLaunchCancelAndQuit`:

1. Launch the exact, initially stopped ordinary app once, with an explicit
   credential-free environment and no project or observer arguments.
2. Observe its unique main window, first-party renderer, dashboard heading and
   enabled **Open project folder** control.
3. Use its own **File → Quit** menu. Require the exact native confirmation
   sheet and its unique **Cancel** and **Quit** buttons.
4. Click **Cancel**. Confirm the app and dashboard remain usable; navigate to
   Project settings and back to Dashboard without selecting any project.
5. Use File → Quit again and click the genuine affirmative **Quit** button.
   Wait for the same application proxy to report `notRunning`.

No skip, expected failure, automatic rerun, arbitrary app path, global
keystroke, permission change or live service operation is included.
Framework `terminate()` is failure-only cleanup after this test's own launch;
if cleanup is needed the test fails, even when that cleanup succeeds.
An occupied preexisting app is never assigned to the cleanup slot.

XCTest enforces a **60-second** scenario allowance with timeouts enabled.
The workflow separately bounds runner build and execution; execution has a
three-minute outer step. Apple rounds `executionTimeAllowance` up to whole
minutes, so this is not a falsely claimed precise 90-second timeout.

The original `xcodebuild` test result must succeed, with exactly one total and
passed test and zero failed/skipped tests. The structured UI result and bounded
diagnostics are separate evidence, never a rewritten preview-package receipt.

**Not proved:** original POSIX application exit status, every internal or
external worker/descriptor's finality, Finder/Installer interaction, Gatekeeper
or notarization, Intel/older macOS, project selection, editing, signing, Store
operations, release readiness or complete Desktop feature acceptance.
`cleanExitStatus` remains null and `allWorkerFinality` remains unestablished.

## Resource/evidence handling

Build this small runner once, then use `test-without-building`; batch it with an
actual changed normal-app build rather than rebuilding the whole application
for this scenario alone. Application and harness source commits are both
recorded; this initial integration requires the same commit.

Raw `.xcresult` and full logs stay in this job's task-owned temporary directory.
Only the closed summary and bounded credential-free diagnostic tails enter the
separate engineering evidence artifact. The user-preview package roster stays
exactly `.pkg`, `README.md`, `PREVIEW.json`. Its unexecuted UI fields describe
the package export stage, not a later independent XCTest result.

After a completed accepted test/evidence upload, remove only this task's
DerivedData, result bundle and disposable full logs. Do not stop shared macOS/
Xcode services or delete shared caches. Failure/timeout is not worker-finality
evidence; retain unresolved task outputs until the disposable job is retired.
