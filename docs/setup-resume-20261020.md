# Resume local setup from current observations

This is a presentation/navigation slice, not another operation owner or saved
progress record. Apply `setup-resume-hooks-20261020.patch` to Root's current
frontend together with the five frontend leaves. The patch targets649ee310;
it does not apply to this lane's older App/controller base.

## What changes

- The existing Home/Wizard selector consumes the actual Smart Setup rows and
  original tool/build/signing controller states. A required local selector can
  lead directly to Settings. Store access and default variant/configuration
  values do not become premature local blockers.
- After a manual installation or restart, Home directs the user to the existing
  tool check/choose/recovery controls, not another download. An actual current
  protected-copy selection only suggests **Review a local build**. It never
  becomes a checked toolchain, build approval or Store approval.
- A current native terminal build plus returned original caller can suggest
  viewing its local result/history. FAIL findings are still possible. A signing
  input check is not a build, and stale/foreign/provisional results do not count.
- Unknown, stopping, prepared and still-returning originals override progress.
  Foreign or not-yet-identified work is labelled separately and never switches
  the selected project. The existing app owner guard covers other domains with
  a link to their original controls, without inventing their phase or project.
- Signing guidance uses the **chosen signed mode** and its existing assignment
  issue. Assignment is not validation; no private values are projected.

The patch exposes only each Android/iOS/offline controller's existing
`pendingGuiSubmissions !== 0` bit. Its original `finally` notifies subscribers
only when that bit changes; deferred CLI observation handling, clocks, native
finality, consent, STOP and admission stay unchanged. No terminal-shaped DATA
is used to release an original caller.

Tools navigation selects the existing platform/build view, then navigates. It
does not inspect, install, register, build, save or grant anything. All original
panels/controls remain mounted according to their existing page behavior.

## Focused evidence

Isolated current-Root frontend projection:
`/tmp/mrk-setup-resume-1_ps70k2/after`. Task logs: `.task-setup-resume/`.

- `node --experimental-strip-types --test --test-isolation=none --test-concurrency=1 desktop/tests/setup-resume.test.mjs`: **5 PASS**, 0 skipped.
- Same runner, `--test-name-pattern='Home retains the original build' desktop/tests/android-build-controller.test.mjs`: **1 PASS**, 0 skipped. Uses the existing real controller/fake-port harness; a native terminal event arrives before its invoke returns, then Home is notified by the actual original `finally`.
- Existing affected `setup-overview.test.mjs`: **17 PASS**, 0 skipped.
- Narrow older-terminal/unacknowledged-project attribution extension: the
  affected resume case passed again; this is part of the same five cases.
- Projected actual TypeScript graph: **PASS**. The first projection lacked the
  seven existing preview JSON imports; copied the actual static catalogues,
  then checked the whole graph. No product source was changed for that error.

No DOM/UI automation, real tools/credentials/native operation, build, installer
or release readiness was tested. Root still integrates the exact hooks and
owns its combined verification. The original native routes keep all their
qualification and recovery requirements.
