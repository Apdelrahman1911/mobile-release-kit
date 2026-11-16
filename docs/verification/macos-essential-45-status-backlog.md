# #45: reproduced workspace update-depth failure

The owner authorized installed-app debugging and controlled native experiments
on 2026-11-16. Recoverable application and user-state backups were verified
before the helper approval experiment. The normal helper was restored enabled;
the unrelated neighboring background item was restored to its original state.
The protected installed application bytes remain unchanged at this checkpoint.

## Reproduction and confirmed cause

The original signed `ac506bb3` application displayed its fatal workspace screen
during the controlled helper-settings return. Subsequent inspection of that
same application captured React error **185**, maximum update depth exceeded.
Its exception stack starts with React's store rerender scheduling and the
configuration-status receiver. All inspected snapshot getters returned stable
references on consecutive reads; an uncached getter was not the cause.

`App.syncGitRead` ran after every render and unconditionally called
`setGitRepository`, including when the selected controller was unchanged.
During accumulated native status notifications, synchronous external-store
renders can keep that ordinary-priority state update pending. React's nested
update limit then fires. A same-value setter call is insufficient protection
when other updates are already pending.

An isolated **real macOS WebKit** test now reproduces that exact React error,
using the application's actual `App` and bridge/controller implementation.
Four existing native status event types are delivered at separate microtask
checkpoints while ordinary-priority tasks are held behind the backlog. The
historical source and the pre-fix topic-branch source both fail at **52 cycles /
208 event deliveries**. The permanent regression also fails with the pre-fix
`App` substituted, before any helper fixture action is submitted.

The fix compares the next controller with a synchronously maintained selection
reference **before dispatching**. Context synchronization, admission checks,
project-bound controllers, original operations and draft retention are retained.
The synchronous reference also handles two project changes before React renders
the next frame.

## Regression results

- Permanent regression: **900 cycles / 3,600 native DATA deliveries**, no React
  error or fatal boundary; exactly one bootstrap.
- Separate Git drafts survive project one → project two → project one, including
  a rapid two-intent ABA switch.
- The controlled helper flow covers requires approval → registration request →
  approval-settings return/focus with a backlog → enabled check → workspace.
- Native regression plus diagnostic/render tests: **10 passed**.
- Complete frontend suite: **2,465 passed**, zero failures/skips.
- TypeScript and Vite production frontend compilation: passed; existing bundle
  size advisory remains.

Reproduce on macOS with Xcode/Swift installed:

```sh
node --experimental-strip-types --test desktop/tests/workspace-native-status.test.mjs
npm --prefix desktop test
npm --prefix desktop run build
```

The fixture uses a nonpersistent WebKit store and inert native DATA. It does not
launch commands, touch projects or credentials, or register a real helper.
Its source, compiled assets and Swift executable live in one fresh temporary
directory and are removed afterward. The test is explicitly skipped outside
macOS, where WebKit/Cocoa are unavailable.

Private log SHA-256 values, allowing comparison without publishing owner paths:

| Evidence | SHA-256 |
|---|---|
| Permanent regression with pre-fix App; React 185 at cycle 52 | `1e613605f74c5a6fea6a6219eee465db041fb30184c27e1d2b07dd6e6645c5ee` |
| Native regression plus diagnostics/render | `ecbce3cf3e7abbfc9880bdd7093f19fab22bffa09813bcf1aa4c88342b144e71` |
| Complete frontend tests | `610e72d4621f19eeefa60b828867d60a2467835999d2d3c5ea817ae32755620b` |
| TypeScript/Vite compilation | `762ba5833c9b899c603f9d75af177e2d5da2696b20ad42b9b4c7078d305110e1` |

## Remaining acceptance

The update-depth cause is reproduced, fixed and regression verified. A fresh
native candidate must still be exercised on the physical Mac; the corrected
frontend has not yet replaced the protected installed application's frontend.
This checkpoint does **not** close the issue or claim complete installed-app
acceptance. The exact exception from the earliest retained November 11 incident
was never captured; the new installed reproduction supplies current evidence.

No installer/helper lifecycle implementation was changed. Potential integration
overlap is limited to two small `App.tsx` locations around Git controller state
and synchronization; no #47–#49 work is integrated here.
