# #45: reproduced workspace update-depth failure

The owner authorized installed-app debugging and controlled native experiments
on 2026-11-16. Recoverable application and user-state backups were verified
before the helper approval experiment. The normal helper was restored enabled;
the unrelated neighboring background item was restored to its original state.
A temporary signed test update completed physical-Mac acceptance on 2026-11-17.
The original five code/signature files were then restored, with their hashes,
protected metadata and complete strict deep signature verified. The helper is
enabled again and the unrelated neighboring background item remains off.

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

## Physical installed-app checkpoint

The ordinary desktop image was compiled from `ded08721` using the existing
protected runtime and protocol anchors, with one compiler job and the 3 GiB
aggregate RSS limit. It was signed with the installed application's actual
publisher identity. The original entry and payload executable logic, helper,
runtime, installation records and user projects were retained. Exactly five
code/signature files differ; all five candidate hashes, original protected
ownership/modes, empty attribute rosters and the complete strict deep signature
have been verified after publication.

An initial test-copy method caused macOS to add provenance attributes, which the
existing runtime inspector correctly refused at `protected-application`. This
was an introduced test-installation failure, **not** proof of the original #46
cause. A private, same-publisher native test transaction then published verified
copies with the original metadata policy intact. It did not remove opaque OS
attributes, relax application checks or modify the product's installer/helper.
The temporary preparation jobs were retired. This local test update makes no
hosted, notarization, installer-cohort or distribution qualification claim.

The resulting installed app launched through its real protected entry and
reported `MRK_DESKTOP_CAPABILITIES=available` on its first connection, without an
inspection failure. It loaded the disposable Android helper-test project and
remained responsive across Overview/Build tools navigation and native status
updates. Read-only inspection of the exact diagnostic storage key found zero
workspace error records in both existing WebKit stores.

The real Login Items helper toggle opened a Touch ID prompt. After the owner
authenticated and unlocked the Mac, its disabled state was observed. It was
restored to enabled and independently checked enabled again after returning to
the app. The unrelated neighboring background item stayed off.

The **same running installed test session** returned to the workspace without
a fatal boundary. Overview still displayed the disposable project's saved
version **1.0.0 / Build 1**. Overview → Build tools → connection details → local
diagnostics → Overview navigation passed. Explicitly refreshing the local error
records showed **zero workspace errors**; native runtime availability remained
available. This is physical OS approval/settings-return evidence in addition to
the automated controlled helper-DATA transition regression.

The test image's native helper setup command separately refused its missing
shipping-identity profile. No successful helper registration/protected-copy
qualification is claimed from this local image. That refusal was displayed
normally and did not break the workspace. No installer/helper fix or another
agent's branch was used to obtain the workspace result.

After acceptance, only the owned, idle test session was retired. All five
original code/signature files were restored by the closed same-publisher test
transaction: original hashes, root ownership/modes, empty attribute rosters and
strict deep signature all passed. Its one-shot job was retired. No project,
runtime or installation record was changed. T3 Code's App Management access was
left enabled at the owner's explicit request.

Private output SHA-256 values:

| Evidence | SHA-256 |
|---|---|
| Physical helper return, saved version and final state | `4f095dddc6e7aa131981424cc9999b26c3e553e067aaffb0e5ce6db64c74c003` |
| Refreshed installed diagnostic view | `d0557a776c228fe8a5cb36783428be61150640a8cb4cbfdebbadb3b89c8cde9f` |
| Original-code restoration verification | `e0fb18d981f722c17740e595def3ccb5b95613490f9dd3435cfbe64f2bef0459` |

## Verdict and delivery boundary

The reproduced workspace update-depth defect is **fixed and verified**, including
the physical installed-app helper-settings return. Implementation is in
`ded08721`; original-code restoration is complete. The exact exception from the
earliest retained November 11 incident was never captured; the newly reproduced
installed React 185 and before/after regression supply the confirmed cause.

The issue remains open for review. No merge, push, hosted run, production
installer qualification or release is represented by this local acceptance.
Those delivery actions are outside the owner's current instructions.

No installer/helper lifecycle implementation was changed. Potential integration
overlap is limited to two small `App.tsx` locations around Git controller state
and synchronization; no #47–#49 work is integrated here.
