# Mac continuation results — 2026-10-24

## Source and scope

- Checkpoint: `af9a4f76be5c4ced9186fb9e2e80e302e3078d7d`.
- Earlier GitRead fix: `148e7c6234a51a548e07bbc87095527e7beaa584`.
- Earlier fix tree: `311234838b7a7d74b5f75a12c23e8f635b70156d`.
- Current correction: `4c354265e9a26c7b48b4ce6d0d743de7383888e3`.
- Current correction tree: `b4b6f3a69044ca5969ff994e441df0196665b691`.
- Continuation branch: `codex/macos-git-read-continuation`.
- A separate clean clone was used. The owner's existing checkout was on a
  different branch with extensive deletions and a modified workflow; it was left
  untouched. No installation, removal, credential access, Store mutation or
  production publication was performed on the owner's Mac. `main` was not changed.

## Current workflow failures and local corrections

Both jobs in [run 40110783814](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/40110783814),
attempt 1, failed on the earlier GitRead fix above. They were two independent
jobs in one workflow, not two successful native qualifications.

### Git27: Installer succeeded, distribution ejection failed

[Job 120921867192](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/40110783814/job/120921867192)
failed in step 63. The original Installer returned zero and installed-file
readback passed. The subsequent ordinary `hdiutil detach` returned 16, Resource
busy: `original-nonzero-distribution-detach`, stage
`package-nonroot-v2-readback`. Git operations had not started. The diagnostic
could not identify a holder; do not claim Finder, Spotlight or PackageKit was
conclusively identified as the original cause.

Installer now receives the retained host copy in `producer-observation-root`,
whose bytes and SHA-256 match the signed package on the mounted distribution.
The mount, original files, signed descriptors, request-correlated log binding,
post-checks and installed readback remain checked. No forced detach, retry,
status suppression or new package is introduced.

A real, harmless local DMG experiment reproduced the relevant lifetime problem:
an open descriptor on the mounted fixture yielded detach 16; after closing it,
normal detach succeeded. An open descriptor on the identical host copy allowed
normal detach 0. This proves the source-lifetime mechanism, not the identity of
the original CI holder or an actual signed installation on the owner's Mac.

### Tool26: Open Project accessibility query failed before any press

[Job 120921867407](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/40110783814/job/120921867407)
failed in step 67 at `OpenProject`, `native-default-input`. The first child Role
query beneath the matched panel returned `kAXErrorCannotComplete` (-25204),
stage `control-projection`, node 1, depth 1, AX call 36. Each AX query previously
had a 100 ms allowance. The initial parent/panel/directory identity checks
succeeded; no button press was attempted. The outer invocation did not return:
`originalCallReturned=false`, `appReturncode=null`, `invocationFinality=unknown`,
`fixturesPreserved=true`. Preserve those original facts. Service readiness,
tool acquisition, installed CLI, key and backup operations were not verified.

Read queries now allow up to 500 ms within the SAME original two-second
endpoint. Press acknowledgment still has its original at-most-100 ms allowance,
installed at the actual admission site before Press. There is no retry, broader
selector, deadline renewal or changed finality rule. A cold AppKit service is a
plausible explanation for the old query failure, not a locally reproduced
diagnosis of the exact macOS 26 event.

The actual source AX reader now passes against a real NSOpenPanel on this Mac:
14 nodes, 86 calls, AX error 0, trusted=true. Earlier attempts were denied by
local Accessibility permission (-25211, a DIFFERENT error). After the owner's
latest permission change, both the disposable test app and freshly compiled
source fixture passed. The fixture only reads its own panel then cancels it;
this does not qualify Press completion or the installed service.

### Additional local corrections

- The maximal supported tool-setup catalogue with the previous review retained
  requires 71,093,161 bytes on ARM64. Its separate fixed cap increased from
  64 MiB to 72 MiB; checked arithmetic, exact-cap/overflow tests and the distinct
  registration budget remain intact.
- The fixed source version JSON reader accepts only Apple's
  `com.apple.provenance` attribute, which macOS 27 attaches to local checkouts.
  Installed-file and payload attribute policies remain strict. The new negative
  test rejects any other attribute in both modes.
- Stale application/frontend fixtures were aligned with existing permission
  revisions, catalogue entries, recovery-code length, prepared key recovery and
  shared IPC memory accounting. No permissions were relaxed to satisfy them.

## Current local validation

The final quick preflight passed all five steps: 14 installer DATA tests,
native fixture compilation, actual AX timeout-setting contract, real DMG
lifetime test (8.939 seconds), and actual dialog projection. The workflow runs
its noninteractive steps immediately after Python setup, before expensive
native preparation, with a three-minute cap. The interactive dialog is local
opt-in because a separately launched app needs its own macOS permission.

Other results:

- Frontend: **2,444/2,444 passed**; production frontend build passed.
- Desktop executable: current source compiled successfully as ARM64 Mach-O
  with `desktop-shell,custom-protocol`. It was not launched or installed.
- Native bridge: **96 passed, 2 ignored**, serial, with `installed-observation`.
- Application Rust full run: **2,879 passed, 2 failed, 7 ignored**. One failure
  was the stale GitHub help/catalogue fixture; its corrected focused rerun
  passed. The remaining failure is the protected Xcode host check described
  below. This amounts to 2,880 passing application cases across those runs,
  not an all-green full-suite result.
- Workflow syntax passed with actionlint's optional shellcheck disabled. A full
  before/after comparison found no new shellcheck findings; existing warnings
  remain. The unused YAML anchor was removed after checking it had no aliases.
- Changed Python files compile, and `git diff --check` passes.

### Remaining local failures: do not hide them

The actual selected-Xcode positive-consume test refuses `/Applications` with
`Ownership`: its mode is 0775, owner root, group admin. That parent is writable
by the admin group. Xcode's own directory is root-owned and 0755. The protected
tool policy was not weakened, and no system directory permissions were changed.
Use a separately provisioned test environment for that positive native case.

The broader `test_macos_*.py` discovery ran **1,410 tests**, reporting **147
failures, 515 errors and 5 skips** (failure/error totals include subtests).
It is NOT passing. Common causes include local fixture files carrying
`com.apple.provenance`, partial source extraction missing
`SAVED_DIAGNOSTIC_STAGES`, outdated mock Operation fields and stale source
assertions. Other assertions, including installation-metadata mutations, remain
unresolved; the passing focused tests do not supersede this broader result.
Do not disable strict production gates or repin stale hashes merely to turn
these fixtures green.

No replacement hosted verification was started during this correction. Local
results do not establish macOS 26 behavior, signed installation, notarization,
real service/CLI/key/backup operation or installed update/credential continuity.

### Repeat the supported local checks

Work in `/Users/abdelrahman/Projects/mobile-release-kit-macos-20261024`, not the
owner's original dirty checkout. Evidence is outside Git at
`/Users/abdelrahman/Projects/mobile-release-kit-macos-20261024-evidence`.

```sh
/opt/homebrew/bin/python3.11 -I -B desktop/tools/macos_local_preflight.py \
  --transport --dialog --output /absolute/new/evidence-directory

cd desktop
PATH="/opt/homebrew/opt/python@3.11/libexec/bin:$PATH" npm test
npm run build

cd native/macos-installed-native
CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 \
  cargo +1.98.1 test --locked --features installed-observation --lib -- --test-threads=1

cd ../../src-tauri
RUST_MIN_STACK=16777216 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 \
  cargo +1.98.1 test --locked --lib -- --test-threads=1
```

Use Python 3.11+, explicit Rust 1.98.1 on ARM, serial native tests, and the
test-only 16 MiB thread stack for the largest catalogue fixture. Do not change
global defaults. For filesystem tests use an owned canonical TMPDIR such as
`...-evidence/test-temp`; `/var` is a symlink and `/private/tmp` inherits group
wheel on this host. The preflight creates its own canonical temporary directory.

Key logs: `preflight-final/results.json`, `preflight-final/native-dialog.log`,
`native-rust-press-final.log`, `frontend-all-final.log`,
`application-rust-final.log`, `github-catalogue-final.log`, `desktop-build-final.log`,
`macos-python-final.log`, and `macos-python-failure-index.txt`. Original CI
failure JSON and full logs remain in the same private evidence directory.

## Earlier GitRead defect: reproduced and corrected

An idle image display becomes `OtherEditActive` when a Git read is pending.
The actual shared `common_gate` already reports Busy for that pending read,
before the later Supervisor `can_exit` check. The image snapshot previously
called `DocumentBinding::bump` to publish this display change. That stopped the
same original Git ticket and invalidated its Document revision.

Before changing that behavior, the local Rust regression failed with:

```text
before: Starting, no error
after:  Stopping, cancelled, DocumentStop, go_claimed_at_boundary=false
```

The regression uses the real in-memory Document, Supervisor owner roster,
capability composition, Git ticket and image snapshot publisher. Its fixture is
below native qualification, starts no child, grants no registered source, and
keeps its receipt Pending. It proves the state/publication defect, not a signed
installed Git invocation or native cleanup success.

Image selection status now owns an independent monotonically increasing display
revision. It compares the entire bounded serialized status, covering capability,
active selection, last terminal and window generation. Identical reads keep the
same revision. Cached bytes are charged by retained capacity. Revision exhaustion
fails closed through the existing Document exhaustion path and returns an error;
it neither wraps nor fabricates settlement.

GitRead admission, current-source checks, cancellation, deadlines, stop precedence
and receipt handling are unchanged. The only Git/Supervisor additions are test
fixtures under `cfg(test)`. No runtime feature nomination was opened.

## Local verification

Host: ARM64, macOS 27.0 (26A428), Xcode 27.0 (27A266a), Node 24.12.0.
Homebrew Python 3.11.16 is available; the shell's earlier Python 3.9.6 observation
did not mean Python 3.11 was absent.

Rust 1.98.0 was installed, but the existing native build script explicitly
refuses it on ARM64. Rust 1.98.1 was installed alongside the existing toolchains,
without changing their default or rewriting the repository's 1.98.0 pin.

Passed against fix `148e7c62`:

- 28 focused Rust tests: image display/selection (including five new regressions),
  retained memory, image service state, GitRead failure provenance and repository
  summary. Tests cover display stability, real Document change/loss, explicit
  cancellation, shutdown invalidation, original pending finality and exhaustion.
- 117 existing frontend tests in `git-read-native.test.mjs`,
  `metadata-images.test.mjs`, `service-metadata-images.test.mjs`, and
  `service-metadata-images-prepare.test.mjs`.
- `npm run build` (includes TypeScript checking).
- `cargo +1.98.1 build --locked --features desktop-shell,custom-protocol
  --bin mobile-release-kit-desktop`, producing an ARM64 Mach-O executable.
- `git diff --check`.

Rust tests used `CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0`; the Desktop
build used `CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0`. This local build was
not launched, installed, distribution-signed, bundled with qualified runtime
inputs or notarized. Existing warning output was not treated as a reason for
unrelated refactoring. A test-only nested Document lock discovered after the
first fix run was corrected; the final regression group passed without a hang.

Local evidence is in the sibling directory whose name ends in
`-macos-20261024-evidence`, outside Git. It contains the before/after test logs,
focused test/build logs, and bounded Tool26 facts. Do not publish raw logs or
treat a diagnostic image as a user installer.

## Existing Tool26 result

Run `40099646335`, attempt 1, job `120888971939`, source `92b6e742...` finished
with failure at `2026-10-24T15:35:18Z`.

- Package signing, notarization and normal installation passed in their original
  scope, as already recorded in the checkpoint.
- Step 67 failed at `OpenProject`, reason `native-default-input`. Its native
  accessibility control projection reported `cannot-complete`; no button press
  returned successfully.
- `originalCallReturned=false`, `appReturncode=null`,
  `invocationFinality=unknown`, `fixturesPreserved=true`.
- Installed CLI, acquisition, key and backup checks were skipped. Service
  readiness was not established. This does not prove a new application service
  defect or a recurrence of the earlier payload-path defect.

No selector change, duplicate monitor or replacement run of that old source was
made. These original unknown-finality facts must remain unchanged.

## Remaining installed delivery

Both original job results have now been consumed, as recorded above.
`verify/desktop-macos-candidate` remains on the earlier tested GitRead fix;
the new correction has not started another workflow. Distribution signing
remains in the existing `macos-developer-id` environment. Resolve or explicitly
scope remaining local fixture failures before spending another long hosted run.
The next hosted result must bind the new exact source and preserve each original
failure/finality. Enable only features actually established by native behavior.

The ordinary signed/notarized 0.1.3 installer, real 0.1.2-to-0.1.3 update,
credential reopening and essential installed lifecycle remain outstanding.
The current run builds nonshipping observers and is not itself that delivery.
Use the existing ordinary/update packaging routes when their prerequisites are
met. Do not install, update or remove software on the owner's daily-use Mac
without the separately required explicit approval. Preserve all external,
provider, Intel and physical-device limitations from the original handoff.
