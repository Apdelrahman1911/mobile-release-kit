# Mac continuation results — 2026-10-24

## Latest continuation — 2026-10-25

The first staged source `331693d865534935ffbbbd6a5aea440c7b31a456`
was rejected before any runner/job: the workflow was 518,614 bytes, exceeding
GitHub's 500 KiB file limit. Runs40151965782/40151965831 contain the original
validation failure; `staged-run40151965831.html` records its annotation.
The test groups now live in a separate reusable workflow (18,948 bytes), and the
caller is 499,939 bytes. A local regression checks the actual GitHub file cap.
Actionlint validates both files, and all 49 checkpoint/runtime-driver tests pass.
This validation-only rejection consumed no Mac build. The corrected first hosted
rehearsal is still pending; no saved package exists for the rejected source.

Staged CI implementation (pending first hosted rehearsal): two build/sign/notary
jobs retain source-bound prepared packages for 14 days. Eleven independent test
groups install that exact package on fresh runners, with a producer-only compiler
and the unchanged image-signing/Installer/readback owners. Successful app builds
and test jobs are reused by GitHub's failed-job rerun. Native manifests use an
explicit observer role, scope/host, source/tree/version, producer job/run/attempt,
and member sizes/SHA256. Download checks the artifact-service digest; native
admission repeats metadata/member checks and compares fresh installed originals.
Build-time fixture namespace stays tied to the producer attempt; installation
receipts remain tied to the real new consumer attempt. No old work-directory
identity or service/SDK state is adopted. A single real process owner is loaded
and shared through checkpoint admission and the test invocation.

New local evidence in the private evidence directory:
- `staged-reusable-tests.log`: 49 tests pass (13 new + 36 existing).
- `staged-install-gate-tests.log`: actual installation metadata gate/mutation
  test passes across both targets and supported install actions.
- `preflight-staged/`: six steps pass, including real disposable DMG transport,
  actual native dialog compilation and timeout-setting contract. The checkpoint
  tests were added to the early workflow preflight before expensive preparation.
- Actionlint passes with the existing Xcode27 hosted label documented in config;
  native code still verifies the actual hosted environment/OS/machine.
- `staged-prepared-tests.log`: older prepared suite ran 24 tests, 20 passed and
  four subtest errors hit strict attribute rejection on local fixture files.
  Its checks are unchanged. No all-tests-green claim.

The latest Mac session observation remains locked. Actual Open Project has not
been rerun; the owner's unlock question is pending. The latest Tool26 control
projection failure is not fixed or reclassified by this CI restructuring.



Run [40143037171](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/40143037171)
on `dc7c5f0e76ef553d389b73453b9aff19e22809e0` (tree
`5ca97052e939028b41b7c62d751b56b1f7a516fa`) finished with failure. Its monitor is
closed; do not restart or poll the old session.

- Git27 job121018568381 passed compilation, app signing, app notarization and
  package finalization. In step64, the original disk-image signer returned1
  (`original-nonzero-distribution-sign`). Installer was never entered, readback
  false, no detach. Captures/closes and credential cleanup were known. Detailed
  codesign stderr was written on the runner but omitted from the upload, so its
  native cause remains unknown. Artifact12582032208 is147100082 bytes and has
  only the first distribution image; it is not an approved signed-image pair.
- Tool26 job121018568677 passed installation/readback/ejection. Step68 failed
  BEFORE service registration at OpenProject: original panel binding passed,
  control projection returned changed after42 AX calls, last roleSplitGroup,
  depth1; no Press, native original call did not return, finalityunknown. The
  caller's process cleanup was contained but does not close the native original.
  Fixtures were preserved. Artifact12582006465 is294121932 bytes and retains
  the signed pair; it can be nominated only through full provenance checks.

The owner now requests small resumable workflow stages, superseding the older
avoid-CI-redesign handoff. No new monolithic candidate should be launched while
that split is implemented. Raw job logs are private files
`candidate-run40143037171-{git,tool}.log`; prior local verification is recorded
in `git-flags-local-verification.json` against the exact candidate tree.

Retained-Git run [40141597634](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/40141597634)
on helper `2cb018014c3843e88a4d3dd72ee0f10490c19b35` finished with failure in job
`121014311545`, step17. Fresh install, readback, signatures and unforced ejection
passed again. The first `git-index-cli` case completed Open Project, then its
GitRead settled refused with `unsupported-repository`; app returncode1, original
call returned, no pending invocation. Later cases stopped and fixtures were
preserved with zero close errors. This is a real Git-source failure, not the old
entry pin or image-refresh cancellation. No workflow is active from this run.

Local reproduction: both real native GitRead and GitLocal source inspections
failed `SourceRefused` on this Mac before correction, with originals settled.
The fixed CLT Git executable is root-owned, mode0755, one link, and carries
`UF_COMPRESSED` (32). `/` and `/Library` carry `SF_NOUNLINK` (1048576); `/private`
also carries Finder's `UF_HIDDEN` (32768). The initial correction still refused
that hidden bit (`git-sources-native-after.log`), so the final policy includes it.
The old source code required zero flags for all of these. The correction admits
compression only for the fixed root-owned Git executable, and the three system
protection flags plus UF_HIDDEN only for root-owned directories. Repository files retain zero
flags, and all ownership/mode/link/ACL/hash checks remain. A bounded per-original
flag roster now requires held/named flags and every later recheck to match.
Old-file replacement/unlink checks are unchanged. These are new application
bytes and require a new signed candidate; the ed91 retained app cannot prove them.
All 21 existing real core Git tests passed in 381.443s using the actual CLT Git:
read/diff/history, stage/unstage, commit, branches, switch, rename and fast-forward.
Their fixed platform executable is now shared consistently by setup and the
operation. No provider/network or user repository was accessed. The deliberate
expected-old refusal test retained its private fixture as designed; it is not
reported as a successful mutation/finality result. See `git-core-native-clt.log`.
Final native verification passed: 323 Git-related Rust tests, including the two
explicit real Account/SourceBook/ACL source inspections and rechecks, with all
originals closed. Three flag-policy tests cover root/user ownership, all other
flag bits, named/held disagreement, later changes and bounded roster capacity.
The six-step local preflight also passed, including those real native checks;
it now accepts `--git-test-bin` for a freshly compiled local test binary and
requires the expected test counts, preventing an empty filter from passing.
Logs: `git-rust-local-final.log` and `preflight-git-flags/`. Actual UI was not
rerun on the locked Mac. A fresh signed candidate is the next verification step.

Retained-Git run [40140647775](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/40140647775)
on helper `14c9c90a76d006f8f06460a138b5179bb63629c6` passed fresh installation,
readback, code signatures and unforced ejection after the 60-second grace. Step17
then stopped at `entry-refused`, before any Git case: the native test driver still
pinned the old5212 source tuple. That independent pin now matches the validated
ed91 nomination. The local preflight now checks agreement between both source
pins, the nominated origin and workflow, plus finite source sizes. The full
current-runtime DATA module passes; no native Git success is implied yet.

Tool26 correction prepared: the existing explicit RequestRegistration now admits
its single register selector after a pre-status of NotFound as well as
NotRegistered, following the same independent installed-file/signature and
consent checks. Observe remains read-only; maintenance absence, denied approval,
unknown native return and actual readiness checks remain unchanged. A read-only
ad-hoc local fixture observed NotFound with and without the expected plist; that
does not establish the signed hosted cause or authorize installation. It shows
that this status alone is not a file-existence proof. The app previously stopped
before asking registration. Only a real register result plus fresh Enabled state
can now pass; native errors/approval are not overridden. No local service was
registered or removed.

Validation: the new first-request state-machine test failed before correction;
all 96 native bridge tests passed after correction (1 ignored), including
error/denial/approval/unknown-return cases. All eight existing app service callback
lifecycle tests passed. The first callback-test filter selected zero tests and is
not counted; the corrected qualified filter ran all eight. Four-step local
preflight passed without touching the locked Mac's UI. Logs use
`service-first-request-*`, `service-callback-tests-2.log`, `reuse-runtime-data.log`
and `preflight-reuse-runtime` in the private evidence directory.

Retained-Git run [40140364346](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/40140364346)
on helper `ac14c5cadeb4949ddf8884326ff01919534079ba` failed before acquisition/native
installation: the added helper exceeded its old 96 KiB source-input cap (99,042
bytes). The cap is now a named finite 112 KiB allowance, included in existing
retained-memory accounting. The actual workflow/source-bound test passes; it
will catch this size mismatch locally. The broader bootstrap module still has
legacy DATA fixture failures and is not an all-green suite. No ejection or native
Git success was obtained from this failed attempt.

**Run 40132594293 completed with failure** on candidate
`ed91b0dd582ca35a6dc57556aa73d60f1fc852a2`, tree
`27e03272ab0f31bf4769a7236322427707cbddae`.

- Git27 job `120987297813`: original Installer0 and readback passed; the first
  ordinary diskutil eject returned 1. Its actual stderr identified PackageKit's
  `installd` (PID 544, parent launchd) as the unmount dissenter. All owned calls,
  captures and closes were known. Git cases were not reached.
- Tool26 job `120987297562`: signing, notarization, installation and ejection
  passed. The actual Open Project path passed, including 232 AX calls, one
  Press and the matching original completion. The service prerequisite then
  returned `service-not-found`, exit78: request settled, Check not entered,
  all originals settled. Tool/CLI cases remain unexecuted.

The next helper correction gives PackageKit one 60-second cleanup grace before
Git27's FIRST eject, within the unchanged endpoint and with the existing finality
reserve. It neither retries nor forces eject and does not assert service exit.
Eject0 and fresh namespace absence still decide success. Insufficient budget,
interruption or changed mount prevents admission. Tool26 behavior is unchanged.

To avoid another full build, the existing retained-Git workflow now nominates
artifact `12578123633` from the exact run/job above (294264707 bytes,
SHA256 `25b26bcf2ccde9432864d7f3717d937f6c31349458beea243afeefd8fe03c239`).
API metadata passed the actual strict producer validator. This is a raw,
nonshipping unqualified carrier; its old failed install is NOT authority for a
new success. The consumer must verify bytes/signatures, freshly install/readback,
and eject successfully before all 15 native Git cases can run.

Local checks: 33 focused DATA tests passed, including deadline/interruption and
source metadata binding; two existing retained-install tests exercised all
success/failure seams for both native scopes and passed. The initial broader
98-test invocation had 1 failure and 36 errors (including a new selection-bytes
access bug now fixed, and legacy fixture/provenance failures); it is not a green
suite. The real tiny-DMG test passed both refusal/close cycles and a separate
asynchronous reader with 60-second grace followed by first-eject0. No Installer,
service registration or privileged operation ran on the owner's Mac. This models
reader lifetime, not PackageKit's actual lifetime. Evidence uses prefix
`cleanup-grace-` in the private sibling evidence directory. Workflow syntax and
diff checks passed. Hosted verification remains required.

The owner explicitly requested continuing through failures until both candidate
jobs succeed. Run [40123897979](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/40123897979)
finished with failure on `f7e2ca8885aa050ae6a22cfdd08300bd1e3aa956`, tree
`986b46f7febbb0f76f84a886bec97ca346527d07`. Its original monitor has exited.
Both job logs, parsed failures and final metadata are retained privately.

- Tool26 `120961099217`: step 47, `notarize-payload` / `payload-submit`.
  Apple's original `notarytool` returned `-10` (Darwin SIGBUS), with empty
  stderr. No Accepted/Invalid result was returned. Original closes and
  credential cleanup were known; target retired. This is a native tool crash,
  not a recorded app rejection. No source fix or internal retry has been
  invented for it; the next candidate reruns normal notarization.
- Git27 `120961099371`: step 64, original Installer returned 1,
  `PKInstallErrorDomain` 112. The root parent's static reason hash
  `0c7fbe1fde5f90f476fa8980a7e022aa5084354810b59d2fbf70570c7b1682e5`
  resolves in this exact source to `protection-other-owner`. Native admission
  was false; originals were known, timely, and not unknown. Readback and
  ejection were not reached. Supplying the user-owned host package conflicted
  with the completed-input reader's protected-ancestor policy.

The earlier host-copy change has been removed; Installer again receives the
verified read-only mounted package. Its ownership and signature policy is
unchanged. The original Git27 ejection stderr was retrieved from artifact
`12570035234`; it explicitly deprecates `hdiutil detach` and directs callers to
`diskutil eject`, then reports Resource busy. Only the macOS27 candidate route
now uses the supported non-force eject command, once, after the same reader
closes and before the same namespace checks. A nonzero remains failure;
no forced detach, command fallback, retry or deadline extension was added.
The exact historical disk holder remains unidentified. Hosted verification of
the new ejection command is still required; local success is not that result.

New local evidence (`preflight-ejection-final`):

- All four noninteractive preflight steps passed, including 12 descriptor,
  diagnostic and ejection DATA tests.
- Both real ejection commands refused a disposable volume while a mounted file
  was open, then succeeded after the reader closed. No software was installed.
- The actual compiled Installer `completed_package::Input` reader rejected the
  user-owned copy with the same `protection-other-owner` reason and accepted
  the read-only mounted fixture, including original byte/metadata rechecks and
  consuming closes. It did not enter Installer main, authenticate a producer,
  copy an app, or gain installation authority.
- All 26 bounded build-diagnostic tests passed; workflow syntax and diff checks
  passed. All 21 standard native Installer tests passed; the one opt-in input
  test is ignored in that standard run and separately passed in the real DMG
  fixture (`installer-all-final.log`).

A combined preflight passed the new native transport checks, then its UI fixture
reported AX NoValue (-25212); the separate full-Open fixture could not start its
panel. `CGSessionCopyCurrentDictionary` confirmed `screenLocked=true`. These
attempts remain failures, not hidden successes. The unchanged UI source already
passed actual Open completion earlier while the Mac was unlocked. No lock or
permission setting was changed. Final noninteractive validation excludes UI and
reuses that earlier scoped result. Logs: `preflight-supported-ejection`,
`preflight-ejection-final`, `installer-input-test-build-2.*`,
`installer-input-data-final.log`, and `ejection-build-diagnostics-final.log`.

A premature request to rerun only Tool26 while Git27 was active was rejected by
GitHub's run-state rule (HTTP 403, containing workflow still running); no rerun
started. Because Git27 subsequently exposed the source-path regression, the
corrected exact candidate above was selected after local checks instead of
rerunning that failed source. Do not launch duplicate monitors or claim either
job passed while pending.

## Previous local preflight on f7e2ca88

Before starting, the local fixture was extended to run the actual native Open
path: real panel identity, both original rechecks, one AXPress, exact temporary
folder returned by the real completion, and successful original cleanup. This
passed with 216 AX calls, flags 15, completion flags 15, selection Match and no
AX error. The six-step local preflight including transport and both UI checks
passed (`preflight-complete-open`). It does not qualify the installed service.

The diagnostic fixture module now passes all 26 tests after restoring its
missing source DATA imports and current closed contracts. The previously
unresolved installation-metadata mutation used an old 2,048-file threshold;
the current bound is 16,384. Testing the current aggregate boundary now passes
for both targets. Production gates were unchanged. The broader legacy Python
suite has not been declared green; the historical counts below are retained.

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

The earlier attempted correction supplied the retained host copy in `producer-observation-root`,
whose bytes and SHA-256 match the signed package on the mounted distribution.
That change was later invalidated by the root Installer ownership refusal in
run 40123897979 and has been removed, as recorded above. The candidate now
retains the original mounted package admission and changes macOS27 ejection.

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
Use the exact candidate and run recorded in the latest continuation above;
older branch/run statements are historical. Distribution signing
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
