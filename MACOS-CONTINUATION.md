# Continue Mobile Release Kit on the owner's Mac

## Current continuation — 2026-10-27

Both signed build checkpoints for source `660493197818275da7239240b4a1b34eb24c32f4`
succeeded in run40394195932. Their immutable saved package IDs/hashes are below.
The original run and single Git retry40410215913 have now finished with failures;
both monitors have completed. No independent test group has succeeded yet.

The Git retry failed before downloading the package: the dispatch's selected
producer-attempt step incorrectly required its source to differ from the current
source. The correction accepts an exact source match without a comparison file.
Changed harness sources still require the complete authenticated ancestor
comparison. Acquisition selects its exact metadata roster from the held package
manifest and preserves the original source/tree/hash/close checks.

Both regressions failed before this correction and now pass.48 focused checks
pass, including real original-file acquisition and both host scopes; workflow
syntax and diff checks pass. The broader51-test run retains four attribute
errors in three unrelated packaging fixture methods. Running the original
source660 baseline reproduces the same four errors among49 tests. They are not
passes; a byte-identical disposable projection did not resolve macOS automatically
adding com.apple.provenance. Strict product attribute checks remain in place.
The next Git-only dispatch can reuse the signed source660 package after this
harness-only commit. No application or native bytes changed.

The new service diagnostic confirms that Apple's original registration mutation
entered and returned: `accepted=false`, error category `other-service-error`,
status `not-found`, outcome `error`, and all originals settled. Installer,
readback, detach and actual Open Project passed. Check/CLI never entered.
This excludes a skipped mutation, but the finite category does not identify
Apple's numeric error. Do not treat it as a plist defect or a service success.
Investigate the actual native error before retrying service/CLI.

## Latest Mac continuation — 2026-10-26

Current fresh candidate run: [40394195932](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/40394195932),
source `660493197818275da7239240b4a1b34eb24c32f4`, attempt1. Both signed
candidate builds succeeded. Git27 saved artifact12692160699
(SHA256 `dfe9a262ed2063babc51524b58f42b0812cc73e8b48bf78f995193b21fc7b040`);
Tool26 saved artifact12690494428
(SHA256 `3d725d76c6b8ffdb2b75b1ea574dcf8ba3131723a9e6252ffd4daccc55b695da`).
Producer step gates, source/run/attempt and artifact metadata were checked with
the existing checkpoint selectors; the consumers verify downloaded bytes.
Git-local job121874413468 failed before Installer: `prepared-resource-insufficient`.
Available estimated memory was2,903,441,408 bytes; the unchanged full audit quote
required2,954,020,401 bytes (50,578,993 bytes short). Artifact digest verification
passed and original cleanup settled. The allocation test passes locally, and
replaying the reported admission correctly preserves that refusal. No code or
memory gate changed. Its one fresh-runner retry is
[40410215913](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/40410215913),
job121878737194, using the same source660/saved package. If resource refusal
repeats, investigate the allocation/host evidence before another retry.
Service-cli job121874413479 remains running in the original build run.
No independent group has succeeded yet. After both initial groups actually
pass, dispatch the remaining nine using this same source/run. Monitor74380
tracks the original run; monitor8846 tracks the Git retry. The ACTIVE follow-up
remains in place. Source769 packages/failures remain historical evidence only.
For future workflow mutations, use the repository owner's existing saved login
in a per-command environment; another active CLI account lacks write access.
Preserve the global account setting and never log or persist the token.

Tool retry [40364299644](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/40364299644)
finished with failure on source `61b0c21096ac2e772ac221006d951301cba32a34`,
attempt1/job121717724392. Install/signature/readback/detach and actual Open
Project passed. The explicit service request settled with service-not-found;
Check and CLI were not entered. Its monitor has finished; the new run is recorded above.

The read-only Apple diagnostic returned four matching events without an error
code. Local read-only disposable fixtures reproduce Apple's "record not found"
status with the expected plist present: it means a missing registration record,
not proven missing service files. Do not move files based on that log. The next
change must expose the original native registration return and terminal state,
then combine that observation with the locally verified pending Git correction
in a fresh signed candidate. No local service was registered or removed.

The pending candidate combines the independently reproduced Git hidden-Library
correction with finite service diagnostics. Observed native registration uses a
version4 report of the same48-byte ABI; ordinary v2 and maintenance v3 keep their
existing layout/semantics. Only returned BOOL and a fixed error category survive;
no NSError, description, path, credential or additional service query is retained.
The final prerequisite report now includes the actual entered/returned/outcome
and that returned native category. Ready still requires joined registration and
a separate fresh Enabled Check. This diagnostic is not a service fix or pass.

Local checks:16 actual Objective-C phase cases pass in each of ordinary and
observed builds with inert service/gate edges (no OS registration);14 native
service Rust tests,14 app service/callback tests,69 parser/checkpoint/runtime
tests, and10 preflight steps including real disposable DMG transport pass.
Python tests required the source import path and a physical temporary directory;
the first missing-module/symlink-path attempts were failures, then passed using
the actual evidence/tmp path. Signed execution remains required.

The full observed application now compiles locally and its actual
`data-contracts` entry returns `MRK_MACOS_DATA_CONTRACTS=passed`. The initial
unbound local build correctly refused its missing runtime manifest/protocol
inputs; the passing build uses explicit hashes from the saved runtime only for
local DATA checks (`service-return-local-compile-inputs.json`). A temporary
non-static diagnostic format failed compilation and was corrected to fixed
compile-time strings before this passing build. No native fixture or UI entered.
The exact new CI check also passed locally against that binary: it verifies the
compiler artifact digest and runs startup contracts before helper builds or
notarization. The final10-step local preflight includes that observed executable.

New pushes run only git-local and service-cli after the two build checkpoints.
The other nine independent groups remain mandatory and must be dispatched with
the new saved source/run after the initial checks pass. Existing source769
packages do not qualify these changed application bytes.69 final targeted tests,
workflow actionlint, and diff checks pass. The current change needs a fresh
signed candidate; no service registration success is claimed yet.

Run40355507324 finished with failure at the service prerequisite. The extended
cold compiler budget worked: producer compilation, signing, Installer, readback
and detach all passed. Actual Open Project also passed. The explicit service
request settled with `service-not-found`; Check and CLI were not entered. The
existing report does not expose Apple's underlying native error code, so it
cannot yet establish why registration did not produce a ready service.

The pending Git correction also has a fast standalone host check. It compiles
the actual application flag module directly with the pinned Rust compiler and
checks real CLT Git and user Library ancestors before expensive CI preparation.
All five checks pass locally (under one second including compilation). The local
preflight also passes both real source checks beneath a newly created hidden
ancestor. It never changes the owner's Library or installed application. These
checks supplement, rather than replace, the pending signed application test.

Tool retry40351985673 repeated the producer-tests deadline before Installer.
The saved-candidate compiler now has one900-second cold test/build envelope
instead of480; only that compile budget and its enclosing package budget
increase. Compiler inputs, signing/emitter/Installer/readback/detach caps
and original settlement requirements are unchanged.58 targeted tests pass.
The older producer/removal fixture has the same three errors on the prior
helper and current helper; those unrelated fixture errors are not passes.

Git retry40349520933 passed install and Open Project, then the actual first
Git read settled with stale-observation. Native reproduction under this
Mac's Library failed both source checks: user-owned Library has UF_HIDDEN,
which the current source policy allowed only on root-owned directories.
An uncommitted application correction now allows only that harmless
directory flag while retaining original owner/mode/ACL/identity/POST checks.
322 Git Rust tests and both real Library source checks pass. Keep this
application change separate until the helper-only Tool retry is consumed;
a changed app needs a fresh signed candidate. Do not qualify source769
with the pending application change.

Both producer checkpoints are now successful and immutable: Git27 attempt1
artifact12585453039, Tool26 attempt2 artifact12661209060. The old run40152218901
was cancelled only after both build jobs succeeded, to stop its obsolete test
scripts. New tests use explicit single-group dispatch against saved source769.

Git run40346979269 onb1c3615c passed hydration, full audit, signing, Installer,
readback and detach. It then refused before launching the app at
`gate-package-call-shape`: the current package owner adds optional `installerLog`
diagnostics to two log calls, while the older Aqua receipt gate required exactly
seven fields. The correction admits/validates only that finite diagnostic on
those two roles and leaves every original status/hash/close gate intact.58
focused tests pass, including actual producer diagnostic data and negative gates.
Tool service run40348393240 on18aa3ff5 failed before Installer: the original
producer-tests call exceeded its compiler deadline. Its return/capture cleanup
remained unknown; no signing credential context or Installer had been entered.
The exact cold compiler/test sequence passed locally in147.96 seconds; its
following producer build and actual compiler-graph parser passed in3.04 seconds.
This local check used no credentials or installed application.
Both those earlier retries are now failed; their exact results are recorded
above. Tool retry40364299644 has also failed as recorded above. Check the private
ledger and GitHub results before further dispatch.

Run40152218901 attempt1 failed. Git27 built and saved its signed package
(artifact12585453039, origin769bd80d); Tool26's payload notarization returned1
with network-connection/url-1009, before any prepared checkpoint. Its downstream
groups had no package. Four Git groups refused during hydration with a generic
ValueError; the one that hydrated reached producer signing and failed because
both environment secrets were empty in the reusable job. Do not invent a more
specific cause for those four hydration failures.

The helper-only Git run40333720831 (source34c87010) passed credential presence,
selected/downloaded the old package, then refused hydration with exact reason
prepared-resource-insufficient: required3091282141 bytes, available3014819840.
The new correction counts the actual gzip expansion in64KiB windows before full
allocation, keeps every existing byte/hash/owner audit, and drops the extra whole
payload dictionary before the independent audit. Real saved package expansion is
502539264 bytes and all7231 file/member correspondences pass; the conservative
quote becomes2953955549 bytes. See staged-real-package-expansion.json.
57 targeted tests pass. The local production writer still refuses this Mac's
automatically added com.apple.provenance; do not call that writer a pass or relax
its policy. Separate disposable DATA-audit evidence is marked accordingly.

Only Tool26 has been rerun: attempt2, job121604550887. Monitor session78535.
The Git build is reused, not recompiled. Check private live metadata before
another dispatch. A new helper-only continuation adds explicit secret inheritance,
an early secret-presence check, finite prepared refusal/resource diagnostics,
artifact-backed selection of original jobs despite GitHub's copied rerun rows,
and a single-group dispatch that verifies the complete helper-only ancestor diff.
No new application binary is claimed by that dispatch.

The actual local Open Project test passed on the unlocked Mac on Oct26:216 AX
calls, original selection/completion succeeded, native resources released.
Evidence:dialog-full-recheck-oct26.log. No permission or installation was changed.

**Latest owner steering:** split the workflow into small resumable parts so a
late failure does not rebuild the whole 90-minute pipeline. This explicitly
authorizes restructuring CI despite the older handoff's avoid-redesign guidance.
Continue the original fix/test/follow-to-success objective with this new approach.
Do not dispatch another monolithic build while implementing the stage boundaries.

Run40143037171 on `dc7c5f0e76ef553d389b73453b9aff19e22809e0` has finished with
failure; its monitor exited. Git27 failed BEFORE Installer at disk-image
`distribution-sign` (codesign returned1, no detailed stderr was uploaded).
Tool26 installed successfully but its Open Project control projection refused
`changed` on a SplitGroup; Press was not attempted, native invocation finality
remains unknown, and service registration was never reached. Preserve these
facts; neither the Git source correction nor service correction got its intended
installed check. Both source fixes passed their recorded local tests.

The staged workflow is now implemented: the two signed-candidate build jobs
export schema2 prepared packages, followed by eleven independent native test
groups. Each group validates the original successful producer attempt, hydrates
fresh files, and runs the existing image signing/Installer/readback owner before
its selected tests. Tests do not rebuild/notarize the app. Rerun failed jobs,
not the whole run. See `docs/macos-ci-retries.md` for the graph and limits.
Source changes that alter the app still need a new signed candidate; they cannot
be hidden by reusing old binaries. Keep source, build attempt and consumer attempt
separate. No current-run origin is nominated from the older diagnostic artifacts.

Local staged checks: 49 checkpoint/runtime-driver tests pass; actual Installer
metadata parser mutations pass; all six preflight steps pass including real DMG
transport and dialog compilation/allowance checks. Actionlint and diff checks pass.
The older prepared suite has 20 passing tests and four subtest errors caused by
local com.apple.provenance fixture attributes. Do not relax its native attribute
policy. The Mac was subsequently unlocked and the actual Open Project test passed on Oct26. No Accessibility change was needed.

**Active request:** follow both candidate jobs until they succeed; investigate,
fix, locally test and rerun failures. Work remains on
`codex/macos-git-read-continuation` in the isolated clone
`/Users/abdelrahman/Projects/mobile-release-kit-macos-20261024`.
Read [MACOS-LOCAL-RESULTS.md](MACOS-LOCAL-RESULTS.md) first for current run status,
original failures, candidate changes and exact verification limits.

The latest retained-Git run40141597634 finished: install/cleanup and Open Project
passed, then the first real GitRead refused `unsupported-repository` with settled
originals. Both native source inspections reproduced a refusal locally. Their
zero-flags policy rejected Apple's compressed CLT Git and protected system
ancestors. The narrow flag-policy correction passes 323 Git Rust tests, both real
native source inspections, 21 real core Git tests and the six-step local preflight. It changes
application bytes and requires a fresh signed candidate, not another ed91 reuse.
The explicit Tool26 service request correction is locally tested but still needs
signed hosted execution. See the latest local results for the next run; neither
job has passed its full native scope yet.

**Run 40132594293 is finished with failure.** Git27 installed/read back successfully,
then diskutil eject1 identified `installd` as the dissenter. Tool26 installed and
completed actual Open Project, then returned service-not-found / exit78 with
originals settled. Read the latest results above. A tested 60-second cleanup grace
and exact ed91 artifact nomination are being prepared on the existing retained
Git reuse route; no new workflow or production publication. Track the next run
recorded in MACOS-LOCAL-RESULTS.md. Service packaging still needs investigation.

Run [40123897979](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/40123897979)
on `f7e2ca8885aa050ae6a22cfdd08300bd1e3aa956` failed; its monitor has exited.
Tool26's Apple notarization tool crashed (SIGBUS, no Accepted/Invalid response).
Git27's root Installer rejected the user-owned host package with
`protection-other-owner`. The host-copy change is now removed. Installer again
receives the protected read-only mounted package. macOS27 ejection uses Apple's
recommended non-force `diskutil eject` once; other routes stay unchanged.
No root ownership check, signature check or original failure is suppressed.

The actual compiled Installer reader locally rejected the host copy and accepted
the mounted fixture with all readers closed. Both real ejection commands refused
an open mounted file and succeeded after close. The four-step noninteractive
preflight, 12 ejection DATA tests and 26 diagnostic tests pass. The UI source is
unchanged and previously passed actual Open completion; new attempts occurred
with the Mac locked and are not passes. No macOS settings were altered.

Earlier changes retained: the reproduced image-status/GitRead cancellation fix
`148e7c62`, AX reads up to 500 ms within the original two-second endpoint with
100 ms Press allowance, tool-setup memory accounting, and fast preflight before
expensive hosted work. Original Tool26 unknown invocation finality from
run 40110783814 remains unknown. Neither local tests nor later runs rewrite it.

The protected Xcode test still refuses this Mac's group-writable `/Applications`;
its permissions remain unchanged. Broad legacy Python packaging tests are not
all green. No production feature gate, signed user installer, production release
or complete installed-runtime qualification is implied by these local results.
The owner's installation, credentials and original dirty checkout are untouched.
Do not modify main or publish production. The checkpoint below is historical
where it differs from the latest continuation.

Checkpoint: **2026-10-24, 15:27 UTC**.

- Repository: <https://github.com/Apdelrahman1911/mobile-release-kit>
- Branch: `checkpoint/macos-local-20261024`
- Application/source baseline: `92b6e7424f627cb304e8ad2687d9a5dfb735ec0b`.
- This checkpoint adds this handoff, not another application change.
- Target: the owner's **Apple Silicon M4, macOS 27**.
- **The automation update is not delivered.** The owner's working `0.1.2`
  installation must be preserved. Source version `0.1.3` is not a finished installer.

## 1. Instructions for the continuation agent

Continue implementation from this branch. Do not restart the feasibility review,
reimplement completed features, or apply historical `docs/*-hooks-*.patch` files
indiscriminately: many describe changes already integrated into the actual source.

Priorities:

1. Fix genuine application defects, beginning with the Git read cancellation
   described below. Reproduce the actual cause before changing behavior.
2. Prefer local, incremental Mac builds and targeted functional tests. Reuse
   valid results and signed dependency artifacts. Do not redesign CI, add test
   frameworks, perform unrelated refactoring, or fix brittle UI selectors.
3. Complete the real tool/service/CLI/key/backup operations and enable only
   features whose corresponding native behavior is established.
4. Build the ordinary user application, sign, notarize, package, verify the real
   update and essential lifecycle, and deliver an installable test artifact.
5. Keep implemented, verified, still gated, and externally blocked work separate.

The owner will do detailed UI/UX testing. The revised UI must remain guided,
simple and understandable; do not make cosmetic polish a delivery blocker.

**Do not merge into `main`, publish a production release, mutate Stores, issue
certificates, or push user application repositories without the appropriate
separate approval.** Preserve credentials, original operation finality, recovery
journals, signing/notarization, source/currentness checks and explicit authorization.
Never expose tokens, private keys, passwords or certificate contents in logs,
command-line arguments, Git or artifacts. Distribution credentials are not
project Store test credentials.

Use existing parallel workers for genuinely independent tasks if available;
avoid multiple writers to shared session/shell files and duplicate CI monitors.
No new GitHub workflow was requested merely to create this checkpoint.

## 2. First actions on the Mac

Work in a clean clone or separate worktree, not over uncommitted user changes.
For a fresh clone:

```bash
git clone --branch checkpoint/macos-local-20261024 --single-branch \
  https://github.com/Apdelrahman1911/mobile-release-kit.git
cd mobile-release-kit
git status --short
```

Inspect and reuse existing tools before installing anything:

```bash
uname -m
sw_vers
xcode-select -p
xcodebuild -version
node --version
python3 --version
rustup toolchain list
df -h .
```

Missing tools should produce a clear setup plan, not automatic global upgrades.
Relevant actual repository settings:

- `desktop/package.json`: Node `>=22.12.0`, React/TypeScript/Vite; locked npm
  dependencies. Use `npm ci` only when dependency installation is needed.
- `desktop/rust-toolchain.toml`: Rust `1.98.0`. The successful current ARM CI
  build explicitly selects **`1.98.1`** in
  `.github/workflows/desktop-macos-installed.yml`; preserve that distinction
  when reproducing the native build. Do not silently rewrite pins.
- `desktop/src-tauri/Cargo.toml`: ordinary application, installed `mrk` CLI,
  native helpers and nonshipping observers have different feature sets.
- `pyproject.toml`: shared Python core requires Python `>=3.11`.

Start with the affected Rust/application logic and its existing tests. Relevant
frontend scripts are `npm run typecheck`, `npm run build`, and the individually
named tests in `desktop/tests`; do not run the entire suite after every edit.
These are starting points, **not claims that a fresh Mac checkout has been built**.

Important local-testing limitations:

- A Vite screen or a development-runtime build is not the signed installed
  runtime. Do not claim it proves Keychain, protected tools or privileged services.
- Existing hosted installer/removal fixtures assume a disposable runner. Do
  **not** run the whole CI shell script on the owner's daily-use Mac, spoof its
  hosted identity, or overwrite/remove the working installation to make a test pass.
- Use disposable project fixtures. Obtain explicit approval before privileged
  installation/update/removal tests affecting the owner's machine.
- The clone contains versioned source and dependency descriptions, not the
  Linux machine's caches, downloaded signed payloads, secrets or private evidence.
  Acquire only needed, currently valid inputs through existing supported routes.
- Keep distribution signing in the existing `macos-developer-id` GitHub
  environment unless the owner separately provisions a supported local signing
  setup. No secret transfer is needed to begin diagnosing shared application logic.

## 3. Immediate blocker: an unrelated status refresh can stop GitRead

### Actual native result, not a hypothesis

Run <https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/40099646335>
attempt `1`, Git27 job `120888971802`, source `92b6e742...`, runner `xcode-27` ARM:

- Observer, remover and installed CLI compilation passed.
- App/package signing and notarization passed.
- Normal installation, installed-file readback and ordinary unforced detach passed.
- The first `git-index-cli` case failed at `GitCli(ReadWait)` at 15:18:31 UTC.
  Later Git cases were stopped, not passed.

The original failure contains:

```text
phase: settled
outcome: cancelled
reason: authorization
resultValid: null
failureProvenance.origin: document-stop
failureProvenance.goClaimedAtBoundary: false
appReturncode: 1
originalCallReturned: true
invocationFinality: no-pending-invocation
```

`authorization` is a generic cancellation label here, **not evidence of a GitHub
login/permission failure**. The winning error is Document stop before the GO
boundary was claimed. That flag alone is not child-entry or finality evidence.
The current invocation genuinely returned; do not retroactively change older
invocations whose finality remained unknown.

### Narrowed source chain: reproduce this first

The following chain is established by source inspection, but its exact upstream
caller has **not yet been independently reproduced on the Mac**:

1. In `desktop/src-tauri/src/shell.rs`, the retained relay calls
   `q.tick_original(&app).await` (around line 4340) before the unconditional
   `document.metadata_images_selection_status()` (around line 4393).
2. `installed_shell_observation_macos_git_cli.rs` starts the original GitRead
   in its `Step::Read`, then waits in `Step::ReadWait`.
3. In `asset_session_images.rs`, `metadata_images_capability` returns
   `OtherEditActive` when the shared Supervisor cannot exit (around line 702).
   A newly pending GitRead makes the Supervisor non-exitable.
4. `snapshot_locked` (around lines 720-724) sees a changed image capability and
   calls `DocumentBinding::bump`.
5. `asset_session.rs` `bump` (around lines 3524-3528) calls `git_read::stop`.
   The other direct caller is `invalidate_all` (around lines 5459-5462).
6. `asset_session_git_read.rs` (around lines 73-76) stops the original ticket
   with `GitReadStop::DocumentStop`.

Thus a passive image-capability display refresh can retire unrelated Git read
authority on the same relay iteration. No fix for this chain is in this checkpoint.

Next acceptance criteria:

- Reproduce idle -> pending GitRead -> image-capability refresh with actual
  application state, not only a source-string assertion.
- A capability-only display refresh must not cancel/change the original Git
  read's Document context.
- Real Document changes/loss, explicit cancellation, shutdown and stale-source
  checks must still stop the original operation correctly.
- Preserve image-status revision semantics: do not emit changed status data at
  the same revision just by deleting the bump.
- Keep original failure precedence, deadlines, lock ordering and finality.

Compare the smallest appropriate fix (for example, separating display-only
revision from Document authority) before implementing it. Do not simply remove
GitRead's revision/stop checks or increase timeouts.

Already investigated; do not restart without new evidence: mixed clocks,
renewed budgets, normal GO/EOF cleanup, generic GitHub authentication failure,
optional Git index refresh, and first-read CLI Host startup. The current winning
Document-stop result is substantially more specific.

## 4. Independent Tool26 verification was still running at checkpoint

Same run/source as above, attempt `1`, **Tool26 job `120888971939`**, macOS 26 ARM.
Latest retained metadata at this checkpoint:

| Stage | Actual recorded status |
| --- | --- |
| Observer/remover/installed CLI compilation and DATA checks | Passed |
| Application and package signing/notarization | Passed |
| Normal Installer and installed-file verification, step 63 | Passed at 15:22:14 UTC |
| Fixed native service request/readiness, step 67 | In progress from 15:22:19 UTC |
| Installed CLI, step 68 | Pending |
| Tool acquisition/cancellation/SDK reuse, step 70 | Pending |
| Key generation/reuse/cold restart/backup, step 71 | Pending |

Read the result of **this existing job** before scheduling replacement work.
Do not reinterpret in-progress, skipped or missing results as passes. The Linux
Tool agent owns its sole monitor; no second watcher or artifact download is needed.
If that agent supplies a later result, it supersedes this timestamped snapshot.

The preceding real Tool failure was `installation / payload-mismatch`:

- The signed Store payload legitimately contains spaces and `%` in names such
  as Fastlane templates and `Terminal Notifier` files under `runtime/store/`.
- The producer already validates the correct scoped full inventory paths.
- The consumer wrongly applied generic path grammar to bare filenames.
- Integrated fix `6bc36585` in `installation_observation_macos.rs` uses the
  existing full-path grammar only for indexed payloads. Fixed control rosters,
  membership, no-follow checks, identity, ownership, limits and deadlines remain.
- Actual-source focused regression passed; producer changes were not needed.
  Post-fix **service success remains unverified** until the above job establishes it.

## 5. Other recent corrections already integrated

- `21ce6508`: truthful failure exit for an early Git read failure before any
  CLI Host workers start. Current Git native failure now returns exit 1 with no
  pending invocation; it does not fabricate successful work.
- `6bc4de7c`: bounded winning-original-error Git provenance, not secret/error dumps.
- `92b6e742`: two missing `failure_provenance: None` initializers in repository
  summary test data. The prior run `40096760249` failed compilation with E0063,
  not an application operation. Both omissions were reproduced locally, six
  existing focused tests passed after correction, and both current Mac builds
  subsequently passed their observer compilation.
- Source version `0.1.3`, genuine previous `0.1.2` update nomination and ARM update
  routing are integrated. They are preparation, not an actual update pass.
- Xcode companion minimum macOS 26 with no upper ceiling is integrated. Actual
  macOS 27 Xcode archive/export remains a separate unverified operation.

All completed relevant subagent fixes above are integrated. There were no
uncommitted Git/Tool source edits to transfer when this checkpoint was made.

## 6. Approved scope and implementation status

Most feature code below is integrated and has component tests. This table is
**not** a claim that all functionality works in the installed application.

| Area | Implemented scope and important remaining boundary |
| --- | --- |
| Beginner-friendly Desktop | Guided local-first setup, staged requirements, contextual explanations, resumable setup and readiness/rehearsal views. Package for the owner; detailed UX is their manual test. |
| Shared Desktop/CLI | Installed Rust `mrk`, authenticated local application service, project/status/history, scoped authorization, cancellation and external-change invalidation. Some routes still require running Desktop and original native selections/review; unattended full parity is not claimed. |
| Project identity | Recognized native Android/iOS, KMP and CMP layouts; Application ID/Bundle ID preview/apply, stale-change protection and recovery. No namespace/source-package refactoring. Refuse dynamic/generated/ambiguous controlling settings, and preserve published identity. |
| Git/GitHub | Selected existing `gh` account token obtained in native code and reused with the existing HTTP transport, repository status/diffs/staging/commit/branches, repository/PR/Actions operations. Do not switch the user's global `gh` account unnecessarily. Actual installed Git flow is blocked as above; Fetch/Push are gated. |
| GitHub setup | Existing workflow/configuration, environment/settings, release/preflight/counter and recovery preparations. Genuine authorized provider operations still require account/repository permissions. |
| Android signing keys | Reuse-first assessment, explicit JKS upload-key generation, fingerprint verification, encrypted vault/assignment and encrypted independent backup/restore. Generation/backup remain gated pending native checks. Never regenerate on wizard rerun or assume a new upload key is accepted by Play. |
| Apple provisioning | Supported Bundle ID/certificate/profile API operations, private key/CSR, key/certificate matching, P12 and original-key recovery. Reuse first. Real account roles, agreements/API key, capabilities and authorized provider verification remain necessary. No distribution-secret repurposing. |
| Tool setup | Reuse-first JDK/SDK/Gradle/Xcode detection, missing-only acquisition, protected registration, manual-install guidance and targeted repair. New acquisition is gated pending real native checks. No upgrade/download of already compatible tools. |
| Versioning | Manual default, candidate-bound durable allocation/reservation, paired Store inventories, hosted allocation/result import and shared-counter enrollment. Retries must not increment twice; distributed uniqueness needs the actual shared counter, not merely a local lock. |
| Metadata/images | Text/localization/version editing, native image selection, metadata configuration and Desktop-prepared CLI Apply. Preserve native file/credential-selection boundaries and unsaved drafts. |
| Build/release/recovery | Shared Android/iOS build/sign/preflight/artifact/evidence/history, Store preparation/lifecycle and interrupted-operation recovery routes. Real signing/provider operations and updated-app credential reopening remain separately unverified. |

Out of scope: Flutter, React Native, a universal source refactoring engine,
automatic public Store rollout, unauthorized provider changes, or making UI
automation the delivery gate.

Currently closed production gates to inspect after corresponding native passes:

- `git_fetch_runtime_macos.rs`: protected Apple CLT Git nomination is empty.
- `git_push_runtime_macos.rs`: ordinary/new-branch Push nominations are empty.
- `credential_upload_key.rs`: native key-generation availability remains false.
- `credential_backup_desktop.rs`: encrypted backup/restore availability remains false.
- `saved_command_tool_acquisition.rs`: new acquisition availability remains false.

An earlier conditional ARM activation draft was deliberately **not integrated**.
Do not enable these merely because UI/code exists. Do not extend ARM results to
Intel or substitute a Fetch result for Push/create-only Push behavior.

## 7. Results to reuse and remaining delivery order

Existing evidence, within its original scope:

- Native project identity four-case check: run `40062565859`, job `120779026897`,
  source prefix `cadc8d9c`.
- 80 focused shared CLI/concurrency/history and 71 vault/backup/state checks.
- Real Linux shared-core Git read, four stage/unstage cases and four safe branch
  switch/dirty-tree cases. These are not installed Mac Git passes.
- Existing frontend and library/CLI compilation plus numerous focused feature
  tests. Do not confuse compilation/component tests with native or live-provider results.
- Current run's signing/notarization/installation results cover the current
  verification packages, not a newly built ordinary shipping application.

Next delivery steps:

1. Reproduce and fix the Document/image-status cancellation with targeted tests.
2. Consume existing Tool26 results; fix any genuine remaining service/tool/key/
   backup problem, independently verifying the original operation.
3. Complete outstanding actual installed Git and other affected native operations.
   Reuse retained signed artifacts when application bytes are unchanged and the
   existing supported route admits them. A changed binary needs new signing.
4. Activate only the corresponding proven ARM features, preserving all real guards.
5. Build/sign/notarize/package the ordinary `0.1.3` application with bundled core.
6. Verify real `0.1.2` -> `0.1.3` update and owned-file/credential preservation,
   basic launch/interaction/quit, and deliver the installer for manual testing.
7. Report rather than conceal remaining physical/provider/Intel limitations.

Still external or unverified: actual macOS 27 Xcode archive/signed export,
compatible Xcode/iOS platforms/licenses and project signing materials, live
Apple/Google/GitHub mutations, Intel qualification, updated-app Keychain/decrypt/
assignment reopening, and detailed owner UX testing. File preservation alone
does not establish that the updated app can use old credentials.

## 8. Code and evidence map

- UI: `desktop/src/`, especially `App.tsx`, `bridge.ts`, `pages/`, `components/`.
- Shared application/CLI: `desktop/src-tauri/src/application_service*`,
  `application_service_host*`, `service_*`, `installed_cli_main.rs`.
- Document/lifecycle: `asset_session.rs`, `asset_session_*`, `shell.rs`,
  `supervisor.rs`, `supervisor_*` under `desktop/src-tauri/src/`.
- Shared release engine: `src/mobile_release/`; Store integration: `fastlane/`.
- Native services: `desktop/native/macos-installed-native/` and existing Rust
  credential/tool/runtime modules. Extend these, not a duplicate engine.
- Packaging: `desktop/packaging/`, `desktop/tools/`,
  `desktop/macos-installed-inputs/`, `desktop/macos-xcode-setup-inputs/`.
- Main affected workflow: `.github/workflows/desktop-macos-installed.yml`.
- Retained-consumer route: `.github/workflows/desktop-macos-candidate-consume.yml`.
- User guide: [desktop/packaging/macos-preview.md](desktop/packaging/macos-preview.md).
- Architecture notes: [docs/desktop.md](docs/desktop.md). Some older scope tables
  are historical; actual source and this dated handoff take precedence for current status.

For continuity only, the existing Linux workspace was
`/root/projects/MobileReleaseKit/automation-20261019/recovered-integration-20261022`.
Its adjacent `verification/` directory retains the original Git log once as
`git27-run40099646335-job120888971802.original.log`, its bounded `.projection.json`,
and `git27-document-stop-source-20261024/README.md`. Tool continuity lives in
`automation-20261019/tool-service-run40099646335-20261024/` with the sole monitor's
`job-latest.json`, `metadata-observations.jsonl`, `monitor.log` and bindings.
These Linux files are **not included in the clone**. Do not assume local session
IDs or absolute paths work on the Mac. Public run/job identities above allow
targeted authorized retrieval when genuinely needed; do not redownload whole
artifacts/log collections by default. Never access retired private-origin or
signing-material directories to reconstruct a missing test input.

If the existing Telegram notifier is available and correctly linked, send
concise milestone/blocker updates. Do not copy its credentials or guess a session.
Keep normal user-facing reports; notification acceptance is not a read receipt.

## Suggested prompt for the next agent

> Read MACOS-CONTINUATION.md and inspect the actual source on this checkpoint
> branch. Continue the approved macOS-first implementation locally on this M4.
> Start by reproducing the image-capability refresh / Document-stop GitRead bug;
> consume the existing Tool26 result before rerunning anything. Keep changes and
> tests targeted, preserve my working app and credentials, and use existing shared
> services. Do not merge main or publish a production release. Report what is
> genuinely verified and deliver the signed/notarized installer when ready.
