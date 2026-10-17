# macOS completion plan and working status

Updated: 2026-10-17. **NOT READY; not delivered or approved for public release.**

## Agreed target

Standalone macOS 26+ application for Apple Silicon **and** Intel. Preserve the
Rust/Tauri application and shared Python release engine. Normal operation must
not require a terminal, separately installed Python/Rust/Ruby, or manual copying
of credentials/assets into internal directories. Xcode, Android SDKs and other
genuine consumer build prerequisites remain explicit doctor/setup requirements.

Both GitHub-backed release workflows and **direct Mac-to-Store operations** are
required. Direct Store execution is new scope: the existing CI-only mutation
guard must not be disabled, relaxed or supplied with fabricated GitHub context.
Android production remains draft preparation; Apple submission retains manual
public release. Main changes, public Desktop distribution and live Store
mutations require separate owner approval.

## Completion milestones

1. **One integrated Mac candidate.** Preserve the handoff and older staged work;
   integrate accepted changes deliberately. Fix native project/picker navigation
   and verify the actual bundled runtime on both architectures. Enabled controls
   and successful compilation do not establish installed functionality.
2. **Everyday UI.** Discovery, initialization, explicit target selection,
   configuration preview/save, metadata/locales/images/version persistence,
   native file/folder/multiple selection, contextual field help, progress,
   actionable errors, history and domain-specific recovery. Preserve unrelated
   files and reject changed originals instead of silently overwriting them.
3. **Credentials and local builds.** Finish signing and nonpublishing online checks;
   verify Keychain persistence/replacement/restart/update behavior, doctor,
   Android build/sign/inspect and real iOS archive/export/recovery. Format
   assessment is not successful signing or account access.
4. **Complete GitHub setup.** Reviewed workflow Apply plus scoped commit/push/PR;
   complete App Review and commitment input mappings; configure and read back
   required secrets/variables/environments/protection without replacing custom
   rules. Complete release dispatch, tracking, history and reconciliation.
5. **Direct Store route.** Explicit project opt-in and clean observed local Git
   source; typed local authorization; durable original intents; existing shared
   Store transitions; build-once promotion and conservative recovery. Local
   evidence stays separate from GitHub authentication. Reject cross-origin
   promotion/recovery initially. Bundle locked Ruby/Bundler/Fastlane and native
   dependencies for both architectures; do not require a user gem installation.
6. **Installation and distribution.** Normal discoverable Applications entry
   without moving the protected runtime; coherent Desktop/package versions;
   enrolled two-generation updates; preservation of projects/credentials/history;
   guided safe uninstall; approved Developer ID/Installer signatures, notarized
   and stapled distribution artifacts, installation and launch verification.

### Current local-source preparation slice

Owned Android-candidate preparation now observes the actual clean local Git
source and holds the selected config/version and Git controls through its scope.
It uses eight bounded Git calls, refuses executable filters and unsupported
repository layouts, supports packed nested branches, and preserves the existing
CI mutation guard. A separately reviewed optional Android service hook now
retains the same signed artifact and saved inputs through original producer
closure, with bounded read-only consumption and focused failure tests. It adds
no second artifact copy or Store call. The combined source/metadata/fresh-output
binding is now integrated with optional signed-Mac candidate creation, durable
local journal checkpoints, and the existing UI/native operation. Review checks
the current retained bundle; Abandon records cancellation and preserves files.
Candidate creation does not upload to a Store or authorize a release. Local
Store intent/authority DATA has separate closed Python/Ruby readers; parsing
these records grants no execution permission. Durable Android Prepare and
explicit-consent Execute, plus read-only prepared-intent and completed-receipt
History review, are integrated in source. Target-only Google Reconcile and its
restart file-review route have independently reviewed core/UI implementations;
joined native and installed qualification remain pending. Reconcile is a fresh
current-target check, not upload retry, general recovery or promotion. Direct
Google recovery/promotion and Apple Store operations remain unfinished. Receipt
review never establishes an old operation's finality or authorizes a retry.
Candidate integration passed the actual Mac app/helper graphs and 27 focused
native tests on each architecture in run `38969579047/1` at `18a54582`; positive
installed Create/Review/Abandon and Keychain flows remain unverified.

## API and compatibility boundaries

- UI calls typed Rust application commands and the existing core, not CLI-text
  parsing or duplicate release logic.
- Credential verification and local preflight use selected native private inputs.
- Local release prepare/start/status/cancel/reconcile have explicit authority,
  original-operation identity and durable settlement. Parsing a draft does not
  grant permission or prove source, credentials, artifacts or Store state.
- Python and Ruby must agree on GitHub versus local execution identity. Existing
  GitHub evidence readers and CI authorization remain compatible and enforced.
- Repository publication and removal expose reviewable operations, not arbitrary
  shell commands, force-push or unrestricted deletion.

## Verification and resource policy

Use ordinary focused Python/Rust/TypeScript/Ruby tests, then real Mac XCTest and
native integration checks. Fast Linux checks precede relevant hosted work. Build
and sign a changed package once; independent installed feature groups reuse that
same immutable artifact. Harness-only fixes must not rebuild/notarize the app.
Retain artifact/signature/provenance safety checks, not redundant source-hash
snapshots or copied implementation tests. A skipped/unexecuted check is not a pass.

Required journeys include fresh install/launch/edit/restart/quit; picker cancel
and reselection; credential persistence and denied access; both native build/sign
paths; GitHub setup and lifecycle; local release policy and evidence separation;
timeouts/network ambiguity/partial recovery; update/reinstall/uninstall integrity.
Use fixtures for Store mutations unless the owner separately authorizes a real
test. Authenticated service checks still require suitable credentials and consent.
Google Play access preflight creates and attempts to delete a temporary uncommitted
edit; cancellation or network failure can leave it to expire. It never commits
the edit or publishes a release and must not be described as zero-write.

All available four slots may now be used (primary plus three subagents), with
disjoint edits and independent reviews for important boundaries. Serialize heavy
builds where necessary, stop only task-owned workers and remove only disposable
task-owned outputs. Do not delete shared caches, dependencies needed next, or
required artifacts/evidence.

## Current evidence and remaining work

- Reference `handoff/2026-09-08` remains clean at `ae6a973de8cbebb22c64ce1c689c1568669b9ec7`.
- Active integration started at `0d7a050b`: CI simplification already has focused
  local verification recorded in `desktop-ci.md`; it is not complete Mac acceptance.
- Older ARM application source `ce644711fb6e2bea26182473441aac192d5638e1` has retained
  signing/notarization, installation and basic launch/quit evidence. The latest
  old harness run `38817185242/1` failed project navigation. Neither that package
  nor an updated harness establishes current feature completeness or Intel parity.
- Picker correction `75c3c36f` has independent implementation source acceptance.
  Actual Mac run `38831920863/1`, job `116752397422`, passed fresh installation,
  XCTest compilation and launch/cancel/quit (1/1), but failed both project-open
  journeys. Both typed paths now read back exactly; navigation completion is
  still unverified. Follow-up `8dfcc59e`, run `38833645811/1`, again passed
  installation, harness compilation and launch/cancel/quit but failed project
  navigation: one test observed the parent panel ready only after the shared
  five-second interval; the other reported a typed-value mismatch. This does
  not prove autocomplete caused the mismatch. `57a6c215` now uses the standard
  Paste action for the synthetic path and ordinary 15-second UI expectations
  within the unchanged whole-case deadline. Original panel, exact path, final
  Open and project/file readbacks remain required. Run `38835494056/1` again
  passed basic launch but both project paths remained empty after Paste.
  Source inspection then found the application replaced the native menu with
  File/Quit only. Commit `e6771bc0` restores standard AppKit Edit actions.
  That product fix needs a newly built application; rerunning the unchanged
  signed carrier cannot verify it. Only small sanitized UI artifacts were
  downloaded locally, never the signed application carrier.
- Desktop npm version alignment is implemented and statically checked against
  the existing app/package `0.1.2`; the Python core remains `0.3.0`.
- Initial local Store draft validation `c9c96314` passed independent source review
  and 8 pure tests (0 failures/errors/skips). It is not authenticated intent,
  executable local Store support or a completed milestone.
- A minimal nonprivileged Applications launcher component is implemented and
  independently source-reviewed. Native run `38834106254/1` at `c969ef283a7b6c9dd13a3173ede0c900410992df`
  passed Swift compilation, plist and architecture checks on Apple Silicon
  (job `116759213883`) and Intel (`116759214327`); both cleanup steps passed.
  The prior compile failed on an unavailable Security constant; the fix uses
  public SDK flags without weakening signature/Team ID checks or claiming
  offline OS trust evaluation. Signed installation/lifecycle integration and
  actual launcher invocation remain pending.
- App Review contact/demo and operation-commitment credential records and
  GitHub mappings are integrated (`6f5fee5c`): original private borrowing,
  exact key/version pairing, no double Base64 encoding. Focused Python and
  frontend tests and TypeScript checks passed. The combined headless Rust gate
  passed 29 tests. Installed Mac credential journeys remain necessary.
- Signed iOS preparation previously could not assign a required private
  dependency token in its original signing context. Commit `03f6f55a` fixes
  that narrow applicability mismatch without changing the shared core's
  requiredness or borrowing identity. Python assessment tests: 30 passed;
  focused Rust assessment tests: 24 passed. Real Apple Distribution/profile
  signing remains distinct from these tests.
- Signed Applications-launcher staging (`6bc13979`) passed five filesystem
  tests; strict inventory/lifecycle decisions (`2946444b`) passed three Rust
  tests. Native component run `38835805273/1` also confirmed both architectures
  compile with system-only linkage and no rpath. Native install/update/removal
  enrollment and actual launcher invocation remain unfinished.
- The private Ruby/Bundler/Fastlane builder has independent source review.
  The optional Intel-only `terminal-notifier` executable is excluded from this
  fixed-lane runtime; wrapper/licenses remain. Both native jobs in
  `38837216127/1` compiled Ruby/OpenSSL/libyaml, then failed because the new
  Bundler tried to replace Ruby's default launcher. `b1f5714a` uses a separate
  private launcher directory and copies the core's complete tooling roster.
  No final runtime smoke passed in that run. Compilation and gem assembly are
  being separated so failed assembly can reuse a verified native base.
- Explicit local preparation policy (`4998f3ad`) is available through the
  existing guided settings editor. It defaults off, preserves actual branch
  policy, and does not grant mutation authority. The focused draft/config/help
  gate passed 31 tests, including unchanged CI-only mutation refusal.
- GitHub workflow Apply and scoped setup branch/draft-PR publication are now
  implemented. Installed authenticated setup/publication and reconciliation
  remain verification obligations; local Apply alone is not publication.
- The signed Ruby/Bundler/Fastlane component now passes on both architectures:
  `desktop-macos-python-runtime-signing.yml`, `38888466802/1`, source
  `7d58cc4d4787957b43d067166a729fcf697697f2`; ARM job `116931896706`, Intel
  `116931896493`. Each completed 133 native sign/verify pairs and closed the
  temporary credential scope, restoring the original keychain selection.
  Exact compiler-only gem objects were excluded, and a missing fixed Store
  signing identifier was corrected without weakening the certificate rules.
  This is component signing, not installed runtime execution or app readiness.
- Packaging now selects those exact signed Store components and composes them
  once with the signed Python capsule and current core. The actual composed
  runtime binding is retained before app compilation and reused by notarization;
  stale Python-only manifest pins no longer describe the combined runtime.
  Six focused consumer methods passed with inert native/credential boundaries,
  as did the current helper-input and scoped runtime-inventory boundary tests.
  Native combined-runtime loading and current app packaging remain pending.
- Installer and Remover native compilation plus five pure Applications adapter
  cases passed on both architectures in `38887513050/1` at `1dfb974e`; its
  separate recovery case failed obsolete fixture bounds. The focused recovery
  case subsequently passed on both architectures in `38889752254/1`, source
  `3dd50b32fe6cbd18637ef4e73660a3734eb0d161` (ARM job `116936098732`, Intel
  `116936098294`). This rerun deliberately did not repeat the successful
  compilation/launcher cases. No installation or crash-recovery runtime pass
  is inferred from pure tests. Interrupted Noop/update integration is ongoing.
- The previously authorized Mac SSH route timed out again on 2026-10-16.
  No build or worker was started there. Native verification continues through
  GitHub macOS runners rather than blocking independent work.
- Applications-launcher packaging is integrated in `3815dcbf`: the fixed G2
  signing owner signs its original bundle before the outer application; the
  existing single payload notarization submission now staples and verifies the
  launcher separately. Four focused methods passed (including refusal cases
  and the unchanged two-ticket route), with independent implementation acceptance.
  These use inert Apple-service boundaries; actual native package qualification
  is still required. No additional notarization submission was introduced.
- The small signed Store loader check `38891319610/1`, source `0958cbb9`, failed
  on both architectures before native signature or Ruby calls. The restored
  component contains legitimate `%gem_name%`/`%plugin_name%` templates and
  internal-space filenames rejected by overly narrow packaging path rules.
  A complete public unsigned inventory also exposed input-only empty directories
  and deeper paths. Context-scoped packaging fixes are in progress; the passed
  signing run is not being repeated. Both failed jobs cleaned their task outputs.
- The corrected standalone loader passed on both Macs in `38896469051/1`,
  source `49ecaf2b04b5ae3c284d6e9a91a358c018fd6b7f`: ARM job `116958026367`,
  Intel job `116958026790`. Each verified all 133 Developer ID images, executed
  the real CRC32/Fastlane loader smoke with networking denied, and rechecked
  all 6,534 files plus the original directory roster. Both cleanup steps passed.
  No Store lane, rebuild, signing or notarization ran. App, launcher and installer
  jobs were deliberately skipped; this does not establish their completion.


- The combined local Rust gate now passes 11 focused tests: local Store consent,
  private credential borrowing, original deadlines, cancellation and dropped GO,
  cleanup/finality, reciprocal operation exclusion, contextual runtime paths,
  and genuine-prior-state Noop recovery. The first test compile caught a missing
  new-domain arm in an offline-only test helper; its explicit refusal arm was
  corrected. The successful rerun compiled in 1m53s and ran in 0.02s, with zero
  failures or ignored tests. No native installer or Store call ran. Store
  integration and the broader Python packaging slice have independent source
  acceptance; native installer path parity and current Mac compilation remain
  the next gate, not a completed installed-app milestone.

- `6968400c` integrates the local Google Play preflight UI/native bridge and
  scoped signed-Store packaging paths. Five frontend tests pass, including a
  failed-Cancel regression: only an explicit retry may resend the exact original
  cancellation; automatic loops and clearing unknown ownership remain forbidden.
  App-only native run `38900278450/1` is in progress on both Macs. Installer work
  is being checked separately so it does not hold up app compiler feedback or
  require rebuilding the app for installer-only changes.
- Interrupted Noop recovery and the native installer/remover Store-path adapter
  have independent source acceptance. The next native installer selection runs
  nine named inert cases, including the two new recovery cases and a real
  path/partial-roster/removal-ancestry regression. This does not yet prove actual
  interrupted installation or removal. RestoreFixedApp pre-publication work is
  detached and incomplete; Update and later Restore interruption paths remain
  unresolved. No new recovery feature is counted as installed-runtime verified.

Important local logs are retained under
`/dev/shm/mrk-ci-simplification-results-20261015/`; compiler targets and test
scratch were removed after their final consumer. The task-owned Cargo download
cache is retained for imminent checks, not a running build worker.

All six milestones remain open. Remaining external inputs may include an actual
iOS test project and Apple Distribution profile/key, authorized Store test apps
and credentials, and a controlled GitHub repository. Desktop Developer ID and
notary credentials are not substitutes for mobile application signing inputs.
No specifically physical-Mac-only blocker is currently established.

Final acceptance requires working major features on both installed Mac builds,
no unresolved security/data-loss/recovery/signing blocker, accurate limitations,
and signed/notarized installers. Do not describe a compile, draft or preview as
feature-complete. The preliminary full-scope estimate is 2–4 engineering weeks;
native failures, credentials and the newly added direct Store route affect it.

## Current native compiler checkpoint — 2026-10-16

- App run `38900278450/1` at `6968400c2963d05b8f02af3e3c4dc09493c9200f`
  compiled the frontend and actual packaged-image graph on ARM (`116970538799`)
  and Intel (`116970539354`). Both jobs then failed before the two Store tests
  executed: their command mistakenly enabled the shipping-image feature, which
  intentionally refuses `cfg(test)`. The correction uses the existing headless
  Mac library for these unchanged memory-only methods; no shipping guard changes.
  The successful image builds remain useful evidence, not successful whole jobs
  or an installed-application pass. Both job cleanup steps completed.
- Installer run `38900790236/1` at `4d9b5f479971fa850bba0a2f134590917d49789e`
  passed both native role checks and eight of nine pure cases on ARM
  (`116972251856`) and Intel (`116972252246`). The failing private-frame case called the now-supported
  recovery tag `5` unknown. Its corrected fixture checks that a partial tag is
  incomplete, sealed truncation/ordinary paths still fail, and unknown tags
  `6`/`255` fail. Production parsing is unchanged. Targeted rerun
  results remain to be recorded; a failed job is not counted as passing.
- The installed Applications launcher journey now has independently reviewed
  XCTest source and five passing focused Python runner tests. It observes the
  launcher callback separately from the payload launch event; neither a source
  review nor those tests establishes an actual installed launch. Native XCTest
  compilation and the real installed journey remain required.

### Focused native follow-up and candidate preparation — 2026-10-16

At `90cbec591eb5279118423bf8d5836e95577892b3`, all selected jobs passed on
macOS 26 ARM64 and Intel, including each job's disposable-output cleanup:

| Run / attempt | Actual scope | Result |
| --- | --- | --- |
| `38902482750/1` | Two memory-only Mac Store contracts per architecture | Passed |
| `38902489232/1` | Corrected private-frame contract per architecture | Passed |
| `38902495062/1` | External XCTest `build-for-testing` per architecture | Passed |

Unselected jobs were intentionally skipped, not counted as passes. The earlier
failed whole runs remain failed; their successful component builds are reused.
The Applications launch/quit journey is compiled, **not yet executed**.

The reviewed candidate route now separates packaging from unrelated fixture,
removal and UI work. Six focused admission/export/failure tests passed locally
as nonroot with a read-only checkout and no network; YAML and all 83 shell
blocks parsed. Existing signing/notary/Installer/readback gates remain required.
Metadata checks found all eleven required signed/source input artifacts available
and unexpired; this is availability evidence, not a new native qualification.
Four GitHub-tool artifacts expire on October 17 around 06:49–06:52 UTC, so later
builds must recheck availability rather than assume they remain downloadable.

No current candidate artifact or new installation/readiness pass is claimed at
this preparation checkpoint. Restore recovery remains detached and incomplete.
Main and public releases remain untouched.

### Candidate preparation fixes — 2026-10-16

Candidate run `38905628857/1`, source `43441eef4b4aa8b8a9d2dcf2ada17c55f1fd4509`,
failed before app compilation, credentials, signing, notarization or installation:

- ARM job `116988351915`: the hosted `macos-26-arm64/20261013.0424` image
  supplies Rust 1.99.0, not the required 1.98.1. The old opaque diagnostic does
  not identify the first failed predicate. Install the exact numbered official
  toolchain, use its versioned directory in all current consumers, and retain
  compiler/host/configuration checks. Failures now identify a bounded stage.
- Intel job `116988352035`: `compose-store-runtime` authenticates configured
  Python before History selection but has no `configured_signing` CLI flag.
  History's gate incorrectly required that absent flag. Admit this exact command
  alongside the existing routes, without changing authentication or provider
  custody. The regression reproduces the old refusal on **both** architectures.

Independent production review accepted these fixes and the inventory-bound
shipping loader. Focused local results: composition/Store **12 passed** (2.334s,
nonroot, networkless, inert native boundaries); affected Aqua **4 passed**
(0.101s); configured compiler environment **1 passed** (1.804s); shipping-loader
failure injection **1 passed** (0.039s). Both workflow YAML files and 127 shell
blocks parse; their actual Rust admission blocks are identical. Four historical
installed inverse/source-snapshot tests were neither repaired nor reexecuted;
this is focused validation, not a claim that all historical tests pass.

The same necessary successor also runs the previously reviewed single
Applications XCTest **after** candidate upload. It reuses the installed app and
does not add another signing/notarization cycle. Native results remain pending.
All local test workers joined; namespace scratch was disposed. No current Mac
installer, installed UI pass, complete recovery or readiness verdict is inferred.

### Real Fastlane layout correction — 2026-10-16

Run `38911528887/1` at `08f76efe1e7597565a2869a1a1324be037fa2ba2`
passed pinned Rust admission on both Macs, then failed runtime preparation before
app compilation/signing. A bounded diagnostic successor (`014d33b1`, run
`38912347149/1`) identified ARM's exact failing check: `prepare_runtime.py:282`,
the required Store-file roster. Its Intel job failed earlier while downloading
the selected seal helper; that is not another composition result.

The locked official `fastlane-2.235.0.gem` contains `fastlane/lib/fastlane.rb`,
not `lib/fastlane.rb`. All three runtime consumers had the same incorrect path.
Correct the Python preparer, final stager and Rust installed-inventory validator;
do not remove the required entry or change the signed dependency component.
The official 1,182,208-byte gem matched `Gemfile.lock`; only passive archive
inspection occurred, with no source execution or signed-carrier download.

An independently specified real-layout fixture reproduces the old failure on
both targets. Corrected Python checks passed: 19 executions, 15 distinct methods
(four imported methods were redundantly discovered), 4.603s. The standalone
Rust inventory test passed locally with rustc 1.98.0 and explicit GCC 13; the
first isolated attempt could not resolve the host's `cc` alternatives link and
did not run the test. All scratch/output was removed with its test namespace.
Independent plan and distinct implementation review accepted the correction.
Native candidate verification remains necessary; no readiness claim is made.

### 2026-10-16 joined local-history/recovery implementation

Local-history UI now joins the actual Document/Saved Session, original project
lease, sequential Keychain helper and shared Python journal. Enrollment and
verification remain separate from build or Store authority. Source review fixed
healthy cleanup incorrectly creating a failure, pre-admission refusal preventing
lease closure, ordinary unused-source refusal becoming cleanup-unknown, and an
unnecessary credential-context prerequisite. Unknown closes still refuse.
Independent helper workspace lockfiles now include the same existing HMAC edges.

The same-candidate interrupted-Restore adapter is integrated but its workflow
nomination remains inactive until an actual suitable candidate exists. Signed
checkpoint reuse now tolerates unrelated later producer-job failure only when
all three required checkpoint steps succeeded. The installation UI accepts the
native 16,384-file scalar bound; the former 2,048 limit rejected the Store bundle.

The joined Linux core/checkpoint/Restore tests passed **24/24** (2.408s). Separate
source-bound evidence includes 16 installation tests, 11 history/frontend tests,
full TypeScript checking, 38 lower-native DATA tests and 4 protocol tests. These
are not installed Mac acceptance. A full Linux library-test codegen was SIGKILLed
and is not a pass; its disposable compiler outputs/workers were removed.

Existing Mac component selection now checks the app/helper graphs and runs only
5 native-wire plus 8 headless app contract tests. Native execution of that joined
source is still required. The earlier candidate at `28d6dce7` is building/signing
on both architectures in run `38957286639/1`; it does not contain these changes.
Real three-holder lifetime, Keychain, installed journeys and direct Store
execution remain unfinished. No new ready installer or main delivery is claimed.

### Local candidate integration — 2026-10-16

Create, Review and Abandon are integrated across UI, Rust and the shared core.
Create keeps the original signed AAB plus its metadata/report/manifest; it does
not rebuild for promotion or grant Store authority. Signing material is sent
only after the pending journal checkpoint, and successful completion requires
all four native acknowledgments, five helper joins and original build cleanup.
Independent source review corrected cancellation cleanup, final-ACK/STOP timing
and inconsistent negative-result handling before integration. Focused local
checks passed: 77 UI/controller tests and TypeScript/production frontend build;
58 core tests plus 5 successor codec tests; 48 Rust protocol-data tests. These
counts overlap where successor checks reuse existing coverage. They are not
installed Mac, actual Keychain, signing-build or Store-operation acceptance.

Prepared package producers succeeded on both architectures at older source
`28d6dce7` (run `38957286639/1`). Installer retry `38967044255/1` at current
harness `e0671e4e` passed preparation but returned a nonzero Installer result.
Its log diagnostic rejected the changed mount-path convention, so the actual
Installer failure reason is not yet established. The diagnostic correction
reuses the retained package; no successful installation is inferred.


### Target-only Google Reconcile — 2026-10-17

The reviewed Reconcile core reuses the existing Store lane and original
source/credential/runtime owners. After restart, **Review for Store check** reads
the current last execution's retained prepared files against local history and
Keychain. It makes no Store call. A separate fresh consent then authorizes a
Google check of the exact internal-testing target. The lane creates an
uncommitted edit, reads its state and attempts to delete it; failed cleanup may
leave that edit to expire. It never uploads, replays mapping, commits, promotes,
rebuilds or re-signs an artifact.

A successful receipt means only that the current complete target matches. It
does not repair earlier native finality, retire old attempts, change the old
journal or authorize another upload. Missing, partial or conflicting targets
remain refusals; unknown original cleanup remains unknown. The earlier prepared
and execution evidence is preserved. This is **not full release recovery**.

Current verification boundaries:

- Native run `38992445045/1`, source
  `f3727c4e998e2b4caae5ddbe18e1cb99cc31c5f4`, passed app/helper compilation plus
  7 wire/lease and 48 app tests on each architecture. Reconcile follows that
  source and is **not covered by this native result**.
- Reconcile source review and focused local checks passed: 65 distinct inert
  Python methods; 43 frontend methods, TypeScript and production Vite build;
  four packaging methods. These are not native Store or installed-app tests.
- Focused Play run `38993479306/1` at `2102a359` stopped before tests: the
  pinned Ruby executable returned permission denied under the test UID. No
  Supply test pass is inferred; runner identity correction is separate work.
- Joined Reconcile native checks and installed journeys remain pending. Existing
  signing/component evidence is unchanged; no new installation or live Store
  acceptance is claimed.

Next direct-Store scope remains: journal-aware Google recovery that preserves
unknown dispatches and partial success; promotion of the same authenticated
build to external testing and a non-served production draft; and Apple local
access/preparation, TestFlight upload, promotion, manual-release submission and
recovery. The shared GitHub-backed lanes already implement those Store
transitions; the missing work is their explicit local authority, original
artifact/checkpoint ownership and UI/native lifecycle, not a replacement Store
engine. Cross-origin evidence and public-release authority stay excluded.
