# Desktop CI

## Functional-first policy (2026-10-18)

Detailed GUI interaction is owner-tested manually, not a delivery gate. Do not
repair selectors or repeat signed builds to make obsolete XCTest journeys green.
Use [the manual trial guide](desktop-macos-manual-test-guide.md) for the existing
signed ARM/Intel candidates and [functional coverage](desktop-macos-functional-coverage.md)
for what each automated suite really proves. Failed or unexecuted operations
remain unresolved; retiring an assertion does not turn them into passes.

Routine path: **fast business/controller tests → affected native tests/build →
package only when release inputs change → owner-approved distribution**.

- Test/docs-only changes still run fast checks when the workflow is triggered,
  but do not rebuild native shells. Shared Rust fixtures, native test inputs,
  product inputs and unknown paths conservatively select native checks.
  Selection runs inside the existing fast job, not on another VM.
- Manual Desktop CI can select macOS, ARM, Intel, Linux, Windows or all. Automatic
  product checks retain all supported platforms. Use local Linux checks first;
  do not dispatch the all-platform workflow just to validate a YAML change.
- Reuse a passed package only for the same application/runtime/configuration
  inputs and valid signature. A changed test helper is not a changed application.
  Existing artifact/run/source identities remain; no new receipt framework.
- On failure inspect the failed step first. Rerun only affected failed jobs;
  retain valid independent results and cancel only our redundant work. Signing,
  notarization and Store actions are never routine unit-test operations.
- Keep real credential, transaction, recovery, installation/update and package
  checks. Mixed legacy native workflows retain their integrity tests until
  equivalent direct checks exist; their remaining UI dependencies are not passes.

## Current Mac candidate package

The fixed `verify/desktop-macos-candidate` branch selects a package-only route
in `desktop-macos-installed.yml`. It reuses the nominated signed Python, Store,
GitHub and Android components, builds the current application, and performs real
application/package/image signing, notarization, installation and readback.
It does not repeat the unrelated fixture Installer, broad DATA suites, separate
Remove image or broad UI suites. Existing targeted component checks remain separate.

The separate **Prepare Xcode.pkg** companion runs independently in the same
workflow: select branch `verify/desktop-macos-xcode-setup`, operation
`xcode-setup-companion`, and one target when manually dispatching. That branch
has no push trigger. This job does not rebuild the main app or fetch its runtime
suppliers. It uses the `macos-developer-id` environment for the appropriate
signing/notarization steps only; installation verification is credential-free.

Its Cargo build, Application signing, Installer signing/notarization, and
first/repeat installation are distinct steps. Both installations reuse the same
finalized companion and source inputs; a failed/unknown first install never
triggers a repeat. Its files and bounded results are separate artifacts, not
extra members of the main DMG. Companion failure does not fail or restart the
main candidate build. Neither a signed companion nor its installation alone
qualifies the Desktop's installed iOS workflows.

The default manual operation, `prepared-install`, still requires the original
`prepared_source`, `prepared_run` and target. Use it for an unchanged prepared
package; it cannot insert a source fix into an already-built Installer. A
cross-source manual retry uses the current installed-record reader after the
actual Installer succeeds, while retaining the original package, producer,
signature and source bindings. This allows an observer correction to be tested
without rebuilding or re-signing the application. It cannot finalize or
nominate a release candidate; that still requires a coherent same-source run.

If a companion installation fails, the job preserves the original Installer
status and reports bounded hook/native/error observations from the existing
Installer-log interval when available. These observations cover the interval
from before the first installation through the failed installation, not an
authenticated attribution to one process. Missing diagnostics are not success,
and raw Installer-log text is not exported by this companion diagnostic.

Only after the main package checks pass does it retain `MobileReleaseKit.dmg`,
`PREVIEW.json` and an installation guide for 14 days. Use the complete DMG:
the package requires its authenticated sibling files on the mounted image.
This internal candidate is **not installed-UI-qualified or production-ready**.
Testing the emitted carrier must not rebuild/re-sign it just to run UI checks.
The post-upload Applications/Android XCTest tail is removed. Candidate retention
does not qualify every feature; ordinary launch/quit and detailed UI interaction
are recorded separately, with the latter now assigned to manual testing.
The package helper's existing bounded failure diagnostics appear directly in
the job log; raw signing/notary captures and credentials do not.
Rejected payload, package and image submissions now include bounded known issue
classes from the same already-returned, validated Apple log. No second signing
or notarization run is needed for that diagnostic; raw paths/messages and
submission identifiers remain private. Diagnostic failure never changes the
original rejection or acceptance checks.

Current-candidate reuse preparation now has a small inert parser in
`desktop/tools/macos_candidate_carrier.py`. It binds the exact nominated
per-architecture push/run/attempt/job/artifact and requires successful Installer,
final-image, candidate-staging and upload steps; a later UI failure is not
mistaken for a failed package. It authenticates the three-member candidate
archive and preserves the preview's unqualified status. ZIP metadata allocation
is bounded before parsing, including rejection of ZIP64 limit overrides.
Seven focused local methods passed, followed by the targeted ZIP64 regression;
independent implementation review accepted the slice. The existing old ARM
origin and execution route are unchanged. The separate candidate-consume workflow
now runs only the existing non-UI interrupted-Restore regression, using the
explicitly nominated candidate. It does not rebuild or re-sign that application.
An observer fix or source review does not establish a successful Restore.
No signed carrier was downloaded locally for this preparation.

Installed/Aqua builds install the exact numbered Rust toolchain with standard
Rustup (ARM 1.98.1, Intel 1.98.0), then verify the existing compiler identity and
clean-configuration requirements. They do not assume the hosted image's moving
`stable` distribution matches the required version. Shipping source loading uses
the current Git inventory rather than a redundant hardcoded script size/hash;
the bounded read and artifact/provenance checks remain intact.

The routine desktop pipeline is `.github/workflows/desktop-ci.yml`:

1. Install `.[test]` and run the workflow's explicit Python modules with
   `python -B -m unittest`. They exercise desktop API, credential policy,
   GitHub, metadata, protocol, and recovery behavior using synthetic inputs.
   Then run `npm ci --ignore-scripts`, `npm test`, and `npm run build` on Linux.
   The build script runs the TypeScript check once before building assets.
2. When native inputs changed, run `cargo test --locked --lib --no-default-features`,
   `cargo check` for the distinct development-runtime configuration, and one
   embedded-frontend shell build on the selected native platforms. Automatic
   product checks use Linux, macOS ARM, macOS Intel, and Windows.

The ARM job also selects the existing ignored private-APFS vault lifecycle test:
real storage create/read/replace/delete and failure cases in a fresh owned
directory, without Keychain or real credentials. It reuses the compiled library,
checks the exact test exists, and cleans that directory after return. The new
selection is syntax-reviewed but **not yet executed on Mac**; Intel and actual
credential import/restart continuity are not covered by this step.

The jobs use the existing package scripts and Cargo features directly. They do
not generate source receipts or select special verification branches. The only
artifact handoff is the exact frontend artifact ID from the same workflow run.
There are no signing credentials, privileged installers, or release uploads.
Core Python/Ruby checks run separately in `ci.yml`.

`ci.yml` keeps its protected `test` status while selecting core checks from
changed paths. Desktop-only changes do not repeat the unrelated core matrix.
Changes to core code, package inputs, dependencies, or verification tools still
run it. Selection errors fail rather than silently skipping verification.
Manual targeted runs now validate their selected jobs instead of failing because
unselected jobs were skipped. They publish **Targeted core check (...)**, never
the protected full-CI `test` status. Full runs still require the existing native
checks and signing-matrix artifact reduction.

The Python selection is a fast behavioral subset, not discovery of every
`tests/desktop` module. Platform fixtures and heavyweight native integrations
remain separate. These checks do **not** establish that an installed application can launch,
select projects, store credentials, or quit correctly. A shell build is not a
package or an installed UI test. Ignored native integration tests also do not
become covered merely by running the ordinary library test command.

The separate `desktop-session-gtk-compile.yml` keeps its existing verification
branch push trigger and also supports manual dispatch, without an expected-SHA
input. It uses ordinary dependency installation and frontend build commands,
Python/JavaScript syntax checks, C compilation against DBus/AT-SPI, and
`cargo test --locked --no-default-features --test session-gtk-qualification --no-run --features desktop-shell,development-runtime`.
Neither the C fixture nor the Rust integration executable runs. This is
compilation coverage, not native session qualification; it creates no custom
receipts and removes only its dedicated compiler outputs and checkout-local
frontend outputs.

## Removed workflows

| Previous workflow | Replacement or reason |
| --- | --- |
| `desktop-session-compile.yml` | Frontend build, headless library tests, development-runtime typecheck and embedded shell build in Desktop CI. |
| `desktop-macos-panel-probe.yml` | Retired one-off panel reachability diagnostic, not an application test. Detailed project navigation is manually tested. |
| `desktop-macos-engineering-ui.yml` | Retired selector-driven GUI journeys; functional tests remain and detailed UI is manual. |
| `desktop-macos-fixed-carrier-resume.yml` | Retired duplicated fixed-carrier GUI orchestration; reuse the retained candidate for manual trials. |
| `desktop-macos-normal-ui-build-intel.yml` | Retired UI-runner-only compilation, not an application build. |
| `desktop-macos-installer-chain.yml` | Retired comparison of three fixed public certificate files. Package signature and trust verification remain in the package pipeline. |
| `desktop-macos-intel-os-providers.yml` | Retired provisional inspection of three system images; it did not establish supplier authority. |
| `desktop-macos-notary-admission.yml` | Retired one-off notary tool admission observation. Actual notarization and verification remain in the package pipeline. |
| `desktop-macos-notary-key-shape.yml` | Retired secret-shape diagnostic. The protected package pipeline still validates and uses the existing notary credential. |

No application security check or package identity check was removed.
The unused panel, Installer-chain, and Intel-provider diagnostic tools and their
probe-only tests were also removed. The panel's standalone Objective-C probe
was not a product build target. The notary diagnostic adapters remain for now:
their tests also exercise real package-parser and tool-trust behavior, which
must be retained when those tests are moved off the adapters.

Pure workflow-shape tests for the retired GUI workflows were removed. Existing
helpers are retained where they share real native/package safety logic. Carrier,
package, certificate, profile and TLS integrity checks remain; no old package is
authorized as a new build.

Routine jobs remove their own disposable outputs after their final consumer:
frontend `node_modules`, `dist` after successful same-run upload or when no native
consumer is required, and each native
job's dedicated `desktop/.ci-target` plus downloaded `dist`. Shared Cargo/npm
caches are not deleted. These cleanup steps also run after ordinary failures;
forced runner termination can prevent any final step from executing. The pure
local Store draft tests are included in the fast Python selection; they do not
establish local Store execution or authentication.

### Small Mac component builds

The Store signing projection excludes the exact lock-checksummed
`terminal-notifier-2.0.0.gem` installation-cache archive. Apple's notarization
service also inspects the optional unsigned app inside that cache; removing its
installed copy alone was insufficient. Installed gem sources, licenses,
specifications and native extensions remain unchanged. The receipt declares
this one omission separately from compiler objects. Older signed-component
receipts remain readable only with their original cache present; that does not
make them notarization-qualified. Reuse the original unsigned Ruby assembly for
the corrected signing batch instead of compiling Ruby again.

`desktop-macos-components.yml` supports targeted manual selections:

- `launcher`: Swift compilation, plist, architecture and linkage checks on both Macs.
- `installer`: native Installer/Remover compilation plus the named pure
  Applications/recovery tests; no Installer/Remover main or filesystem adapter runs.
- `installer-recovery`: only the named recovery tests after unchanged compilation
  and launcher tests have already passed.
- `installer-frames`: only the private-frame/parser regression when the remaining
  installer checks already have applicable successful results.
- `app`: frontend and the actual packaged Tauri image graph, plus the two named
  memory-only Mac Store cleanup/ownership tests in the headless Mac library.
  The shipping-image role deliberately rejects a unit-test harness. This is not
  installed UI testing.
- `app-contracts`: only those two tests, reusing an unchanged successful image
  build rather than rebuilding the frontend and Tauri dependencies.
- `ui-build`: compile the existing external XCTest target on both Macs, without
  building, signing, installing or launching the application.
- `integration`: the changed app and installer checks together, without rebuilding
  the unchanged Swift launcher or re-signing the Store component.
- `store-runtime`: reuse the selected signed Ruby/Fastlane component, verify its
  native signatures, run its loader with networking denied and check its originals.
  No Store lane, signing, notarization or application build runs.

These jobs use no signing environment or Store credentials. Task-owned compiler
outputs and caches are removed after their final consumer. Compilation and loader
results do not establish installation, signed distribution or feature completeness.

### Trusted checkout instead of frozen helper code

Aqua, the normal UI runner, GitHub tool preparation, Android dependency
preparation, the fixed-carrier helper, and the read-only Mac helper no longer
compare their checked-out helper code against hard-coded copies of its digest.
The read-only helper also no longer requires a literal detached `.git/HEAD`:
the workflow explicitly checks out its selected commit. This deliberately
removes the duplicate source admission, not package provenance verification.
Fixed helper paths, bounded reads, applicable original-file mutation checks,
module-collision handling, deadlines, and cleanup remain. Downloaded artifacts,
release configuration, signing identities, certificate fingerprints, and TLS
checks are separate and were not removed.

Pure Swift/Rust/YAML source snapshots and historical patch-inversion tests were
removed. Tests that execute parsers, reducers, filesystem operations, failure
handling, or lifecycle logic remain. The Mac behavioral selection now derives
its counts from its explicit current test list rather than a frozen selection
hash. Actual executed IDs and counts must still match that selection; failures,
skips, partial execution, and unknown cleanup are not successes. Diagnostics
retain their existing size/privacy limits without duplicating the test list in
every context record.

## Package and specialized native migration is incomplete

The existing `desktop-macos-installed.yml` and its CPython, runtime-signing,
Android-support, and GitHub-tool supplier workflows still provide packaging. They use the
custom runtime, resident image, Installer, and signed package producers; a bare
Tauri build cannot replace them. `desktop-ubuntu-publication.yml` likewise
remains a distinct runtime-publication pipeline.

The current legacy package routes are still selected by their existing
verification branches. They are **not** part of pull-request CI. Existing
`macos-developer-id` environment protection, secret names, artifact provenance,
and signing/notary verification are unchanged. Moving this code into a small,
manual, environment-protected package workflow is follow-up work, not a claim
made by this change. No public release is produced by Desktop CI.

The old foundation, connection/TLS, workflow-edit, environment, GNOME, and macOS
installed/Aqua jobs contain distinct integration or UI tests. They remain until
their meaningful cases have ordinary replacements; deleting their YAML would
not make the new test matrix equivalent. Some also have compile-only helper
graphs or credential enrollment tasks not represented by the shell build.

The reusable preflight, candidate, external-testing, and production-submission
workflows are product release callers, not obsolete desktop diagnostics. They
are unchanged.

## Local validation checkpoint — 2026-10-16

No hosted workflow was dispatched, no signed carrier was downloaded, and no
Store, notarization, public release, main update, or branch push was performed
for this change. Local checks used synthetic inputs; process-sensitive Python
checks ran as a non-root user in a read-only, networkless namespace with private
temporary storage. Temporary build dependencies and outputs were removed after
use; small diagnostic logs were retained outside the repository.

- Frontend: **719 tests passed**, TypeScript/Vite build passed.
- Rust library: **838 passed, 18 ignored**, no failures. The ignored tests are
  still native verification obligations, not passes.
- Python desktop fast subset: **253 passed**; the subsequently added Android
  result-reader module separately passed **5 tests**.
- Core affected-path selector: **6 passed**. Required/targeted status handling:
  **232 synthetic status scenarios** and **7 existing workflow tests** passed.
- Fixed-carrier helper: **15 passed**. Checkout loaders: **4 passed**.
  Native-helper preparation: **4 focused tests passed**.
- Lifecycle fixture corrections: **7 passed**. Three corrected staging tests
  passed, including the complete existing package failure-injection method.
  **13 retained behavioral tests** also passed after source-only assertions were removed.
- Shipping reducers/privacy: **6 passed**. Mac failure diagnostics: **9 passed**.
  Observer selection/result/routing: **6 passed** across focused runs. Public
  failure projection: **6 passed**. These are local behavioral checks, not
  evidence of a native Mac operation.

An earlier wider legacy check ran **1,050 tests and failed** (102 failures and
46 errors, including subtests). Subsequent focused work resolved selected real
fixture defects and removed obsolete snapshot assertions. That entire check
has **not** been rerun, so there is no claim that all remaining legacy tests pass.
The full Mac/Windows/Linux shell matrix, installed launch/lifecycle, and actual
signing/notarization/package checks remain unexecuted for this branch.

The ordinary CI pipeline and these cleanup changes are **not an application
READY verdict**. Remaining work is the specialized package/native migration,
remaining meaningful legacy failures, actual platform execution, review of the
final application, and owner-approved delivery. Existing successful application
checks should be reused only where the relevant source and toolchain are unchanged.

Independent implementation reviews accepted the loader changes, workflow/status
handling, test-fixture fixes, current-roster integration, and source-only test
retirement. Review found and resolved a count-binding regression and diagnostic
size overflow before acceptance; neither was waived.
