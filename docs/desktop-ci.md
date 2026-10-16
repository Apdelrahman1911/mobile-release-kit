# Desktop CI

The routine desktop pipeline is `.github/workflows/desktop-ci.yml`:

1. Install `.[test]` and run the workflow's explicit Python modules with
   `python -B -m unittest`. They exercise desktop API, credential policy,
   GitHub, metadata, protocol, and recovery behavior using synthetic inputs.
   Then run `npm ci --ignore-scripts`, `npm test`, and `npm run build` on Linux.
   The build script runs the TypeScript check once before building assets.
2. After those pass, run `cargo test --locked --lib --no-default-features` and
   build both the development and embedded-frontend shells on Linux, macOS ARM,
   macOS Intel, and Windows.

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
| `desktop-session-compile.yml` | Frontend build, headless library test build/execution, and `cargo build --features desktop-shell,development-runtime` in Desktop CI. |
| `desktop-macos-panel-probe.yml` | Retired one-off panel reachability diagnostic, not an application test. Actual project navigation remains a separate native UI obligation. |
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

The fixed-carrier workflow now invokes its checked-out Python helper directly,
instead of five duplicated source-hash/read/compile wrappers. The normal
Android UI result reader was also extracted from a large YAML heredoc into
`desktop/tools/macos_android_ui_result.py`. Both trust the selected checkout
for executable code rather than hard-coded copies of that code's digest.
Actual carrier, package, certificate, profile, and TLS integrity checks remain.
These changes do not authorize an old package as a new build or establish a
successful native UI operation.

Routine jobs remove their own disposable outputs after their final consumer:
frontend `node_modules`, `dist` after successful same-run upload, and each native
job's dedicated `desktop/.ci-target` plus downloaded `dist`. Shared Cargo/npm
caches are not deleted. These cleanup steps also run after ordinary failures;
forced runner termination can prevent any final step from executing. The pure
local Store draft tests are included in the fast Python selection; they do not
establish local Store execution or authentication.

### Small Mac component builds

`desktop-macos-components.yml` compiles the Applications launcher with the
native macOS SDK on Apple Silicon and Intel, then checks its plist and Mach-O
architecture. A separate job uses ordinary `cargo check` for the exclusive
Installer and Remover roles on both architectures using their supported Rust
1.98.1 clock/toolchain tuple. Three named, pure Applications-adapter byte/data
tests run in the Installer test binary; the actual Installer/Remover main and
filesystem adapter do not run. Dispatch can select only
the launcher, only the Installer/Remover check, or both. The workflow has no signing environment, Store credentials, installed app
invocation or retained carrier download. Its new temporary output and compiler
cache are disposable and removed after their last consumer. This is component
compilation, not launcher runtime, installation, signing or distribution evidence.
The dedicated verification branch can exercise this small job without rebuilding
the Desktop application or repeating notarization.

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
