# Mobile Release Kit — macOS early preview

**This is a limited, normal application preview, not the completed Desktop product.**
It is not an observer/test executable. The package uses the ordinary
`src/main.rs → shell::run()` application entrypoint with bundled UI assets,
Mobile Release Kit core and Python runtime. You do not need to install Python,
Rust, Node.js or the CLI to try the application.

## Before installing

- **Supported preview machine:** Apple Silicon (ARM64), macOS 26.
  Intel Macs, older macOS releases, upgrades and moving the installation are
  not qualified by this package.
- Use a disposable/synthetic mobile project. Do not provide production signing
  material, live Store credentials or private release data for this early test.
- This package and app are **not Developer ID signed/notarized**. The app has
  an ad-hoc integrity signature only. Gatekeeper may refuse installation/open.
  Do not disable Gatekeeper, strip quarantine or change security settings to
  force it to run. Report a refusal; it is a distribution limitation, not a pass.
- Installer requires normal macOS administrator approval to place protected
  application/runtime files. The app itself must run as your normal user.
- Existing occupied installation destinations are refused without overwriting
  or removing their contents. Do not delete an existing installation just to
  make this preview install. Update/uninstall support is a separate obligation.

The adjacent **PREVIEW.json** identifies the exact source commit/tree,
GitHub workflow/run/attempt, package SHA-256, installed inventory and runtime
SHA-256. Its results distinguish normal build, package audit and installation
readback from UI or distribution acceptance.

## Install and open without a terminal

1. Open **MobileReleaseKit.pkg** in Finder and follow the macOS Installer.
2. In Finder choose **Go → Go to Folder…** and enter:
   `/Library/Application Support/MobileReleaseKit`
3. Double-click **Mobile Release Kit.app**.

Keep the app in that protected location: the runtime is installed beside it
under a versioned directory. Do not move the app to Applications or elsewhere.
No Applications shortcut, drag-install or relocation support is claimed.

The package-export receipt is intentionally a **build/Installer/readback
snapshot**: its automatic-open and normal-Quit fields remain unexecuted at that
stage. The same hosted job subsequently runs one external XCTest scenario
against the exact ordinary app, without instrumentation: launch/render, Cancel
the genuine Quit sheet, navigate safely, then genuinely Quit. Look for the
separate exact-source `normal-ui/result.json` engineering evidence; only an
actual successful test/count receipt establishes that narrow UI observation.
A missing, failed or skipped check is not a pass.

This check does not prove POSIX exit status or every worker's finality, Finder/
Installer interaction, Gatekeeper or full feature journeys. Physical/manual
observations of this exact package and the checklist below remain separate.

## What this source currently exposes on macOS

Subject to the existing per-request runtime, document and ownership checks:

- Project-folder selection.
- Read-only project/configuration information, configuration validation,
  suggestions and change previews, environment requirements, GitHub setup
  proposals, and saved release-version observation.
- Configuration review/Save through its existing transaction owner.
- Local GitHub workflow preview/Apply, metadata/localization text editing and
  release-version editing through the existing scoped transaction owners.
- Evidence-folder selection and session-only GitHub read-only integration.
- Supported session-only signing-input selection/assessment.
- The unsigned iOS archive path, which still needs a compatible Xcode/build
  environment and all existing admission checks.

This is source-selected scope, **not acceptance of those journeys on this new
normal binary**. External Android/iOS build tools are not bundled; tool
requirements and native qualification still apply.

The newly integrated edit/evidence/GitHub paths above still need real normal-app
journey verification; source integration and Linux checks are not Mac acceptance.
Still unavailable or not qualified here: project-relative field-picker journeys;
image selection/import; persistent credentials; authenticated release dispatch;
active doctor; offline preflight; project recovery; signed iOS export and iOS
recovery. No Store mutation, public release, promotion, complete Android/iOS
lifecycle or full feature parity is claimed.

## Small manual acceptance checklist

Use a synthetic project and retain PREVIEW.json with your observations.

- Does the normal app open? Note the macOS version and any exact error category.
- Is the selected-project state understandable?
- Select a synthetic project folder, then try canceling a folder selection.
  Verify cancel does not silently change the selected project.
- Open configuration, validate it and inspect a change preview.
- Optional: deliberately save a harmless change in that synthetic project.
  Confirm only the previewed change was saved and unrelated files survived.
- Quit normally with the application menu. Does the window close without a
  stuck process or a false completion message?

A failed or unexecuted item stays unresolved. Do not send credentials, signing
files, private project contents or raw local logs with a report.

## Verification scope

The hosted preview keeps the ordinary native package-format audit, exact normal
Cargo target gate, ad-hoc signature verification, one-shot Installer and
independent nonroot byte/mode readback. It does **not** repeat the separate old
ACL probe, five headless regressions or seven Installer-fixture cases. Their
unchanged engineering route remains available; their historical status is not
upgraded by this preview.

The separate project-field Aqua observer failure is preserved and unresolved.
It does not prove an ordinary human picker failed, and the preview does not
resolve it. Desktop remains **NOT READY / undelivered** until the required
capability, lifecycle, native, distribution and complete-product gates have real
accepted evidence.
