# Mobile Release Kit — macOS early preview

**This is a limited, normal application preview, not the completed Desktop product.**
It is not an observer/test executable. The package uses the ordinary
C entry → ordinary Rust `src/main.rs → shell::run()` route with bundled UI assets,
Mobile Release Kit core and Python runtime. The nested payload keeps the existing
product identity and app-data namespace; you still open the outer named app. You do not need to install Python,
Rust, Node.js or the CLI to try the application.

## Before installing

- **Verification targets:** Apple Silicon (ARM64) and Intel (x86_64), macOS 26.
  The workflow checks separate architecture-specific packages; a configured
  target or running job is not a supported-delivery claim. Use only the exact
  target whose required completed checks and distribution evidence are accepted.
  Older macOS releases, upgrades and moving the installation remain unqualified.
- Use a disposable/synthetic mobile project. Do not provide production signing
  material, live Store credentials or private release data for this early test.
- **Ordinary V2 installation requires the configured, SOURCE-selected producer
  identity:** its genuine Developer ID Application certificate/key, completed
  package signature and the native app-purpose checks. The public Application,
  Installer and notary configurations are enrolled. Current-package Installer-key,
  notarization and installed-preview verification remain pending; configuration
  is not native qualification. Credential-free engineering fixtures do **not** satisfy
  this requirement; an unsigned/ad-hoc fixture is not an ordinary V2 package.
- This delivery route additionally requires the separate SOURCE-selected
  Developer ID Installer identity and Apple notary authentication. It admits
  only the finalized payload, Installer package and user DMG after their own
  actual signing/notary/stapler checks; unavailable credentials mean no preview.
  The original user DMG is retained unchanged. Only a separate finalized copy
  whose read-only mount contains the exact `Install.pkg`, `producer.json` and
  `producer.sig` can be exported; there is no fallback to the unstapled image.
- Downloaded-image/Installer interaction and Gatekeeper qualification remain
  separate, required distribution evidence; an Accepted notary result alone
  does not prove those checks or application/worker lifecycle completion.
  Do not disable Gatekeeper, strip quarantine or change security settings to
  force installation/open. Report a refusal rather than treating it as a pass.
- Installer requires normal macOS administrator approval to place protected
  application/runtime files. The app itself must run as your normal user.
- The V2 installer checks existing linked installation records before a
  same-package no-op, missing-app restore or explicitly SOURCE-authorized
  update. Missing/unknown records, unlisted predecessors or retained failures
  are refused, not repaired by deleting files. These paths still need genuine
  native qualification; no old-version pruning is provided. Removal uses the
  separate removal disk image and its accompanying guide; its execution and recovery
  remain unqualified here.

The adjacent **PREVIEW.json** identifies the exact source commit/tree,
GitHub workflow/run/attempt, DMG/package/producer-sidecar SHA-256 values,
request-correlated installed inventory and runtime SHA-256. Its results
distinguish normal build, original Installer status and V2 readback from UI,
signing-account or complete distribution acceptance. Its final-carrier fields
bind the raw preceding receipt, original/final image hashes, original0 and
scoped native verification/mount observations. They do not turn synthetic DATA
checks into native notarization, downloaded-install or Gatekeeper evidence.

## Retrieve the matching temporary artifacts

In GitHub Actions, open the exact reviewed run and attempt, then its **Artifacts**.
Use `<target>` = `aarch64-apple-darwin` for Apple Silicon or
`x86_64-apple-darwin` for Intel, matching the actual package and reviewed job.
Neither target is qualified merely because its artifact exists.
Download the two separate artifacts with the same target, full source commit,
run ID and run attempt:

- `mobile-release-kit-macos26-<target>-preview-<source>-<run-id>-<run-attempt>`
  contains the delivery, guide and **PREVIEW.json**.
- `desktop-macos-installed-<target>-<source>-<run-id>-<run-attempt>`
  contains **public-verification-evidence.json**, not raw local logs or native results.

Keep both reports together and check their source/workflow, run/attempt and target
bindings. Do not substitute another target, run, attempt or removal-lifecycle artifact.
These temporary artifacts have **14-day retention** and can expire or be unavailable;
missing evidence is not a pass or permission to use an older package.
The delivery can be uploaded before later GUI checks complete: review the actual
completed job and check outcomes, not just artifact availability.
Preserve downloaded-file quarantine and macOS security policy while extracting
and opening the files; report any refusal without removing quarantine or bypassing it.

## Install and open without a terminal

1. Once an exact build has the required genuine qualification, open
   **MobileReleaseKit.dmg** in Finder. Inside that read-only image, open
   **Install.pkg** and follow macOS Installer. Keep the adjacent **producer.json**
   and **producer.sig** in place: do not rename, move or separate the three files.
   An arbitrary standalone package copied to writable Downloads is unsupported.
2. In Finder choose **Go → Go to Folder…** and enter:
   `/Library/Application Support/MobileReleaseKit`
3. Double-click **Mobile Release Kit.app**.

Keep the app in that protected location: the runtime is installed beside it
under a versioned directory. Do not move the app to Applications or elsewhere.
No Applications shortcut, drag-install or relocation support is claimed.

The package-export receipt is intentionally a **build/Installer/readback
snapshot**: its automatic-open and normal-Quit fields remain unexecuted at that
stage. The same hosted job subsequently runs one external XCTest scenario
against the exact ordinary app, without instrumentation: launch through the
entry, render, open/Cancel the real project picker, Cancel the genuine Quit sheet,
navigate safely, then genuinely Quit. One permanent-gate observation checks
exclusion while the app/picker is live and availability after observed Quit. Look for the
matching **public-verification-evidence.json** in the separate evidence artifact.
Its `normal-ui/test.status` and `normal-ui/summary.status` are scalar original-return
observations, not the original XCTest counts or full UI proof. A zero scalar status
alone does not establish the narrow UI observation: the actual completed check and
its exact-source qualification still require review. Raw native results are not
published in that artifact. A missing, failed or skipped check is not a pass.

This check does not prove POSIX exit status or every worker's finality, direct
payload pre-main exclusion, Finder/Installer interaction, Gatekeeper or full
feature journeys. The root maintenance gate is permanent; never remove or replace
it as troubleshooting. Update/restore evidence and the separate removal
carrier's execution/recovery remain separate obligations. Physical/manual observations of this exact
distribution and the checklist below remain separate.

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
- The Android build/source-selection and unsigned iOS archive paths. Android
  still requires its admitted external toolchain, license acknowledgments and
  signing inputs; iOS requires a compatible Xcode/build environment. All existing
  admission checks and journey-specific native qualification remain required.

This is source-selected scope, **not acceptance of those journeys on this new
normal binary**. External Android/iOS build tools are not bundled; tool
requirements and native qualification still apply.

The paths above still need real normal-app journey verification; source
integration and Linux checks are not Mac acceptance. Source also contains gated
candidates for project-relative field-picker journeys, image selection/import,
persistent credentials, build-tool diagnostics, offline preflight and project
recovery. These implemented paths remain unqualified for this delivery; their
presence does not establish an accepted UI journey or permission to bypass a refusal.
Authenticated release dispatch, signed iOS export and iOS recovery are not
claimed by this preview. No Store mutation, public release, promotion, complete
Android/iOS lifecycle or full feature parity is claimed.

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
Cargo target gate, SOURCE-selected signing and separate producer verification,
the original standard Installer and request-correlated nonroot V2 readback.
Only known original returns, current readback and clean detachment can complete
the owned package group; unknown mounts/writers are retained, never forced away.
The same completed app/runtime input is
also used for the fixed eight-case Installer fixture before ordinary install.
Its isolated fixture roots are not user installations; only actual successful
fixture execution/readback establishes those outcomes. It does **not** repeat
the separate old ACL probe or five headless regressions. Their unchanged
engineering route remains available; their historical status is not upgraded
by this preview.

The separate project-field Aqua observer failure is preserved and unresolved.
It does not prove an ordinary human picker failed, and the preview does not
resolve it. Desktop remains **NOT READY / undelivered** until the required
capability, lifecycle, native, distribution and complete-product gates have real
accepted evidence.
