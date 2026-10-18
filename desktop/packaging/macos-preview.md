# Try Mobile Release Kit on macOS

**Internal test candidate, not a production-ready or publicly released app.**
Use a disposable Mac installation and a synthetic mobile project. Installed UI,
update, recovery and complete release journeys still need their own successful
checks; a signed package or an available download does not prove them.

## Choose the correct download

- Current verification targets are **macOS 26**, with separate **Apple Silicon
  (ARM64)** and **Intel (x86_64)** packages. Check About This Mac and the target in
  `PREVIEW.json`. Older or future macOS versions and Rosetta substitution are not
  qualified by these builds.
- In the reviewed GitHub Actions run, open **Artifacts** and download the matching
  `mobile-release-kit-macos26-<target>-candidate-<source>-<run-id>-<run-attempt>`.
  `<target>` is `aarch64-apple-darwin` or `x86_64-apple-darwin`.
  A legacy preview run uses `-preview-` instead of `-candidate-`; do not mix them.
- Extract the downloaded archive. Keep `MobileReleaseKit.dmg`, `PREVIEW.json`
  and `README.md` together. Candidate artifacts expire after **14 days**. Ask for
  a current reviewed build if the artifact is unavailable; do not substitute an
  older package or infer that a missing check passed.
- Read the actual run/check results supplied with the build. Downloads can exist
  even when later UI tests fail. `PREVIEW.json` identifies the build and its
  completed packaging/installation observations, not full application readiness.

These instructions supplement older downloaded guides; they do not change the
bytes or verification status of an existing artifact.

## Install and open — no terminal needed

1. Open **MobileReleaseKit.dmg** in Finder.
2. Open **Install.pkg inside the mounted image** and follow macOS Installer.
   Keep **producer.json** and **producer.sig** beside it. Do not copy only the
   package to Downloads, rename its siblings, or drag an app from the image.
3. Approve the normal macOS administrator prompt if you intend to install this
   reviewed build. The Desktop application itself runs as your ordinary user.
4. Open **Applications → Mobile Release Kit**. This installed launcher opens the
   protected application; it is not a movable copy of the app or its runtime.

The actual app remains at
`/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app`.
Do not move it, its versioned runtime, or its maintenance files. If installation
or launch is refused, preserve the result and report it. **Do not disable
Gatekeeper, remove quarantine, change permissions or delete installation state.**
Launch is still an independently required check; these directions are not a claim
that the current candidate has passed it.

## What you need to provide

Python, Rust, Node.js, Ruby and the CLI do **not** need a separate installation to
use the packaged app. Mobile build tools and your own release credentials are
separate prerequisites:

- **Android:** install a compatible JDK, Android SDK and extracted Gradle
  distribution. Use **Releases → Android build → Set up Android tools** and the
  three **Browse** controls. The UI explains service approval, inspection,
  vendor-license acknowledgment and the separate protected-copy confirmation.
  Selecting a folder alone does not register tools or prove compatibility.
  Required bundletool/AAPT2 support is supplied by the app, not a fourth folder.
- **iOS:** install compatible full Xcode from Apple and finish Apple's first-run
  setup yourself. If the reviewed release includes **Prepare Xcode.pkg**, run
  that separate matching-architecture companion with macOS Installer, then reopen
  the app. It prepares a protected Xcode copy; it does not download Xcode, accept
  Apple's licenses, modify your original Xcode or change global `xcode-select`.
  The app prefers that managed copy when present and checks it before operations.
  Environment version observations alone are not build/signing eligibility.
- **Signing:** you do not supply the Desktop publisher's Developer ID or notary
  credentials to install or open this app. Signing your own iOS app instead needs
  your **Apple Distribution** P12/private key/password and matching App Store
  provisioning profile. Android needs your upload keystore and its values.
  Store access has separate Google Play or App Store Connect credentials; an
  Apple Distribution certificate is not a Store API key.

For this early trial, use synthetic inputs, not production signing material or
live Store accounts. Credential assessment is not proof that a password, signing
identity or account works. Use native pickers; do not copy private files into the
project or the app's installation folder.

## Find the main controls

Start at **Dashboard** to choose a project. **Project settings** handles the
configuration draft and reviewed saves; **Environment** explains prerequisites
and offers explicit checks. **Credentials** handles selected inputs and available
encrypted storage; **Metadata** handles localized text and images. **GitHub**
previews configuration/workflow changes before Apply. **Releases**, **Artifacts**
and **Recovery** expose their supported operations and current restrictions.
Use each field's help and the separate preview/confirmation buttons. A visible
control is not a promise that its native operation is qualified on this build.
Do not dispatch release workflows, upload to a Store or publish during this trial.
Quit normally from the application menu when finished.

## Updates, interrupted installation and removal

There is no automatic updater or arbitrary drag-and-replace upgrade. Only a
matching verified installer with an explicitly authorized predecessor may update
this installation. Preserve projects, credentials and interrupted-operation state;
do not uninstall or delete files to force an update or restore.

The current candidate download **does not include an uninstaller**. If a separate
matching **MobileReleaseKit-Remove.dmg** is supplied and its checks are accepted,
follow its removal guide and open **Remove.pkg on that image**, with both signed
sidecars left beside it. Removal is not initiated by the Environment location
card. The supported remover preserves project/signing/user credential data; a
failed or unexecuted removal/recovery check remains unresolved. Do not substitute
moving the launcher to Trash for removal of the protected installation.

Report the build's `PREVIEW.json`, Mac architecture/version and concise actions
and error categories. Never send credentials, private project contents or raw
local logs. A failed, skipped or unexecuted check is not a pass.
