# Manual macOS candidate trial

Updated 2026-10-18. **Private candidate trial, not a public release or a claim that
every feature works.** The owner will test the interface manually; unfinished
XCTest journeys are not feature passes. Use a disposable Mac VM for this trial:
the current download does not include a matching uninstaller.

## Choose the correct download

These are the existing signed/notarized candidates from
[run 39116948396, attempt 1](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/39116948396),
application source `fcb1aa46fb95e601479078fdc98ba05acb701c05`.
Both architectures completed their packaging, Installer, final-image and artifact
retention steps. The later producer UI tests failed; the whole run is **not** a
successful UI qualification.

| Mac | Required system | Download |
| --- | --- | --- |
| Apple Silicon | macOS 26.x; native ARM64 | [Artifact 12134468997](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/39116948396/artifacts/12134468997) |
| Intel | macOS 26.x; native x86_64 | [Artifact 12134938034](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/39116948396/artifacts/12134938034) |

Check **Apple menu → About This Mac** first. The current Installer allows macOS
26.0 through 26.x, **not** macOS 27 or older systems. Do not substitute the other
architecture or use Rosetta as a workaround. GitHub access may be required.
Both artifacts were available on 2026-10-18; their current retention expires on
2026-11-01 (ARM 11:19:26 UTC; Intel 11:23:45 UTC). Ask for renewed delivery if a
link expires rather than downloading an unrelated build.

The ZIP contains `MobileReleaseKit.dmg`, `README.md` and `PREVIEW.json`. Keep the
guide and metadata. For independent download verification, the recorded **ZIP**
SHA-256 values are below; these are not hashes of the individual DMG:

```text
ARM   110514695 bytes  b3441b310812d7527f6d5a30e942fd5e26c8a62277f3174fd002db3bdbabc47c
Intel 113033403 bytes  63bbdae7d00da1609396fd0896dd03d97efced596cfec5dcd4c29654d687b50b
```

## Install and open without bypasses

1. Start with a disposable VM and copies of test projects. Preserve a VM snapshot
   from before installation. Do not install over an important existing copy.
2. Open `MobileReleaseKit.dmg` in Finder. Open **Install.pkg inside the mounted
   image** and follow macOS Installer, including its administrator prompt. Keep
   `producer.json` and `producer.sig` alongside the package inside that image.
   This is **not** a drag-and-drop app installation; do not extract just the PKG.
3. Keep quarantine, Gatekeeper, SIP and normal permissions enabled. Stop if macOS
   rejects the package or its identity is unexpected. Do not disable security,
   remove quarantine, run the app as root or change protected-folder permissions.
4. After Installer reports success, open **Finder → Applications → Mobile Release
   Kit** as the ordinary user. The launch entry is
   `/Applications/Mobile Release Kit.app`; the protected app is at
   `/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app`.
   Do not move/copy the protected app or its inner payload.
5. Check that the dashboard loads and **Open project** works. Use the normal app
   menu to Quit, then reopen. An installation-location card alone is not an
   installation-integrity or signing check.

No separate Python, Rust, Node.js, Ruby or Mobile Release Kit CLI installation is
needed for the bundled application. Mobile build tools remain separate below.

## Manual feature checklist

Use a trusted, disposable project copy. Record **pass / fail / not tested** for
each applicable item; a disabled control is not a pass. Read the app's review and
consent before any write or execution. Do not use production signing credentials
or request Store uploads during this trial.

| Area | What to exercise and check |
| --- | --- |
| Project and help | Open the project with the native picker; verify the selected path and saved configuration. Visit navigation and contextual help. Cancel a picker and confirm the previous selection remains. |
| Project settings | Edit a test value, validate and inspect the proposed files. Cancel the review first: files must remain unchanged. Then explicitly confirm Save, refresh and verify the saved value. Unrelated project files must remain unchanged. |
| Version | Read the saved version; open its editor, review and save test values. Read it again. Check unrelated keys/comments and the separate unsaved Settings draft are preserved. |
| Metadata | Configure and save a test locale. Load/edit public text, review exact destinations, cancel once, then save. Select test PNG images through the native picker and inspect names, digests, dimensions and destinations before confirming any copy. Keep source images unchanged. |
| GitHub and evidence | Review workflow proposals before Apply; cancel first and check no files changed. Use disposable repository settings. Inspect existing release documents through the real picker; observation must not dispatch a workflow, upload or silently prepare a release. |
| Credentials | Use disposable test signing material through the private picker, not manual internal-folder copies. Exercise assessment, explicit save/assignment, lock/unlock, normal Quit/reopen and any permitted replacement. Never include secret values in feedback. |
| Environment and offline checks | Observe installed tools, then review the selected project's saved inputs before running offline checks. Unsaved drafts must not silently become execution inputs. Project hooks may execute: “offline” is not a sandbox or a promise of no network access. |
| Android | With compatible tools and a trusted test project, exercise source-folder selection, inspection and explicit protected-copy setup; then saved-input review, consent, one local build and output inspection. Test signing only with disposable upload credentials. No Play upload is requested here. |
| iOS | With compatible full Xcode, first try the separate unsigned-archive flow and inspect the output. Signed IPA export and account recovery need their own genuine test inputs and explicit review; an unsigned archive is not a signed-export pass. No App Store upload is requested here. |
| Recovery and normal exit | If a genuine pending operation is reported, preserve its files and use its supported Inspect/review/recovery controls. Confirm the selected operation and proposed effect before consent. Check normal Quit and reopening. Do not kill Installer or delete journal files to manufacture a recovery test. |

For writes, compare the project copy before/after, not just a success banner.
Cancellation is not rollback of already executed project code. Stop on an
unknown or unfinished result; do not repeatedly start the same operation.

### External mobile-tool prerequisites

- **Android:** supply compatible official JDK, Android SDK and Gradle folders
  using the app's Browse controls. The app includes its fixed support tools;
  finding Java alone does not establish build readiness. Follow the actual
  source-inspection, license and service-registration requirements. Do not
  rename/move vendor folders or accept licenses on someone else's behalf.
- **iOS:** obtain full compatible Xcode from Apple and finish Apple's first-run
  setup and required platform installation. The separately supplied, matching
  **Prepare Xcode.pkg** prepares a protected copy; it is not part of this app ZIP
  and does not download Xcode or accept Apple's licenses. Its signing/notarization
  and first/repeat installation were tested on both architectures; that is not a
  complete iOS-build or signed-export result. See [iOS archive guidance](desktop-ios-archive.md).
- **Mobile signing is separate from Mac app signing.** Developer ID Application,
  Developer ID Installer and notarization credentials do not sign an iOS app for
  distribution. Local signed IPA export needs an Apple Distribution certificate
  and private key in a P12, a matching distribution provisioning profile, and
  matching controlled team/bundle ID/certificate fingerprint. Android uses its
  upload keystore and matching upload-certificate fingerprint. Store API
  credentials are separate again. Never send these private inputs in chat or Git.

## Update, removal and interrupted installation

These are **remaining lifecycle checks**, not completed features inferred from
successful packaging. There is no automatic updater. A different/newer arbitrary
PKG is not permission to replace this installation.

- **Update:** wait for a genuinely matching, authorized successor installer and
  its instructions. On a disposable test installation, save work, use **Prepare
  app to quit** when available and Quit normally. Test the actual update, reopen,
  and verify project data, saved credentials and assignments survived. A
  qualified predecessor/successor pair has not yet been established for this
  delivery; do not attempt to manufacture one by editing metadata.
- **Removal:** this candidate has **no matching removal image included**. Do not
  Trash the Applications entry as a substitute, delete the protected tree or run
  an unrelated remover. When a matching `MobileReleaseKit-Remove.dmg` is supplied,
  follow its `REMOVE.md`, use its genuine `Remove.pkg` and required app consent,
  and verify projects/credential data remain. The existing
  [removal guide](../desktop/packaging/macos-removal.md) describes the intended
  route; it is not proof that a remover for this download is available or tested.
- **Failure/interruption:** wait for Installer to finish and preserve its result
  and existing files. Some interrupted installations require the exact original
  release's complete Install image; newer is not necessarily suitable. Installer
  → **Window → Installer Log** provides details. Review before sharing: logs can
  contain private paths. Missing files or Installer exit zero alone do not prove
  recovery. Current automated Restore reached baseline and installation, but its
  later withdrawal/interrupted cases still failed and are not qualified.

Ordinary removal/reinstall, a real authorized update with credential continuity,
and interrupted install/removal remain separate from manual UI acceptance. Do
not deliberately interrupt production installation on an important machine.

## Feedback and verification limits

Report the architecture, macOS version, artifact ID, area/action, expected result
and actual result. Redact screenshots; do not attach credentials, private project
files, raw native captures or unreviewed logs. Keep the original project copy and
failed operation state available locally for investigation.

Some automated failures were harness selector/fixture/transport defects, not
proven product defects. They still do not establish successful features. This
guide does not certify complete Android/iOS builds, Store operations, credential
persistence, all file editors, update, removal or interrupted recovery on either
architecture. Manual findings and actual lifecycle outcomes decide what works.

Source references: [selected candidate metadata](../desktop/macos-installed-inputs/candidate-carrier-selection.json),
[Installer OS policy](../desktop/macos-installed-inputs/Distribution.xml),
[Installer recovery instructions](../desktop/macos-installed-inputs/InstallerReadMe.html),
and [engineering evidence and limitations](desktop-macos-completion.md).
