# Mobile Release Kit 0.2.13 for Apple Silicon

This candidate targets Apple Silicon Macs running macOS 26.0 or later.
Intel Macs, macOS 25 and earlier, Windows, and Linux are outside this release's
qualification. Issues [#19] and [#20] track broader platform scope.

| Item | Expected value |
| --- | --- |
| Version and installed release identity | 0.2.13 and macos26-arm64-desktop-19 |
| Architecture | aarch64-apple-darwin |
| Candidate source | Exact protected main commit in RELEASE-MANIFEST.json |
| Proposed tag | desktop-v0.2.13 |
| Package identifier | dev.mobile-release-kit.desktop.installed |
| Open from Applications | /Applications/Mobile Release Kit.app |

## Install or upgrade

Mount **MobileReleaseKit-0.2.13-macos-arm64-Install.dmg** and open
**Install.pkg** inside the image. Leave the producer files next to the
package. Approve the operation in macOS Installer, then open Mobile Release Kit
from Applications. Build tools shows the bundled runtime after initialization.

To upgrade from the enrolled signed 0.2.12, save your work and quit the app
before following the same steps. Setup authenticates the current app, package
and installation record before switching versions. It preserves projects,
drafts, settings and credentials. Earlier enrolled builds have an exact
entry in the predecessor table bound to their source, signed inventory,
policy and package digests. Downgrades and unrecognized installation records
are refused before replacement.

Running the identical installer with an intact app leaves the installation
in place. The matching package can restore a missing app when the protected
record admits recovery.

## Prepare and Quit, removal and reinstall

Save your work and choose **Prepare and Quit** from the app's menu before
maintenance if the Android helper is running. Complete the native macOS
prompt if it appears. If the app reports a refusal, keep the exact error.

Mount **MobileReleaseKit-0.2.13-macos-arm64-Remove.dmg** and open
**Uninstall Mobile Release Kit**. Choose **Uninstall App (Keep My Data)**,
then **Continue** and follow the macOS Installer prompts. If the app is open,
review its removal confirmation. Wait for the uninstaller to confirm that
removal finished and data was kept. Reinstall from the matching Install DMG.

Keep My Data preserves project folders, settings, drafts, history and saved
credentials. The remover checks the current installation and any retained
rollback generation in scope. **Delete All Data** requires extra confirmation
and proof that app removal completed. It deletes supported app-owned data
and leaves project folders and unrelated files outside deletion scope. See
[macOS removal guidance](macos-removal.md) for cancellation and recovery.

Use the matching signed media after an interruption. If a retry is refused,
retain the original files, recovery records and logs. Changing permissions
or manually moving bundles can invalidate the recovery record.

## Verify downloaded media

Download both DMGs, RELEASE-MANIFEST.json and SHA256SUMS from the
same release. In that directory run `shasum -a 256 -c SHA256SUMS`.
Compare the manifest's source commit and tree with the tag. Verify each
download with GitHub CLI, substituting the full main commit for SOURCE_COMMIT.

```sh
for asset in MobileReleaseKit-0.2.13-macos-arm64-Install.dmg \
             MobileReleaseKit-0.2.13-macos-arm64-Remove.dmg \
             RELEASE-MANIFEST.json SHA256SUMS; do
  gh attestation verify "$asset" \
    --repo Apdelrahman1911/mobile-release-kit \
    --source-ref refs/heads/main --source-digest SOURCE_COMMIT \
    --deny-self-hosted-runners \
    --signer-workflow Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-installed.yml || exit 1
done
```

Each DMG contains a separately signed and stapled Installer package. The
manifest lists both package digests and signed producer descriptors. GitHub's
source archive at the tag identifies the source. The DMGs and frozen manifest
identify the installable product.

[#19]: https://github.com/Apdelrahman1911/mobile-release-kit/issues/19
[#20]: https://github.com/Apdelrahman1911/mobile-release-kit/issues/20
