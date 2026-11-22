# Remove or resume removal of Mobile Release Kit for macOS

This is the separate **removal** disk image, not the application installer. It is built for the matching managed Mobile Release Kit source/release shown in `REMOVAL.json`. Keep the matching application installer if you may reinstall.

1. Save your work and stop release/build operations in Mobile Release Kit.
2. Open `MobileReleaseKit-Remove.dmg`, then open **Uninstall Mobile Release Kit** from the mounted image. The app uses the signed `Remove.pkg` and its two signed sidecars beside it on the read-only volume.
3. Choose **Uninstall App (Keep My Data)** to preserve your data. Choose **Uninstall App & Delete All Data** only when you want to erase this app's own settings, drafts, history, caches, and saved credentials after successful removal. Confirm that choice separately.
4. Choose **Continue**, follow macOS Installer, and enter administrator authorization when prompted. The running app asks you to confirm removal, finishes its work, and unregisters its service. Quit Installer when it finishes to see the uninstaller's result.
5. If Installer reports a problem, keep the removal image and its diagnostic result for recovery. The remover refuses unknown installations, unrelated files, active or unknown original operations, or unmatched signing evidence.

## What stays

Keep My Data preserves your projects, project releases, signing assets, saved vault contents and Keychain credentials. Delete All Data requires a second confirmation and a protected completion report for the same installation. If Installer is cancelled or removal is interrupted before completion, user data is kept.

## Interrupted removal

If removal was interrupted, preserve its result and use this same matching removal image again. This is a **new explicitly authorized attempt**, not evidence that the previous attempt succeeded. Recovery authenticates the protected prior admission and every remaining original under fresh exclusive maintenance ownership; missing files alone are not success evidence. There is no automatic fallback from a failed live-app attempt to the recovery route.

The ARM64 0.2.5 removal image also recognizes one enrolled 0.2.3 removal artifact. It can resume a protected attempt that recorded a post-check failure at the payload-removal stage after the original app was withdrawn. The new package and current removal program must authenticate independently. The archived 0.2.3 removal and installed-producer files must still match the enrolled artifact and the remaining payload. Use this image only with a fresh explicit authorization to resume the interrupted removal.

After confirmed removal, use the matching application installer to reinstall. Protected recovery/control state and preserved user data are reauthenticated; reinstall does not silently relabel an earlier unknown result or restore signing identities from the package. A refused recovery should be investigated rather than bypassed.

## Test-build evidence

`REMOVAL.json` binds this carrier to its source, package, signatures and actual packaging run. A packaged-and-image-verified result does **not** establish that initial removal, interrupted recovery, a downloaded Gatekeeper launch or your machine's behavior has been tested. Review the application's completion report for those results before using this build on an important installation.
