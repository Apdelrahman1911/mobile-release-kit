# Remove or resume removal of Mobile Release Kit for macOS

This is the separate **removal** disk image, not the application installer. It is built for the matching managed Mobile Release Kit source/release shown in `REMOVAL.json`. Keep the matching application installer if you may reinstall.

1. Save your work and stop release/build operations in Mobile Release Kit.
2. Open `MobileReleaseKit-Remove.dmg`. Keep all three files together on the read-only mounted image. Do not copy only `Remove.pkg` into Downloads.
3. Open `Remove.pkg` only when you intend to remove this managed installation **or explicitly resume an interrupted removal**. macOS Installer requests administrator authorization.
4. For an existing application, the authenticated app asks you to confirm removal, finishes its own work and unregisters its service. Cancellation is not successful removal.
5. The remover refuses an unknown installation, unrelated files, an active/unknown original operation, or unmatched signing/source evidence. Do not force-delete files or retry by changing permissions.

## What stays

Your projects, project releases, signing assets, saved vault contents and Keychain credentials are preserved. This operation is not a request to erase your data. Unknown files are not treated as disposable application files.

## Interrupted removal

If removal was interrupted, preserve its result and use this same matching removal image again. This is a **new explicitly authorized attempt**, not evidence that the previous attempt succeeded. Recovery authenticates the protected prior admission and every remaining original under fresh exclusive maintenance ownership; missing files alone are not success evidence. There is no automatic fallback from a failed live-app attempt to the recovery route.

After confirmed removal, use the matching application installer to reinstall. Protected recovery/control state and preserved user data are reauthenticated; reinstall does not silently relabel an earlier unknown result or restore signing identities from the package. A refused recovery should be investigated rather than bypassed.

## Test-build evidence

`REMOVAL.json` binds this carrier to its source, package, signatures and actual packaging run. A packaged-and-image-verified result does **not** establish that initial removal, interrupted recovery, a downloaded Gatekeeper launch or your machine's behavior has been tested. Review the application's completion report for those results before using this build on an important installation.
