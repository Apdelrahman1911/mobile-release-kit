# Install, update and remove Mobile Release Kit on macOS (0.1.5)

This is the current guide for the ordinary Apple Silicon package. It supersedes
the `0.1.1` / `desktop-01` wording kept for history in `macos-installed.md` and
`macos-maintenance-data.md`.

| Item | Value |
| --- | --- |
| Package version / release | `0.1.5` / `macos26-arm64-desktop-05` (target `aarch64-apple-darwin`) |
| Minimum macOS | 26.0 |
| Package identifier | `dev.mobile-release-kit.desktop.installed` |
| App | `/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app` (bundle `dev.mobile-release-kit.desktop`) |
| Applications launcher | `/Applications/Mobile Release Kit.app` (convenience copy only) |
| Accepted predecessors | `0.1.2 / desktop-02` (`bf9d397b`) and `0.1.4 / desktop-04` (`ac506bb3`, package SHA-256 `ed44a41a…4f15`) |

Intel (`x86_64`) has no enrolled predecessor and no verified package yet.

## What the standard Installer does with `Install.pkg`

Open `Install.pkg` from the read-only carrier with its `producer.json` and
`producer.sig` beside it. macOS Installer asks for administrator approval. The
package authenticates the detached producer signature and then selects one
route from the installed state:

- **Fresh install** when neither the app nor the release exists.
- **Same-package no-op** when exactly this package is already installed and the
  app is present. No payload is rewritten.
- **Missing-app restore** when exactly this package is recorded but the app is
  absent. Only the app is restored from the package; the runtime is kept.
- **Update** when an accepted predecessor (table above) is installed with its
  app present. The new runtime and record are published, the app is switched,
  and the previous generation is retained. A downgrade or an unlisted tuple is
  refused without changes.

Your projects, project releases, saved settings under
`~/Library/Application Support/dev.mobile-release-kit.desktop`, vault contents
and Keychain items are not part of the payload and are never removed or
rewritten by install, update or removal.

## OS-managed metadata on an existing installation

macOS 27 can attach its own `com.apple.provenance` tag to an installed file
after an App Management-mediated write. Neither root nor the owner can remove
it. The maintenance audit therefore admits, on regular files of an **already
recorded** generation only, either no extended attributes or exactly that one
tag in its 11-byte version-1 form. The tag is read, never removed or copied,
and the file's bytes must still match the recorded inventory hash. Any other
attribute is still refused. Every incoming, newly created or launcher object
must have no extended attributes. The authenticated bundle roots keep their
existing `com.apple.macl` snapshot rule.

## Remove

Use the matching `Remove.pkg` from the separate removal image (see
`macos-removal.md`). With the app present it runs the live removal; with the app
absent it resumes an interrupted removal that the protected record shows was
admitted earlier. User data stays.

## Known stops (refused safely, no data loss)

These cases end in a refusal, not damage. Keep the result files and report them.

1. **Removal after an interrupted-restore retry.** If a missing-app restore was
   interrupted and then completed by a retry, the record links a
   `restoreRecovery`. Live removal refuses that link (current or archived), and
   the resume route needs an absent app and an earlier removal admission. The
   app keeps working; removal for this history is not yet qualified.
2. **Maintenance after a recovered failed update.** If an update fails before
   its state is published and the worker's bounded inverse restores the old app,
   the state records `InverseRecorded`. The old app works, but ordinary
   maintenance (update, no-op, removal) requires `MutationRecorded` and stops.
   Treat this as a recovered failed update, not a successful one.
3. **Interrupted-removal resume over a provenance-tagged file.** The live update
   and removal walks admit the OS provenance tag as described above. The separate
   archive census of an interrupted removal still requires zero attributes.

Do not delete protected directories, change permissions or strip metadata to get
past a refusal.
