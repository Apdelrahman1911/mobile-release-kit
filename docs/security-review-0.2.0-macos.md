# Scoped macOS security review — 0.2.0 (#30)

Addendum to [security-review-0.1.4-macos.md](security-review-0.1.4-macos.md),
for the macOS 0.2.0 candidate on `fix/macos-release-015` (release
`macos26-arm64-desktop-06`), reviewed 2026-11-19. Scope is macOS only; it is
not a release approval or a complete cross-platform #30 sign-off. No
credential, Keychain item, repository setting, environment or publishing
workflow was read or changed.

## Gates carried over from 0.1.4

| 0.1.4 item | 0.2.0 state |
|---|---|
| P1 `ctutils 0.4.2` (RUSTSEC-2026-0385) in the helper/image locks | Resolved: every macOS lock that contains it (`src-tauri`, `helpers/macos-desktop-image`, `helpers/macos-android-register`) locks `0.4.4`. |
| P2 `tokio 1.48.0` (RUSTSEC-2026-0386), needing a coordinated refresh | Resolved: the application and both path-dependent helper locks moved together to `tokio 1.51.6` / `tokio-macros 2.7.2`; `cargo metadata --locked` passes for each, and the android-register helper compiles with the refreshed lock. |
| P2 other target: `rustix 1.1.5` (RUSTSEC-2026-0486), `glib 0.18.5` | Unchanged and still not in the macOS graph (see below); Linux/Windows work. |
| P2 owner setting: repository-level signing secrets | Unchanged; needs owner settings work (environment protection). |

## Dependency advisories (2026-11-19)

Method: every registry package in the six macOS Cargo lockfiles and
`desktop/package-lock.json` (581 package versions) was queried against the
public OSV database, which carries the RustSec and GitHub advisories that
`cargo audit` and `npm audit` report. "Shipped on macOS" means the package is
in the normal-dependency graph of a shipped macOS binary (both targets, all
features), which is the same inventory as the bundled third-party notices.

| Package | Advisory | Shipped on macOS | Disposition |
|---|---|---|---|
| `vite 7.3.1`, `esbuild 0.27.7`, `source-map-js 1.2.1` | Dev-server advisories (path traversal, `server.fs` bypasses, launch-editor on Windows, dev-server DoS) | Only Vite's module-preload helper is bundled; the vulnerable dev server never ships | P3: bump `vite` to ≥ 7.3.7 for developer machines. No product exposure. |
| `chrono 0.4.45` | RUSTSEC-2026-0543, unmaintained (informational) | Yes | No vulnerability. Track a maintained replacement. |
| `unic-*` 0.9.0 (5 crates) | RUSTSEC-2025-0075/0080/0081/0098/0100, unmaintained (informational) | Yes (via the Tauri UI shell) | No vulnerability. Track upstream migration. |
| `proc-macro-error 1.0.4` | RUSTSEC-2024-0370, unmaintained | No (build-time macro, other target) | None for macOS. |
| `rustix 1.1.5` | RUSTSEC-2026-0486, fixed in 1.1.6 | No | Linux/Windows exact pins; raise there. |
| `glib 0.18.5` | RUSTSEC-2024-0429 / GHSA-wrw7-89jp-8q8g | No (GTK) | Linux. |
| `zbus_names`, `zvariant`, `zvariant_derive` | Unmaintained (informational) | No (Linux secret service) | Linux. |

No advisory with a known vulnerability applies to code shipped in the macOS
package.

## Changes in 0.2.0 that touch security-relevant behaviour

- **Disk images (#51).** Install and Remove images show only the installer or
  uninstaller. The signed sidecars (`producer.json`/`.sig`, and the Remove
  sidecars) stay beside the package with unchanged names, bytes and 0444
  modes; only `UF_HIDDEN` is set, and the packaging tool re-verifies identity,
  size and flags after hiding. Images are now APFS, because HFS+ turns
  `UF_HIDDEN` into a synthesized `com.apple.FinderInfo` attribute and every
  readback requires attribute-free originals. Installer and removal already
  admitted read-only local `apfs` and `hfs` images. No signature, notarization
  or integrity check was relaxed.
- **Uninstaller (#83).** A Developer ID signed, hardened-runtime, notarized
  AppleScript app in the Remove image. It has no entitlements and no privacy
  usage descriptions. Removal itself is the unchanged signed `Remove.pkg` run by
  the standard Installer. "Delete All Data" runs as the signed-in user (it
  refuses root), only after the managed app is confirmed absent (exit 65
  otherwise), and only on fixed per-user paths for the app's three bundle
  identifiers, each only if it is a real entry owned by the user. Links are
  kept and reported, never followed, and `rm -x` never crosses volumes. Keychain
  deletion matches the app's three exact service names; macOS may ask the user
  to allow it, and a refusal is reported as kept. The hosted remove check proves
  cancellation, Installer-quit recovery, refusal while installed and scoped
  deletion against decoys (a look-alike sibling, a project folder, `~/.config/gh`
  and link targets).
- **Third-party notices (#29).** Notices are generated from the lockfiles, and
  the packaging stager refuses to ship them once any lockfile no longer matches
  the digests they were generated from.
- **Installed signature (hosted fresh check).** The installed app must pass
  `codesign --verify --strict --deep`, a Gatekeeper exec assessment as
  Notarized Developer ID, and carry the hardened runtime flag.

## Unchanged from 0.1.4

The CSP, the single local `main` capability and the entitlements used for the
shipped bundles are unchanged by this batch. The registered command review in the 0.1.4
document still applies; 0.2.0 adds no Tauri command.

## Open items (owner action, not filed automatically)

1. P2 owner setting: move macOS signing secrets into a protected environment.
2. P3: bump `vite` (dev dependency) to ≥ 7.3.7.
3. P3: track maintained replacements for `chrono` and the `unic-*` crates.
4. Other platforms: `rustix 1.1.6`, GTK `glib`, Linux `zbus`/`zvariant`.
