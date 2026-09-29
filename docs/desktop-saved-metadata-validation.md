# Validate saved metadata

On **Metadata**, select an enabled saved platform and choose **Validate metadata**.
The check uses the native-selected project and **every locale configured for that
platform** in saved `release/mobile-release.json`. It does not validate an
unsaved draft, create missing files, save configuration, or run automatically.

## Selected scope

- Required locale text comes from the existing core policy: three Android fields
  or five iOS fields per configured locale. Additional direct, nonhidden
  `.txt`, `.md` and `.json` files in those locale directories use the same
  text checks. Arbitrary subdirectories are not traversed.
- Android release notes use the configured saved version source and
  `<root>/android/<locale>/changelogs/<build>.txt`. Only a missing exact-build file
  permits `default.txt`; an invalid or unsafe exact-build file never falls back.
- iOS also checks exactly `<root>/review/ios-beta-notes.txt`,
  `<root>/review/ios-notes.txt` and `<root>/testflight/what-to-test.txt`.
  Their contents, lengths, digests and summaries are not returned or displayed.
  Other review/TestFlight files, private contact/demo inputs and signing material
  are outside this operation.
- Canonical Android image slots and iOS screenshot display groups come from the
  shipped core image catalogue. Observed files receive complete bounded reads
  and the existing PNG/JPEG header, dimension, count and duplicate checks.
  **Pixels are not decoded or visually validated.** Missing image slots remain
  optional under this local policy, not a promise of Store screenshot coverage.

Unrelated sibling trees, excluded paths and the other platform are not traversed.
The command accepts only a registered project ID and one platform; the renderer
cannot supply another root, policy, locale subset, file list or private input.

## Meaning and limits

“Completed local checks” is not Store readiness or acceptance. No account, Store,
URL reachability, credentials, network, external tools or project code are used.
A report is a **single-request non-atomic observation**, not a filesystem
snapshot. It is matched to the exact saved configuration bytes observed by the
current project session; externally changed files require a new explicit check.

The original named reader and passive document owner retain their existing
bounds: 128 files, 8 MiB aggregate, 10,000 directory entries, 12 path components,
32 KiB public/fixed text, five-second cooperative work and ten-second passive
endpoint. Android notes and configuration/version sources retain their existing
individual bounds. Images retain the core 10 MiB ceiling, subject to the smaller
aggregate budget; the report is at most 256 KiB. Limits, unsafe aliases/links,
changes and unconfirmed original cleanup return no complete report.

Navigation, project/platform/configuration changes, refresh/save intent and
editor activity retire displayed results. They **do not settle or replace an
original pending request**. Its passive owner must finish before a competing
saved operation or another check can start. There is no automatic retry.

## Availability and verification

The browser preview is explicitly unavailable; it never fabricates a successful
report. Installed availability follows the existing native passive-method
allowlist. This source addition includes the Linux allowlist entry, not a claim
of installed end-to-end qualification. macOS remains gated pending qualification
of that same original passive route. Windows requires a qualified equivalent
named metadata reader; the separate Windows snapshot path does not enable it.

Focused Python reader-seam, native DTO and renderer promise tests cover contracts
and refusal cases. They do not prove native filesystem settlement, packaged
runtime operation, decoded image validity or Store acceptance.
