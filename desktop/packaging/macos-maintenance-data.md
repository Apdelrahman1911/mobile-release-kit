# Maintenance preparation DATA (not available maintenance)

`macos_install_maintenance` is a pure, bounded v2 DATA module. It accepts a detached
release-producer tuple plus at most eight explicit predecessors. Each tuple binds
the fixed product/profile, canonical numeric version, immutable release ID, source,
protocol, runtime manifest, complete inventory, signing-policy digest and completed
package digest. The final package digest is detached: do not embed it in itself.
Release selection remains build-bound; there is no destination-derived expectation.
No real v2 release/publisher tuple is configured by this preparation.

The actual app/Installer/observer build and package stager now select version and
release from the single fixed source `macos-installed-inputs/build-release.json`.
Cargo emits their constants for every app-crate target and checks the Cargo/Tauri
version projections. Staging checks the signed app/package against the same DATA;
the existing Info.plist and Distribution versions remain checked projections.
The native helper uses the central fixed executing-payload path, not app-generated
build output. Invalid/missing source DATA refuses; no runtime environment or
destination record can choose the release. The historical supplier description
keeps its original release label independently of current build selection.

E2 package SOURCE selects one explicit trusted build role. `ordinary-image` uses
the real desktop and resident cdylibs plus fixed libSystem-only C facades.
`installed-shell-observation` remains an explicit non-image fixture: its actual
observer test executable uses the resident image/facade/plist group, never a dummy
desktop image, unified features or a missing-image fallback. Both images have
fixed Frameworks paths, MH_DYLIB kind, absolute install names and closed protected
Apple dependencies; executable bytes renamed to a dylib cannot qualify.
The common inventory keeps its existing schema and Kind. It classifies both
images as executable immutable code, requires helper/plist/resident completeness
and desktop-to-resident dependency. A separate source/build-role layout gate
requires both images for ordinary admission and no desktop image for the observer.
The same live installed identity book rebinds that exact code/plist roster.

The existing helper packaging owner binds source commit and the held, parsed
build-release original to Rust and both C facades. Its finite eight-call prepare
graph builds the resident cdylib, copies before signing, verifies it, then builds
the entry and two facades and signs/verifies the resident facade. Each staged
verify phase checks both retained signed originals and the source plist; failed
returns or unknown closes do not become completion. Images/helpers are separately
signed before nested and outer bundles, never repaired with `--deep`. Receipts
keep the raw C facade, original desktop image and final signed image hashes
distinct. No native acceptance or shipping-signing authority follows from this
SOURCE layout or its inert fixture regressions.

This source selects engineering `0.1.0` / `macos26-arm64-entry-m2a-01` for the
ordinary entry/payload layout. That release, historical
`macos26-arm64-project-draft-01` and engineering version `0.1.0` remain excluded
from v2 producer DATA. Entry participation does not create a v2 release,
authenticate signing policy, authorize a predecessor or settle an invocation.
The permanent root gate is never deleted/replaced; public maintenance remains unavailable.
The private E2 preparation path still needs distinct integrated/native acceptance;
it is not G/vault completion or Installer update, restore or uninstall. A future
producer must select a genuine unique new build identity
before signing and inventory generation, then publish its completed package
digest in detached schema2 DATA only after complete package audit.

The classifier consumes explicitly supplied comparison labels. It does not inspect
names, validate a signature, observe prior settlement, create a lease or authorize
an operation. Missing/unknown/contradictory DATA is not positive correspondence.
Absence does not prove uninstall; exact-current does not prove a current no-op.
Published engineering-v1 identities are excluded, not implicitly migrated.

`InvocationBindingData` describes only future result binding: explicit current ID,
action, package/source and old/new package digests. The caller must independently
supply the actual current original; equality cannot establish freshness, single use,
exit/close status or finality. This DATA module implements no result channel or
Installer mutation caller; the separate private preparation transport does not
turn comparison DATA into permission.

`Distribution.xml` and `InstallerReadMe.html` prepare fixed, local-system, fresh-only
Installer presentation. They are not consumed by the existing workflows. The audited
scripts-only component and native absence/publication policy remain unchanged.
Target macOS26 tool binding and a complete outer-product audit are still required.
Update/restore/uninstall availability, legacy migration, qualified M2 participant
retention, M3/M4 mutation, shipping signing/notarization and native acceptance are
not provided here.
