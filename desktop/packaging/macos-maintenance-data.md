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

This source selects engineering `0.1.0` / `macos26-arm64-entry-m2a-01` for the
ordinary entry/payload layout. That release, historical
`macos26-arm64-project-draft-01` and engineering version `0.1.0` remain excluded
from v2 producer DATA. Entry participation does not create a v2 release,
authenticate signing policy, authorize a predecessor or settle an invocation.
The permanent root gate is never deleted/replaced; M2 worker/direct-pre-main
closure and M3/M4 maintenance remain unavailable. A future producer must select a genuine unique new build identity
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
exit/close status or finality. No result channel/path or native caller is implemented.

`Distribution.xml` and `InstallerReadMe.html` prepare fixed, local-system, fresh-only
Installer presentation. They are not consumed by the existing workflows. The audited
scripts-only component and native absence/publication policy remain unchanged.
Target macOS26 tool binding and a complete outer-product audit are still required.
Update/restore/uninstall availability, legacy migration, M2 participant retention,
M3/M4 mutation, signing/notarization and native acceptance are not provided here.
