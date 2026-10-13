# Maintenance preparation DATA (not available maintenance)

`macos_install_maintenance` is a pure, bounded v2 DATA module. It accepts a detached
release-producer tuple plus at most eight explicit predecessors. Each tuple binds
the fixed product/profile, canonical numeric version, immutable release ID, source,
protocol, runtime manifest, complete inventory, signing-policy digest and completed
package digest. The final package digest is detached: do not embed it in itself.
Release selection remains build-bound; there is no destination-derived expectation.
No real v2 release/publisher tuple is configured by this preparation.

The actual app/Installer/observer build and package stager now select version and
release from the fixed target-selected sources `macos-installed-inputs/build-release.json`
(ARM64) and `macos-installed-inputs/build-release-intel.json` (x86_64).
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

This source selects candidate package version `0.1.1` with release IDs
`macos26-arm64-desktop-01` and `macos26-x86_64-desktop-01` for the ordinary
entry/payload layout. These are not published or qualified releases. The
historical `macos26-arm64-entry-m2a-01`, `macos26-arm64-project-draft-01` and
engineering version `0.1.0` remain excluded from v2 producer DATA. The
source history remains empty for fresh installation; no predecessor is
authorized. Selecting candidate names does not authenticate signing policy,
produce a completed package or settle an invocation.
The permanent root gate is never deleted/replaced; public maintenance remains unavailable.
The normal UI now has a separate **Prepare app to quit** entry. It requires exact
local confirmation, the ordinary installed-image profile, configured helper and
the original settled Document/Android owners. It delegates to the existing native
preparation; only its private Completion can request normal Quit. Read-only status
and a checked confirmation are not ownership or Installer authority. Early known
refusal can reopen only through that private completion; started/unknown effects
retain the original closure. Browser preview, observer and helper profiles cannot
use this entry. Moving between UI screens neither cancels nor restarts native work.

This normal entry still needs actual packaged-Mac verification with the original
helper, including failure and interrupted Quit. It does not complete G or grant
global descendant finality, Installer update, restore, pruning or uninstall.
Projects, credentials and protected files are not deleted by preparation. A future
producer must still bind this candidate identity to the genuine configured
Developer ID signer before signing and inventory generation, then publish
its completed package digest in detached schema2 DATA only after complete
package audit. Notarization is separate; an unsigned engineering fixture
does not satisfy ordinary v2 producer identity.

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

## B2 private original writer (not a maintenance activation)

The native Installer contains an inactive, fixed self-image parent/worker route.
It shares the existing prepared copy/readback/EXCL publication body with the
ordinary fresh Installer; it is not a second copier or an arbitrary command API.
Neither ordinary `run`, fixture `run`, nor `postinstall` selects that private role.
This source implementation does not establish native acceptance or make update,
same-package, restore, pruning or uninstall available.

One original monotonic120s endpoint starts before admission; work/GO/publication
stops at110s, leaving10s inside that same budget for original settlement. The
parent's actual EX precedes spawn and GO. A duplicated read-only gate OFD reaches
workerfd2; neither process unlocks/reopens it. The parent's one-use Command
reference and the worker's fd2 are explicitly kernel-retained, not reported as
consuming closes. The worker requires exact GO **and actual command EOF** before
payload writes. Separate Darwin pipe endpoints are checked against their own
original facts, not against the opposite endpoint's inode number.

A pre-exit worker result contains only returned effects, bounded closed failure
labels, known book closes and timing. It cannot attest its stdout/fd2 close or its
own join. The parent constructs its private `JoinedWriter` only after real EOF,
original channel closes, original Child wait, source POST and the common deadline.
A joined nonzero result remains failure. Parent/Command kernel finality still
requires the **outer original Installer process return**; a parsed result cannot
provide that fact. Unknown originals are retained rather than adopted or repaired.

B3 ordinary entry and result/export integration are mandatory: genuine completed
package context and independently selected producer/release trust, B1 linked
state/capsules, occupied-state/no-op/restore/update handling, unique invocation
exports and outer-parent finality must use this same writer. There is no permissive
enable/trusted flag. Genuine ARM/Intel native process/lock/parent-loss/collision
and installation verification remain required; SOURCE and inert native-unit checks
do not replace those observations.
