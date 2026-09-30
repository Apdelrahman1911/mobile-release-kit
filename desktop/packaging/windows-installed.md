# Fixed-release Windows runtime publication (producer preparation)

**Source contract only.** This feature does not qualify a Windows runtime,
activate an installed consumer, assemble an MSI, or enable application/Python
startup. Separate SOURCE, exact prepared-DATA and COMMAND/native review precede
any execution. The existing Windows installed profile remains inspection-only.

## Fixed layout and privilege boundary

The nondefault `windows-runtime-publisher` feature selects the standalone
`mrk-windows-runtime-publish` binary and the private native `runtime-publication`
feature. Only Windows x64 MSVC is supported. It must not be combined with
`desktop-shell`, `development-runtime`, another platform publisher/installer,
or Mac observation. No dependencies, default capabilities or workflows change.

Let **P** be the original OS-known native 64-bit Program Files location, **T** be
literal `x86_64-pc-windows-msvc`, **D** be the full lowercase compiled manifest
SHA256, and **Q** the compiled protocol SHA256. The helper takes **no arguments**
(exactly argc=1). Neither environment, cwd, executable location, MSI properties
nor UI input may choose paths, anchors or target.

```text
P\Mobile Release Kit\runtime-input\T\D\                 inert package input
P\Mobile Release Kit\versions\T\D\                      new retained output
```

The original known-folder discovery and local NTFS mapping, canonical no-reparse
ancestry, full volume+128-bit file IDs, actual owner/DACL, noninheritance,
single-link regular files and absence of alternate streams are checked. Source
readers deny write/delete sharing and retain their original parents. A trusted
installer must serialize this actual helper/input transaction. There is no
protection claim against a malicious administrator or conflicting privileged
writer, and no account creation, impersonation, privilege adjustment or UAC
self-relaunch. Admission positively requires a nonimpersonating primary
LocalSystem token or actually fully elevated enabled Administrators context;
ordinary-reader elevated-token refusal is not a privileged success shortcut.

The safe wrapper hashes the original manifest before strict JSON, using existing
VersionSpec target/core/protocol/inventory/path/case and all37 supplier checks.
The exact47 files are manifest.json; six existing bootstrap files; core.zip;
github-ca.pem; python/MRK-EMBEDDED-NOTICES.txt; and **every unchanged member** of
the fixed37-file CPython 3.14.7 embed-amd64 supplier roster. The only payload
subdirectory is `python`. The literal complete roster is
`PUBLICATION_PAYLOADS` in the native publication module. No extra/empty directory,
pruning, recompression, changed supplier byte, second manifest source or path
redirection is accepted. Supplier/preparer provenance is not renewed here.

## Create once, copy, verify, seal

Existing shared ancestors are admitted, never ACL-repaired. Missing `versions`
and T may be exclusively created; D must **always be new**, even when an
occupied D has identical bytes. Collision is terminal refusal, not adoption,
repair, rename, rollback or permission hardening of an existing object.

The process-lifetime OnceLock owns the actual serialized native Publication
before native effects. All input/output cells, names, descriptors and native
arguments are pinned and registered before entry. Each new output starts with
explicit Administrators ownership and a protected SYSTEM/Administrators-only
DACL. CreateDirectoryW returns a creation result, not a directory handle; its
later identity original is separately recorded.

For each fixed file: read actual bounded source chunks, require an exact
successful WriteFile count (no short-write repair loop), check source EOF/length/
SHA256, require **FlushFileBuffers on that actual writer**, then attempt that
writer's CloseHandle **once**. Only a known close allows a distinct readback
original bound to the same full ID. Readback checks full bytes/EOF/length/hash,
metadata, streams and protected security, then closes once. Readback never
substitutes for a failed writer, flush or close. All47 source/writer/readback
closures and complete source/destination inventories precede ordinary grants.

Separate minimal WRITE_DAC controls are acquired only after previous same-path
originals are positively Closed. New shared ancestors also remain trusted-only
until the full copy/inventory gate; their later read/traverse seals precede D's
final consumer-admission grant, with necessary ancestor controls retained until
dependent originals close. Existing shared ancestor ACLs are never changed.
Final protected descriptors grant Users read/traverse on directories, read and
execute on fixed `.exe`, `.dll` and `.pyd` files, and read only on other files.
No ordinary write, append, delete, delete-child, owner/DACL, EA or attribute
mutation right is granted. These image rights deliberately differ from the
synthetic fullwalk fixture's read-only file rights; no image is launched here.

All file and python-directory controls are sealed, postchecked and closed before
the final D-root READ/LIST/TRAVERSE grant. **ExposureAttempted is recorded before
SetKernelObjectSecurity.** That root grant is a consumer-admission point, **not
atomic whole-tree secrecy**: Windows traverse bypass can permit reads of already
sealed, already-complete children. Any later failure remains failed/possibly
exposed, never rolled back or relabelled unpublished. Same-original root
postchecks, its one close, every remaining original settlement and the original
process's successful return are required for success. A receipt or exit from a
different process is not evidence of those operations.

Bounds are one180-second endpoint (not renewed), 64KiB chunks, 48 live originals,
8256 original records, 2048 file attempts, 8192 total enumerated entries,
512MiB/file and 1GiB **combined source plus readback** reads. An entered synchronous
OS call can outlast the endpoint; expiry does not cancel it or manufacture its
return. Failure settles independent known originals once where safe. Unknown
is absorbing and retains actual owner/active native storage; no close retry,
replacement-handle recovery, cleanup or destructor finality is used. Process
containment is not original finality. Partial/interrupted/unknown D stays occupied.

FlushFileBuffers success is only its documented file result. It is **not** a
directory fsync, whole-tree transaction, power-loss atomic publication or durable
rollback promise. Future consumers must still inspect the complete protected
inventory including D itself. No loader-success flag, producing Windows alias,
Resources/claim/spawn, project/snapshot/Save, C/P2 or delivery gate is enabled.

## Binding MSI ownership and retention contract — assembly deferred

Future x64 per-machine Tauri/WiX packaging owns only shell/frontend/helper and
the inert `runtime-input` subtree. The normal shell remains **asInvoker**; only
the fixed helper action is privileged.

**Published D and every retained shared version ancestor must be outside MSI
File/Component keypaths and harvesting.** They must also be outside uninstall,
repair, rollback, RemoveFile wildcard, RemoveFolder/recursive custom action,
ACL-repair traversal and RemoveExistingProducts removal paths. A `Permanent`
component flag alone is insufficient proof. Parent-directory ownership must not
indirectly reintroduce any traversal/removal of retained versions.

An upgrade that changes the runtime uses a **new D** and may replace package-owned launcher selection only
after actual known publication success. Old and unknown D, and their shared
ancestors, remain untouched during repair, rollback and uninstall, including
after parent death. Occupied-D refusal cannot be converted into adoption or
"repair succeeded." There is no production retirement API or synthetic-fixture
retirement in packaging.

MSI must not mutate/remove the helper or any input original while its actual
publication process is unresolved. Serialization and known original exit are
required. Do not introduce PID discovery, broad kills, a broker or lease system
to guess settlement. Offline maintenance/reclamation, concrete MSI/WiX assembly,
WebView2 distribution and installed consumer acceptance are separate work. This
source slice does not enable bundling and does not claim these promises have
already been verified in an installer artifact.

## Verification boundary

Inline tests cover only pure policy/return/order/retention controls; they are not
actual injected Windows failures or durability observations. Existing supplier
and synthetic fullwalk evidence is not qualification of this producer. A later
separately approved serial Windows envelope must freeze exact current-core DATA
and D/Q, build the fixed helper, observe one actual publication and ordinary
protected fullwalk, then separately observe occupied-name refusal without
replacement. No Python/application launch or unrelated suite is authorized by
this document.

## Fixed-input acquisition (separate, nondefault native feature)

`installer-acquisition` retains the protected source54 tree into independently
OS-discovered native64 Program Files. It does not select a destination from the
source candidate, publish a runtime, execute a prerequisite/helper, activate a
shell, or qualify an installer. H is the lowercase publisher image SHA256.
Both per-I input branches must be absent before any mutation; I is the compiled54-row profile hash described below. Every actual
exclusive-create collision is terminal; retained partials are never adopted or
deleted. All existing `versions` contents are outside this operation.

The one retained owner has separate readonly-source and output/readback books,
one original mutation slot, one first failure and one 600-second cooperative
endpoint. A real enclosing process watchdog remains required before enabling
bootstrap. The source candidate must independently satisfy fixed-drive/local-
NTFS/canonical no-reparse/full-ID/privileged immutable ACL admission. Ordinary
user-writable extraction is not a substitute for secure bootstrap.

The literal47 runtime leaves are unchanged and remain publicly re-exported as
`PUBLICATION_PAYLOADS`. The other seven leaves are the publisher, desktop shell,
offline WebView2 installer, two notices and two controls. Source and destination
mapping is private fixed DATA. Two pre-read controls keep their actual original
handles, exact bounded caches and real EOF until their normal copy steps.
Other leaves each open once; their actual metadata.size is checked against the
authenticated expected size before that leaf's writer, not guessed from directory
entry DATA. Caller-authenticated source and distinct readback hashes are required.

Acquisition alone uses a 1GiB payload + 1MiB inventory + 16KiB admission read ceiling
per book and 131072 output records. Default/Publication limits remain unchanged.
Positive short reads, excess-detection bytes and finite exhaustion fail closed;
record capacity is not a guarantee for arbitrary short-read schedules. Finality
requires all54 source/write/readback proofs, exact memberships, same-original
postconditions and both books positively settled. Partial/failure/Unknown is
never InputsRetained. All output remains SYSTEM/Administrators-only; no grant,
activation, upgrade/repair/removal or ordinary-user UI claim is made here.

## Installer-internal shared publication core (dormant)

The isolated `windows-installer-profile` now compiles this SAME owning publication
body in process, forwarding only the native `runtime-publication` feature. It
does not enable the application's disjoint standalone-publisher feature.
The standalone no-argument entry, actual exit0/1/2 mapping, exact runtime roster,
collision refusal, native limits and both original finality observations remain
unchanged. Its public entry exists only in the standalone publisher profile.

The crate-private direct entry requires a loan of the actual registered
controller and its retained original watchdog handle, created on the original
caller after actual GO/ARMED acknowledgement. It cannot select an operation,
path, hash, budget or prerequisite receipt. It does not re-lock the caller-held
custody mutex. The same original570/600-second guard applies before producing
phases and after positive returns. An already-returned native/policy error is
selected before a later STOP; STOP prevents more production but does not suppress
required original-thread once-only settlement. A lost original guard during
unresolved settlement reaches the dedicated-process failure boundary.

The actual typed core return is retained in the original controller before later
controller checks. Occupied D remains an error; Unknown, already-started or
unavailable originals cannot authorize continuation. Native originals/storage
remain retained. Core Ok is neither installer success nor activation: eventual
original watchdog join, aggregate final gate and actual bridge-process return
are still required.

Retained publisher H is still a required observed input in the unchanged52+2
inventory. It does not authenticate the bridge machine code. The real bridge
image must bind the compiled shared core independently.

The existing acquisition-only entry retires and joins its guard. Its return
CANNOT be reused to call direct publication under a fresh installer clock.
The complete continuous owner, protected bootstrap/image admission, real offline
WebView2 owner, authenticated cancellation, safe permission-phase integration,
selection and maintenance remain separate unfinished work. No bridge binary, NSIS `.onInit`,
installer enablement or ordinary-user activation is added by this source slice.

## Application image identity, readonly runtime reuse and retained-shell primitive

The existing exact canonical54-row acquisition profile now supplies a separate
image identity **I = SHA256(profile bytes)**. Its independently compiled pin
binds source/T/core/D/Q, the finalized signed shell at row48, helper H and every
other input/control. Signing/finalizing the shell precedes profile generation;
the bridge is built afterward and is outside the54 rows, so no self-hash cycle
is introduced. A DATA-only ExpectedInputData constructor cannot select I.

```text
supplier source: runtime-input/T/D/<47>
retained output: runtime-input/T/I/<47>
                 installer-input/T/I/<publisher-H,shell,prerequisite,notices,controls>
public runtime:  versions/T/D/<47>
```

The two exclusive acquisition absences now use I; every54 source/readback/hash/
EOF/closure obligation remains. Same-D changed-shell upgrades receive a new I,
not an overwrite of the old shell. Same-I collision still fails; it is not repair.

The installer-only publication constructor borrows the actual settled acquisition
and derives I/D, original output-book identity and final MRK Facts. The safe caller
also requires the actual retained acquisition return under its same armed guard.
The construction-only acquisition loan ends before Publication registration;
subsequent joint access must use Publication then Acquisition. No callback owner
broker or reacquisition of the watchdog custody mutex is introduced.

That SAME Publication chooses once from the actual admitted versions/T/D name:
**PublishNew** reads acquired I, exclusively creates D and keeps all original
two-read publication checks; a later occupied race remains an error.
**ReuseExisting** instead reads the actual public D manifest and all other46
originals, validates the same compiled/supplier/exact47 policy, public descriptors,
complete hashes, real EOF, unchanged facts, token/location/parent checks and once
settlement. It cannot create, copy, open controls, Seal or repair. Its manifest
cache belongs to the original existing D read, never acquisition's I cache.
Actual PublishedNew/ReusedExisting return DATA are distinct and retained once.
The standalone no-argument producer continues to require a new D.

A bounded native retained-shell permission primitive lives inside the original
acquisition owner. It admits exactly six roles: EXE, shell, I, T, installer-input,
MRK. Only its actual exclusive private creations may receive ordinary rights;
already exactly-public ancestors stay readonly. Program Files, runtime-input,
helper, prerequisite, licenses and controls receive no new rights. MRK must
correspond to acquisition's actual final Facts: new publication may reconcile
only its recorded versions child creation, while reuse requires unchanged Facts.
Original54 byte proofs, exact reopened identities/security/metadata and each
permitted ACL-only transition protect the retained shell; this is not a claim of
a second activation SHA256 read or protection from a malicious administrator.

New activation originals do not reopen/reset old settled books. The check-only
InstallerBoundary borrows the actual ActiveInstallerGuard, preserving its original
570/600 endpoint/custody. Native methods and each Control/Seal have separate
before/result-first-after gates. STOP prevents further production but allows
known-original cleanup under the same unit custody boundary; Unknown/active frames
are retained. Admission errors and native failures are once-latched. Possible
exposure is recorded before the first grant, not inferred from its success.

**The prerequisite/activation entry remains CLOSED.** These native operations and
their DATA regressions are not a complete installed application. The actual
offline WebView2 owner, safe named phase requiring its real retained result,
continuous sequencer, protected bridge/bootstrap, selection/maintenance/recovery
and native acceptance are still mandatory. No prerequisite success, new public
route, bridge binary, NSIS entry or UI installation claim is fabricated here.

Launch selection must bind (T,I,D,row48), keep old image/selection until the
separate actual selection transaction, and report uncertain replacement as
partial success rather than claiming the old pointer remained unchanged.
Actual ordinary-user retained-I startup, same-D/new-I/new-D and partial-selection
Windows verification remain unexecuted until Root's reviewed execution gate.

## Private retained launch-selection and maintenance source

The private `windows-installer-selection` feature adds typed native operations;
it is **not a shipping installer, maintenance executable, or Desktop command**.
The Common Programs folder is obtained from Windows. Its fixed
`Mobile Release Kit.lnk` is the sole normal-launch selector. It names the exact
retained `installer-input/T/I/shell/mobile-release-kit-desktop.exe` without arguments,
working-directory override, elevation, environment expansion, network target, or
automatic launch. The native64 HKLM uninstall entry is derivative registration,
not another authority or proof that the installer completed.

Preview and Apply are separate one-shot controller invocations. No original
watchdog is retained during user think time. Apply reobserves the exact preview
and uses the same actual borrowed 570/600 controller for work, result retention,
once-only settlement, watchdog retirement/join, and final gate. New selection
additionally requires the actual completed Publication, prerequisite,
acquisition, and six-role activation originals—not serialized readiness flags.

Canonical existing PROFILE bytes and Windows-authored launch bytes are retained
under `selection/T/I/profile.json` and `selection/T/I/launch.lnk`.
Maintenance redecodes the existing PROFILE schema and authenticates protected
provenance. Verify/restore and recovery retain and recheck the real readonly54
input and runtime47 originals until selection settles. The selected link and the
protected recovery directory must be on the same actually admitted local NTFS
volume. Foreign occupants are refused, never replaced or adopted.

Registry support/access and exact transacted values are staged before the first
selector move. Only the literal product leaf below an already existing protected
native64 Uninstall parent can be created/deleted. Unsupported transactions or
access denial refuse; no nontransacted fallback exists. Each selector move and
registry commit requires an exclusive immutable intent record whose writes,
Windows flush, readback/EOF, and consuming close completed beforehand.
The old selector is moved by its held original with replacement disabled; the
new held selector is then moved with replacement disabled. These moves and the
registry transaction do not form one atomic or power-loss transaction.

After a failed native return or STOP, no new producing record is written.
Original entry/return observations remain retained in memory. A missing returned
record means uncertainty; recovery freshly observes the actual protected
records and owned selected/backup files. Reports distinguish attempted effects,
returned native codes, OS-flushed and fully closed record counts, charged versus
confirmed output bytes, and unknown write counts. Persisted output paths are
observations, not cleanup/deletion authority.

The narrow maintenance labels are:
- **Verify this installation and restore missing launch entries**: readonly
  verification; it does not repair payload bytes or ACLs.
- **Remove launch entries**: authenticates and removes only the owned selector
  and derivative key; it does not require healthy/present executable payloads.
- **Restore previous / complete current launch selection**: explicit new preview
  and authentication, never automatic replay or launch.

All I/D trees, recovery records, projects, credentials, release evidence and
shared WebView2 remain retained. The UI must show actual retained byte usage
where observed; unavailable sizes are unknown, not zero.

The separately admitted maintenance bridge, full bootstrap/installer sequencer,
and verified modify/uninstall command values are still required. No fictitious
UninstallString is registered. Source review or DATA tests do not qualify
ShellLink, registry, native original closure or hosted Windows behavior.
The focused Windows fixture owner/selector extension and genuine native
evidence remain necessary before any installer enablement.
