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
P\Mobile Release Kit\mrk-windows-runtime-publish.exe      future package helper
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

Upgrade uses a **new D** and may replace package-owned launcher selection only
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
