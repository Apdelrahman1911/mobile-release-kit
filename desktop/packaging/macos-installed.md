# Mac installed project/draft/Save — engineering SOURCE draft

**Integrated engineering draft; installation/Aqua/Save remain unverified.**
The reviewed Mac SOURCE02 was composed onto Linux V commit
`18eaffcfb62d0bc9a256c448f1a1c025db0ca1ee` using 28 exact source copies plus the
contextual `shell.rs` union, retaining V's diagnostics and N's Mac owner wiring.
Subsequent native API and Installer compile corrections are recorded below.
Accepted DATA01 and the affected-only DATA03 parser results are reused for their
unchanged exercised closures, not as native qualification.
The five selected regressions below require a complete successful hosted gate.
Do not push the verification branch or use these commands before separate
actual-source/command review; integration is not proof that this revision works.


## App-owned Android support archives

`desktop/macos-installed-inputs/android-support.json` is the reviewed, closed
source recipe for bundletool1.18.3 and AGP AAPT2 8.9.2-12782657. The developer
stager requires both original archives explicitly; the user still selects only
JDK, SDK and Gradle through the application. There is no fourth picker or cache
discovery. The workflows acquire these two public files with an empty
credential/configuration environment, HTTPS-only redirects and fixed byte/time
bounds, then authenticate every original and its selected notices before builds.

The original JARs remain non-executable DATA under
`Contents/Resources/android-support/`, with all eight selected original public
license/notice members under `notices/`. This adds ten leaves /37,042,096 bytes;
existing app, inventory and memory bounds remain unchanged. No vendor program
is extracted, executed, re-signed or altered by packaging, and no SDK license is
accepted for the user. This placement follows Apple's
[TN2206 Resources guidance](https://developer.apple.com/library/archive/technotes/tn2206/_index.html).

Before Installer inputs are published, the signed app is reread and its entire
owned support-resource roster, bytes and non-executable modes must match the
source recipe. Archives/notices copy as0644 and normalize to0444 in the protected
installation. Missing, extra, changed or executable support resources refuse
before output. The recorded manifest digest is DATA, not runtime authorization.
Native signature/Installer/readback checks remain required on the current
package. Packaging equality alone does **not** qualify the complete Android
supplier, grant protected registration, or prove a build/sign operation.

## Fixed Mac vault helper integration — source draft, not qualified

The ordinary app still cannot call Add/Lookup directly. The separate
desktop/helpers/macos-vault-helper Cargo graph builds only the fixed
Contents/Helpers/mrk-vault-keychain helper, with no observer/fixture role,
renderer API or general command interface. App compilation rejects accidental
feature unification. The existing OriginalWork coordinator registers the one
blocking child before native admission; it owns launch, request GO, three pipes,
absolute work/cleanup limits, the real child wait, and the actual worker join.

The ordinary installed/Aqua workflow tool selections remain separate from the
native clock guard. That guard preserves Rust **1.98.1**, commit
`48a229ceaefd4985c50990b14116b6d856af0985`, for both `aarch64-apple-darwin` and
`x86_64-apple-darwin`; it additionally admits Rust **1.98.0**, commit
`88d9e12ae178fab0fb5cc050a94da85685d449ea`, **only** for `x86_64-apple-darwin`.
The three complete target/release/commit rows are closed SOURCE inputs, not an
arbitrary compiler-version range or fallback. The original selected compiler
query must succeed with bounded UTF-8 output and exactly one matching full
release and commit-hash field. Cargo target cfg must be macOS/LP64/Apple/Unix.
Existing supported cross-target builds are not replaced by a new host policy;
the compiler-only CI caller independently checks its actual compiler host.

The official Rust sources below are byte-identical at those two exact commits.
Prefix each relative path with either pinned source root:
- `https://raw.githubusercontent.com/rust-lang/rust/48a229ceaefd4985c50990b14116b6d856af0985/`
- `https://raw.githubusercontent.com/rust-lang/rust/88d9e12ae178fab0fb5cc050a94da85685d449ea/`

| Relative Rust SOURCE path | Bytes | SHA-256 at both commits |
| --- | ---: | --- |
| `library/std/src/sys/time/mod.rs` | 1125 | `449afdd86955252a302d889032a6cb2cbb04dd786f8cb81d9a9059ad933e7e4c` |
| `library/std/src/sys/time/unix.rs` | 4999 | `2250ca181d117737d32734c50156a7a9e74852251a17bf70b2a002b8d6fbac43` |
| `library/std/src/sys/pal/unix/time.rs` | 8303 | `963774dbbabd67a0a8264d7f1edf0faca0bbc4e064af6c2459371481a5888307` |

Unix selection plus the Apple cfg chooses `CLOCK_UPTIME_RAW`; `Instant::now`
passes that clock to `Timespec::now`, whose macOS path calls
`libc::clock_gettime(clock, ...)`. The existing native helper uses the same
clock; its original bracket, conversion, regression checks and deadlines are
unchanged. This is specific standard-library SOURCE correspondence, not a
promise about future compilers, a runtime timing measurement, or qualification
of installation, signatures, service registration, process finality or UI.
No shared global Rust toolchain or Windows/Linux profile is changed.

Packaging order is helper build → hardened/empty-entitlements signature →
strict helper verification → final helper byte digest/size → digest-bound app
build → helper/app staging → hardened/empty-entitlements app signature → strict
helper/app verification → exact input roster. Neither signing command uses
--deep; a changed nested helper fails the input digest check. The helper must
be arm64/macOS26, use only absolute Apple-system library dependencies and the
system dyld, and contain no rpath, dyld environment, or legacy loader override.
The root installer gives the helper the same protected0555/root:wheel leaf
policy as the app executable; no additional arbitrary executable is admitted.

Reverse caller admission uses protected installed-code originals and the actual
kernel parent. Strict static signatures must carry the runtime flag and empty
recognized entitlements. Actual dynamic parent/self code must satisfy the exact
cdhash requirement, be Valid, and not be Debugged. Parent loss or changed code
revokes forward work, not independently admitted original-only restoration.
**Exact cdhash authenticates code identity, not executing-file location**:
a byte-identical copy remains identity-equivalent. There is no promise of
copied-path refusal or protection from an already compromised ordinary session.

Initialize preserves reservation → one Add → exact Lookup → joined/settled key
authentication → durable header publication. Unlock never adds. Early failure
and STOP contract the original cleanup endpoint; neither delivery latency nor
a later cleanup callback renews it. Independent restore slots remain usable
after a poisoned forward callback. Partial framing, failed closes, unknown
native allocation/finality, forced exit, orphan return, or missed deadlines
cannot become a key candidate or release a memory charge. A failed child
registration retains its prearmed book as Unknown, rather than doing unregistered
native cleanup from the coordinator. Normal before-GO cancellation instead
runs the same cleanup-capable registered child without granting forward work.

The bounded helper build/signing records are retained with the existing
source/run/attempt evidence. The separate helper target joins existing
task-owned output retirement only after its required copies and original work
are complete. It is not a reason to delete shared caches or another task's work.

**Unexecuted obligations remain unexecuted.** Source/DATA tests are not actual
installed-caller, Keychain, shared-clock, process/pipe finality, or durability
qualification. Required native negative/positive controls and final integrated
review must pass before persistence/availability may be enabled. All existing
qualification gates remain false. Ad-hoc hardened CI signing is not Developer ID,
notarization, publisher identity, signed-upgrade continuity, or production
distribution acceptance.

## 2026-09-21 supported-directory-API and command corrections

The first normal Mac compile failed because getdirentries64 was undeclared. Its
reviewed successor compiled but the SDK deliberately rejected getdirentries at
link with64-bit inodes. Neither run reached Installer or native regressions.
The successor uses public getattrlistbulk on the same borrowed original FD and
cursor, with a strict4-byte-packed returned-attribute decoder and unchanged
full64-bit inode/type/name output. Missing/extra attributes, malformed batches
and unsupported kinds refuse; no entry is skipped or partially accepted.
No private declaration, inode ABI override, DIR/dup ownership or close is added.
The same job first compiles/links the changed native shim using the selected
CLT SDK, without loading it, so header/link errors fail before the full build.
The sole task-owned link output is retired immediately after a successful check.
A new same-C-decoder regression joins the existing native group, making the
selection **2+1+2 = five**. Run35637529386/1 at
`2e71e54e7855595a7d2201695f64bee5f681ad7c` passed the SDK compile/link check,
normal app build/sign, two dialog regressions and the Installer finalizer test.
The checked native permission conversion resolved the earlier Installer compile
failure. The run then failed before the two native ABI tests: Cargo rejected
`--no-default-features` for the non-workspace path dependency. Its command now
omits only that feature-selection flag; the native crate declares no default
features. The root manifest/lock, package, target and exact two tests are retained.
Both ABI tests, all seven Installer cases and ordinary installation/readback
still need successful execution. This is not installed-app/Aqua qualification.

## Explicit Darwin no-ACL observation and early primitive probe

The original run35653635077/1 reached native fixture setup but reported the
unbound diagnostic `setupError=acl-refused`; all five selected regressions ran,
while the seven fixture cases and ordinary installation/readback did not. The
exact failed object/API/errno is not known. No installed/Aqua pass is claimed.

Pinned Apple Libc contracts show that `acl_get_fd_np` can return NULL/ENOENT for
a valid descriptor with **no ACL**, not only an acquisition failure. The shared
shim now uses one same-FD `fstatx_np`, requires complete consistent ordinary
stat properties, and explicitly queries ACL presence. Presence is zero/nonzero,
not necessarily1. Every call failure refuses; no errno is accepted as absence.
Present ACLs keep Darwin's valid-first-entry rule: an actual ACE always refuses.
SDK sentinels are not owned ACLs. Actual errno0, fallback errors, first failure and
separate single-free errors remain distinguishable; no descriptor is duplicated.

A fixed nonroot macOS26/ARM64 APFS probe replaces the previous throwaway link-only
check before the shell build. It exercises the actual shim on fresh no-ACL file
and directory, zero-entry ACL, a real synthetic ACE, and raw-native EBADF (never
an invalid Rust borrow or manufactured close). Only its own three exclusive
entries may be changed/retired; original close/cleanup errors fail. Native compile
and probe statuses/logs remain separate, source-bound and bounded. The five
existing regressions still cover their separate contracts. Probe success is not
Installer/Aqua acceptance; native execution of this correction is still required.

Failure-only `MRK_MACOS_INSTALL_ACL_DIAGNOSTIC` records carry finite object role,
API phase, return/error and free-error scalars (maximum512 bytes). No pathname,
ACL content, environment or account information is written. Diagnostic output is
non-panicking and cannot bypass original finalization. Collector selection stays
unbound; the protected final-result transport below is a separate channel, not
promotion of a log or pending staging receipt. System/source ACLs and modes are
never normalized. Run35659557286/1 passed its six original ACL probe controls and
five focused regressions, then failed fixture setup; it is not Installer success.
The changed transport/created-directory path still needs its own native evidence.

## Deliberately small product surface

These are current normal Mac implementation selections, not a record of native
acceptance. Original runtime, document, input and owner admission still applies.

- macOS **26.x, ARM64**, normal `desktop-shell,custom-protocol`, no
  `development-runtime`. App startup rejects root/set-ID/incompatible hosts.
- The Mac passive selector includes thirteen methods: `capabilities`, `catalog`,
  `project.snapshot`, `config.validate`, `config.suggest`, `config.preview`,
  `environment.requirements`, `github.setup.propose`, `release.version.observe`,
  `metadata.text.observe`, `metadata.text.validate`,
  `artifacts.candidate.observe`, and `release.evidence.observe`.
  These read/validate routes do not grant edit, private-input or release custody.
- Separate existing configuration `EditOwner`: open → prepare/review → explicit
  Apply/Save → close/status. Same core `InitRootLease`/transaction, stale-base
  policy, `.gitignore` control, and absent-`release/` creation. The project picker
  supplies an observation/registered identity, **not** the Save lease.
- Normal Mac selectors also connect workflow Apply, public locale-text Save,
  saved-version edits and public-image edits to their separate domains of the
  original shared edit owner. Image selection shares the fixed image-edit gate.
- Project-folder and documents-only evidence-folder selection are implemented
  separately from credential/signing-file inputs. Ordinary session/persistence
  selection retains the original Supervisor/document and pinned-helper gates;
  selection alone proves neither saved credentials nor restart/upgrade continuity.
- Separate installed profiles exist for build-tool diagnostics, saved Android
  offline checks/builds, project recovery and full-Xcode iOS archive work. Their
  operation-specific runtime/tool/input custody and native acceptance remain
  separate; an offline check does not authorize a build.
- GitHub read-only and publisher-bound preflight/release profiles have separate
  selectors. A local workflow proposal grants no network or Store operation;
  profile selection is not live-service success or general network authority.
- The undelivered candidate selects the separate project-relative P2 profile:
  `INSTALLED_MAC_PROJECT_FIELDS_QUALIFIED` is true for ordinary-app validation.
  Browse for `version.source`, `ios.project`, `ios.workspace`, and `metadata.root`
  chooses existing descendants into the draft, without copying or Save; manual
  text entry remains. Both Xcode fields are retained even when they conflict.
  This availability is not qualification: exact-source AppKit/APFS refusal/owner
  evidence and the ordinary two-case UI batch must pass before delivery.
- The separate undelivered Android source-folder flag is true for ordinary-app
  validation. Status refines only an otherwise-available Document/publisher gate
  with the same cached selector already required by Choose; original Cancel and
  the seven denial states are unchanged. The same two-case batch must genuinely
  Browse JDK, SDK and Gradle, Cancel while retaining the selected JDK, replace it
  with another inert directory, then observe backend SourceRefused after a real
  native directory Open while retaining all prior selections. This does not
  qualify supplier inspection, registration/protected copying, builds or native
  link/wrong-kind handling. Exact enabled-source ordinary native evidence is
  still required before delivery; no additional selection profile is enabled.

The existing frontend/capability intersection is still used. None of these
selectors, source tests or a successful build establishes the outstanding native
UI/owner acceptance, SDK/tool qualification, signing/notarization, Store approval
or product readiness. The separate evidence and signing limitations below remain.

## Fixed installation and root boundary

The installed app is
`/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app`.
The candidate ARM64 runtime path is
`/Library/Application Support/MobileReleaseKit/versions/macos26-arm64-desktop-01/runtime`
(x86_64 selects `macos26-x86_64-desktop-01` instead). Both candidates use
package version `0.1.1`; these names are not public release or native
installation qualification.
The historical supplier archive keeps its original label; it does not select the
current installed release.

### M2-A ordinary entry (engineering integration, not available maintenance)

The outer app is the small C/libSystem-only `mrk-macos-entry`, bundle identifier
`dev.mobile-release-kit.desktop.entry`. Its fixed nested
`Contents/Helpers/MobileReleaseKitPayload.app` contains the ordinary Rust/Tauri
product, existing helpers/resources and the unchanged identifier
`dev.mobile-release-kit.desktop`. The product's app-data/vault namespace therefore
does not move. Helper authentication compares the actual executing payload to its
static payload signature, never the entry signature. Android's `BundleProgram`
remains payload-relative `Contents/Helpers/mrk-android-register`.

The existing fresh-only Installer provisions or strictly admits the permanent
`maintenance-gate-v1` at the installation root: exact30B
`MRK-MACOS-MAINTENANCE-GATE-v1\n`, root:wheel0444, one regular link, empty
ACL/xattrs and protected local APFS ancestry. It never repairs, replaces or
unlinks that gate. Gate writes/seal/file+parent persistence and original closes
are accounted separately from the existing two release-metadata files. Installer
holds nonblocking EX through publication and final protected checks, closing its
participant last; another unknown original close retains that participant for
kernel process exit and never produces installed/settled success.

The ordinary entry takes SH before loading the product, constructs the fixed
clean eight-key account environment, then execs the fixed payload in the same
process. Rust admits that one handoff before the builder, sets the same inherited
FD CLOEXEC and never unlocks it on Quit/cancel/Drop. Only kernel process exit
releases it. Build and post-signing inspection reject non-libSystem entry loads,
loader overrides and native initializers. Helpers → payload → entry are explicitly
signed inside-out, with final entry/payload/helper digest bindings; no deep repair.

The extended original normal UI scenario must genuinely follow its exact-URL
launch handle across exec, show the real Tauri window and native picker, Cancel
and normally Quit, with gate EX probes before/during/after. Neither an EX probe
nor XCTest `notRunning` authenticates SH custody or proves all-worker finality.
Observed Aqua deliberately still invokes its nested instrumented payload directly
and supplies **no ordinary-entry or M2 gate evidence**. Direct payload pre-main,
independent Python/tool/helper/service lifetimes, forced-parent/unknown closure and
M3/M4 maintenance remain unqualified. Source or DATA success is not native
acceptance; Developer-ID/notarization and Desktop readiness are not claimed.

### M2-B1 fixed vault-worker participant (source integration, native evidence pending)

The existing `LookupBook` now owns a separate parent-opened SH participant
through `VaultHelperSlots`/`CodeOriginals`, admitted before replaceable helper
code is read. Its fixed command adapter inherits that same live original only
in the one child immediately before exec. The parent remains CLOEXEC; there is
no descriptor duplication, parent inheritable window, `LOCK_UN`, generic command
API or replacement process runner. The helper admits the exact protected gate
before Work/GO, restores CLOEXEC on its same descriptor and retains it until
kernel exit. Gate argv is not parent authentication: original code/peer checks
and the existing request/GO protocol are still mandatory.

The parent checks gate correspondence after actual original child exit, also
following application failure/STOP, under the original cleanup endpoint. Code,
native and pipe originals settle independently before the gate's one consuming
close. Unknown launch/wait/native/close/deadline or absent postcheck retains the
participant and its charge; terminal/EOF alone never closes it or constructs a
key candidate. The actual blocking-driver join remains a separate prerequisite.
The observer reports five real parent-record gate facts, not fictional child
memory or gate-close wire receipts, and validates them in both live success
and closed partial-failure contracts.

The focused nonshipping native control is the one ignored Rust test
`vault_helper_filesystem::gate_custody_control::shipping_helper_retains_gate_after_parent_reference_close_until_actual_exit`.
It is compiled only for debug installed-observation tests, requires the reviewed
protected installation/original native owner and an actual independent EX-success
baseline (no ordinary app-entry SH still held), sends no GO or credential request,
then checks parent CLOEXEC, child-only SH after the test's parent-reference close,
actual EOF/exit/original pipe settlement and finally EX availability. Select only
that explicitly admitted control, not a raw/all-ignored suite. This is **not**
actual forced-parent disappearance, arbitrary direct-loader coverage, overall
worker finality or an available maintenance action. The separate startup-policy
adapter still runs only the noninstalled temporary release helper: canonical/empty
environment cases must refuse67 before C gate admission, while malformed inputs
refuse64/65/66. Its synthetic parsed scalars are not a gate handoff or native
custody evidence; historic argv1/EOF receipts do not qualify the new source.

These source paths and DATA tests do not themselves constitute native execution.
Fresh pinned macOS evidence is required for the affected shipping-helper journeys
and custody control. All broader M2/M3/M4, physical-host, signing/notarization and
Desktop-readiness limitations above remain; no qualification flag is enabled by
this slice.

This deliberately uses a protected Library location, not an `Applications`
ancestor that might permit group replacement. It is an engineering installation,
not drag-copy, an updater, upgrade support, Developer ID distribution, a
notarized package or Gatekeeper/quarantine qualification. Never chmod a shared
ancestor, delete an occupied app/version, or run the app/Python with sudo to
make an unavailable profile pass. A user-writable copy or App Translocation
cannot select the installed runtime by its executable pathname.

`mrk-macos-install` is a one-shot **standard Installer** postinstall program.
`pkgbuild --nopayload` first supplies a retained original scripts-only package:
input DATA, the fixed native installer and a fixed shell entry. Its Scripts
archive may retain the ordinary packager's UID/GID despite `--ownership recommended`.
The nonroot DATA preparation checks that exact owner, complete bytes/modes/roster
and fixed package identity, then copies only the unchanged decoded `PackageInfo`
bytes into fresh parts. Native macOS tar creates gzip odc Scripts with numeric
UID0/GID0 overrides from the original fresh scripts tree; native xar assembles a
separate fresh package. No source chown, privileged preparation, custom archive
serializer, XML rewriting or final-destination payload is involved.
Tar writes the guarded new regular `Scripts` file in its already private parts
directory, not stdout: BSD tar pads stdout even when compressed, which the strict
gzip audit correctly rejects. The native file writer has no other producer.

Preparation is **not** final acceptance. The final DATA audit rechecks the
original, requires byte-identical PackageInfo, exactly PackageInfo/Scripts XAR
members and the complete root:wheel CPIO bytes/modes/roster before Installer.
It rejects links, specials, missing/duplicate roots, extra members and changed
contents. A tiny inert packaging-only probe runs before expensive compilation;
neither its success nor its `exit97` hook is an Installer or GUI qualification.
If the native format or ownership fails, retain the originals and review the
fixed package-refusal diagnostic—never skip the audit, retry over outputs or
run Python as root to normalize them. Actual native verification remains a
separate evidence gate, not a claim made by this preparation route.

The Installer:

1. Records every acquisition and mkdir effect before the syscall. It consumes
   only its compiled inventory, bounded to 2048 files/512 MiB; root-owned source
   DATA has no pending PackageKit extraction writer. Root administrators and
   PackageKit itself are trusted, not concurrent privileged adversaries.
2. Uses no-follow original descriptors and ownership-aware local APFS checks.
   Existing system ancestors may have a different root-owned group but must be
   non-group/world-writable with empty ACLs. Product ancestors are root:wheel
   0755; a random, fresh `.install-…` staging directory is root:wheel 0700.
   Darwin-created directories can inherit an admitted non-wheel parent's group.
   Only a fresh root-uid/private original is normalized to0:0; checked original
   clock/name/FD custody precedes fchown, and failure/expiry prevents chmod.
   Both identity books refresh only after exact normalized named/FD comparison.
   Existing directories and the private-file creation policy are unchanged.
3. Copies with exclusive files, one process and no copy subprocesses. It hashes,
   explicitly closes, reopens only for readback of the same created inode,
   checks every file and complete directory roster, and seals staged directories
   0555, executable app/Python 0555, all other files 0444; empty ACL/no xattrs.
   File full-sync and directory persistence precede publication. Depth-first
   traversal bounds live originals to 96; closed records remain in the ledger.
4. Publishes runtime first, app second using **only**
   `renameatx_np(..., RENAME_EXCL)`. An earlier absence check is not authority.
   Retains the actual first-publication receipt before the second attempt.
   The two names are not a single atomic transaction. Occupied/racing targets
   survive; an unknown or first-only outcome is retained and reported, not
   repaired, overwritten, rolled back or deleted.
5. Labels durable publication receipts as **pending final closes**. Only after
   closing every original descriptor and sampling the **same original deadline**
   can the immutable installation DTO report `installed`; overall success also
   requires the protected export below. Equality is late; actual positive closes
   stay Closed. The post-native persistence/forward-close gates
   and final classifier preserve the first error; a final unknown close has its
   own fixed reason. Exit 20 is retained published-but-incomplete, never success.
   Timeout/unknown retains staging and any published object. This source has no
   deletion/cleanup path at all, even for unpublished staging.

The 120-second Installer admission clock is not an extension of any application
clock and cannot preempt a blocked kernel syscall. Unknown must remain Unknown;
process absence or a standard Installer exit alone cannot prove native finality.

## Finding and opening the installed app

The application remains in the fixed protected Library location above. After a
successful installation, open Finder, choose **Go → Go to Folder**, enter
`/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app`, and open
the app. This does not require a terminal, copying assets or moving the bundle.

The Environment page describes this fixed location and the current fresh-only
installation policy. Its **Show in Finder** action accepts no renderer path and
uses the ordinary user's fixed native Finder request under the original document
lifecycle gate. “Request sent” does not prove Finder became visible or validate
the installed bytes, signing, notarization, or release readiness.

This engineering package does not yet repair, update or uninstall an occupied
installation. Rerunning the same package is not a repair operation. Retain partial
installation evidence; do not delete protected installation directories to bypass
a refusal. These presentation changes do not add maintenance, a package wrapper,
LaunchServices registration, auto-launch, or a privileged application process.

## Installer entry and bounded diagnostics

The fixed package hook admits only its existing absolute `.../postinstall`
spelling and exact `./postinstall`, with target `/`. Both use physical `cd -P`
and replace the shell with the same `./mrk-macos-install "$PWD/input"`; they
cannot select another tool or destination. Literal stderr phase/refusal markers
show entry, target, invocation spelling, physical-directory selection and the
pre-exec boundary. They expose no raw arguments, working directory or environment,
and do not claim that exec completed. The relative spelling is a robustness
correction: error112 in run35646922068 did not establish its actual argv0/CWD.

The existing nonroot DATA stager can record a cursor immediately before Installer
and one diagnostic snapshot after its original return. It reads only physical
`/private/var/log/install.log`: same root-owned single-link file identity,
unchanged preceding4096-byte anchor, complete LF boundaries, at most1MiB of new
bytes,128KiB per line and256KiB of selected raw project-anchored lines. Cursor
JSON is bounded to16KiB and capture JSON to256KiB before output; selected bytes
and status scalars are bounded before the explicit artifact upload. Unrelated
neighboring lines are counted/hashed as part of the interval, never retained.
Each selected line keeps its original interval offset and hash. Missing access,
rotation, caps, incomplete/rewritten data or read/close/write uncertainty is
explicitly unknown, with no retry, alternate log source or permission change.
An output write/close failure can leave an unconfirmed task-owned file; preserve
it as unknown, not as a complete capture.

Original Installer status is saved before collection, including on failure;
its nonzero exit is propagated unchanged. Cursor/capture statuses remain separate.
No status is fabricated after timeout/cancellation. Log growth is recorded, and
reopened metadata is not continuous original-FD custody. Selected lines are
**project-correlated diagnostics, not authenticated PackageKit PID attribution**.
Opposite/duplicate result markers remain mixed/ambiguous; even one marker remains
unbound. No diagnostic capture, client-output marker or tail substitutes for the
protected result export, source/inventory/manifest checks, fixture readback,
ordinary readback or Aqua gates. Historical failed runs remain failed.

### Protected same-invocation result transport

The Installer client need not forward its child script's stdout. Successful
ordinary and fixture entries therefore export their unchanged settled final DTO
to exactly one root-owned file directly below `/Library/Application Support`:
`MobileReleaseKit-InstallerResult-v1-{ordinary|fixture}-{source40}-{inventory64}-{manifest64}.json`.
There is no alternate pathname, environment override, privileged Python reader,
log fallback or general IPC service.

Only original success starts export. A dedicated book owns at most four original
FDs, separate from the settled installation: three protected parents and one
exclusive0600 writer. The new root-uid private writer may inherit its parent's
group, then only that original is normalized to0:0/0444. Occupied names refuse;
no adoption, replacement, repair, retry or deletion occurs. JSON is closed,
UTF-8 and at most65536 bytes including LF. Full sealed leaf identity/size,
actual empty ACL/no-xattrs, file fsync+F_FULLFSYNC, one checked writer close,
parent persistence, stable protected ancestry and reverse original closes must
all pass. Ordinary export retains `Install.end`; the fixture captures one10s
export-only endpoint after its aggregate settles, before serialization. A final
post-close clock veto remains mandatory; no fallible stdout follows success.
Export failure changes original ordinary0 to20 or fixture0 to1; partial effects
and any installed objects are retained. Old nonzero outcomes never export.

Before each original Installer invocation, the nonroot stager admits only ENOENT
for this exact expected name, through checked protected parent originals. The
workflow saves the original Installer status before diagnostics, preserves an
original failure unchanged and checks status-write success separately. Required
`--installer-status` is exactly `0` plus LF in the original task-owner0600 file
under its private0700 work parent. This is saved same-run evidence, not a claim
of crash-durable journaling. Nonroot export readback requires one original
regular/single-link0:0/0444 file, exact expected bindings and all leaf/parent
closes before accepting DATA. Existing ordinary/seven-case validators and
complete installed roster/byte/mode proofs remain unchanged.

The wrapper intentionally says `pending-original-export-finalization`: a file
cannot certify its own later sync, close or timeout. Neither presence nor this
old-success DTO independently establishes finality. Qualification also requires
the original successful Installer return and reviewed producer finalization,
plus checked readback and installed-tree evidence. Observation JSON retains the
inner DTO and bounded export identity/hash with that explicit finality basis.
This source change is not itself native Installer or Aqua qualification.

## Fixed eight-case Installer fixture — separate package, not a runner

`macos-installed-installer-fixture` selects one compile-time entry using the same
`Install` helpers, sole native calls and finalizer. It is forbidden with
`desktop-shell`; it is absent from the ordinary `macos-installed-installer`
feature. Both builds require the explicit 40-hex
`MRK_MACOS_INSTALL_SOURCE_COMMIT` and retain source/inventory/runtime bindings.
Neither root entry accepts a case, destination or environment selector: only
its fixed Scripts input path. No root libtest or general harness is introduced.

The fixture package identifier is
`dev.mobile-release-kit.desktop.installed-fixture`; the ordinary package remains
`dev.mobile-release-kit.desktop.installed`. Each scripts archive is audited
against its own complete bytes and fixed package identity. They reuse **one**
completed signed app, unchanged M runtime and install inventory. The standalone
Installer is built separately per feature; neither app nor interpreter is rebuilt.

The fixture creates a fresh root:wheel 0755
`/Library/Application Support/MobileReleaseKit-InstallerFixture-<source12>-<nonce32>`
with exactly eight fixed case directories. Staging remains root:wheel **0700**.
Each case retains its own original 120-second deadline and descriptor book;
setup has its own original 120-second deadline. Unexpected native errors,
Unknown closes or expiry fail the fixture and prevent later cases. No retry,
rollback, repair, overwrite, deletion or staging-access permission is added.

| Fixed case | Required native/original outcome |
|---|---|
| `occupied-app` | Existing app occupant unchanged; no publication. |
| `occupied-release` | Existing release/runtime occupant unchanged; no publication. |
| `runtime-publication-collision` | Observe absence, create occupant, actual `RENAME_EXCL` returns EEXIST; no publication. |
| `staging-file-collision` | Observe absence, create marker, actual payload `O_EXCL` returns EEXIST; no publication. |
| `first-publication-second-refusal` | Runtime and both installation metadata files published; actual exclusive app rename refuses occupied app; retained partial/20. |
| `prepublication-persistence-report` | Actual payload-file persistence succeeds, then a fixture-only reported failure prevents publication. |
| `postruntime-persistence-report` | Actual stage persistence after runtime rename succeeds, then reported failure retains runtime/unpublished app, partial/20. |
| `metadata-descriptor-collision` | Runtime and exact inventory published; a separate descriptor occupant causes actual metadata `O_EXCL` EEXIST. Preserve runtime, inventory and occupant; no app publication, partial/20. |

The tiny shared close/deadline table checks before/at/after endpoint, first-error
preservation and absorbing Unknown while unrelated Closed facts remain positive.
Its reported error is fed to an **inert Closing/no-FD record**; no live descriptor
is invalidated, closed twice or reconstructed. The eight actual cases close each
acquired original once and fail, rather than pass, on unexpected native failure.

`MRK_MACOS_INSTALL_FIXTURE_RESULT` distinguishes real native returns from the two
reported persistence faults. Nonroot readback validates the exact eight-case
schema and explicit source/inventory/runtime anchors, preserved accessible
occupant identities/hashes and every byte/mode of all three published runtime copies.
It checks staging metadata only and **never opens or chmods staging**. A matching
source-prefixed nonce component is the only report-derived path portion.

These are deterministic collision/exclusivity observations, **not concurrent-race
proof**. Reported persistence/close-classification errors are **not actual APFS
EIO, a native close failure or power-loss durability**. The workflow runs this
separate standard Installer package and its readback before the ordinary package;
any unexpected result stops that route. Actual app/Save/Aqua remain separate.

## Recorded installation inventory (B1a)

After the runtime's confirmed publication/persistence receipt, and **before**
app publication, the same original Installer writes two root:wheel 0444 files
under the fixed `versions/<release>/` directory:

- `install-inventory.json`: the exact authenticated input bytes, not a new
  serialization or a self-referential inventory.
- `installation-v1.json`: a bounded, closed DATA descriptor binding the package,
  bundle, version, release, source, protocol, runtime manifest, inventory hash
  and length, the original 16-byte stage instance, and stable protected-root
  and release-directory identities.

The descriptor records `inventory-recorded`, **not installed/finalized**.
Mutable directory times, size and link count are not generation identity;
current original/name, full stat, ACL/mount/protection and roster observations
remain separately required. The descriptor does not authenticate its own
historical writer completion, Developer ID signature, a package hash, execution,
or permission to delete/repair/adopt anything.

Both exclusive opens, actual bytes written, persistence, readback and consuming
closes use the Installer's original 120-second endpoint and existing original
book. Any metadata failure prevents app publication and retains partial evidence;
there is no rollback or overwrite. The source-bound inner result and phase
receipts now require `installationMetadata` with `state`, `attemptedFiles`,
`openedFiles`, `plannedBytes`, `writtenBytes`, and `writersSettled`. The existing
outer export wrapper and final original status remain the finality basis.

Ordinary and fixture nonroot observations compare exact installed inventory
bytes, the descriptor tuple/stable directory identities, flags and complete
release roster before consuming all read originals. The ordinary preview
consumer also requires the metadata observation and exact returned-byte counts.
B1a adds no background service or maintenance action. The separate B1b ordinary
application reader/assessment/UI integration and its native verification are
not established by these DATA records or inert parser tests.

## Reused payload and explicit build bindings

Historical supplier M: source `aa455fa2a5bffe9cc05c0593830f4359946888ec`,
run **35602474108/1**, artifact **10639324707**. Accepted ZIP SHA256
`42a6abab90f9641ba1b8c4aa9bb4202b153d676cc6d135b8227d8690e18275be`;
its `payload.tar` SHA256
`c927caedfc5a40290da443989534e85bfdf192934f4650c3747a70c53f68d35a`;
original manifest SHA256
`7e0b042c82ff567ccfa156974118911e2ba159dbe45020344aaf4d71a28acc44`.
The historical DATA01 recipe added the two source-staged notices under
`python/licenses/`; every other supplier byte, including its then-current core
and six bootstraps, remained identical. Its independently accepted manifest was
**82483 bytes, 586 rows** (584 original files plus exactly two notices), SHA256
`2cbf9b45a1a7189e28654f62707f10705ba71d29df93e8eee7cf66b436a9abef`,
with historical protocol
`860d1cee0072730a487ac8e632206c69e3ba676cab849b144a61755c4b84e41e`.
Those facts remain supplier provenance, not current-core or native acceptance.
The unchanged historical `runtime` subcommand still enforces that old profile.

An earlier current-payload DATA snapshot (historical, not today's fresh
supplier workflow nomination) bound the following independently reviewed values:
- M (manifest): `854740a4ef63a127d8884008a8f031b00961b81419ae2228376f2bb579399721`.
- S (source inputs): `0abf9451b69602d6b3c03e631bedee18362461178bc985f5f5baf2c632ce69df`.
- Q (protocol): `083e6afae3e329c4e0d81bad00dd0c9920f77491b38ce0d23aa602996f4c4bf5`.

Their existing `current-runtime` actions reuse only the accepted interpreter
supplier and the two pinned notices, and prepares the current core/bootstrap/CA
bytes from the reviewed source. The fixed private
`$MRK_MACOS_WORK/current-runtime-preparation` path must be absent; the action
requires explicit S/M before publishing the fresh final runtime. The subsequent
`input --current-runtime` selects the current protocol/roster rather than the
historical default. Both packages use that one completed app/runtime inventory.

The captured current-source roster is 151 inputs (139 core files, ten bootstraps,
the committed CA and the preparation tool), totaling 3,766,874 bytes. The reviewed
manifest is 82,988 bytes with 590 runtime-file records. The M/S values above bind
that descriptor; workflow/guide-only consumer pin updates do not alter its payload
closure. The accepted interpreter supplier is unchanged, so no interpreter source
acquisition or CPython rebuild is needed.
These DATA bindings do not sign the runtime or grant native/GUI/distribution
acceptance. `build.rs` never discovers an anchor from an adjacent file.

The application is a normal Cargo-built Tauri bundled-asset binary in a standard
`.app` wrapper (`Info.plist`, icon, `PkgInfo`). No CLI/plugin runner is added.
The macOS Tauri overlay declares an active app and minimum 26.0. The narrow
workflow assembles that same wrapper directly, avoiding a new Tauri-CLI build
dependency. In the earlier snapshot above, ad-hoc signing targeted the completed
app and standalone Installer; the separate runtime was not re-signed. The
configured derivation below now supplies the Python signature before M, not by
mutating a completed runtime. A complete signed-app/runtime inventory is passed
explicitly into the installer build. That per-build inventory binds this build's
completed output, not an adjacent file, and grants no runtime/GUI qualification.

## CI signing identity provisioning — implementation, not credential authority

The runtime-signing shipping route, ordinary installed route, and the eleven
package-producing Aqua scopes use the `macos-developer-id` GitHub environment.
The credential-free runtime engineering route and the three nonpackage Aqua
classification/private/lifecycle routes select `macos-engineering` and receive
no signing secret. Repository administrators must independently configure the
protected environment's permitted trusted verification branches, required
reviewers and these two environment secrets:

* `MRK_MACOS_DEVELOPER_ID_P12_BASE64`: canonical base64 of the owner-authorized
  Developer ID Application identity PKCS12, at most32KiB decoded;
* `MRK_MACOS_DEVELOPER_ID_P12_PASSWORD`: its nonempty bounded printable-ASCII
  password. No secret or secret hash belongs in SOURCE, artifacts or a public
  receipt. The public SOURCE profiles/certificates must independently match.

An environment name in YAML is not proof that protection rules or credentials
exist. Unconfigured profiles still refuse shipping before credential allocation;
no ad-hoc fallback, guessed identity or future signed-capsule/M pin is supplied.
Each secret-bearing combined build/sign step disables tracing and allexport and
unexports both variables before its first child. Only the fixed packaging helper
receives inline assignments; Cargo, rustc, stagers, native probes and unrelated
children receive neither variable. No `$GITHUB_ENV`, exported job secret,
workspace key file or cross-step keychain adoption is used.

The existing original invocation owner provisions one private keychain per fixed
signing purpose. Its240s ceiling is clipped to the original enclosing endpoint,
with30s cleanup reserved inside that same ceiling, at most64 auxiliary calls per
operation and16KiB private captures per call. Exact search-list/default originals
are queried, and the user search list is temporarily restricted to the single
private keychain only after exact public SOURCE identity/certificate admission.
The default keychain is never changed. The ordered original list is restored and
rechecked, then the private keychain is removed with the Security API. Each phase
must finish all original closes and default/search-list POST before later work.
Unknown/late/mutating/close results retain private state rather than adopt or
delete an unproven object; they forbid further signing/probe/Installer dispatch
and success. Public facts contain only fixed roles/status/finality, not private
argv, search paths, output, passwords or credential hashes.

The exclusive held0700 private root is outside the work/artifact roots. The one
decoded PKCS12 has exact0600 mode, full original write/readback/POST/close and is
removed before the signing callback. Opaque Security-created database/sidecar
contents are never read: a bounded owned-single-link regular-file census permits
readable metadata modes such as0644 under the private root, rejects special,
executable and nonowner-write bits, and retains named/held/root identity checks.
It does not assume every Security version creates0600 databases or chmod an
unknown API result. Empty-root API cleanup and known closes are required.

Existing code signing retains the exact Developer ID Application SHA1 and current
flags/empty entitlement policy. Five fixed helper phases replace only the prior
vault-helper/desktop-image/payload-app/root-app/root-installer signing commands;
there is no arbitrary path/argv signer or `--deep`. The native package-producer
copy is first ad-hoc signed/strictly verified and bound to its actual CDHash and
unchanged compiled content, sealed0555, and only then admitted by exact `-T` plus
its CDHash partition. It uses the same per-purpose keychain for the existing
`SecIdentityCreateWithCertificate(NULL, sourceCertificate)` call. This is distinct
from an unsigned or compiler-future executable permission grant. Public package
original-call roles and the existing15-call emission/Installer sequence remain.

This wiring does **not** configure a Developer ID Installer identity: the current
bounded package producer uses the Application identity and existing raw producer
signature; adopting Installer/package signing would require a separate explicit
policy. No Apple ID/notary API key, `notarytool`, staple, Gatekeeper or distributable
notarization claim is added. Genuine configured key discovery/use, signature
verification, native emitter/Installer, final signed-runtime nomination/M and
installed/Aqua journeys remain required. Credential-free hardened-runtime
engineering results remain reusable for their exact executed SOURCE; they are
not substituted for Developer ID, environment protection or notarization.

## Python signature derivation before the final runtime manifest

The fresh public CPython suppliers for both targets are already built, probed,
and ad-hoc signed. Their six fixed receipt/TAR/source/run/attempt/artifact pins
remain original supplier authority, not Developer ID or notarization evidence.
The isolated `desktop-macos-python-runtime-signing.yml` workflow reuses those
originals; it does not rebuild Python or modify either supplier artifact.

Its two fixed refs select **engineering** or **configured shipping** explicitly.
Both use the existing original-process owner, one private task, and an empty
entitlements plist. Engineering signs ad-hoc with hardened runtime enabled,
then runs the existing modules (including real libffi callbacks), loader, TLS,
and cancellation probes on the exact signed bytes. Intel is tested first; a
failure is not a reason to retry with broader entitlements. Neither
`allow-jit`, `disable-library-validation`, nor
`allow-unsigned-executable-memory` is automatically enabled. This credential-free
behavior check publishes only bounded facts, never a shipping capsule or M.

Configured shipping requires the existing SOURCE signing profiles and the exact
configured Developer ID identity. It signs the one executable in a standalone
owned slot with `--options runtime` and a timestamp, verifies the exact code
requirement with `codesign --verify --strict --all-architectures`, and runs the
same four native probes. There is no `--deep`, keychain discovery, ad-hoc
fallback, or signer-selected entitlement exception. Missing credentials remain
an external requirement; the path is implemented but no configured-signature,
notarization, installation, or UI result is implied by its presence.

Only `python/bin/python3` may differ. The complete original TAR/header/content
inventory is checked before copying; every other resource byte is preserved.
Inputs, SOURCE, copied files, and their held directory identities are checked
again after the original calls. Only known originals authorize the bounded
read-only-to-cleanup directory transition and task retirement; uncertain
operation/close/retirement outcomes withhold all capsule authority. No command
can start after retirement begins. Successful shipping exports exactly
`python3` and a <=16KiB `python-signed-receipt.json`, and the outer original zero
exit is required before the workflow uploads that capsule.

The existing `describe-current-runtime` and `current-runtime` commands optionally
accept this **complete** additional input group:

```
--signed-python FILE --signing-receipt FILE
--expected-signed-python SHA256 --expected-signing-receipt SHA256
--expected-signing-source COMMIT --expected-signing-run RUN_ID
--expected-signing-attempt ATTEMPT
```

The original fresh `--python-root`, `--supplier-receipt`, and
`--expected-supplier` inputs remain mandatory. The group cannot be mixed with
the historical archive route or partially supplied. It binds the fixed original
supplier6, independently nominated derivation source/run/hashes, configured
profiles, one-file correspondence, and exact native-evidence/finality roster;
receipt booleans alone never authorize a signature. DATA staging does not invoke
the signed executable or treat the capsule as installation authority.

The substituted bytes enter the unchanged current-runtime preparer **before**
it computes M. The original supplier inventory and receipt retain their own
identities; the derived signature has separate provenance. S still covers the
same current-core/bootstrap/CA preparation inputs. A signed executable changes
M, so existing ARM/Intel ad-hoc S/M observations cannot be reused as the signed
M. Both inputs and signatures are rechecked after final publication; partial
outputs after a failed POST are inadmissible, not a retry candidate. The ordinary
installed/Aqua callers must never sign a runtime after freezing M or claim
shipping readiness from the engineering workflow.

### Fixed consumer nomination and transport

The independent SOURCE file
`desktop/macos-installed-inputs/python-signed-runtime-binding.json` selects the
capsule. Its strict schema contains both fixed targets; each row is either
exactly `{"state":"unconfigured"}` or a configured signing source commit,
run/attempt/artifact IDs, signed Python and receipt hashes, S/M, and both existing
identity-profile hashes. The committed initial rows are **unconfigured**. They
contain no guessed future hashes, IDs, signatures or M. An unconfigured selected
target fails before payload/dependency downloads or compilation; an unconfigured
other target does not block it. There is no fallback to ad-hoc M, latest artifacts
or a neighboring receipt. The credential-free engineering signer remains
independent of this nomination.

This file is deliberately separate from the producer identity profile: embedding
a receipt hash in that profile would change a digest already sealed by the
receipt. The signing producer's commit/run are also distinct from the later
consuming app commit and its current S. Original supplier6 remain unchanged.
Configure a row only after independently reviewing the real capsule's original
native signing/probe/finality evidence and exact two-file correspondence, then
describing its signed M with the existing seven explicit capsule arguments.
`describe-current-runtime` can do that DATA work before nomination; its output
must not be automatically adopted by a shipping job. A later nomination-only
commit does not reclassify or recreate the original native signing evidence.

After checkout and fixed DATA-Python setup, ordinary/preview and the eleven Aqua
current-runtime scopes use `runtime-signing-selection --target` to read the
nomination and profiles. Only its small closed public tuple is exported to fixed
environment keys. M comes from that SOURCE tuple; the independent literal S,
protocol and original supplier6 checks remain. Nonruntime Aqua scopes do not
read the nomination. The source/tool record retains both the consuming commit
and the selected signing tuple plus nomination digest, never conflating them.

Each caller downloads the original supplier and exactly one separately pinned
capsule artifact, by fixed repository/run/artifact IDs and with digest mismatch
refusal. `project-signed-python --target --transport-root DIR --output DIR`
reads exactly `python3` and `python-signed-receipt.json`, checks their configured
hashes and all original no-follow names/identities/owners/EOF/POST/closes, and
uses a new read-only output with modes 0555/0444. Downloaded originals are never
rewritten or executed. Extra entries, links, wrong modes, overlap, replacement,
partial output or unknown close refuse; failed output is retained unqualified,
not cleaned up or retried. This projection is DATA, not signature validation.

Both final `current-runtime` callers require `--configured-signing` plus the
complete seven capsule arguments above. The selected tuple/profiles and original
supplier are checked before work allocation and again across final publication;
unchanged receipt validation establishes one-file correspondence before prepare
computes M. The configured M must match those actual signed bytes. Receipt
booleans or nomination state alone grant no signature, installation or shipping
authority. Genuine identity/key availability, real signed capsule and M, and
ordinary/installed/Aqua/notarization qualification are still separate obligations.


## Existing owners and native originals

`Supervisor` and configuration `EditOwner` own the same original inspection,
transfer, one-use launch claim, child, IO and settlement joins as the Linux
seams. Their deadlines are not widened: passive 10s + 2s cleanup and the existing
finite edit/review/Apply clocks. Inspection/acquisition starts only after the
existing owner registers its blocking worker. Retained root-owned no-follow
names/ACLs and complete manifest hashes accompany, not replace, protected
installation and writer finality. Final claim is inside the existing owner's
STOP/document/deadline decision. No pathname-only executable fallback exists.

The engine receives `-I -S -B`, the fixed bootstrap/core/cwd, `env_clear`, fixed
`LANG`/`LC_ALL` and `__CF_USER_TEXT_ENCODING=0x<real-UID-uppercase-hex>:0:0`.
No inherited Python/DYLD/search-path/home data is used. This seam does not claim
that its smaller environment was exercised by M's broader publisher smoke.

A small Objective-C ABI shim retains the exact project `NSOpenPanel` or Quit
`NSAlert`, parent and copied completion. `OriginalWork` retains the coordinating
task and each serialized main-loop dispatch receiver. Cancel publishes nothing.
One-use native close and release are explicit; native completion return, hidden
window/no attached sheet, actual close, release and original coordinator join
remain distinct. An adapter-local absorbing uncertainty latch gates outcome
consumption and the next dispatch independently of the first user-facing refusal;
late native Unknown cannot hide behind SourceRefused/UserCancelled. Actual
AppKit codes retain Accept/Decline/Other by panel kind; Abort/Stop/other values
and programmatic close callbacks are Other, never genuine Cancel. A known panel
can still close/release normally. There is no Drop-as-cleanup or dispatch retry.
WK termination/page-load hooks,
`DocumentLifetime` and the existing app-held Quit exit observer remain in place.
Mac project discovery never creates an asset session or enables C/P2.

## Narrow future verification, not a success label

`desktop-macos-installed.yml` activates only on a push to the fixed
`verify/desktop-macos-installed` branch after actual source/command review. This
registers the workflow without merging unverified code into default main; it is
not a broad push trigger or an automatic retry. Both expected and Installer
source bind to `github.sha`, with exact event/ref/workflow-source/path checks,
nonroot disposable ARM64 macOS26 admission, independently fixed S/Q and
SOURCE-nominated signed M with separate 64-hex/equality guards. Permissions remain read-only and checkout
retains no credentials. There is no release/Store action, new descriptor or
interpreter rebuild.

The same job records actual Rust/Cargo, selected CLT SDK/compiler, Node and
stager-Python versions with source/run bindings. It makes one normal app build,
then binds the completed frontend, signed app and current-source runtime into one
install inventory. Before either privileged package invocation, it runs the five
existing regressions below as nonroot, grouped **2+1+2**, using the same locked
dependency graph, release profile, ARM64 target and build bindings/target cache.
Only selected libtest artifacts are additionally compiled; no second ordinary
app or interpreter build is scheduled. The native ABI package is selected from
the parent manifest/lock, not from a new standalone dependency resolution.

The ordinary workflow does not invoke the Aqua owner; ordinary4 remains a separate later obligation.
Its first-save, noop-stale, picker-loss and save-loss cases require their own
reviewed fresh namespace, not a second invocation in the retained native9 root.
No normal P2/project-picker qualification bit is enabled by this payload rebind.
The ordinary release binary, separate Installer observations, instrumented Aqua
P2/native9 and normal app/Save acceptance remain distinct evidence.

Each invocation retains at most a 128-KiB log tail and the original Cargo/tee/tail
statuses. The gate requires exactly the selected successful test names and
executed counts 2/1/2, with zero failed/ignored/measured tests; zero matches is a
failure. `--exact` receives the full names **after Cargo's `--`**, never a module
prefix. The original commands must all succeed; a successful logger cannot mask
a Cargo failure. Fixed seven-case and ordinary standard Installer packages,
archive audits and both nonroot readbacks follow unchanged. These commands remain
**unrun** for this source revision and do not establish native or GUI acceptance.
Observations still state **application not launched; Aqua/Save unverified**.

The original six tests in `tests/desktop/test_macos_installed_staging.py` passed
under DATA01 with unchanged exercised closures. The three added methods passed
**DATA03, 3/3**, under separate command and result review: fixed package identity,
bound/timely original results and exact fixture-schema refusal of unexpected
native uncertainty. Their exercised stager/test callable bodies stay unchanged.
Two new ordinary current-payload source-contract methods check only the changed
workflow bindings and preserved scope; their execution is a separate gate, not
claimed here. Reuse prior accepted results; do not repeat the six tests, DATA03
or the accepted descriptor for this workflow/test/guide change. No parser fixture witnesses the seven actual
Installer cases, Darwin ACL/rename/fsync, native close finality or panel ordering.

The exact hosted selections are shown below for command review, **not standalone
execution authorization**. They require the workflow's completed inputs and
nonroot host; its bounded logging and count/name checks are mandatory:

```sh
cargo test --manifest-path desktop/src-tauri/Cargo.toml --locked --release --no-default-features --features desktop-shell,custom-protocol --target aarch64-apple-darwin --lib -- --exact --test-threads=1 --color=never --format=pretty shell::owned_macos::tests::native_unknown_blocks_dispatch_and_outcome_despite_first_user_refusal shell::owned_macos::tests::response_mapping_preserves_other_and_missing_facts_poison_dispatch
cargo test --manifest-path desktop/src-tauri/Cargo.toml --locked --release --no-default-features --features macos-installed-installer --target aarch64-apple-darwin --bin mrk-macos-install -- --exact --test-threads=1 --color=never --format=pretty installer::tests::original_final_deadline_vetoes_late_known_closes_without_erasing_first_error
cargo test --manifest-path desktop/src-tauri/Cargo.toml --locked --release --target aarch64-apple-darwin --package mrk-macos-installed-native --lib -- --exact --test-threads=1 --color=never --format=pretty tests::only_explicit_user_appkit_responses_can_be_accept_or_decline tests::bulk_directory_records_preserve_full_ids_and_refuse_malformed_batches
```

The existing `runtime::tests::macos_*` and `asset_source::macos::tests::*`
definitions remain unrun native selections for the later finite command plan,
not a broad-suite or multi-platform harness request.

After the source/base/command gates, perform the focused real session on the
actual installed app as a normal logged-in user, away from checkout/runtime
build directories. It must include:

1. Actual eight-method availability and configuration-owner launch. Verify the
   installed Python's unchanged private Mach-O load closure and real-UID clean
   environment at its original launch boundary, not from a shell's environment
   or M's old smoke. Test changed bytes/type/link/ACL/writable-install refusals
   and startup/STOP/settlement edges without weakening path/ownership checks.
2. Real native project open and Cancel. Cancel publishes no project ID/draft or
   file mutation; a successful selection is bound to its original document and
   genuine source-directory identity, not a synthetic picker return.
3. Small synthetic project, **no `release/`**. Reuse the accepted base's genuine
   hint/suggestion/adoption flow; edit/validate/preview, inspect the review's
   directory creation and exact changes, then explicitly Save. Independently
   read back `release/mobile-release.json` and the controlled `.gitignore`
   update; preserve unrelated originals. Verify no-op and stale-base refusal,
   and cancel a prepared Save without mutation. No core rewrite/fixture shortcut.
4. Quit Cancel, confirmed Quit with outstanding work, and WK document
   termination/reload. Observe original task/native dismissal/IO/child/lease
   settlement and application exit; no late publication or document rebinding,
   replacement cleanup, renewed clocks or false success after Unknown.
5. Beyond the eight deterministic/reported-policy fixture cases, actual APFS
   concurrent race, persistence/lock/journal and native original-close failure
   edges require a separately reviewed finite native command plan. Preserve
   occupied bytes and root-owned partial evidence. Do not promote the fixture's
   reported faults into actual EIO/close failure or power-loss observations.

Do not infer that hosted Aqua works from the payload run or this new workflow.
If a real session cannot be established, report that concrete blocker and use an
authorized logged-in Mac for the **same** focused procedure, not a headless DTO
substitute. No physical Mac/signing account is presumed necessary in advance.

Outstanding native risks: exact pinned nix0.30.1 Darwin types/flags; AppKit/C ABI
including Darwin ACL end-of-list convention; filesystem persistence/exclusive
rename; root scripts-archive ownership/modes; actual installed launch timing;
WK/main-loop callback order; panel dismissal/release; original final joins;
Save transaction behavior. All are unverified here. Selected CLT/SDK agreement
and compiler-runtime/component correspondence, thirteen notice sufficiency,
Developer ID/notarization/quarantine, upgrades, Intel and older macOS remain
separate, unresolved delivery obligations. No legal/distribution clearance is
implied by adding notices or by an engineering package.
