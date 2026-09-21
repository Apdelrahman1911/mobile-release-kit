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

## Deliberately small product surface

- macOS **26.x, ARM64**, normal `desktop-shell,custom-protocol`, no
  `development-runtime`. App startup rejects root/set-ID/incompatible hosts.
- Exactly eight passive methods: `capabilities`, `catalog`, `project.snapshot`,
  `config.validate`, `config.suggest`, `config.preview`,
  `environment.requirements`, `github.setup.propose`.
- Separate existing configuration `EditOwner`: open → prepare/review → explicit
  Apply/Save → close/status. Same core `InitRootLease`/transaction, stale-base
  policy, `.gitignore` control, and absent-`release/` creation. The project picker
  supplies an observation/registered identity, **not** the Save lease.
- No Mac P2 picker, C candidate evidence, saved metadata/version service,
  credentials, workflow/metadata Apply, diagnostics, builds, Store or network
  service. Existing frontend and capability intersection are reused unchanged.
  File/P2/evidence native panels are explicitly unsupported on this platform.

## Fixed installation and root boundary

The installed app is
`/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app`.
The runtime is
`/Library/Application Support/MobileReleaseKit/versions/macos26-arm64-project-draft-01/runtime`.

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
   can `MRK_MACOS_INSTALL_RESULT` report `installed`. Equality is late; actual
   positive closes stay Closed. The post-native persistence/forward-close gates
   and final classifier preserve the first error; a final unknown close has its
   own fixed reason. Exit 20 is retained published-but-incomplete, never success.
   Timeout/unknown retains staging and any published object. This source has no
   deletion/cleanup path at all, even for unpublished staging.

The 120-second Installer admission clock is not an extension of any application
clock and cannot preempt a blocked kernel syscall. Unknown must remain Unknown;
process absence or a standard Installer exit alone cannot prove native finality.

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
unbound. No diagnostic capture or tail substitutes for the unchanged client-output
record, source/inventory/manifest checks, fixture readback, ordinary readback or
Aqua gates. The next native attempt must establish the actual channel before any
separate change to readback authority can be considered.

## Fixed seven-case Installer fixture — separate package, not a runner

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
with exactly seven fixed case directories. Staging remains root:wheel **0700**.
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
| `first-publication-second-refusal` | Runtime published; actual exclusive app rename refuses occupied app; retained partial/20. |
| `prepublication-persistence-report` | Actual payload-file persistence succeeds, then a fixture-only reported failure prevents publication. |
| `postruntime-persistence-report` | Actual stage persistence after runtime rename succeeds, then reported failure retains runtime/unpublished app, partial/20. |

The tiny shared close/deadline table checks before/at/after endpoint, first-error
preservation and absorbing Unknown while unrelated Closed facts remain positive.
Its reported error is fed to an **inert Closing/no-FD record**; no live descriptor
is invalidated, closed twice or reconstructed. The seven actual cases close each
acquired original once and fail, rather than pass, on unexpected native failure.

`MRK_MACOS_INSTALL_FIXTURE_RESULT` distinguishes real native returns from the two
reported persistence faults. Nonroot readback validates the exact seven-case
schema and explicit source/inventory/runtime anchors, preserved accessible
occupant identities/hashes and every byte/mode of both published runtime copies.
It checks staging metadata only and **never opens or chmods staging**. A matching
source-prefixed nonce component is the only report-derived path portion.

These are deterministic collision/exclusivity observations, **not concurrent-race
proof**. Reported persistence/close-classification errors are **not actual APFS
EIO, a native close failure or power-loss durability**. The workflow runs this
separate standard Installer package and its readback before the ordinary package;
any unexpected result stops that route. Actual app/Save/Aqua remain separate.

## Reused payload and explicit build bindings

Retained M: source `aa455fa2a5bffe9cc05c0593830f4359946888ec`,
run **35602474108/1**, artifact **10639324707**. Accepted ZIP SHA256
`42a6abab90f9641ba1b8c4aa9bb4202b153d676cc6d135b8227d8690e18275be`;
its `payload.tar` SHA256
`c927caedfc5a40290da443989534e85bfdf192934f4650c3747a70c53f68d35a`;
original manifest SHA256
`7e0b042c82ff567ccfa156974118911e2ba159dbe45020344aaf4d71a28acc44`.
The source-staged notices are additional files under `python/licenses/`.
Everything else—including Mach-O, core and all six bootstraps—must be identical.
No interpreter source acquisition, rebuild, payload re-signing or replacement
manifest is inferred from the old native acceptance.

The independently accepted DATA01 result established the successor manifest:
**82483 bytes, 586 rows** (584 original files plus exactly two notices), SHA256
`2cbf9b45a1a7189e28654f62707f10705ba71d29df93e8eee7cf66b436a9abef`.
That exact digest is now the explicit
`MRK_BUNDLED_RUNTIME_MANIFEST_SHA256` input and the workflow admission pin.
`describe-runtime` remains read-only description, never automatic authority;
`runtime` refuses a mismatching explicit digest before creating output. This
accepted DATA result is not a native rebuild/install result. Protocol remains
`860d1cee0072730a487ac8e632206c69e3ba676cab849b144a61755c4b84e41e`.
`build.rs` never discovers either anchor from an adjacent file.

The application is a normal Cargo-built Tauri bundled-asset binary in a standard
`.app` wrapper (`Info.plist`, icon, `PkgInfo`). No CLI/plugin runner is added.
The macOS Tauri overlay declares an active app and minimum 26.0. The narrow
workflow assembles that same wrapper directly, avoiding a new Tauri-CLI build
dependency. Its only ad-hoc signing commands target the completed app and the
standalone Installer; the runtime lives **outside** the app and is never passed
to codesign. A complete signed-app/runtime inventory is then passed explicitly
into the installer build. That per-build inventory binds this build's completed
output, not an arbitrary adjacent file, and grants no runtime/GUI qualification.

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
nonroot disposable ARM64 macOS26 admission and the literal accepted M-plus-notices
digest plus its independent equality check. Permissions remain read-only and
checkout retains no credentials. There is no release/Store or payload rebuild.

The same job records actual Rust/Cargo, selected CLT SDK/compiler, Node and
stager-Python versions with source/run bindings. It makes one normal app build,
then binds the completed frontend, signed app and unchanged runtime into one
install inventory. Before either privileged package invocation, it runs the five
existing regressions below as nonroot, grouped **2+1+2**, using the same locked
dependency graph, release profile, ARM64 target and build bindings/target cache.
Only selected libtest artifacts are additionally compiled; no second ordinary
app or interpreter build is scheduled. The native ABI package is selected from
the parent manifest/lock, not from a new standalone dependency resolution.

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
native uncertainty. Their stager/test bytes are unchanged here. Reuse these
accepted results; do not repeat the six tests, DATA03 or M description for a
workflow/doc scheduling change. No parser fixture witnesses the seven actual
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
5. Beyond the seven deterministic/reported-policy fixture cases, actual APFS
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
