# Transaction successor: preparation correction only; MSI still incomplete

The successor fixes all packager read/validate/copy comparisons to ignore access
 time while retaining device/inode, mode, link count, owner/group, size,
nanosecond modification/change times, creation time, platform flags, generation,
Windows file attributes and reparse tag. It also rechecks the pathname after
reading, and keeps actual content SHA256 admission. Six added regressions bring
the DATA suite to 31 tests. These checks do not authenticate Windows DACLs or ADS.

A freshly downloaded official CPython 3.14.7 x64 embed ZIP matched the existing
12,673,227-byte SHA256 pin and the checksum on the Python release page. Preparing
the current frozen source, fixed notices and CA succeeded. The output is DATA,
not an executed interpreter or qualified native runtime.

No native transaction code was added by this successor. The previous native
publisher exclusion remains unchanged. Both MSI refusal gates remain. The
following previous limitations still apply; this is not a launch-ready MSI.

---

# Successor status — incomplete native MSI integration

This cumulative overlay adds a real Win32 process exclusion primitive to the
existing publisher, after native installer-token admission and before source
admission or output mutation. It creates one fixed Global mutex and refuses
EVERY existing object; it neither waits for nor adopts abandoned ownership.
The original pinned frame records the actual handle and immediate last error.
The handle remains live until process exit, including after Rust storage drop.
Unknown native returns remain unknown during failure settlement. This protects
against overlapping publisher processes, including different runtime digests.
It is NOT durable MSI transaction ownership or authenticated completion.

`publication_exclusion.rs` has one inert return-classification test and one
ignored native kernel test. The latter requires explicit Windows admission;
it must never be reported as DATA evidence. The existing CI source inventory,
source-derived libtest count and inert selector now include this module. The
packager source binding includes the new native source and native lib.rs.
No dependency, Cargo feature, qualification bit or workflow permission changes.

Unimplemented code paths, not merely missing execution evidence:
- Durable package-bound intent/completion protocol and authenticated maintenance.
- Original installer-parent handle custody, parent-loss/reboot recovery and
  prevention of helper/input replacement by MSI before publisher invocation.
- Maintenance lock integration spanning InstallFiles, rollback, repair, removal
  and upgrade; the publisher-only mutex cannot guard these MSI operations.
- Real MSI custom-action owner that observes original publisher exit and native
  settlement before durable completion, plus safe fullwalk reconfiguration.
- WiX action sequencing and enabled build path: both refusal gates remain.
- Native tests for those missing transaction/maintenance paths.

Consequently this successor is NOT ready for an MSI execution approval. No
installer exists. Native compilation is unverified. Do not interpret the new
mutex as satisfying the broader transaction contract. The prior assembly and
DATA policy remain below as historical context; its four-file/no-native-change
inventory is superseded by RESULT.json in the successor evidence directory.

Windows session inputs remain false in runtime.rs. Required acceptance concerns
the original ordinary user Supervisor/document, source custody and native dialog
selection: Browse/Cancel/reselect; stale document/context refusal; reparse/ADS,
case alias and source replacement; token/integrity/DACL rejection; cancellation,
window close and shutdown while work is active; original worker/handle settlement;
normal GUI and WebView2 startup. Existing windows-normal-project-ui/passive and
fullwalk profiles provide portions of this evidence. Neither the publisher nor
a compiler pass supplies all of it. No enabling edit is proposed here.

Primary references:
- https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexexw
- https://docs.rs/windows-sys/0.61.2/windows_sys/Win32/System/Threading/fn.CreateMutexExW.html
- https://docs.firegiant.com/wix/schema/wxs/customaction/

---

# Windows x64 MSI assembly preparation

NONSHIPPING. This implementation stages bounded, independently bound DATA and
produces explicit WiX 4 authoring for the existing normal desktop shell and fixed
runtime publisher. It does not enable generic Tauri bundling or change runtime
qualification. No Windows executable or MSI was built in this task.

Base: ac506bb3aa663b1389f21d2cc2ff4b9b21ad96e3,
tree e88750f60d1027cd8f7bb5a3f736cbb38ace2770, version 0.1.4.
Applying the overlay creates a new source tree requiring separate admission.

## Implemented files and use

`desktop/tools/prepare_windows_msi.py` validates a hash-pinned binding, checks
critical source hashes, verifies the exact 49 input files, stages their bytes
with copy-time hash checking, and writes Package.wxs, binding.json and
assembly.json to an exclusive new output. Partial output is retained on failure.
It never launches a process, modifies installed paths or follows input links.
The CLI only prepares DATA:

```sh
python3 -I -B desktop/tools/prepare_windows_msi.py \
  --source "$REVIEWED_SOURCE" --inputs "$ADMITTED_INPUTS" \
  --binding "$REVIEWED_BINDING" --binding-sha256 "$REVIEWED_BINDING_SHA256" \
  --output "$FRESH_PRIVATE_OUTPUT"
```

The binding is exact-key JSON with schema=1; full sourceCommit/sourceTree;
version; target=x86_64-pc-windows-msvc; manifestSha256; protocolSha256;
sourceFiles mapping source-relative names to SHA256; and files mapping the input
names below to {size, sha256}. The code's SOURCE_REQUIRED set must be present.
This is a bounded source-slice check, not independent proof of an entire Git
tree or proof that a compiler produced those binaries. The lead must admit the
full source/build provenance and the binding digest independently. Do not derive
expected hashes from untrusted files and call that acceptance.

Input names are `mobile-release-kit-desktop.exe`,
`mrk-windows-runtime-publish.exe`, and `runtime/<path>` for all 47 paths from the
bound native publisher's PUBLICATION_PAYLOADS. Only runtime/ and runtime/python/
are allowed directories. No notices/dependencies may be silently added. The
current roster already contains the embedded supplier notices; desktop license
closure remains a release prerequisite and may require a reviewed roster change.
Inputs must be quiescent private build DATA, not installed runtime directories.
No native DACL, ADS, signer, PE architecture or supplier qualification is claimed
by Python filesystem checks. Those must run in the native admission envelope.

The binding is limited to 256 KiB; source inventory to 128 entries, 4 MiB each,
32 MiB total; input files to 512 MiB each, 1 GiB total; runtime source plus readback
to 1 GiB. Payload hashing and copying use 64 KiB chunks. The manifest is at most
1 MiB. All numbers and exact input sets are checked before output allocation.
The existing publisher remains the authority for its stricter manifest schema,
supplier pins, full inventory and protected runtime handling.

## Identity, layout and privilege

ProductVersion maps 0.1.4 directly to three MSI numeric fields. Prerelease labels,
fourth fields, leading zeros and overflow are rejected. The proposed UpgradeCode
is UUIDv5 of the fixed desktop identity and x64 MSI family; the ProductCode is
version-derived. These are proposed first-package identities, not established
installed identities; lead must confirm no preexisting MSI family before adoption.
WiX generates the actual PackageCode, which must be extracted into final artifact
provenance. The assembly digest binds all source and signed input records. A new
build with the same version does not authorize replacement of an admitted package.

Use only reviewed WiX **4** with `-arch x64`; later WiX versions can inject
automatic upgrade behavior. Native schema/ICE validation is still required.
The generator authors 49 explicit always64 components with stable path-based
GUIDs and file keypaths; runtime-input GUIDs include D. No harvesting is used.
The package is perMachine beneath ProgramFiles64Folder/Mobile Release Kit.
The helper and shell occupy their existing fixed names, and runtime inputs go to
runtime-input/T/D. No Directory or Component names the retained versions tree.
There are no RemoveFile, RemoveFolder, CreateFolder, shortcuts, rollback actions,
MajorUpgrade/RemoveExistingProducts actions, services or shell elevation changes.
Parent directory rows provide destinations, not recursive removal actions.

The shell stays asInvoker. Native PE resource verification must positively
confirm it; staging does not rewrite its manifest. Only the fixed publisher is
declared as a privileged custom action: no arguments, deferred, nonimpersonated,
synchronous checked return. It is deliberately **not sequenced**. Merely adding
an After=InstallFiles sequence would not solve the original-process/input lifetime
problem after installer parent death.

Every generated package contains literal Launch Condition=0, independent of
public properties. `--build` unconditionally exits 2 before any subprocess or
output. These are explicit refusal controls, not security against an administrator
editing/rebuilding the XML or bypassing MSI sequences. There is no installer
execution authorization. No command-line qualification override exists.

## Transaction/maintenance control portion

`windows_msi_transaction.py` implements the pure state policy tested alongside
assembly. It is not imported into the native publisher and is not an operating
system transaction implementation. Its inputs represent observations that a
future native owner must obtain, not values an MSI property or receipt can assert.

Fresh publication requires absent D and original locked inputs. Activation
requires the original publisher's known exit 0, positive original-handle
settlement, matching package binding and protected fullwalk. Exit 2 remains
failure. Parent loss/unknown is absorbing. Completed maintenance additionally
requires authenticated package-owned completion and a new fullwalk. Matching
bytes alone never suffice. Retained runtime removal is always forbidden.

Still required before sequencing any custom action: implement and qualify an
original native transaction owner in the sole privileged publisher, with fixed
package/input identities and serialization across fresh install, repair, upgrade,
uninstall and rollback. It must preserve unknown/partial publication and prevent
input/helper replacement while the original process is unresolved, including
parent death/reboot boundaries. MSI registration, registry values, matching
hashes, timeout, killing a PID and a success flag cannot substitute for authenticated
completion or original exit. On uncertain history refuse maintenance without
cleanup. Do not add a second privileged broker or relax existing DACL admission.
The pure policy defines useful acceptance cases but does not solve that native
ownership protocol. Accordingly native integration is explicitly blocked.

## Existing failure and next reviewable native action

Read-only inspection of run
https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/36817599395
found completed failure at app test compilation, exit 101, diagnostic E0503 at
installed_runtime_windows.rs:598 on a7d7839cf184fe29d6e87dcd292a68771b732a9e.
Its earlier windows-installed-test-compile-only check passed. Retained original
job log and remote old source show the old image_mut() borrow followed by
entries:self.entries in ImageVersionObservation. Current approved source has no
image_mut() and returns VersionObservation directly at lines 303–311. Thus the
reported old borrow pattern is absent in current source; this is inspection,
not proof that current Windows compilation succeeds. No speculative patch made.

The 20 most recent desktop-foundation runs were inspected; all were completed
failures and none used the approved base SHA. This bounded check does not prove
absence of older or other-workflow duplicates. Repeat a full exact-SHA/scope
check immediately before any authorized dispatch.

Exact next action: lead reviews this overlay/patch and admits a new source SHA/tree
with the same M/Q inputs for the existing desktop-foundation Windows envelope.
First inspect all exact-SHA active/completed runs and retained artifacts to avoid
duplication. Then propose one existing `scope=windows-runtime-publication` run on
its required verify/desktop-windows-runtime-publication branch, attempt 1,
expected_sha equal to both source and workflow SHA, windows-2025-vs2026/ImageOS
win25-vs2026. Use its original-owner compiler envelope, jobs1 and enforced 3 GiB,
serialized through the existing compiler lock. Do not dispatch from this overlay.
Compile the fixed headless publisher with:

```sh
cargo build --locked --jobs 1 --target x86_64-pc-windows-msvc \
  --no-default-features --features windows-runtime-publisher \
  --bin mrk-windows-runtime-publish
```

Supply the admitted MRK_BUNDLED_RUNTIME_MANIFEST_SHA256 and
MRK_BUNDLED_PROTOCOL_SHA256. After separately admitted publisher/consumer and
native transaction acceptance, build the normal shell with its existing graph,
verify asInvoker, PE x64, WebView2 prerequisite, dependent DLL and license closure,
then stage the independently bound signed images with this tool. Only after a
reviewed integration replaces the refusal gates may a separate approved WiX
build, ICE validation and disposable-host lifecycle suite be proposed. A compiler
pass never permits changing INSTALLED_WINDOWS_SESSION_INPUTS_QUALIFIED.

Required native cases: fresh install, successful repeat repair with authenticated
completion, unknown occupied D with matching bytes, exit2, partial publication,
crash/parent loss at each phase, original process hang, rejected DACL/reparse/ADS,
upgrade with fresh D, downgrade/same-version refusal, repair/uninstall races,
rollback preserving all versions/ancestors, ordinary GUI launch and shutdown.
Sign only publisher-owned images using an admitted public-trust identity and
trusted timestamp; preserve vendor signatures; bind post-signing bytes, verify
extracted MSI payload equality, sign/verify final MSI and freeze its hash/size,
PackageCode and source/build/signature provenance. No signing secrets were used.

## Verification and merge scope

25 inert Python DATA tests pass. Synthetic payloads are explicitly inert strings,
not PE files or admitted runtimes. Original and subsequent logs/fixtures remain.
No compiler, Windows native tests, WiX linker, installer or signing tool ran.
A review correction removed an invalid PackageCode XML attribute before final
verification. The original generated fixture is retained as historical output.
No existing/shared build files changed. Lead may merge these four additive files
without a Linux build-file conflict. Any future Cargo/build.rs/workflow deltas
must be separately coordinated; none are hidden in this patch.

Primary references checked during implementation:
- https://docs.firegiant.com/wix/schema/wxs/package/
- https://docs.firegiant.com/wix/schema/wxs/customaction/
- https://docs.firegiant.com/wix/schema/wxs/summaryinformation/
- https://learn.microsoft.com/en-us/windows/win32/msi/productversion
- https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-return-processing-options
