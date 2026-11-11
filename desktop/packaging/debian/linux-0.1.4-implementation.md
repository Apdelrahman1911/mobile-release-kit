# Ubuntu 24.04 amd64 implementation overlay — NOT NATIVE ACCEPTED

Base ac506bb3aa663b1389f21d2cc2ff4b9b21ad96e3, tree e88750f60d1027cd8f7bb5a3f736cbb38ace2770.
Proposed artifact mobile-release-kit-desktop_0.1.4-1_amd64.deb.
Applying this overlay changes source identity. Record the resulting approved tree
and commit before building; do not label a modified build with the base identity.

## Native transaction

The fixed Rust publisher still owns every native operation synchronously and
takes no arguments. Existing root context, no-follow/openat2, mount, ownership,
ACL, capability, deadline, inventory, no-replace rename, writer-close and original
settlement checks remain. No new crate, Cargo feature, shared build.rs or Windows
file changes. The only shared-tree edit is the Linux-only publisher module; its
new sibling pure policy module needs to be included when merging.

After publication rename/fsync, the publisher captures final root identity,
preserving all child identities from independent content readback. It must then
positively settle ALL original descriptors and succeed within its deadline.
Only then does a separate Publisher acquire fresh root/context/source/final
descriptors, verify the entire inventory/content again, and compare exact
identities with the first invocation's historical observations.

Completion evidence lives beside D, outside the immutable manifest roster:
.complete-pending-D is exclusively created, written, changed from its OWN 0600
to 0444, fsynced, positively closed, reopened, independently read back and closed.
Only then NOREPLACE renames it to .complete-D and fsyncs the parent.
Its canonical bytes bind target, manifest, protocol, every relative path, device,
inode, full mode, uid, gid, link count, size, mtime and ctime including nanoseconds.
Atime is deliberately excluded. The record is evidence of successfully settled
publication, NOT a process close receipt or an executable-runtime qualification.

Repeat configure verifies protected final record and all current native runtime
identities plus the full content/inventory; matching hashes alone cannot succeed.
It does not rewrite runtime files or adjust existing ownership/modes/ACLs.
dpkg provides package transaction serialization. Direct concurrent helper calls
may fail closed at exclusive creation/rename; there is no lock takeover.

Crash table:
- Before final runtime rename: any .publish-D blocks; preserve it.
- After runtime rename, before original settlement: D without record blocks.
- After original settlement but before record commit: D or pending record blocks.
- After record rename, before parent sync/last recorder close: next configure may
  validate the complete record/runtime and sync the parent. The original publisher
  was already positively settled before this record could exist.
- Record without D, extra runtime member, replacement inode, same-inode mutation,
  protocol change, ACL/mode/mount difference, or pending plus completed record:
  refuse; no cleanup or adoption.
- Previously installed D from the older publisher has no completion record and
  remains refused. Migration is an explicit lead-owned decision; this patch does
  not manufacture historical success.

This intentionally conservative recovery does not automatically finish unknown
partial installs. Ordinary repeated SUCCESSFUL configuration is the addressed
Debian idempotency case. Debian policy's broader recovery expectations still
require native review for these deliberately preserved ambiguous states.

## Assembly entry point and receipt

assemble_ubuntu_deb.py reuses stage_ubuntu_deb.py unchanged. It runs unprivileged
on Ubuntu 24.04 amd64, enumerates ELF files from both exact compiler outputs and
the entire admitted runtime (including extension/shared objects), uses
dpkg-shlibdeps without missing-library suppression, validates its Depends output,
stages the package, then invokes dpkg-deb --root-owner-group --build.
It never executes ELF inputs, uses ldd, installs, signs or deletes partial output.
Closure errors retain stdout/stderr and prevent assembly. Private bundled library
resolution may require correct admitted package metadata; do not suppress errors.
dlopen/plugin/GUI dependencies require a separate native runtime audit because
DT_NEEDED analysis cannot prove them. Native notices must cover the final shell.

Invocation after lead admission:
python3 -I -B desktop/tools/assemble_ubuntu_deb.py --config /ABS/staging.json --receipt /ABS/build-receipt.json --receipt-sha256 ADMITTED_SHA256 --work /ABS/PRIVATE/fresh-assembly

staging.json contains existing stage_ubuntu_deb arguments: compiled,
compiler_files, compiler_files_sha256, runtime, manifest_sha256, protocol_sha256,
prepared_artifact, prepared_files, prepared_files_sha256, desktop_notices,
desktop_notice_files, desktop_notice_files_sha256, version=0.1.4-1.
All paths absolute. output and depends are computed. The independently admitted
receipt contains schemaVersion=1, version=0.1.4, sourceCommit, sourceTree,
sourceFiles=[{path,size,sha256}], and the five matching *_sha256 fields.
sourceFiles must cover the entire reviewed build-input tree, including frontend,
core/runtime sources, lockfiles, toolchain and all overlay files. The tool checks
listed bytes and mandatory critical members; completeness and authenticity of the
build receipt are admission responsibilities. Receipt hashing alone is not proof
of compiler provenance. Bind compiler pair and M/Q to this SAME source in the
build envelope; an old admitted runtime is not automatically current-source bound.

## Exact next lead-owned review/action

1. Portable Rust policy tests now compiled and all eight passed under the shared
   compiler lock and process-group RSS supervisor on macOS. Do not use RLIMIT_AS
   on macOS. This is DATA evidence only. Linux module compilation and native IO
   remain unexecuted. See successor EXECUTION.md and RESULT.json for current facts.
2. Before approving execution, re-query existing Ubuntu workflow runs and jobs:
   gh api 'repos/Apdelrahman1911/mobile-release-kit/actions/workflows/desktop-ubuntu-publication.yml/runs?per_page=5'
   Current read found latest 36680533514 failure at eb39c598..., followed by
   failures 36656013790 and 36639693708; older successes 36344095615 and
   36284691187. All five completed and none this base. Inspect the latest failure's
   actual job log and the retained payload from 36284691187 before proposing a new
   run. Recheck ALL queued/in-progress runs for the admitted candidate to prevent
   duplicates; this five-run read is not an exhaustive audit.
3. Admit a disposable Ubuntu24.04 amd64 VM with supported kernel/root filesystem,
   initial namespaces and real root package installation context. Containers,
   fakeroot and chroot do not establish publisher native acceptance.
   Use existing publication workflow admission/owner boundaries, not a dispatch
   with substituted base SHA. No workflow dispatch is part of this overlay.
4. Prepare current-source runtime plus complete notices under existing M/Q
   contracts. Build current frontend using npm run build with already admitted
   dependencies. Compile separate headless publisher:
   cargo build --locked --jobs 1 --release --target x86_64-unknown-linux-gnu --no-default-features --features ubuntu-runtime-publisher --bin mrk-runtime-publish
   Compile shell separately with desktop-shell,custom-protocol (no development-runtime), same
   target/release/source/M/Q and fresh isolated target directory:
   cargo build --locked --jobs 1 --release --target x86_64-unknown-linux-gnu --no-default-features --features desktop-shell,custom-protocol --bin mobile-release-kit-desktop
   Both need MRK_BUNDLED_RUNTIME_MANIFEST_SHA256 and MRK_BUNDLED_PROTOCOL_SHA256.
   Enforce 3GiB hard memory and jobs1 for all compilation; serialize using the
   existing global lock before any compiler start. Confirm all current build.rs
   release contract prerequisites, pinned tools and lockfiles before execution.
5. Admit compiler/notice/runtime inventories and receipt; execute assembly in a
   fresh private output. Review dependency logs, ELF machine/type and all dynamic
   dependencies, package control/scripts/desktop entry, licenses and package
   content inventory via dpkg-deb --info/--contents. Record complete package hash.
6. In a fresh disposable VM only, lead-authorized sudo dpkg --install /ABS/package.deb,
   then sudo dpkg-reconfigure -f noninteractive mobile-release-kit-desktop twice. Retain original
   statuses and fd/native observations; compare all runtime bytes/inodes/modes and
   all older/unknown trees before/after. Verify fullwalk and nonroot GUI startup,
   core actions, lock/unlock, quit/process settlement and user-data retention.
7. Separate disposable snapshots: unknown D, unknown .publish-D, pending record,
   missing/truncated record, record symlink/hardlink, substituted same-byte inode,
   same-inode changed-and-restored bytes, extra file, ACL/default ACL and mount
   substitution; all must fail without tree repair/removal. Instrument test-only
   crash boundaries before/after rename, fsync, original close and record commit.
   Never execute injected failures on the owner's computer. Preserve each state.
8. Validate upgrade, same-version reinstall, remove/purge and reinstall retention,
   concurrent manual helper invocation, reboot record validation, and package
   database states. Do not enable qualification flags based on builds or DATA tests.
   Production signing/repository authentication, final licenses, GUI/dlopen closure,
   native acceptance and release provenance remain pending. No secrets accessed.

References consulted:
https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html
https://man7.org/linux/man-pages/man2/rename.2.html
https://man7.org/linux/man-pages/man2/fsync.2.html
https://manpages.debian.org/bookworm/dpkg-dev/dpkg-shlibdeps.1.en.html
