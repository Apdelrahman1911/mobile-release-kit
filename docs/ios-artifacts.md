# iOS artifact correspondence

## Candidate inputs and validation boundaries

Every iOS candidate requires an IPA **and its retained xcarchive**, even when
`ios.symbols.policy` is `disabled`. A supplied detached dSYM artifact must contain
the exact `dSYMs/` inventory and bytes from that archive. In protected CI use:

```text
--artifact ios-ipa=.mobile-release/artifacts/ios/app.ipa
--artifact ios-archive=.mobile-release/artifacts/ios/archive.zip
--artifact ios-dsyms=.mobile-release/artifacts/ios/dsyms.zip
```

Only the last input is optional. The packed roots are exactly `archive.xcarchive/`
and `dsyms/`; local preflight also accepts their directories. Signed preflight
requires the pair. Offline IPA-only inspection cannot report correspondence PASS.

Build preflight and fresh Store preparation independently inspect private,
toolkit-owned snapshots. Native signing checks and artifact records use those
same bytes, never mutable source paths bracketed only by hashes. Original files
must still match before authorization is sealed. This rejects input-path and
A→B→A substitution; it does not protect a fully compromised same-user runner.
Store preparation never executes application build scripts or project checks.

## What must correspond

- Primary and nested app/extension/framework/XPC/resource-bundle paths, declared
  executables, Bundle IDs, and type-sensitive Info.plists. XML versus binary plist
  encoding may differ, but values may not; duplicate keys fail. Applications and
  extensions use the committed version/build. Frameworks retain their own versions.
- Every Mach-O, including embedded dylibs and suffixless helpers: CPU/subtype,
  UUID, file type, and signature-neutral content hash. Identical framework copies
  at different paths are allowed; conflicting images with the same UUID are not.
- All other resources and directory inventories. Only recognized bundles' exact
  `_CodeSignature/CodeResources` and app/extension `embedded.mobileprovision` may
  differ. Extra signature-directory payload and native code hidden there fail.
- Every **present** retained dSYM DWARF slice must match a shipped native identity;
  unknown/substituted/duplicate symbols fail. `retain` additionally requires every
  primary-app slice. Complete missing-nested/per-architecture coverage remains a
  separate outstanding validation requirement; present-symbol consistency is not
  proof of that stronger guarantee. No third-party symbol upload is performed.

Thin/fat, 32/64-bit Mach-O structures are bounded and parsed without executing code.
Unknown load commands, overlapping sections/slices, forged signature extents,
missing UUIDs and unsupported layouts fail closed. dSYMs have a distinct MH_DSYM
path supporting original virtual sections and file-backed DWARF after `__LINKEDIT`.

## Re-signing, integrity and authenticity

The comparison permits only signature changes and their validated bookkeeping:
the trailing `LC_CODE_SIGNATURE` allocation, its command/header padding, and the
containing read-only `__LINKEDIT` size fields. All other commands and content,
including linkedit payload and ordinary gaps, remain bound. Slice order/location
may differ in a FAT wrapper with bounded zero alignment padding.

Native `codesign` can leave old signature bytes after a shrinking SuperBlob.
Only bounded slack **after** its declared envelope is permitted; unindexed
nonzero envelope data still fails. Native signatures need not authenticate slack.
The candidate/intent's authenticated **whole-file** SHA-256 binds all bytes,
including signatures and slack. Changing them after sealing fails execution.
Neither a UUID nor a signature-neutral hash independently proves authenticity or
the semantic truth of arbitrary DWARF data. Native Apple signing/profile checks
and original producer/attestation evidence remain required.

## Supported exporter and limits

Shared export sets `stripSwiftSymbols: false`, `thinning: "<none>"`, and
`uploadSymbols: false`. Recompiling, stripping, thinning, resource transformation,
or changing an effective plist value is not a supported export adapter. Do not
weaken correspondence or rebuild an accepted candidate to recover it.

Optional `SwiftSupport/iphoneos` dylibs must correspond between archive and IPA
and match every shipped counterpart slice. Unshipped support slices may retain
additional architectures and do not count as installed-code symbol coverage.
WatchKitSupport, ODR packs, bitcode/recompilation roots and unknown ancillary roots
are unsupported. A preserved vendor `__LLVM` segment is ordinary hashed content,
not permission to recompile or strip it. The shared single-primary-profile
credential limitation still applies independently of artifact correspondence.

No input symlinks or special files are allowed. ZIPs are single-disk stored/deflated,
unencrypted, without sidecar roots; workflow `ditto` disables resource forks,
extended attributes and quarantine metadata. Limits include 100,000 paths, depth
64, 4 GiB per input/member, 16 GiB expanded tree, 32 MiB central directory,
4 MiB plist, and 1 GiB per native object. Native data-in-code tables allow at most
1,000,000 records (8,000,000 table bytes), parsed in bounded chunks with indexed
section lookup rather than a full section scan per record.

One shared **15-minute cooperative deadline** spans private snapshot creation,
copying, extraction, plist/native/symbol inspection, signing checks and final
input rechecks. Later files and cached phases cannot renew it. Each native child
retains its own timeout; an already-running bounded child or stalled OS call can
overshoot the cooperative deadline, but expiry prevents the next child, fresh
Store preparation, or publication of a new intent. This is not hard wall-clock
preemption or protection from a compromised runner.
Unsupported cases fail before mutation; they need a reviewed adapter, not a bypass.

## Retention, recovery and verification

Upgrade pins before candidate creation. Existing unsafe/independently validated
evidence cannot be silently reissued as this contract. Retain the original packed
archive/symbols as well as the IPA for incomplete-operation recovery. Execution
checks their exact intent-bound hashes; it never substitutes new symbols/archive.
Authenticated accepted-build recovery reuses historical validation even after
profile/certificate expiry. Every actual new IPA send still runs isolated current
signing validation on an exact private IPA snapshot. Complete final-evidence reuse
remains Store-free and needs no binary revalidation. See [recovery](recovery.md).

Deadline failure removes private snapshots, not original artifacts or surviving
evidence. If read-only Store preparation finished but intent publication failed,
retry with the unchanged candidate: the unsealed readback remains diagnostic,
and a separate fresh readback is captured before authorization. No new upload,
rebuild, re-signing, or replacement version is authorized by a timeout.

`tests/unit/test_ios_correspondence.py`, `test_macho_native.py`,
`test_inspection_budget.py`, CLI recovery/current-upload tests,
schema tests and real mocked-HTTP Fastlane lanes cover substitution, malformed
inputs, source races, post-seal tampering, deadline exhaustion/cleanup and retry
after readback but before intent persistence. Native tests use only synthetic/ad-hoc
signatures on the local Xcode and disposable SDK copies. They are **not** a real
Apple Distribution `archive/exportArchive` rehearsal on pinned Xcode 26.3; the
consumer must run that protected, non-public integration gate before activation.
