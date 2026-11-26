# Complete a prepared SDK without downloading its compatible half

## Scope

For the existing pinned Mac profiles, an actual selected-source inspection may
find exactly one compatible required SDK package and one genuinely missing
package. This slice copies the compatible package into a **new** prepared SDK
folder, then acquires only the missing archives through the existing cache and
verified public-vendor transport. JDK/Gradle selections are kept. Nothing merges
into, removes, repairs, or upgrades the user's installation.

The resulting complete **source candidate** still goes through the ordinary
native picker, Inspect selected tools, license/review, and explicit protected
copy registration. No registration, installation acceptance, build readiness,
or native qualification follows from the result format. `NATIVE_QUALIFIED` and
every existing availability/consent gate are unchanged.

## Original ownership and ordering

1. The same native `Original::inspect_picked` first completes the existing
   acquisition SourceSlots read and its real consuming closes. The prior joined
   Inspect and fresh Acquire must still match their full partition/fingerprint.
2. `acquisition_sdk_copy_input` projects only those retained original records.
   It requires exactly one compatible SDK half, the same registered picked
   root, required member identities, and optional metadata observation. Its
   private path and binding never enter public status, logs, or renderer input.
3. The private `mrk-sdk-copy/1` value carries one component, selected root/full
   68-byte Darwin identity, and a domain-separated observation digest. The
   digest includes the same checked reference, root, required member kinds and
   full identities in component-wise path order, plus optional package.xml
   identity/byte hash. This is comparison DATA, not a continuing native loan.
4. On the existing admitted `ToolAcquisitionRun`, `SdkCopy` is retained before
   opening **new** `_Directory`/`_FD` originals with the same cancellation ledger.
   Held source/cache root ancestry must not overlap. Source and destination use
   no-follow descriptors; present bad/missing/changed data refuses, never falls
   back to downloading the compatible component.
5. Only the required subtree is copied through the existing
   `OutputTree.member`. Exact pinned modes, sizes, hashes, full stat identities,
   and complete required-subtree census are checked. A second bounded read
   performs full source POST. Optional package.xml is compared, not copied;
   the normal registration owner remains the supplier of compiled metadata.
   Unrelated SDK packages and license files are not read/copied/changed.
6. Source originals must positively close **before any new vendor transfer**.
   The existing durable pending cache intent/job, missing-only cache lookup,
   extraction, output reinspection, and parent runtime/cache/child/driver joins
   remain in place. The same cleanup scope attempts source and cache closes
   independently. A failed/unknown source close prevents transfer and complete
   result publication, retains the original, and never clears the native fence.

The original 1200s work/1210s hard bounds include native inspection, copying,
downloads and joins. No guard, clock, pending record, or original is renewed.

## Bounds and result compatibility

- The existing checked four-archive roster still bounds total expansion to
  1GiB and members to32768. No new quota or service is introduced.
- `_Space` now reserves new missing compressed bytes **plus all candidate
  expansion, including copied bytes**, with the unchanged metadata/2GiB reserve.
  Cache hits avoid only compressed download allocation, not candidate expansion.
- The native post-read ordinal vector is at most32768 machine words (256KiB
  on supported Mac64), smaller than the now-returned 1,721,344-byte source read
  workspace. All old SourceSlots records remain retained and counted. CopyInput
  and its actual path capacity are visited by `Original::retained_bytes`.
- The child adds no full file buffer: one64KiB chunk, at most48 ancestry slots
  and a total64 source-slot frontier, bounded required-roster references and
  names. The existing child/runtime memory limit and deadline stay mandatory.
  These are finite data/workspace bounds, **not a whole Python heap/RSS claim**.
- Private request12MiB, manifest8MiB, public result/status64KiB, public96MiB /
  future82MiB / separate installed-code128MiB admissions are unchanged.
- Schema1 remains unchanged, including old single-package/manual reports.
  Schema2 adds exactly `copiedSourceComponents: [one SDK half]`. Downloaded plus
  reused archives must still equal exactly the native missing set. The copied
  half must equal the native `Expected` value; the complete SDK group is their
  union. Neither JSON nor its copy list replaces the same parent census,
  currentness, positive joins, or fresh ordinary source inspection.

NDK, CMake, emulator, platform-tools, unsupported versions/layouts, denied or
uncertain source copies, and vendor license acceptance still require the
existing manual route. This is supported two-package candidate assembly, not
general SDK-manager automation. Source/cache overlap is conservatively refused.

## Integration

New leaves/tests: `tool_acquisition_sdk.rs`,
`android_registration_source_acquisition_sdk_macos.rs`,
`_tool_acquisition_sdk.py`, `test_tool_acquisition_sdk.py`, and
`tool-acquisition-sdk.test.mjs`.

Apply `tool-acquisition-sdk-root-hooks-20261020.patch` with the leaves. Its13
existing-file hooks cover the two child declarations, original native
inspection/Expected/census binding, private child protocol/run, staging service,
strict TypeScript decoding/partition comparison, existing Environment guidance,
two existing real-controller suites, and the ordinary package test list.
No App/Bridge/shell/ACL/workflow/runtime-bootstrap changes are required. Existing
runtime packaging already enumerates the whole checked Python package.

### Focused evidence

Author ran, on public source projections and inert fixtures only:

- 41 Python tests:22 existing acquisition +4 partial +6 private protocol +9 new
  SDK tests. Both copy directions, verified cache-first/missing-only requests,
  copied disk quote, retained user bytes/inodes/modes/siblings, optional metadata,
  pre-HTTP tamper, copy POST drift, overlap, ambiguous close, and exact native
  input/result binding are exercised. No actual vendor/network/process ran.
- 61 Node tests across existing acquisition/native/controller/source-picker
  suites and3 new SDK tests. Original pending/fresh status/consent/currentness
  still gate publication. Explicit SDK picking preserves existing JDK/Gradle;
  inspection/registration/build are not automatic.
- Frontend `tsc --noEmit` with existing exact dependency cache: PASS. Its own
  temporary node_modules link was removed; no installation or cache deletion.
- Six Rust sources passed rustfmt **syntax parsing only**, not compilation.

Root must compile/run these **unrun** Rust DATA cases in its existing gate:

```
tool_acquisition_protocol::sdk::tests::only_one_compatible_sdk_half_is_copyable
tool_acquisition_protocol::sdk::tests::old_results_and_new_exact_sdk_singleton_are_distinct
tool_acquisition_protocol::sdk::tests::source_hash_binds_full_identity_order_and_optional_metadata
tool_acquisition_protocol::tests::assembled_sdk_result_keeps_missing_archives_separate_from_exact_copied_half
```

Mac-only DATA (no path/ACL/child execution):

```
installed_runtime::android_registration_source::acquisition::sdk_copy::tests::sdk_copy_projection_requires_actual_source_return_and_closes
```

Actual installed Mac acquisition/copy/download/picker/registration acceptance
remains separately unverified and unavailable until Root's native qualification.
