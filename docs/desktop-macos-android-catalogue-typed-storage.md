# Compile-time catalogue table storage, version 1

This is a SOURCE representation change, not supplier authorization. It replaces
large generated row constructors with immutable binary assets decoded by safe
Rust const functions into the same named, typed static arrays. The runtime
supplier types, layouts, serde implementations, canonical stream order, array
order, ordinals, validation, caches, pointer consumers and resource ceilings are
unchanged. Fewer source constructors are a candidate for reducing compiler
pressure; no memory improvement has been measured or established.

The generator uses `macos_android_catalogue_tables.py`. Its independent DATA
reader decodes the records back to closed expression tuples for comparison and
for the existing preparation roster. It does not use `eval`, interpret code, or
open a path. The external owner must bind this SOURCE along with the generator.
`android_supplier_macos_catalogue_binary.rs` uses no unsafe code, allocation,
ABI casts or runtime input. Runtime authority continues to come from the
unchanged supplier/provenance/native/inventory joins.

## Envelopes

All integer fields are unsigned and little-endian. Profile 1 is ARM64 and
profile 2 is x86_64. Filenames include profile, kind and full SHA-256; readers
must verify the compiled/source-bound expected path, bytes and hash. A hash is
a storage identity, not native qualification or supplier acceptance.

The records header is 24 bytes: `MRKTBL01` (8), profile u32 at 8, section count
u32 at 12, directory end u32 at 16, zero u32 at 20. Each directory entry is 20
bytes: kind u8 at 0, zero u8 at 1, ordinal u16 at 2, record stride u32 at 4, row
count u32 at 8, absolute data offset u32 at 12, data byte length u32 at 16.
Entries are strictly ordered by (kind, ordinal). Data is contiguous from the
directory end to exact EOF. Every kind below occurs; OfficialMember ordinals
are exactly 0 through 5; other kinds have ordinal 0 except NestedNative. Counts
are at most 128 sections, 32768 rows per section, 128 rows per nested section,
and 278528 rows total. A nested ordinal is below 32768. No trailing data, gaps,
overlaps, duplicate keys, unknown kinds, mismatched strides or nonzero reserved
fields are accepted.

The string header is `MRKSTR01` (8), profile u32 at 8 and string count u32 at
12, followed by count+1 u32 offsets relative to the following UTF8 payload.
Count is 1 through 131072. Offsets 0 and 1 are zero: index 0 is empty. Each
remaining string is nonempty, strictly increasing by UTF8 bytes, unique, valid
UTF8 and at most 2048 bytes. The last offset is exact payload EOF. The source
converter accepts the current ASCII generated grammar; the safe readers can
validate UTF8. Records contain string indices, never process pointers.

Each individual pack is at most 32 MiB. Generated wrapper plus both packs plus
the unchanged header extent is at most the existing 32 MiB output allowance.
The wrapper plus both new packs may not exceed the old literal source size.
Output callbacks receive at most 65536 bytes, with contiguous asset offsets.
Owners additionally enforce their aggregate disk/RSS/time allowances. Failed
or partial output remains tentative and must never be installed as success.

## Record layout

`S` means a u32 string index; a header `H` is four u32 values: prefix offset,
prefix bytes, commands offset, commands bytes in the original immutable header
asset. A present header has 1..4096 prefix bytes and 32..16416 command bytes;
both ranges must be inside that asset. The Python equivalence reader also joins
the exact original CAT_Hn_PREFIX/CAT_Hn_COMMANDS name pair. All inactive union
fields and all reserved bytes are zero.

| Kind / stride | Fields at byte offsets |
| --- | --- |
| 1 OfficialMember / 32 | name S@0; kind u8@4; disposition u8@5; support u8@6; zero u8@7; mode u32@8; source ordinal u32@12; bytes u64@16; sha S@24; alias target S@28 |
| 2 SourceMemberSpec / 32 | group u8@0; kind u8@1; zero u16@2; relative S@4; bytes u64@8; sha S@16; alias target S@20; canonical S@24; mode-slice index u32@28 |
| 3 SourceBinding / 16 | provenance u8@0; archive u8@1; disposition u8@2; zero u8@3; member u32@4; payload/alias ordinal u32@8; parent prefix S@12 |
| 4 PayloadSource / 48 | installed path S@0; mode u32@4; size u64@8; sha S@16; origin u8@20; group u8@21; support u8@22; metadata u8@23; relative S@24; archive sha S@28; archive bytes u64@32; zero u64@40 |
| 5 FileClass / 24 | class u8@0; SDK kind u8@1; zero u16@2; nested table index u32@4; H@8 |
| 6 NestedNative / 40 | member S@0; mode u32@4; bytes u64@8; sha S@16; native kind u8@20; header-present u8@21; zero u16@22; H@24 |
| 7 CanonicalAlias / 16 | path S@0; target S@4; canonical S@8; source ordinal u32@12 |
| 8 directory / 4 | path S@0 |

Tags are finite, independently matched in the Rust and Python readers:

- Archive/source kind: 0 directory, 1 file, 2 alias.
- Archive disposition: 0 picked, 1 sealed support, 2 wrapper directory.
- Group: 0 Jdk, 1 Sdk, 2 Gradle, 3 FixedSupport.
- Support: 0 BundletoolJar, 1 Aapt2OsxJar.
- Binding provenance: 0 vendor, 1 archive parent; archive is below 6.
- Binding disposition: 0 payload, 1 alias, 2 directory.
- Payload origin: 0 directly picked, 1 direct support, 2 compiled metadata,
  3 member of the same original support archive. Origin 3 retains the encoded
  archive tuple and uses the unchanged small `CAT_PROJECTED` declaration.
- Metadata: 0 Platform35Revision2, 1 BuildTools35.
- Class: 0 Data, 1 LicenseText, 2 GradleShell, 3 GradleForeignLauncher,
  4 AndroidTargetElf, 5 SdkBash, 6 SdkLegacyIntel, 7 MachO, 8 JvmArchive.
- SDK: 0 D8, 1 Apksigner, 2 LldShell, 3 LldIntel, 4 CxxIntel, 5 CxxAbiIntel.
- Native: 0 Arm64, 1 JdkInstalledCounterpart, 2 JdkJpackageTemplate,
  3 OtherPlatformElf, 4 OtherPlatformPe, 5 GradleIntelPlatform,
  6 GradlePlainJansiIntel, 7 BundletoolDarwinI386X64, 8 CurrentX64,
  9 OtherPlatformArm64, 10 OtherPlatformI386.
- Header-present: 0 absent, 1 present.

Mode slices remain small typed const declarations. Each has 1..4 distinct
ascending modes no greater than 0777. Their sorted deduplicated list has at most
16 entries. Nested table indices refer to a small const slice list: 0 is empty,
then the original CAT_N tables in numeric-ordinal order. Both forms borrow
static storage; consumers receive the existing `&'static [T]` shapes.

## Acceptance evidence still required

Before generated output is accepted, an admitted owner must bind exact original
source/header inputs and converter/reader code, compare every decoded row with
the original restricted-parser tuple in original order, verify section counts
and tuple hashes, compare every unchanged source region and original header
byte, and verify the exact closed output inventory. That check covers both
profiles. No row may be dropped or reordered to reduce size.

The finite synthetic tests cover every record shape, profile separation,
malformed envelopes/tags/indices/reserved bytes/UTF8, deterministic output,
output caps, interrupted sinks and the default generator packing boundary.
The old literal formatter tests remain on the literal inner function because
their intentionally incomplete fixtures are not complete supplier catalogues.

Python tuple equivalence does not prove actual Rust const evaluation, serde
stream equivalence, ABI/layout, static pointer identity, acquisition budget
conservation or compiler resource fit. Those require separately admitted checks
on the exact final source. Preserve existing supplier digest/provenance/source
book/cache/native/original-open tests and ceilings. Actual-role compiler checks
and any native/device/signing checks remain separately gated.

## Bounded const evaluation

Each profile keeps its single original header, record and string backing in its
wrapper. A private inline codec includes the shared decoder and validates all
strings in separately evaluated groups of32. Coverage consumes actual validated
unit ordinals. The accessor checks each span is at most2048bytes before safe
UTF8, including an independently checked predecessor at every block boundary.

Every section, including an empty alias table, has a checked descriptor. Named
32-row chunk statics retain all original row checks. A named array of references
to those chunks feeds the original contiguous final typed array; it never copies
all chunk values into another aggregate. Final nested tables precede classes and
all public roster/payload references retain the same final-table identities.

Section and string profiles must agree at every chunk entry. Equal-tag alternate
raw objects remain excluded by exact closed generated-source bindings; metadata
is not filesystem authority. Full tuple/serde/pointer checks and compiler resource
limits remain mandatory. A smaller source format does not prove compiler success.
