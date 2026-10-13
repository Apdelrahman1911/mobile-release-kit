//! Comparison DATA shared by the private macOS Android supplier builder and
//! the original app source book. Nothing here owns or opens a path/descriptor,
//! acknowledges a license, selects a renderer supplier, or attests finality.
use crate::android_toolchain_macos_policy::{self as policy, Alias, FileSpec};
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) enum SourceGroup { Jdk, Sdk, Gradle, FixedSupport }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JdkLayout {
    /// The actual selected .jdk bundle.
    Bundle,
    /// The selected Contents/Home is proven by the original source book to
    /// belong to its SAME retained .jdk ancestry. This enum is not that proof.
    HomeInSameBundle,
}
/// Small selected-original layout/release observations, not project settings
/// and not supplier authority. The compiled profile supplies the SDK/Gradle/
/// AGP tuple. No arbitrary Gradle script or project configuration is parsed.
pub(crate) struct SourceLayouts<'a> {
    pub(crate) jdk: JdkLayout,
    pub(crate) jdk_vendor: &'a str,
    pub(crate) jdk_version: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) enum SupportAsset { BundletoolJar, Aapt2OsxJar }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum ZipMethod { Stored, Deflate }

/// All offsets are measured in the SAME original ZIP, not an extracted file.
/// The archive pin is separate from this expanded member pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ZipMemberSpec<'a> {
    pub(crate) name: &'a str,
    pub(crate) method: ZipMethod,
    pub(crate) flags: u16,
    pub(crate) local_header_offset: u64,
    pub(crate) data_offset: u64,
    pub(crate) compressed_bytes: u64,
    pub(crate) bytes: u64,
    pub(crate) crc32: u32,
    pub(crate) sha256: &'a str,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ArchivePin<'a> {
    pub(crate) bytes: u64,
    pub(crate) sha256: &'a str,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum OriginalSource {
    /// Relative to the retained picked bundle/SDK/distribution root. JDK
    /// members are always bundle-relative, including HomeInSameBundle picks.
    Picked { group: SourceGroup, relative: &'static str },
    /// Closed logical asset; the installed asset owner supplies the real path.
    /// The builder neither invents that path nor adds a fourth picker.
    Support(SupportAsset),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum PayloadOrigin {
    /// Exact compiled official-definition projection. No picked SourceBinding
    /// or invented package.xml observation provides these payload bytes.
    CompiledSdkMetadata(SdkMetadataKind),
    DirectOriginal(OriginalSource),
    MemberOfSameOriginalArchive {
        asset: SupportAsset,
        archive: ArchivePin<'static>,
        member: ZipMemberSpec<'static>,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct CanonicalFile {
    pub(crate) path: &'static str,
    pub(crate) size: u64,
    pub(crate) sha256: &'static str,
    pub(crate) mode: u32,
}
/// Compiled sorted inventory position is the zero-based payload ordinal.
/// Metadata document indexes are separate. Static borrowed paths have no
/// source-book/native custody; actual registration rereads the same originals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct PayloadSource {
    pub(crate) installed: CanonicalFile,
    pub(crate) origin: PayloadOrigin,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) enum SourceKindSpec {
    Directory { modes: &'static [u32] },
    File { bytes: u64, sha256: &'static str, modes: &'static [u32] },
    Alias { target: &'static str, canonical: &'static str, modes: &'static [u32] },
}
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct SourceMemberSpec {
    pub(crate) group: SourceGroup,
    pub(crate) relative: &'static str,
    pub(crate) kind: SourceKindSpec,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct SourceTree {
    pub(crate) group: SourceGroup,
    /// Empty means that entire retained root. A nonempty prefix is the exact
    /// selected SDK package subtree; never enumerate a broad SDK then truncate.
    pub(crate) prefix: &'static str,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct SupportOriginalSpec {
    pub(crate) asset: SupportAsset,
    pub(crate) archive: ArchivePin<'static>,
    pub(crate) modes: &'static [u32],
}
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct SupportMemberSpec {
    pub(crate) asset: SupportAsset,
    pub(crate) member: ZipMemberSpec<'static>,
}
/// Two fixed SDK packages, not renderer-selected metadata paths or consent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum SdkMetadataKind { Platform35Revision2, BuildTools35 }
impl SdkMetadataKind {
    pub(crate) const fn index(self) -> usize {
        match self { Self::Platform35Revision2 => 0, Self::BuildTools35 => 1 }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct OptionalSdkMetadataSpec {
    pub(crate) kind: SdkMetadataKind,
    pub(crate) relative: &'static str,
    pub(crate) max_bytes: usize,
    pub(crate) modes: &'static [u32],
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct PickedSdkMetadataData<'a> {
    pub(crate) file: &'a FileSpec,
    pub(crate) contents: &'a [u8],
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct SourceRoster {
    pub(crate) trees: &'static [SourceTree],
    pub(crate) members: &'static [SourceMemberSpec],
    pub(crate) support: &'static [SupportOriginalSpec],
    pub(crate) archive_members: &'static [SupportMemberSpec],
    pub(crate) optional_sdk_metadata: &'static [OptionalSdkMetadataSpec; 2],
}

/// Admission accounting only. Neither phase is source/transfer GO or finality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourcePhase { Inspection, Reproof }

pub(crate) const SOURCE_ORIGINAL_SPILL: usize = 512 + 2;
pub(crate) const SOURCE_ORIGINAL_LIMIT: usize = 2 * policy::ENTRY_LIMIT + SOURCE_ORIGINAL_SPILL;

/// Actual compiled-roster capacities. A caller must still charge the concrete
/// native SourceSlots layout and all simultaneously retained Review/client DATA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SourceStorage {
    pub(crate) members: usize,
    pub(crate) aliases: usize,
    pub(crate) originals: usize,
    pub(crate) file_heap: usize,
    pub(crate) alias_heap: usize,
    pub(crate) alias_original_heap: usize,
}
impl SourceStorage {
    pub(crate) fn for_roster(members: &[SourceMemberSpec], payload: &[PayloadSource]) -> Option<Self> {
        if members.is_empty() || members.len() > policy::ENTRY_LIMIT { return None; }
        let mut result = Self { members: members.len(), aliases: 0, originals: 0,
            file_heap: 0, alias_heap: 0, alias_original_heap: 0 };
        let mut files = 0usize;
        for member in members {
            if member.group == SourceGroup::FixedSupport || member.relative.len() > 512 { return None; }
            match member.kind {
                SourceKindSpec::Directory { .. } => {},
                SourceKindSpec::File { .. } => {
                    files = files.checked_add(1)?;
                    result.file_heap = result.file_heap.checked_add(member.relative.len())?.checked_add(64)?;
                },
                SourceKindSpec::Alias { target, canonical, .. } => {
                    if target.len() > 512 || canonical.len() > 512 { return None; }
                    result.aliases = result.aliases.checked_add(1)?;
                    result.alias_heap = result.alias_heap.checked_add(member.relative.len())?
                        .checked_add(target.len())?.checked_add(canonical.len())?;
                    // AliasOriginal retains another owned target, not this view.
                    result.alias_original_heap = result.alias_original_heap.checked_add(target.len())?;
                },
            }
        }
        if files > policy::FILE_COUNT || result.aliases > policy::ALIAS_COUNT { return None; }
        result.originals = members.len().checked_sub(result.aliases)?
            .checked_add(payload_original_open_plan(payload).ok()?)?.checked_add(SOURCE_ORIGINAL_SPILL)?;
        (result.originals <= SOURCE_ORIGINAL_LIMIT).then_some(result)
    }
    /// The SAME maxima must drive both actual allocation and its charge.
    pub(crate) fn maximum(self, other: Self) -> Self {
        Self { members: self.members.max(other.members), aliases: self.aliases.max(other.aliases),
            originals: self.originals.max(other.originals), file_heap: self.file_heap.max(other.file_heap),
            alias_heap: self.alias_heap.max(other.alias_heap), alias_original_heap: self.alias_original_heap.max(other.alias_original_heap) }
    }
    pub(crate) fn covers(self, actual: Self) -> bool {
        self.maximum(actual) == self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PayloadPlanFailure { Bounds, Inventory }
/// The one existing canonical-ordinal second-pass plan. Retained ancestry may
/// reduce actual opens; it may never increase this admitted original bound.
pub(crate) fn payload_original_open_plan(map: &[PayloadSource]) -> Result<usize, PayloadPlanFailure> {
    if map.is_empty() || map.len() > policy::FILE_COUNT { return Err(PayloadPlanFailure::Bounds); }
    let mut previous: Option<(SourceGroup, &str)> = None; let mut count = 0usize;
    for payload in map {
        if let PayloadOrigin::DirectOriginal(OriginalSource::Picked { group, relative }) = payload.origin {
            if group == SourceGroup::FixedSupport || !policy::relative(relative) { return Err(PayloadPlanFailure::Inventory); }
            let directory = relative.rsplit_once('/').map_or("", |(parent, _)| parent);
            let common = previous.filter(|(before, _)| *before == group).map_or(0, |(_, before)| {
                before.split('/').zip(directory.split('/')).take_while(|(a, b)| !a.is_empty() && a == b).count()
            });
            let directories = if directory.is_empty() { 0 } else { directory.split('/').count() };
            count = count.checked_add(directories.checked_sub(common).ok_or(PayloadPlanFailure::Bounds)?)
                .and_then(|count| count.checked_add(1)).ok_or(PayloadPlanFailure::Bounds)?;
            previous = Some((group, directory));
        }
    }
    if count > policy::ENTRY_LIMIT + 256 { return Err(PayloadPlanFailure::Bounds); }
    Ok(count)
}

/// FileSpec.path is SOURCE-group-relative and its mode is the observed source
/// permission bits, NOT a permission requested for the protected installation.
/// Alias fields are similarly source-group-relative lexical comparison DATA.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SourceMemberKind<'a> {
    Directory { relative: &'a str, mode: u32 },
    File(&'a FileSpec),
    Alias { data: &'a Alias, mode: u32 },
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct SourceMemberData<'a> {
    pub(crate) group: SourceGroup,
    pub(crate) kind: SourceMemberKind<'a>,
}
impl SourceMemberData<'_> {
    pub(crate) fn relative(&self) -> &str {
        match self.kind {
            SourceMemberKind::Directory { relative, .. } => relative,
            SourceMemberKind::File(file) => &file.path,
            SourceMemberKind::Alias { data, .. } => &data.path,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct SupportOriginalData<'a> {
    pub(crate) asset: SupportAsset,
    pub(crate) archive: ArchivePin<'a>,
    pub(crate) mode: u32,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct SupportMemberData<'a> {
    pub(crate) asset: SupportAsset,
    pub(crate) member: ZipMemberSpec<'a>,
}
/// Complete observed selected closures in the recipe's stable sorted order.
/// Reordering/missing/extra entries refuse. This is not proof of original
/// identity, before/after stability, original clocks, safe ACLs, joins or
/// consumed closes: the app source book retains and enforces all of those.
pub(crate) struct SourceObservations<'a> {
    pub(crate) members: &'a [SourceMemberData<'a>],
    pub(crate) support: &'a [SupportOriginalData<'a>],
    pub(crate) archive_members: &'a [SupportMemberData<'a>],
    /// Platform then build-tools. Genuine absence remains None; present bytes
    /// are complete actual observations and never become generated payload.
    pub(crate) optional_sdk_metadata: [Option<PickedSdkMetadataData<'a>>; 2],
}

#[cfg(test)]
mod storage_tests {
    use super::*;
    const HASH: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const FILE: CanonicalFile = CanonicalFile { path: "jdk/Test.jdk/Contents/release", size: 1, sha256: HASH, mode: 0o444 };
    fn picked(group: SourceGroup, relative: &'static str) -> PayloadSource {
        PayloadSource { installed: FILE, origin: PayloadOrigin::DirectOriginal(OriginalSource::Picked { group, relative }) }
    }
    const MEMBERS: &[SourceMemberSpec] = &[
        SourceMemberSpec { group: SourceGroup::Jdk, relative: "Contents", kind: SourceKindSpec::Directory { modes: &[0o755] } },
        SourceMemberSpec { group: SourceGroup::Jdk, relative: "Contents/release",
            kind: SourceKindSpec::File { bytes: 1, sha256: HASH, modes: &[0o644] } },
        SourceMemberSpec { group: SourceGroup::Jdk, relative: "Contents/release-link",
            kind: SourceKindSpec::Alias { target: "release", canonical: "Contents/release", modes: &[0o777] } },
    ];
    pub(super) fn compiled_shape_charges_all_source_strings_and_shared_maxima_data() {
        let map = [picked(SourceGroup::Jdk, "Contents/release")];
        let shape = SourceStorage::for_roster(MEMBERS, &map).unwrap();
        assert_eq!(shape, SourceStorage { members: 3, aliases: 1, originals: 2 + 2 + SOURCE_ORIGINAL_SPILL,
            file_heap: "Contents/release".len() + 64,
            alias_heap: "Contents/release-link".len() + "release".len() + "Contents/release".len(),
            alias_original_heap: "release".len() });
        let support = [PayloadSource { installed: FILE,
            origin: PayloadOrigin::DirectOriginal(OriginalSource::Support(SupportAsset::BundletoolJar)) }];
        assert_eq!(SourceStorage::for_roster(MEMBERS, &support).unwrap().originals, 2 + SOURCE_ORIGINAL_SPILL);
        let other = SourceStorage { members: 4, aliases: 0, originals: shape.originals + 1,
            file_heap: shape.file_heap + 9, alias_heap: 0, alias_original_heap: 0 };
        let maximum = shape.maximum(other);
        assert!(maximum.covers(shape) && maximum.covers(other));
        assert!(!shape.covers(other) && !other.covers(shape));
        assert_eq!(maximum.alias_heap, shape.alias_heap);
        assert_eq!(maximum.alias_original_heap, shape.alias_original_heap);
        assert_eq!(maximum.file_heap, other.file_heap);
        // A bounded accounting fixture is not a complete compiled Reference.
    }
    pub(super) fn payload_plan_preserves_frontier_and_refuses_unbounded_shapes_data() {
        let support = PayloadSource { installed: FILE,
            origin: PayloadOrigin::DirectOriginal(OriginalSource::Support(SupportAsset::BundletoolJar)) };
        let generated = PayloadSource { installed: FILE,
            origin: PayloadOrigin::CompiledSdkMetadata(SdkMetadataKind::Platform35Revision2) };
        let map = [picked(SourceGroup::Jdk, "Contents/Home/bin/java"),
            picked(SourceGroup::Jdk, "Contents/Home/bin/javac"), support,
            picked(SourceGroup::Jdk, "Contents/Home/lib/runtime.jar"),
            picked(SourceGroup::Gradle, "bin/gradle"), generated,
            picked(SourceGroup::Sdk, "platforms/android-35/android.jar")];
        assert_eq!(payload_original_open_plan(&map), Ok(4 + 1 + 2 + 2 + 3));
        assert_eq!(payload_original_open_plan(&[]), Err(PayloadPlanFailure::Bounds));
        for row in [picked(SourceGroup::FixedSupport, "member"), picked(SourceGroup::Jdk, "../member")] {
            assert_eq!(payload_original_open_plan(&[row]), Err(PayloadPlanFailure::Inventory));
        }
        let too_many = vec![support; policy::FILE_COUNT + 1];
        assert_eq!(payload_original_open_plan(&too_many), Err(PayloadPlanFailure::Bounds));
        drop(too_many);
        let frontier: Vec<_> = (0..((policy::ENTRY_LIMIT + 256) / 4 + 1)).map(|i|
            picked(if i % 2 == 0 { SourceGroup::Jdk } else { SourceGroup::Gradle }, "a/b/c/file")).collect();
        assert_eq!(payload_original_open_plan(&frontier), Err(PayloadPlanFailure::Bounds));
        let map = [picked(SourceGroup::Jdk, "Contents/release")];
        assert!(SourceStorage::for_roster(&[], &map).is_none());
        let too_many = vec![MEMBERS[0]; policy::ENTRY_LIMIT + 1];
        assert!(SourceStorage::for_roster(&too_many, &map).is_none());
        drop(too_many);
        let too_many = vec![MEMBERS[1]; policy::FILE_COUNT + 1];
        assert!(SourceStorage::for_roster(&too_many, &map).is_none());
        drop(too_many);
        let too_many = vec![MEMBERS[2]; policy::ALIAS_COUNT + 1];
        assert!(SourceStorage::for_roster(&too_many, &map).is_none());
    }
    #[test]
    fn compiled_shape_charges_all_source_strings_and_shared_maxima() {
        compiled_shape_charges_all_source_strings_and_shared_maxima_data();
    }
    #[test]
    fn payload_plan_preserves_frontier_and_refuses_unbounded_shapes() {
        payload_plan_preserves_frontier_and_refuses_unbounded_shapes_data();
    }
}
#[cfg(test)]
pub(crate) fn assert_source_storage_data_contract() {
    storage_tests::compiled_shape_charges_all_source_strings_and_shared_maxima_data();
    storage_tests::payload_plan_preserves_frontier_and_refuses_unbounded_shapes_data();
}
