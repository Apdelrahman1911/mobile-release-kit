//! Comparison DATA shared by the private macOS Android supplier builder and
//! the original app source book. Nothing here owns or opens a path/descriptor,
//! acknowledges a license, selects a renderer supplier, or attests finality.
use crate::android_toolchain_macos_policy::{Alias, FileSpec};
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
