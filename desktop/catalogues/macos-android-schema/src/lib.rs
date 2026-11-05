//! Immutable catalogue row schema shared by the two static data crates and application.
//! This module has no source, filesystem, native, registration or runtime authority.
use serde::Serialize;

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Component { Jdk, SdkPlatform, SdkBuildTools, Gradle, Aapt2, Bundletool }

#[derive(Clone, Copy, Serialize)]
pub enum PublishedChecksum { Sha256(&'static str), Sha1(&'static str) }

#[derive(Clone, Copy, Serialize)]
pub enum ArchiveKind {
    Directory { mode: u32 },
    File { mode: u32, bytes: u64, sha256: &'static str },
    Alias { mode: u32, target: &'static str },
}

#[derive(Clone, Copy, Serialize)]
pub enum ArchiveDisposition {
    Picked { source_index: u32 },
    /// Complete vendor-member provenance for fixed support. The separately
    /// pinned signed relation accounts for its three changed native members;
    /// installed support is never relabeled as byte-identical vendor input.
    SealedSupport(SupportAsset),
    /// Only an explicit directory wrapping the selected distribution/bundle.
    WrapperDirectory,
}

#[derive(Clone, Copy, Serialize)]
pub struct OfficialMember {
    pub name: &'static str,
    pub kind: ArchiveKind,
    pub disposition: ArchiveDisposition,
}

#[derive(Clone, Copy, Serialize)]
pub struct OfficialArchive {
    pub component: Component,
    pub official_source: &'static str,
    pub vendor_release: &'static str,
    pub archive: ArchivePin<'static>,
    pub published: PublishedChecksum,
    /// Actual archive-directory count/expansion, not a local selected-file count.
    pub member_count: u32,
    pub expanded_bytes: u64,
    pub members: &'static [OfficialMember],
}

#[derive(Clone, Copy, Serialize)]
pub enum SourceProvenance {
    Vendor { archive: u8, member: u32 },
    /// A necessary filesystem parent absent from the actual archive headers.
    /// The complete bidirectional prefix closure below binds this exact archive
    /// and prefix; neither a fictional member nor an archival mode is supplied.
    ArchiveParent { archive: u8, prefix: &'static str },
}

#[derive(Clone, Copy, Serialize)]
pub enum SourceDisposition {
    Payload(u32),
    Alias(u32),
    /// Empty source directories are explicitly observed; canonical installed
    /// directory closure is derived only from regular files/aliases.
    Directory,
}

#[derive(Clone, Copy, Serialize)]
pub struct SourceBinding {
    pub provenance: SourceProvenance,
    pub disposition: SourceDisposition,
}

#[derive(Serialize)]
pub struct CanonicalAlias {
    pub path: &'static str, pub target: &'static str, pub canonical: &'static str,
    pub source_index: u32,
}

#[derive(Clone, Copy, Serialize)]
pub struct NativeHeader {
    /// Actual archived-byte header snapshots reviewed with its complete hash.
    pub prefix: &'static [u8],
    pub commands: &'static [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum NativeResourceKind {
    Arm64,
    JdkInstalledCounterpart,
    JdkJpackageTemplate,
    OtherPlatformElf,
    OtherPlatformPe,
    GradleIntelPlatform,
    // Plain Gradle still copies this Intel resource; it is not an ARM64 JNI.
    GradlePlainJansiIntel,
    // Genuine bundletool ARM64 bypasses its Intel/Rosetta-only JNA route.
    BundletoolDarwinI386X64,
    CurrentX64,
    OtherPlatformArm64,
    OtherPlatformI386,
}

#[derive(Clone, Copy, Serialize)]
pub struct NestedNative {
    pub member: &'static str, pub bytes: u64, pub sha256: &'static str, pub mode: u32,
    pub kind: NativeResourceKind,
    // None is admitted ONLY by a complete exact compiled resource tuple below.
    // It is not a caller-selected inactive flag or a general DATA downgrade.
    pub header: Option<NativeHeader>,
}

#[derive(Serialize)]
pub enum FileClass {
    Data,
    /// An explicit reviewed textual license/notice whose vendor archive mode
    /// happens to be executable. This is not a general script downgrade.
    LicenseText,
    GradleShell,
    GradleForeignLauncher,
    AndroidTargetElf,
    SdkBash(Sdk35File),
    SdkLegacyIntel(Sdk35File, NativeHeader),
    MachO(NativeHeader),
    JvmArchive { native_members: &'static [NestedNative] },
}

#[derive(Clone, Copy, Serialize)]
pub struct VersionSpec {
    pub jdk_vendor: &'static str, pub jdk_version: &'static str,
    pub gradle_version: &'static str, pub agp_version: &'static str,
    pub sdk_platform: &'static str, pub sdk_platform_revision: &'static str,
    pub sdk_build_tools_version: &'static str,
}

#[derive(Clone, Copy, Serialize)]
pub struct RoleSpec {
    pub java: &'static str, pub javac: &'static str, pub gradle: &'static str,
    pub bundletool: &'static str, pub sdk: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum SourceGroup { Jdk, Sdk, Gradle, FixedSupport }

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum SupportAsset { BundletoolJar, Aapt2OsxJar }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ZipMethod { Stored, Deflate }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ZipMemberSpec<'a> {
    pub name: &'a str,
    pub method: ZipMethod,
    pub flags: u16,
    pub local_header_offset: u64,
    pub data_offset: u64,
    pub compressed_bytes: u64,
    pub bytes: u64,
    pub crc32: u32,
    pub sha256: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ArchivePin<'a> {
    pub bytes: u64,
    pub sha256: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum OriginalSource {
    /// Relative to the retained picked bundle/SDK/distribution root. JDK
    /// members are always bundle-relative, including HomeInSameBundle picks.
    Picked { group: SourceGroup, relative: &'static str },
    /// Closed logical asset; the installed asset owner supplies the real path.
    /// The builder neither invents that path nor adds a fourth picker.
    Support(SupportAsset),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum PayloadOrigin {
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
pub struct CanonicalFile {
    pub path: &'static str,
    pub size: u64,
    pub sha256: &'static str,
    pub mode: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PayloadSource {
    pub installed: CanonicalFile,
    pub origin: PayloadOrigin,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub enum SourceKindSpec {
    Directory { modes: &'static [u32] },
    File { bytes: u64, sha256: &'static str, modes: &'static [u32] },
    Alias { target: &'static str, canonical: &'static str, modes: &'static [u32] },
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct SourceMemberSpec {
    pub group: SourceGroup,
    pub relative: &'static str,
    pub kind: SourceKindSpec,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct SourceTree {
    pub group: SourceGroup,
    /// Empty means that entire retained root. A nonempty prefix is the exact
    /// selected SDK package subtree; never enumerate a broad SDK then truncate.
    pub prefix: &'static str,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct SupportOriginalSpec {
    pub asset: SupportAsset,
    pub archive: ArchivePin<'static>,
    pub modes: &'static [u32],
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct SupportMemberSpec {
    pub asset: SupportAsset,
    pub member: ZipMemberSpec<'static>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum SdkMetadataKind { Platform35Revision2, BuildTools35 }

pub const MAC_TOOLCHAIN_PROFILE: &str = "android-registered-macos-arm64-v1";

pub const MAC_X64_TOOLCHAIN_PROFILE: &str = "android-registered-macos-x86_64-v1";

impl SdkMetadataKind {
    pub const fn index(self) -> usize {
        match self { Self::Platform35Revision2 => 0, Self::BuildTools35 => 1 }
    }
}

pub const SDK35_ARCHIVE_BYTES: u64 = 76_857_898;
pub const SDK35_ARCHIVE_SHA: &str = "530cdbd1ec315e1477624d7ed2f0f2962108d69f36eddba5894cef9ea2cedb48";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Sdk35File { D8, Apksigner, LldShell, LldIntel, CxxIntel, CxxAbiIntel }
pub struct Sdk35Pin {
    pub kind: Sdk35File, pub path: &'static str, pub member: &'static str,
    pub bytes: u64, pub sha256: &'static str, pub original_mode: u32,
}
pub const SDK35_PINS: [Sdk35Pin; 6] = [
    Sdk35Pin { kind: Sdk35File::D8, path: "sdk/build-tools/35.0.0/d8", member: "android-15/d8",
        bytes: 2678, sha256: "b773a721be3d4988dea9660815a9e441b76100e5b0f5c72b5893cfadadc76c6f", original_mode: 0o755 },
    Sdk35Pin { kind: Sdk35File::Apksigner, path: "sdk/build-tools/35.0.0/apksigner", member: "android-15/apksigner",
        bytes: 2959, sha256: "b47549e373b895ce6ca620d0c7887e674d9615ffa837a86ac601dcfd04adb0f0", original_mode: 0o755 },
    Sdk35Pin { kind: Sdk35File::LldShell, path: "sdk/build-tools/35.0.0/lld", member: "android-15/lld",
        bytes: 647, sha256: "a4d5291a75bfa2350de74a00a3aa5099f190fd6bc86c581bb38215720884fc15", original_mode: 0o755 },
    Sdk35Pin { kind: Sdk35File::LldIntel, path: "sdk/build-tools/35.0.0/lld-bin/lld", member: "android-15/lld-bin/lld",
        bytes: 33452016, sha256: "7497b5765b30cbaf67b07de4ef631eeaab6f6a21392f2852b3ac252a44a0a250", original_mode: 0o755 },
    Sdk35Pin { kind: Sdk35File::CxxIntel, path: "sdk/build-tools/35.0.0/lib64/libc++.1.dylib", member: "android-15/lib64/libc++.1.dylib",
        bytes: 680976, sha256: "46494d6cd3737f83ddf4fcda11d69c810cd324fa0114e8110757514f8aa767c8", original_mode: 0o644 },
    Sdk35Pin { kind: Sdk35File::CxxAbiIntel, path: "sdk/build-tools/35.0.0/lib64/libc++abi.1.dylib", member: "android-15/lib64/libc++abi.1.dylib",
        bytes: 179936, sha256: "89194f2f5b98042d0e16c4948d9dad4905821749a90dd9326bb7ce509028ba66", original_mode: 0o644 },
];
impl Sdk35File {
    pub fn pin(self) -> &'static Sdk35Pin {
        &SDK35_PINS[match self { Self::D8 => 0, Self::Apksigner => 1, Self::LldShell => 2,
            Self::LldIntel => 3, Self::CxxIntel => 4, Self::CxxAbiIntel => 5 }]
    }
    pub fn script(self) -> bool { matches!(self, Self::D8 | Self::Apksigner | Self::LldShell) }
    pub fn legacy(self) -> bool { !matches!(self, Self::D8 | Self::Apksigner) }
}
impl Sdk35Pin {
    pub fn matches(&self, path: &str, bytes: u64, sha256: &str, mode: u32) -> bool {
        path == self.path && bytes == self.bytes && sha256 == self.sha256 && mode == (self.original_mode & !0o222)
    }
}

#[derive(Clone, Copy)]
pub struct CatalogueData {
    /// Fixed compiled profile only. Not a saved-project compatibility claim.
    pub profile: &'static str,
    pub observed_jdk_vendor: &'static str,
    pub observed_jdk_version: &'static str,
    pub versions: VersionSpec,
    pub roles: RoleSpec,
    pub gradle_distribution_url: &'static str,
    pub gradle_distribution_sha256: &'static str,
    pub archives: &'static [OfficialArchive],
    pub trees: &'static [SourceTree],
    pub source_members: &'static [SourceMemberSpec],
    pub source_bindings: &'static [SourceBinding],
    pub support: &'static [SupportOriginalSpec],
    pub support_members: &'static [SupportMemberSpec],
    pub payload: &'static [PayloadSource],
    pub classes: &'static [FileClass],
    pub aliases: &'static [CanonicalAlias],
    pub directories: &'static [&'static str],
}
