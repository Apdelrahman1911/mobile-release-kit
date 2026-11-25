// Compile-time storage codec only. Runtime supplier validation is unchanged.
// No Rust ABI casts, unsafe reads, allocation, filesystem input or authority.
use super::*;

const fn byte(raw: &[u8], at: usize) -> u8 { assert!(at < raw.len(), "catalogue byte range"); raw[at] }
const fn u32le(raw: &[u8], at: usize) -> u32 {
    assert!(at <= raw.len() && raw.len() - at >= 4, "catalogue integer range");
    u32::from_le_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]])
}
const fn u64le(raw: &[u8], at: usize) -> u64 {
    assert!(at <= raw.len() && raw.len() - at >= 8, "catalogue integer range");
    u64::from_le_bytes([raw[at], raw[at+1], raw[at+2], raw[at+3], raw[at+4], raw[at+5], raw[at+6], raw[at+7]])
}
const fn range(raw: &'static [u8], at: usize, count: usize) -> &'static [u8] {
    assert!(at <= raw.len() && count <= raw.len() - at, "catalogue slice range");
    raw.split_at(at).1.split_at(count).0
}
const fn magic(raw: &[u8], expected: &[u8]) {
    assert!(raw.len() >= expected.len(), "catalogue magic range");
    let mut i = 0; while i < expected.len() { assert!(raw[i] == expected[i], "catalogue magic"); i += 1; }
}
const fn stride(kind: u8) -> usize {
    match kind { 1 | 2 => 32, 3 | 7 => 16, 4 => 48, 5 => 24, 6 => 40, 8 => 4, _ => panic!("catalogue section tag") }
}
#[derive(Clone, Copy)]
pub(super) struct Tables { raw: &'static [u8], count: usize, profile: u32 }
impl Tables {
    pub(super) const fn new(raw: &'static [u8], profile: u32) -> Self {
        assert!(raw.len() <= 32 * 1024 * 1024, "catalogue records bound"); magic(raw, b"MRKTBL01");
        assert!((profile == 1 || profile == 2) && u32le(raw, 8) == profile, "catalogue records profile");
        let count = u32le(raw, 12) as usize;
        assert!(count >= 12 && count <= 128 && u32le(raw, 20) == 0, "catalogue section count");
        let mut next = 24 + count * 20;
        assert!(u32le(raw, 16) as usize == next && next <= raw.len(), "catalogue directory extent");
        let mut i = 0; let mut previous = 0u32; let mut kinds = 0u16; let mut archives = 0u8; let mut total_rows = 0usize;
        while i < count {
            let at = 24 + i * 20; let kind = byte(raw, at);
            assert!(byte(raw, at + 1) == 0, "catalogue section reserved");
            let index = u16::from_le_bytes([byte(raw, at+2), byte(raw, at+3)]) as u32;
            let key = (kind as u32) * 65536 + index;
            assert!(key > previous, "catalogue section order"); previous = key;
            assert!(u32le(raw, at + 4) as usize == stride(kind), "catalogue section stride");
            let rows = u32le(raw, at + 8) as usize;
            assert!(rows <= 32768 && (kind != 6 || rows <= 128), "catalogue section rows");
            total_rows += rows;
            assert!(total_rows <= 8 * 32768 + 128 * 128, "catalogue total rows");
            if kind == 1 { assert!(index < 6, "catalogue archive ordinal"); archives |= 1 << index; }
            else if kind != 6 { assert!(index == 0, "catalogue singleton ordinal"); }
            else { assert!(index < 32768, "catalogue nested ordinal"); }
            assert!(u32le(raw, at + 12) as usize == next, "catalogue section contiguity");
            let length = rows * stride(kind);
            assert!(u32le(raw, at + 16) as usize == length && length <= raw.len() - next, "catalogue section length");
            next += length; kinds |= 1 << kind; i += 1;
        }
        assert!(next == raw.len() && kinds == 510 && archives == 63, "catalogue complete sections");
        Self { raw, count, profile }
    }
    const fn section_raw(self, kind: u8, index: usize, rows: usize) -> &'static [u8] {
        let mut i = 0;
        while i < self.count {
            let at = 24 + i * 20;
            let found = u16::from_le_bytes([byte(self.raw, at+2), byte(self.raw, at+3)]) as usize;
            if byte(self.raw, at) == kind && found == index {
                assert!(u32le(self.raw, at+8) as usize == rows, "catalogue typed row count");
                return range(self.raw, u32le(self.raw, at+12) as usize, rows * stride(kind));
            }
            i += 1;
        }
        panic!("catalogue missing section")
    }
    pub(super) const fn section(self, kind: u8, index: usize, rows: usize) -> Section {
        Section { raw: self.section_raw(kind, index, rows), profile: self.profile, kind, index, total: rows }
    }
}
#[derive(Clone, Copy)]
pub(super) struct Strings { raw: &'static [u8], count: usize, base: usize, profile: u32 }
impl Strings {
    #[cfg(test)]
    pub(super) const fn new(raw: &'static [u8], profile: u32) -> Self {
        let shape = string_shape(raw, profile);
        let count = (shape.value.count + BLOCK_ROWS - 1) / BLOCK_ROWS;
        let mut i = 0;
        while i < count {
            let checked = check_string_chunk(shape, i);
            assert!(checked.ordinal as usize == i, "catalogue string chunk coverage");
            i += 1;
        }
        shape.value
    }
    const fn at(self, index: u32) -> &'static str {
        let i = index as usize; assert!(i < self.count, "catalogue string index");
        let a = u32le(self.raw, 16 + i * 4) as usize; let b = u32le(self.raw, 20 + i * 4) as usize;
        assert!(a <= b && b <= self.raw.len() - self.base && b - a <= 2048, "catalogue string offset");
        match std::str::from_utf8(range(self.raw, self.base + a, b - a)) { Ok(value) => value, Err(_) => panic!("catalogue UTF8") }
    }
}
const BLOCK_ROWS: usize = 32;
#[derive(Clone, Copy)]
struct StringShape { value: Strings }
#[derive(Clone, Copy)]
struct CheckedStringChunk { ordinal: u32 }
const _: () = {
    assert!(std::mem::size_of::<CheckedStringChunk>() == 4);
    assert!(std::mem::align_of::<CheckedStringChunk>() == 4);
};
const fn string_shape(raw: &'static [u8], profile: u32) -> StringShape {
    assert!(raw.len() <= 32 * 1024 * 1024, "catalogue strings bound"); magic(raw, b"MRKSTR01");
    assert!((profile == 1 || profile == 2) && u32le(raw, 8) == profile, "catalogue strings profile");
    let count = u32le(raw, 12) as usize;
    assert!(count > 0 && count <= 131072, "catalogue string count");
    let base = 16 + (count + 1) * 4;
    assert!(base <= raw.len() && u32le(raw, 16) == 0 && u32le(raw, 20) == 0, "catalogue empty string");
    assert!(u32le(raw, 16 + count * 4) as usize == raw.len() - base, "catalogue strings trailing bytes");
    StringShape { value: Strings { raw, count, base, profile } }
}
const fn check_string_chunk(shape: StringShape, ordinal: usize) -> CheckedStringChunk {
    let value = shape.value;
    let blocks = (value.count + BLOCK_ROWS - 1) / BLOCK_ROWS;
    assert!(ordinal < blocks, "catalogue string chunk ordinal");
    let start = ordinal * BLOCK_ROWS;
    let end = if value.count - start < BLOCK_ROWS { value.count } else { start + BLOCK_ROWS };
    let mut i = start;
    while i < end {
        let a = u32le(value.raw, 16 + i * 4) as usize;
        let b = u32le(value.raw, 20 + i * 4) as usize;
        assert!(a <= b && b <= value.raw.len() - value.base && b - a <= 2048, "catalogue string extent");
        let current = value.at(i as u32);
        if i > 0 {
            // at() independently bounds the predecessor before its UTF8 scan.
            let before = value.at(i as u32 - 1).as_bytes(); let after = current.as_bytes();
            let mut j = 0;
            while j < before.len() && j < after.len() && before[j] == after[j] { j += 1; }
            assert!(if j == before.len() { j < after.len() } else { j < after.len() && before[j] < after[j] }, "catalogue string order");
        }
        i += 1;
    }
    CheckedStringChunk { ordinal: ordinal as u32 }
}
const fn finish_strings(shape: StringShape, units: &[CheckedStringChunk]) -> Strings {
    assert!(units.len() == (shape.value.count + BLOCK_ROWS - 1) / BLOCK_ROWS, "catalogue string chunk count");
    let mut i = 0;
    while i < units.len() {
        assert!(units[i].ordinal as usize == i, "catalogue string chunk coverage"); i += 1;
    }
    shape.value
}
// Metadata checks bind this closed generated graph, not filesystem authority.
// Equal-tag alternate RAW objects are excluded by exact SOURCE-region bindings,
// which require the one original CAT_TABLES/CAT_STRINGS in each wrapper.
#[derive(Clone, Copy)]
pub(super) struct Section { raw: &'static [u8], profile: u32, kind: u8, index: usize, total: usize }
impl Section {
    const fn require_kind(self, kind: u8) { assert!(self.kind == kind, "catalogue chunk kind"); }
    const fn chunk(self, ordinal: usize) -> (&'static [u8], usize, usize) {
        assert!(ordinal < (self.total + BLOCK_ROWS - 1) / BLOCK_ROWS, "catalogue section chunk ordinal");
        let start = ordinal * BLOCK_ROWS;
        let length = if self.total - start < BLOCK_ROWS { self.total - start } else { BLOCK_ROWS };
        (range(self.raw, start * stride(self.kind), length * stride(self.kind)), start, length)
    }
}
pub(super) struct DecodedChunk<T> {
    values: [T; BLOCK_ROWS], profile: u32, kind: u8,
    index: usize, total: usize, start: usize, length: usize,
}
impl<T> DecodedChunk<T> {
    const fn new(section: Section, start: usize, length: usize, values: [T; BLOCK_ROWS]) -> Self {
        Self { values, profile: section.profile, kind: section.kind, index: section.index,
            total: section.total, start, length }
    }
    const fn require(&self, section: Section, start: usize) {
        assert!(self.profile == section.profile && self.kind == section.kind && self.index == section.index
            && self.total == section.total && self.start == start, "catalogue chunk identity");
        assert!(start < section.total, "catalogue chunk start");
        let remaining = section.total - start;
        let length = if remaining < BLOCK_ROWS { remaining } else { BLOCK_ROWS };
        assert!(self.length == length, "catalogue chunk length");
    }
}
const fn require_assembly(section: Section, kind: u8, rows: usize, chunks: usize) {
    section.require_kind(kind);
    assert!(section.total == rows, "catalogue assembly total");
    assert!(chunks == (rows + BLOCK_ROWS - 1) / BLOCK_ROWS, "catalogue assembly chunks");
}

const fn group(tag: u8) -> SourceGroup {
    match tag { 0 => SourceGroup::Jdk, 1 => SourceGroup::Sdk, 2 => SourceGroup::Gradle, 3 => SourceGroup::FixedSupport, _ => panic!("catalogue source group") }
}
const fn asset(tag: u8) -> SupportAsset {
    match tag { 0 => SupportAsset::BundletoolJar, 1 => SupportAsset::Aapt2OsxJar, _ => panic!("catalogue support asset") }
}
const fn native_kind(tag: u8) -> NativeResourceKind {
    match tag { 0 => NativeResourceKind::Arm64, 1 => NativeResourceKind::JdkInstalledCounterpart,
        2 => NativeResourceKind::JdkJpackageTemplate, 3 => NativeResourceKind::OtherPlatformElf,
        4 => NativeResourceKind::OtherPlatformPe, 5 => NativeResourceKind::GradleIntelPlatform,
        6 => NativeResourceKind::GradlePlainJansiIntel, 7 => NativeResourceKind::BundletoolDarwinI386X64,
        8 => NativeResourceKind::CurrentX64, 9 => NativeResourceKind::OtherPlatformArm64,
        10 => NativeResourceKind::OtherPlatformI386, _ => panic!("catalogue native kind") }
}
const fn sdk(tag: u8) -> policy::Sdk35File {
    match tag { 0 => policy::Sdk35File::D8, 1 => policy::Sdk35File::Apksigner, 2 => policy::Sdk35File::LldShell,
        3 => policy::Sdk35File::LldIntel, 4 => policy::Sdk35File::CxxIntel, 5 => policy::Sdk35File::CxxAbiIntel,
        _ => panic!("catalogue SDK kind") }
}
const fn header(raw: &'static [u8], row: &[u8], at: usize) -> NativeHeader {
    let p = u32le(row, at) as usize; let n = u32le(row, at+4) as usize;
    let c = u32le(row, at+8) as usize; let m = u32le(row, at+12) as usize;
    assert!(n > 0 && n <= 4096 && m >= 32 && m <= 16416, "catalogue header extent");
    NativeHeader { prefix: range(raw, p, n), commands: range(raw, c, m) }
}
const fn zeros(raw: &[u8], at: usize, length: usize) {
    assert!(at <= raw.len() && length <= raw.len() - at, "catalogue reserved range");
    let mut i = at; while i < at + length { assert!(raw[i] == 0, "catalogue reserved bytes"); i += 1; }
}
pub(super) const fn official_chunk(section: Section, strings: Strings, ordinal: usize) -> DecodedChunk<OfficialMember> {
    section.require_kind(1); assert!(strings.profile == section.profile, "catalogue chunk string profile");
    let (raw, start, length) = section.chunk(ordinal);
    let mut rows = [OfficialMember { name: "", kind: ArchiveKind::Directory { mode: 0 }, disposition: ArchiveDisposition::WrapperDirectory }; BLOCK_ROWS];
    let mut i = 0; while i < length {
        let at = i * 32; let mode = u32le(raw, at+8); zeros(raw, at+7, 1);
        let kind = match byte(raw, at+4) {
            0 => { zeros(raw, at+16, 16); ArchiveKind::Directory { mode } },
            1 => { zeros(raw, at+28, 4); ArchiveKind::File { mode, bytes: u64le(raw, at+16), sha256: strings.at(u32le(raw, at+24)) } },
            2 => { zeros(raw, at+16, 12); ArchiveKind::Alias { mode, target: strings.at(u32le(raw, at+28)) } },
            _ => panic!("catalogue archive kind"),
        };
        let disposition = match byte(raw, at+5) {
            0 => { zeros(raw, at+6, 1); ArchiveDisposition::Picked { source_index: u32le(raw, at+12) } },
            1 => { zeros(raw, at+12, 4); ArchiveDisposition::SealedSupport(asset(byte(raw, at+6))) },
            2 => { zeros(raw, at+6, 1); zeros(raw, at+12, 4); ArchiveDisposition::WrapperDirectory },
            _ => panic!("catalogue archive disposition"),
        };
        rows[i] = OfficialMember { name: strings.at(u32le(raw, at)), kind, disposition }; i += 1;
    } DecodedChunk::new(section, start, length, rows)
}

pub(super) const fn sources_chunk(section: Section, strings: Strings, ordinal: usize, modes: &'static [&'static [u32]]) -> DecodedChunk<SourceMemberSpec> {
    section.require_kind(2); assert!(strings.profile == section.profile, "catalogue chunk string profile");
    let (raw, start, length) = section.chunk(ordinal);
    let mut rows = [SourceMemberSpec { group: SourceGroup::Jdk, relative: "", kind: SourceKindSpec::Directory { modes: &[] } }; BLOCK_ROWS];
    let mut i = 0; while i < length {
        let at = i * 32; zeros(raw, at+2, 2); let mode_index = u32le(raw, at+28) as usize;
        assert!(mode_index < modes.len(), "catalogue mode index"); let values = modes[mode_index];
        assert!(!values.is_empty() && values.len() <= 4, "catalogue modes length");
        let mut m = 0; while m < values.len() { assert!(values[m] <= 0o777 && (m == 0 || values[m-1] < values[m]), "catalogue modes"); m += 1; }
        let kind = match byte(raw, at+1) {
            0 => { zeros(raw, at+8, 20); SourceKindSpec::Directory { modes: values } },
            1 => { zeros(raw, at+20, 8); SourceKindSpec::File { bytes: u64le(raw, at+8), sha256: strings.at(u32le(raw, at+16)), modes: values } },
            2 => { zeros(raw, at+8, 12); SourceKindSpec::Alias { target: strings.at(u32le(raw, at+20)), canonical: strings.at(u32le(raw, at+24)), modes: values } },
            _ => panic!("catalogue source kind"),
        };
        rows[i] = SourceMemberSpec { group: group(byte(raw, at)), relative: strings.at(u32le(raw, at+4)), kind }; i += 1;
    } DecodedChunk::new(section, start, length, rows)
}

pub(super) const fn bindings_chunk(section: Section, strings: Strings, ordinal: usize) -> DecodedChunk<SourceBinding> {
    section.require_kind(3); assert!(strings.profile == section.profile, "catalogue chunk string profile");
    let (raw, start, length) = section.chunk(ordinal);
    let mut rows = [SourceBinding { provenance: SourceProvenance::Vendor { archive: 0, member: 0 }, disposition: SourceDisposition::Directory }; BLOCK_ROWS];
    let mut i = 0; while i < length {
        let at = i * 16; zeros(raw, at+3, 1); let archive = byte(raw, at+1); assert!(archive < 6, "catalogue binding archive");
        let provenance = match byte(raw, at) {
            0 => { zeros(raw, at+12, 4); SourceProvenance::Vendor { archive, member: u32le(raw, at+4) } },
            1 => { zeros(raw, at+4, 4); SourceProvenance::ArchiveParent { archive, prefix: strings.at(u32le(raw, at+12)) } },
            _ => panic!("catalogue provenance"),
        };
        let disposition = match byte(raw, at+2) {
            0 => SourceDisposition::Payload(u32le(raw, at+8)), 1 => SourceDisposition::Alias(u32le(raw, at+8)),
            2 => { zeros(raw, at+8, 4); SourceDisposition::Directory }, _ => panic!("catalogue source disposition"),
        };
        rows[i] = SourceBinding { provenance, disposition }; i += 1;
    } DecodedChunk::new(section, start, length, rows)
}

pub(super) const fn payload_chunk(section: Section, strings: Strings, ordinal: usize, projected: ZipMemberSpec<'static>) -> DecodedChunk<PayloadSource> {
    section.require_kind(4); assert!(strings.profile == section.profile, "catalogue chunk string profile");
    let (raw, start, length) = section.chunk(ordinal);
    let mut rows = [PayloadSource { installed: CanonicalFile { path: "", size: 0, sha256: "", mode: 0 }, origin: PayloadOrigin::CompiledSdkMetadata(SdkMetadataKind::Platform35Revision2) }; BLOCK_ROWS];
    let mut i = 0; while i < length {
        let at = i * 48; zeros(raw, at+40, 8);
        let origin = match byte(raw, at+20) {
            0 => { zeros(raw, at+22, 2); zeros(raw, at+28, 12); PayloadOrigin::DirectOriginal(OriginalSource::Picked { group: group(byte(raw, at+21)), relative: strings.at(u32le(raw, at+24)) }) },
            1 => { zeros(raw, at+21, 1); zeros(raw, at+23, 17); PayloadOrigin::DirectOriginal(OriginalSource::Support(asset(byte(raw, at+22)))) },
            2 => { zeros(raw, at+21, 2); zeros(raw, at+24, 16); PayloadOrigin::CompiledSdkMetadata(match byte(raw, at+23) {
                0 => SdkMetadataKind::Platform35Revision2, 1 => SdkMetadataKind::BuildTools35, _ => panic!("catalogue metadata kind") }) },
            3 => { zeros(raw, at+21, 1); zeros(raw, at+23, 5); PayloadOrigin::MemberOfSameOriginalArchive { asset: asset(byte(raw, at+22)), archive: ArchivePin { bytes: u64le(raw, at+32), sha256: strings.at(u32le(raw, at+28)) }, member: projected } },
            _ => panic!("catalogue payload origin"),
        };
        rows[i] = PayloadSource { installed: CanonicalFile { path: strings.at(u32le(raw, at)), mode: u32le(raw, at+4), size: u64le(raw, at+8), sha256: strings.at(u32le(raw, at+16)) }, origin }; i += 1;
    } DecodedChunk::new(section, start, length, rows)
}

pub(super) const fn nested_chunk(section: Section, strings: Strings, ordinal: usize, headers: &'static [u8]) -> DecodedChunk<NestedNative> {
    section.require_kind(6); assert!(strings.profile == section.profile, "catalogue chunk string profile");
    let (raw, start, length) = section.chunk(ordinal);
    let mut rows = [NestedNative { member: "", bytes: 0, sha256: "", mode: 0, kind: NativeResourceKind::Arm64, header: None }; BLOCK_ROWS];
    let mut i = 0; while i < length {
        let at = i * 40; zeros(raw, at+22, 2);
        let snapshot = match byte(raw, at+21) { 0 => { zeros(raw, at+24, 16); None }, 1 => Some(header(headers, raw, at+24)), _ => panic!("catalogue optional header") };
        rows[i] = NestedNative { member: strings.at(u32le(raw, at)), mode: u32le(raw, at+4), bytes: u64le(raw, at+8),
            sha256: strings.at(u32le(raw, at+16)), kind: native_kind(byte(raw, at+20)), header: snapshot }; i += 1;
    } DecodedChunk::new(section, start, length, rows)
}

pub(super) const fn classes_chunk(section: Section, _strings: Strings, ordinal: usize, headers: &'static [u8], nested: &'static [&'static [NestedNative]]) -> DecodedChunk<FileClass> {
    section.require_kind(5); assert!(_strings.profile == section.profile, "catalogue chunk string profile");
    let (raw, start, length) = section.chunk(ordinal); let mut rows = [const { FileClass::Data }; BLOCK_ROWS];
    let mut i = 0; while i < length {
        let at = i * 24; zeros(raw, at+2, 2); let tag = byte(raw, at);
        if tag <= 4 { zeros(raw, at+1, 23); }
        rows[i] = match tag {
            0 => FileClass::Data, 1 => FileClass::LicenseText, 2 => FileClass::GradleShell,
            3 => FileClass::GradleForeignLauncher, 4 => FileClass::AndroidTargetElf,
            5 => { zeros(raw, at+4, 20); FileClass::SdkBash(sdk(byte(raw, at+1))) },
            6 => { zeros(raw, at+4, 4); FileClass::SdkLegacyIntel(sdk(byte(raw, at+1)), header(headers, raw, at+8)) },
            7 => { zeros(raw, at+1, 1); zeros(raw, at+4, 4); FileClass::MachO(header(headers, raw, at+8)) },
            8 => { zeros(raw, at+1, 1); zeros(raw, at+8, 16); let ordinal = u32le(raw, at+4) as usize;
                assert!(ordinal < nested.len(), "catalogue nested table index"); FileClass::JvmArchive { native_members: nested[ordinal] } },
            _ => panic!("catalogue file class"),
        }; i += 1;
    } DecodedChunk::new(section, start, length, rows)
}

pub(super) const fn aliases_chunk(section: Section, strings: Strings, ordinal: usize) -> DecodedChunk<CanonicalAlias> {
    section.require_kind(7); assert!(strings.profile == section.profile, "catalogue chunk string profile");
    let (raw, start, length) = section.chunk(ordinal);
    let mut rows = [const { CanonicalAlias { path: "", target: "", canonical: "", source_index: 0 } }; BLOCK_ROWS];
    let mut i = 0; while i < length { let at = i * 16;
        rows[i] = CanonicalAlias { path: strings.at(u32le(raw, at)), target: strings.at(u32le(raw, at+4)), canonical: strings.at(u32le(raw, at+8)), source_index: u32le(raw, at+12) }; i += 1;
    } DecodedChunk::new(section, start, length, rows)
}

pub(super) const fn directories_chunk(section: Section, strings: Strings, ordinal: usize) -> DecodedChunk<&'static str> {
    section.require_kind(8); assert!(strings.profile == section.profile, "catalogue chunk string profile");
    let (raw, start, length) = section.chunk(ordinal); let mut rows = [""; BLOCK_ROWS]; let mut i = 0;
    while i < length { rows[i] = strings.at(u32le(raw, i * 4)); i += 1; } DecodedChunk::new(section, start, length, rows)
}

const fn copy_class(value: &FileClass) -> FileClass {
    match value {
        FileClass::Data => FileClass::Data,
        FileClass::LicenseText => FileClass::LicenseText,
        FileClass::GradleShell => FileClass::GradleShell,
        FileClass::GradleForeignLauncher => FileClass::GradleForeignLauncher,
        FileClass::AndroidTargetElf => FileClass::AndroidTargetElf,
        FileClass::SdkBash(kind) => FileClass::SdkBash(*kind),
        FileClass::SdkLegacyIntel(kind, header) => FileClass::SdkLegacyIntel(*kind, *header),
        FileClass::MachO(header) => FileClass::MachO(*header),
        FileClass::JvmArchive { native_members } => FileClass::JvmArchive { native_members: *native_members },
    }
}
const fn copy_alias(value: &CanonicalAlias) -> CanonicalAlias {
    CanonicalAlias { path: value.path, target: value.target, canonical: value.canonical, source_index: value.source_index }
}
pub(super) const fn assemble_official<const N: usize>(section: Section, chunks: &[&DecodedChunk<OfficialMember>]) -> [OfficialMember; N] {
    require_assembly(section, 1, N, chunks.len());
    let mut rows = [OfficialMember { name: "", kind: ArchiveKind::Directory { mode: 0 }, disposition: ArchiveDisposition::WrapperDirectory }; N];
    let mut block = 0; let mut at = 0;
    while block < chunks.len() {
        let chunk = chunks[block]; chunk.require(section, at);
        let mut j = 0;
        while j < chunk.length { rows[at] = chunk.values[j]; at += 1; j += 1; }
        block += 1;
    }
    assert!(at == N, "catalogue assembly coverage"); rows
}

pub(super) const fn assemble_sources<const N: usize>(section: Section, chunks: &[&DecodedChunk<SourceMemberSpec>]) -> [SourceMemberSpec; N] {
    require_assembly(section, 2, N, chunks.len());
    let mut rows = [SourceMemberSpec { group: SourceGroup::Jdk, relative: "", kind: SourceKindSpec::Directory { modes: &[] } }; N];
    let mut block = 0; let mut at = 0;
    while block < chunks.len() {
        let chunk = chunks[block]; chunk.require(section, at);
        let mut j = 0;
        while j < chunk.length { rows[at] = chunk.values[j]; at += 1; j += 1; }
        block += 1;
    }
    assert!(at == N, "catalogue assembly coverage"); rows
}

pub(super) const fn assemble_bindings<const N: usize>(section: Section, chunks: &[&DecodedChunk<SourceBinding>]) -> [SourceBinding; N] {
    require_assembly(section, 3, N, chunks.len());
    let mut rows = [SourceBinding { provenance: SourceProvenance::Vendor { archive: 0, member: 0 }, disposition: SourceDisposition::Directory }; N];
    let mut block = 0; let mut at = 0;
    while block < chunks.len() {
        let chunk = chunks[block]; chunk.require(section, at);
        let mut j = 0;
        while j < chunk.length { rows[at] = chunk.values[j]; at += 1; j += 1; }
        block += 1;
    }
    assert!(at == N, "catalogue assembly coverage"); rows
}

pub(super) const fn assemble_payload<const N: usize>(section: Section, chunks: &[&DecodedChunk<PayloadSource>]) -> [PayloadSource; N] {
    require_assembly(section, 4, N, chunks.len());
    let mut rows = [PayloadSource { installed: CanonicalFile { path: "", size: 0, sha256: "", mode: 0 }, origin: PayloadOrigin::CompiledSdkMetadata(SdkMetadataKind::Platform35Revision2) }; N];
    let mut block = 0; let mut at = 0;
    while block < chunks.len() {
        let chunk = chunks[block]; chunk.require(section, at);
        let mut j = 0;
        while j < chunk.length { rows[at] = chunk.values[j]; at += 1; j += 1; }
        block += 1;
    }
    assert!(at == N, "catalogue assembly coverage"); rows
}

pub(super) const fn assemble_nested<const N: usize>(section: Section, chunks: &[&DecodedChunk<NestedNative>]) -> [NestedNative; N] {
    require_assembly(section, 6, N, chunks.len());
    let mut rows = [NestedNative { member: "", bytes: 0, sha256: "", mode: 0, kind: NativeResourceKind::Arm64, header: None }; N];
    let mut block = 0; let mut at = 0;
    while block < chunks.len() {
        let chunk = chunks[block]; chunk.require(section, at);
        let mut j = 0;
        while j < chunk.length { rows[at] = chunk.values[j]; at += 1; j += 1; }
        block += 1;
    }
    assert!(at == N, "catalogue assembly coverage"); rows
}

pub(super) const fn assemble_classes<const N: usize>(section: Section, chunks: &[&DecodedChunk<FileClass>]) -> [FileClass; N] {
    require_assembly(section, 5, N, chunks.len());
    let mut rows = [const { FileClass::Data }; N];
    let mut block = 0; let mut at = 0;
    while block < chunks.len() {
        let chunk = chunks[block]; chunk.require(section, at);
        let mut j = 0;
        while j < chunk.length { rows[at] = copy_class(&chunk.values[j]); at += 1; j += 1; }
        block += 1;
    }
    assert!(at == N, "catalogue assembly coverage"); rows
}

pub(super) const fn assemble_aliases<const N: usize>(section: Section, chunks: &[&DecodedChunk<CanonicalAlias>]) -> [CanonicalAlias; N] {
    require_assembly(section, 7, N, chunks.len());
    let mut rows = [const { CanonicalAlias { path: "", target: "", canonical: "", source_index: 0 } }; N];
    let mut block = 0; let mut at = 0;
    while block < chunks.len() {
        let chunk = chunks[block]; chunk.require(section, at);
        let mut j = 0;
        while j < chunk.length { rows[at] = copy_alias(&chunk.values[j]); at += 1; j += 1; }
        block += 1;
    }
    assert!(at == N, "catalogue assembly coverage"); rows
}

pub(super) const fn assemble_directories<const N: usize>(section: Section, chunks: &[&DecodedChunk<&'static str>]) -> [&'static str; N] {
    require_assembly(section, 8, N, chunks.len());
    let mut rows = [""; N];
    let mut block = 0; let mut at = 0;
    while block < chunks.len() {
        let chunk = chunks[block]; chunk.require(section, at);
        let mut j = 0;
        while j < chunk.length { rows[at] = chunk.values[j]; at += 1; j += 1; }
        block += 1;
    }
    assert!(at == N, "catalogue assembly coverage"); rows
}
// Existing tiny malformed callers use the same actual bounded decoder and assembly.
#[cfg(test)]
pub(super) const fn official<const N: usize>(tables: Tables, strings: Strings, index: usize) -> [OfficialMember; N] {
    assert!(N <= BLOCK_ROWS, "catalogue tiny test rows");
    let section = tables.section(1, index, N);
    if N == 0 { return assemble_official::<N>(section, &[]); }
    let chunk = official_chunk(section, strings, 0);
    assemble_official::<N>(section, &[&chunk])
}

#[cfg(test)]
pub(super) const fn sources<const N: usize>(tables: Tables, strings: Strings, index: usize, modes: &'static [&'static [u32]]) -> [SourceMemberSpec; N] {
    assert!(N <= BLOCK_ROWS, "catalogue tiny test rows");
    let section = tables.section(2, index, N);
    if N == 0 { return assemble_sources::<N>(section, &[]); }
    let chunk = sources_chunk(section, strings, 0, modes);
    assemble_sources::<N>(section, &[&chunk])
}

#[cfg(test)]
pub(super) const fn bindings<const N: usize>(tables: Tables, strings: Strings, index: usize) -> [SourceBinding; N] {
    assert!(N <= BLOCK_ROWS, "catalogue tiny test rows");
    let section = tables.section(3, index, N);
    if N == 0 { return assemble_bindings::<N>(section, &[]); }
    let chunk = bindings_chunk(section, strings, 0);
    assemble_bindings::<N>(section, &[&chunk])
}

#[cfg(test)]
pub(super) const fn payload<const N: usize>(tables: Tables, strings: Strings, index: usize, projected: ZipMemberSpec<'static>) -> [PayloadSource; N] {
    assert!(N <= BLOCK_ROWS, "catalogue tiny test rows");
    let section = tables.section(4, index, N);
    if N == 0 { return assemble_payload::<N>(section, &[]); }
    let chunk = payload_chunk(section, strings, 0, projected);
    assemble_payload::<N>(section, &[&chunk])
}

#[cfg(test)]
pub(super) const fn nested<const N: usize>(tables: Tables, strings: Strings, index: usize, headers: &'static [u8]) -> [NestedNative; N] {
    assert!(N <= BLOCK_ROWS, "catalogue tiny test rows");
    let section = tables.section(6, index, N);
    if N == 0 { return assemble_nested::<N>(section, &[]); }
    let chunk = nested_chunk(section, strings, 0, headers);
    assemble_nested::<N>(section, &[&chunk])
}

#[cfg(test)]
pub(super) const fn classes<const N: usize>(tables: Tables, strings: Strings, index: usize, headers: &'static [u8], nested: &'static [&'static [NestedNative]]) -> [FileClass; N] {
    assert!(N <= BLOCK_ROWS, "catalogue tiny test rows");
    let section = tables.section(5, index, N);
    if N == 0 { return assemble_classes::<N>(section, &[]); }
    let chunk = classes_chunk(section, strings, 0, headers, nested);
    assemble_classes::<N>(section, &[&chunk])
}

#[cfg(test)]
pub(super) const fn aliases<const N: usize>(tables: Tables, strings: Strings, index: usize) -> [CanonicalAlias; N] {
    assert!(N <= BLOCK_ROWS, "catalogue tiny test rows");
    let section = tables.section(7, index, N);
    if N == 0 { return assemble_aliases::<N>(section, &[]); }
    let chunk = aliases_chunk(section, strings, 0);
    assemble_aliases::<N>(section, &[&chunk])
}

#[cfg(test)]
pub(super) const fn directories<const N: usize>(tables: Tables, strings: Strings, index: usize) -> [&'static str; N] {
    assert!(N <= BLOCK_ROWS, "catalogue tiny test rows");
    let section = tables.section(8, index, N);
    if N == 0 { return assemble_directories::<N>(section, &[]); }
    let chunk = directories_chunk(section, strings, 0);
    assemble_directories::<N>(section, &[&chunk])
}

const _: () = {
    assert!(std::mem::size_of::<OfficialMember>() <= 64 && std::mem::align_of::<OfficialMember>() <= 16);
    assert!(std::mem::size_of::<DecodedChunk<OfficialMember>>() <= 32 * 64 + 64);
    assert!(std::mem::size_of::<SourceMemberSpec>() <= 128 && std::mem::align_of::<SourceMemberSpec>() <= 16);
    assert!(std::mem::size_of::<DecodedChunk<SourceMemberSpec>>() <= 32 * 128 + 64);
    assert!(std::mem::size_of::<SourceBinding>() <= 64 && std::mem::align_of::<SourceBinding>() <= 16);
    assert!(std::mem::size_of::<DecodedChunk<SourceBinding>>() <= 32 * 64 + 64);
    assert!(std::mem::size_of::<PayloadSource>() <= 256 && std::mem::align_of::<PayloadSource>() <= 16);
    assert!(std::mem::size_of::<DecodedChunk<PayloadSource>>() <= 32 * 256 + 64);
    assert!(std::mem::size_of::<FileClass>() <= 64 && std::mem::align_of::<FileClass>() <= 16);
    assert!(std::mem::size_of::<DecodedChunk<FileClass>>() <= 32 * 64 + 64);
    assert!(std::mem::size_of::<NestedNative>() <= 128 && std::mem::align_of::<NestedNative>() <= 16);
    assert!(std::mem::size_of::<DecodedChunk<NestedNative>>() <= 32 * 128 + 64);
    assert!(std::mem::size_of::<CanonicalAlias>() <= 64 && std::mem::align_of::<CanonicalAlias>() <= 16);
    assert!(std::mem::size_of::<DecodedChunk<CanonicalAlias>>() <= 32 * 64 + 64);
    assert!(std::mem::size_of::<&'static str>() <= 16 && std::mem::align_of::<&'static str>() <= 16);
    assert!(std::mem::size_of::<DecodedChunk<&'static str>>() <= 32 * 16 + 64);
    assert!(std::mem::size_of::<Section>() <= 64);
};

// Finite test hooks expose no trusted value or unchecked production constructor.
#[cfg(test)]
pub(super) fn test_string_unit(raw: &'static [u8], profile: u32, ordinal: usize) {
    let shape = string_shape(raw, profile); let _ = check_string_chunk(shape, ordinal);
}
#[cfg(test)]
pub(super) fn test_string_coverage(raw: &'static [u8], profile: u32, order: &[usize]) {
    assert!(order.len() <= 4, "catalogue finite test units");
    let shape = string_shape(raw, profile);
    let mut units = [CheckedStringChunk { ordinal: 0 }; 4];
    for (i, ordinal) in order.iter().enumerate() { units[i] = check_string_chunk(shape, *ordinal); }
    let _ = finish_strings(shape, &units[..order.len()]);
}
#[cfg(test)]
pub(super) fn test_directory_chunks(records: &'static [u8], raw_strings: &'static [u8], profile: u32, case: u8) {
    let tables = Tables::new(records, profile); let strings = Strings::new(raw_strings, profile);
    let section = tables.section(8, 0, 33);
    let mut first = directories_chunk(section, strings, 0);
    let mut tail = directories_chunk(section, strings, 1);
    match case {
        1 => { let _ = assemble_directories::<33>(section, &[&first]); return; }
        2 => { let _ = assemble_directories::<33>(section, &[&first, &first]); return; }
        3 => { let _ = assemble_directories::<33>(section, &[&tail, &first]); return; }
        4 => first.kind = 7,
        5 => tail.profile = if profile == 1 { 2 } else { 1 },
        6 => tail.index = 1,
        7 => tail.total = 34,
        8 => tail.length = 2,
        9 => tail.start = 31,
        10 => { let empty = tables.section(7, 0, 0); assert!(assemble_aliases::<0>(empty, &[]).is_empty()); return; }
        11 => { let empty = tables.section(7, 0, 0); let _ = assemble_aliases::<1>(empty, &[]); return; }
        0 => {},
        _ => panic!("catalogue unknown finite case"),
    }
    let rows = assemble_directories::<33>(section, &[&first, &tail]);
    assert_eq!(rows.len(), 33); assert_eq!(rows[0], strings.at(1)); assert_eq!(rows[32], strings.at(1));
}
#[cfg(test)]
pub(super) fn test_noncopy_chunks(classes_raw: &'static [u8], aliases_raw: &'static [u8], raw_strings: &'static [u8], profile: u32) {
    static HEADER: [u8; 64] = [0; 64];
    static EMPTY: [NestedNative; 0] = [];
    static NESTED: [&[NestedNative]; 1] = [&EMPTY];
    let strings = Strings::new(raw_strings, profile);
    let classes = Tables::new(classes_raw, profile).section(5, 0, 33);
    let first = classes_chunk(classes, strings, 0, &HEADER, &NESTED);
    let last = classes_chunk(classes, strings, 1, &HEADER, &NESTED);
    let rows = assemble_classes::<33>(classes, &[&first, &last]);
    assert!(matches!(rows[0], FileClass::Data));
    match &rows[31] { FileClass::JvmArchive { native_members } => assert!(std::ptr::eq(*native_members, &EMPTY)), _ => panic!("catalogue class tail reference") }
    match &rows[32] { FileClass::MachO(header) => { assert!(std::ptr::eq(header.prefix, &HEADER[..1])); assert!(std::ptr::eq(header.commands, &HEADER[1..33])); }, _ => panic!("catalogue class final header") }
    let aliases = Tables::new(aliases_raw, profile).section(7, 0, 33);
    let first = aliases_chunk(aliases, strings, 0); let last = aliases_chunk(aliases, strings, 1);
    let rows = assemble_aliases::<33>(aliases, &[&first, &last]);
    assert_eq!(rows[31].source_index, 31); assert_eq!(rows[32].source_index, 32);
    assert_eq!(rows[32].path, strings.at(1)); assert_eq!(rows[32].target, strings.at(2));
    assert_eq!(rows[32].canonical, strings.at(3));
}

#[cfg(test)]
pub(super) fn test_mixed_profile(records: &'static [u8], raw_strings: &'static [u8], section_profile: u32, string_profile: u32) {
    let section = Tables::new(records, section_profile).section(8, 0, 33);
    let strings = Strings::new(raw_strings, string_profile);
    let _ = directories_chunk(section, strings, 0);
}
