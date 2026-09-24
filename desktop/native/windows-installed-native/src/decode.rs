//! Bounded DATA decoding. No native calls, path reopening or ABI redeclarations.
use super::{Error, FileKind, Result, Refusal, AdmissionCheck as C, AdmissionIndex, BUFFER, MAP_UNITS, MAX_FILE_BYTES};
use std::mem::{offset_of, size_of};
use windows_sys::Wdk::Storage::FileSystem::FILE_STREAM_INFORMATION;
use windows_sys::Win32::Storage::FileSystem as FS;

// Both observed production admission and ordinary callers use these SAME decoders.
#[derive(Clone, Copy)]
pub(crate) struct Observed<'a>(Refusal<'a>);
impl<'a> Observed<'a> {
    pub(crate) fn new(trace: Refusal<'a>) -> Self { Self(trace) }
    pub(crate) fn span<'b>(self, raw: &'b [u8], offset: usize, count: usize) -> Result<&'b [u8]> {
        raw.get(offset..offset.checked_add(count).ok_or(Error::Bounds)?).ok_or_else(|| self.0.unsafe_at(C::Span))
    }
    pub(crate) fn u16_at(self, raw: &[u8], offset: usize) -> Result<u16> {
        Ok(u16::from_le_bytes(self.span(raw, offset, 2)?.try_into().map_err(|_| self.0.unsafe_at(C::Span))?))
    }
    pub(crate) fn u32_at(self, raw: &[u8], offset: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(self.span(raw, offset, 4)?.try_into().map_err(|_| self.0.unsafe_at(C::Span))?))
    }
    pub(crate) fn u64_at(self, raw: &[u8], offset: usize) -> Result<u64> {
        Ok(u64::from_le_bytes(self.span(raw, offset, 8)?.try_into().map_err(|_| self.0.unsafe_at(C::Span))?))
    }
    fn utf16(self, raw: &[u8]) -> Result<String> {
        if raw.len() % 2 != 0 { return Err(self.0.unsafe_at(C::Utf16Width)); }
        let units: Vec<u16> = raw.chunks_exact(2).map(|v| u16::from_le_bytes([v[0], v[1]])).collect();
        String::from_utf16(&units).map_err(|_| self.0.unsafe_at(C::Utf16Encoding))
    }
    pub(crate) fn terminated(self, raw: &[u8], count: Option<usize>) -> Result<String> {
        let value = self.utf16(raw)?;
        let end = value.encode_utf16().position(|c| c == 0).ok_or_else(|| self.0.unsafe_at(C::Terminator))?;
        if end == 0 || count.is_some_and(|n| n != end) { return Err(self.0.unsafe_at(C::TextLength)); }
        self.utf16(self.span(raw, 0, end * 2)?)
    }
}
pub(crate) fn span(raw: &[u8], offset: usize, count: usize) -> Result<&[u8]> { Observed::new(Refusal::none()).span(raw, offset, count) }
pub(crate) fn u16_at(raw: &[u8], offset: usize) -> Result<u16> { Observed::new(Refusal::none()).u16_at(raw, offset) }
pub(crate) fn u32_at(raw: &[u8], offset: usize) -> Result<u32> { Observed::new(Refusal::none()).u32_at(raw, offset) }
pub(crate) fn u64_at(raw: &[u8], offset: usize) -> Result<u64> { Observed::new(Refusal::none()).u64_at(raw, offset) }
pub(crate) fn terminated(raw: &[u8], count: Option<usize>) -> Result<String> { Observed::new(Refusal::none()).terminated(raw, count) }
pub(crate) fn component(value: &str) -> bool {
    if value.is_empty() || value == "." || value == ".." || value.len() > 255
        || value.encode_utf16().count() > 255 || value.ends_with('.') || value.ends_with(' ')
        || value.chars().any(|c| c < ' ' || c == '\u{7f}' || "<>:\"/\\|?*".contains(c)) { return false; }
    let stem = value.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$") { return false; }
    for prefix in ["COM", "LPT"] {
        if let Some(tail) = stem.strip_prefix(prefix) {
            if ["1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"].contains(&tail) { return false; }
        }
    }
    true
}
pub(crate) fn dos_location(value: &str) -> Result<(String, Vec<String>)> { Observed::new(Refusal::none()).dos_location(value) }
pub(crate) fn mapping(raw: &[u8]) -> Result<String> { Observed::new(Refusal::none()).mapping(raw) }
impl Observed<'_> {
    pub(crate) fn dos_location(self, value: &str) -> Result<(String, Vec<String>)> {
        let bytes = value.as_bytes();
        if bytes.len() <= 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' { return Err(self.0.unsafe_at(C::LocationDrive)); }
        let tail = value.get(3..).ok_or_else(|| self.0.unsafe_at(C::LocationDrive))?;
        let components: Vec<String> = tail.split('\\').map(str::to_owned).collect();
        if components.is_empty() || components.iter().any(|n| !component(n)) { return Err(self.0.unsafe_at(C::LocationComponents)); }
        Ok((value.get(..2).ok_or_else(|| self.0.unsafe_at(C::LocationDrive))?.to_owned(), components))
    }
    pub(crate) fn mapping(self, raw: &[u8]) -> Result<String> {
        if raw.len() < 4 || raw.len() > MAP_UNITS * 2 { return Err(self.0.unsafe_at(C::MappingSize)); }
        let value = self.utf16(raw)?;
        let parts: Vec<&str> = value.split('\0').collect();
        if parts.len() < 3 || parts[parts.len()-2..] != ["", ""]
            || parts[..parts.len()-2].iter().any(|s| s.is_empty()) { return Err(self.0.unsafe_at(C::MappingFrame)); }
        let first = parts[0];
        let digits = first.strip_prefix("\\Device\\HarddiskVolume").ok_or_else(|| self.0.unsafe_at(C::MappingDevice))?;
        if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|b| b.is_ascii_digit()) { return Err(self.0.unsafe_at(C::MappingDigits)); }
        Ok(first.to_owned()) // historical MULTI_SZ entries never become another open
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileIdentity { pub volume_serial: u64, pub file_id: [u8; 16] }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub identity: FileIdentity,
    pub kind: FileKind,
    pub attributes: u32,
    pub size: u64,
    pub allocation_size: u64,
    pub links: u32,
    pub creation: i64,
    pub write: i64,
    pub change: i64,
}
pub(crate) fn metadata(kind: FileKind, basic: &[u8], standard: &[u8], tag: &[u8], id: &[u8]) -> Result<Metadata> {
    Observed::new(Refusal::none()).metadata(kind, basic, standard, tag, id)
}
impl Observed<'_> {
fn attributes(self, value: u32) -> Result<()> {
    let unsupported = FS::FILE_ATTRIBUTE_REPARSE_POINT | FS::FILE_ATTRIBUTE_DEVICE
        | FS::FILE_ATTRIBUTE_VIRTUAL | FS::FILE_ATTRIBUTE_OFFLINE
        | FS::FILE_ATTRIBUTE_RECALL_ON_OPEN | FS::FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
    let supported = FS::FILE_ATTRIBUTE_ARCHIVE | FS::FILE_ATTRIBUTE_COMPRESSED
        | FS::FILE_ATTRIBUTE_DIRECTORY | FS::FILE_ATTRIBUTE_ENCRYPTED | FS::FILE_ATTRIBUTE_HIDDEN
        | FS::FILE_ATTRIBUTE_INTEGRITY_STREAM | FS::FILE_ATTRIBUTE_NORMAL | FS::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
        | FS::FILE_ATTRIBUTE_NO_SCRUB_DATA | FS::FILE_ATTRIBUTE_PINNED | FS::FILE_ATTRIBUTE_READONLY
        | FS::FILE_ATTRIBUTE_SPARSE_FILE | FS::FILE_ATTRIBUTE_SYSTEM | FS::FILE_ATTRIBUTE_TEMPORARY
        | FS::FILE_ATTRIBUTE_UNPINNED;
    if value & unsupported != 0 || value & !(supported | unsupported) != 0 { return Err(self.0.unsafe_at(C::Attributes)); }
    Ok(())
}
pub(crate) fn metadata(self, kind: FileKind, basic: &[u8], standard: &[u8], tag: &[u8], id: &[u8]) -> Result<Metadata> {
    self.metadata_inner(kind, basic, standard, tag, id, true)
}
pub(crate) fn system_image_metadata(self, kind: FileKind, basic: &[u8], standard: &[u8], tag: &[u8], id: &[u8]) -> Result<Metadata> {
    if kind != FileKind::File { return Err(self.0.unsafe_at(C::ObjectKind)); }
    self.metadata_inner(kind, basic, standard, tag, id, false)
}
// Separately protected provider files are not enumerated Windows OS images.
// This observation alone grants no path, ACL, loader or execution authority.
pub(crate) fn managed_webview_image_metadata(self, kind: FileKind, basic: &[u8], standard: &[u8], tag: &[u8], id: &[u8]) -> Result<Metadata> {
    if kind != FileKind::File { return Err(self.0.unsafe_at(C::ObjectKind)); }
    self.metadata_inner(kind, basic, standard, tag, id, false)
}
fn metadata_inner(self, kind: FileKind, basic: &[u8], standard: &[u8], tag: &[u8], id: &[u8], single_link: bool) -> Result<Metadata> {
    if basic.len() != size_of::<FS::FILE_BASIC_INFO>() || standard.len() != size_of::<FS::FILE_STANDARD_INFO>()
        || tag.len() != size_of::<FS::FILE_ATTRIBUTE_TAG_INFO>() || id.len() != size_of::<FS::FILE_ID_INFO>() { return Err(self.0.unsafe_at(C::MetadataSize)); }
    let attrs = self.u32_at(basic, offset_of!(FS::FILE_BASIC_INFO, FileAttributes))?;
    self.attributes(attrs)?;
    if attrs != self.u32_at(tag, offset_of!(FS::FILE_ATTRIBUTE_TAG_INFO, FileAttributes))? { return Err(self.0.unsafe_at(C::AttributeAgreement)); }
    let directory = *self.span(standard, offset_of!(FS::FILE_STANDARD_INFO, Directory), 1)?.first().ok_or_else(|| self.0.unsafe_at(C::Span))?;
    let pending = *self.span(standard, offset_of!(FS::FILE_STANDARD_INFO, DeletePending), 1)?.first().ok_or_else(|| self.0.unsafe_at(C::Span))?;
    // Read native BOOLEAN bytes, never instantiate an invalid Rust bool.
    if directory > 1 { return Err(self.0.unsafe_at(C::DirectoryBoolean)); }
    if pending != 0 { return Err(self.0.unsafe_at(C::DeletePending)); }
    if (directory != 0) != (kind == FileKind::Directory) { return Err(self.0.unsafe_at(C::ObjectKind)); }
    if (directory != 0) != (attrs & FS::FILE_ATTRIBUTE_DIRECTORY != 0) { return Err(self.0.unsafe_at(C::DirectoryAttribute)); }
    let links = self.u32_at(standard, offset_of!(FS::FILE_STANDARD_INFO, NumberOfLinks))?;
    let size = self.u64_at(standard, offset_of!(FS::FILE_STANDARD_INFO, EndOfFile))?;
    let allocation = self.u64_at(standard, offset_of!(FS::FILE_STANDARD_INFO, AllocationSize))?;
    if size > i64::MAX as u64 { return Err(self.0.unsafe_at(C::FileSize)); }
    if allocation > i64::MAX as u64 { return Err(self.0.unsafe_at(C::AllocationSize)); }
    if kind == FileKind::File {
        if links == 0 || single_link && links != 1 { return Err(self.0.unsafe_at(C::FileLinks)); }
        if size > MAX_FILE_BYTES { return Err(self.0.unsafe_at(C::FileSize)); }
    }
    let file_id: [u8; 16] = self.span(id, offset_of!(FS::FILE_ID_INFO, FileId), 16)?.try_into().map_err(|_| self.0.unsafe_at(C::Span))?;
    if file_id == [0; 16] { return Err(self.0.unsafe_at(C::FileId)); }
    Ok(Metadata { identity: FileIdentity { volume_serial: self.u64_at(id, offset_of!(FS::FILE_ID_INFO, VolumeSerialNumber))?, file_id },
        kind, attributes: attrs, size, allocation_size: allocation, links,
        creation: self.u64_at(basic, offset_of!(FS::FILE_BASIC_INFO, CreationTime))? as i64,
        write: self.u64_at(basic, offset_of!(FS::FILE_BASIC_INFO, LastWriteTime))? as i64,
        change: self.u64_at(basic, offset_of!(FS::FILE_BASIC_INFO, ChangeTime))? as i64 })
}
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry { pub name: String, pub file_id: [u8; 16], pub kind: FileKind, pub attributes: u32 }
pub(crate) fn directory(raw: &[u8]) -> Result<Vec<DirectoryEntry>> { Observed::new(Refusal::none()).directory(raw) }
// One decoder policy still supplies both observed and ordinary callers.
pub(crate) fn ancestor_directory(raw: &[u8], selected: &str) -> Result<Vec<DirectoryEntry>> {
    Observed::new(Refusal::none()).ancestor_directory(raw, selected)
}
impl Observed<'_> {
    pub(crate) fn directory(self, raw: &[u8]) -> Result<Vec<DirectoryEntry>> { self.directory_records(raw, DirectoryPolicy::Strict) }
    pub(crate) fn ancestor_directory(self, raw: &[u8], selected: &str) -> Result<Vec<DirectoryEntry>> {
        if !component(selected) { return Err(self.0.unsafe_at(C::AncestorName)); }
        self.directory_records(raw, DirectoryPolicy::Ancestor(selected))
    }
    pub(crate) fn selected_directory(self, raw: &[u8], selected: &[String]) -> Result<Vec<DirectoryEntry>> {
        super::loader::selected_names(selected)?;
        self.directory_records(raw, DirectoryPolicy::Selected(selected))
    }
}
enum DirectoryPolicy<'a> { Strict, Ancestor(&'a str), Selected(&'a [String]) }
impl DirectoryPolicy<'_> {
    fn ordinary(&self, name: &str) -> bool {
        match self {
            Self::Strict => true,
            Self::Ancestor(selected) => name == "." || name == ".." || name.eq_ignore_ascii_case(selected),
            Self::Selected(selected) => name == "." || name == ".." || selected.iter().any(|s| name.eq_ignore_ascii_case(s)),
        }
    }
}
impl Observed<'_> {
fn directory_records(self, raw: &[u8], policy: DirectoryPolicy<'_>) -> Result<Vec<DirectoryEntry>> {
    if raw.len() > BUFFER { return Err(Error::Bounds); }
    let header = offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileName);
    let mut offset = 0usize;
    let mut entries = Vec::new();
    loop {
        let d = Self(self.0.index(AdmissionIndex::Directory, entries.len()));
        if offset % 8 != 0 { return Err(d.0.unsafe_at(C::DirectoryOffset)); }
        d.span(raw, offset, header)?;
        let record = raw.get(offset..).ok_or_else(|| d.0.unsafe_at(C::Span))?;
        let next = d.u32_at(record, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, NextEntryOffset))? as usize;
        let length = d.u32_at(record, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileNameLength))? as usize;
        if length == 0 || length > 510 || length % 2 != 0 { return Err(d.0.unsafe_at(C::DirectoryNameLength)); }
        let end = header.checked_add(length).ok_or(Error::Bounds)?;
        if next != 0 && (next % 8 != 0 || next < end || offset.checked_add(next).ok_or(Error::Bounds)? >= raw.len()) { return Err(d.0.unsafe_at(C::DirectoryNext)); }
        let name = d.utf16(d.span(record, header, length)?)?;
        if name.contains('\0') || (name != "." && name != ".." && !component(&name)) { return Err(d.0.unsafe_at(C::DirectoryName)); }
        let attrs = d.u32_at(record, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileAttributes))?;
        if policy.ordinary(&name) { d.attributes(attrs)?; }
        let kind = if attrs & FS::FILE_ATTRIBUTE_DIRECTORY != 0 { FileKind::Directory } else { FileKind::File };
        if (name == "." || name == "..") && kind != FileKind::Directory { return Err(d.0.unsafe_at(C::DirectoryDot)); }
        let file_id = d.span(record, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileId), 16)?.try_into().map_err(|_| d.0.unsafe_at(C::Span))?;
        if file_id == [0; 16] { return Err(d.0.unsafe_at(C::FileId)); }
        // FileIndex and non-reparse ReparsePointTag are deliberately not used.
        entries.push(DirectoryEntry { name, file_id, kind, attributes: attrs });
        if next == 0 { return Ok(entries); }
        offset = offset.checked_add(next).ok_or(Error::Bounds)?;
    }
}
}
pub(crate) fn streams(raw: &[u8], kind: FileKind) -> Result<()> { Observed::new(Refusal::none()).streams(raw, kind) }
impl Observed<'_> {
pub(crate) fn streams(self, raw: &[u8], kind: FileKind) -> Result<()> {
    if raw.len() > BUFFER { return Err(Error::Bounds); }
    if raw.is_empty() { return if kind == FileKind::Directory { Ok(()) } else { Err(self.0.unsafe_at(C::StreamMissing)) }; }
    let header = offset_of!(FILE_STREAM_INFORMATION, StreamName);
    self.span(raw, 0, header)?;
    let next = self.u32_at(raw, offset_of!(FILE_STREAM_INFORMATION, NextEntryOffset))?;
    let length = self.u32_at(raw, offset_of!(FILE_STREAM_INFORMATION, StreamNameLength))? as usize;
    if next != 0 || length == 0 || length % 2 != 0 { return Err(self.0.unsafe_at(C::StreamFrame)); }
    if self.utf16(self.span(raw, header, length)?)? != "::$DATA" { return Err(self.0.unsafe_at(C::StreamName)); }
    if self.u64_at(raw, offset_of!(FILE_STREAM_INFORMATION, StreamSize))? > i64::MAX as u64 { return Err(self.0.unsafe_at(C::StreamSize)); }
    if self.u64_at(raw, offset_of!(FILE_STREAM_INFORMATION, StreamAllocationSize))? > i64::MAX as u64 { return Err(self.0.unsafe_at(C::StreamAllocation)); }
    // There may be alignment padding after the one complete record. A second
    // record or any named stream is never accepted as ordinary unnamed data.
    if raw.len() > ((header + length + 7) & !7) { return Err(self.0.unsafe_at(C::StreamPadding)); }
    Ok(())
}
}
