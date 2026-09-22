//! Bounded DATA decoding. No native calls, path reopening or ABI redeclarations.
use super::{Error, FileKind, Result, BUFFER, MAP_UNITS, MAX_FILE_BYTES};
use std::mem::{offset_of, size_of};
use windows_sys::Wdk::Storage::FileSystem::FILE_STREAM_INFORMATION;
use windows_sys::Win32::Storage::FileSystem as FS;

pub(crate) fn span(raw: &[u8], offset: usize, count: usize) -> Result<&[u8]> {
    raw.get(offset..offset.checked_add(count).ok_or(Error::Bounds)?).ok_or(Error::Unsafe)
}
pub(crate) fn u16_at(raw: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(span(raw, offset, 2)?.try_into().map_err(|_| Error::Unsafe)?))
}
pub(crate) fn u32_at(raw: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(span(raw, offset, 4)?.try_into().map_err(|_| Error::Unsafe)?))
}
pub(crate) fn u64_at(raw: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(span(raw, offset, 8)?.try_into().map_err(|_| Error::Unsafe)?))
}
fn utf16(raw: &[u8]) -> Result<String> {
    if raw.len() % 2 != 0 { return Err(Error::Unsafe); }
    let units: Vec<u16> = raw.chunks_exact(2).map(|v| u16::from_le_bytes([v[0], v[1]])).collect();
    String::from_utf16(&units).map_err(|_| Error::Unsafe)
}
pub(crate) fn terminated(raw: &[u8], count: Option<usize>) -> Result<String> {
    let value = utf16(raw)?;
    let end = value.encode_utf16().position(|c| c == 0).ok_or(Error::Unsafe)?;
    if end == 0 || count.is_some_and(|n| n != end) { return Err(Error::Unsafe); }
    utf16(span(raw, 0, end * 2)?)
}
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
pub(crate) fn dos_location(value: &str) -> Result<(String, Vec<String>)> {
    let bytes = value.as_bytes();
    if bytes.len() <= 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' { return Err(Error::Unsafe); }
    let tail = value.get(3..).ok_or(Error::Unsafe)?;
    let components: Vec<String> = tail.split('\\').map(str::to_owned).collect();
    if components.is_empty() || components.iter().any(|n| !component(n)) { return Err(Error::Unsafe); }
    Ok((value.get(..2).ok_or(Error::Unsafe)?.to_owned(), components))
}
pub(crate) fn mapping(raw: &[u8]) -> Result<String> {
    if raw.len() < 4 || raw.len() > MAP_UNITS * 2 { return Err(Error::Unsafe); }
    let value = utf16(raw)?;
    let parts: Vec<&str> = value.split('\0').collect();
    if parts.len() < 3 || parts[parts.len()-2..] != ["", ""]
        || parts[..parts.len()-2].iter().any(|s| s.is_empty()) { return Err(Error::Unsafe); }
    let first = parts[0];
    let digits = first.strip_prefix("\\Device\\HarddiskVolume").ok_or(Error::Unsafe)?;
    if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|b| b.is_ascii_digit()) { return Err(Error::Unsafe); }
    Ok(first.to_owned()) // historical MULTI_SZ entries never become another open
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
fn attributes(value: u32) -> Result<()> {
    let unsupported = FS::FILE_ATTRIBUTE_REPARSE_POINT | FS::FILE_ATTRIBUTE_DEVICE
        | FS::FILE_ATTRIBUTE_VIRTUAL | FS::FILE_ATTRIBUTE_OFFLINE
        | FS::FILE_ATTRIBUTE_RECALL_ON_OPEN | FS::FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
    let supported = FS::FILE_ATTRIBUTE_ARCHIVE | FS::FILE_ATTRIBUTE_COMPRESSED
        | FS::FILE_ATTRIBUTE_DIRECTORY | FS::FILE_ATTRIBUTE_ENCRYPTED | FS::FILE_ATTRIBUTE_HIDDEN
        | FS::FILE_ATTRIBUTE_INTEGRITY_STREAM | FS::FILE_ATTRIBUTE_NORMAL | FS::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
        | FS::FILE_ATTRIBUTE_NO_SCRUB_DATA | FS::FILE_ATTRIBUTE_PINNED | FS::FILE_ATTRIBUTE_READONLY
        | FS::FILE_ATTRIBUTE_SPARSE_FILE | FS::FILE_ATTRIBUTE_SYSTEM | FS::FILE_ATTRIBUTE_TEMPORARY
        | FS::FILE_ATTRIBUTE_UNPINNED;
    if value & unsupported != 0 || value & !(supported | unsupported) != 0 { return Err(Error::Unsafe); }
    Ok(())
}
pub(crate) fn metadata(kind: FileKind, basic: &[u8], standard: &[u8], tag: &[u8], id: &[u8]) -> Result<Metadata> {
    if basic.len() != size_of::<FS::FILE_BASIC_INFO>() || standard.len() != size_of::<FS::FILE_STANDARD_INFO>()
        || tag.len() != size_of::<FS::FILE_ATTRIBUTE_TAG_INFO>() || id.len() != size_of::<FS::FILE_ID_INFO>() { return Err(Error::Unsafe); }
    let attrs = u32_at(basic, offset_of!(FS::FILE_BASIC_INFO, FileAttributes))?;
    attributes(attrs)?;
    if attrs != u32_at(tag, offset_of!(FS::FILE_ATTRIBUTE_TAG_INFO, FileAttributes))? { return Err(Error::Unsafe); }
    let directory = *span(standard, offset_of!(FS::FILE_STANDARD_INFO, Directory), 1)?.first().ok_or(Error::Unsafe)?;
    let pending = *span(standard, offset_of!(FS::FILE_STANDARD_INFO, DeletePending), 1)?.first().ok_or(Error::Unsafe)?;
    // Read native BOOLEAN bytes, never instantiate an invalid Rust bool.
    if directory > 1 || pending != 0 || (directory != 0) != (kind == FileKind::Directory)
        || (directory != 0) != (attrs & FS::FILE_ATTRIBUTE_DIRECTORY != 0) { return Err(Error::Unsafe); }
    let links = u32_at(standard, offset_of!(FS::FILE_STANDARD_INFO, NumberOfLinks))?;
    let size = u64_at(standard, offset_of!(FS::FILE_STANDARD_INFO, EndOfFile))?;
    let allocation = u64_at(standard, offset_of!(FS::FILE_STANDARD_INFO, AllocationSize))?;
    if size > i64::MAX as u64 || allocation > i64::MAX as u64 || (kind == FileKind::File && (links != 1 || size > MAX_FILE_BYTES)) { return Err(Error::Unsafe); }
    let file_id: [u8; 16] = span(id, offset_of!(FS::FILE_ID_INFO, FileId), 16)?.try_into().map_err(|_| Error::Unsafe)?;
    if file_id == [0; 16] { return Err(Error::Unsafe); }
    Ok(Metadata { identity: FileIdentity { volume_serial: u64_at(id, offset_of!(FS::FILE_ID_INFO, VolumeSerialNumber))?, file_id },
        kind, attributes: attrs, size, allocation_size: allocation, links,
        creation: u64_at(basic, offset_of!(FS::FILE_BASIC_INFO, CreationTime))? as i64,
        write: u64_at(basic, offset_of!(FS::FILE_BASIC_INFO, LastWriteTime))? as i64,
        change: u64_at(basic, offset_of!(FS::FILE_BASIC_INFO, ChangeTime))? as i64 })
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry { pub name: String, pub file_id: [u8; 16], pub kind: FileKind, pub attributes: u32 }
pub(crate) fn directory(raw: &[u8]) -> Result<Vec<DirectoryEntry>> {
    directory_records(raw, DirectoryPolicy::Strict)
}
// A separate DATA decoder avoids letting a blanket permissive flag leak into
// immutable inventory. Framing/names/full IDs stay checked for every sibling.
pub(crate) fn ancestor_directory(raw: &[u8], selected: &str) -> Result<Vec<DirectoryEntry>> {
    if !component(selected) { return Err(Error::Unsafe); }
    directory_records(raw, DirectoryPolicy::Ancestor(selected))
}
enum DirectoryPolicy<'a> { Strict, Ancestor(&'a str) }
impl DirectoryPolicy<'_> {
    fn ordinary(&self, name: &str) -> bool {
        match self {
            Self::Strict => true,
            Self::Ancestor(selected) => name == "." || name == ".." || name.eq_ignore_ascii_case(selected),
        }
    }
}
fn directory_records(raw: &[u8], policy: DirectoryPolicy<'_>) -> Result<Vec<DirectoryEntry>> {
    if raw.len() > BUFFER { return Err(Error::Bounds); }
    let header = offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileName);
    let mut offset = 0usize;
    let mut entries = Vec::new();
    loop {
        if offset % 8 != 0 { return Err(Error::Unsafe); }
        span(raw, offset, header)?;
        let record = raw.get(offset..).ok_or(Error::Unsafe)?;
        let next = u32_at(record, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, NextEntryOffset))? as usize;
        let length = u32_at(record, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileNameLength))? as usize;
        if length == 0 || length > 510 || length % 2 != 0 { return Err(Error::Unsafe); }
        let end = header.checked_add(length).ok_or(Error::Bounds)?;
        if next != 0 && (next % 8 != 0 || next < end || offset.checked_add(next).ok_or(Error::Bounds)? >= raw.len()) { return Err(Error::Unsafe); }
        let name = utf16(span(record, header, length)?)?;
        if name.contains('\0') || (name != "." && name != ".." && !component(&name)) { return Err(Error::Unsafe); }
        let attrs = u32_at(record, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileAttributes))?;
        if policy.ordinary(&name) { attributes(attrs)?; }
        let kind = if attrs & FS::FILE_ATTRIBUTE_DIRECTORY != 0 { FileKind::Directory } else { FileKind::File };
        if (name == "." || name == "..") && kind != FileKind::Directory { return Err(Error::Unsafe); }
        let file_id = span(record, offset_of!(FS::FILE_ID_EXTD_DIR_INFO, FileId), 16)?.try_into().map_err(|_| Error::Unsafe)?;
        if file_id == [0; 16] { return Err(Error::Unsafe); }
        // FileIndex and non-reparse ReparsePointTag are deliberately not used.
        entries.push(DirectoryEntry { name, file_id, kind, attributes: attrs });
        if next == 0 { return Ok(entries); }
        offset = offset.checked_add(next).ok_or(Error::Bounds)?;
    }
}
pub(crate) fn streams(raw: &[u8], kind: FileKind) -> Result<()> {
    if raw.len() > BUFFER { return Err(Error::Bounds); }
    if raw.is_empty() { return if kind == FileKind::Directory { Ok(()) } else { Err(Error::Unsafe) }; }
    let header = offset_of!(FILE_STREAM_INFORMATION, StreamName);
    span(raw, 0, header)?;
    let next = u32_at(raw, offset_of!(FILE_STREAM_INFORMATION, NextEntryOffset))?;
    let length = u32_at(raw, offset_of!(FILE_STREAM_INFORMATION, StreamNameLength))? as usize;
    if next != 0 || length == 0 || length % 2 != 0 { return Err(Error::Unsafe); }
    if utf16(span(raw, header, length)?)? != "::$DATA"
        || u64_at(raw, offset_of!(FILE_STREAM_INFORMATION, StreamSize))? > i64::MAX as u64
        || u64_at(raw, offset_of!(FILE_STREAM_INFORMATION, StreamAllocationSize))? > i64::MAX as u64 { return Err(Error::Unsafe); }
    // There may be alignment padding after the one complete record. A second
    // record or any named stream is never accepted as ordinary unnamed data.
    if raw.len() > ((header + length + 7) & !7) { return Err(Error::Unsafe); }
    Ok(())
}
