//! The two fixed installed Android DATA archives. Nested in the installed
//! runtime module so this uses its SAME private Book/protected-app proof.
//! No fourth picker, extracted executable, cwd search or vendor execution.
//! The containing source original retains this entire slot across worker loss.
#![forbid(unsafe_code)]
use super::*;
use crate::android_supplier_macos::Recipe;
use crate::android_supplier_macos_source::{
    ArchivePin, SupportAsset, SupportOriginalData, SupportMemberData, ZipMemberSpec, ZipMethod,
};
use miniz_oxide::{DataFormat, MZFlush, MZStatus, inflate::stream::{InflateState, inflate}};
use std::mem::size_of;

const ZIP_ENTRIES: usize = 32768;
const ZIP_NAME: usize = 512;
const BLOCK: usize = 65536;
const ZIP_TAIL: usize = 65535 + 22;
const SUPPORT_RECORDS: usize = 32;
const FILE_BYTES: u64 = 512 * 1024 * 1024;
type Sink<'a> = dyn FnMut(&[u8]) -> Result<()> + 'a;

fn asset_index(asset: SupportAsset) -> usize {
    match asset { SupportAsset::BundletoolJar => 0, SupportAsset::Aapt2OsxJar => 1 }
}
fn asset_leaf(asset: SupportAsset) -> &'static str {
    match asset {
        SupportAsset::BundletoolJar => "bundletool-all-1.18.3.jar",
        SupportAsset::Aapt2OsxJar => "aapt2-8.9.2-12782657-osx.jar",
    }
}
#[derive(Clone, PartialEq, Eq)]
struct ArchiveObservation { asset: SupportAsset, identity: Identity, bytes: u64, sha256: String, mode: u32 }
/// Comparison DATA only. Construction requires this operation's actual whole
/// archive reads and same-original selected member projection; never a path FD.
#[derive(PartialEq, Eq)]
pub(crate) struct FixedSupportReview {
    installation: Vec<Identity>, archives: [ArchiveObservation; 2],
    member: ZipMemberSpec<'static>,
}
impl FixedSupportReview {
    pub(crate) fn observations(&self) -> ([SupportOriginalData<'_>; 2], [SupportMemberData<'_>; 1]) {
        let archives = std::array::from_fn(|index| {
            let data = &self.archives[index];
            SupportOriginalData { asset: data.asset, mode: data.mode,
                archive: ArchivePin { bytes: data.bytes, sha256: &data.sha256 } }
        });
        (archives, [SupportMemberData { asset: SupportAsset::Aapt2OsxJar, member: self.member }])
    }
    pub(crate) fn logical_bytes(&self) -> Option<u64> {
        self.archives[0].bytes.checked_add(self.archives[1].bytes)?.checked_add(self.member.bytes)
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        self.archives.iter().try_fold(size_of::<Self>()
            .checked_add(self.installation.capacity().checked_mul(size_of::<Identity>())?)?,
            |sum, archive| sum.checked_add(archive.sha256.capacity()))
    }
}
#[derive(Clone, Copy)]
struct Span { first: u64, end: u64 }
struct Scratch {
    input: [u8; BLOCK], output: [u8; BLOCK], tail: [u8; ZIP_TAIL],
    name: [u8; ZIP_NAME], local_name: [u8; ZIP_NAME], extra: [u8; 65535],
    inflate: Box<InflateState>,
}
impl Scratch {
    fn new() -> Self {
        Self { input: [0; BLOCK], output: [0; BLOCK], tail: [0; ZIP_TAIL],
            name: [0; ZIP_NAME], local_name: [0; ZIP_NAME], extra: [0; 65535],
            inflate: InflateState::new_boxed(DataFormat::Raw) }
    }
}
pub(crate) struct FixedSupportSlots {
    original: Book, indexes: [Option<usize>; 2], review: Option<FixedSupportReview>,
    scratch: Scratch, names: Vec<[u8; 32]>, spans: Vec<Span>,
    inspected: bool, settled: bool, projected: bool,
    frozen: Option<(bool, Option<(AdmissionFailure, Instant)>)>,
}
impl FixedSupportSlots {
    /// Pure typed allocation only; no installed path/native frame/CRC CPU probe.
    pub(crate) fn new() -> Self {
        Self { original: Book::new(), indexes: [None; 2], review: None,
            scratch: Scratch::new(), names: Vec::new(), spans: Vec::new(),
            inspected: false, settled: false, projected: false, frozen: None }
    }
    pub(crate) fn new_registered(gate:Option<crate::saved_command_owner::AndroidRegistrationWorkGate>)->Self{
        let mut original=Self::new();original.original.registration_gate=gate;original
    }
    /// Checked additive app-owned high-water row, NOT an opaque SnapshotBook
    /// allocation bound. Caller separately needs genuine native admission.
    pub(crate) fn working_reservation_bytes() -> Option<usize> {
        size_of::<Self>().checked_add(size_of::<InflateState>())?
            .checked_add(ZIP_ENTRIES.checked_mul(size_of::<[u8; 32]>() + size_of::<Span>())?)?
            // The existing Book reserves its existing8256 record cells.
            .checked_add(8256usize.checked_mul(size_of::<Record>())?)?
            .checked_add(SUPPORT_RECORDS.checked_mul(255 + size_of::<Identity>())?)?
            .checked_add(size_of::<FixedSupportReview>() + 2 * 64)?
            .checked_add(2 * size_of::<crc32fast::Hasher>() + 3 * size_of::<Sha256>())?
            // Existing Book::read uses its own inline block while ours persists.
            .checked_add(BLOCK + 256)
    }
    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        let original = if let Some((known, _)) = self.frozen {
            if !known { return None; }
            // Frozen source-worker outcome: do not re-enter the retired Book.
            self.original.records.iter().try_fold(
                self.original.records.capacity().checked_mul(size_of::<Record>())?,
                |sum, record| sum.checked_add(record.name.capacity()))?
        } else { self.original.retained_heap_bytes()? };
        size_of::<Self>().checked_add(size_of::<InflateState>())?
            .checked_add(original)?
            .checked_add(self.names.capacity().checked_mul(size_of::<[u8; 32]>())?)?
            .checked_add(self.spans.capacity().checked_mul(size_of::<Span>())?)?
            .checked_add(self.review.as_ref().map_or(Some(0), FixedSupportReview::retained_bytes)?)
    }
    pub(crate) fn first_failure(&self) -> Option<(AdmissionFailure, Instant)> {
        self.frozen.map_or_else(|| self.original.first_failure(), |(_, first)| first)
    }
    fn fail<T>(&self, result: Result<T>) -> Result<T> {
        if let Err(failure) = result.as_ref() { self.original.note_acl(*failure, Instant::now()); }
        result
    }
    pub(crate) fn inspect_once(&mut self, recipe: &Recipe, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        let result = self.inspect_inner(recipe, end, stop);
        self.fail(result)
    }
    fn inspect_inner(&mut self, recipe: &Recipe, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        if self.inspected || self.settled || !self.original.never_started() { return Err(AdmissionFailure::AlreadyUsed); }
        let roster = recipe.source_roster();
        if roster.support.len() != 2 || roster.archive_members.len() != 1
            || roster.support[0].asset != SupportAsset::BundletoolJar
            || roster.support[1].asset != SupportAsset::Aapt2OsxJar
            || roster.archive_members[0].asset != SupportAsset::Aapt2OsxJar { return Err(AdmissionFailure::Inventory); }
        self.names.try_reserve_exact(ZIP_ENTRIES).map_err(native_error)?;
        self.spans.try_reserve_exact(ZIP_ENTRIES).map_err(native_error)?;
        if self.names.capacity() != ZIP_ENTRIES || self.spans.capacity() != ZIP_ENTRIES { return Err(AdmissionFailure::Bounds); }
        self.original.arm_acl_once(end, stop)?;
        // Exactly the runtime's existing protected installed-app proof. The
        // returned index is its SAME retained Contents edge, not Resources DATA.
        let contents = self.original.protected_app_once(end, stop)?;
        let resources = self.original.open(Some(contents), "Resources", true, end, stop)?;
        let support = self.original.open(Some(resources), "android-support", true, end, stop)?;
        for index in [resources, support] {
            let id = self.original.records[index].identity.ok_or(AdmissionFailure::Identity)?;
            if id.gid != 0 || id.mode & 0o7777 != 0o555 { return Err(AdmissionFailure::Ownership); }
            native::no_xattrs(self.original.fd(index)?.as_fd()).map_err(native_error)?;
        }
        let mut observations: [Option<ArchiveObservation>; 2] = [None, None];
        for spec in roster.support {
            self.original.point(end, stop)?;
            if spec.archive.bytes == 0 || spec.archive.bytes > FILE_BYTES || !sha(spec.archive.sha256) {
                return Err(AdmissionFailure::Bounds);
            }
            let index = self.original.open(Some(support), asset_leaf(spec.asset), false, end, stop)?;
            self.indexes[asset_index(spec.asset)] = Some(index);
            let id = self.original.records[index].identity.ok_or(AdmissionFailure::Identity)?;
            let mode = u32::from(id.mode & 0o7777);
            if id.gid != 0 || mode != 0o444 || !spec.modes.contains(&mode) { return Err(AdmissionFailure::Ownership); }
            let (hash, ignored) = self.original.read(index, spec.archive.bytes, false, end, stop)?;
            if !ignored.is_empty() || hash != spec.archive.sha256 { return Err(AdmissionFailure::Inventory); }
            observations[asset_index(spec.asset)] = Some(ArchiveObservation {
                asset: spec.asset, identity: id, bytes: spec.archive.bytes, sha256: hash, mode,
            });
        }
        let member = roster.archive_members[0].member;
        let archive = roster.support[1].archive;
        let index = self.indexes[1].ok_or(AdmissionFailure::Unknown)?;
        self.zip_member(index, archive, member, end, stop)?;
        self.project(index, member, end, stop, &mut |_| Ok(()))?;
        self.projected = true;
        self.recheck(end, stop)?;
        if self.original.records.len() > SUPPORT_RECORDS { return Err(AdmissionFailure::Bounds); }
        let mut installation = Vec::new();
        installation.try_reserve_exact(self.original.records.len()).map_err(native_error)?;
        if installation.capacity() != self.original.records.len() { return Err(AdmissionFailure::Bounds); }
        for record in &self.original.records {
            installation.push(record.identity.ok_or(AdmissionFailure::Identity)?);
        }
        let [first, second] = observations;
        self.review = Some(FixedSupportReview { installation,
            archives: [first.ok_or(AdmissionFailure::Unknown)?, second.ok_or(AdmissionFailure::Unknown)?], member });
        self.inspected = true;
        Ok(())
    }
    fn recheck(&self, end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        for (index, record) in self.original.records.iter().enumerate() {
            if record.state == State::Owned { self.original.check_name(index, end, stop)?; }
        }
        self.original.point(end, stop)
    }
    pub(crate) fn review(&self) -> Result<&FixedSupportReview> {
        if !self.inspected || !self.projected { return Err(AdmissionFailure::Inventory); }
        self.review.as_ref().ok_or(AdmissionFailure::Unknown)
    }
    /// Called only by the original source worker. Payload framing/consent remains
    /// in its caller; these borrowed chunks grant no helper filesystem access.
    pub(crate) fn stream(&mut self, asset: SupportAsset, member: Option<ZipMemberSpec<'static>>,
        end: Instant, stop: &watch::Receiver<bool>, sink: &mut Sink<'_>) -> Result<()> {
        let result = (|| {
            if self.settled || !self.inspected { return Err(AdmissionFailure::AlreadyUsed); }
            let expected = self.review()?;
            let index = self.indexes[asset_index(asset)].ok_or(AdmissionFailure::Unknown)?;
            self.original.check_name(index, end, stop)?;
            if self.original.records[index].identity != Some(expected.archives[asset_index(asset)].identity) {
                return Err(AdmissionFailure::Identity);
            }
            match (asset, member) {
                (SupportAsset::BundletoolJar, None) => {
                    let size = expected.archives[0].bytes;
                    let expected_hash = expected.archives[0].sha256.clone();
                    let mut at = 0u64; let mut hash = Sha256::new();
                    while at < size {
                        let take = usize::try_from((size - at).min(BLOCK as u64)).map_err(native_error)?;
                        read_at(&self.original, index, at, &mut self.scratch.output[..take], end, stop)?;
                        hash.update(&self.scratch.output[..take]); sink(&self.scratch.output[..take])?;
                        at = at.checked_add(take as u64).ok_or(AdmissionFailure::Bounds)?;
                    }
                    if hex_digest(hash) != expected_hash { return Err(AdmissionFailure::Inventory); }
                },
                (SupportAsset::Aapt2OsxJar, Some(member)) if member == expected.member => {
                    self.project(index, member, end, stop, sink)?;
                },
                _ => return Err(AdmissionFailure::Inventory),
            }
            self.original.check_name(index, end, stop)
        })();
        self.fail(result)
    }
    /// First-F is published by the caller around each original close. A stop
    /// never suppresses separately admissible sibling cleanup, or causes retry.
    pub(crate) fn settle_originals(&mut self,
        expired: &mut dyn FnMut(Option<(AdmissionFailure, Instant)>) -> bool) -> CloseOutcome {
        if self.settled { return CloseOutcome::Unknown; }
        self.settled = true;
        let mut first = self.original.first_failure();
        let outcome = self.original.settle(&mut |failure| {
            first = earliest_failure(first, failure); expired(first)
        });
        let known = outcome == CloseOutcome::Settled;
        if !known { first = earliest_failure(first, Some((AdmissionFailure::Unknown, Instant::now()))); }
        self.frozen = Some((known, first));
        outcome
    }
    /// Frozen DATA only after the source worker consumed the actual close tail.
    pub(crate) fn settled(&self) -> bool { self.frozen.is_some_and(|(known, _)| known) }
    pub(crate) fn take_review(&mut self) -> Result<FixedSupportReview> {
        if !self.settled() || self.first_failure().is_some() || !self.inspected || !self.projected {
            return Err(AdmissionFailure::Unknown);
        }
        self.review.take().ok_or(AdmissionFailure::AlreadyUsed)
    }

    fn zip_member(&mut self, index: usize, archive: ArchivePin<'_>, selected: ZipMemberSpec<'static>,
        end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
        let count = usize::try_from(archive.bytes.min(ZIP_TAIL as u64)).map_err(native_error)?;
        if count < 22 { return Err(AdmissionFailure::Inventory); }
        let tail_at = archive.bytes - count as u64;
        read_at(&self.original, index, tail_at, &mut self.scratch.tail[..count], end, stop)?;
        let mut found = None;
        for at in (0..=count - 22).rev() {
            let tail = &self.scratch.tail;
            if &tail[at..at + 4] == b"PK\x05\x06"
                && at + 22 + le16(tail, at + 20)? as usize == count {
                if found.replace(at).is_some() { return Err(AdmissionFailure::Inventory); }
            }
        }
        let at = found.ok_or(AdmissionFailure::Inventory)?;
        let tail = &self.scratch.tail;
        let entries = usize::from(le16(tail, at + 10)?);
        let directory_bytes = u64::from(le32(tail, at + 12)?);
        let directory_at = u64::from(le32(tail, at + 16)?);
        if le16(tail, at + 4)? != 0 || le16(tail, at + 6)? != 0
            || usize::from(le16(tail, at + 8)?) != entries || entries == 0 || entries > ZIP_ENTRIES
            || directory_at.checked_add(directory_bytes) != Some(tail_at + at as u64) {
            return Err(AdmissionFailure::Inventory);
        }
        let directory_end = directory_at + directory_bytes;
        let mut cursor = directory_at; let mut selected_count = 0;
        for _ in 0..entries {
            self.original.point(end, stop)?;
            let mut header = [0; 46];
            read_at(&self.original, index, cursor, &mut header, end, stop)?;
            if &header[..4] != b"PK\x01\x02" || le16(&header, 34)? != 0 { return Err(AdmissionFailure::Inventory); }
            let flags = le16(&header, 8)?;
            let method = match le16(&header, 10)? { 0 => ZipMethod::Stored, 8 => ZipMethod::Deflate,
                _ => return Err(AdmissionFailure::Inventory) };
            let crc = le32(&header, 16)?; let compressed = u64::from(le32(&header, 20)?);
            let expanded = u64::from(le32(&header, 24)?);
            let length = usize::from(le16(&header, 28)?); let extra = usize::from(le16(&header, 30)?);
            let comment = usize::from(le16(&header, 32)?);
            let local = u64::from(le32(&header, 42)?);
            if length == 0 || length > ZIP_NAME || expanded > FILE_BYTES || flags & !0x080e != 0
                || method == ZipMethod::Stored && (flags & 6 != 0 || compressed != expanded)
                || [compressed, expanded, local].contains(&u64::from(u32::MAX)) { return Err(AdmissionFailure::Inventory); }
            cursor = cursor.checked_add(46).ok_or(AdmissionFailure::Bounds)?;
            read_at(&self.original, index, cursor, &mut self.scratch.name[..length], end, stop)?;
            let name = &self.scratch.name[..length];
            let trimmed = name.strip_suffix(b"/").unwrap_or(name);
            if !archive_name(trimmed) { return Err(AdmissionFailure::Inventory); }
            let mut hash = Sha256::new();
            for byte in trimmed { hash.update([byte.to_ascii_lowercase()]); }
            self.names.push(hash.finalize().into());
            let is_selected = name == selected.name.as_bytes();
            cursor = cursor.checked_add(length as u64).ok_or(AdmissionFailure::Bounds)?;
            read_at(&self.original, index, cursor, &mut self.scratch.extra[..extra], end, stop)?;
            extra_fields(&self.scratch.extra[..extra])?;
            cursor = cursor.checked_add((extra + comment) as u64).filter(|next| *next <= directory_end)
                .ok_or(AdmissionFailure::Bounds)?;
            let mut local_header = [0; 30];
            read_at(&self.original, index, local, &mut local_header, end, stop)?;
            if &local_header[..4] != b"PK\x03\x04" || le16(&local_header, 6)? != flags
                || le16(&local_header, 8)? != le16(&header, 10)? || le16(&local_header, 26)? as usize != length {
                return Err(AdmissionFailure::Inventory);
            }
            let local_extra = usize::from(le16(&local_header, 28)?);
            let local_name_at = local.checked_add(30).ok_or(AdmissionFailure::Bounds)?;
            read_at(&self.original, index, local_name_at, &mut self.scratch.local_name[..length], end, stop)?;
            if self.scratch.local_name[..length] != self.scratch.name[..length] { return Err(AdmissionFailure::Inventory); }
            read_at(&self.original, index, local_name_at + length as u64, &mut self.scratch.extra[..local_extra], end, stop)?;
            extra_fields(&self.scratch.extra[..local_extra])?;
            let data = local_name_at.checked_add((length + local_extra) as u64).ok_or(AdmissionFailure::Bounds)?;
            let mut last = data.checked_add(compressed).filter(|last| *last <= directory_at).ok_or(AdmissionFailure::Bounds)?;
            if flags & 8 == 0 {
                if le32(&local_header, 14)? != crc || u64::from(le32(&local_header, 18)?) != compressed
                    || u64::from(le32(&local_header, 22)?) != expanded { return Err(AdmissionFailure::Inventory); }
            } else {
                for (offset, value) in [(14, u64::from(crc)), (18, compressed), (22, expanded)] {
                    let actual = u64::from(le32(&local_header, offset)?);
                    if actual != 0 && actual != value { return Err(AdmissionFailure::Inventory); }
                }
                let mut descriptor = [0; 16];
                read_at(&self.original, index, last, &mut descriptor[..4], end, stop)?;
                let prefix = if &descriptor[..4] == b"PK\x07\x08" { 4 } else { 0 };
                read_at(&self.original, index, last, &mut descriptor[..prefix + 12], end, stop)?;
                if le32(&descriptor, prefix)? != crc || u64::from(le32(&descriptor, prefix + 4)?) != compressed
                    || u64::from(le32(&descriptor, prefix + 8)?) != expanded { return Err(AdmissionFailure::Inventory); }
                last = last.checked_add((prefix + 12) as u64).filter(|last| *last <= directory_at)
                    .ok_or(AdmissionFailure::Bounds)?;
            }
            self.spans.push(Span { first: local, end: last });
            if is_selected {
                selected_count += 1;
                if name_kind(le32(&header, 38)?) == Some(false)
                    || selected.method != method || selected.flags != flags || selected.local_header_offset != local
                    || selected.data_offset != data || selected.compressed_bytes != compressed
                    || selected.bytes != expanded || selected.crc32 != crc
                    || selected.bytes == 0 || !sha(selected.sha256) { return Err(AdmissionFailure::Inventory); }
            }
        }
        if cursor != directory_end || selected_count != 1 { return Err(AdmissionFailure::Inventory); }
        self.names.sort_unstable();
        if self.names.windows(2).any(|pair| pair[0] == pair[1]) { return Err(AdmissionFailure::Inventory); }
        self.spans.sort_unstable_by_key(|span| span.first);
        if self.spans.windows(2).any(|pair| pair[0].end > pair[1].first) { return Err(AdmissionFailure::Inventory); }
        self.original.check_name(index, end, stop)
    }
    fn project(&mut self, index: usize, member: ZipMemberSpec<'static>, end: Instant,
        stop: &watch::Receiver<bool>, sink: &mut Sink<'_>) -> Result<()> {
        if member.bytes == 0 || member.bytes > FILE_BYTES || member.compressed_bytes == 0
            || member.compressed_bytes > FILE_BYTES { return Err(AdmissionFailure::Bounds); }
        self.scratch.inflate.reset(DataFormat::Raw);
        // Runtime CPU feature detection is inside the entered original, not GO.
        self.original.point(end, stop)?;
        let mut crc = crc32fast::Hasher::new(); let mut hash = Sha256::new();
        let (mut read, mut consumed, mut expanded) = (0u64, 0u64, 0u64);
        let (mut input_at, mut input_end) = (0usize, 0usize);
        let mut ended = false;
        loop {
            self.original.point(end, stop)?;
            if input_at == input_end && read < member.compressed_bytes {
                let take = usize::try_from((member.compressed_bytes - read).min(BLOCK as u64)).map_err(native_error)?;
                read_at(&self.original, index, member.data_offset.checked_add(read).ok_or(AdmissionFailure::Bounds)?,
                    &mut self.scratch.input[..take], end, stop)?;
                read += take as u64; input_at = 0; input_end = take;
            }
            let (used, written, stream_end) = match member.method {
                ZipMethod::Stored => {
                    let size = input_end - input_at;
                    self.scratch.output[..size].copy_from_slice(&self.scratch.input[input_at..input_end]);
                    (size, size, read == member.compressed_bytes)
                },
                ZipMethod::Deflate => {
                    let result = inflate(&mut self.scratch.inflate, &self.scratch.input[input_at..input_end],
                        &mut self.scratch.output, MZFlush::None);
                    let status = result.status.map_err(|_| AdmissionFailure::Inventory)?;
                    (result.bytes_consumed, result.bytes_written, status == MZStatus::StreamEnd)
                },
            };
            if used > input_end - input_at || written > BLOCK { return Err(AdmissionFailure::Unknown); }
            input_at += used; consumed = consumed.checked_add(used as u64).ok_or(AdmissionFailure::Bounds)?;
            expanded = expanded.checked_add(written as u64).filter(|bytes| *bytes <= member.bytes)
                .ok_or(AdmissionFailure::Bounds)?;
            if written != 0 {
                let bytes = &self.scratch.output[..written]; crc.update(bytes); hash.update(bytes); sink(bytes)?;
            }
            if stream_end { ended = true; break; }
            if used == 0 && written == 0 { break; }
        }
        if !ended || read != member.compressed_bytes || consumed != member.compressed_bytes
            || input_at != input_end || expanded != member.bytes || crc.finalize() != member.crc32
            || hex_digest(hash) != member.sha256 { return Err(AdmissionFailure::Inventory); }
        self.original.check_name(index, end, stop)
    }
}
fn hex_digest(hash: Sha256) -> String { hash.finalize().iter().map(|byte| format!("{byte:02x}")).collect() }
fn read_at(book: &Book, index: usize, at: u64, bytes: &mut [u8], end: Instant, stop: &watch::Receiver<bool>) -> Result<()> {
    let size = book.records.get(index).and_then(|record| record.identity).and_then(|id| u64::try_from(id.size).ok())
        .ok_or(AdmissionFailure::Identity)?;
    if bytes.len() > ZIP_TAIL || at.checked_add(bytes.len() as u64).is_none_or(|last| last > size) {
        return Err(AdmissionFailure::Bounds);
    }
    book.point(end, stop)?;
    let offset = i64::try_from(at).map_err(native_error)?;
    if unistd::lseek(book.fd(index)?, offset, unistd::Whence::SeekSet).map_err(native_error)? != offset {
        return Err(AdmissionFailure::Native);
    }
    let mut used = 0;
    while used < bytes.len() {
        book.point(end, stop)?;
        let count = unistd::read(book.fd(index)?, &mut bytes[used..]).map_err(native_error)?;
        if count == 0 { return Err(AdmissionFailure::Inventory); }
        used += count;
    }
    book.point(end, stop)
}
fn le16(bytes: &[u8], at: usize) -> Result<u16> {
    bytes.get(at..at + 2).and_then(|v| v.try_into().ok()).map(u16::from_le_bytes).ok_or(AdmissionFailure::Bounds)
}
fn le32(bytes: &[u8], at: usize) -> Result<u32> {
    bytes.get(at..at + 4).and_then(|v| v.try_into().ok()).map(u32::from_le_bytes).ok_or(AdmissionFailure::Bounds)
}
fn archive_name(name: &[u8]) -> bool {
    !name.is_empty() && name.len() <= ZIP_NAME && name.split(|b| *b == b'/').count() <= 16
        && name.split(|b| *b == b'/').all(|part| !part.is_empty() && part.len() <= 255
            && part != b"." && part != b".." && !matches!(part.last(), Some(b'.' | b' '))
            && part.iter().all(|b| b.is_ascii_alphanumeric() || b"_+@.,= $-".contains(b)))
}
fn extra_fields(bytes: &[u8]) -> Result<()> {
    let mut at = 0;
    while at < bytes.len() {
        let id = le16(bytes, at)?; let size = usize::from(le16(bytes, at + 2)?);
        if matches!(id, 0x0001 | 0x0017 | 0x9901) { return Err(AdmissionFailure::Inventory); }
        at = at.checked_add(4 + size).filter(|at| *at <= bytes.len()).ok_or(AdmissionFailure::Bounds)?;
    }
    Ok(())
}
fn name_kind(attributes: u32) -> Option<bool> {
    match attributes >> 16 & 0o170000 { 0 => None, 0o100000 => Some(true), _ => Some(false) }
}
