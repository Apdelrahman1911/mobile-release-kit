//! Qualification-only original owner for ONE fixed, headless libtest child.
//! Compiled only by cfg(test); no product capability, general launcher or fullwalk.
//! This same libtest thread owns every synchronous borrower. In particular, a
//! blocked CreateProcessWithLogonW is NOT detached, timed out, or freed. Hosted
//! step expiry is containment/Unknown, never an original-return/close receipt.
use super::*;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use windows_sys::Win32::NetworkManagement::NetManagement as NM;
use windows_sys::Win32::Security::Cryptography as BC;

pub(super) const CHILD: &str = "hosted_tests::hosted_native_read_only_contract";
const OWNER: &str = "ordinary_owner::hosted_ordinary_original_handle_contract";
const FLAGS: [&str; 4] = ["--exact", "--ignored", "--nocapture", "--test-threads=1"];
const REQUEST: &str = "ordinary-request.txt";
const RESULT: &str = "native-result.json";
const OWNER_RESULT: &str = "ordinary-owner-result.private.json";
const LIMIT: usize = 4096;
const OWNER_LIMIT: usize = 65536;
const NATIVE_SECONDS: u64 = 90;
const SETTLE_MS: u32 = 10_000;

fn need(value: bool) -> Result<()> { if value { Ok(()) } else { Err(Error::Unsafe) } }
// One shared, absorbing next-effect gate. Callers supply elapsed time from the
// original owner clock, including after synchronous observations return. This
// does not cancel a borrower or prohibit settling an already-owned original.
pub(super) fn next_effect(elapsed: Duration, deadline_latched: &mut bool) -> Result<()> {
    *deadline_latched |= elapsed >= Duration::from_secs(NATIVE_SECONDS);
    need(!*deadline_latched)
}
fn hex(raw: &[u8]) -> String { raw.iter().map(|b| format!("{b:02x}")).collect() }
fn is_hex(value: &str, size: usize) -> bool {
    value.len() == size && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn decimal(value: &str) -> bool {
    !value.is_empty() && value.len() <= 20 && !value.starts_with('0') && value.bytes().all(|b| b.is_ascii_digit())
}
fn unhex(value: &str) -> Result<Vec<u8>> {
    need(value.len() <= 136 && value.len() % 2 == 0 && is_hex(value, value.len()))?;
    value.as_bytes().chunks_exact(2).map(|pair| {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        Ok(digit(pair[0]) * 16 + digit(pair[1]))
    }).collect()
}
fn digest(raw: &[u8]) -> Result<String> {
    need(raw.len() <= 128 << 20)?;
    let mut output = [0u8; 32];
    // Documented CNG pseudo-handle: borrowed, never closed. No provider/import,
    // key, random fallback, package dependency or hand-written hash algorithm.
    let status = unsafe { BC::BCryptHash(BC::BCRYPT_SHA256_ALG_HANDLE, null(), 0,
        raw.as_ptr(), raw.len() as u32, output.as_mut_ptr(), output.len() as u32) };
    need(status == 0)?;
    Ok(hex(&output))
}
fn command(path: &str) -> String { format!("\"{path}\" {CHILD} {}", FLAGS.join(" ")) }
fn command_digest(path: &str) -> Result<String> {
    let text = command(path);
    need(text.encode_utf16().count() <= 1023)?;
    digest(&text.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>())
}
fn fixed_path(value: &str) -> Result<PathBuf> {
    need(value.len() <= 1024 && value.is_ascii() && !value.bytes().any(|b| b < 32 || matches!(b, b'"' | b'%' | b'=')))?;
    let path = PathBuf::from(value);
    need(path.is_absolute() && value.as_bytes().get(1) == Some(&b':')
        && value.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && value.as_bytes().get(2) == Some(&b'\\')
        && !value.contains('/') && !value.starts_with("\\\\")
        && value.split('\\').skip(1).all(|part| decode::component(part)))?;
    Ok(path)
}

// The actual native driver and existing nine inert methods use these SAME
// absorbing decisions. Synthetic records cannot call any native function.
#[derive(Clone, Debug)]
pub(super) struct ProcessFacts {
    pub claimed: bool, pub returned: bool, pub created: bool,
    pub failed: bool, pub unknown: bool, pub signaled: bool,
    pub exit: Option<u32>, pub terminated: bool,
    pub process: SlotState, pub thread: SlotState,
}
impl ProcessFacts {
    pub fn new() -> Self {
        Self { claimed: false, returned: false, created: false, failed: false,
            unknown: false, signaled: false, exit: None, terminated: false,
            process: SlotState::Reserved, thread: SlotState::Reserved }
    }
    pub fn begin(&mut self) -> Result<()> {
        if self.claimed { return Err(Error::State); }
        self.claimed = true; self.process = SlotState::Acquiring; self.thread = SlotState::Acquiring; Ok(())
    }
    pub fn creation(&mut self, ok: bool, error: u32, outputs: (usize, usize, u32, u32), late: bool) -> Result<()> {
        if !self.claimed || self.returned { return Err(Error::State); }
        self.returned = true; self.failed |= late;
        let (process, thread, pid, tid) = outputs;
        let valid = |h| h != 0 && h != usize::MAX;
        if ok && valid(process) && valid(thread) && process != thread && pid != 0 && tid != 0 && pid != tid {
            self.created = true; self.process = SlotState::Owned; self.thread = SlotState::Owned;
            return if late { Err(Error::Unsafe) } else { Ok(()) };
        }
        self.failed = true;
        if !ok && error != 0 && error != F::ERROR_IO_PENDING && outputs == (0, 0, 0, 0) {
            self.process = SlotState::NoHandle; self.thread = SlotState::NoHandle;
            Err(Error::Unavailable)
        } else {
            self.unknown = true; self.process = SlotState::Unknown; self.thread = SlotState::Unknown;
            Err(Error::Unknown)
        }
    }
    pub fn wait(&mut self, returned: u32, late: bool) -> Result<()> {
        if !self.created || self.signaled { return Err(Error::State); }
        self.failed |= late;
        if returned == F::WAIT_OBJECT_0 { self.signaled = true; return Ok(()); }
        self.failed = true;
        if returned != F::WAIT_TIMEOUT { self.unknown = true; }
        Err(if self.unknown { Error::Unknown } else { Error::Unsafe })
    }
    pub fn exited(&mut self, ok: bool, code: u32) -> Result<()> {
        if !self.signaled || self.exit.is_some() { return Err(Error::State); }
        if !ok { self.failed = true; self.unknown = true; return Err(Error::Unknown); }
        self.exit = Some(code); self.failed |= code != 0;
        Ok(())
    }
    pub fn begin_terminate(&mut self) -> Result<()> {
        if !self.created || self.signaled || self.terminated { return Err(Error::State); }
        self.terminated = true; self.failed = true; Ok(())
    }
    pub fn begin_close(&mut self, thread: bool) -> Result<()> {
        if !self.signaled { return Err(Error::State); }
        let state = if thread { &mut self.thread } else { &mut self.process };
        if *state != SlotState::Owned { return Err(Error::State); }
        *state = SlotState::Closing; Ok(())
    }
    pub fn closed(&mut self, thread: bool, ok: bool) -> Result<()> {
        let state = if thread { &mut self.thread } else { &mut self.process };
        if *state != SlotState::Closing { return Err(Error::State); }
        *state = if ok { SlotState::Closed } else { SlotState::Unknown };
        self.failed |= !ok; self.unknown |= !ok;
        if ok { Ok(()) } else { Err(Error::Unknown) }
    }
    pub fn passed(&self) -> bool {
        self.claimed && self.returned && self.created && self.signaled && self.exit == Some(0)
            && !self.failed && !self.unknown && !self.terminated
            && self.process == SlotState::Closed && self.thread == SlotState::Closed
    }
}
pub(super) fn complete_write(ok: bool, actual: u32, expected: usize, closed: bool) -> bool {
    ok && expected > 0 && expected <= OWNER_LIMIT && actual as usize == expected && closed
}
pub(super) fn fresh_account(absent: u32, pointer_null: bool, added: u32, sid: &[u8], groups: &[Vec<u8>]) -> bool {
    absent == NM::NERR_UserNotFound && pointer_null && added == 0
        && local_account_sid(sid) && groups == [builtin(545)]
}
fn local_account_sid(sid: &[u8]) -> bool {
    sid.len() == 28 && sid[..8] == [1, 5, 0, 0, 0, 0, 0, 5] && sid[8..12] == 21u32.to_le_bytes()
}
fn builtin(rid: u32) -> Vec<u8> {
    [vec![1, 2, 0, 0, 0, 0, 0, 5], 32u32.to_le_bytes().to_vec(), rid.to_le_bytes().to_vec()].concat()
}
fn system_sid() -> Vec<u8> { [vec![1, 1, 0, 0, 0, 0, 0, 5], 18u32.to_le_bytes().to_vec()].concat() }

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Stamp {
    pub volume: u64, pub id: [u8; 16], pub creation: i64, pub write: i64, pub change: i64,
    pub size: i64, pub allocation: i64, pub links: u32, pub attributes: u32,
}
impl Stamp {
    pub fn wire(&self) -> String {
        format!("{}:{}:{}:{}:{}:{}", self.volume, hex(&self.id), self.creation,
            self.write, self.change, self.attributes)
    }
    fn json(&self) -> String {
        format!("{{\"volume\":{},\"fileId\":\"{}\",\"creation\":{},\"write\":{},\"change\":{},\"size\":{},\"allocation\":{},\"links\":{},\"attributes\":{}}}",
            self.volume, hex(&self.id), self.creation, self.write, self.change,
            self.size, self.allocation, self.links, self.attributes)
    }
}
pub(super) fn acl_stamp(before: &Stamp, after: &Stamp) -> bool {
    let mut admitted = before.clone(); admitted.change = after.change;
    admitted == *after && after.change >= before.change
}

struct FileBody {
    path: Vec<u16>, handle: F::HANDLE, state: SlotState, active: bool,
    error: u32, count: u32, raw: Vec<u8>, security: Box<Aligned>,
    basic: FS::FILE_BASIC_INFO, standard: FS::FILE_STANDARD_INFO,
    tag: FS::FILE_ATTRIBUTE_TAG_INFO, id: FS::FILE_ID_INFO,
    final_name: Vec<u16>, _pin: PhantomPinned,
}
struct OriginalFile { body: Held<FileBody>, directory: bool }
impl OriginalFile {
    fn new(path: &Path, directory: bool) -> Result<Self> {
        let value = path.to_str().ok_or(Error::Unsafe)?;
        need(value.encode_utf16().count() <= 1024)?;
        Ok(Self { body: ManuallyDrop::new(Box::pin(FileBody {
            path: wide(value), handle: null_mut(), state: SlotState::Reserved, active: false,
            error: 0, count: 0, raw: Vec::new(), security: Box::new(Aligned([0; BUFFER])),
            basic: FS::FILE_BASIC_INFO::default(), standard: FS::FILE_STANDARD_INFO::default(),
            tag: FS::FILE_ATTRIBUTE_TAG_INFO::default(), id: FS::FILE_ID_INFO::default(),
            final_name: vec![0; 32768], _pin: PhantomPinned,
        })), directory })
    }
    fn body(&mut self) -> &mut FileBody {
        // No movement of the pinned body; all native pointers refer to this
        // original's retained complete buffers, never temporary output storage.
        unsafe { self.body.as_mut().get_unchecked_mut() }
    }
    fn open(&mut self, access: u32, create: bool, security: *const S::SECURITY_ATTRIBUTES) -> Result<()> {
        let directory = self.directory; let b = self.body();
        if b.state != SlotState::Reserved { return Err(Error::State); }
        b.state = SlotState::Acquiring; b.active = true;
        b.handle = unsafe { FS::CreateFileW(b.path.as_ptr(), access,
            FS::FILE_SHARE_READ | if directory { FS::FILE_SHARE_WRITE } else { 0 },
            security, if create { FS::CREATE_NEW } else { FS::OPEN_EXISTING },
            FS::FILE_FLAG_OPEN_REPARSE_POINT | if directory { FS::FILE_FLAG_BACKUP_SEMANTICS } else { 0 }, null_mut()) };
        b.error = if valid_handle(b.handle) { 0 } else { unsafe { F::GetLastError() } };
        if valid_handle(b.handle) { b.active = false; b.state = SlotState::Owned; Ok(()) }
        else if b.error != 0 && b.error != F::ERROR_IO_PENDING && b.handle == F::INVALID_HANDLE_VALUE {
            b.active = false; b.state = SlotState::NoHandle; Err(Error::Unavailable)
        } else { b.state = SlotState::Unknown; Err(Error::Unknown) }
    }
    fn info(&mut self, which: u8) -> Result<()> {
        let b = self.body();
        if b.state != SlotState::Owned || b.active { return Err(Error::State); }
        let (class, output, size) = match which {
            0 => (FS::FileBasicInfo, (&mut b.basic as *mut FS::FILE_BASIC_INFO).cast(), size_of::<FS::FILE_BASIC_INFO>()),
            1 => (FS::FileStandardInfo, (&mut b.standard as *mut FS::FILE_STANDARD_INFO).cast(), size_of::<FS::FILE_STANDARD_INFO>()),
            2 => (FS::FileAttributeTagInfo, (&mut b.tag as *mut FS::FILE_ATTRIBUTE_TAG_INFO).cast(), size_of::<FS::FILE_ATTRIBUTE_TAG_INFO>()),
            3 => (FS::FileIdInfo, (&mut b.id as *mut FS::FILE_ID_INFO).cast(), size_of::<FS::FILE_ID_INFO>()),
            _ => return Err(Error::State),
        };
        b.active = true;
        let ok = unsafe { FS::GetFileInformationByHandleEx(b.handle, class, output, size as u32) };
        b.error = if ok != 0 { 0 } else { unsafe { F::GetLastError() } };
        b.active = ok == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
        if b.active { b.state = SlotState::Unknown; return Err(Error::Unknown); }
        need(ok != 0)
    }
    fn stamp(&mut self) -> Result<Stamp> {
        for which in 0..4 { self.info(which)?; }
        let directory = self.directory; let b = self.body();
        need(b.standard.Directory == directory && !b.standard.DeletePending
            && b.standard.EndOfFile >= 0 && b.standard.AllocationSize >= 0
            && b.standard.NumberOfLinks == 1
            && b.tag.FileAttributes == b.basic.FileAttributes
            && b.basic.FileAttributes & FS::FILE_ATTRIBUTE_REPARSE_POINT == 0
            && b.id.FileId.Identifier != [0; 16])?;
        Ok(Stamp { volume: b.id.VolumeSerialNumber, id: b.id.FileId.Identifier,
            creation: b.basic.CreationTime, write: b.basic.LastWriteTime, change: b.basic.ChangeTime,
            size: b.standard.EndOfFile, allocation: b.standard.AllocationSize,
            links: b.standard.NumberOfLinks, attributes: b.basic.FileAttributes })
    }
    fn named(&mut self, expected: &Path) -> Result<()> {
        let text = expected.to_str().ok_or(Error::Unsafe)?;
        let b = self.body();
        if b.state != SlotState::Owned || b.active { return Err(Error::State); }
        b.active = true;
        b.count = unsafe { FS::GetFinalPathNameByHandleW(b.handle, b.final_name.as_mut_ptr(),
            b.final_name.len() as u32, FS::FILE_NAME_NORMALIZED | FS::VOLUME_NAME_DOS) };
        b.error = if b.count != 0 { 0 } else { unsafe { F::GetLastError() } };
        b.active = b.count == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
        if b.active { b.state = SlotState::Unknown; return Err(Error::Unknown); }
        need(b.count > 0 && (b.count as usize) < b.final_name.len())?;
        let actual = String::from_utf16(&b.final_name[..b.count as usize]).map_err(|_| Error::Unsafe)?;
        need(actual.strip_prefix("\\\\?\\") == Some(text))
    }
    fn read(&mut self, limit: usize) -> Result<Vec<u8>> {
        let before = self.stamp()?;
        need(!self.directory && before.size >= 0 && before.size as usize <= limit && limit <= 128 << 20)?;
        let b = self.body();
        b.raw = vec![0; before.size as usize + 1]; b.count = 0; b.active = true;
        let ok = unsafe { FS::ReadFile(b.handle, b.raw.as_mut_ptr(), b.raw.len() as u32, &mut b.count, null_mut()) };
        b.error = if ok != 0 { 0 } else { unsafe { F::GetLastError() } };
        b.active = ok == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
        if b.active { b.state = SlotState::Unknown; return Err(Error::Unknown); }
        need(ok != 0 && b.count as i64 == before.size)?;
        let value = b.raw[..b.count as usize].to_vec();
        need(self.stamp()? == before)?;
        Ok(value)
    }
    fn descriptor(&mut self) -> Result<Vec<u8>> {
        let b = self.body();
        if b.state != SlotState::Owned || b.active { return Err(Error::State); }
        b.count = 0; b.active = true;
        let ok = unsafe { S::GetKernelObjectSecurity(b.handle,
            S::OWNER_SECURITY_INFORMATION | S::GROUP_SECURITY_INFORMATION | S::DACL_SECURITY_INFORMATION,
            b.security.0.as_mut_ptr().cast(), BUFFER as u32, &mut b.count) };
        b.error = if ok != 0 { 0 } else { unsafe { F::GetLastError() } };
        b.active = ok == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
        if b.active { b.state = SlotState::Unknown; return Err(Error::Unknown); }
        need(ok != 0 && b.count as usize <= BUFFER && b.count >= 20)?;
        Ok(b.security.0[..b.count as usize].to_vec())
    }
    fn write(&mut self, value: &[u8], limit: usize) -> Result<()> {
        need(!value.is_empty() && value.len() <= limit && limit <= OWNER_LIMIT)?;
        let b = self.body();
        if b.state != SlotState::Owned || b.active || !b.raw.is_empty() { return Err(Error::State); }
        b.raw = value.to_vec(); b.count = 0; b.active = true;
        let ok = unsafe { FS::WriteFile(b.handle, b.raw.as_ptr(), b.raw.len() as u32, &mut b.count, null_mut()) };
        b.error = if ok != 0 { 0 } else { unsafe { F::GetLastError() } };
        b.active = ok == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
        if b.active { b.state = SlotState::Unknown; return Err(Error::Unknown); }
        // Exactly one attempt. An ordinary short write is still failure; the
        // caller must then explicitly close the same original, not retry it.
        need(complete_write(ok != 0, b.count, value.len(), true))
    }
    fn close(&mut self) -> Result<()> {
        let b = self.body();
        match b.state {
            SlotState::Reserved | SlotState::NoHandle | SlotState::Closed => return Ok(()),
            SlotState::Owned if !b.active => (),
            _ => return Err(Error::Unknown),
        }
        b.state = SlotState::Closing;
        let ok = unsafe { F::CloseHandle(b.handle) };
        b.error = if ok != 0 { 0 } else { unsafe { F::GetLastError() } };
        b.state = if ok != 0 { SlotState::Closed } else { SlotState::Unknown };
        if ok != 0 { Ok(()) } else { Err(Error::Unknown) }
    }
}
impl Drop for OriginalFile {
    fn drop(&mut self) {
        let b = self.body();
        if !b.active && matches!(b.state, SlotState::Reserved | SlotState::NoHandle | SlotState::Closed) {
            unsafe { ManuallyDrop::drop(&mut self.body); }
        }
        // Never CloseHandle in Drop. Uncertain buffers/originals are retained.
    }
}
fn close_files(files: &mut [OriginalFile]) -> bool {
    // A later original can be a child of any earlier directory. On the first
    // uncertain close stop, retaining every remaining ancestor without retry.
    for file in files.iter_mut().rev() {
        if file.close().is_err() { return false; }
    }
    true
}
fn owned_file(files: &mut Vec<OriginalFile>, path: &Path, directory: bool, access: u32) -> Result<usize> {
    need(files.len() < 40)?;
    let index = files.len(); files.push(OriginalFile::new(path, directory)?);
    files[index].open(access, false, null())?;
    files[index].named(path)?; files[index].stamp()?;
    Ok(index)
}

#[derive(Clone, Eq, PartialEq)]
struct AclImage { owner: Vec<u8>, group: Vec<u8>, control: u16, revision: u8, aces: Vec<Vec<u8>> }
impl AclImage {
    fn parse(raw: &[u8]) -> Result<Self> {
        need(raw.len() >= 20 && raw.len() <= BUFFER && raw[0] == 1 && raw[1] == 0)?;
        let control = decode::u16_at(raw, 2)?;
        need(control & (S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT) == (S::SE_SELF_RELATIVE | S::SE_DACL_PRESENT)
            && decode::u32_at(raw, 12)? == 0)?;
        let principal = |at| -> Result<Vec<u8>> {
            let offset = decode::u32_at(raw, at)? as usize;
            need(offset >= 20 && offset % 4 == 0)?;
            Ok(security::sid_at(raw, offset, raw.len())?.bytes().to_vec())
        };
        let owner = principal(4)?; let group = principal(8)?;
        let at = decode::u32_at(raw, 16)? as usize;
        need(at >= 20 && at % 4 == 0)?;
        let head = decode::span(raw, at, 8)?;
        let size = decode::u16_at(head, 2)? as usize;
        let count = decode::u16_at(head, 4)? as usize;
        need(matches!(head[0], 2 | 4) && head[1] == 0 && decode::u16_at(head, 6)? == 0
            && size >= 8 && count <= 1024 && size % 4 == 0)?;
        decode::span(raw, at, size)?;
        let mut aces = Vec::new(); let mut cursor = at + 8;
        for _ in 0..count {
            let header = decode::span(raw, cursor, 4)?;
            let length = decode::u16_at(header, 2)? as usize;
            need(matches!(header[0], 0 | 1) && header[1] & !0x1f == 0 && length >= 16 && length % 4 == 0
                && cursor + length <= at + size)?;
            let sid = security::sid_at(raw, cursor + 8, cursor + length)?;
            need(sid.bytes().len() + 8 == length)?;
            aces.push(decode::span(raw, cursor, length)?.to_vec()); cursor += length;
        }
        // Do not reinterpret unknown ACEs, null DACLs or leftover nonzero data.
        need(raw[cursor..at + size].iter().all(|byte| *byte == 0))?;
        Ok(Self { owner, group, control, revision: head[0], aces })
    }
    fn base(&self, parent: &[u8], account: &[u8], directory: bool) -> Result<()> {
        need([system_sid(), builtin(544), parent.to_vec()].contains(&self.owner)
            && self.owner != account && self.group != account)?;
        for ace in &self.aces {
            let sid = &ace[8..];
            need(sid != account)?;
            let mut mask = decode::u32_at(ace, 4)?;
            for (generic, rights) in [(F::GENERIC_ALL, FS::FILE_ALL_ACCESS),
                (F::GENERIC_READ, FS::FILE_GENERIC_READ), (F::GENERIC_WRITE, FS::FILE_GENERIC_WRITE),
                (F::GENERIC_EXECUTE, FS::FILE_GENERIC_EXECUTE)] {
                if mask & generic != 0 { mask = (mask & !generic) | rights; }
            }
            need(mask & !FS::FILE_ALL_ACCESS == 0)?;
            if ace[0] == 1 || ace[1] as u32 & S::INHERIT_ONLY_ACE != 0
                || sid == parent || sid == system_sid() || sid == builtin(544) { continue; }
            // Only the already task-owned tree is changed. Other principals may
            // read/traverse, but may not mutate/replace these exact originals.
            let mut mutation = FS::DELETE | FS::FILE_DELETE_CHILD | FS::WRITE_DAC | FS::WRITE_OWNER
                | FS::FILE_WRITE_DATA | FS::FILE_APPEND_DATA | FS::FILE_WRITE_EA | FS::FILE_WRITE_ATTRIBUTES;
            if !directory { mutation |= FS::FILE_WRITE_DATA; }
            need(mask & mutation == 0)?;
        }
        Ok(())
    }
    fn add(&self, sid: &[u8], mask: u32) -> Result<(Self, Box<Aligned>)> {
        let size = 8 + self.aces.iter().map(Vec::len).sum::<usize>() + 8 + sid.len();
        need(size <= BUFFER && size <= u16::MAX as usize && self.aces.len() < 1024)?;
        let mut expected = self.clone();
        let mut ace = vec![0, 0];
        ace.extend_from_slice(&((8 + sid.len()) as u16).to_le_bytes());
        ace.extend_from_slice(&mask.to_le_bytes()); ace.extend_from_slice(sid);
        // One explicit non-inheriting ACE; retain every original ACE byte/order.
        let insertion = expected.aces.iter().position(|a| a[1] as u32 & S::INHERITED_ACE != 0).unwrap_or(expected.aces.len());
        expected.aces.insert(insertion, ace);
        let mut acl = Box::new(Aligned([0; BUFFER]));
        acl.0[0] = expected.revision; acl.0[2..4].copy_from_slice(&(size as u16).to_le_bytes());
        acl.0[4..6].copy_from_slice(&(expected.aces.len() as u16).to_le_bytes());
        let mut at = 8;
        for ace in &expected.aces { acl.0[at..at + ace.len()].copy_from_slice(ace); at += ace.len(); }
        Ok((expected, acl))
    }
}
fn grant(file: &mut OriginalFile, role: &str, parent: &[u8], account: &[u8], mask: u32,
    start: Instant, deadline_latched: &mut bool) -> Result<String> {
    next_effect(start.elapsed(), deadline_latched)?;
    let before = file.stamp()?; let raw_before = file.descriptor()?;
    let image = AclImage::parse(&raw_before)?; image.base(parent, account, file.directory)?;
    let (expected, acl) = image.add(account, mask)?;
    let mut descriptor = Box::new(S::SECURITY_DESCRIPTOR::default());
    need(unsafe { S::InitializeSecurityDescriptor((&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(), 1) } != 0)?;
    need(unsafe { S::SetSecurityDescriptorDacl((&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(),
        1, acl.0.as_ptr().cast(), 0) } != 0)?;
    let b = file.body();
    if b.state != SlotState::Owned || b.active { return Err(Error::State); }
    next_effect(start.elapsed(), deadline_latched)?;
    b.active = true;
    // Same original only. No SetNamedSecurityInfo/SetSecurityInfo propagation,
    // recursion, owner/group/SACL replacement, inheritable ACE or broad trustee.
    let ok = unsafe { S::SetKernelObjectSecurity(b.handle, S::DACL_SECURITY_INFORMATION,
        (&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast()) };
    b.error = if ok != 0 { 0 } else { unsafe { F::GetLastError() } };
    b.active = ok == 0 && (b.error == 0 || b.error == F::ERROR_IO_PENDING);
    if b.active {
        b.state = SlotState::Unknown;
        diagnostic("original-acl-operation", None, true);
        loop { std::thread::park(); std::hint::black_box((&mut *b, &descriptor, &acl)); }
    }
    need(ok != 0)?;
    let after = file.stamp()?; let raw_after = file.descriptor()?;
    need(acl_stamp(&before, &after) && AclImage::parse(&raw_after)? == expected && raw_before != raw_after)?;
    next_effect(start.elapsed(), deadline_latched)?;
    Ok(format!("{{\"role\":\"{role}\",\"mask\":{mask},\"before\":{},\"after\":{},\"securityBefore\":\"{}\",\"securityAfter\":\"{}\",\"singleExplicitNoninheritingAce\":true}}",
        before.json(), after.json(), digest(&raw_before)?, digest(&raw_after)?))
}

// NetAPI allocation outputs remain original objects until their explicit single
// NetApiBufferFree. A status/pointer/size contradiction is retained, not adopted.
struct NetBuffer {
    pointer: *mut u8, status: u32, bytes: u32, entries: u32, total: u32,
    release_attempted: bool, released: bool, release_status: u32,
}
impl NetBuffer {
    fn new() -> Self { Self { pointer: null_mut(), status: u32::MAX, bytes: 0, entries: 0, total: 0,
        release_attempted: false, released: false, release_status: u32::MAX } }
    fn range(&self, pointer: *const u8, size: usize) -> Result<&[u8]> {
        let start = self.pointer as usize; let selected = pointer as usize;
        need(!self.pointer.is_null() && selected >= start && size <= self.bytes as usize
            && selected.checked_add(size).is_some_and(|end| start.checked_add(self.bytes as usize).is_some_and(|limit| end <= limit)))?;
        Ok(unsafe { std::slice::from_raw_parts(pointer, size) })
    }
    fn sized(&mut self) -> Result<()> {
        if self.status != 0 || self.pointer.is_null() { return Err(Error::Unknown); }
        let result = unsafe { NM::NetApiBufferSize(self.pointer.cast(), &mut self.bytes) };
        if result != 0 || self.bytes == 0 || self.bytes as usize > BUFFER { return Err(Error::Unknown); }
        Ok(())
    }
    fn string(&self, pointer: *const u16, maximum: usize) -> Result<Vec<u16>> {
        let mut value = Vec::new();
        for i in 0..=maximum {
            let raw = self.range((pointer as usize).checked_add(i * 2).ok_or(Error::Bounds)? as *const u8, 2)?;
            let unit = u16::from_le_bytes([raw[0], raw[1]]);
            if unit == 0 { return Ok(value); }
            value.push(unit);
        }
        Err(Error::Bounds)
    }
    fn sid(&self, pointer: S::PSID) -> Result<Vec<u8>> {
        let head = self.range(pointer.cast(), 8)?;
        need(head[0] == 1 && head[1] <= 15)?;
        let raw = self.range(pointer.cast(), 8 + head[1] as usize * 4)?;
        Ok(security::sid_at(raw, 0, raw.len())?.bytes().to_vec())
    }
    fn free(&mut self) -> Result<()> {
        if self.release_attempted { return Err(Error::State); }
        self.release_attempted = true;
        if self.pointer.is_null() {
            self.released = self.status == NM::NERR_UserNotFound || self.status == 0 && self.entries == 0;
            return if self.released { Ok(()) } else { Err(Error::Unknown) };
        }
        if self.status != 0 { return Err(Error::Unknown); }
        self.release_status = unsafe { NM::NetApiBufferFree(self.pointer.cast()) };
        self.released = self.release_status == 0;
        if self.released { Ok(()) } else { Err(Error::Unknown) }
    }
}
struct Account {
    name: Vec<u16>, password: Box<[u16; 65]>, users: Vec<u16>, sid: Vec<u8>,
    absent: u32, absent_pointer_null: bool, add: u32, group_add: bool, attempted: bool,
    delete_attempted: bool, delete_status: u32, removed: bool,
    queries: Vec<Box<NetBuffer>>,
}
impl Account {
    fn new() -> Result<Self> {
        let mut sid = builtin(545); let mut name_buffer = [0u16; 256]; let mut domain = [0u16; 256];
        let mut name_units = 256; let mut domain_units = 256; let mut usage = 0;
        let ok = unsafe { S::LookupAccountSidW(null(), sid.as_mut_ptr().cast(), name_buffer.as_mut_ptr(),
            &mut name_units, domain.as_mut_ptr(), &mut domain_units, &mut usage) };
        need(ok != 0 && usage == S::SidTypeAlias && name_units > 0 && name_units < 256
            && domain_units < 256 && String::from_utf16(&domain[..domain_units as usize]).map_err(|_| Error::Unsafe)? == "BUILTIN")?;
        let users = name_buffer[..name_units as usize].iter().copied().chain(std::iter::once(0)).collect();
        // Resolve the well-known Users alias BEFORE any password exists.
        let mut random = [0u8; 68];
        let random_status = unsafe { BC::BCryptGenRandom(null_mut(), random.as_mut_ptr(), random.len() as u32,
            BC::BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
        if random_status != 0 {
            for byte in &mut random { unsafe { std::ptr::write_volatile(byte, 0); } }
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
            return Err(Error::Unavailable);
        }
        let name = wide(&format!("mrk{}", hex(&random[..8])));
        let mut password = Box::new([0u16; 65]);
        password[..4].copy_from_slice(&[b'A' as u16, b'a' as u16, b'7' as u16, b'!' as u16]);
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!_";
        for (slot, byte) in password[4..64].iter_mut().zip(&random[8..]) { *slot = alphabet[(*byte & 63) as usize] as u16; }
        for byte in &mut random { unsafe { std::ptr::write_volatile(byte, 0); } }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        Ok(Self { name, password, users, sid: Vec::new(), absent: u32::MAX, absent_pointer_null: false,
            add: u32::MAX, group_add: false, attempted: false, delete_attempted: false,
            delete_status: u32::MAX, removed: false, queries: Vec::with_capacity(8) })
    }
    fn zero(&mut self) {
        for unit in self.password.iter_mut() { unsafe { std::ptr::write_volatile(unit, 0); } }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
    fn query(&mut self) -> Result<Option<Vec<u8>>> {
        need(self.queries.len() < 8)?;
        let first_query = self.queries.is_empty();
        self.queries.push(Box::new(NetBuffer::new()));
        let q = self.queries.last_mut().ok_or(Error::State)?;
        q.status = unsafe { NM::NetUserGetInfo(null(), self.name.as_ptr(), 23, &mut q.pointer) };
        if q.status == NM::NERR_UserNotFound && q.pointer.is_null() {
            if first_query { self.absent = q.status; self.absent_pointer_null = q.pointer.is_null(); }
            q.free()?; return Ok(None);
        }
        let observed = (|| -> Result<Vec<u8>> {
            q.sized()?;
            q.range(q.pointer, size_of::<NM::USER_INFO_23>())?;
            let info = unsafe { std::ptr::read_unaligned(q.pointer.cast::<NM::USER_INFO_23>()) };
            need(q.string(info.usri23_name, 20)? == self.name[..self.name.len() - 1]
                && info.usri23_flags == (NM::UF_SCRIPT | NM::UF_NORMAL_ACCOUNT))?;
            q.sid(info.usri23_user_sid)
        })();
        let freed = q.free();
        if freed.is_err() { return Err(Error::Unknown); }
        observed.map(Some)
    }
    fn groups(&mut self) -> Result<Vec<Vec<u8>>> {
        need(self.queries.len() < 8)?;
        self.queries.push(Box::new(NetBuffer::new()));
        let q = self.queries.last_mut().ok_or(Error::State)?;
        q.status = unsafe { NM::NetUserGetLocalGroups(null(), self.name.as_ptr(), 0, NM::LG_INCLUDE_INDIRECT,
            &mut q.pointer, BUFFER as u32, &mut q.entries, &mut q.total) };
        let observed = (|| -> Result<Vec<Vec<u8>>> {
            if q.status != 0 || q.entries != q.total { return Err(Error::Unknown); }
            need(q.entries <= 1)?;
            if q.entries == 0 {
                if !q.pointer.is_null() { return Err(Error::Unknown); }
                return Ok(Vec::new());
            }
            q.sized()?; q.range(q.pointer, size_of::<NM::LOCALGROUP_USERS_INFO_0>())?;
            let info = unsafe { std::ptr::read_unaligned(q.pointer.cast::<NM::LOCALGROUP_USERS_INFO_0>()) };
            need(q.string(info.lgrui0_name, 256)? == self.users[..self.users.len() - 1])?;
            Ok(vec![builtin(545)])
        })();
        let freed = q.free();
        if freed.is_err() { return Err(Error::Unknown); }
        observed
    }
    fn create(&mut self, parent: &[u8], start: Instant, deadline_latched: &mut bool) -> Result<()> {
        if self.attempted { return Err(Error::State); }
        next_effect(start.elapsed(), deadline_latched)?;
        self.attempted = true; // Caller already registered durable private intent.
        need(self.query()?.is_none())?;
        let mut information = NM::USER_INFO_1::default();
        information.usri1_name = self.name.as_mut_ptr(); information.usri1_password = self.password.as_mut_ptr();
        information.usri1_priv = NM::USER_PRIV_USER;
        information.usri1_flags = NM::UF_SCRIPT | NM::UF_NORMAL_ACCOUNT;
        let mut parameter = 0u32;
        next_effect(start.elapsed(), deadline_latched)?;
        self.add = unsafe { NM::NetUserAdd(null(), 1, (&information as *const NM::USER_INFO_1).cast(), &mut parameter) };
        // Any creation error/ambiguity retains intent; never delete an account
        // selected merely by this name, reuse a collision, or retry creation.
        if self.add != 0 { return Err(Error::Unknown); }
        self.sid = self.query()?.ok_or(Error::Unknown)?;
        // A local creation cannot adopt an alias of the parent's identity or a
        // foreign/malformed SID before changing membership or granting rights.
        if !local_account_sid(&self.sid) || !local_account_sid(parent)
            || self.sid[..24] != parent[..24] || self.sid == parent {
            return Err(Error::Unknown);
        }
        if self.groups()?.is_empty() {
            let member = NM::LOCALGROUP_MEMBERS_INFO_0 { lgrmi0_sid: self.sid.as_mut_ptr().cast() };
            next_effect(start.elapsed(), deadline_latched)?;
            self.group_add = true;
            let status = unsafe { NM::NetLocalGroupAddMembers(null(), self.users.as_ptr(), 0,
                (&member as *const NM::LOCALGROUP_MEMBERS_INFO_0).cast(), 1) };
            if status != 0 { return Err(Error::Unknown); }
        }
        let groups = self.groups()?;
        need(fresh_account(self.absent, self.absent_pointer_null, self.add, &self.sid, &groups))?;
        next_effect(start.elapsed(), deadline_latched)
    }
    fn retire(&mut self, start: Instant, deadline_latched: &mut bool) -> Result<()> {
        next_effect(start.elapsed(), deadline_latched)?;
        need(self.attempted && self.add == 0 && !self.delete_attempted && !self.removed && !self.sid.is_empty()
            && self.password.iter().all(|unit| *unit == 0))?;
        // No name-only cleanup: immediately reobserve the actual returned SID.
        need(self.query()?.as_deref() == Some(self.sid.as_slice()) && self.groups()? == [builtin(545)])?;
        next_effect(start.elapsed(), deadline_latched)?;
        self.delete_attempted = true; // Irreversible intent, not a success receipt.
        self.delete_status = unsafe { NM::NetUserDel(null(), self.name.as_ptr()) };
        if self.delete_status != 0 || self.query()?.is_some() { return Err(Error::Unknown); }
        self.removed = true;
        next_effect(start.elapsed(), deadline_latched)
    }
}
impl Drop for Account {
    fn drop(&mut self) { self.zero(); } // Only owned memory, never OS/account cleanup.
}

#[derive(Clone)]
pub(super) struct Binding {
    source: String, tree: String, run: String, artifact: String,
    bytes: usize, sha: String, command_sha: String, identity: String,
}
impl Binding {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        need(raw.len() <= LIMIT && raw.is_ascii() && raw.ends_with(b"\n") && !raw.contains(&b'\r'))?;
        let text = std::str::from_utf8(raw).map_err(|_| Error::Unsafe)?;
        let lines: Vec<_> = text.lines().collect();
        need(lines.len() == 10 && lines[0] == "MRK_WINDOWS_ORDINARY_REQUEST_V1")?;
        let mut values = Vec::new();
        for (line, key) in lines[1..].iter().zip([
            "sourceSha", "sourceTree", "runId", "attempt", "artifact", "artifactBytes", "artifactSha256", "commandSha256", "artifactIdentity",
        ]) {
            let (name, value) = line.split_once('=').ok_or(Error::Unsafe)?;
            need(name == key && !value.is_empty())?; values.push(value);
        }
        need(is_hex(values[0], 40) && values[0] != "0".repeat(40) && is_hex(values[1], 40)
            && values[1] != "0".repeat(40) && decimal(values[2]) && values[3] == "1"
            && is_hex(values[6], 64) && is_hex(values[7], 64) && decimal(values[5]))?;
        fixed_path(values[4])?;
        let bytes = values[5].parse().map_err(|_| Error::Unsafe)?;
        need(bytes > 0 && bytes <= 128 << 20)?;
        let identity: Vec<_> = values[8].split(':').collect();
        need(identity.len() == 6 && is_hex(identity[1], 32) && identity[1] != "0".repeat(32)
            && decimal(identity[0]) && identity[0].parse::<u64>().is_ok()
            && identity[2..5].iter().all(|value| decimal(value) && value.parse::<i64>().is_ok())
            && decimal(identity[5]) && identity[5].parse::<u32>().is_ok())?;
        Ok(Self { source: values[0].to_owned(), tree: values[1].to_owned(), run: values[2].to_owned(),
            artifact: values[4].to_owned(), bytes, sha: values[6].to_owned(), command_sha: values[7].to_owned(),
            identity: values[8].to_owned() })
    }
    pub fn matches(&self, stamp: &Stamp) -> bool {
        stamp.wire() == self.identity && stamp.size == self.bytes as i64 && stamp.links == 1
    }
    fn compiled(&self) -> Result<()> {
        need(super::hosted_tests::hosted_source()? == self.source
            && option_env!("MRK_WINDOWS_SOURCE_TREE") == Some(self.tree.as_str())
            && option_env!("GITHUB_RUN_ID") == Some(self.run.as_str())
            && std::env::var("GITHUB_RUN_ID").as_deref() == Ok(self.run.as_str())
            && std::env::var("MRK_WINDOWS_SOURCE_TREE").as_deref() == Ok(self.tree.as_str()))
    }
    fn result(&self, sid_sha: &str) -> String {
        // The caller is ONLY the already-settled, exact-count positive branch.
        // File closure is gated by that original child's observed exit zero,
        // never asserted inside the bytes which precede their own close.
        format!("{{\"schemaVersion\":1,\"sourceSha\":\"{}\",\"sourceTree\":\"{}\",\"runId\":\"{}\",\"attempt\":1,\"artifactBytes\":{},\"artifactSha256\":\"{}\",\"commandSha256\":\"{}\",\"accountSidSha256\":\"{}\",\"test\":\"{CHILD}\",\"native\":{{\"context\":\"ordinary-admitted\",\"contextContracts\":1,\"admitted\":1,\"refused\":0,\"rootContracts\":1,\"rootNotExecuted\":0,\"primaryOriginals\":1,\"absentThreadReceipts\":6,\"closedOriginals\":2,\"unknown\":0,\"bookSettled\":true}},\"resultFile\":{{\"createNew\":true,\"writeCalls\":1,\"closeGate\":\"original-child-exit-zero-required\"}}}}\n",
            self.source, self.tree, self.run, self.bytes, self.sha, self.command_sha, sid_sha)
    }
}
fn args_are(target: &str, image: &Path) -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    need(args.len() == 6 && Path::new(&args[0]) == image && args[1] == target
        && args[2..].iter().map(String::as_str).eq(FLAGS))
}
fn write_one(path: &Path, raw: &[u8], limit: usize, security: *const S::SECURITY_ATTRIBUTES) -> Result<()> {
    let mut file = OriginalFile::new(path, false)?;
    let observation = (|| -> Result<()> {
        file.open(FS::FILE_GENERIC_WRITE | FS::FILE_READ_ATTRIBUTES, true, security)?;
        file.named(path)?; file.stamp()?;
        file.write(raw, limit)
    })();
    if matches!(observation, Err(Error::Unknown)) {
        diagnostic("result-original-operation", None, true);
        loop { std::thread::park(); std::hint::black_box((&mut file, security)); }
    }
    let closed = file.close();
    if closed.is_err() {
        diagnostic("result-original-close", None, true);
        loop { std::thread::park(); std::hint::black_box((&mut file, security)); }
    }
    observation
}
fn child_security(parent: &[u8], account: &[u8]) -> Result<(Box<Aligned>, Box<S::SECURITY_DESCRIPTOR>)> {
    // Only the single new result file. No inherited grant or standard Users ACE.
    let mut acl = Box::new(Aligned([0; BUFFER]));
    let principals = [(system_sid(), FS::FILE_ALL_ACCESS), (builtin(544), FS::FILE_ALL_ACCESS),
        (parent.to_vec(), FS::FILE_ALL_ACCESS), (account.to_vec(), FS::FILE_GENERIC_WRITE | FS::FILE_READ_ATTRIBUTES)];
    let size = 8 + principals.iter().map(|(sid, _)| 8 + sid.len()).sum::<usize>();
    need(size < BUFFER && size < u16::MAX as usize)?;
    acl.0[0] = 2; acl.0[2..4].copy_from_slice(&(size as u16).to_le_bytes());
    acl.0[4..6].copy_from_slice(&(principals.len() as u16).to_le_bytes());
    let mut at = 8;
    for (sid, rights) in principals {
        security::sid_at(&sid, 0, sid.len())?;
        let length = 8 + sid.len();
        acl.0[at + 2..at + 4].copy_from_slice(&(length as u16).to_le_bytes());
        acl.0[at + 4..at + 8].copy_from_slice(&rights.to_le_bytes());
        acl.0[at + 8..at + length].copy_from_slice(&sid); at += length;
    }
    let mut descriptor = Box::new(S::SECURITY_DESCRIPTOR::default());
    need(unsafe { S::InitializeSecurityDescriptor((&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(), 1) } != 0
        && unsafe { S::SetSecurityDescriptorDacl((&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(),
            1, acl.0.as_ptr().cast(), 0) } != 0
        && unsafe { S::SetSecurityDescriptorControl((&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(),
            S::SE_DACL_PROTECTED, S::SE_DACL_PROTECTED) } != 0)?;
    Ok((acl, descriptor))
}
pub(super) fn write_native_result(actual_user: &[u8]) -> Result<()> {
    let get = |name| std::env::var(name).map_err(|_| Error::State);
    let artifact = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    let image = artifact.to_str().ok_or(Error::Unsafe)?;
    fixed_path(image)?; args_are(CHILD, &artifact)?;
    let raw = format!("MRK_WINDOWS_ORDINARY_REQUEST_V1\nsourceSha={}\nsourceTree={}\nrunId={}\nattempt=1\nartifact={}\nartifactBytes={}\nartifactSha256={}\ncommandSha256={}\nartifactIdentity={}\n",
        get("GITHUB_SHA")?, get("MRK_WINDOWS_SOURCE_TREE")?, get("GITHUB_RUN_ID")?, image,
        get("MRK_WINDOWS_NATIVE_ARTIFACT_BYTES")?, get("MRK_WINDOWS_NATIVE_ARTIFACT_SHA256")?,
        get("MRK_WINDOWS_NATIVE_COMMAND_SHA256")?, get("MRK_WINDOWS_NATIVE_ARTIFACT_IDENTITY")?);
    let binding = Binding::parse(raw.as_bytes())?; binding.compiled()?;
    need(command_digest(image)? == binding.command_sha)?;
    let account = unhex(&get("MRK_WINDOWS_ORDINARY_SID")?)?;
    let parent = unhex(&get("MRK_WINDOWS_PARENT_SID")?)?;
    need(account == actual_user && account != parent && account != system_sid() && account != builtin(544))?;
    let output = fixed_path(&get("MRK_WINDOWS_ORDINARY_OUTPUT")?)?;
    need(std::env::current_dir().map_err(|_| Error::Unavailable)? == output
        && output.file_name().and_then(|s| s.to_str()) == Some("ordinary-output"))?;
    let mut file = OriginalFile::new(&artifact, false)?;
    let observation = (|| -> Result<()> {
        file.open(FS::FILE_GENERIC_READ, false, null())?; file.named(&artifact)?;
        need(binding.matches(&file.stamp()?))?;
        let raw = file.read(128 << 20)?;
        need(raw.len() == binding.bytes && digest(&raw)? == binding.sha)
    })();
    if matches!(observation, Err(Error::Unknown)) {
        loop { std::thread::park(); std::hint::black_box(&mut file); }
    }
    let closed = file.close();
    if closed.is_err() {
        loop { std::thread::park(); std::hint::black_box(&mut file); }
    }
    observation?;
    let value = binding.result(&digest(actual_user)?);
    need(value.len() <= LIMIT)?;
    let (acl, mut descriptor) = child_security(&parent, &account)?;
    let attributes = S::SECURITY_ATTRIBUTES { nLength: size_of::<S::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: (&mut *descriptor as *mut S::SECURITY_DESCRIPTOR).cast(), bInheritHandle: 0 };
    // Unknown parks inside write_one: this same stack still owns the complete
    // security inputs and child original; it never leaks then exits as "settled".
    let result = write_one(&output.join(RESULT), value.as_bytes(), LIMIT, &attributes);
    std::hint::black_box((&acl, &descriptor, &attributes));
    result
}

struct Launch {
    domain: [u16; 2], application: Vec<u16>, command: Vec<u16>, environment: Vec<u16>, directory: Vec<u16>,
    startup: T::STARTUPINFOW, outputs: T::PROCESS_INFORMATION,
    return_recorded: bool, returned: i32, error: u32, first_wait: u32,
    settle_wait: u32, first_wait_error: u32, settle_wait_error: u32, exit_output: u32, exit_return: i32,
    exit_error: u32, terminate_return: i32, terminate_error: u32,
    process_close: i32, process_close_error: u32, thread_close: i32, thread_close_error: u32,
    facts: ProcessFacts, _pin: PhantomPinned,
}
impl Launch {
    fn new(binding: &Binding, output: &Path, account: &Account, parent: &[u8]) -> Result<Pin<Box<Self>>> {
        let output = output.to_str().ok_or(Error::Unsafe)?;
        let system_root = std::env::var("SystemRoot").map_err(|_| Error::State)?;
        fixed_path(&system_root)?;
        let mut windows = [0u16; 32768];
        let count = unsafe { SI::GetSystemWindowsDirectoryW(windows.as_mut_ptr(), windows.len() as u32) };
        need(count > 0 && (count as usize) < windows.len()
            && String::from_utf16(&windows[..count as usize]).map_err(|_| Error::Unsafe)? == system_root)?;
        let mut environment = vec![
            ("GITHUB_ACTIONS", "true".to_owned()), ("GITHUB_RUN_ATTEMPT", "1".to_owned()),
            ("GITHUB_RUN_ID", binding.run.clone()), ("GITHUB_SHA", binding.source.clone()),
            ("ImageOS", "win25-vs2026".to_owned()), ("MRK_DESKTOP_HOSTED_CHECKS", "windows-installed-native-v1".to_owned()),
            ("MRK_WINDOWS_NATIVE_ARTIFACT_BYTES", binding.bytes.to_string()),
            ("MRK_WINDOWS_NATIVE_ARTIFACT_SHA256", binding.sha.clone()),
            ("MRK_WINDOWS_NATIVE_ARTIFACT_IDENTITY", binding.identity.clone()),
            ("MRK_WINDOWS_NATIVE_COMMAND_SHA256", binding.command_sha.clone()),
            ("MRK_WINDOWS_ORDINARY_OUTPUT", output.to_owned()), ("MRK_WINDOWS_ORDINARY_SID", hex(&account.sid)),
            ("MRK_WINDOWS_PARENT_SID", hex(parent)), ("MRK_WINDOWS_SOURCE_TREE", binding.tree.clone()),
            ("PATH", format!("{system_root}\\System32;{system_root}")), ("RUNNER_ARCH", "X64".to_owned()),
            ("RUNNER_ENVIRONMENT", "github-hosted".to_owned()), ("RUNNER_OS", "Windows".to_owned()),
            ("SystemRoot", system_root.clone()), ("TEMP", output.to_owned()), ("TMP", output.to_owned()),
            ("WINDIR", system_root),
        ];
        environment.sort_by_key(|(name, _)| name.to_ascii_uppercase());
        let environment: Vec<u16> = environment.iter().flat_map(|(name, value)| wide(&format!("{name}={value}")))
            .chain(std::iter::once(0)).collect();
        need(environment.len() <= 8192 && command(&binding.artifact).encode_utf16().count() <= 1023)?;
        let mut startup = T::STARTUPINFOW::default(); startup.cb = size_of::<T::STARTUPINFOW>() as u32;
        // lpDesktop=null explicitly inherits the actual desktop/station. Their
        // access is NOT precomputed, granted, or inferred from headlessness.
        // All flags/std handles remain zero: no profile, shell or redirection.
        Ok(Box::pin(Self { domain: [b'.' as u16, 0], application: wide(&binding.artifact), command: wide(&command(&binding.artifact)),
            environment, directory: wide(output), startup, outputs: T::PROCESS_INFORMATION::default(),
            return_recorded: false, returned: 0, error: 0, first_wait: u32::MAX,
            settle_wait: u32::MAX, first_wait_error: 0, settle_wait_error: 0, exit_output: 0,
            exit_return: 0, exit_error: 0, terminate_return: 0, terminate_error: 0,
            process_close: 0, process_close_error: 0, thread_close: 0, thread_close_error: 0,
            facts: ProcessFacts::new(), _pin: PhantomPinned }))
    }
    fn enter(self: Pin<&mut Self>, account: &mut Account, start: Instant, deadline_latched: &mut bool) -> Result<()> {
        let this = unsafe { self.get_unchecked_mut() };
        next_effect(start.elapsed(), deadline_latched)?;
        this.facts.begin()?;
        // Every UTF-16 input, full STARTUPINFO, complete initialized PI and
        // return/error destinations are owned/stable BEFORE this sole entry.
        this.returned = unsafe { T::CreateProcessWithLogonW(account.name.as_ptr(), this.domain.as_ptr(),
            account.password.as_ptr(), 0, this.application.as_ptr(), this.command.as_mut_ptr(),
            T::CREATE_UNICODE_ENVIRONMENT, this.environment.as_ptr().cast(), this.directory.as_ptr(),
            &this.startup, &mut this.outputs) };
        this.error = if this.returned == 0 { unsafe { F::GetLastError() } } else { 0 };
        this.return_recorded = true;
        // No allocation, formatting, new call or ownership adoption intervened.
        account.zero(); // Only now has its original plaintext borrower returned.
        this.facts.creation(this.returned != 0, this.error,
            (this.outputs.hProcess as usize, this.outputs.hThread as usize,
                this.outputs.dwProcessId, this.outputs.dwThreadId),
            start.elapsed() >= Duration::from_secs(NATIVE_SECONDS))
    }
    fn finish(self: Pin<&mut Self>, start: Instant) {
        let this = unsafe { self.get_unchecked_mut() };
        if !this.return_recorded || !this.facts.created { return; }
        if !this.facts.failed {
            let remaining = Duration::from_secs(NATIVE_SECONDS).saturating_sub(start.elapsed());
            if remaining.is_zero() { this.facts.failed = true; }
            else {
                this.first_wait = unsafe { T::WaitForSingleObject(this.outputs.hProcess,
                    remaining.as_millis().min(u128::from(u32::MAX - 1)) as u32) };
                this.first_wait_error = if this.first_wait == F::WAIT_FAILED { unsafe { F::GetLastError() } } else { 0 };
                let _ = this.facts.wait(this.first_wait, start.elapsed() >= Duration::from_secs(NATIVE_SECONDS));
            }
        }
        if !this.facts.signaled && this.facts.begin_terminate().is_ok() {
            this.terminate_return = unsafe { T::TerminateProcess(this.outputs.hProcess, 125) };
            this.terminate_error = if this.terminate_return == 0 { unsafe { F::GetLastError() } } else { 0 };
            if this.terminate_return == 0 { this.facts.unknown = true; }
            // Termination is asynchronous. Even its success is not finality.
            this.settle_wait = unsafe { T::WaitForSingleObject(this.outputs.hProcess, SETTLE_MS) };
            this.settle_wait_error = if this.settle_wait == F::WAIT_FAILED { unsafe { F::GetLastError() } } else { 0 };
            let _ = this.facts.wait(this.settle_wait, true);
        }
        if !this.facts.signaled { this.facts.unknown = true; return; }
        this.exit_return = unsafe { T::GetExitCodeProcess(this.outputs.hProcess, &mut this.exit_output) };
        this.exit_error = if this.exit_return == 0 { unsafe { F::GetLastError() } } else { 0 };
        let _ = this.facts.exited(this.exit_return != 0, this.exit_output);
        // Every borrower has returned before either once-only original close.
        if this.facts.begin_close(true).is_ok() {
            this.thread_close = unsafe { F::CloseHandle(this.outputs.hThread) };
            this.thread_close_error = if this.thread_close == 0 { unsafe { F::GetLastError() } } else { 0 };
            let _ = this.facts.closed(true, this.thread_close != 0);
        }
        if this.facts.begin_close(false).is_ok() {
            this.process_close = unsafe { F::CloseHandle(this.outputs.hProcess) };
            this.process_close_error = if this.process_close == 0 { unsafe { F::GetLastError() } } else { 0 };
            let _ = this.facts.closed(false, this.process_close != 0);
        }
    }
}

fn parent_user(book: &mut NativeBook) -> Result<Vec<u8>> {
    let index = book.process_token.ok_or(Error::State)?;
    let complete = book.token(index, S::TokenUser)?;
    let raw = complete.bytes(complete.count()?)?;
    need(raw.len() >= size_of::<S::TOKEN_USER>())?;
    let pointer = decode::u64_at(raw, offset_of!(S::TOKEN_USER, User) + offset_of!(S::SID_AND_ATTRIBUTES, Sid))? as usize;
    let offset = pointer.checked_sub(raw.as_ptr() as usize).ok_or(Error::Unsafe)?;
    need(offset >= size_of::<S::TOKEN_USER>())?;
    let sid = security::sid_at(raw, offset, raw.len())?.bytes().to_vec();
    need(sid.len() == 28 && sid != system_sid() && sid != builtin(544))?;
    Ok(sid)
}
fn diagnostic(stage: &str, launch: Option<&Launch>, unknown: bool) {
    use std::io::Write;
    let mut raw = [0u8; 768];
    let mut output = std::io::Cursor::new(raw.as_mut_slice());
    let (returned, error, exit) = launch.map_or((false, 0, None), |value|
        (value.return_recorded, value.error, value.facts.exit));
    let _ = write!(&mut output, "MRK_WINDOWS_ORDINARY_OWNER_REFUSED={{\"stage\":\"{stage}\",\"createReturned\":{returned},\"createError\":{error},\"exitCode\":");
    match exit { Some(code) => { let _ = write!(&mut output, "{code}"); },
        None => { let _ = write!(&mut output, "null"); } }
    if let Some(value) = launch {
        let _ = write!(&mut output, ",\"wait\":{},\"waitError\":{},\"settleWait\":{},\"settleError\":{},\"exitError\":{},\"terminateError\":{},\"processCloseError\":{},\"threadCloseError\":{}",
            value.first_wait, value.first_wait_error, value.settle_wait, value.settle_wait_error,
            value.exit_error, value.terminate_error, value.process_close_error, value.thread_close_error);
    }
    let _ = writeln!(&mut output, ",\"unknown\":{unknown},\"cleanupNotRetried\":true}}");
    let size = output.position() as usize;
    let _ = std::io::stdout().lock().write(&raw[..size.min(768)]);
}

#[test]
#[ignore = "one original-handle ordinary-account owner on its fixed disposable Windows hosted job"]
fn hosted_ordinary_original_handle_contract() -> Result<()> {
    let start = Instant::now();
    let mut deadline_latched = false;
    super::hosted_tests::hosted_source()?;
    let root_text = std::env::var("MRK_DESKTOP_CI_ROOT").map_err(|_| Error::State)?;
    let root = fixed_path(&root_text)?;
    let temp = fixed_path(&std::env::var("RUNNER_TEMP").map_err(|_| Error::State)?)?;
    let run = std::env::var("GITHUB_RUN_ID").map_err(|_| Error::State)?;
    need(decimal(&run) && root == temp.join(format!("mrk-windows-installed-native-{run}-1"))
        && std::env::current_dir().map_err(|_| Error::Unavailable)? == root)?;
    let image = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    args_are(OWNER, &image)?;
    let basename = image.file_name().and_then(|s| s.to_str()).ok_or(Error::Unsafe)?;
    let hash = basename.strip_prefix("mrk_windows_installed_native-").and_then(|s| s.strip_suffix(".exe")).ok_or(Error::Unsafe)?;
    need(is_hex(hash, 16) && image.parent() == Some(root.join("target/x86_64-pc-windows-msvc/debug/deps").as_path()))?;
    let mut files = Vec::with_capacity(40);
    let mut book = NativeBook::new();
    let mut parent_settlement_attempted = false; let mut parent_settled = false;
    let mut account: Option<Account> = None; let mut launch: Option<Pin<Box<Launch>>> = None;
    let mut transitions = Vec::with_capacity(7); let mut binding = None;
    let mut result_sha = String::new(); let mut sid_sha = String::new();
    let mut stage = "parent-context";
    let mut observation = (|| -> Result<()> {
        need(matches!(book.observe_user_once(), Err(Error::Unsafe)))?;
        let index = book.process_token.ok_or(Error::State)?;
        super::hosted_tests::actual_elevated_primary_refusal(&mut book, index)?;
        let parent = parent_user(&mut book)?;
        stage = "original-inputs";
        // Pin all actual ancestors against reparse/rename, but change ACLs ONLY
        // at/below this freshly owned root, never RUNNER_TEMP or an OS directory.
        let mut ancestors: Vec<_> = root.ancestors().map(Path::to_path_buf).collect();
        ancestors.reverse();
        need(ancestors.len() <= 24)?;
        let mut root_index = 0;
        for path in &ancestors {
            let access = FS::FILE_READ_ATTRIBUTES | FS::READ_CONTROL
                | if path == &root { FS::WRITE_DAC } else { 0 };
            let index = owned_file(&mut files, path, true, access)?;
            if path == &root { root_index = index; }
        }
        let request = owned_file(&mut files, &root.join(REQUEST), false, FS::FILE_GENERIC_READ)?;
        let data = files[request].read(LIMIT)?;
        let selected = Binding::parse(&data)?;
        selected.compiled()?;
        need(selected.run == run && Path::new(&selected.artifact) == image
            && command_digest(&selected.artifact)? == selected.command_sha)?;
        let mut directories = vec![(root_index, "root".to_owned())];
        for name in ["target", "target/x86_64-pc-windows-msvc", "target/x86_64-pc-windows-msvc/debug",
            "target/x86_64-pc-windows-msvc/debug/deps"] {
            let index = owned_file(&mut files, &root.join(name), true, FS::FILE_READ_ATTRIBUTES | FS::READ_CONTROL | FS::WRITE_DAC)?;
            directories.push((index, name.to_owned()));
        }
        let artifact = owned_file(&mut files, &image, false, FS::FILE_GENERIC_READ | FS::WRITE_DAC)?;
        let artifact_before = files[artifact].stamp()?;
        need(selected.matches(&artifact_before))?;
        let bytes = files[artifact].read(128 << 20)?;
        need(bytes.len() == selected.bytes && digest(&bytes)? == selected.sha)?;
        // Hash/read does not authorize adoption of another artifact or discard
        // original ChangeTime. The exact preflight identity must still match.
        need(files[artifact].stamp()? == artifact_before)?;
        stage = "account-intent";
        next_effect(start.elapsed(), &mut deadline_latched)?;
        account = Some(Account::new()?);
        let current = account.as_mut().ok_or(Error::State)?;
        let name = String::from_utf16(&current.name[..current.name.len() - 1]).map_err(|_| Error::Unsafe)?;
        let intent = format!("{{\"schemaVersion\":1,\"sourceSha\":\"{}\",\"runId\":\"{}\",\"attempt\":1,\"accountName\":\"{name}\",\"freshAccountIntent\":true,\"fixedNativeChildOnly\":true}}\n",
            selected.source, selected.run);
        next_effect(start.elapsed(), &mut deadline_latched)?;
        write_one(&root.join("ordinary-owner-intent.private.json"), intent.as_bytes(), LIMIT, null())?;
        stage = "fresh-account";
        current.create(&parent, start, &mut deadline_latched)?;
        need(current.sid != parent)?;
        next_effect(start.elapsed(), &mut deadline_latched)?;
        sid_sha = digest(&current.sid)?;
        stage = "exact-acl";
        let output = root.join("ordinary-output");
        let output_name = wide(output.to_str().ok_or(Error::Unsafe)?);
        // CreateDirectoryW is exclusive. Collision/error never adopts output.
        next_effect(start.elapsed(), &mut deadline_latched)?;
        let created = unsafe { FS::CreateDirectoryW(output_name.as_ptr(), null()) };
        let creation_error = if created != 0 { 0 } else { unsafe { F::GetLastError() } };
        if created == 0 {
            if creation_error == 0 || creation_error == F::ERROR_IO_PENDING {
                // Keep the original directory call's name on this same stack.
                diagnostic("output-original-create", None, true);
                loop { std::thread::park(); std::hint::black_box(&output_name); }
            }
            return Err(if creation_error == F::ERROR_ALREADY_EXISTS { Error::Unsafe } else { Error::Unavailable });
        }
        next_effect(start.elapsed(), &mut deadline_latched)?;
        let output_index = owned_file(&mut files, &output, true, FS::FILE_READ_ATTRIBUTES | FS::READ_CONTROL | FS::WRITE_DAC)?;
        for (index, role) in directories {
            transitions.push(grant(&mut files[index], &role, &parent, &current.sid, FS::FILE_TRAVERSE,
                start, &mut deadline_latched)?);
        }
        transitions.push(grant(&mut files[artifact], "artifact", &parent, &current.sid,
            FS::FILE_GENERIC_READ | FS::FILE_GENERIC_EXECUTE, start, &mut deadline_latched)?);
        let artifact_after = files[artifact].stamp()?;
        transitions.push(grant(&mut files[output_index], "ordinary-output", &parent, &current.sid,
            FS::FILE_ADD_FILE | FS::FILE_TRAVERSE | FS::FILE_READ_ATTRIBUTES | FS::SYNCHRONIZE,
            start, &mut deadline_latched)?);
        need(transitions.len() == 7)?;
        // This exact caller still has its original elevated primary, and no
        // impersonation. Close its NativeBook explicitly before original create.
        super::hosted_tests::actual_elevated_primary_refusal(&mut book, index)?;
        need(parent_user(&mut book)? == parent)?;
        parent_settlement_attempted = true;
        parent_settled = book.settle_once() == CloseOutcome::Settled && book.settled();
        need(parent_settled)?;
        stage = "preowned-create";
        let mut child = selected.clone(); child.identity = artifact_after.wire();
        launch = Some(Launch::new(&child, &output, current, &parent)?);
        next_effect(start.elapsed(), &mut deadline_latched)?;
        let original = launch.as_mut().ok_or(Error::State)?;
        let created = original.as_mut().enter(current, start, &mut deadline_latched);
        original.as_mut().finish(start); // Always settle a definitely owned pair.
        created?;
        need(original.facts.passed())?;
        next_effect(start.elapsed(), &mut deadline_latched)?;
        stage = "closed-native-result";
        let result = owned_file(&mut files, &output.join(RESULT), false, FS::FILE_GENERIC_READ)?;
        let raw = files[result].read(LIMIT)?;
        need(raw == selected.result(&sid_sha).as_bytes())?;
        result_sha = digest(&raw)?;
        need(files[artifact].stamp()? == artifact_after)?;
        next_effect(start.elapsed(), &mut deadline_latched)?;
        binding = Some(selected);
        Ok(())
    })();
    // No early ?/panic/Drop-as-close may skip this original settlement.
    if let Some(current) = account.as_mut() { current.zero(); }
    if !parent_settlement_attempted {
        parent_settlement_attempted = true;
        parent_settled = book.settle_once() == CloseOutcome::Settled && book.settled();
    }
    let process_unknown = launch.as_ref().is_some_and(|value|
        value.facts.unknown || value.facts.created && !value.facts.signaled);
    if process_unknown || !parent_settled || matches!(observation, Err(Error::Unknown)) {
        diagnostic(stage, launch.as_deref(), true);
        // Original worker/inputs/output slots stay reachable; no detached
        // borrower, account deletion, file cleanup or late-success promotion.
        loop { std::thread::park(); std::hint::black_box((&mut launch, &mut account, &mut book, &mut files)); }
    }
    let files_settled = close_files(&mut files);
    if !files_settled {
        diagnostic("original-file-close", launch.as_deref(), true);
        loop { std::thread::park(); std::hint::black_box((&mut launch, &mut account, &mut book, &mut files)); }
    }
    if next_effect(start.elapsed(), &mut deadline_latched).is_err() { observation = Err(Error::Unsafe); }
    if observation.is_err() {
        diagnostic(stage, launch.as_deref(), false);
        return observation;
    }
    let current = account.as_mut().ok_or(Error::State)?;
    // Only after original child wait/exit/handle closes, result read/close and
    // every native input original settlement; failure/Unknown retains account.
    let retired = current.retire(start, &mut deadline_latched);
    if matches!(retired, Err(Error::Unknown)) {
        diagnostic("account-original-retirement", launch.as_deref(), true);
        loop { std::thread::park(); std::hint::black_box((&mut launch, &mut account, &mut book, &mut files)); }
    }
    retired?;
    let current = account.as_ref().ok_or(Error::State)?;
    next_effect(start.elapsed(), &mut deadline_latched)?;
    need(current.removed && launch.as_ref().is_some_and(|value| value.facts.passed())
        && files.iter().all(|file| file.body.state == SlotState::Closed))?;
    let selected = binding.ok_or(Error::State)?;
    let original = launch.as_ref().ok_or(Error::State)?;
    let record = format!("{{\"schemaVersion\":1,\"sourceSha\":\"{}\",\"sourceTree\":\"{}\",\"runId\":\"{}\",\"attempt\":1,\"artifactBytes\":{},\"artifactSha256\":\"{}\",\"commandSha256\":\"{}\",\"accountSidSha256\":\"{}\",\"ownerTest\":\"{OWNER}\",\"childTest\":\"{CHILD}\",\"createCalls\":1,\"createReturn\":{},\"createError\":null,\"firstWait\":{},\"exitReturn\":{},\"originalExitCode\":{},\"terminateCalls\":0,\"processCloseReturn\":{},\"threadCloseReturn\":{},\"deadlineLatched\":false,\"unknown\":false,\"parentBookSettled\":true,\"inputOriginals\":{},\"inputOriginalsClosed\":{},\"freshAccountVerified\":true,\"onlyUsersMembership\":true,\"accountRemovedAfterSettlement\":true,\"nativeResultSha256\":\"{}\",\"aclTransitions\":[{}],\"ownerResult\":{{\"createNew\":true,\"writeCalls\":1,\"closeGate\":\"original-owner-exit-zero-required\"}},\"managedSourceMappingAuthenticated\":false,\"managedOrdinaryStartAuthorized\":false,\"protectedFullwalk\":false,\"productionEnabled\":false}}\n",
        selected.source, selected.tree, selected.run, selected.bytes, selected.sha, selected.command_sha, sid_sha,
        original.returned, original.first_wait, original.exit_return, original.exit_output,
        original.process_close, original.thread_close, files.len(), files.len(), result_sha, transitions.join(","));
    need(record.len() <= OWNER_LIMIT)?;
    next_effect(start.elapsed(), &mut deadline_latched)?;
    write_one(&root.join(OWNER_RESULT), record.as_bytes(), OWNER_LIMIT, null())?;
    // Even a late complete record is not admissible: original owner exit zero
    // is a separate mandatory gate, after its own write and original close.
    next_effect(start.elapsed(), &mut deadline_latched)
}
