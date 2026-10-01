//! Fixed Required Notes v1 wire DATA. Not an Image ABI extension or native permit.
//! Frames/keys/native custody live in the separate Notes owner.
//! This is the single native/bridge definition; no duplicate C ABI decoder. This module only
//! checks framing and copies already-owned DATA; it never performs an OS call.
use std::mem::{align_of, offset_of, size_of};

pub const VERSION: u32 = 1;
pub const INPUT_MAX: usize = 65_536;
pub const OUTPUT_MAX: usize = 65_536;
pub const PAGE_PAYLOAD_MAX: usize = OUTPUT_MAX - 64;
pub const BRIDGE_HEAP: usize = 524_288;
pub const RETURN_RESERVE: usize = 131_072;
pub const CALLS_PRODUCER: u64 = 65_536;
pub const CALLS_RECOVERY: u64 = 65_536;
pub const CALLS_FINALITY: u64 = 1_024;
pub const CALLS_TOTAL: u64 = CALLS_PRODUCER + CALLS_RECOVERY + CALLS_FINALITY;
pub const LAYOUT_TAG: u32 = 0x4e57_3131;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    Wire = 1, Bounds = 2, Owner = 3, Key = 4, Busy = 5, Thread = 6,
    OneUse = 7, Phase = 8, Stale = 9, Namespace = 10, Security = 11,
    Io = 12, Core = 13, Parser = 14, Capacity = 15, Incomplete = 16,
    Cancelled = 18, Deadline = 19, NativeUnavailable = 32, NativeUnsafe = 33,
    NativeBounds = 34, NativeState = 35, NativeUnknown = 36,
}
pub type Result<T> = std::result::Result<T, Fault>;
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status { Ok = 0, Eof = 1, Refused = 2, FailedKnown = 3, Unknown = 4, ExpectedCollision = 5 }

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    PrepareLease = 1, AcquireLease = 2, CheckLease = 3, EnterScope = 4,
    FreezeFixed = 5, FreezeVersion = 6, FreezeSelected = 7, AcquireDeclared = 8,
    SourceObservation = 9, BeginRead = 10, ReadNext = 11, BeginRoster = 12,
    RosterNext = 13, Presence = 14, RecheckSource = 15, CheckEpoch = 16,
    SettleScope = 17, FreezeApply = 18, BindControlBegin = 19,
    BindControlChunk = 20, BindControlFinish = 21, CreatePrivate = 22,
    WriteChunk = 23, FinishWrite = 24, FullFence = 25, Move = 26,
    FinishMove = 27, PublishSecurity = 28, RestoreSecurity = 29,
    FinishSecurity = 30, Delete = 31, CloseDeleted = 32, FinishDelete = 33,
    CloseOriginal = 34, RecordFailure = 35, BeginCompensation = 36,
    JoinCompensation = 37, BeginCommittedCleanup = 38, DataPage = 39,
    Retire = 40, ContextStatus = 41, ScopeStatus = 42,
}
impl TryFrom<u32> for Operation {
    type Error = Fault;
    fn try_from(n: u32) -> Result<Self> {
        Ok(match n {
            1 => Self::PrepareLease, 2 => Self::AcquireLease, 3 => Self::CheckLease,
            4 => Self::EnterScope, 5 => Self::FreezeFixed, 6 => Self::FreezeVersion,
            7 => Self::FreezeSelected, 8 => Self::AcquireDeclared, 9 => Self::SourceObservation,
            10 => Self::BeginRead, 11 => Self::ReadNext, 12 => Self::BeginRoster,
            13 => Self::RosterNext, 14 => Self::Presence, 15 => Self::RecheckSource,
            16 => Self::CheckEpoch, 17 => Self::SettleScope, 18 => Self::FreezeApply,
            19 => Self::BindControlBegin, 20 => Self::BindControlChunk, 21 => Self::BindControlFinish,
            22 => Self::CreatePrivate, 23 => Self::WriteChunk, 24 => Self::FinishWrite,
            25 => Self::FullFence, 26 => Self::Move, 27 => Self::FinishMove,
            28 => Self::PublishSecurity, 29 => Self::RestoreSecurity, 30 => Self::FinishSecurity,
            31 => Self::Delete, 32 => Self::CloseDeleted, 33 => Self::FinishDelete,
            34 => Self::CloseOriginal, 35 => Self::RecordFailure, 36 => Self::BeginCompensation,
            37 => Self::JoinCompensation, 38 => Self::BeginCommittedCleanup,
            39 => Self::DataPage, 40 => Self::Retire, 41 => Self::ContextStatus,
            42 => Self::ScopeStatus, _ => return Err(Fault::Wire),
        })
    }
}
impl Operation {
    pub fn primary_effect(self) -> bool {
        matches!(self, Self::CreatePrivate | Self::WriteChunk | Self::FullFence |
            Self::Move | Self::PublishSecurity | Self::RestoreSecurity | Self::Delete)
    }
    pub fn retained_data_only(self) -> bool {
        matches!(self, Self::DataPage | Self::ContextStatus | Self::ScopeStatus)
    }
    // This is a closed classification, NOT permission after an unreturned frame.
    // The separate owner must prove known callable supplier, independent original
    // finality frame, reserves/deadline, and definitely-known per-cell custody.
    pub fn independent_finality_kind(self) -> bool {
        matches!(self, Self::SettleScope | Self::CloseOriginal | Self::Retire |
            Self::DataPage | Self::ContextStatus | Self::ScopeStatus)
    }
    fn minimum_output(self) -> usize {
        match self {
            Self::PrepareLease | Self::EnterScope | Self::FreezeFixed |
            Self::FreezeVersion | Self::FreezeSelected | Self::FreezeApply => 128,
            Self::AcquireLease | Self::CheckLease | Self::SourceObservation | Self::RecheckSource => 332,
            Self::CheckEpoch => 627,
            Self::Presence => 427,
            Self::ReadNext | Self::RosterNext => OUTPUT_MAX,
            Self::FinishMove => 8 + 3 * (4 + 360 + 255),
            Self::FinishSecurity => 8 + 2 * (4 + 360 + 255),
            Self::SettleScope | Self::ScopeStatus => 64,
            Self::FinishDelete => 72,
            _ if self.primary_effect() => 80,
            _ => 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Request {
    pub size: u32, pub version: u32, pub operation: u32, pub reserved: u32,
    pub owner: u64, pub a: u64, pub b: u64, pub c: u64,
    pub number: u32, pub count: u32, pub input_len: u32, pub output_capacity: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Reply {
    pub size: u32, pub version: u32, pub status: u32, pub error: u32,
    pub owner: u64, pub token: u64, pub sequence: u64, pub epoch: u64,
    pub output_len: u32, pub count: u32, pub total: u32,
    pub flags: u32, pub first_failure: u32, pub reserved: [u32; 3],
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Info {
    pub scalars: [u32; 54],
    pub request_offsets: [u32; 12],
    pub reply_offsets: [u32; 14],
}
const _: () = assert!(size_of::<Request>() == 64 && align_of::<Request>() == 8);
const _: () = assert!(size_of::<Reply>() == 80 && align_of::<Reply>() == 8);
const _: () = assert!(size_of::<Info>() == 320 && align_of::<Info>() == 4);
pub fn info() -> Info {
    Info {
        scalars: [
            320, 1, 64, 80, 8, 8, 65_536, 65_536, 42, LAYOUT_TAG,
            3, 38, 38, 20, 38, 4_096, 2_048, 2_048, 128, 524_288,
            32_768, 65_536, 32_768, 32_768, 15_360, 7_680, 7_680,
            33_554_432, 1_114_112, 524_288, 131_072, 1_073_741_824,
            536_870_912, 536_870_912, 536_870_912, 524_288, 65_536,
            48, 42, 154, 23, 5, 11, 44, 12, 512, 255, 0, 0,
            132_096, 65_536, 65_536, 1_024, 0,
        ],
        request_offsets: [
            offset_of!(Request, size), offset_of!(Request, version), offset_of!(Request, operation),
            offset_of!(Request, reserved), offset_of!(Request, owner), offset_of!(Request, a),
            offset_of!(Request, b), offset_of!(Request, c), offset_of!(Request, number),
            offset_of!(Request, count), offset_of!(Request, input_len), offset_of!(Request, output_capacity),
        ].map(|n| n as u32),
        reply_offsets: [
            offset_of!(Reply, size), offset_of!(Reply, version), offset_of!(Reply, status),
            offset_of!(Reply, error), offset_of!(Reply, owner), offset_of!(Reply, token),
            offset_of!(Reply, sequence), offset_of!(Reply, epoch), offset_of!(Reply, output_len),
            offset_of!(Reply, count), offset_of!(Reply, total), offset_of!(Reply, flags),
            offset_of!(Reply, first_failure), offset_of!(Reply, reserved),
        ].map(|n| n as u32),
    }
}

pub mod flags {
    pub const NATIVE_UNKNOWN: u32 = 1;
    pub const NATIVE_RESOURCES_SETTLED: u32 = 2;
    pub const EFFECTS_FINAL: u32 = 4;
    pub const PRIMITIVES_ENTERED: u32 = 8;
    pub const ALL_ENTERED_RETURNED: u32 = 16;
    pub const BRIDGE_FRAME_UNKNOWN: u32 = 32;
    pub const LEASE_BEGUN: u32 = 64;
    pub const SCOPE_SETTLED: u32 = 128;
    pub const COMPENSATION_CHOSEN: u32 = 256;
    pub const COMMITTED_CLEANUP_CHOSEN: u32 = 512;
    pub const COMMITTED: u32 = 1024;
    pub const RETIREMENT_ATTEMPTED: u32 = 2048;
    pub const ROLLED_BACK: u32 = 4096;
    pub const ALL: u32 = 8191;
}

fn require(ok: bool, error: Fault) -> Result<()> { if ok { Ok(()) } else { Err(error) } }
fn zero(values: &[u64]) -> Result<()> { require(values.iter().all(|v| *v == 0), Fault::Wire) }
fn nonzero(values: &[u64]) -> Result<()> { require(values.iter().all(|v| *v != 0), Fault::Key) }
fn scope(n: u32) -> Result<()> { require((1..=3).contains(&n), Fault::Wire) }
impl Request {
    pub fn header(&self, actual_input: usize, actual_output: usize) -> Result<Operation> {
        require(self.size == 64 && self.version == VERSION && self.reserved == 0, Fault::Wire)?;
        require(self.input_len as usize == actual_input && self.output_capacity as usize == actual_output,
            Fault::Wire)?;
        require(actual_input <= INPUT_MAX && actual_output <= OUTPUT_MAX, Fault::Bounds)?;
        let operation = Operation::try_from(self.operation)?;
        require(actual_output >= operation.minimum_output(), Fault::Capacity)?;
        require((operation == Operation::PrepareLease) == (self.owner == 0), Fault::Owner)?;
        Ok(operation)
    }
    // Native typed lookup, current-scope/lifetime checks and semantic path policy
    // remain mandatory AFTER this scalar frame check. Header sequence is not a
    // capability and no key is constructed here.
    pub fn operands(&self, op: Operation, input: &[u8]) -> Result<()> {
        require(self.operation == op as u32 && input.len() == self.input_len as usize, Fault::Wire)?;
        let number = self.number as u64;
        let count = self.count as u64;
        let empty = || require(input.is_empty(), Fault::Wire);
        match op {
            Operation::PrepareLease => {
                zero(&[self.a, self.b, self.c, number, count])?;
                RootBinding::parse(input).map(|_| ())
            }
            Operation::AcquireLease | Operation::CheckLease |
            Operation::JoinCompensation | Operation::Retire | Operation::ContextStatus => {
                zero(&[self.a, self.b, self.c, number, count])?; empty()
            }
            Operation::EnterScope | Operation::SettleScope | Operation::ScopeStatus => {
                zero(&[self.a, self.b, self.c, count])?; scope(self.number)?; empty()
            }
            Operation::FreezeFixed | Operation::BeginRead | Operation::BeginRoster |
            Operation::ReadNext | Operation::RosterNext | Operation::FinishWrite |
            Operation::FullFence | Operation::PublishSecurity | Operation::RestoreSecurity |
            Operation::CloseDeleted | Operation::CloseOriginal | Operation::BeginCommittedCleanup |
            Operation::BindControlFinish => {
                nonzero(&[self.a])?; zero(&[self.b, self.c, number, count])?; empty()
            }
            Operation::FreezeVersion => {
                nonzero(&[self.a, self.b])?; zero(&[self.c, count])?;
                match self.number { 0 => empty(), 1 => relative(input).map(|_| ()), _ => Err(Fault::Wire) }
            }
            Operation::FreezeSelected => {
                nonzero(&[self.a, self.b])?;
                require((1..=5).contains(&self.number) && self.count <= 1, Fault::Wire)?;
                let mut c = Cursor::new(input);
                let selected_len = c.u32()? as usize; let counterpart_len = c.u32()? as usize;
                let selected = relative(c.bytes(selected_len)?)?;
                let counterpart = c.bytes(counterpart_len)?;
                require((self.count == 0) == counterpart.is_empty(), Fault::Wire)?;
                if self.count == 1 {
                    require(self.number <= 2, Fault::Wire)?;
                    let other = relative(counterpart)?;
                    require(selected != other && selected.rsplit_once('/').map(|v| v.0)
                        == other.rsplit_once('/').map(|v| v.0), Fault::Wire)?;
                }
                c.finish()
            }
            Operation::AcquireDeclared | Operation::SourceObservation | Operation::Presence |
            Operation::Move | Operation::CreatePrivate | Operation::FinishDelete => {
                nonzero(&[self.a, self.b])?; zero(&[self.c, number, count])?; empty()
            }
            Operation::RecheckSource | Operation::CheckEpoch => {
                nonzero(&[self.a, self.b, self.c])?; zero(&[number, count])?; empty()
            }
            Operation::FreezeApply => {
                nonzero(&[self.a, self.b])?; zero(&[self.c, count])?;
                match self.number {
                    0 => empty(),
                    1 | 2 => size_digest(input, 65_536).map(|_| ()),
                    _ => Err(Fault::Wire),
                }
            }
            Operation::BindControlBegin => {
                nonzero(&[self.a])?; zero(&[self.b, self.c, number, count])?;
                size_digest(input, 524_288).map(|_| ())
            }
            Operation::BindControlChunk => {
                nonzero(&[self.a])?; zero(&[self.b, self.c, count])?;
                require(!input.is_empty() && self.number <= 524_288, Fault::Bounds)
            }
            Operation::WriteChunk => {
                nonzero(&[self.a])?; zero(&[self.b, self.c, number, count])?;
                require(!input.is_empty(), Fault::Wire)
            }
            Operation::FinishMove => {
                nonzero(&[self.a, self.b, self.c])?; zero(&[number, count])?;
                let mut c = Cursor::new(input); nonzero(&[c.u64()?])?; c.finish()
            }
            Operation::FinishSecurity => {
                nonzero(&[self.a, self.b, self.c])?; zero(&[count])?;
                require(self.number == 1 || self.number == 2, Fault::Wire)?; empty()
            }
            Operation::Delete => {
                nonzero(&[self.a])?; zero(&[self.c, number, count])?; empty()
            }
            Operation::RecordFailure => {
                zero(&[self.a, self.b, self.c, count])?;
                require(matches!(self.number, 13 | 14 | 18 | 19), Fault::Wire)?; empty()
            }
            Operation::BeginCompensation => {
                zero(&[self.c, count])?; empty()?;
                match self.number {
                    1 => zero(&[self.a, self.b]),
                    2 => nonzero(&[self.a, self.b]),
                    _ => Err(Fault::Wire),
                }
            }
            Operation::DataPage => {
                nonzero(&[self.b])?; zero(&[self.c])?; empty()?;
                require((1..=8).contains(&self.number) && (1..=PAGE_PAYLOAD_MAX as u32).contains(&self.count),
                    Fault::Wire)?;
                require(self.output_capacity as usize >= 64 + self.count as usize, Fault::Capacity)
            }
        }
    }
}

pub struct RootBinding<'a> { pub volume: u64, pub file_id: [u8; 16], pub root: &'a str }
impl<'a> RootBinding<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let mut c = Cursor::new(bytes);
        require(c.bytes(8)? == b"MRKNLS1\0" && c.u32()? == 48 && c.u32()? == 0, Fault::Wire)?;
        let volume = c.u64()?; let file_id: [u8; 16] = c.bytes(16)?.try_into().map_err(|_| Fault::Wire)?;
        let len = c.u32()? as usize; require(c.u32()? == 0 && len <= 11_266, Fault::Bounds)?;
        let raw = c.bytes(len)?; c.finish()?;
        require(file_id != [0; 16] && raw.len() > 3 && raw[0].is_ascii_alphabetic()
            && raw[1] == b':' && raw[2] == b'\\' && !raw.contains(&0), Fault::Wire)?;
        let root = std::str::from_utf8(raw).map_err(|_| Fault::Wire)?;
        require(root[3..].split('\\').count() <= 44 && root[3..].split('\\').all(component), Fault::Wire)?;
        Ok(Self { volume, file_id, root })
    }
}
pub fn relative(bytes: &[u8]) -> Result<&str> {
    require(!bytes.is_empty() && bytes.len() <= 512, Fault::Bounds)?;
    let value = std::str::from_utf8(bytes).map_err(|_| Fault::Wire)?;
    require(value.split('/').count() <= 12 && value.split('/').all(component), Fault::Wire)?;
    Ok(value)
}
// Same finite native component spelling policy. Complete roster NFC/casefold
// alias checks still belong to the original source pass, never this byte parser.
pub fn component(value: &str) -> bool {
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
pub fn size_digest(input: &[u8], maximum: u64) -> Result<(u64, [u8; 32])> {
    let mut c = Cursor::new(input); let bytes = c.u64()?;
    let digest = c.bytes(32)?.try_into().map_err(|_| Fault::Wire)?; c.finish()?;
    require(bytes <= maximum, Fault::Bounds)?; Ok((bytes, digest))
}
pub struct Cursor<'a> { input: &'a [u8], at: usize }
impl<'a> Cursor<'a> {
    pub fn new(input: &'a [u8]) -> Self { Self { input, at: 0 } }
    pub fn bytes(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(count).ok_or(Fault::Bounds)?;
        let bytes = self.input.get(self.at..end).ok_or(Fault::Wire)?;
        self.at = end; Ok(bytes)
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into().map_err(|_| Fault::Wire)?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.bytes(8)?.try_into().map_err(|_| Fault::Wire)?))
    }
    pub fn finish(&self) -> Result<()> { require(self.at == self.input.len(), Fault::Wire) }
}
pub struct Encoder<'a> { data: &'a mut [u8], at: usize }
impl<'a> Encoder<'a> {
    pub fn new(data: &'a mut [u8]) -> Self { Self { data, at: 0 } }
    pub fn bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self.at.checked_add(bytes.len()).ok_or(Fault::Bounds)?;
        self.data.get_mut(self.at..end).ok_or(Fault::Capacity)?.copy_from_slice(bytes);
        self.at = end; Ok(())
    }
    pub fn u32(&mut self, value: u32) -> Result<()> { self.bytes(&value.to_le_bytes()) }
    pub fn u64(&mut self, value: u64) -> Result<()> { self.bytes(&value.to_le_bytes()) }
    pub fn i64(&mut self, value: i64) -> Result<()> { self.bytes(&value.to_le_bytes()) }
    pub fn len(&self) -> usize { self.at }
}

// No failure returns a partial factory/observation/read/roster/page/scope batch.
// The sole exception is one whole primary Effect80 if that original frame was
// actually entered. Failed22 MUST NOT return a PendingEpoch token.
pub fn failure_payload(op: Operation, status: Status, primary_entered: bool,
    primary_effect: Option<&[u8; 80]>, typed_operand: u64, output: &mut [u8]) -> Result<(u64, u32)> {
    require(matches!(status, Status::Refused | Status::FailedKnown | Status::Unknown), Fault::Wire)?;
    if status == Status::Refused {
        require(!primary_entered && primary_effect.is_none(), Fault::Wire)?;
        return Ok((0, 0));
    }
    if !primary_entered {
        require(primary_effect.is_none(), Fault::Wire)?; return Ok((0, 0));
    }
    require(op.primary_effect(), Fault::Wire)?;
    let effect = primary_effect.ok_or(Fault::Incomplete)?;
    require(&effect[..8] == b"MRKNEF1\0", Fault::Wire)?;
    let mut writer = Encoder::new(output); writer.bytes(effect)?;
    Ok((if op == Operation::CreatePrivate { 0 } else { typed_operand }, 80))
}

pub struct Page<'a> {
    pub kind: u32, pub owner: u64, pub scope: u32, pub key: u64,
    pub offset: u64, pub complete: &'a [u8],
}
impl Page<'_> {
    // complete is the already-owned original representation. This never queries
    // a descriptor or assembles a complete 32MiB object in the bridge heap.
    pub fn encode(&self, requested: u32, output: &mut [u8]) -> Result<usize> {
        require((1..=8).contains(&self.kind) && self.owner != 0 && self.key != 0 && self.scope <= 3, Fault::Key)?;
        require((1..=PAGE_PAYLOAD_MAX as u32).contains(&requested), Fault::Bounds)?;
        require(output.len() >= 64 + requested as usize, Fault::Capacity)?;
        let offset = usize::try_from(self.offset).map_err(|_| Fault::Bounds)?;
        let tail = self.complete.get(offset..).ok_or(Fault::Bounds)?;
        let n = tail.len().min(requested as usize); let mut w = Encoder::new(output);
        w.bytes(b"MRKNDP1\0")?; w.u32(64)?; w.u32(self.kind)?; w.u64(self.owner)?;
        w.u32(self.scope)?; w.u32(0)?; w.u64(self.key)?; w.u64(self.offset)?;
        w.u64(u64::try_from(self.complete.len()).map_err(|_| Fault::Bounds)?)?;
        w.u32(n as u32)?; w.u32(0)?; w.bytes(&tail[..n])?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_layout_and_reserved_no_security_caps() {
        let i = info(); assert_eq!(i.scalars.len(), 54);
        assert_eq!(i.scalars[47], 0); assert_eq!(i.scalars[48], 0); assert_eq!(i.scalars[53], 0);
        assert_eq!(i.request_offsets, [0,4,8,12,16,24,32,40,48,52,56,60]);
        assert_eq!(i.reply_offsets, [0,4,8,12,16,24,32,40,48,52,56,60,64,68]);
        assert_eq!(CALLS_TOTAL, 132_096);
    }
    #[test]
    fn removed_lease_operands_and_scope_a_are_rejected() {
        let mut r = Request { operation: 2, owner: 1, a: 1, ..Request::default() };
        assert_eq!(r.operands(Operation::AcquireLease, &[]), Err(Fault::Wire));
        r.operation = 17; r.number = 1;
        assert_eq!(r.operands(Operation::SettleScope, &[]), Err(Fault::Wire));
        r.a = 0; assert_eq!(r.operands(Operation::SettleScope, &[]), Ok(()));
    }
    #[test]
    fn data_page_count_is_requested_bytes_not_zero_or_record_index() {
        let r = Request { operation: 39, owner: 9, b: 12, number: 7, count: 3,
            output_capacity: 67, ..Request::default() };
        assert_eq!(r.operands(Operation::DataPage, &[]), Ok(()));
        let mut bad = r; bad.count = 0;
        assert_eq!(bad.operands(Operation::DataPage, &[]), Err(Fault::Wire));
        let mut output = [0u8; 67];
        let p = Page { kind: 7, owner: 9, scope: 3, key: 12, offset: 2, complete: b"abc" };
        assert_eq!(p.encode(3, &mut output), Ok(1));
        assert_eq!(&output[64..65], b"c");
    }
}
