//! Private SOURCE-only B1 adapter over the original image primitive book.
//! NOT a transaction engine, installed activation, security setter or pipe owner.
//! The fixed Python caller is trusted in-process code: it must supply live,
//! correctly sized, nonoverlapping buffers through the synchronous return.
//! Pointer range checks cannot prove arbitrary C pointers valid. No HANDLE,
//! access mask, native class, callback or path after Prepare crosses this ABI.
//!
//! SLOT is the strong original owner, not a finalizer or replacement lease.
//! It is never taken/dropped, including after panic/UNKNOWN/positive retirement.
//! One pinned reusable frame is recycled only after known synchronous return.
//! The caller retains the DLL; later B2 must retain child/loader/pipe originals.
//! Native16MiB and its unchanged counts are separate from the explicit <=512KiB
//! bridge allocation allowance (including returned DATA); neither is installer
//! memory. Python caller byte buffers have a separate fixed 512KiB allowance.
#![cfg(all(target_os = "windows", target_arch = "x86_64", target_env = "msvc"))]
#![deny(unsafe_op_in_unsafe_fn)]

use mrk_windows_installed_native::{
    image_writer::{ImagePrimitives, ImageKey, PassKey, MoveKey, DeleteKey, ImageRole,
        PlannedChild, PlannedEdge, PlannedMove, PlannedDelete, EffectKind, NativeReturn,
        PassKind, MoveReceipt, DeletionReceipt},
    CloseOutcome, DirectoryEntry, Error, FileIdentity, FileKind,
};
use std::marker::PhantomPinned;
use std::mem::{align_of, offset_of, size_of};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::{Mutex, TryLockError};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::ThreadId;

// A distinct fixed stdio-v1 ABI; the writer's 18-operation wire remains unchanged.
mod stdio;

// Distinct closed Notes42 ABI; no Image/stdin operation is extended.
#[cfg(feature = "required-notes")]
mod required_notes;

const VERSION: u32 = 1;
const INPUT_MAX: usize = 65_536;
const OUTPUT_MAX: usize = 65_536;
const CHILDREN: usize = 38; // The primitive additionally charges project ancestors.
const MOVES: usize = 16;
const DELETES: usize = 38;
const PASSES: usize = 32;
const PAGE: usize = 128;
const BRIDGE_HEAP: usize = 512 * 1024;
const RETURN_RESERVE: usize = 128 * 1024;
const CALLS: u64 = 16_384;
const FINAL_CALLS: u64 = 64;
const LAYOUT_TAG: u32 = 0x4957_3131;
const OK: u32 = 0;
const EOF: u32 = 1;
const REFUSED: u32 = 2;
const FAILED: u32 = 3;
const UNKNOWN: u32 = 4;
const WIRE: u32 = 1;
const BOUNDS: u32 = 2;
const OWNER: u32 = 3;
const TOKEN: u32 = 4;
const BUSY: u32 = 5;
const THREAD: u32 = 6;
const USED: u32 = 7;
const NATIVE_UNKNOWN: u32 = 1;
const HANDLES_SETTLED: u32 = 2;
const EFFECTS_FINAL: u32 = 4;
const PRIMITIVE_ENTERED: u32 = 8; // NOT proof a particular native effect entered.
const PRIMITIVE_RETURNED: u32 = 16;
const BRIDGE_UNKNOWN: u32 = 32;
const OWNER_BEGUN: u32 = 64;

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
    pub output_len: u32, pub count: u32, pub total: u32, pub flags: u32,
    pub first_failure: u32, pub reserved: [u32; 3],
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Info {
    pub size: u32, pub version: u32, pub request_size: u32, pub reply_size: u32,
    pub request_align: u32, pub reply_align: u32, pub input_max: u32, pub output_max: u32,
    pub max_children: u32, pub max_moves: u32, pub max_deletes: u32, pub max_passes: u32,
    pub bridge_heap_max: u32, pub operations: u32, pub layout_tag: u32, pub reserved: u32,
    pub request_offsets: [u32; 12], pub reply_offsets: [u32; 14],
}
const _: () = assert!(size_of::<Request>() == 64 && align_of::<Request>() == 8);
const _: () = assert!(size_of::<Reply>() == 80 && align_of::<Reply>() == 8);
const _: () = assert!(size_of::<Info>() == 168 && align_of::<Info>() == 4);

fn info() -> Info {
    Info {
        size: size_of::<Info>() as u32, version: VERSION,
        request_size: size_of::<Request>() as u32, reply_size: size_of::<Reply>() as u32,
        request_align: align_of::<Request>() as u32, reply_align: align_of::<Reply>() as u32,
        input_max: INPUT_MAX as u32, output_max: OUTPUT_MAX as u32,
        max_children: CHILDREN as u32, max_moves: MOVES as u32,
        max_deletes: DELETES as u32, max_passes: PASSES as u32,
        bridge_heap_max: BRIDGE_HEAP as u32, operations: 18, layout_tag: LAYOUT_TAG, reserved: 0,
        request_offsets: [offset_of!(Request, size), offset_of!(Request, version),
            offset_of!(Request, operation), offset_of!(Request, reserved),
            offset_of!(Request, owner), offset_of!(Request, a), offset_of!(Request, b),
            offset_of!(Request, c), offset_of!(Request, number), offset_of!(Request, count),
            offset_of!(Request, input_len), offset_of!(Request, output_capacity)].map(|n| n as u32),
        reply_offsets: [offset_of!(Reply, size), offset_of!(Reply, version),
            offset_of!(Reply, status), offset_of!(Reply, error), offset_of!(Reply, owner),
            offset_of!(Reply, token), offset_of!(Reply, sequence), offset_of!(Reply, epoch),
            offset_of!(Reply, output_len), offset_of!(Reply, count), offset_of!(Reply, total),
            offset_of!(Reply, flags), offset_of!(Reply, first_failure),
            offset_of!(Reply, reserved)].map(|n| n as u32),
    }
}
fn reply(status: u32, error: u32) -> Reply {
    Reply { size: size_of::<Reply>() as u32, version: VERSION, status, error, ..Reply::default() }
}
fn native_error(error: Error) -> u32 {
    match error { Error::Unavailable => 32, Error::Unsafe => 33,
        Error::Bounds => 34, Error::State => 35, Error::Unknown => 36 }
}
fn reserve<T>(count: usize, maximum: usize) -> Result<Vec<T>, u32> {
    if count > maximum { return Err(BOUNDS); }
    let mut value = Vec::new();
    value.try_reserve_exact(count).map_err(|_| BOUNDS)?;
    if value.capacity() > maximum { return Err(BOUNDS); }
    Ok(value)
}
struct Cursor<'a> { data: &'a [u8], at: usize }
impl<'a> Cursor<'a> {
    fn bytes(&mut self, count: usize) -> Result<&'a [u8], u32> {
        let end = self.at.checked_add(count).ok_or(BOUNDS)?;
        let value = self.data.get(self.at..end).ok_or(WIRE)?; self.at = end; Ok(value)
    }
    fn u32(&mut self) -> Result<u32, u32> {
        let bytes: [u8; 4] = self.bytes(4)?.try_into().map_err(|_| WIRE)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn index(&mut self) -> Result<u16, u32> { u16::try_from(self.u32()?).map_err(|_| BOUNDS) }
    fn text(&mut self, maximum: usize) -> Result<String, u32> {
        let count = self.u32()? as usize;
        if count == 0 || count > maximum { return Err(BOUNDS); }
        let value = self.bytes(count)?;
        if !value.is_ascii() || value.contains(&0) { return Err(WIRE); }
        let mut owned = reserve(count, maximum)?; owned.extend_from_slice(value);
        String::from_utf8(owned).map_err(|_| WIRE)
    }
}
struct Plan {
    project: String, children: Vec<PlannedChild>,
    moves: Vec<PlannedMove>, deletes: Vec<PlannedDelete>,
}
fn role(value: u32) -> Result<ImageRole, u32> {
    Ok(match value {
        1 => ImageRole::ExistingDirectory, 2 => ImageRole::MutationParent,
        3 => ImageRole::Config, 4 => ImageRole::IgnoreFile, 5 => ImageRole::UnchangedImage,
        6 => ImageRole::ReplaceTarget, 7 => ImageRole::PrivateDirectory,
        8 => ImageRole::ControlFile, 9 => ImageRole::StagedImage,
        10 => ImageRole::StagedDirectory, _ => return Err(WIRE),
    })
}
fn plan(data: &[u8]) -> Result<Plan, u32> {
    if data.len() > INPUT_MAX { return Err(BOUNDS); }
    let mut c = Cursor { data, at: 0 };
    if c.bytes(8)? != b"MRKIW1\0\0" { return Err(WIRE); }
    let child_count = c.u32()? as usize; let move_count = c.u32()? as usize;
    let delete_count = c.u32()? as usize;
    let mut children = reserve(child_count, CHILDREN)?;
    let mut moves = reserve(move_count, MOVES)?;
    let mut deletes = reserve(delete_count, DELETES)?;
    let project = c.text(32_768)?;
    for _ in 0..child_count {
        children.push(PlannedChild { parent: c.index()?, role: role(c.u32()?)?, name: c.text(255)? });
    }
    for _ in 0..move_count {
        let source = c.index()?;
        let from = PlannedEdge { parent: c.index()?, name: c.text(255)? };
        let to = PlannedEdge { parent: c.index()?, name: c.text(255)? };
        moves.push(PlannedMove { source, from, to });
    }
    for _ in 0..delete_count {
        deletes.push(PlannedDelete { source: c.index()?,
            at: PlannedEdge { parent: c.index()?, name: c.text(255)? } });
    }
    if c.at != data.len() { return Err(WIRE); }
    Ok(Plan { project, children, moves, deletes })
}
struct Encoder<'a> { data: &'a mut [u8], at: usize }
impl Encoder<'_> {
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), u32> {
        let end = self.at.checked_add(bytes.len()).ok_or(BOUNDS)?;
        self.data.get_mut(self.at..end).ok_or(BOUNDS)?.copy_from_slice(bytes);
        self.at = end; Ok(())
    }
    fn u32(&mut self, n: u32) -> Result<(), u32> { self.bytes(&n.to_le_bytes()) }
    fn u64(&mut self, n: u64) -> Result<(), u32> { self.bytes(&n.to_le_bytes()) }
    fn i64(&mut self, n: i64) -> Result<(), u32> { self.bytes(&n.to_le_bytes()) }
    fn identity(&mut self, id: FileIdentity) -> Result<(), u32> {
        self.u64(id.volume_serial)?; self.bytes(&id.file_id)
    }
}
struct Key<K> { value: u64, key: K }
struct Pass {
    value: u64, key: Option<PassKey>, image: usize, generation: u16,
    kind: u32, complete: bool,
}
fn pass_matches(pass: &Pass, value: u64, kind: u32, complete: bool, latest: u16) -> bool {
    pass.value == value && pass.kind == kind && pass.complete == complete && pass.generation == latest
}
enum Value {
    Unit, Token(u64), Read(Option<Vec<u8>>), Roster(Option<Vec<DirectoryEntry>>),
    Move(MoveReceipt), Deleted(DeletionReceipt), Retired(CloseOutcome),
}
struct Frame {
    request: Request, input: Vec<u8>, output: Vec<u8>,
    result: Option<Result<Value, Error>>, receipt: Reply,
    phase: u8, // 0 unentered, 1 entered, 2 actual return, 3 UNKNOWN (never reset)
    _pin: PhantomPinned,
}
impl Frame {
    fn new() -> Result<Pin<Box<Self>>, u32> {
        let mut input = reserve(INPUT_MAX, INPUT_MAX)?; input.resize(INPUT_MAX, 0);
        let mut output = reserve(OUTPUT_MAX, OUTPUT_MAX)?; output.resize(OUTPUT_MAX, 0);
        Ok(Box::pin(Self { request: Request::default(), input, output, result: None,
            receipt: reply(OK, 0), phase: 0, _pin: PhantomPinned }))
    }
}
struct Owner {
    id: u64, thread: ThreadId, native: ImagePrimitives,
    images: Vec<Key<ImageKey>>, moves: Vec<Key<MoveKey>>, deletes: Vec<Key<DeleteKey>>,
    passes: [Option<Pass>; PASSES], latest: [u16; CHILDREN + 1],
    pass_count: usize, next_token: u64, sequence: u64,
    begun: bool, retire_attempted: bool, unknown: bool, frame: Pin<Box<Frame>>,
}
#[derive(Clone, Copy)]
enum Call {
    Begin, Acquire(usize), BeginRead(usize), BeginRoster(usize),
    Read(usize), Roster(usize), Write(usize), FinishWrite(usize), Fence(usize),
    Rename(usize, usize), FinishMove(usize, usize, usize),
    Dispose(usize, Option<usize>), CloseDisposed(usize), FinishDeletion(usize, usize),
    Close(usize), Retire, Observe(u32, usize, usize),
}
impl Owner {
    fn prepare(plan: &Plan, id: u64) -> Result<Box<Self>, u32> {
        // All allocation/key creation below is before begin_once: no native book
        // has entered and a constructor failure cannot abandon a native effect.
        let native = ImagePrimitives::prepare_lifecycle(
            &plan.project, &plan.children, &plan.moves, &plan.deletes).map_err(native_error)?;
        let mut images = reserve(plan.children.len() + 1, CHILDREN + 1)?;
        let mut moves = reserve(plan.moves.len(), MOVES)?;
        let mut deletes = reserve(plan.deletes.len(), DELETES)?;
        let mut next = 1u64;
        for n in 0..=plan.children.len() {
            images.push(Key { value: next, key: native.key(n as u16).map_err(native_error)? }); next += 1;
        }
        for n in 0..plan.moves.len() {
            moves.push(Key { value: next, key: native.move_key(n as u16).map_err(native_error)? }); next += 1;
        }
        for n in 0..plan.deletes.len() {
            deletes.push(Key { value: next, key: native.delete_key(n as u16).map_err(native_error)? }); next += 1;
        }
        let value = Box::new(Self { id, thread: std::thread::current().id(), native,
            images, moves, deletes, passes: std::array::from_fn(|_| None), latest: [0; CHILDREN + 1],
            pass_count: 0, next_token: next, sequence: 0, begun: false,
            retire_attempted: false, unknown: false, frame: Frame::new()? });
        if value.heap_bytes().checked_add(RETURN_RESERVE).is_none_or(|n| n > BRIDGE_HEAP) { return Err(BOUNDS); }
        Ok(value)
    }
    fn frame_mut(&mut self) -> &mut Frame {
        // SAFETY: only fields are modified. This private method never moves the
        // pinned frame; its Box stays reachable in SLOT for the entire child.
        unsafe { self.frame.as_mut().get_unchecked_mut() }
    }
    fn heap_bytes(&self) -> usize {
        let frame = self.frame.as_ref().get_ref();
        let returned = match &frame.result {
            Some(Ok(Value::Read(Some(bytes)))) => bytes.capacity(),
            Some(Ok(Value::Roster(Some(entries)))) =>
                entries.capacity() * size_of::<DirectoryEntry>()
                    + entries.iter().map(|e| e.name.capacity()).sum::<usize>(),
            _ => 0,
        };
        size_of::<Self>() + size_of::<Frame>() + frame.input.capacity() + frame.output.capacity()
            + self.images.capacity() * size_of::<Key<ImageKey>>()
            + self.moves.capacity() * size_of::<Key<MoveKey>>()
            + self.deletes.capacity() * size_of::<Key<DeleteKey>>() + returned
    }
    fn facts(&self, status: u32, error: u32) -> Reply {
        let mut result = reply(status, error);
        result.owner = self.id; result.sequence = self.sequence; result.epoch = self.native.namespace_epoch();
        result.first_failure = self.native.first_failure().map(native_error).unwrap_or(if self.unknown { 36 } else { 0 });
        result.flags = if self.native.is_unknown() { NATIVE_UNKNOWN } else { 0 }
            | if self.native.settled() { HANDLES_SETTLED } else { 0 }
            | if self.native.accepted_effects_finalized() { EFFECTS_FINAL } else { 0 }
            | if self.unknown { BRIDGE_UNKNOWN } else { 0 }
            | if self.begun { OWNER_BEGUN } else { 0 };
        result
    }
    fn image(&self, value: u64) -> Result<usize, u32> {
        self.images.iter().position(|key| key.value == value).ok_or(TOKEN)
    }
    fn movement(&self, value: u64) -> Result<usize, u32> {
        self.moves.iter().position(|key| key.value == value).ok_or(TOKEN)
    }
    fn deletion(&self, value: u64) -> Result<usize, u32> {
        self.deletes.iter().position(|key| key.value == value).ok_or(TOKEN)
    }
    fn pass(&self, value: u64, kind: u32, complete: bool) -> Result<usize, u32> {
        self.passes.iter().position(|slot| slot.as_ref().is_some_and(|pass|
            pass.key.is_some() && pass_matches(pass, value, kind, complete, self.latest[pass.image]))).ok_or(TOKEN)
    }
    fn preflight(&self, r: Request) -> Result<Call, u32> {
        if r.owner != self.id { return Err(OWNER); }
        if self.thread != std::thread::current().id() { return Err(THREAD); }
        if r.operation == 18 {
            if r.b != 0 || r.c != 0 || r.input_len != 0 { return Err(WIRE); }
            if r.number == 6 {
                if r.count != 0 { return Err(WIRE); }
                return Ok(Call::Observe(6, self.image(r.a)?, 0));
            }
            if !(1..=5).contains(&r.number) || r.a > usize::MAX as u64 || r.count as usize > PAGE
                || (r.number == 1 && (r.a != 0 || r.count != 0)) { return Err(WIRE); }
            return Ok(Call::Observe(r.number, r.a as usize, r.count as usize));
        }
        if self.unknown || self.native.is_unknown() || self.frame.phase == 1 || self.frame.phase == 3 { return Err(USED); }
        // An accepted disposition's original once-close also survives known failure.
        // Fresh disposition (13) and namespace finalization (15) never use this reserve.
        let finality = matches!(r.operation, 14 | 16 | 17);
        if self.retire_attempted || self.sequence >= CALLS
            || (!finality && (self.sequence >= CALLS - FINAL_CALLS || self.native.first_failure().is_some())) { return Err(USED); }
        if r.number != 0 || r.count != 0 || (r.operation != 8 && r.input_len != 0) { return Err(WIRE); }
        if !self.begun && r.operation != 2 && r.operation != 17 { return Err(USED); }
        let call = match r.operation {
            2 if r.a == 0 && r.b == 0 && r.c == 0 && !self.begun => Call::Begin,
            3 if r.b == 0 && r.c == 0 => Call::Acquire(self.image(r.a)?),
            4 | 5 if r.b == 0 && r.c == 0 => {
                let image = self.image(r.a)?;
                if self.pass_count >= PASSES || self.latest[image] == u16::MAX
                    || self.next_token == u64::MAX
                    || self.passes.iter().any(|p| p.as_ref().is_some_and(|p| !p.complete)) { return Err(USED); }
                if r.operation == 4 { Call::BeginRead(image) } else { Call::BeginRoster(image) }
            },
            6 if r.b == 0 && r.c == 0 => Call::Read(self.pass(r.a, 1, false)?),
            7 if r.b == 0 && r.c == 0 => Call::Roster(self.pass(r.a, 2, false)?),
            8 if r.b == 0 && r.c == 0 && r.input_len > 0 => Call::Write(self.image(r.a)?),
            9 if r.b == 0 && r.c == 0 => Call::FinishWrite(self.image(r.a)?),
            10 if r.b == 0 && r.c == 0 => Call::Fence(self.image(r.a)?),
            11 if r.c == 0 => Call::Rename(self.movement(r.a)?, self.pass(r.b, 2, true)?),
            12 => Call::FinishMove(self.movement(r.a)?, self.pass(r.b, 2, true)?, self.pass(r.c, 2, true)?),
            13 if r.c == 0 => Call::Dispose(self.deletion(r.a)?, if r.b == 0 { None } else { Some(self.pass(r.b, 2, true)?) }),
            14 if r.b == 0 && r.c == 0 => Call::CloseDisposed(self.deletion(r.a)?),
            15 if r.c == 0 => Call::FinishDeletion(self.deletion(r.a)?, self.pass(r.b, 2, true)?),
            16 if r.b == 0 && r.c == 0 => Call::Close(self.image(r.a)?),
            17 if r.a == 0 && r.b == 0 && r.c == 0 => Call::Retire,
            _ => return Err(WIRE),
        };
        Ok(call)
    }
    fn run(&mut self, call: Call, request: Request, input: &[u8]) -> Reply {
        // Only a known returned/unentered frame is recycled. UNKNOWN never calls run.
        {
            let frame = self.frame_mut();
            frame.result = None; frame.output.fill(0);
            frame.input[..input.len()].copy_from_slice(input);
            frame.request = request; frame.phase = 0;
        }
        if self.heap_bytes().checked_add(RETURN_RESERVE).is_none_or(|n| n > BRIDGE_HEAP) {
            return self.facts(REFUSED, BOUNDS);
        }
        self.sequence += 1;
        let mut entered = self.facts(UNKNOWN, 36); entered.flags |= PRIMITIVE_ENTERED;
        self.frame_mut().receipt = entered;
        self.frame_mut().phase = 1; // original owner and complete buffers already registered
        let result: Result<Value, Error> = match call {
            Call::Begin => { self.begun = true; self.native.begin_once().map(|()| Value::Unit) },
            Call::Acquire(i) => self.native.acquire_once(&self.images[i].key).map(|()| Value::Unit),
            Call::BeginRead(i) | Call::BeginRoster(i) => {
                let kind = if matches!(call, Call::BeginRead(_)) { 1 } else { 2 };
                let index = self.pass_count; self.pass_count += 1; self.latest[i] += 1;
                let token = self.next_token; self.next_token += 1;
                self.passes[index] = Some(Pass { value: token, key: None, image: i,
                    generation: self.latest[i], kind, complete: false });
                let value = if kind == 1 { self.native.begin_read_pass(&self.images[i].key) }
                    else { self.native.begin_roster_pass(&self.images[i].key) };
                match value {
                    Ok(key) => {
                        // No allocation/callback/fallible work between return and adoption.
                        if let Some(slot) = self.passes[index].as_mut() { slot.key = Some(key); }
                        Ok(Value::Token(token))
                    },
                    Err(error) => Err(error),
                }
            },
            Call::Read(i) | Call::Roster(i) => {
                // Split native and token fields; the actual PassKey never leaves this owner.
                let (native, passes) = (&mut self.native, &self.passes);
                match passes[i].as_ref().and_then(|p| p.key.as_ref()) {
                    Some(key) if matches!(call, Call::Read(_)) => native.read_next(key).map(Value::Read),
                    Some(key) => native.roster_next(key).map(Value::Roster),
                    None => Err(Error::State),
                }
            },
            Call::Write(i) => {
                let (native, images, frame) = (&mut self.native, &self.images, &self.frame);
                native.write_chunk(&images[i].key, &frame.input[..request.input_len as usize]).map(|()| Value::Unit)
            },
            Call::FinishWrite(i) => self.native.finish_write_once(&self.images[i].key).map(|()| Value::Unit),
            Call::Fence(i) => self.native.full_fence(&self.images[i].key).map(|()| Value::Unit),
            Call::Rename(i, p) => {
                let (native, moves, passes) = (&mut self.native, &self.moves, &self.passes);
                match passes[p].as_ref().and_then(|p| p.key.as_ref()) {
                    Some(key) => native.rename_once(&moves[i].key, key).map(|()| Value::Unit),
                    None => Err(Error::State),
                }
            },
            Call::FinishMove(i, a, b) => {
                let (native, moves, passes) = (&mut self.native, &self.moves, &self.passes);
                match (passes[a].as_ref().and_then(|p| p.key.as_ref()), passes[b].as_ref().and_then(|p| p.key.as_ref())) {
                    (Some(a), Some(b)) => native.finish_move(&moves[i].key, a, b).map(Value::Move),
                    _ => Err(Error::State),
                }
            },
            Call::Dispose(i, p) => {
                let (native, deletes, passes) = (&mut self.native, &self.deletes, &self.passes);
                let key = p.and_then(|p| passes[p].as_ref()).and_then(|p| p.key.as_ref());
                native.dispose_once(&deletes[i].key, key).map(|()| Value::Unit)
            },
            Call::CloseDisposed(i) => self.native.close_disposed_once(&self.deletes[i].key).map(|()| Value::Unit),
            Call::FinishDeletion(i, p) => {
                let (native, deletes, passes) = (&mut self.native, &self.deletes, &self.passes);
                match passes[p].as_ref().and_then(|p| p.key.as_ref()) {
                    Some(p) => native.finish_deletion(&deletes[i].key, p).map(Value::Deleted),
                    None => Err(Error::State),
                }
            },
            Call::Close(i) => self.native.close_once(&self.images[i].key).map(|()| Value::Unit),
            Call::Retire => { self.retire_attempted = true; Ok(Value::Retired(self.native.retire_handles_once())) },
            Call::Observe(..) => Err(Error::State),
        };
        // Result/effect custody is latched BEFORE any serialization, caller callback or return.
        self.frame_mut().result = Some(result);
        self.frame_mut().phase = 2;
        let mut receipt = match self.frame.result.as_ref() {
            Some(Err(error)) => self.facts(if *error == Error::Unknown { UNKNOWN } else { FAILED }, native_error(*error)),
            Some(Ok(Value::Retired(CloseOutcome::Unknown))) => self.facts(UNKNOWN, 36),
            _ => self.facts(OK, 0),
        };
        receipt.flags |= PRIMITIVE_ENTERED | PRIMITIVE_RETURNED;
        if self.native.is_unknown() { self.unknown = true; receipt.status = UNKNOWN; }
        if let Call::Read(i) | Call::Roster(i) = call {
            if !self.unknown && matches!(&self.frame.result, Some(Ok(Value::Read(None) | Value::Roster(None)))) {
                if let Some(pass) = self.passes[i].as_mut() { pass.complete = true; }
                receipt.status = EOF;
            }
        }
        self.frame_mut().receipt = receipt;
        if self.heap_bytes() > BRIDGE_HEAP || self.encode_result(&mut receipt).is_err() {
            self.unknown = true; receipt.status = UNKNOWN; receipt.error = 36; receipt.output_len = 0;
        }
        if receipt.status == UNKNOWN {
            self.unknown = true; self.frame_mut().phase = 3;
            receipt.flags |= BRIDGE_UNKNOWN; receipt.first_failure = if receipt.first_failure == 0 { 36 } else { receipt.first_failure };
        }
        self.frame_mut().receipt = receipt; receipt
    }
    fn encode_result(&mut self, receipt: &mut Reply) -> Result<(), u32> {
        let frame = self.frame_mut();
        let mut out = Encoder { data: &mut frame.output, at: 0 };
        match frame.result.as_ref() {
            Some(Ok(Value::Token(token))) => receipt.token = *token,
            Some(Ok(Value::Read(Some(bytes)))) => {
                if bytes.len() > INPUT_MAX || bytes.capacity() > INPUT_MAX { return Err(BOUNDS); }
                out.bytes(bytes)?;
            },
            Some(Ok(Value::Roster(Some(entries)))) => {
                if entries.len() > PAGE { return Err(BOUNDS); }
                for entry in entries {
                    if !entry.name.is_ascii() { return Err(WIRE); }
                    out.u32(if entry.kind == FileKind::Directory { 1 } else { 2 })?;
                    out.u32(entry.attributes)?; out.u32(entry.name.len() as u32)?; out.u32(0)?;
                    out.bytes(&entry.file_id)?; out.bytes(entry.name.as_bytes())?;
                }
                receipt.count = entries.len() as u32;
            },
            Some(Ok(Value::Move(value))) => {
                out.u32(value.step as u32)?; out.u32(0)?; out.identity(value.identity)?;
                out.u64(value.epoch)?; out.i64(value.change_before)?; out.i64(value.change_after)?;
            },
            Some(Ok(Value::Deleted(value))) => {
                out.u32(value.step as u32)?; out.u32(0)?; out.identity(value.identity)?; out.u64(value.epoch)?;
            },
            _ => {},
        }
        receipt.output_len = out.at as u32; Ok(())
    }
    fn prepared_output(&mut self, output: &mut [u8]) -> Result<Reply, u32> {
        let mut out = Encoder { data: output, at: 0 };
        for (index, value) in self.images.iter().enumerate() {
            out.u32(1)?; out.u32(index as u32)?; out.u64(value.value)?;
        }
        for (index, value) in self.moves.iter().enumerate() {
            out.u32(2)?; out.u32(index as u32)?; out.u64(value.value)?;
        }
        for (index, value) in self.deletes.iter().enumerate() {
            out.u32(3)?; out.u32(index as u32)?; out.u64(value.value)?;
        }
        let mut result = self.facts(OK, 0);
        result.output_len = out.at as u32; result.count = (self.images.len() + self.moves.len() + self.deletes.len()) as u32;
        result.total = result.count; self.frame_mut().receipt = result; Ok(result)
    }
    fn observe(&self, kind: u32, start: usize, count: usize, output: &mut [u8]) -> Result<Reply, u32> {
        // DATA only, even after UNKNOWN; never reset/replace the original frame,
        // read its pending raw buffer, enter native code or release its allocations.
        let mut out = Encoder { data: output, at: 0 };
        let mut result = self.facts(OK, 0);
        if kind == 1 {
            let costs = self.native.costs().map_err(native_error)?;
            for n in [costs.native_live as u64, costs.native_records as u64, costs.native_file_records as u64,
                costs.cumulative_entries as u64, costs.cumulative_read_bytes, costs.cumulative_written_bytes,
                costs.user_checks as u64, costs.passes_started as u64, costs.effects_entered as u64,
                costs.retained_heap_bytes as u64, self.heap_bytes() as u64, self.sequence] { out.u64(n)?; }
        } else if kind == 6 {
            out.identity(self.native.acquisition_identity(&self.images[start].key).map_err(native_error)?)?;
        } else {
            let total = match kind { 2 => self.native.effects().len(), 3 => self.native.pass_receipts().len(),
                4 => self.native.move_observations().len(), 5 => self.native.deletion_observations().len(), _ => return Err(WIRE) };
            if start > total || count == 0 || count > PAGE { return Err(BOUNDS); }
            let end = total.min(start.checked_add(count).ok_or(BOUNDS)?);
            result.total = total as u32; result.count = (end - start) as u32;
            for index in start..end {
                match kind {
                    2 => {
                        let e = &self.native.effects()[index];
                        let tag = match e.kind { EffectKind::ExistingOpen => 1, EffectKind::ExclusiveCreate => 2,
                            EffectKind::Write => 3, EffectKind::Read => 4, EffectKind::FullFence => 5,
                            EffectKind::SecurityQuery => 6, EffectKind::RosterRestart => 7,
                            EffectKind::RosterContinue => 8, EffectKind::Rename => 9, EffectKind::Disposition => 10 };
                        let flags = u32::from(e.entered) | (u32::from(e.adopted) << 1)
                            | (u32::from(e.latched) << 2) | (u32::from(e.complete) << 3)
                            | (u32::from(e.iosb_status.is_some()) << 4) | (u32::from(e.information.is_some()) << 5);
                        let (returned, status, error) = match e.returned {
                            None => (0, 0, 0), Some(NativeReturn::Nt(n)) => (1, n as u32, 0),
                            Some(NativeReturn::Boolean { value, error }) => (2, value as u32, error),
                        };
                        for n in [tag, e.row as u32, flags, returned, status, error, e.iosb_status.unwrap_or(0) as u32, 0] { out.u32(n)?; }
                        out.u64(e.information.unwrap_or(0))?; out.u64(0)?; out.u64(0)?; out.u64(0)?;
                    },
                    3 => {
                        let p = &self.native.pass_receipts()[index];
                        out.u32(p.generation as u32)?; out.u32(if p.kind == PassKind::Read { 1 } else { 2 })?;
                        out.identity(p.identity)?; out.u64(p.bytes)?; out.u32(p.entries)?; out.u32(0)?;
                    },
                    4 => {
                        let m = &self.native.move_observations()[index];
                        let flags = u32::from(m.entered) | (u32::from(m.accepted) << 1)
                            | (u32::from(m.finalized) << 2) | (u32::from(m.epoch.is_some()) << 3)
                            | (u32::from(m.change_before.is_some()) << 4) | (u32::from(m.change_after.is_some()) << 5);
                        out.u32(m.step as u32)?; out.u32(flags)?; out.u64(m.epoch.unwrap_or(0))?;
                        out.i64(m.change_before.unwrap_or(0))?; out.i64(m.change_after.unwrap_or(0))?;
                    },
                    5 => {
                        let d = &self.native.deletion_observations()[index];
                        let flags = u32::from(d.entered) | (u32::from(d.disposition_accepted) << 1)
                            | (u32::from(d.close_attempted) << 2) | (u32::from(d.handle_retired) << 3)
                            | (u32::from(d.deleted) << 4) | (u32::from(d.disposition_epoch.is_some()) << 5)
                            | (u32::from(d.retired_epoch.is_some()) << 6);
                        out.u32(d.step as u32)?; out.u32(flags)?; out.u64(d.disposition_epoch.unwrap_or(0))?;
                        out.u64(d.retired_epoch.unwrap_or(0))?; out.u64(0)?;
                    },
                    _ => return Err(WIRE),
                }
            }
        }
        result.output_len = out.at as u32; Ok(result)
    }
}
struct State { attempted: bool, fatal: bool, owner: Option<Box<Owner>> }
static SLOT: Mutex<State> = Mutex::new(State { attempted: false, fatal: false, owner: None });
static FATAL: AtomicBool = AtomicBool::new(false);

fn header(r: Request) -> Result<(), u32> {
    if r.size as usize != size_of::<Request>() || r.version != VERSION || r.reserved != 0
        || !(1..=18).contains(&r.operation) { return Err(WIRE); }
    // Always admit the entire maximum response BEFORE any pass/operation is consumed.
    if r.input_len as usize > INPUT_MAX || r.output_capacity as usize != OUTPUT_MAX { return Err(BOUNDS); }
    if r.operation == 1 && (r.owner != 0 || r.a != 0 || r.b != 0 || r.c != 0 || r.number != 0 || r.count != 0) { return Err(WIRE); }
    Ok(())
}
fn perform(state: &mut State, request: Request, input: &[u8], output: &mut [u8]) -> Reply {
    if request.operation == 1 {
        if state.attempted || state.fatal { return reply(REFUSED, USED); }
        state.attempted = true;
        let result = plan(input).and_then(|plan| Owner::prepare(&plan, (u64::from(std::process::id()) << 32) | 1));
        match result {
            Ok(owner) => state.owner = Some(owner), // strong registry before any later native entry
            Err(error) => return reply(REFUSED, error),
        }
        return match state.owner.as_mut() {
            Some(owner) => match owner.prepared_output(output) { Ok(result) => result, Err(error) => reply(REFUSED, error) },
            None => reply(UNKNOWN, USED),
        };
    }
    let fatal = state.fatal;
    let Some(owner) = state.owner.as_mut() else { return reply(REFUSED, OWNER); };
    if fatal && request.operation != 18 { return owner.facts(UNKNOWN, 36); }
    let call = match owner.preflight(request) {
        Ok(call) => call, Err(error) => return owner.facts(if owner.unknown { UNKNOWN } else { REFUSED }, error),
    };
    if let Call::Observe(kind, start, count) = call {
        return match owner.observe(kind, start, count, output) {
            Ok(result) => result, Err(error) => owner.facts(REFUSED, error),
        };
    }
    let result = owner.run(call, request, input);
    if result.output_len as usize <= OUTPUT_MAX {
        output[..result.output_len as usize].copy_from_slice(&owner.frame.output[..result.output_len as usize]);
    }
    result
}
fn poison(state: &mut State) {
    state.fatal = true;
    if let Some(owner) = state.owner.as_mut() {
        owner.unknown = true; owner.frame_mut().phase = 3;
        let frame = owner.frame_mut();
        frame.receipt.status = UNKNOWN; frame.receipt.error = 36;
        frame.receipt.flags |= BRIDGE_UNKNOWN;
        if frame.receipt.first_failure == 0 { frame.receipt.first_failure = 36; }
    }
}
fn range(address: usize, bytes: usize) -> Result<(usize, usize), u32> {
    if address == 0 || bytes == 0 { return Err(WIRE); }
    Ok((address, address.checked_add(bytes).ok_or(BOUNDS)?))
}
fn disjoint(ranges: &[(usize, usize)]) -> bool {
    ranges.iter().enumerate().all(|(at, a)| ranges.iter().skip(at + 1).all(|b| a.1 <= b.0 || b.1 <= a.0))
}
unsafe fn boundary(request: *const Request, input: *const u8, response: *mut Reply, output: *mut u8) -> u32 {
    if request.is_null() || (request as usize) % align_of::<Request>() != 0
        || response.is_null() || (response as usize) % align_of::<Reply>() != 0 { return REFUSED; }
    // SAFETY: documented fixed-caller pointer contract and checked alignment.
    let r = unsafe { request.read() };
    if let Err(error) = header(r) {
        // SAFETY: caller owns a live aligned Reply; no native operation was consumed.
        unsafe { response.write(reply(REFUSED, error)); } return REFUSED;
    }
    let mut ranges = [(0usize, 0usize); 4];
    for (index, (address, bytes)) in [(request as usize, size_of::<Request>()),
        (response as usize, size_of::<Reply>()), (output as usize, OUTPUT_MAX)].into_iter().enumerate() {
        let Ok(value) = range(address, bytes) else { return REFUSED; }; ranges[index] = value;
    }
    let n = if r.input_len == 0 { 3 } else {
        let Ok(value) = range(input as usize, r.input_len as usize) else { return REFUSED; }; ranges[3] = value; 4
    };
    if !disjoint(&ranges[..n]) { return REFUSED; }
    let mut state = match SLOT.try_lock() {
        Ok(state) => state,
        Err(TryLockError::WouldBlock) => {
            // Nonblocking refusal, no entry, no counter/lease/frame change.
            unsafe { response.write(reply(REFUSED, BUSY)); } return REFUSED;
        },
        Err(TryLockError::Poisoned(poisoned)) => { let mut state = poisoned.into_inner(); poison(&mut state); state },
    };
    if FATAL.load(Ordering::Acquire) { poison(&mut state); }
    // SAFETY: disjoint fixed caller-owned buffers, bounded lengths, rooted for this
    // actual synchronous call. Nothing keeps a pointer to caller storage.
    let input = if r.input_len == 0 { &[][..] } else { unsafe { std::slice::from_raw_parts(input, r.input_len as usize) } };
    let output = unsafe { std::slice::from_raw_parts_mut(output, OUTPUT_MAX) };
    let result = match catch_unwind(AssertUnwindSafe(|| perform(&mut state, r, input, output))) {
        Ok(result) => result,
        Err(payload) => {
            // Guard and owner stay outside the unwinding closure. Do not drop a
            // foreign panic payload or the original frame while recording UNKNOWN.
            poison(&mut state); std::mem::forget(payload);
            state.owner.as_ref().map_or_else(|| reply(UNKNOWN, 36), |owner| owner.facts(UNKNOWN, 36))
        },
    };
    unsafe { response.write(result); } result.status
}

/// Layout DATA only; no native resource, owner or filesystem operation.
/// # Safety
/// output must designate a live writable, aligned Info for this entire call.
#[no_mangle]
pub unsafe extern "system" fn mrk_iw_v1_info(output: *mut Info, bytes: u32) -> u32 {
    if output.is_null() || bytes as usize != size_of::<Info>() || (output as usize) % align_of::<Info>() != 0 { return REFUSED; }
    match catch_unwind(AssertUnwindSafe(|| { unsafe { output.write(info()); } OK })) {
        Ok(status) => status,
        Err(payload) => { FATAL.store(true, Ordering::Release); std::mem::forget(payload); UNKNOWN },
    }
}

/// Closed image primitive operation set 1..18; never a generic filesystem RPC.
/// # Safety
/// All four pointers obey Request/Reply/Info layout DATA and the live, disjoint
/// fixed-buffer contract above. No unload until actual calls return and original
/// ownership is positively settled; an UNKNOWN caller must keep the DLL loaded.
#[no_mangle]
pub unsafe extern "system" fn mrk_iw_v1_call(
    request: *const Request, input: *const u8, response: *mut Reply, output: *mut u8,
) -> u32 {
    match catch_unwind(AssertUnwindSafe(|| unsafe { boundary(request, input, response, output) })) {
        Ok(status) => status,
        Err(payload) => {
            FATAL.store(true, Ordering::Release); std::mem::forget(payload);
            if let Ok(mut state) = SLOT.try_lock() { poison(&mut state); }
            UNKNOWN
        },
    }
}
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
