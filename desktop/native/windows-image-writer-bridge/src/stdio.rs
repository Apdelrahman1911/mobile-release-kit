//! Separate fixed stdio-v1 ABI in the SAME retained image DLL. The B1 writer
//! ABI/18 operations are unchanged. No HANDLE argument, DLL load, worker,
//! replacement owner or clock crosses this interface.
use mrk_windows_installed_native::{image_stdio::{Child, Role, State, Observation,
    BUFFER_BYTES, ARENA_BYTES, LIFETIME_ENTRIES, HANDOFF_BYTES}, Error};
use std::{mem::{align_of, offset_of, size_of}, panic::{catch_unwind, AssertUnwindSafe},
    sync::{Mutex, TryLockError}, thread::ThreadId};

const VERSION: u32 = 1;
const TAG: u32 = 0x4953_3131;
const OPERATIONS: u32 = 14;
const FINAL_RESERVE: u64 = 1024;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Request {
    pub size: u32, pub version: u32, pub operation: u32, pub role: u32,
    pub generation: u64, pub length: u32, pub capacity: u32, pub reserved: [u32; 2],
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Reply {
    pub size: u32, pub version: u32, pub status: u32, pub error: u32,
    pub generation: u64, pub requested: u32, pub transferred: u32, pub flags: u32,
    pub close_mask: u32, pub mappings: [u64; 3], pub output_len: u32,
    pub first_failure: u32, pub reserved: [u32; 2],
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Info {
    pub fields: [u32; 16], pub request_offsets: [u32; 8], pub reply_offsets: [u32; 13],
}
const _: () = assert!(size_of::<Request>() == 40 && align_of::<Request>() == 8);
const _: () = assert!(size_of::<Reply>() == 80 && align_of::<Reply>() == 8);
const _: () = assert!(size_of::<Info>() == 148 && align_of::<Info>() == 4);
fn info() -> Info {
    Info {
        fields: [148, VERSION, 40, 80, 8, 8, BUFFER_BYTES as u32, OPERATIONS,
            TAG, ARENA_BYTES as u32, LIFETIME_ENTRIES as u32, FINAL_RESERVE as u32,
            HANDOFF_BYTES as u32, 3, 0, 0],
        request_offsets: [offset_of!(Request, size), offset_of!(Request, version),
            offset_of!(Request, operation), offset_of!(Request, role),
            offset_of!(Request, generation), offset_of!(Request, length),
            offset_of!(Request, capacity), offset_of!(Request, reserved)].map(|n| n as u32),
        reply_offsets: [offset_of!(Reply, size), offset_of!(Reply, version),
            offset_of!(Reply, status), offset_of!(Reply, error), offset_of!(Reply, generation),
            offset_of!(Reply, requested), offset_of!(Reply, transferred), offset_of!(Reply, flags),
            offset_of!(Reply, close_mask), offset_of!(Reply, mappings), offset_of!(Reply, output_len),
            offset_of!(Reply, first_failure), offset_of!(Reply, reserved)].map(|n| n as u32),
    }
}
fn reply(status: State, error: u32) -> Reply {
    Reply { size: 80, version: VERSION, status: status as u32, error, ..Reply::default() }
}
fn role(value: u32) -> Result<Role, Error> {
    match value { 0 => Ok(Role::Input), 1 => Ok(Role::Output), 2 => Ok(Role::Error), _ => Err(Error::Unsafe) }
}
fn request(value: &Request) -> Result<(), Error> {
    if value.size != 40 || value.version != VERSION || !(1..=OPERATIONS).contains(&value.operation)
        || value.role > 2 || value.reserved != [0; 2]
        || value.length as usize > BUFFER_BYTES || value.capacity as usize > BUFFER_BYTES {
        return Err(Error::Bounds);
    }
    let op = value.operation;
    let control = matches!(op, 1..=5 | 12 | 13);
    if control && (value.role != 0 || value.generation != 0) { return Err(Error::State); }
    match op {
        1..=5 | 8 | 9 | 11 | 14 if value.length != 0 || value.capacity != 0 => Err(Error::Bounds),
        6 if value.role != 0 || value.length == 0 || value.capacity != 0 => Err(Error::Bounds),
        7 if value.role == 0 || value.length == 0 || value.capacity != 0 => Err(Error::Bounds),
        10 if value.length != 0 || value.role == 0 && value.capacity == 0
            || value.role != 0 && value.capacity != 0 => Err(Error::Bounds),
        12 if value.length != HANDOFF_BYTES as u32 || value.capacity != 0 => Err(Error::Bounds),
        13 if value.length != 0 || value.capacity != HANDOFF_BYTES as u32 => Err(Error::Bounds),
        _ => Ok(()),
    }
}
struct Owner {
    child: Child, thread: ThreadId, calls: u64, entered: bool, unknown: bool,
    original_request: Option<Request>, original_reply: Reply,
}
impl Owner {
    fn new() -> Self {
        Self { child: Child::new(), thread: std::thread::current().id(), calls: 0,
            entered: false, unknown: false, original_request: None,
            original_reply: reply(State::Idle, 0) }
    }
    fn capture(&mut self, observed: Observation) {
        self.original_reply = Reply { size: 80, version: VERSION,
            status: observed.state as u32, error: observed.error,
            generation: observed.generation, requested: observed.requested,
            transferred: observed.transferred, close_mask: observed.close_mask,
            first_failure: observed.first_failure,
            flags: u32::from(observed.unknown || self.unknown)
                | (u32::from(self.child.settled()) << 1)
                | (u32::from(self.child.handoff_complete()) << 2), ..Reply::default() };
    }
    fn enter(&mut self, r: Request, source: &[u8], destination: &mut [u8]) -> Result<(), Error> {
        request(&r)?;
        if self.thread != std::thread::current().id() || self.entered { return Err(Error::State); }
        let settle = matches!(r.operation, 8..=11 | 14);
        if self.unknown && !settle { return Err(Error::Unknown); }
        let end = if settle { LIFETIME_ENTRIES } else { LIFETIME_ENTRIES - FINAL_RESERVE };
        if self.calls >= end { return Err(Error::Bounds); }
        let selected = role(r.role)?;
        if !matches!(r.operation, 1..=5 | 12 | 13 | 14)
            && r.generation != self.child.observation(selected).generation { return Err(Error::State); }
        self.calls += 1;
        self.original_request = Some(r); self.original_reply = reply(State::Unknown, 0);
        self.entered = true; // original frame is rooted before the native boundary
        match r.operation {
            1 => {
                let maps = self.child.preflight_once()?;
                self.original_reply = reply(State::Idle, 0);
                self.original_reply.mappings = maps.map(|n| n as u64);
            },
            2 => { self.child.wrappers_retired_once()?; self.original_reply = reply(State::Idle, 0); },
            3 => { self.child.claim_input_once()?; self.capture(self.child.observation(Role::Input)); },
            4 => { self.child.claim_output_once()?; self.capture(self.child.observation(Role::Output)); },
            5 => { self.child.claim_error_once()?; self.capture(self.child.observation(Role::Error)); },
            6 => { let actual = self.child.begin_read(selected, r.length as usize)?; self.capture(actual); },
            7 => { let actual = self.child.begin_write(selected, source)?; self.capture(actual); },
            8 => { let actual = self.child.poll(selected)?; self.capture(actual); },
            9 => { let actual = self.child.cancel(selected)?; self.capture(actual); },
            10 => {
                let actual = self.child.observation(selected);
                if selected == Role::Input {
                    let count = self.child.take_read(selected, destination)?;
                    self.capture(actual);
                    self.original_reply.output_len = count.unwrap_or(0) as u32;
                    self.original_reply.transferred = count.unwrap_or(0) as u32;
                    // Complete(0) remains Complete. Only the native broken-peer
                    // EOF contract produces Eof; cancelled is never taken as EOF.
                } else {
                    let count = self.child.take_write(selected)?;
                    self.capture(actual);
                    self.original_reply.transferred = count as u32;
                }
            },
            11 => { let actual = self.child.close_once(selected)?; self.capture(actual); },
            12 => { self.child.admit_prologue_once(source)?; self.capture(self.child.observation(Role::Input)); },
            13 => {
                let bytes = self.child.acknowledgement()?;
                destination.copy_from_slice(&bytes);
                self.capture(self.child.observation(Role::Output));
                self.original_reply.output_len = HANDOFF_BYTES as u32;
            },
            14 => self.capture(self.child.observation(selected)),
            _ => return Err(Error::State),
        }
        self.entered = false;
        Ok(())
    }
    fn failed_return(&mut self, request: Request, error: Error) {
        // Preserve the exact observed channel generation/extent even on a
        // refusal. Successful BOOL/status alone never invents a new operation.
        self.entered = false;
        if error == Error::Unknown { self.unknown = true; }
        if let Ok(selected) = role(request.role) { self.capture(self.child.observation(selected)); }
        self.original_reply.status = if self.unknown || self.original_reply.flags & 1 != 0 {
            State::Unknown
        } else { State::Refused } as u32;
        self.original_reply.error = super::native_error(error);
    }
}
static ORIGINAL: Mutex<Option<Owner>> = Mutex::new(None);
fn range<T>(pointer: *const T, count: usize) -> bool {
    !pointer.is_null() && (pointer as usize) % align_of::<T>() == 0
        && count.checked_mul(size_of::<T>()).and_then(|n| (pointer as usize).checked_add(n)).is_some()
}
fn disjoint(a: usize, alen: usize, b: usize, blen: usize) -> bool {
    alen == 0 || blen == 0 || a.checked_add(alen).is_some_and(|end| end <= b)
        || b.checked_add(blen).is_some_and(|end| end <= a)
}
/// SAFETY: output is a live, exclusive Info destination for this synchronous call.
#[no_mangle]
pub unsafe extern "system" fn mrk_stdio_v1_info(output: *mut Info, bytes: u32) -> u32 {
    if bytes != 148 || !range(output, 1) { return State::Refused as u32; }
    unsafe { output.write(info()); }
    State::Idle as u32
}
/// SAFETY: fixed trusted ctypes caller keeps all admitted ranges live, exclusive
/// and nonoverlapping through this synchronous return. No caller buffer address
/// survives the call; pending OS IO uses only the original native arena.
#[no_mangle]
pub unsafe extern "system" fn mrk_stdio_v1_call(
    input: *const Request, source: *const u8, output: *mut Reply, destination: *mut u8,
) -> u32 {
    if !range(input, 1) || !range(output, 1)
        || !disjoint(input as usize, 40, output as usize, 80) { return State::Refused as u32; }
    let r = unsafe { input.read() };
    if request(&r).is_err() { unsafe { output.write(reply(State::Refused, 1)); } return State::Refused as u32; }
    let input_bytes = if matches!(r.operation, 7 | 12) { r.length as usize } else { 0 };
    let output_bytes = r.capacity as usize;
    if input_bytes != 0 && !range(source, input_bytes)
        || output_bytes != 0 && !range(destination, output_bytes)
        || !disjoint(source as usize, input_bytes, destination as usize, output_bytes)
        || !disjoint(input as usize, 40, destination as usize, output_bytes)
        || !disjoint(output as usize, 80, source as usize, input_bytes)
        || !disjoint(output as usize, 80, destination as usize, output_bytes) {
        unsafe { output.write(reply(State::Refused, 1)); } return State::Refused as u32;
    }
    let mut slot = match ORIGINAL.try_lock() {
        Ok(slot) => slot,
        Err(TryLockError::WouldBlock) => { unsafe { output.write(reply(State::Refused, 5)); } return State::Refused as u32; },
        Err(TryLockError::Poisoned(error)) => {
            let mut slot = error.into_inner();
            if let Some(original) = slot.as_mut() { original.unknown = true; original.child.mark_unknown(); }
            unsafe { output.write(reply(State::Unknown, 5)); } return State::Unknown as u32;
        },
    };
    if slot.is_none() {
        if r.operation != 1 { unsafe { output.write(reply(State::Refused, 7)); } return State::Refused as u32; }
        *slot = Some(Owner::new()); // strong root before first preflight/claim
    }
    let Some(original) = slot.as_mut() else { return State::Unknown as u32; };
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let source = if input_bytes == 0 { &[] } else { unsafe { std::slice::from_raw_parts(source, input_bytes) } };
        let destination = if output_bytes == 0 { &mut [] } else { unsafe { std::slice::from_raw_parts_mut(destination, output_bytes) } };
        original.enter(r, source, destination)
    }));
    match outcome {
        Ok(Ok(())) => {},
        Ok(Err(error)) => original.failed_return(r, error),
        Err(_) => { original.unknown = true; original.child.mark_unknown();
            original.original_reply = reply(State::Unknown, 36); },
    }
    let retained = original.original_reply;
    unsafe { output.write(retained); }
    retained.status
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stdio_layout_is_separate_from_the_unchanged_writer_abi() {
        let value = info();
        assert_eq!(value.request_offsets, [0, 4, 8, 12, 16, 24, 28, 32]);
        assert_eq!(value.reply_offsets, [0, 4, 8, 12, 16, 24, 28, 32, 36, 40, 64, 68, 72]);
        assert_eq!(value.fields[7], 14);
        assert_ne!(value.fields[8], super::super::LAYOUT_TAG);
    }
    #[test]
    fn closed_direction_and_control_wire_refuses_before_any_native_entry() {
        let mut r = Request { size: 40, version: 1, operation: 6, length: 96, ..Request::default() };
        assert!(request(&r).is_ok());
        r.role = 1; assert!(request(&r).is_err());
        r.operation = 7; assert!(request(&r).is_ok());
        r.operation = 4; assert!(request(&r).is_err());
        r.role = 0; r.length = 0; r.generation = 1; assert!(request(&r).is_err());
        r.generation = 0; assert!(request(&r).is_ok());
        r.reserved[1] = 1; assert!(request(&r).is_err());
    }
    #[test]
    fn overlap_and_extent_checks_never_form_an_aliasing_native_buffer() {
        assert!(!disjoint(32, 40, 40, 80));
        assert!(disjoint(32, 40, 72, 80));
        assert!(!disjoint(usize::MAX - 2, 8, usize::MAX - 1, 4));
        assert!(!range::<u64>(std::ptr::null(), 1));
    }
}
