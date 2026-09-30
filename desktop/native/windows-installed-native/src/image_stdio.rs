//! Fixed original Windows image child/stdio primitives, not an executor.
//! Every operation lives in this retained arena before entry. Drop never closes
//! handles, and frees memory only after positive original-consumer finality. The
//! existing EditOwner (or one static child bridge slot) retains uncertainty.
use super::{CloseOutcome, Error, NativeBook, Result};
use std::{cell::UnsafeCell, mem::{size_of, ManuallyDrop}, pin::Pin, ptr::{null, null_mut}};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Win32::{Foundation as F, Security as S, Storage::FileSystem as FS};
use windows_sys::Win32::System::{Console as C, IO, Pipes as P, Threading as T};

pub const BUFFER_BYTES: usize = 65_536;
pub const ARENA_BYTES: usize = 512 * 1024;
pub const LIFETIME_ENTRIES: u64 = 131_072;
const SETTLEMENT_RESERVE: u64 = 1_024;
pub const HANDOFF_BYTES: usize = 96;
const ACCESS: u32 = 0x0012_0183; // SYNCHRONIZE/READ_CONTROL, R/W DATA/ATTR; NOT APPEND/CREATE_INSTANCE.
const BAD_STATE: u32 = 0x8000_0001;
const BAD_DATA: u32 = 0x8000_0002;
const LOST_RETURN: u32 = 0x8000_0003;
const STD_IDS: [u32; 3] = [u32::MAX - 9, u32::MAX - 10, u32::MAX - 11];
// Microsoft WDK 10.0.26100 ntifs.h NamedPipeType/ReadMode/CompletionMode,
// wdm.h create disposition/result. The Win32 PIPE_REJECT_REMOTE_CLIENTS
// value (8) is NOT the native NamedPipeType flag (2).
const PIPE_FILE_CREATE: u32 = 2;
const PIPE_FILE_CREATED: usize = 2;
const PIPE_BYTE_STREAM_TYPE: u32 = 0;
const PIPE_REJECT_REMOTE_CLIENTS: u32 = 2;
const PIPE_BYTE_STREAM_MODE: u32 = 0;
const PIPE_QUEUE_OPERATION: u32 = 0;
const PIPE_CREATE_OPTIONS: u32 = 0; // asynchronous: no SYNCHRONOUS_IO_* option
// The old Win32 default is 50ms. This is only the native default pipe-instance
// wait interval, not a controller deadline. This module never calls WaitNamedPipe.
const PIPE_DEFAULT_TIMEOUT_100NS: i64 = -500_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Role { Input = 0, Output = 1, Error = 2 }
impl Role {
    fn index(self) -> usize { self as usize }
    fn reads(self, side: u32) -> bool { (self == Self::Input) == (side == 2) }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum State { Idle = 0, Pending = 1, Complete = 2, Eof = 3, Cancelled = 4,
    Refused = 5, Failed = 6, Unknown = 7, Closed = 8 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    pub state: State, pub generation: u64, pub requested: u32, pub transferred: u32,
    pub error: u32, pub first_failure: u32, pub unknown: bool, pub close_mask: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Process { NotEntered, Failed, Running, Exited(u32), Unknown }

// No request may supply a HANDLE, an access mask, a native class or pipe name.
#[repr(C)]
struct IoSlot {
    overlapped: UnsafeCell<IO::OVERLAPPED>, buffer: UnsafeCell<[u8; BUFFER_BYTES]>,
}
// All pointer arguments to NtCreateNamedPipeFile live outside mutable metadata.
// Pending/informational/warning returns keep these cells UNREAD and unmodified;
// retaining an allocation alone would not make concurrent output reads safe.
#[repr(C)]
struct PipeCreateStorage {
    output: UnsafeCell<F::HANDLE>,
    iosb: UnsafeCell<IO::IO_STATUS_BLOCK>,
    name: UnsafeCell<[u16; 160]>,
    unicode: UnsafeCell<F::UNICODE_STRING>,
    attributes: UnsafeCell<OBJECT_ATTRIBUTES>,
    timeout: UnsafeCell<i64>,
}
#[repr(C)]
struct Channel {
    original: F::HANDLE, client: F::HANDLE, event: F::HANDLE,
    pipe_attempted: u32, pipe_returned: u32, pipe_ntstatus: i32, pipe_custody: u32,
    pipe_output_seen: u32, pipe_output: F::HANDLE,
    pipe_iosb_seen: u32, pipe_iosb_status: i32, pipe_information: usize,
    count: u32, state: u32, operation: u32, requested: u32, delivered: u32,
    generation: u64, returned: i32, error: u32, return_seen: u32,
    begin_return: i32, begin_error: u32, completion_return: i32, completion_error: u32,
    cancel_attempted: u32, cancel_return: i32, cancel_error: u32,
    original_close: u32, client_close: u32, event_close: u32, mapping_close: u32,
    claimed: u32, server_pid: u32, client_pid: u32, actual_access: u32,
    flags: u32, mode: u32, maximum_instances: u32, output_size: u32, input_size: u32,
    uncertain: u32,
}
#[repr(C)]
struct Metadata {
    channels: [Channel; 3],
    calls: u64, first: u32, unknown: u32, side: u32, pid: u32, thread: u32,
    prepared: u32, startup_retired: u32, preflight: u32, wrappers_retired: u32, handoff: u32,
    handoff_read: u32, handoff_written: u32,
    create_attempted: u32, create_returned: u32, create_bool: i32, create_error: u32,
    create_custody: u32, process_original: u32, thread_original: u32,
    process: T::PROCESS_INFORMATION, startup: T::STARTUPINFOEXW,
    process_close: u32, thread_close: u32, force_attempted: u32,
    exit_seen: u32, exit_code: u32, attributes_started: u32, attributes_ready: u32,
    attributes_deleted: u32, attribute_size: usize,
    inherited: [F::HANDLE; 3],
    executable: [u16; 8192], command: [u16; 16384], cwd: [u16; 8192],
    environment: [u16; 8192], names: [[u16; 160]; 3], nonce: [u8; 32],
    descriptor_len: u32,
    security: [u32; 1024], security_len: u32,
    object_info: [u32; 32], object_len: u32,
    call_return: i32, call_error: u32, call_seen: u32, scalar: u32,
    mapping_before: [usize; 3],
}
#[repr(C)]
struct LaunchStorage {
    pipes: [PipeCreateStorage; 3],
    descriptor: UnsafeCell<[u32; 128]>,
    attributes: UnsafeCell<[usize; 128]>,
    inherited: UnsafeCell<[F::HANDLE; 3]>,
}
#[repr(C)]
struct Arena {
    io: [IoSlot; 3],
    launch: LaunchStorage,
    metadata: UnsafeCell<Metadata>,
}
// Leave a conservative 64-KiB allowance for bounded UTF16 formatting/security DATA.
const _: () = assert!(size_of::<Arena>() + 64 * 1024 <= ARENA_BYTES);
// Pending native destinations are accessed through SHARED IoSlot references.
// Never make &mut Arena/IoSlot: UnsafeCell does not waive &mut exclusivity.
// Only the disjoint metadata is mutably borrowed under the original owner lock.
unsafe impl Send for Arena {}

#[link(name = "ucrt")]
unsafe extern "C" {
    fn _get_osfhandle(fd: i32) -> isize;
    fn _close(fd: i32) -> i32;
    fn _errno() -> *mut i32;
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryObject(handle: F::HANDLE, class: u32, data: *mut core::ffi::c_void,
        length: u32, returned: *mut u32) -> i32;
    // https://learn.microsoft.com/windows/win32/devnotes/nt-create-named-pipe-file
    // Fixed private entry only: no request can choose these native parameters.
    fn NtCreateNamedPipeFile(file_handle: *mut F::HANDLE, desired_access: u32,
        object_attributes: *const OBJECT_ATTRIBUTES, io_status_block: *mut IO::IO_STATUS_BLOCK,
        share_access: u32, create_disposition: u32, create_options: u32,
        named_pipe_type: u32, read_mode: u32, completion_mode: u32,
        maximum_instances: u32, inbound_quota: u32, outbound_quota: u32,
        default_timeout: *const i64) -> i32;
}
fn fresh() -> ManuallyDrop<Pin<Box<Arena>>> {
    // Allocate in place; no 300-KiB temporary on CPython's/main-owner stack.
    let mut raw = Box::<Arena>::new_uninit();
    // SAFETY: Arena contains only integer/pointer/UnsafeCell POD fields. Zero is
    // its reserved/unentered state. Pin precedes any native address publication.
    unsafe {
        raw.as_mut_ptr().write_bytes(0, 1);
        ManuallyDrop::new(Pin::new_unchecked(raw.assume_init()))
    }
}
fn arena(value: &ManuallyDrop<Pin<Box<Arena>>>) -> &Arena { value.as_ref().get_ref() }
fn metadata(value: &ManuallyDrop<Pin<Box<Arena>>>) -> &Metadata {
    // SAFETY: shared owner access excludes all Rust metadata mutation. The
    // kernel retains only disjoint io/launch cells, never this metadata.
    unsafe { &*arena(value).metadata.get() }
}
fn parts(value: &mut ManuallyDrop<Pin<Box<Arena>>>) -> (&[IoSlot; 3], &LaunchStorage, &mut Metadata) {
    let shared = arena(value);
    // SAFETY: exclusive original-owner borrow serializes metadata. No mutable
    // reference covers the allocation/io cells which the kernel may access.
    unsafe { (&shared.io, &shared.launch, &mut *shared.metadata.get()) }
}
fn fail(a: &mut Metadata, error: u32, unknown: bool) -> Error {
    if a.first == 0 { a.first = if error == 0 { BAD_STATE } else { error }; }
    if unknown { a.unknown = 1; Error::Unknown } else { Error::Unsafe }
}
fn entry(a: &mut Metadata, settlement: bool) -> Result<()> {
    if a.call_seen == 1 { return Err(fail(a, LOST_RETURN, true)); }
    let end = if settlement { LIFETIME_ENTRIES } else { LIFETIME_ENTRIES - SETTLEMENT_RESERVE };
    if a.calls >= end { return Err(fail(a, BAD_STATE, true)); }
    a.calls += 1;
    a.call_seen = 1;
    Ok(())
}
fn returned(a: &mut Metadata, value: i32, error: u32) {
    a.call_return = value; a.call_error = error; a.call_seen = 2;
}
fn bool_result(a: &mut Metadata) -> Result<()> {
    if a.call_return == 0 { Err(fail(a, a.call_error, false)) } else { Ok(()) }
}
fn state(value: u32) -> State {
    match value { 0 => State::Idle, 1 => State::Pending, 2 => State::Complete,
        3 => State::Eof, 4 => State::Cancelled, 5 => State::Refused,
        6 => State::Failed, 8 => State::Closed, _ => State::Unknown }
}
fn observation(a: &Metadata, role: Role) -> Observation {
    let c = &a.channels[role.index()];
    Observation { state: state(c.state), generation: c.generation, requested: c.requested,
        transferred: c.count, error: c.error, first_failure: a.first,
        unknown: a.unknown != 0 || c.uncertain != 0,
        close_mask: u32::from(c.original_close == 2)
            | (u32::from(c.event_close == 2) << 1)
            | (u32::from(c.mapping_close == 2) << 2) }
}
fn known_complete(c: &Channel) -> bool {
    (c.return_seen == 0 && c.operation == 0 && c.state == State::Idle as u32)
        || c.return_seen == 2 && matches!(state(c.state),
            State::Idle | State::Complete | State::Eof | State::Cancelled | State::Failed)
}
fn original_handle(handle: F::HANDLE) -> bool {
    // Pseudo handles are negative constants, not owned kernel-object originals.
    !handle.is_null() && (handle as isize) > 0
}
fn pipe_access(role: Role, client: bool) -> u32 {
    let reads = if client { role == Role::Input } else { role != Role::Input };
    FS::READ_CONTROL | FS::SYNCHRONIZE | FS::FILE_READ_ATTRIBUTES
        | if reads { FS::FILE_READ_DATA } else { FS::FILE_WRITE_DATA }
}
fn pipe_server_share(role: Role) -> u32 {
    // Permit only the opposite peer direction; never configure a duplex fallback.
    if role == Role::Input { FS::FILE_SHARE_READ } else { FS::FILE_SHARE_WRITE }
}
fn definite_pipe_return(status: i32) -> bool {
    status == F::STATUS_SUCCESS || (status as u32 >> 30) == 3
}
fn admitted_pipe_output(a: &Metadata, handle: F::HANDLE, iosb_status: i32, information: usize) -> bool {
    original_handle(handle) && iosb_status == F::STATUS_SUCCESS && information == PIPE_FILE_CREATED
        && a.channels.iter().all(|c| [c.original, c.client, c.event].iter().all(|h| *h != handle))
        && handle != a.process.hProcess && handle != a.process.hThread
}
fn pipe_created_original(c: &Channel) -> bool {
    c.pipe_attempted == 1 && c.pipe_returned == 1 && c.pipe_ntstatus == F::STATUS_SUCCESS
        && c.pipe_custody == 2 && c.pipe_output_seen == 1 && c.pipe_iosb_seen == 1
        && c.pipe_iosb_status == F::STATUS_SUCCESS && c.pipe_information == PIPE_FILE_CREATED
        && original_handle(c.original) && c.pipe_output == c.original
}
fn pipe_creation_consumed(c: &Channel) -> bool {
    match c.pipe_custody {
        0 => c.pipe_attempted == 0 && c.pipe_returned == 0,
        1 => c.pipe_attempted == 1 && c.pipe_returned == 1
            && (c.pipe_ntstatus as u32 >> 30) == 3 && c.pipe_output_seen == 1
            && c.pipe_output.is_null() && c.original_close == 4,
        2 => pipe_created_original(c) && c.original_close == 2,
        _ => false,
    }
}
fn pipe_create_unknown(a: &mut Metadata, role: Role, error: u32) -> Error {
    let c = &mut a.channels[role.index()];
    c.pipe_custody = 3; c.uncertain = 1;
    fail(a, error, true)
}
fn created_original(a: &Metadata) -> bool {
    a.create_attempted == 1 && a.create_returned == 1 && a.create_bool != 0
        && a.create_custody == 2 && a.process_original == 1 && a.thread_original == 1
}
fn admitted_process_outputs(a: &Metadata) -> bool {
    let p = &a.process;
    original_handle(p.hProcess) && original_handle(p.hThread) && p.hProcess != p.hThread
        && p.dwProcessId != 0 && p.dwThreadId != 0 && p.dwProcessId != p.dwThreadId
        && p.dwProcessId != a.pid && p.dwThreadId != a.thread
        && a.channels.iter().all(|c| [c.original, c.client, c.event].iter().all(|h|
            *h != p.hProcess && *h != p.hThread))
}
fn empty_process_outputs(a: &Metadata) -> bool {
    a.process.hProcess.is_null() && a.process.hThread.is_null()
        && a.process.dwProcessId == 0 && a.process.dwThreadId == 0
}
fn no_child_effect(a: &Metadata) -> bool {
    a.create_attempted == 0
        || a.create_returned == 1 && a.create_bool == 0 && a.create_custody == 1
            && empty_process_outputs(a)
}
fn creation_ready(a: &Metadata) -> bool {
    a.side == 1 && a.prepared == 2 && a.startup_retired == 0
        && a.create_attempted == 0 && a.unknown == 0 && a.first == 0 && a.call_seen != 1
        && a.attributes_ready == 1 && a.attributes_deleted == 0
        && a.nonce != [0; 32] && a.pid != 0
        && a.channels.iter().enumerate().all(|(i, c)|
            pipe_created_original(c)
                && original_handle(c.original) && original_handle(c.client) && original_handle(c.event)
                && c.original != c.client && c.original != c.event && c.client != c.event
                && c.original_close == 0 && c.client_close == 0 && c.event_close == 0
                && c.claimed == 1 && c.uncertain == 0 && a.inherited[i] == c.client
                && c.state == State::Complete as u32 && c.operation == 3 && c.return_seen == 2)
}
fn parent_consumers_settled(a: &Metadata) -> bool {
    a.unknown == 0 && a.call_seen != 1
        && (no_child_effect(a) || created_original(a)
            && a.exit_seen == 1 && a.process_close == 2 && a.thread_close == 2)
        && a.channels.iter().all(|c| {
            let absent = |handle: F::HANDLE, receipt: u32| handle.is_null() && receipt == 0
                || (handle.is_null() || handle == F::INVALID_HANDLE_VALUE) && receipt == 4;
            pipe_creation_consumed(c)
                && (c.original_close == 2 || absent(c.original, c.original_close))
                && (c.client_close == 2 || absent(c.client, c.client_close))
                && (c.event_close == 2 || absent(c.event, c.event_close))
                && c.state != State::Pending as u32 && c.state != State::Unknown as u32
                && c.return_seen != 1 && c.uncertain == 0
        })
        && (a.attributes_ready == 0 || a.attributes_deleted == 2)
}
fn process_control_ready(a: &Metadata) -> bool {
    created_original(a) && a.process_close == 0 && a.exit_seen == 0
}
fn acknowledgement_ready(a: &Metadata) -> bool {
    created_original(a) && a.handoff == 0 && a.nonce != [0; 32]
        && a.pid != 0 && a.unknown == 0 && a.first == 0
}
fn valid_acknowledgement(a: &Metadata, bytes: &[u8]) -> bool {
    acknowledgement_ready(a) && bytes == handoff(a.pid, a.process.dwProcessId, &a.nonce, true)
}
fn accept_cancel_result(a: &mut Metadata, role: Role) {
    let c = &a.channels[role.index()];
    if c.cancel_return == 0 && c.cancel_error != F::ERROR_NOT_FOUND {
        let error = c.cancel_error; fail(a, error, true);
    }
    // This callback only classifies the cancellation request's observed return.
    // It cannot manufacture completion, change operation/generation or clear state.
}
fn completed_state(value: i32, error: u32, operation: u32, count: u32, requested: u32) -> State {
    if value != 0 { return if count <= requested { State::Complete } else { State::Unknown }; }
    match error {
        F::ERROR_IO_INCOMPLETE => State::Pending,
        F::ERROR_BROKEN_PIPE if operation == 1 => State::Eof,
        F::ERROR_OPERATION_ABORTED => State::Cancelled,
        _ => State::Unknown,
    }
}
fn context(a: &mut Metadata) -> Result<()> {
    entry(a, true)?;
    // SAFETY: fixed scalar observations; output is retained before classification.
    let pid = unsafe { T::GetCurrentProcessId() }; returned(a, 1, 0);
    entry(a, true)?;
    let tid = unsafe { T::GetCurrentThreadId() }; returned(a, 1, 0);
    if a.pid != pid || a.side == 2 && a.thread != tid { return Err(fail(a, BAD_STATE, true)); }
    Ok(())
}
fn close_slot(a: &mut Metadata, role: Option<Role>, field: u32) -> Result<()> {
    let (handle, receipt) = match role {
        Some(role) => {
            let c = &a.channels[role.index()];
            match field { 0 => (c.original, c.original_close), 1 => (c.client, c.client_close),
                2 => (c.event, c.event_close), _ => return Err(Error::State) }
        },
        None => if field == 0 { (a.process.hProcess, a.process_close) }
            else { (a.process.hThread, a.thread_close) },
    };
    if receipt != 0 || !original_handle(handle)
        || role.is_none() && (!created_original(a)
            || if field == 0 { a.process_original != 1 } else { a.thread_original != 1 }) {
        return Err(fail(a, BAD_STATE, true));
    }
    entry(a, true)?;
    set_close_receipt(a, role, field, 1); // arm the ORIGINAL slot, not a stack copy
    let value = unsafe { F::CloseHandle(handle) };
    let error = if value == 0 { unsafe { F::GetLastError() } } else { 0 };
    returned(a, value, error);
    set_close_receipt(a, role, field, if value != 0 { 2 } else { 3 });
    if value == 0 { Err(fail(a, error, true)) } else { Ok(()) }
}
fn set_close_receipt(a: &mut Metadata, role: Option<Role>, field: u32, value: u32) {
    match role {
        Some(role) => {
            let c = &mut a.channels[role.index()];
            match field { 0 => c.original_close = value, 1 => c.client_close = value,
                _ => c.event_close = value }
        },
        None => if field == 0 { a.process_close = value; } else { a.thread_close = value; },
    }
}
fn close_field(a: &mut Metadata, role: Role, field: u32) -> Result<()> { close_slot(a, Some(role), field) }
fn event(a: &mut Metadata, role: Role) -> Result<()> {
    if !a.channels[role.index()].event.is_null() { return Err(fail(a, BAD_STATE, true)); }
    entry(a, false)?;
    let c = &mut a.channels[role.index()];
    c.event_close = 1; // acquiring/return-loss is NOT an empty slot
    c.event = unsafe { T::CreateEventW(null(), 1, 0, null()) };
    c.error = if c.event.is_null() { unsafe { F::GetLastError() } } else { 0 };
    let ok = !c.event.is_null(); let error = c.error;
    c.event_close = if ok { 0 } else { 4 };
    returned(a, i32::from(ok), error);
    bool_result(a)
}
fn handle_facts(a: &mut Metadata, role: Role, client: bool, inherited: bool) -> Result<()> {
    let i = role.index();
    let handle = if client { a.channels[i].client } else { a.channels[i].original };
    entry(a, false)?;
    let value = unsafe { F::GetHandleInformation(handle, &mut a.channels[i].flags) };
    let error = if value == 0 { unsafe { F::GetLastError() } } else { 0 };
    returned(a, value, error); bool_result(a)?;
    if a.channels[i].flags != u32::from(inherited) { return Err(fail(a, BAD_DATA, false)); }
    entry(a, false)?;
    a.scalar = unsafe { FS::GetFileType(handle) };
    let kind = a.scalar; returned(a, 1, 0);
    if kind != FS::FILE_TYPE_PIPE { return Err(fail(a, BAD_DATA, false)); }
    entry(a, false)?;
    // PUBLIC_OBJECT_BASIC_INFORMATION is 56 bytes on the sole x64 target;
    // GrantedAccess is its second DWORD. No variable native class is accepted.
    let value = unsafe { NtQueryObject(handle, 0, a.object_info.as_mut_ptr().cast(),
        (a.object_info.len() * 4) as u32, &mut a.object_len) };
    returned(a, value, 0);
    if value != 0 || a.object_len != 56 {
        return Err(fail(a, BAD_DATA, value == 0x103));
    }
    a.channels[i].actual_access = a.object_info[1];
    let reads = if client { role == Role::Input } else { role != Role::Input };
    let data = a.channels[i].actual_access & 3;
    let required = FS::READ_CONTROL | FS::FILE_READ_ATTRIBUTES | FS::SYNCHRONIZE;
    if a.channels[i].actual_access & required != required
        || data != (if reads { 1 } else { 2 }) || client && a.channels[i].actual_access & 4 != 0 {
        return Err(fail(a, BAD_DATA, false));
    }
    // Dependent info/state/security queries occur only after observed access.
    // NtCreateNamedPipeFile requested READ_ATTRIBUTES with exactly one DATA
    // direction, including outbound stdin; no undocumented Win32 access bit.
    entry(a, false)?;
    let c = &mut a.channels[i];
    let value = unsafe { P::GetNamedPipeInfo(handle, &mut c.flags,
        &mut c.output_size, &mut c.input_size, &mut c.maximum_instances) };
    let error = if value == 0 { unsafe { F::GetLastError() } } else { 0 };
    returned(a, value, error); bool_result(a)?;
    if a.channels[i].flags != u32::from(!client) || a.channels[i].maximum_instances != 1 {
        return Err(fail(a, BAD_DATA, false));
    }
    entry(a, false)?;
    let value = unsafe { P::GetNamedPipeHandleStateW(handle, &mut a.channels[i].mode,
        null_mut(), null_mut(), null_mut(), null_mut(), 0) };
    let error = if value == 0 { unsafe { F::GetLastError() } } else { 0 };
    returned(a, value, error); bool_result(a)?;
    if a.channels[i].mode != 0 { return Err(fail(a, BAD_DATA, false)); }
    entry(a, false)?;
    let value = if client {
        unsafe { P::GetNamedPipeServerProcessId(handle, &mut a.channels[i].server_pid) }
    } else {
        unsafe { P::GetNamedPipeClientProcessId(handle, &mut a.channels[i].client_pid) }
    };
    let error = if value == 0 { unsafe { F::GetLastError() } } else { 0 };
    returned(a, value, error); bool_result(a)
}
fn begin(io: &[IoSlot; 3], a: &mut Metadata, role: Role, operation: u32, data: &[u8], length: usize) -> Result<Observation> {
    context(a)?;
    if a.unknown != 0 || a.first != 0 || length == 0 || length > BUFFER_BYTES {
        return Err(fail(a, BAD_STATE, false));
    }
    let i = role.index();
    if a.side == 2 && a.handoff < 2 {
        if !a.channels.iter().all(|c| c.claimed == 1) { return Err(fail(a, BAD_STATE, false)); }
        if operation == 1 {
            if role != Role::Input || a.handoff != 0
                || length > HANDOFF_BYTES.saturating_sub(a.handoff_read as usize) {
                return Err(fail(a, BAD_STATE, false));
            }
        } else {
            let expected = handoff(a.channels[0].server_pid, a.pid, &a.nonce, true);
            let start = a.handoff_written as usize;
            if role != Role::Output || a.handoff != 1 || start + length > HANDOFF_BYTES
                || data != &expected[start..start + length] { return Err(fail(a, BAD_DATA, false)); }
        }
    }
    let c = &a.channels[i];
    if c.claimed != 1 || c.state != State::Idle as u32 || c.original_close != 0
        || (operation == 1) != role.reads(a.side) || !matches!(operation, 1 | 2)
        || operation == 2 && data.len() != length {
        return Err(fail(a, BAD_STATE, false));
    }
    entry(a, false)?;
    let value = unsafe { T::ResetEvent(a.channels[i].event) };
    let error = if value == 0 { unsafe { F::GetLastError() } } else { 0 };
    returned(a, value, error); bool_result(a)?;
    entry(a, false)?;
    let c = &mut a.channels[i];
    c.generation = c.generation.checked_add(1).ok_or(Error::Bounds)?;
    c.operation = operation; c.requested = length as u32; c.count = 0; c.delivered = 0;
    c.cancel_attempted = 0; c.return_seen = 1; c.state = State::Pending as u32;
    // SAFETY: the previous operation completed and its bytes were consumed.
    // These owned destinations stay pinned even if the caller drops its future.
    unsafe {
        io[i].overlapped.get().write(std::mem::zeroed());
        (*io[i].overlapped.get()).hEvent = c.event;
        if operation == 2 { std::ptr::copy_nonoverlapping(data.as_ptr(), io[i].buffer.get().cast::<u8>(), length); }
        c.returned = if operation == 1 {
            FS::ReadFile(c.original, io[i].buffer.get().cast::<u8>(), length as u32,
                null_mut(), io[i].overlapped.get())
        } else {
            FS::WriteFile(c.original, io[i].buffer.get().cast::<u8>(), length as u32,
                null_mut(), io[i].overlapped.get())
        };
        c.error = if c.returned == 0 { F::GetLastError() } else { 0 };
    }
    c.begin_return = c.returned; c.begin_error = c.error;
    c.return_seen = 2;
    let value = c.returned; let error = c.error;
    returned(a, value, error);
    if value == 0 && error != F::ERROR_IO_PENDING {
        let c = &mut a.channels[i];
        c.state = if error == F::ERROR_BROKEN_PIPE && operation == 1 { State::Eof }
            else if error == F::ERROR_OPERATION_ABORTED { State::Cancelled }
            else { State::Failed } as u32;
        if c.state == State::Failed as u32 { fail(a, error, false); }
        return Ok(observation(a, role));
    }
    poll(io, a, role) // SAME OVERLAPPED; not a repeated read/write.
}
fn poll(io: &[IoSlot; 3], a: &mut Metadata, role: Role) -> Result<Observation> {
    context(a)?;
    let i = role.index();
    if a.channels[i].state != State::Pending as u32 { return Ok(observation(a, role)); }
    entry(a, true)?;
    let c = &mut a.channels[i];
    c.returned = unsafe { IO::GetOverlappedResult(c.original, io[i].overlapped.get(), &mut c.count, 0) };
    c.error = if c.returned == 0 { unsafe { F::GetLastError() } } else { 0 };
    c.completion_return = c.returned; c.completion_error = c.error;
    c.return_seen = 2;
    let value = c.returned; let error = c.error;
    returned(a, value, error);
    let c = &mut a.channels[i];
    let completed = completed_state(value, error, c.operation, c.count, c.requested);
    if value == 0 { c.count = 0; }
    c.state = completed as u32;
    if completed == State::Unknown {
        c.uncertain = 1;
        fail(a, if value != 0 { BAD_DATA } else { error }, true);
    }
    Ok(observation(a, role))
}
fn cancel(io: &[IoSlot; 3], a: &mut Metadata, role: Role) -> Result<Observation> {
    context(a)?;
    let i = role.index();
    if a.channels[i].state != State::Pending as u32 || a.channels[i].cancel_attempted != 0 {
        return Ok(observation(a, role));
    }
    entry(a, true)?;
    let c = &mut a.channels[i];
    c.cancel_attempted = 1;
    c.cancel_return = unsafe { IO::CancelIoEx(c.original, io[i].overlapped.get()) };
    c.cancel_error = if c.cancel_return == 0 { unsafe { F::GetLastError() } } else { 0 };
    let value = c.cancel_return; let error = c.cancel_error;
    returned(a, value, error);
    accept_cancel_result(a, role);
    // Success and NOT_FOUND only request/observe a cancellation race. The same
    // operation remains Pending until GetOverlappedResult positively completes.
    Ok(observation(a, role))
}
fn take_read(io: &[IoSlot; 3], a: &mut Metadata, role: Role, destination: &mut [u8]) -> Result<Option<usize>> {
    context(a)?;
    let i = role.index();
    let c = &mut a.channels[i];
    if !role.reads(a.side) || c.operation != 1 || c.uncertain != 0 { return Err(Error::State); }
    if c.state == State::Eof as u32 { return Ok(None); }
    if c.state != State::Complete as u32 { return Err(Error::State); }
    let remaining = c.count.checked_sub(c.delivered).ok_or(Error::Unknown)? as usize;
    let count = remaining.min(destination.len());
    // SAFETY: this exact operation positively completed. Only returned bytes
    // are read; the kernel no longer has a pending write into its owned buffer.
    unsafe { std::ptr::copy_nonoverlapping(io[i].buffer.get().cast::<u8>()
        .add(c.delivered as usize), destination.as_mut_ptr(), count); }
    c.delivered += count as u32;
    if a.side == 2 && a.handoff == 0 { a.handoff_read += count as u32; }
    if c.delivered == c.count { c.state = State::Idle as u32; }
    Ok(Some(count)) // Some(0) is a successful zero-byte read, never EOF.
}
fn take_write(a: &mut Metadata, role: Role) -> Result<usize> {
    context(a)?;
    let c = &mut a.channels[role.index()];
    if role.reads(a.side) || c.operation != 2 || c.state != State::Complete as u32
        || c.uncertain != 0 { return Err(Error::State); }
    c.state = State::Idle as u32;
    if a.side == 2 && a.handoff == 1 && role == Role::Output {
        a.handoff_written += c.count;
        if a.handoff_written == HANDOFF_BYTES as u32 { a.handoff = 2; }
    }
    Ok(c.count as usize)
}
fn retire_crt_once(a: &mut Metadata, role: Role) -> Result<()> {
    let i = role.index();
    entry(a, true)?;
    let standard = unsafe { C::GetStdHandle(STD_IDS[i]) }; returned(a, 1, 0);
    entry(a, true)?;
    let crt = unsafe { _get_osfhandle(i as i32) }; returned(a, 1, 0);
    if standard != a.channels[i].original || crt as usize != a.mapping_before[i] {
        return Err(fail(a, BAD_DATA, true));
    }
    entry(a, true)?;
    a.channels[i].original_close = 1;
    let value = unsafe { _close(i as i32) }; // sole CRT consumer; never CloseHandle too
    let error = if value != 0 { unsafe { *_errno() as u32 } } else { 0 };
    returned(a, value, error);
    a.channels[i].original_close = if value == 0 { 2 } else { 3 };
    if value != 0 { return Err(fail(a, error, true)); }
    entry(a, true)?;
    let current = unsafe { C::GetStdHandle(STD_IDS[i]) }; returned(a, 1, 0);
    if !current.is_null() {
        // A shared UCRT may already retire its standard mapping on _close.
        // Otherwise only the SAME original mapping may be cleared; no foreign
        // replacement is ever consumed or used as evidence.
        if current != a.channels[i].original { return Err(fail(a, BAD_DATA, true)); }
        entry(a, true)?;
        a.channels[i].mapping_close = 1;
        let value = unsafe { C::SetStdHandle(STD_IDS[i], null_mut()) };
        let error = if value == 0 { unsafe { F::GetLastError() } } else { 0 };
        returned(a, value, error);
        if value == 0 { a.channels[i].mapping_close = 3; return Err(fail(a, error, true)); }
        entry(a, true)?;
        let observed = unsafe { C::GetStdHandle(STD_IDS[i]) }; returned(a, 1, 0);
        if !observed.is_null() { return Err(fail(a, BAD_DATA, true)); }
    }
    a.channels[i].mapping_close = 2;
    Ok(())
}
fn close_channel(a: &mut Metadata, role: Role) -> Result<Observation> {
    context(a)?;
    let i = role.index();
    let c = &a.channels[i];
    if c.state == State::Closed as u32 { return Ok(observation(a, role)); }
    if c.claimed != 1 || !known_complete(c) || c.uncertain != 0 {
        // A pending/unknown operation keeps its original handle, event and
        // OVERLAPPED alive. It is not a close attempt or a fabricated receipt.
        return Err(Error::Unknown);
    }
    let mut positive = true;
    if a.channels[i].original_close == 0 {
        positive &= if a.side == 2 { retire_crt_once(a, role).is_ok() }
            else { close_field(a, role, 0).is_ok() };
    }
    // Independent event consumption still runs after a known-complete IO even
    // when the endpoint/CRT/mapping consumer failed. Neither is retried.
    if a.channels[i].event_close == 0 { positive &= close_field(a, role, 2).is_ok(); }
    positive &= a.channels[i].original_close == 2 && a.channels[i].event_close == 2
        && (a.side != 2 || a.channels[i].mapping_close == 2);
    if !positive { return Err(fail(a, BAD_STATE, true)); }
    a.channels[i].state = State::Closed as u32;
    Ok(observation(a, role))
}

fn descriptor(launch: &LaunchStorage, a: &mut Metadata, user: &super::Sid) -> Result<()> {
    let sid = user.bytes();
    if sid.len() != 28 { return Err(Error::Unsafe); } // actual admitted ordinary account SID
    // One protected, noninherited, current-user-only ACE. No generic-write bit
    // (which includes FILE_CREATE_PIPE_INSTANCE for a client) is ever granted.
    let size = 20 + sid.len() + 8 + 8 + sid.len();
    let bytes = unsafe { std::slice::from_raw_parts_mut(launch.descriptor.get().cast::<u8>(), 512) };
    bytes[..size].fill(0);
    bytes[0] = 1; bytes[2..4].copy_from_slice(&0x9004u16.to_le_bytes());
    bytes[4..8].copy_from_slice(&20u32.to_le_bytes());
    let acl = 20 + sid.len();
    bytes[16..20].copy_from_slice(&(acl as u32).to_le_bytes());
    bytes[20..acl].copy_from_slice(sid);
    bytes[acl] = 2;
    bytes[acl + 2..acl + 4].copy_from_slice(&((size - acl) as u16).to_le_bytes());
    bytes[acl + 4..acl + 6].copy_from_slice(&1u16.to_le_bytes());
    bytes[acl + 10..acl + 12].copy_from_slice(&((8 + sid.len()) as u16).to_le_bytes());
    bytes[acl + 12..acl + 16].copy_from_slice(&ACCESS.to_le_bytes());
    bytes[acl + 16..size].copy_from_slice(sid);
    a.descriptor_len = size as u32; Ok(())
}
fn security(a: &mut Metadata, handle: F::HANDLE, user: &super::Sid) -> Result<()> {
    entry(a, false)?;
    let value = unsafe { S::GetKernelObjectSecurity(handle,
        S::OWNER_SECURITY_INFORMATION | S::DACL_SECURITY_INFORMATION,
        a.security.as_mut_ptr().cast(), (a.security.len() * 4) as u32, &mut a.security_len) };
    let error = if value == 0 { unsafe { F::GetLastError() } } else { 0 };
    returned(a, value, error); bool_result(a)?;
    if a.security_len > 4096 { return Err(fail(a, BAD_DATA, false)); }
    // Fixed bounded DATA parser already used by the native crate, not Authz
    // approximation or a caller-selected security descriptor.
    let bytes = unsafe { std::slice::from_raw_parts(a.security.as_ptr().cast::<u8>(), a.security_len as usize) };
    let facts = super::security::Observed::new(super::Refusal::none()).credential_descriptor(bytes, user)?;
    if facts.owner != *user || facts.control & 0x1000 == 0 || facts.aces.len() != 1
        || !facts.aces[0].allow || facts.aces[0].flags != 0
        || facts.aces[0].mask != ACCESS || facts.aces[0].sid != *user {
        return Err(fail(a, BAD_DATA, false));
    }
    Ok(())
}
fn wide(destination: &mut [u16], source: &str) -> Result<()> {
    if source.contains('\0') { return Err(Error::Unsafe); }
    let mut at = 0;
    for unit in source.encode_utf16() {
        if at + 1 >= destination.len() { return Err(Error::Bounds); }
        destination[at] = unit; at += 1;
    }
    if at == 0 { return Err(Error::Unsafe); }
    destination[at] = 0; Ok(())
}
fn quoted(path: &str) -> Result<String> {
    if path.is_empty() || path.contains(['\0', '"']) || path.ends_with('\\') {
        return Err(Error::Unsafe);
    }
    Ok(format!("\"{path}\""))
}
fn handoff(parent: u32, child: u32, nonce: &[u8; 32], acknowledgement: bool) -> [u8; HANDOFF_BYTES] {
    let mut bytes = [0u8; HANDOFF_BYTES];
    bytes[..8].copy_from_slice(if acknowledgement { b"MRKACK1\0" } else { b"MRKSTD1\0" });
    for (at, value) in [(8, 1u32), (12, 96), (16, parent), (20, child), (24, 1), (28, 0x0003_0201)] {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[32..64].copy_from_slice(nonce); bytes
}
fn create_pipe(launch: &LaunchStorage, a: &mut Metadata, role: Role) -> Result<()> {
    let i = role.index();
    let c = &a.channels[i];
    if a.side != 1 || a.prepared != 1 || a.create_attempted != 0 || a.unknown != 0
        || c.pipe_attempted != 0 || !c.original.is_null() || c.original_close != 0 {
        return Err(fail(a, BAD_STATE, false));
    }
    let mut hex = String::with_capacity(64);
    for byte in a.nonce { use std::fmt::Write; write!(&mut hex, "{byte:02x}").map_err(|_| Error::Bounds)?; }
    let suffix = ["stdin", "stdout", "stderr"][i];
    let leaf = format!("MobileReleaseKit.Image.{hex}.{suffix}");
    wide(&mut a.names[i], &format!("\\\\.\\pipe\\{leaf}"))?;
    let native_name = format!("\\Device\\NamedPipe\\{leaf}");
    let length = native_name.encode_utf16().count();
    if length >= 160 { return Err(fail(a, BAD_DATA, false)); }
    let storage = &launch.pipes[i];
    // SAFETY: this slot has never been entered. Pin predates these input/self
    // pointers, and none of these cells is subsequently reused or mutated.
    unsafe {
        wide(&mut *storage.name.get(), &native_name)?;
        storage.output.get().write(null_mut());
        storage.iosb.get().write(IO::IO_STATUS_BLOCK {
            Anonymous: IO::IO_STATUS_BLOCK_0 { Status: F::STATUS_PENDING },
            Information: usize::MAX,
        });
        storage.unicode.get().write(F::UNICODE_STRING {
            Length: (length * 2) as u16, MaximumLength: ((length + 1) * 2) as u16,
            Buffer: storage.name.get().cast::<u16>(),
        });
        storage.attributes.get().write(OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: null_mut(), ObjectName: storage.unicode.get(), Attributes: 0,
            SecurityDescriptor: launch.descriptor.get().cast(), SecurityQualityOfService: null_mut(),
        });
        storage.timeout.get().write(PIPE_DEFAULT_TIMEOUT_100NS);
    }
    entry(a, false)?;
    a.channels[i].pipe_attempted = 1;
    a.channels[i].original_close = 1; // never treat an unreturned create as no handle
    // FILE_CREATE refuses an existing pipe, rather than requesting another
    // instance on its ACL. FILE_CREATE_PIPE_INSTANCE is neither requested on
    // these handles nor granted to inherited clients by the protected ACL.
    // ObjectAttributes=0 makes a user-mode noninherited handle (not KERNEL_HANDLE).
    let status = unsafe { NtCreateNamedPipeFile(storage.output.get(), pipe_access(role, false),
        storage.attributes.get(), storage.iosb.get(), pipe_server_share(role), PIPE_FILE_CREATE,
        PIPE_CREATE_OPTIONS, PIPE_BYTE_STREAM_TYPE | PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_BYTE_STREAM_MODE, PIPE_QUEUE_OPERATION, 1, BUFFER_BYTES as u32,
        BUFFER_BYTES as u32, storage.timeout.get()) };
    a.channels[i].pipe_ntstatus = status;
    a.channels[i].pipe_returned = 1;
    returned(a, status, 0); // NTSTATUS, not BOOL/GetLastError
    if !definite_pipe_return(status) {
        // No read of output/IOSB here, even if a fabricated-looking positive
        // value is present. A kernel destination may still be changing.
        return Err(pipe_create_unknown(a, role, status as u32));
    }
    // SAFETY: only SUCCESS or a severity-3 definite NT error reaches this read.
    // The documented non-PENDING return is authoritative; stale IOSB is not a
    // failure-completion receipt. It is inspected only to corroborate SUCCESS.
    let handle = unsafe { *storage.output.get() };
    a.channels[i].pipe_output = handle;
    a.channels[i].pipe_output_seen = 1;
    if status != F::STATUS_SUCCESS {
        if !handle.is_null() { return Err(pipe_create_unknown(a, role, BAD_DATA)); }
        a.channels[i].pipe_custody = 1;
        a.channels[i].original_close = 4; // definite failed create, never adopted
        return Err(fail(a, status as u32, false));
    }
    let (iosb_status, information) = unsafe {
        ((*storage.iosb.get()).Anonymous.Status, (*storage.iosb.get()).Information)
    };
    a.channels[i].pipe_iosb_status = iosb_status;
    a.channels[i].pipe_information = information;
    a.channels[i].pipe_iosb_seen = 1;
    if !admitted_pipe_output(a, handle, iosb_status, information) {
        // Raw cells and snapshots remain rooted, but rejected output is never
        // put in an ordinary handle slot or offered to CloseHandle.
        return Err(pipe_create_unknown(a, role, BAD_DATA));
    }
    let c = &mut a.channels[i];
    c.original = handle; c.original_close = 0; c.claimed = 1; c.pipe_custody = 2;
    Ok(())
}

fn connect(io: &[IoSlot; 3], a: &mut Metadata, role: Role) -> Result<()> {
    let i = role.index();
    if a.channels[i].client.is_null() || a.channels[i].server_pid != a.pid
        || a.channels[i].client_pid != a.pid { return Err(fail(a, BAD_DATA, false)); }
    entry(a, false)?;
    let c = &mut a.channels[i];
    c.generation = 1; c.operation = 3; c.requested = 0;
    c.return_seen = 1; c.state = State::Pending as u32;
    unsafe {
        (*io[i].overlapped.get()).hEvent = c.event;
        c.returned = P::ConnectNamedPipe(c.original, io[i].overlapped.get());
        c.error = if c.returned == 0 { F::GetLastError() } else { 0 };
    }
    c.begin_return = c.returned; c.begin_error = c.error;
    c.return_seen = 2;
    let value = c.returned; let error = c.error;
    returned(a, value, error);
    if value != 0 || error == F::ERROR_PIPE_CONNECTED {
        // ERROR_PIPE_CONNECTED is accepted only for the admitted original
        // preopened pair above. It is not permission to adopt another client.
        a.channels[i].state = State::Complete as u32;
    } else if error != F::ERROR_IO_PENDING {
        a.channels[i].state = State::Failed as u32;
        return Err(fail(a, error, false));
    }
    Ok(())
}

/// Registered in Startup before prepare. No Drop close, spawn retry, task,
/// timer, PID reopen, caller-supplied stdio handle or arbitrary executable API.
pub struct Parent { original: ManuallyDrop<Pin<Box<Arena>>> }
impl Parent {
    pub fn new() -> Self { Self { original: fresh() } }
    pub fn prepare_once(&mut self, loader: &mut NativeBook, python: &str, bootstrap: &str,
        core: &str, cwd: &str, system_root: &str, nonce: [u8; 32]) -> Result<()> {
        let (io, launch, a) = parts(&mut self.original);
        if a.side != 0 || a.prepared != 0 || a.startup_retired != 0 || a.create_attempted != 0
            || loader.metadata_images_selection().is_none() {
            return Err(fail(a, BAD_STATE, false));
        }
        a.side = 1; a.prepared = 1; // one attempt, including any preclaim failure
        entry(a, false)?;
        a.pid = unsafe { T::GetCurrentProcessId() };
        returned(a, 1, 0);
        entry(a, false)?;
        a.thread = unsafe { T::GetCurrentThreadId() }; returned(a, 1, 0);
        loader.recheck_user()?; // original loader token; NOT a new token/owner
        let user = &loader.user.as_ref().ok_or(Error::State)?.user;
        descriptor(launch, a, user)?;
        if [python, bootstrap, core, cwd, system_root].iter().any(|value| value.len() > 4096)
            || nonce == [0; 32] || !python.ends_with("\\python\\python.exe")
            || !bootstrap.ends_with("\\config_edit_bootstrap.py") || !core.ends_with("\\core.zip")
            || !std::path::Path::new(python).is_absolute() || !std::path::Path::new(cwd).is_absolute()
            || !std::path::Path::new(system_root).is_absolute() {
            return Err(fail(a, BAD_DATA, false));
        }
        wide(&mut a.executable, python)?; wide(&mut a.cwd, cwd)?;
        let command = format!("{} -I -S -B {} {} metadata_images", quoted(python)?,
            quoted(bootstrap)?, quoted(core)?);
        wide(&mut a.command, &command)?;
        // Closed environment, double-NUL terminated by the zero-initialized tail.
        wide(&mut a.environment, &format!("SystemRoot={system_root}"))?;
        a.nonce = nonce;
        for role in [Role::Input, Role::Output, Role::Error] {
            let i = role.index();
            event(a, role)?;
            create_pipe(launch, a, role)?;
            let attributes = S::SECURITY_ATTRIBUTES { nLength: size_of::<S::SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: launch.descriptor.get().cast(), bInheritHandle: 1 };
            let access = pipe_access(role, true);
            entry(a, false)?;
            a.channels[i].client_close = 1;
            a.channels[i].client = unsafe { FS::CreateFileW(a.names[i].as_ptr(), access,
                FS::FILE_SHARE_READ | FS::FILE_SHARE_WRITE, &attributes, FS::OPEN_EXISTING,
                FS::FILE_FLAG_OVERLAPPED, null_mut()) };
            let ok = original_handle(a.channels[i].client);
            let error = if !ok { unsafe { F::GetLastError() } } else { 0 };
            a.channels[i].client_close = if ok { 0 } else { 4 };
            returned(a, i32::from(ok), error); bool_result(a)?;
            handle_facts(a, role, false, false)?;
            security(a, a.channels[i].original, user)?;
            handle_facts(a, role, true, true)?;
            if a.channels[i].server_pid != a.pid || a.channels[i].client_pid != a.pid {
                return Err(fail(a, BAD_DATA, false));
            }
            security(a, a.channels[i].client, user)?;
            a.inherited[i] = a.channels[i].client;
            connect(io, a, role)?;
        }
        // Attribute storage is fixed, aligned and retained before the sizing or
        // initialization entry. No new allocation intervenes after final claim.
        // The attribute list retains this value pointer until deletion. Keep
        // both arrays in shared UnsafeCells, outside every mutable metadata borrow.
        unsafe { launch.inherited.get().write(a.inherited); }
        a.attribute_size = size_of::<[usize; 128]>();
        entry(a, false)?;
        a.attributes_started = 1;
        let value = unsafe { T::InitializeProcThreadAttributeList(launch.attributes.get().cast(),
            1, 0, &mut a.attribute_size) };
        let error = if value == 0 { unsafe { F::GetLastError() } } else { 0 };
        returned(a, value, error); bool_result(a)?;
        a.attributes_ready = 1;
        if a.attribute_size > size_of::<[usize; 128]>() { return Err(fail(a, BAD_DATA, true)); }
        entry(a, false)?;
        let value = unsafe { T::UpdateProcThreadAttribute(launch.attributes.get().cast(), 0,
            T::PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize, launch.inherited.get().cast(),
            size_of::<[F::HANDLE; 3]>(), null_mut(), null_mut()) };
        let error = if value == 0 { unsafe { F::GetLastError() } } else { 0 };
        returned(a, value, error); bool_result(a)?;
        a.startup.StartupInfo.cb = size_of::<T::STARTUPINFOEXW>() as u32;
        a.startup.StartupInfo.dwFlags = T::STARTF_USESTDHANDLES;
        a.startup.StartupInfo.hStdInput = a.inherited[0];
        a.startup.StartupInfo.hStdOutput = a.inherited[1];
        a.startup.StartupInfo.hStdError = a.inherited[2];
        a.startup.lpAttributeList = launch.attributes.get().cast();
        a.prepared = 2;
        Ok(())
    }
    pub fn poll_connections(&mut self) -> Result<bool> {
        let (io, _, a) = parts(&mut self.original);
        if a.prepared != 2 || a.startup_retired != 0 || a.create_attempted != 0 { return Err(Error::State); }
        for role in [Role::Input, Role::Output, Role::Error] {
            if a.channels[role.index()].state == State::Pending as u32 { poll(io, a, role)?; }
        }
        Ok(a.unknown == 0 && a.first == 0 && a.channels.iter().all(|c|
            c.operation == 3 && c.return_seen == 2 && c.state == State::Complete as u32))
    }
    pub fn cancel_connections(&mut self) -> Result<()> {
        let (io, _, a) = parts(&mut self.original);
        let mut positive = true;
        for role in [Role::Input, Role::Output, Role::Error] { positive &= cancel(io, a, role).is_ok(); }
        if positive { Ok(()) } else { Err(Error::Unknown) }
    }
    pub fn ready_to_create(&self) -> bool {
        let a = metadata(&self.original);
        creation_ready(a)
    }
    /// Caller holds the original registry/STOP/deadline claim. This is the
    /// one native entry after that claim: no allocation/callback/inspection.
    pub fn create_once(&mut self) -> Result<()> {
        if !self.ready_to_create() { return Err(Error::State); }
        let a = parts(&mut self.original).2;
        entry(a, false)?;
        a.create_attempted = 1;
        a.create_bool = unsafe { T::CreateProcessW(a.executable.as_ptr(),
            a.command.as_mut_ptr(), null(), null(), 1,
            T::EXTENDED_STARTUPINFO_PRESENT | T::CREATE_UNICODE_ENVIRONMENT | T::CREATE_NO_WINDOW,
            a.environment.as_ptr().cast(), a.cwd.as_ptr(),
            &a.startup.StartupInfo, &mut a.process) };
        a.create_error = if a.create_bool == 0 { unsafe { F::GetLastError() } } else { 0 };
        a.create_returned = 1;
        returned(a, a.create_bool, a.create_error); // outputs already in the original arena
        if a.create_bool == 0 {
            let empty = empty_process_outputs(a);
            a.create_custody = if empty { 1 } else { 3 };
            return Err(fail(a, a.create_error, !empty));
        }
        if !admitted_process_outputs(a) {
            a.create_custody = 3; // preserve rejected raw outputs; never control/close them
            return Err(fail(a, BAD_DATA, true));
        }
        a.create_custody = 2; a.process_original = 1; a.thread_original = 1;
        for c in &mut a.channels { c.state = State::Idle as u32; c.operation = 0; }
        Ok(())
    }
    /// Always after actual CreateProcess return, independently of its BOOL.
    pub fn retire_startup_once(&mut self) -> Result<()> {
        let (_, launch, a) = parts(&mut self.original); let mut good = true;
        a.startup_retired = 1; // sticky: retirement permanently revokes creation readiness
        if a.create_attempted != 0 && a.create_returned == 0 { return Err(fail(a, LOST_RETURN, true)); }
        for role in [Role::Input, Role::Output, Role::Error] {
            let c = &a.channels[role.index()];
            if !c.client.is_null() && c.client != F::INVALID_HANDLE_VALUE && c.client_close == 0 {
                good &= close_field(a, role, 1).is_ok();
            }
        }
        if a.attributes_ready == 1 && a.attributes_deleted == 0 {
            good &= retire_attributes(launch, a).is_ok();
        }
        if a.thread_original == 1 && a.thread_close == 0 { good &= process_close(a, false).is_ok(); }
        if good { Ok(()) } else { Err(Error::Unknown) }
    }
    pub fn prologue(&self) -> Result<[u8; HANDOFF_BYTES]> {
        let a = metadata(&self.original);
        if !acknowledgement_ready(a) { return Err(Error::State); }
        Ok(handoff(a.pid, a.process.dwProcessId, &a.nonce, false))
    }
    pub fn accept_acknowledgement(&mut self, bytes: &[u8]) -> Result<()> {
        let a = parts(&mut self.original).2;
        if !valid_acknowledgement(a, bytes) {
            return Err(fail(a, BAD_DATA, true));
        }
        a.handoff = 1; Ok(())
    }
    pub fn process(&mut self) -> Result<Process> {
        let a = parts(&mut self.original).2;
        if a.create_attempted == 0 { return Ok(Process::NotEntered); }
        if no_child_effect(a) { return Ok(Process::Failed); }
        if !created_original(a) { return Ok(Process::Unknown); }
        if a.exit_seen == 1 { return Ok(Process::Exited(a.exit_code)); }
        if !process_control_ready(a) { return Ok(Process::Unknown); }
        context(a)?; entry(a, true)?;
        let wait = unsafe { T::WaitForSingleObject(a.process.hProcess, 0) };
        let error = if wait == F::WAIT_FAILED { unsafe { F::GetLastError() } } else { 0 };
        returned(a, wait as i32, error);
        if wait == F::WAIT_TIMEOUT { return Ok(Process::Running); }
        if wait != F::WAIT_OBJECT_0 { return Err(fail(a, error, true)); }
        entry(a, true)?;
        let value = unsafe { T::GetExitCodeProcess(a.process.hProcess, &mut a.exit_code) };
        let error = if value == 0 { unsafe { F::GetLastError() } } else { 0 };
        returned(a, value, error); bool_result(a)?;
        a.exit_seen = 1; // signalled original, not STILL_ACTIVE/PID disappearance
        process_close(a, true)?;
        Ok(Process::Exited(a.exit_code))
    }
    pub fn terminate_once(&mut self) -> Result<()> {
        let a = parts(&mut self.original).2;
        if a.force_attempted != 0 || !process_control_ready(a) { return Err(Error::State); }
        context(a)?; entry(a, true)?; a.force_attempted = 1;
        let value = unsafe { T::TerminateProcess(a.process.hProcess, 78) };
        let error = if value == 0 { unsafe { F::GetLastError() } } else { 0 };
        returned(a, value, error); bool_result(a)
    }
    pub fn no_child_effect(&self) -> bool { no_child_effect(metadata(&self.original)) }
    pub fn consumers_settled(&self) -> bool { parent_consumers_settled(metadata(&self.original)) }
    pub fn has_process_original(&self) -> bool { created_original(metadata(&self.original)) }
    pub fn settle_unspawned_once(&mut self) -> CloseOutcome {
        if !self.no_child_effect() { return CloseOutcome::Unknown; }
        let _ = self.retire_startup_once();
        let (io, _, a) = parts(&mut self.original);
        for role in [Role::Input, Role::Output, Role::Error] {
            let i = role.index();
            if a.channels[i].state == State::Pending as u32 { let _ = cancel(io, a, role); let _ = poll(io, a, role); }
            if a.channels[i].claimed == 1 && a.channels[i].state != State::Closed as u32
                && known_complete(&a.channels[i]) {
                let _ = close_channel(a, role);
            }
            if a.channels[i].claimed == 0 && (a.channels[i].original.is_null()
                || a.channels[i].original == F::INVALID_HANDLE_VALUE && a.channels[i].original_close == 4) {
                // This independent event was never a pipe-create argument.
                // Its once-close cannot settle a pending/unadmitted pipe output
                // or authorize reclamation of the retained creation storage.
                if !a.channels[i].event.is_null() && a.channels[i].event_close == 0 { let _ = close_field(a, role, 2); }
            }
        }
        if self.consumers_settled() { CloseOutcome::Settled } else { CloseOutcome::Unknown }
    }
    pub fn mark_unknown(&mut self) { fail(parts(&mut self.original).2, LOST_RETURN, true); }
}
impl Drop for Parent {
    fn drop(&mut self) {
        // Memory-only last-owner reclamation. Factory/loans keep Parent alive.
        // No destructor issues a close/cancel/wait or releases unresolved OS IO.
        if self.consumers_settled() {
            unsafe { ManuallyDrop::drop(&mut self.original); }
        }
    }
}
fn retire_attributes(launch: &LaunchStorage, a: &mut Metadata) -> Result<()> {
    entry(a, true)?; a.attributes_deleted = 1;
    unsafe { T::DeleteProcThreadAttributeList(launch.attributes.get().cast()); }
    returned(a, 1, 0); a.attributes_deleted = 2; Ok(())
}
fn process_close(a: &mut Metadata, process: bool) -> Result<()> {
    close_slot(a, None, if process { 0 } else { 1 })
}

pub struct Child { original: ManuallyDrop<Pin<Box<Arena>>> }
impl Child {
    pub fn new() -> Self { Self { original: fresh() } }
    /// Read-only fixed-descriptor snapshots, NOT ownership tokens. The Python
    /// bootstrap compares these with its own msvcrt originals before retiring
    /// its exact empty, closefd=False wrapper chains. No HANDLE is an argument.
    pub fn preflight_once(&mut self) -> Result<[usize; 3]> {
        let a = parts(&mut self.original).2;
        if a.side != 0 { return Err(fail(a, BAD_STATE, true)); }
        a.side = 2; a.preflight = 1;
        entry(a, false)?;
        a.pid = unsafe { T::GetCurrentProcessId() }; returned(a, 1, 0);
        entry(a, false)?;
        a.thread = unsafe { T::GetCurrentThreadId() }; returned(a, 1, 0);
        for role in [Role::Input, Role::Output, Role::Error] {
            let i = role.index();
            entry(a, false)?;
            a.channels[i].original = unsafe { C::GetStdHandle(STD_IDS[i]) };
            returned(a, 1, 0);
            let original = a.channels[i].original;
            if original.is_null() || original == F::INVALID_HANDLE_VALUE
                || a.channels[..i].iter().any(|c| c.original == original) {
                return Err(fail(a, BAD_DATA, false));
            }
            entry(a, false)?;
            let crt = unsafe { _get_osfhandle(i as i32) };
            returned(a, 1, 0);
            if crt < 0 || crt as usize != original as usize { return Err(fail(a, BAD_DATA, false)); }
            a.mapping_before[i] = crt as usize;
            a.channels[i].client = original; // observation alias, NEVER a second consumer
            handle_facts(a, role, true, true)?;
            if a.channels[i].server_pid == 0 || a.channels[i].server_pid == a.pid
                || i != 0 && a.channels[i].server_pid != a.channels[0].server_pid {
                return Err(fail(a, BAD_DATA, false));
            }
        }
        a.preflight = 2;
        Ok(a.mapping_before)
    }
    pub fn wrappers_retired_once(&mut self) -> Result<()> {
        let a = parts(&mut self.original).2;
        context(a)?;
        if a.preflight != 2 || a.wrappers_retired != 0 { return Err(fail(a, BAD_STATE, true)); }
        a.wrappers_retired = 1;
        // Python has already closed TextIOWrapper/Buffered*/FileIO originals
        // while no channel operation existed. This verifies that their closes
        // did not consume/change the admitted shared-UCRT or Win32 mappings.
        for i in 0..3 {
            entry(a, false)?;
            let standard = unsafe { C::GetStdHandle(STD_IDS[i]) }; returned(a, 1, 0);
            entry(a, false)?;
            let crt = unsafe { _get_osfhandle(i as i32) }; returned(a, 1, 0);
            if standard != a.channels[i].original || crt as usize != a.mapping_before[i] {
                return Err(fail(a, BAD_DATA, true));
            }
        }
        a.wrappers_retired = 2; Ok(())
    }
    fn claim(&mut self, role: Role) -> Result<()> {
        let a = parts(&mut self.original).2;
        context(a)?;
        if a.wrappers_retired != 2 || a.unknown != 0 || a.first != 0
            || a.channels[role.index()].claimed != 0 { return Err(fail(a, BAD_STATE, false)); }
        event(a, role)?;
        let c = &mut a.channels[role.index()];
        c.claimed = 1; c.return_seen = 2; c.state = State::Idle as u32;
        Ok(())
    }
    pub fn claim_input_once(&mut self) -> Result<()> { self.claim(Role::Input) }
    pub fn claim_output_once(&mut self) -> Result<()> { self.claim(Role::Output) }
    pub fn claim_error_once(&mut self) -> Result<()> { self.claim(Role::Error) }
    pub fn admit_prologue_once(&mut self, bytes: &[u8]) -> Result<()> {
        let a = parts(&mut self.original).2; context(a)?;
        if a.handoff != 0 || a.handoff_read != HANDOFF_BYTES as u32 || bytes.len() != HANDOFF_BYTES
            || !a.channels.iter().all(|c| c.claimed == 1) {
            return Err(fail(a, BAD_DATA, true));
        }
        let mut nonce = [0u8; 32]; nonce.copy_from_slice(&bytes[32..64]);
        if nonce == [0; 32] || bytes != handoff(a.channels[0].server_pid, a.pid, &nonce, false) {
            return Err(fail(a, BAD_DATA, true));
        }
        a.nonce = nonce; a.handoff = 1; Ok(())
    }
    pub fn acknowledgement(&self) -> Result<[u8; HANDOFF_BYTES]> {
        let a = metadata(&self.original);
        if a.handoff != 1 { return Err(Error::State); }
        Ok(handoff(a.channels[0].server_pid, a.pid, &a.nonce, true))
    }
    pub fn handoff_complete(&self) -> bool {
        let a = metadata(&self.original);
        a.handoff == 2 && a.unknown == 0 && a.first == 0
    }
    pub fn mark_unknown(&mut self) { fail(parts(&mut self.original).2, LOST_RETURN, true); }
    pub fn settled(&self) -> bool {
        let a = metadata(&self.original);
        a.unknown == 0 && a.call_seen != 1 && a.channels.iter().all(|c|
            c.state == State::Closed as u32 && c.original_close == 2
                && c.event_close == 2 && c.mapping_close == 2)
    }
}
macro_rules! io_methods {
    ($owner:ty) => { impl $owner {
        pub fn observation(&self, role: Role) -> Observation { observation(metadata(&self.original), role) }
        pub fn begin_read(&mut self, role: Role, length: usize) -> Result<Observation> {
            let (io, _, a) = parts(&mut self.original); begin(io, a, role, 1, &[], length)
        }
        pub fn begin_write(&mut self, role: Role, bytes: &[u8]) -> Result<Observation> {
            let (io, _, a) = parts(&mut self.original); begin(io, a, role, 2, bytes, bytes.len())
        }
        pub fn poll(&mut self, role: Role) -> Result<Observation> {
            let (io, _, a) = parts(&mut self.original); poll(io, a, role)
        }
        pub fn cancel(&mut self, role: Role) -> Result<Observation> {
            let (io, _, a) = parts(&mut self.original); cancel(io, a, role)
        }
        pub fn take_read(&mut self, role: Role, bytes: &mut [u8]) -> Result<Option<usize>> {
            let (io, _, a) = parts(&mut self.original); take_read(io, a, role, bytes)
        }
        pub fn take_write(&mut self, role: Role) -> Result<usize> { take_write(parts(&mut self.original).2, role) }
        pub fn close_once(&mut self, role: Role) -> Result<Observation> { close_channel(parts(&mut self.original).2, role) }
    } };
}
io_methods!(Parent);
io_methods!(Child);

#[cfg(test)]
#[path = "image_stdio_tests.rs"]
mod tests;
