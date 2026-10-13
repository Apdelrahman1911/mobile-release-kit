//! The only unsafe boundary in this isolated executable. The four sodium
//! declarations match the pinned official 1.0.22 headers. They are NEVER linked
//! into or called by Desktop. Darwin policy/close declarations are checked by
//! the same target's compile-only abi-check.c, not a runtime path selector.

use std::ffi::{c_int, c_uchar, c_ulonglong, c_void};
use std::fs::File;
use std::os::fd::{FromRawFd, IntoRawFd};

use crate::protocol::{self, Request, INPUT_STORAGE, MAX_CIPHERTEXT, PUBLIC_KEY_BYTES,
    REQUEST_HEADER, REQUEST_PREFIX, SEAL_BYTES};

#[link(name = "sodium", kind = "static")]
unsafe extern "C" {
    fn sodium_init() -> c_int;
    fn crypto_box_seal(c: *mut c_uchar, m: *const c_uchar, mlen: c_ulonglong,
        pk: *const c_uchar) -> c_int;
    fn sodium_memzero(pnt: *mut c_void, len: usize);
    fn randombytes_close() -> c_int;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Rlimit { current: u64, maximum: u64 }

// These are fixed Darwin64 libc interfaces, not configurable native commands.
#[link(name = "System")]
unsafe extern "C" {
    fn getrlimit(resource: c_int, result: *mut Rlimit) -> c_int;
    fn setrlimit(resource: c_int, value: *const Rlimit) -> c_int;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn close(fd: c_int) -> c_int;
}

const RLIMIT_CPU: c_int = 0;
const RLIMIT_FSIZE: c_int = 1;
const RLIMIT_CORE: c_int = 4;
const RLIMIT_NOFILE: c_int = 8;
const F_GETFD: c_int = 1;

const _: () = {
    assert!(std::mem::size_of::<c_uchar>() == 1);
    assert!(std::mem::size_of::<c_int>() == 4);
    assert!(std::mem::size_of::<c_ulonglong>() == 8);
    assert!(std::mem::size_of::<usize>() == 8);
    assert!(std::mem::size_of::<Rlimit>() == 16);
    assert!(std::mem::align_of::<Rlimit>() == 8);
    assert!(PUBLIC_KEY_BYTES == 32 && SEAL_BYTES == 48);
    assert!(protocol::MAX_INPUT_FRAME == 49_196);
    assert!(protocol::MAX_OUTPUT_FRAME == 49_212);
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Failure {
    Policy,
    Arguments,
    Allocation,
    StandardOriginals,
    Input(protocol::Refusal),
    InputClose,
    Initialization,
    Seal,
    RandomClose,
    Output(protocol::Refusal),
    OutputClose,
    ErrorClose,
}

fn first(failure: &mut Option<Failure>, result: Result<(), Failure>) {
    if let Err(error) = result {
        if failure.is_none() { *failure = Some(error); }
    }
}

fn lower_limit(resource: c_int, cap: u64) -> Result<Rlimit, Failure> {
    let mut old = Rlimit { current: 0, maximum: 0 };
    // SAFETY: fixed Darwin interface; both output fields are initialized and
    // writable for the whole call. No owned native handle is acquired.
    if unsafe { getrlimit(resource, &mut old) } != 0 || old.current > old.maximum {
        return Err(Failure::Policy);
    }
    let wanted = Rlimit { current: old.current.min(cap), maximum: old.maximum.min(cap) };
    // Only lower this child process's limits. Never change Desktop's limits or
    // turn a low inherited allowance into a new, larger allowance.
    if unsafe { setrlimit(resource, &wanted) } != 0 { return Err(Failure::Policy); }
    let mut actual = Rlimit { current: 0, maximum: 0 };
    if unsafe { getrlimit(resource, &mut actual) } != 0 || actual.current != wanted.current
        || actual.maximum != wanted.maximum
    {
        return Err(Failure::Policy);
    }
    Ok(actual)
}

fn establish_policy() -> Result<(), Failure> {
    // MUST finish before buffers are filled or any stdin byte is consumed.
    // This is a child CPU ceiling, not a replacement/renewal of the parent's
    // already-running 10-second wall deadline and one cleanup endpoint.
    lower_limit(RLIMIT_CORE, 0)?;
    let cpu = lower_limit(RLIMIT_CPU, 2)?;
    lower_limit(RLIMIT_FSIZE, 65_536)?;
    let files = lower_limit(RLIMIT_NOFILE, 32)?;
    if cpu.current == 0 || files.current < 8 { return Err(Failure::Policy); }
    Ok(())
}

struct Wiped<const N: usize> {
    bytes: Box<[u8; N]>,
    wiped: bool,
}

impl<const N: usize> Wiped<N> {
    fn allocate() -> Result<Self, Failure> {
        // Allocation and initialization happen before receiving any secret.
        // The boxed bytes never move when their small owner is moved.
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(N).map_err(|_| Failure::Allocation)?;
        bytes.resize(N, 0u8);
        let bytes: Box<[u8; N]> = bytes.into_boxed_slice().try_into()
            .map_err(|_| Failure::Allocation)?;
        Ok(Self { bytes, wiped: false })
    }
    fn wipe(&mut self) {
        if self.wiped { return; }
        // SAFETY: the entire initialized, uniquely owned allocation is valid
        // and writable. Canonical memzero has no initialization prerequisite.
        unsafe { sodium_memzero(self.bytes.as_mut_ptr().cast::<c_void>(), N) };
        self.wiped = true; // only after the actual call returns
    }
}

impl<const N: usize> Drop for Wiped<N> {
    fn drop(&mut self) { self.wipe(); }
}

struct OriginalFile { file: Option<File> }

impl OriginalFile {
    fn original(&mut self) -> &mut File {
        // Only called while this fixed slot owns its original, before its sole
        // consume_close below. No caller-visible mutable descriptor API exists.
        self.file.as_mut().expect("fixed helper original slot")
    }
    fn consume_close(&mut self) -> bool {
        let Some(file) = self.file.take() else { return false; };
        let fd = file.into_raw_fd();
        // SAFETY: sole File ownership was consumed above. A nonzero result is
        // unknown/error, never retried (including EINTR), and vetoes success.
        unsafe { close(fd) == 0 }
    }
}

impl Drop for OriginalFile {
    fn drop(&mut self) {
        if self.file.is_some() { let _ = self.consume_close(); }
        // A drop-only path does not supply any positive close receipt. The
        // normal path explicitly checks all three consuming closes below.
    }
}

struct Originals { input: OriginalFile, output: OriginalFile, error: OriginalFile }

impl Originals {
    fn take() -> Result<Self, Failure> {
        // This single-threaded child never creates another consumer of these
        // originals. Refuse invalid inherited FDs before constructing Files.
        for fd in [0, 1, 2] {
            if unsafe { fcntl(fd, F_GETFD) } < 0 { return Err(Failure::StandardOriginals); }
        }
        // SAFETY: each checked inherited descriptor is owned exactly once;
        // no stdin/stdout/stderr buffered singleton is used by the helper.
        Ok(unsafe {
            Self {
                input: OriginalFile { file: Some(File::from_raw_fd(0)) },
                output: OriginalFile { file: Some(File::from_raw_fd(1)) },
                error: OriginalFile { file: Some(File::from_raw_fd(2)) },
            }
        })
    }
}

fn seal_captured(input: &mut Wiped<INPUT_STORAGE>, request: Request,
    output: &mut Wiped<MAX_CIPHERTEXT>) -> Result<(), Failure>
{
    let length = c_ulonglong::try_from(request.plaintext_bytes()).map_err(|_| Failure::Seal);
    let mut failure = None;
    let mut initialized_attempt = false;
    match length {
        Err(error) => failure = Some(error),
        Ok(length) => {
            initialized_attempt = true;
            // Even initialization can abort on failed entropy. Only this
            // separate, parent-owned process ever enters canonical sodium.
            let initialized = unsafe { sodium_init() };
            if initialized != 0 && initialized != 1 { failure = Some(Failure::Initialization); }
            else {
                // SAFETY: output has >= n+48 writable bytes, m has n bytes,
                // pk has 32 bytes; allocations are separate and remain live.
                // For empty m the pointer still refers to valid storage.
                let result = unsafe {
                    crypto_box_seal(output.bytes.as_mut_ptr(),
                        input.bytes.as_ptr().add(REQUEST_HEADER), length,
                        input.bytes.as_ptr().add(REQUEST_PREFIX))
                };
                if result != 0 { failure = Some(Failure::Seal); }
            }
        }
    }
    // No output occurs before the returned wipe and RNG consuming close.
    input.wipe();
    if initialized_attempt && unsafe { randombytes_close() } != 0 {
        first(&mut failure, Err(Failure::RandomClose));
    }
    match failure {
        Some(error) => { output.wipe(); Err(error) }
        None => Ok(()),
    }
}

pub(super) fn run() -> Result<(), Failure> {
    establish_policy()?;
    if std::env::args_os().nth(1).is_some() { return Err(Failure::Arguments); }
    let mut input = Wiped::<INPUT_STORAGE>::allocate()?;
    let mut output = Wiped::<MAX_CIPHERTEXT>::allocate()?;
    let mut originals = Originals::take()?;

    let request = protocol::read_request(originals.input.original(), &mut input.bytes);
    let mut failure = request.as_ref().err().copied().map(Failure::Input);
    first(&mut failure, if originals.input.consume_close() { Ok(()) } else { Err(Failure::InputClose) });
    if failure.is_none() {
        if let Ok(request) = request {
            first(&mut failure, seal_captured(&mut input, request, &mut output));
        }
    }
    input.wipe(); // also covers every normally returned framing/IO/close error
    if failure.is_none() {
        if let Ok(request) = request {
            first(&mut failure, protocol::write_response(originals.output.original(), request,
                &output.bytes[..request.ciphertext_bytes()]).map_err(Failure::Output));
        }
    }
    output.wipe();
    first(&mut failure, if originals.output.consume_close() { Ok(()) } else { Err(Failure::OutputClose) });
    first(&mut failure, if originals.error.consume_close() { Ok(()) } else { Err(Failure::ErrorClose) });
    match failure { Some(error) => Err(error), None => Ok(()) }
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod tests;
