//! Current-user DPAPI primitive, not a vault owner or availability grant.
//!
//! This adapter is deliberately UNWIRED. The existing application OriginalWork
//! must admit and retain the synchronous call, its inputs and this actual return.
//! It runs off the UI/deadline thread; it creates no thread, timeout or retry.
//! STOP cannot cancel an entered Windows call. Keep its original worker until it
//! returns, then reject a late/stale result before publishing any key or file.
//!
//! The caller supplies the validated fixed 64-byte vault-header prefix (format,
//! algorithm, backend, vault and generation identity) as DPAPI entropy. This
//! adapter neither parses that format nor grants authority from its spelling.
//! The ordinary nonimpersonated user/profile, durable initialization reservation,
//! private original-file custody and authenticated header remain caller gates.
//! No machine-wide protection, UI prompt, credential-store overwrite, plaintext
//! fallback, key generation, filesystem operation or missing-key repair exists.
//!
//! Input/accepted-output caps are not a preallocation bound on Windows internals.
//! Every returned native allocation is wiped and LocalFree is attempted once,
//! including native-error/shape/bounds/copy refusals. A failed free is retained in
//! the returned object as unknown custody, never retried or treated as finality.
//! Native cbData is a reported payload length, not an allocator-capacity receipt.
//! A caller must not substitute it for proof that an unknown allocation is gone.

use std::cell::Cell;
use std::marker::PhantomData;
use std::mem::size_of;
use std::ptr::{null, null_mut};
use std::sync::atomic::{compiler_fence, Ordering};
use std::time::Instant;
use windows_sys::Win32::Foundation as F;
use windows_sys::Win32::Security::Cryptography as C;

pub const KEY_BYTES: usize = 32;
pub const HEADER_CONTEXT_BYTES: usize = 64;
pub const MAX_PROTECTED_BYTES: usize = 4096;
const FLAGS: u32 = C::CRYPTPROTECT_UI_FORBIDDEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Api { Protect, Unprotect }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal { InputBounds, Native, OutputShape, OutputBounds, Allocation, CleanupUnknown }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cleanup { NoAllocation, Released, Unknown }
impl Cleanup {
    fn known(self) -> bool { matches!(self, Self::NoAllocation | Self::Released) }
}

/// Nonsecret facts about this one returning call; not an OriginalWork join.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    pub api: Api,
    /// None means input admission refused before entering Windows.
    pub native_return: Option<i32>,
    /// GetLastError captured immediately after an actual false native return.
    pub native_error: Option<u32>,
    pub reported_native_bytes: u32,
    pub native_allocation_returned: bool,
    pub cleanup: Cleanup,
    /// Captured immediately after the one failed LocalFree, never an invented code.
    pub cleanup_error: Option<u32>,
    /// First actual refusal observation on the existing process monotonic clock.
    /// Captured before later native disposal; not a new deadline or a wire field.
    pub first_failure_at: Option<Instant>,
}

/// Bounded protected bytes, not an authenticated vault record or key lease.
/// No Debug/Display/Clone/serde implementation or public byte field is provided.
pub struct ProtectedBlob { bytes: Vec<u8> }
impl ProtectedBlob {
    fn copy_from(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.is_empty() || bytes.len() > MAX_PROTECTED_BYTES { return Err(Refusal::OutputBounds); }
        let mut result = Self { bytes: Vec::new() };
        result.bytes.try_reserve_exact(bytes.len()).map_err(|_| Refusal::Allocation)?;
        if result.bytes.capacity() > MAX_PROTECTED_BYTES { return Err(Refusal::Allocation); }
        result.bytes.extend_from_slice(bytes);
        Ok(result)
    }
    /// Only protected ciphertext is lent to the later original-file writer.
    pub fn with_protected_bytes<R>(&self, use_blob: impl FnOnce(&[u8]) -> R) -> R {
        use_blob(&self.bytes)
    }
    pub fn len(&self) -> usize { self.bytes.len() }
    pub fn is_empty(&self) -> bool { self.bytes.is_empty() }
    /// Includes actual Rust Vec capacity, not merely its logical length.
    pub fn retained_bytes(&self) -> usize { size_of::<Self>() + self.bytes.capacity() }
}
impl Drop for ProtectedBlob {
    fn drop(&mut self) { wipe(&mut self.bytes); }
}

/// One opaque 32-byte candidate. Only this module can construct it.
/// Its native allocation was positively wiped/freed before it can leave a
/// successful NativeResult. Header authentication and current owner admission
/// are STILL required; DPAPI success alone must never publish a usable lease.
pub struct KeyCandidate { bytes: [u8; KEY_BYTES] }
impl KeyCandidate {
    fn copy_from(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() != KEY_BYTES { return Err(Refusal::OutputShape); }
        let mut result = Self { bytes: [0; KEY_BYTES] };
        result.bytes.copy_from_slice(bytes);
        Ok(result)
    }
    /// Synchronous consuming header-authentication seam, not a key getter.
    /// The caller must reserve/transfer the resulting cipher's actual charge
    /// before refunding this candidate. No callback or borrow is retained here.
    pub fn consume<R>(self, authenticate: impl FnOnce(&[u8; KEY_BYTES]) -> R) -> R {
        authenticate(&self.bytes)
    }
    pub fn retained_bytes(&self) -> usize { size_of::<Self>() }
}
impl Drop for KeyCandidate {
    fn drop(&mut self) { wipe(&mut self.bytes); }
}

/// Actual result and any uncertain allocation remain in the original owner.
/// Taking the value is neither a native-worker join nor a publication permit.
/// On LocalFree failure this object retains the opaque pointer/length and no
/// candidate is obtainable. Dropping it is NOT proof of cleanup; no retry occurs.
pub struct NativeResult<T> {
    facts: Facts,
    refusal: Option<Refusal>,
    value: Option<T>,
    allocation: NativeOutput,
}
impl<T> NativeResult<T> {
    pub fn facts(&self) -> Facts { self.facts }
    pub fn refusal(&self) -> Option<Refusal> { self.refusal }
    pub fn native_result_succeeded(&self) -> bool {
        self.facts.native_return.is_some_and(|value| value != 0)
            && self.refusal.is_none() && self.facts.cleanup.known() && self.facts.first_failure_at.is_none()
    }
    pub fn take_value(&mut self) -> Option<T> {
        if self.native_result_succeeded() { self.value.take() } else { None }
    }
    /// Some(0) is still an unreleased original, NOT an empty/all-freed proof.
    /// The reported length excludes Windows allocator padding/metadata. Retain
    /// unknown custody regardless of this number; no capacity refund is granted.
    pub fn reported_unreleased_native_bytes(&self) -> Option<u32> {
        (!self.allocation.blob.pbData.is_null()).then_some(self.allocation.blob.cbData)
    }
}

/// Protect the original initialization owner's borrowed fixed-size key.
/// The caller already owns/charges it and supplies the same validated header
/// prefix it will authenticate on later retrieval. No key copy is retained here.
pub fn protect(key: &[u8; KEY_BYTES], header_context: &[u8; HEADER_CONTEXT_BYTES]) -> NativeResult<ProtectedBlob> {
    invoke(Api::Protect, key, header_context, ProtectedBlob::copy_from)
}

/// Retrieve only a fixed-size candidate from a bounded original protected blob.
/// Corrupt/wrong-user/wrong-context Windows failures have no fallback branch.
pub fn unprotect(protected: &[u8], header_context: &[u8; HEADER_CONTEXT_BYTES]) -> NativeResult<KeyCandidate> {
    invoke(Api::Unprotect, protected, header_context, KeyCandidate::copy_from)
}

fn input_length(api: Api, length: usize) -> Result<u32, Refusal> {
    let admitted = match api {
        Api::Protect => length == KEY_BYTES,
        Api::Unprotect => length != 0 && length <= MAX_PROTECTED_BYTES,
    };
    if !admitted { return Err(Refusal::InputBounds); }
    u32::try_from(length).map_err(|_| Refusal::InputBounds)
}

fn output_length(api: Api, length: u32, allocated: bool) -> Result<usize, Refusal> {
    if !allocated || length == 0 { return Err(Refusal::OutputShape); }
    let length = usize::try_from(length).map_err(|_| Refusal::OutputBounds)?;
    match api {
        Api::Protect if length > MAX_PROTECTED_BYTES => Err(Refusal::OutputBounds),
        Api::Unprotect if length != KEY_BYTES => Err(Refusal::OutputShape),
        _ => Ok(length),
    }
}

fn invoke<T>(api: Api, input: &[u8], header_context: &[u8; HEADER_CONTEXT_BYTES],
    copy: impl FnOnce(&[u8]) -> Result<T, Refusal>) -> NativeResult<T> {
    // Prearmed before the native call can publish ANY returned pointer. The
    // native API writes directly into this guard, including false-return paths.
    let mut allocation = NativeOutput::new();
    let mut facts = Facts { api, native_return: None, native_error: None,
        reported_native_bytes: 0, native_allocation_returned: false,
        cleanup: Cleanup::NoAllocation, cleanup_error: None, first_failure_at: None };
    let lengths = input_length(api, input.len()).and_then(|input| {
        u32::try_from(HEADER_CONTEXT_BYTES).map(|context| (input, context)).map_err(|_| Refusal::InputBounds)
    });
    let (input_bytes, context_bytes) = match lengths {
        Ok(lengths) => lengths,
        Err(refusal) => {
            observe_first_failure(&mut facts.first_failure_at, Some(Instant::now()));
            let (cleanup, error) = allocation.release(); facts.cleanup = cleanup; facts.cleanup_error = error;
            observe_first_failure(&mut facts.first_failure_at, allocation.cleanup_failed_at);
            return NativeResult { facts, refusal: Some(refusal), value: None, allocation };
        },
    };
    let source = C::CRYPT_INTEGER_BLOB { cbData: input_bytes, pbData: input.as_ptr().cast_mut() };
    let entropy = C::CRYPT_INTEGER_BLOB { cbData: context_bytes, pbData: header_context.as_ptr().cast_mut() };
    // SAFETY: documented synchronous APIs borrow the complete admitted input
    // and fixed entropy as read-only data despite the ABI's mutable pbData.
    // The prearmed output guard is exclusive/stable through the call. No native
    // callback, retained input pointer, returned description or prompt is asked
    // for. Exactly UI_FORBIDDEN is used: no LOCAL_MACHINE/AUDIT/prompt flags.
    let returned = unsafe { match api {
        Api::Protect => C::CryptProtectData(&source, null(), &entropy, null(), null(), FLAGS, &mut allocation.blob),
        Api::Unprotect => C::CryptUnprotectData(&source, null_mut(), &entropy, null(), null(), FLAGS, &mut allocation.blob),
    } };
    // No other native function occurs before capture of the original error.
    let native_error = if returned == 0 { Some(unsafe { F::GetLastError() }) } else { None };
    facts.native_return = Some(returned); facts.native_error = native_error;
    facts.reported_native_bytes = allocation.blob.cbData;
    facts.native_allocation_returned = !allocation.blob.pbData.is_null();
    // Save the actual native scalar facts before the clock observation. The
    // first failure time still precedes shape handling, wipe and LocalFree.
    if returned == 0 { observe_first_failure(&mut facts.first_failure_at, Some(Instant::now())); }
    let copied = if returned == 0 { Err(Refusal::Native) }
        else { allocation.payload(api).and_then(copy) };
    let (mut value, mut refusal) = match copied {
        Ok(value) => (Some(value), None),
        Err(reason) => {
            observe_first_failure(&mut facts.first_failure_at, Some(Instant::now()));
            (None, Some(reason))
        },
    };
    let (cleanup, error) = allocation.release(); facts.cleanup = cleanup; facts.cleanup_error = error;
    observe_first_failure(&mut facts.first_failure_at, allocation.cleanup_failed_at);
    settle_value(&mut value, &mut refusal, cleanup);
    NativeResult { facts, refusal, value, allocation }
}

// Observation only. The owner applies its existing earliest work/cleanup
// endpoints; no duration, worker, wait or retry is introduced by this adapter.
fn observe_first_failure(first: &mut Option<Instant>, observed: Option<Instant>) {
    if first.is_none() { *first = observed; }
}

fn settle_value<T>(value: &mut Option<T>, refusal: &mut Option<Refusal>, cleanup: Cleanup) {
    if !cleanup.known() {
        // Drop any private copied key BEFORE it can leave this actual call.
        // Keep an earlier native/shape/allocation refusal; cleanup is separate.
        *value = None;
        if refusal.is_none() { *refusal = Some(Refusal::CleanupUnknown); }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReleaseState { Fresh, Attempted, NoAllocation, Released, Unknown }
impl ReleaseState {
    fn begin(&mut self, allocated: bool) -> bool {
        if *self != Self::Fresh { return false; }
        *self = if allocated { Self::Attempted } else { Self::NoAllocation };
        allocated
    }
    fn returned(&mut self, success: bool) {
        // Only the first actual LocalFree return can settle this original.
        if *self == Self::Attempted { *self = if success { Self::Released } else { Self::Unknown }; }
    }
    fn cleanup(self) -> Cleanup {
        match self { Self::NoAllocation => Cleanup::NoAllocation, Self::Released => Cleanup::Released,
            Self::Fresh | Self::Attempted | Self::Unknown => Cleanup::Unknown }
    }
}

struct NativeOutput {
    blob: C::CRYPT_INTEGER_BLOB,
    state: ReleaseState,
    cleanup_error: Option<u32>,
    cleanup_failed_at: Option<Instant>,
    _not_sync: PhantomData<Cell<()>>,
}
// SAFETY: only the one synchronous call mutates this original blob. Moving its
// exclusively owned return between the original worker and document book never
// overlaps a native borrow; LocalFree permits this process-local allocation to
// be freed by another thread. No raw pointer is exposed and it is not Sync.
unsafe impl Send for NativeOutput {}
impl NativeOutput {
    fn new() -> Self {
        Self { blob: C::CRYPT_INTEGER_BLOB { cbData: 0, pbData: null_mut() },
            state: ReleaseState::Fresh, cleanup_error: None, cleanup_failed_at: None, _not_sync: PhantomData }
    }
    fn payload(&self, api: Api) -> Result<&[u8], Refusal> {
        if self.state != ReleaseState::Fresh { return Err(Refusal::CleanupUnknown); }
        let length = output_length(api, self.blob.cbData, !self.blob.pbData.is_null())?;
        // SAFETY: the returning trusted Windows API owns this pointer and
        // documents cbData initialized output bytes. Shape/cap checks precede
        // slice creation; this shared borrow ends before wipe/free begins.
        Ok(unsafe { std::slice::from_raw_parts(self.blob.pbData, length) })
    }
    fn release(&mut self) -> (Cleanup, Option<u32>) {
        if self.state.begin(!self.blob.pbData.is_null()) {
            // The supported crate is x86_64, so widening DWORD to usize cannot
            // truncate. Even refused/oversized output is disposed, never sliced
            // as an accepted key/blob or abandoned just because it exceeded cap.
            // SAFETY: the documented LocalAlloc output remains exclusively owned
            // and live through its reported payload bytes. Wipe uses volatile
            // stores before the single native deallocation attempt.
            unsafe { wipe_raw(self.blob.pbData, self.blob.cbData as usize); }
            // SAFETY: original DPAPI LocalAlloc pointer, first attempt only.
            let remaining = unsafe { F::LocalFree(self.blob.pbData.cast()) };
            let error = if remaining.is_null() { None } else { Some(unsafe { F::GetLastError() }) };
            self.cleanup_error = error;
            self.state.returned(remaining.is_null());
            if !remaining.is_null() { observe_first_failure(&mut self.cleanup_failed_at, Some(Instant::now())); }
            if remaining.is_null() { self.blob.pbData = null_mut(); self.blob.cbData = 0; }
            // On failure retain the original pointer/length but never dereference
            // or free it again. Caller retains this Unknown original, not a key.
        }
        (self.state.cleanup(), self.cleanup_error)
    }
}
impl Drop for NativeOutput {
    fn drop(&mut self) {
        // Panic/error fallback still wipes and attempts each original once.
        // An already failed/uncertain attempt is NEVER repeated by Drop.
        let _ = self.release();
    }
}

fn wipe(bytes: &mut [u8]) {
    for byte in bytes { unsafe { std::ptr::write_volatile(byte, 0); } }
    compiler_fence(Ordering::SeqCst);
}
unsafe fn wipe_raw(pointer: *mut u8, length: usize) {
    for index in 0..length {
        // SAFETY: caller owns the live initialized allocation through length.
        unsafe { std::ptr::write_volatile(pointer.add(index), 0); }
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    // DATA only: none of these cases calls DPAPI, LocalFree or another native API.
    // Wrong-user/corrupt-blob/entropy and real native allocation/cleanup behavior
    // remain explicit native obligations for the later source-bound owner lane.
    #[test]
    fn fixed_inputs_and_outputs_refuse_before_copy_or_native_entry() {
        assert_eq!(input_length(Api::Protect, KEY_BYTES), Ok(KEY_BYTES as u32));
        for length in [0, KEY_BYTES - 1, KEY_BYTES + 1, usize::MAX] {
            assert_eq!(input_length(Api::Protect, length), Err(Refusal::InputBounds));
        }
        assert_eq!(input_length(Api::Unprotect, MAX_PROTECTED_BYTES), Ok(MAX_PROTECTED_BYTES as u32));
        for length in [0, MAX_PROTECTED_BYTES + 1, usize::MAX] {
            assert_eq!(input_length(Api::Unprotect, length), Err(Refusal::InputBounds));
        }
        assert_eq!(output_length(Api::Protect, MAX_PROTECTED_BYTES as u32, true), Ok(MAX_PROTECTED_BYTES));
        assert_eq!(output_length(Api::Protect, MAX_PROTECTED_BYTES as u32 + 1, true), Err(Refusal::OutputBounds));
        for length in [0, KEY_BYTES as u32 - 1, KEY_BYTES as u32 + 1, u32::MAX] {
            assert_eq!(output_length(Api::Unprotect, length, true), Err(Refusal::OutputShape));
        }
        assert_eq!(output_length(Api::Unprotect, KEY_BYTES as u32, false), Err(Refusal::OutputShape));
        assert_eq!(output_length(Api::Unprotect, KEY_BYTES as u32, true), Ok(KEY_BYTES));
        assert_eq!(FLAGS, C::CRYPTPROTECT_UI_FORBIDDEN);
        assert_eq!(FLAGS & C::CRYPTPROTECT_LOCAL_MACHINE, 0);
    }

    #[test]
    fn release_attempt_and_unknown_are_monotonic_without_native_calls() {
        for success in [false, true] {
            let mut state = ReleaseState::Fresh;
            assert!(state.begin(true)); assert!(!state.begin(true));
            assert_eq!(state.cleanup(), Cleanup::Unknown);
            state.returned(success);
            let original = state.cleanup();
            assert_eq!(original, if success { Cleanup::Released } else { Cleanup::Unknown });
            state.returned(!success); assert!(!state.begin(true));
            assert_eq!(state.cleanup(), original);
        }
        let mut empty = ReleaseState::Fresh;
        assert!(!empty.begin(false)); empty.returned(true);
        assert_eq!(empty.cleanup(), Cleanup::NoAllocation);
        assert!(!empty.begin(true));
    }

    #[test]
    fn cleanup_unknown_drops_private_value_and_preserves_original_failure() {
        struct Witness<'a>(&'a Cell<u32>);
        impl Drop for Witness<'_> { fn drop(&mut self) { self.0.set(self.0.get() + 1); } }
        let drops = Cell::new(0);
        for earlier in [None, Some(Refusal::Native), Some(Refusal::OutputBounds)] {
            let mut value = Some(Witness(&drops)); let mut refusal = earlier;
            let before = drops.get(); settle_value(&mut value, &mut refusal, Cleanup::Unknown);
            assert!(value.is_none()); assert_eq!(drops.get(), before + 1);
            assert_eq!(refusal, earlier.or(Some(Refusal::CleanupUnknown)));
        }
        let mut value = Some(Witness(&drops)); let mut refusal = None;
        settle_value(&mut value, &mut refusal, Cleanup::Released);
        assert!(value.is_some()); assert!(refusal.is_none());
    }

    #[test]
    fn first_refusal_time_precedes_and_survives_delayed_cleanup_data() {
        // Supplied monotonic DATA endpoints, not sleeping or native execution.
        // These use the same first-observation merge as actual invoke/release.
        let first = Instant::now();
        let cleanup = first.checked_add(std::time::Duration::from_secs(30)).unwrap();
        let later = cleanup.checked_add(std::time::Duration::from_secs(30)).unwrap();
        for reason in [Refusal::InputBounds, Refusal::Native, Refusal::OutputShape,
            Refusal::OutputBounds, Refusal::Allocation] {
            let mut observed = None;
            observe_first_failure(&mut observed, Some(first));
            let mut value = None::<KeyCandidate>; let mut refusal = Some(reason);
            observe_first_failure(&mut observed, Some(cleanup));
            settle_value(&mut value, &mut refusal, Cleanup::Unknown);
            observe_first_failure(&mut observed, Some(later));
            assert_eq!(observed, Some(first)); assert_eq!(refusal, Some(reason));
            assert!(value.is_none());
        }
    }

    #[test]
    fn first_failed_free_time_is_not_an_eventual_return_or_success_clock() {
        let failed_free = Instant::now();
        let returned = failed_free.checked_add(std::time::Duration::from_secs(30)).unwrap();
        let mut observed = None;
        observe_first_failure(&mut observed, None); // No failure in earlier stages.
        assert_eq!(observed, None);
        observe_first_failure(&mut observed, Some(failed_free));
        let mut value = None::<KeyCandidate>; let mut refusal = None;
        settle_value(&mut value, &mut refusal, Cleanup::Unknown);
        observe_first_failure(&mut observed, Some(returned));
        assert_eq!(observed, Some(failed_free)); assert_eq!(refusal, Some(Refusal::CleanupUnknown));
        let mut success = None;
        observe_first_failure(&mut success, None);
        let mut successful_value = Some(()); let mut successful_refusal = None;
        settle_value(&mut successful_value, &mut successful_refusal, Cleanup::Released);
        assert_eq!(success, None); assert_eq!(successful_value, Some(())); assert_eq!(successful_refusal, None);
    }

    #[test]
    fn fixed_candidate_consumes_synchronously_and_owned_wipe_clears_bytes() {
        assert!(KeyCandidate::copy_from(&[7; KEY_BYTES - 1]).is_err());
        let candidate = match KeyCandidate::copy_from(&[7; KEY_BYTES]) { Ok(value) => value, Err(_) => panic!("DATA candidate refused") };
        assert_eq!(candidate.retained_bytes(), KEY_BYTES);
        assert_eq!(candidate.consume(|key| key.iter().map(|byte| u32::from(*byte)).sum::<u32>()), 7 * KEY_BYTES as u32);
        let mut owned = [7; KEY_BYTES]; wipe(&mut owned); assert_eq!(owned, [0; KEY_BYTES]);
        let mut blob = match ProtectedBlob::copy_from(&[8; 128]) { Ok(value) => value, Err(_) => panic!("DATA blob refused") };
        assert_eq!(blob.with_protected_bytes(|bytes| bytes.len()), 128);
        assert!(blob.retained_bytes() >= size_of::<ProtectedBlob>() + blob.len());
        wipe(&mut blob.bytes); assert!(blob.with_protected_bytes(|bytes| bytes.iter().all(|byte| *byte == 0)));
        assert!(ProtectedBlob::copy_from(&[]).is_err());
        assert!(ProtectedBlob::copy_from(&[0; MAX_PROTECTED_BYTES + 1]).is_err());
    }

    #[test]
    fn refusal_has_no_extractable_candidate_or_false_cleanup_refund() {
        // Empty original only: no fabricated pointer, allocation or native call.
        let mut allocation = NativeOutput::new();
        let (cleanup, error) = allocation.release();
        let facts = Facts { api: Api::Unprotect, native_return: None, native_error: None,
            reported_native_bytes: 0, native_allocation_returned: false, cleanup, cleanup_error: error, first_failure_at: None };
        let mut result: NativeResult<KeyCandidate> = NativeResult { facts, refusal: Some(Refusal::InputBounds), value: None, allocation };
        assert!(!result.native_result_succeeded()); assert!(result.take_value().is_none());
        assert_eq!(result.reported_unreleased_native_bytes(), None);
        assert_eq!(result.facts().native_return, None);
        assert_eq!(result.facts().cleanup, Cleanup::NoAllocation);
    }
}
