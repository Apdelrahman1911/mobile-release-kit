//! Test-only original owner of one public-key CNG encryption.
//! No file/path input, callback, worker, retry, private key or native success authority.
use crate::output_origin_capsule_data as data;
use crate::output_origin_capsule_public_key::{PublicKey, PINNED_PUBLIC_KEY};
use std::{ffi::c_void, marker::PhantomPinned, pin::Pin, ptr::null_mut};
use windows_sys::Win32::Security::Cryptography as BC;

struct Original {
    algorithm: BC::BCRYPT_ALG_HANDLE, key: BC::BCRYPT_KEY_HANDLE,
    algorithm_order: data::HandleOrder, key_order: data::HandleOrder,
    public: &'static PublicKey, padding: BC::BCRYPT_OAEP_PADDING_INFO,
    ciphertext: [u8; data::CIPHERTEXT_BYTES], written: u32,
    active: Option<data::Phase>, returns: [Option<i32>; 5], _pin: PhantomPinned,
}
impl Original {
    fn new(public: &'static PublicKey) -> Self {
        Self {
            algorithm: null_mut(), key: null_mut(),
            algorithm_order: data::HandleOrder::new(), key_order: data::HandleOrder::new(),
            public, padding: BC::BCRYPT_OAEP_PADDING_INFO { pszAlgId: BC::BCRYPT_SHA256_ALGORITHM, pbLabel: null_mut(), cbLabel: 0 },
            ciphertext: [0; data::CIPHERTEXT_BYTES], written: 0,
            active: None, returns: [None; 5], _pin: PhantomPinned,
        }
    }
    fn settled(&self) -> bool {
        self.active.is_none() && self.algorithm_order.settled() && self.key_order.settled()
    }
    fn call(self: Pin<&mut Self>, phase: data::Phase, plaintext: &mut [u8; data::PLAINTEXT_BYTES],
        permitted: &mut impl FnMut() -> bool) -> data::Step {
        use data::{Failure, HandleState, Phase, Stage, Step};
        // This object and every native out slot are pinned before the first call.
        let value = unsafe { self.get_unchecked_mut() };
        if value.active.is_some() { return Step::Unresolved; }
        if matches!(phase, Phase::Destroy | Phase::Close) {
            let enter = match phase { Phase::Destroy => value.key_order.close_enter(), _ => value.algorithm_order.close_enter() };
            match enter { Some(false) => return Step::Good, None => return Step::Unresolved, Some(true) => () }
            // Original close is allowed late, once. Sampling never renews a window.
            let before = permitted(); value.active = Some(phase);
            let status = match phase {
                Phase::Destroy => unsafe { BC::BCryptDestroyKey(value.key) },
                _ => unsafe { BC::BCryptCloseAlgorithmProvider(value.algorithm, 0) },
            };
            let index = if phase == Phase::Destroy { 3 } else { 4 };
            value.returns[index] = Some(status); value.active = None;
            let after = permitted();
            let closed = if phase == Phase::Destroy { value.key_order.close_return(status) } else { value.algorithm_order.close_return(status) };
            if !closed { return Step::Unresolved; }
            return if before && after { Step::Good } else { Step::Refused(Failure::data(Stage::Clock)) };
        }
        if !permitted() { return Step::Refused(Failure::data(Stage::Clock)); }
        match phase {
            Phase::Open => {
                if !value.algorithm_order.acquire_enter() { return Step::Unresolved; }
                value.active = Some(phase);
                let status = unsafe { BC::BCryptOpenAlgorithmProvider(&mut value.algorithm,
                    BC::BCRYPT_RSA_ALGORITHM, BC::MS_PRIMITIVE_PROVIDER, 0) };
                value.returns[0] = Some(status); value.active = None;
                let after = permitted();
                match value.algorithm_order.acquire_return(status, !value.algorithm.is_null()) {
                    HandleState::Owned if after => Step::Good,
                    HandleState::Owned => Step::Refused(Failure::data(Stage::Clock)),
                    HandleState::NoHandle => Step::Refused(Failure::native(Stage::ProviderOpen, status)),
                    _ => Step::Unresolved,
                }
            }
            Phase::Import => {
                if !value.algorithm_order.owned() || !value.key_order.acquire_enter() { return Step::Unresolved; }
                value.active = Some(phase);
                // The documented import is read-only. The only input is this
                // compiled, source-pinned public BLOB; validation is not disabled.
                let status = unsafe { BC::BCryptImportKeyPair(value.algorithm, null_mut(),
                    BC::BCRYPT_RSAPUBLIC_BLOB, &mut value.key, value.public.blob.as_ptr().cast_mut(),
                    data::PUBLIC_BLOB_BYTES as u32, 0) };
                value.returns[1] = Some(status); value.active = None;
                let after = permitted();
                match value.key_order.acquire_return(status, !value.key.is_null()) {
                    HandleState::Owned if after => Step::Good,
                    HandleState::Owned => Step::Refused(Failure::data(Stage::Clock)),
                    HandleState::NoHandle => Step::Refused(Failure::native(Stage::PublicImport, status)),
                    _ => Step::Unresolved,
                }
            }
            Phase::Encrypt => {
                if !value.key_order.owned() || value.returns[2].is_some() { return Step::Unresolved; }
                value.active = Some(phase);
                let status = unsafe { BC::BCryptEncrypt(value.key, plaintext.as_mut_ptr(),
                    data::PLAINTEXT_BYTES as u32, (&mut value.padding as *mut BC::BCRYPT_OAEP_PADDING_INFO).cast::<c_void>(),
                    null_mut(), 0, value.ciphertext.as_mut_ptr(), data::CIPHERTEXT_BYTES as u32,
                    &mut value.written, BC::BCRYPT_PAD_OAEP) };
                value.returns[2] = Some(status); value.active = None;
                let after = permitted();
                if status != 0 { Step::Refused(Failure::native(Stage::Encrypt, status)) }
                else if value.written != data::CIPHERTEXT_BYTES as u32 { Step::Refused(Failure::data(Stage::CipherLength)) }
                else if !after { Step::Refused(Failure::data(Stage::Clock)) }
                else { Step::Good }
            }
            _ => Step::Unresolved,
        }
    }
}
fn clear_private(capture: &mut data::Capture) {
    // No native borrower is live here. This does not claim to erase pre-existing
    // decoder/provider copies, nor perform any original output cleanup.
    for byte in capture.private_buffer().iter_mut() { unsafe { std::ptr::write_volatile(byte, 0); } }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
pub(crate) fn seal(capture: &mut data::Capture, mut permitted: impl FnMut() -> bool) -> data::Reply {
    let key_id = PINNED_PUBLIC_KEY.as_ref().map(|key| key.sha256);
    if let Err(failure) = capture.begin_seal() {
        clear_private(capture); return data::Reply::Incomplete { key_id, failure };
    }
    let Some(public) = PINNED_PUBLIC_KEY.as_ref().filter(|key| data::public_blob_valid(&key.blob)) else {
        clear_private(capture);
        return data::Reply::Incomplete { key_id, failure: data::Failure::data(data::Stage::Recipient) };
    };
    let mut original = std::pin::pin!(Original::new(public));
    let outcome = data::seal_once(|phase| original.as_mut().call(phase, capture.private_buffer(), &mut permitted));
    let reply = match outcome {
        data::Step::Good if original.as_ref().get_ref().settled() =>
            data::Reply::Sealed { key_id: public.sha256, ciphertext: original.as_ref().get_ref().ciphertext },
        data::Step::Refused(failure) if original.as_ref().get_ref().settled() =>
            data::Reply::Incomplete { key_id, failure },
        _ => {
            // Unknown never permits a guessed close, freeing original buffers,
            // emitting ciphertext or returning a diagnostic/native success.
            loop { std::thread::park(); std::hint::black_box((&mut original, &mut *capture)); }
        }
    };
    clear_private(capture); reply
}
// Caller-owned fixed storage, excluding pre-existing owner buffers and OS
// provider internals. No claim of a synchronous CNG cancellation/memory API.
const _: () = assert!(std::mem::size_of::<data::Capture>() + std::mem::size_of::<Original>()
    + std::mem::size_of::<data::Reply>() + data::FRAME_BYTES + data::PUBLIC_BLOB_BYTES <= 16 * 1024);
