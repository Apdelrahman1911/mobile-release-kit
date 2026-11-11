//! Process-lifetime exclusion for the privileged publisher, NOT durable MSI
//! completion. Existing objects are NEVER acquired/adopted, even if abandoned.
//! Default token DACL is sufficient here only because existing objects always
//! refuse: an untrusted precreation can deny service, never confer authority.
//! Caller admits its installer token first and retains this frame in its original
//! static owner. No Drop, retry, wait, release or timeout supplies settlement.
use super::{Error, Result};
use std::{cell::UnsafeCell, marker::PhantomPinned, pin::Pin, ptr::null};
use windows_sys::Win32::{Foundation as F, System::Threading as T};

const NAME: &str = "Global\\MobileReleaseKit.RuntimePublication.x64.v1";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage { Prepared, Entered, Owned, Refused, Unknown }

struct Frame {
    name: Vec<u16>,
    handle: UnsafeCell<F::HANDLE>,
    stage: Stage,
    last_error: Option<u32>,
    _pin: PhantomPinned,
}

/// A private original native frame. No native HANDLE escapes this module.
/// HANDLE deliberately remains open until process termination, on success too.
/// Thus a later publisher cannot race the first process's final exit reporting.
/// This is not protection against MSI replacing files before invoking us, and
/// does not survive reboot. MSI sequencing must remain disabled until its own
/// durable transaction protocol and maintenance preflight are implemented.
pub(super) struct PublicationExclusion { frame: Pin<Box<Frame>> }
impl PublicationExclusion {
    pub(super) fn new() -> Self { Self::named(NAME) }
    fn named(name: &str) -> Self {
        Self { frame: Box::pin(Frame { name: name.encode_utf16().chain(Some(0)).collect(),
            handle: UnsafeCell::new(std::ptr::null_mut()), stage: Stage::Prepared,
            last_error: None, _pin: PhantomPinned }) }
    }
    pub(super) fn unresolved(&self) -> bool { matches!(self.frame.stage, Stage::Entered | Stage::Unknown) }
    pub(super) fn enter_once(&mut self) -> Result<()> {
        // SAFETY: the pinned frame/name never move or resize. We mutate only
        // scalar state, never a structurally pinned field. Native call is sync.
        let frame = unsafe { self.frame.as_mut().get_unchecked_mut() };
        if frame.stage != Stage::Prepared { return Err(Error::State); }
        frame.stage = Stage::Entered;
        // SAFETY: terminated immutable name; NULL attributes mean noninherited
        // handle with the already-admitted token's default descriptor. Register
        // the actual original return BEFORE observing GetLastError.
        unsafe {
            F::SetLastError(0);
            *frame.handle.get() = T::CreateMutexExW(null(), frame.name.as_ptr(),
                T::CREATE_MUTEX_INITIAL_OWNER, T::MUTEX_MODIFY_STATE);
            frame.last_error = Some(F::GetLastError());
        }
        // No wait on an existing object: its ownership, DACL, abandonment and
        // provenance are irrelevant because it cannot authorize publication.
        let handle = unsafe { *frame.handle.get() };
        frame.stage = classify(!handle.is_null() && handle != F::INVALID_HANDLE_VALUE,
            frame.last_error.unwrap_or(u32::MAX));
        match frame.stage {
            Stage::Owned => Ok(()),
            Stage::Refused => Err(Error::Unavailable),
            _ => Err(Error::Unknown),
        }
    }
}
fn classify(valid: bool, error: u32) -> Stage {
    match (valid, error) {
        (true, 0) => Stage::Owned,
        (true, F::ERROR_ALREADY_EXISTS) => Stage::Refused,
        (false, 0 | F::ERROR_IO_PENDING) => Stage::Unknown,
        (false, _) => Stage::Refused,
        (true, _) => Stage::Unknown,
    }
}
// Frame owns no asynchronous native borrow. Dropping it does NOT close/release
// the kernel handle; the process holds exclusion until its original termination.
// This intentional bounded leak is one HANDLE per original process owner.

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "native kernel object test; separate explicit Windows admission"]
    fn exclusion_native_existing_object_never_authorizes_second_owner() {
        // Test-only namespace, no installed files/registry or production mutex.
        let name = format!("Local\\MRK.Exclusion.NativeTest.{}", std::process::id());
        let mut first = PublicationExclusion::named(&name);
        assert_eq!(first.enter_once(), Ok(()));
        assert_eq!(first.enter_once(), Err(Error::State));
        let mut second = PublicationExclusion::named(&name);
        assert_eq!(second.enter_once(), Err(Error::Unavailable));
        assert_eq!(second.frame.stage, Stage::Refused);
        // Dropping original Rust storage must not release process exclusion.
        drop(first);
        let mut third = PublicationExclusion::named(&name);
        assert_eq!(third.enter_once(), Err(Error::Unavailable));
        assert_eq!(third.enter_once(), Err(Error::State));
    }
    #[test]
    fn exclusion_return_classification_is_not_wait_or_content_adoption() {
        assert_eq!(classify(true, 0), Stage::Owned);
        assert_eq!(classify(true, F::ERROR_ALREADY_EXISTS), Stage::Refused);
        for error in [F::ERROR_ACCESS_DENIED, F::ERROR_INVALID_HANDLE, F::ERROR_IO_PENDING, u32::MAX] {
            assert_eq!(classify(true, error), Stage::Unknown);
        }
        assert_eq!(classify(false, 0), Stage::Unknown);
        assert_eq!(classify(false, F::ERROR_IO_PENDING), Stage::Unknown);
        assert_eq!(classify(false, F::ERROR_ACCESS_DENIED), Stage::Refused);
    }
}
