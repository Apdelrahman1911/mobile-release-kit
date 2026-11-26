//! The original Prepared waiter, named to account for the relay continuation.
//! It owns no native work. Dropping this observer never settles or cancels the
//! actual original. The delegated target projects no full AssetStatus heap.
use super::*;
use std::{future::Future, pin::Pin, task::{Context, Poll}};

enum Target {
    Ordinary,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    UploadKey(Arc<crate::service_upload_key_requests::NativeLink>),
}
pub(super) struct PreparedReply {
    document: DocumentBinding,
    id: u32,
    target: Target,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}
enum Ready { Waiting, Returned(Option<AssetStatus>) }
impl PreparedReply {
    pub(super) fn ordinary(document: DocumentBinding, id: u32) -> Self {
        Self { document, id, target: Target::Ordinary, sleep: None }
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn upload_key(document: DocumentBinding, id: u32,
        original: Arc<crate::service_upload_key_requests::NativeLink>) -> Self {
        Self { document, id, target: Target::UploadKey(original), sleep: None }
    }
    fn ready(&self) -> Result<Ready, CommandError> {
        self.document.reconcile();
        let state = self.document.lock();
        let slot = state.slot.as_ref().filter(|s| s.owner.id == self.id)
            .ok_or_else(|| AssetError::new(Reason::ContextStale))?;
        if state.unknown || matches!(slot.settlement, Settlement::Unknown | Settlement::LateKnown) {
            return Err(AssetError::new(Reason::CleanupUnknown).into());
        }
        if !slot.owner.resources_settled() || !matches!(slot.phase, Phase::Selected | Phase::Preview | Phase::Idle) {
            return Ok(Ready::Waiting);
        }
        if slot.reason == Reason::ContextStale { return Err(AssetError::new(Reason::ContextStale).into()); }
        if let Some(error) = &slot.error { return Err(error.clone()); }
        if slot.reason != Reason::None { return Err(AssetError::new(slot.reason).into()); }
        match &self.target {
            Target::Ordinary => Ok(Ready::Returned(Some(self.document.snapshot(&state)))),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Target::UploadKey(link) => {
                #[cfg(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
                    all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64"))))]
                {
                    agent_upload_key::prepared_reply(&self.document, &state, link, self.id)?;
                    Ok(Ready::Returned(None))
                }
                #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
                    all(target_os = "macos", target_pointer_width = "64", any(target_arch = "aarch64", target_arch = "x86_64")))))]
                { let _ = link; Err(AssetError::new(Reason::Unqualified).into()) }
            }
        }
    }
}
impl Future for PreparedReply {
    type Output = Result<Option<AssetStatus>, CommandError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Some(sleep) = &mut this.sleep {
            if sleep.as_mut().poll(cx).is_pending() { return Poll::Pending; }
            this.sleep = None;
        }
        match this.ready() {
            Err(e) => Poll::Ready(Err(e)),
            Ok(Ready::Returned(value)) => Poll::Ready(Ok(value)),
            Ok(Ready::Waiting) => {
                let mut sleep = Box::pin(tokio::time::sleep(Duration::from_millis(50)));
                let _ = sleep.as_mut().poll(cx);
                this.sleep = Some(sleep);
                Poll::Pending
            }
        }
    }
}
// ONE existing 50ms wait at a time; the future itself is in the named relay
// Call. The UploadKey arm never creates the Ordinary full snapshot allocation.
pub(super) const HEAP_BYTES: usize = std::mem::size_of::<tokio::time::Sleep>();
// Poll/ready result cells can overlap on the original caller's stack. The
// delegated None variant has no AssetStatus heap, but still has this layout.
pub(super) const RETURN_BYTES: usize = std::mem::size_of::<Result<Ready, CommandError>>()
    + std::mem::size_of::<Result<Option<AssetStatus>, CommandError>>();

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    #[test]
    fn one_prepared_wait_and_compact_reply_fit_the_named_relay_not_a_second_task() {
        assert_eq!(HEAP_BYTES, std::mem::size_of::<tokio::time::Sleep>());
        assert!(RETURN_BYTES >= 2 * std::mem::size_of::<Option<AssetStatus>>());
        assert!(std::mem::size_of::<PreparedReply>() >= std::mem::size_of::<DocumentBinding>()
            + std::mem::size_of::<Option<Pin<Box<tokio::time::Sleep>>>>());
        // The dependency-free MAIN stamp is bounded identity DATA; no full
        // records, assessment value, material or encoded AssetStatus is held.
        assert!(std::mem::size_of::<crate::service_upload_key_protocol::Prepared>() < 512);
    }
}
