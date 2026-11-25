//! Exact observer-only taps on the ORIGINAL stderr reader and driver state.
//! Marker bytes remain in its ordinary buffer; no extra reader/channel, token
//! data, child wait, close, cancellation controller or receipt is introduced.
use super::*;
use crate::git_local_protocol as wire;
use crate::shell::installed_observation::git_fetch::{Control, MARKER};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
pub(super) fn control(owner: &Owner) -> Option<&Arc<Control>> {
    owner.git_local.as_ref()?.observation.get()
}
pub(super) struct Stderr<R> {
    inner: R,
    owner: Arc<Owner>,
    seen: usize,
    invalid: bool,
}
impl<R> Stderr<R> {
    pub(super) fn new(inner: R, owner: Arc<Owner>) -> Self {
        Self {
            inner,
            owner,
            seen: 0,
            invalid: false,
        }
    }
}
impl<R: AsyncRead + Unpin> AsyncRead for Stderr<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let start = buf.filled().len();
        let returned = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &returned {
            if let Some(c) = control(&self.owner).cloned().filter(|c| c.held_case()) {
                if self
                    .owner
                    .git_local
                    .as_ref()
                    .is_some_and(|v| v.phase == wire::Phase::Apply)
                {
                    for b in &buf.filled()[start..] {
                        if self.seen >= MARKER.len() || *b != MARKER[self.seen] {
                            self.invalid = true;
                            c.fail();
                            break;
                        }
                        self.seen += 1;
                    }
                    if !self.invalid && start < buf.filled().len() && self.seen == MARKER.len() {
                        if !c.marker(&self.owner.id) {
                            self.invalid = true;
                            c.fail()
                        }
                        self.owner.changed.notify_waiters();
                    }
                }
            }
        }
        returned
    }
}
pub(super) fn sample(owner: &Owner, resources: &Resources) {
    let Some(c) = control(owner) else { return };
    if c.marker_pending(&owner.id) {
        // Independent original driver observation, not a marker assertion.
        // Child disappearance/PID lookup is neither used nor sufficient.
        if resources.child.is_some()
            && resources.waited.is_none()
            && !owner.failed()
            && owner
                .git_local
                .as_ref()
                .is_some_and(|v| matches!(*lock(&v.receipt), GitLocalReceipt::Pending))
        {
            if !c.producer_pending(&owner.id) {
                c.fail()
            }
        } else {
            c.fail()
        }
    }
}
pub(super) async fn changed(owner: &Owner) {
    let Some(c) = control(owner).filter(|c| c.held_case()) else {
        std::future::pending::<()>().await;
        return;
    };
    loop {
        // Register before testing the observed DATA: no lost-marker wake and
        // no new timer. Reuse the same original Owner notifier/select loop.
        let changed = owner.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if c.marker_pending(&owner.id) {
            return;
        }
        changed.await;
    }
}
impl Supervisor {
    pub(crate) fn bind_installed_git_fetch(
        &self,
        document: &Arc<()>,
        control: &Arc<Control>,
    ) -> Result<(), BridgeError> {
        self.assert_installed_session_available(document)?;
        self.inner
            .runtime
            .bind_git_fetch_observation(document, control)
    }
}
