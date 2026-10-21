//! One fixed continuation in the existing Shell relay book, not a runner.
//! The original caller is retained before GO and joined before service finality.
use super::*;
use std::{
    future::Future,
    mem::{align_of, size_of},
    pin::Pin,
    task::{Context, Poll, Waker},
};
#[derive(Default)]
struct Book {
    handle: Option<tokio::task::JoinHandle<()>>,
    start: Option<oneshot::Sender<()>>,
    entry: Option<Arc<requests::Entry>>,
}
// Name the one fixed future so its actual layout, not a guessed async block
// allowance, is charged. This is still the original Shell relay's one task.
struct Call {
    original: DocumentBinding,
    claim: Option<requests::Claim>,
    go: oneshot::Receiver<()>,
}
impl Future for Call {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let call = self.get_mut();
        let result = match Pin::new(&mut call.go).poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(v) => v,
        };
        if let Some(claim) = call.claim.take() {
            if result.is_ok() {
                call.original.run_agent_upload_key(claim);
            } else {
                claim.returned(Err(Error::Conflict));
            }
        }
        Poll::Ready(())
    }
}
const WORD: usize = size_of::<usize>();
const ARC_HEADER: usize = 2 * WORD;
// Cargo.lock Tokio 1.48.0 runtime/task/core.rs Header/Core/Trailer, including
// the optional source/tracing words; scheduler Handle is measured directly.
// Closed platform Cell alignment is at most 128. Per-field padding is charged
// before rounding the final cell; shared scheduler bodies are not cloned here.
const TASK_HEADER: usize = 3 * WORD + 2 * size_of::<u64>();
const TASK_STAGE: usize = if size_of::<Call>() > size_of::<Result<(), tokio::task::JoinError>>() {
    size_of::<Call>()
} else {
    size_of::<Result<(), tokio::task::JoinError>>()
};
const TASK_CORE: usize =
    size_of::<tokio::runtime::Handle>() + size_of::<u64>() + 2 * WORD + TASK_STAGE;
const TASK_TRAILER: usize =
    2 * WORD + size_of::<Option<Waker>>() + size_of::<Option<Arc<dyn Fn() + Send + Sync>>>();
const TASK_ALIGNMENT: usize = 128;
const TASK_CELL: usize =
    (TASK_HEADER + TASK_CORE + TASK_TRAILER + 8 * align_of::<u64>() + TASK_ALIGNMENT - 1)
        / TASK_ALIGNMENT
        * TASK_ALIGNMENT;
// sync/oneshot.rs Inner<()>: state + Option<()> + two Wakers, aligned, in ONE
// Arc. Sender/receiver themselves are already in Book/Call above.
const ONESHOT_CELL: usize =
    ARC_HEADER + WORD + size_of::<Option<()>>() + 2 * size_of::<Waker>() + WORD;
pub(super) const BACKING: usize =
    size_of::<UploadKeyRelay>() + ARC_HEADER + TASK_CELL + ONESHOT_CELL;
pub(crate) struct UploadKeyRelay {
    book: AsyncMutex<Book>,
    closed: AtomicBool,
}
impl UploadKeyRelay {
    pub(crate) fn new() -> Self {
        Self {
            book: AsyncMutex::new(Book::default()),
            closed: AtomicBool::new(false),
        }
    }
    pub(crate) fn close(&self, document: &DocumentBinding) {
        self.closed.store(true, Ordering::SeqCst);
        document.agent_upload_key_close(false);
    }
    pub(crate) fn lost(&self, document: &DocumentBinding) {
        self.closed.store(true, Ordering::SeqCst);
        document.agent_upload_key_close(true);
    }
    pub(crate) async fn returned(&self) -> bool {
        self.book
            .try_lock()
            .is_ok_and(|b| b.handle.is_none() && b.entry.is_none())
    }
    pub(crate) async fn join_finished(&self, document: &DocumentBinding) {
        let Ok(mut b) = self.book.try_lock() else {
            return;
        };
        let Some(handle) = b.handle.as_mut().filter(|h| h.is_finished()) else {
            return;
        };
        let normal = (&mut *handle).await.is_ok();
        if let Some(entry) = &b.entry {
            entry.continuation_joined(normal);
        }
        b.handle.take();
        b.start.take();
        b.entry.take();
        drop(b);
        if !normal {
            self.lost(document);
        }
        document.inner.changes.send_modify(|_| {});
    }
    pub(crate) async fn tick(self: &Arc<Self>, document: &DocumentBinding) {
        document.agent_upload_key_tick();
        self.join_finished(document).await;
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let closing = {
            let s = document.lock();
            s.stopping || s.lost_observed || !s.lifetime.original_bound()
        };
        if closing {
            self.close(document);
            return;
        }
        let Ok(mut b) = self.book.try_lock() else {
            return;
        };
        if b.handle.is_some() || b.entry.is_some() {
            return;
        }
        let claim = match document.agent_upload_key_claim() {
            Ok(Some(c)) => c,
            Ok(None) => return,
            Err(_) => {
                drop(b);
                self.lost(document);
                return;
            }
        };
        let entry = claim.link().entry().clone();
        let original = document.clone();
        let (start, go) = oneshot::channel();
        b.entry = Some(entry.clone());
        b.start = Some(start);
        b.handle = Some(tokio::spawn(Call {
            original,
            claim: Some(claim),
            go,
        }));
        if self.closed.load(Ordering::SeqCst) || entry.first_stop().map_or(true, |s| s.is_some()) {
            entry.cancel(p::Reason::PermissionRevoked, Instant::now());
            b.start.take();
            return;
        }
        if b.start.take().is_some_and(|go| go.send(()).is_err()) {
            entry.unknown();
        }
    }
}
