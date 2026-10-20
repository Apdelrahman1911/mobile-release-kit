//! ONE continuation slot in the existing Shell RelayBook. It never owns a
//! runner/clock/Store; it retains the original reserve future until actual join.
use super::*;
use tokio::sync::oneshot;

pub(super) const BACKING: usize = 16 * 1024;
#[derive(Default)]
struct Book {
    handle: Option<tokio::task::JoinHandle<Result<(), ()>>>,
    start: Option<oneshot::Sender<()>>,
    entry: Option<Arc<requests::Entry>>,
}
pub(crate) struct ReserveRelay {
    book: AsyncMutex<Book>,
    closed: AtomicBool,
}
impl ReserveRelay {
    pub(crate) fn new() -> Self {
        Self {
            book: AsyncMutex::new(Book::default()),
            closed: AtomicBool::new(false),
        }
    }
    /// No RelayBook guard here. The continuation never holds or requests this
    /// slot either, including reserve_finish/native retirement.
    async fn join_ready(&self) -> Result<bool, ()> {
        let Ok(mut book) = self.book.try_lock() else {
            return Ok(false);
        };
        let Some(handle) = book.handle.as_mut().filter(|h| h.is_finished()) else {
            return Ok(false);
        };
        let joined = (&mut *handle).await; // Actual original borrow/join, not flag finality.
        let ok = matches!(joined, Ok(Ok(())));
        if let Some(entry) = &book.entry {
            entry.continuation_joined(ok);
        }
        book.handle.take();
        book.start.take();
        book.entry.take();
        if ok {
            Ok(true)
        } else {
            Err(())
        }
    }
    pub(crate) async fn join_finished(&self, document: &DocumentBinding) {
        match self.join_ready().await {
            Ok(false) => {}
            Ok(true) => document.inner.changes.send_modify(|_| {}),
            Err(()) => {
                self.lost(document);
                document.inner.changes.send_modify(|_| {});
            }
        }
    }
    fn close_latch(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // A contended slot keeps its original sender/handle. The release
        // recheck sees closed and cannot grant admission.
        if let Ok(mut book) = self.book.try_lock() {
            book.start.take();
        }
    }
    pub(crate) fn close(&self, document: &DocumentBinding) {
        self.close_latch();
        document.agent_reserve_close(false);
    }
    pub(crate) fn lost(&self, document: &DocumentBinding) {
        self.close_latch();
        document.agent_reserve_close(true);
    }
    pub(crate) async fn tick(self: &Arc<Self>, document: &DocumentBinding, app_data: &Path) {
        document.agent_reserve_tick();
        self.join_finished(document).await;
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let closing = {
            let state = document.lock();
            state.stopping || state.lost_observed || !state.lifetime.original_bound()
        };
        if closing {
            self.close(document);
            return;
        }
        let Ok(mut book) = self.book.try_lock() else {
            return;
        };
        if book.handle.is_some() || book.entry.is_some() {
            return;
        }
        let claim = match document.agent_reserve_claim() {
            Ok(Some(v)) => v,
            Ok(None) => return,
            Err(_) => {
                drop(book);
                self.lost(document);
                return;
            }
        };
        let entry = claim.entry().clone();
        let link = claim.link().clone();
        let (start, enter) = oneshot::channel();
        book.entry = Some(entry.clone()); // Retain before spawning/polling.
        book.start = Some(start);
        let original = document.clone();
        let location = app_data.to_path_buf(); // Existing shell-selected native app-data only.
        book.handle = Some(tokio::spawn(async move {
            let mut claim = claim;
            if enter.await.is_err() {
                claim
                    .entry()
                    .cancel(wire::Reason::ContextChanged, Instant::now());
                return claim.not_admitted(Error::Conflict).map_err(|_| ());
            }
            original.run_agent_reserve(claim, location).await
        }));
        drop(book);
        let current = !self.closed.load(Ordering::SeqCst)
            && document.agent_reserve_release_current(&link).is_ok();
        let mut book = self.book.lock().await;
        if book.entry.as_ref().is_none_or(|e| !Arc::ptr_eq(e, &entry)) {
            entry.unknown();
            drop(book);
            self.lost(document);
            return;
        }
        if !current || self.closed.load(Ordering::SeqCst) {
            entry.cancel(wire::Reason::ContextChanged, Instant::now());
            book.start.take(); // Original body returns through the same handle.
            return;
        }
        if let Some(start) = book.start.take() {
            if start.send(()).is_err() {
                entry.unknown();
            }
        }
    }
}

#[cfg(test)]
#[path = "service_version_reserve_relay_tests.rs"]
mod tests;
