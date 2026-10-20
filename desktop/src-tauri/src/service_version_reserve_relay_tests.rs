//! Actual retained Tokio handles/latches and inbox metadata only. These tests
//! intentionally never create a native Review/Lane/NativeUse or join receipt.
use super::*;
use crate::service_version_reserve_requests::tests::Rig;
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
async fn preentry(slot: &ReserveRelay, claim: requests::Claim, panic: bool) {
    let mut book = slot.book.lock().await;
    let (start, enter) = oneshot::channel();
    book.entry = Some(claim.entry().clone());
    book.start = Some(start);
    book.handle = Some(tokio::spawn(async move {
        let mut claim = claim;
        if enter.await.is_err() {
            claim
                .entry()
                .cancel(wire::Reason::ContextChanged, Instant::now());
        }
        if panic {
            panic!("inert pre-entry continuation loss");
        }
        claim.not_admitted(Error::Conflict).map_err(|_| ())
    }));
}
async fn join(slot: &ReserveRelay) -> Result<bool, ()> {
    let end = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match slot.join_ready().await {
            Ok(false) => {}
            result => return result,
        }
        assert!(
            tokio::time::Instant::now() < end,
            "original fixture continuation did not return"
        );
        tokio::task::yield_now().await;
    }
}
#[test]
fn unreleased_same_slot_never_claims_native_and_shutdown_joins_before_refund() {
    runtime().block_on(async {
        let r = Rig::new();
        let claim = r.claim();
        let entry = claim.entry().clone();
        let slot = ReserveRelay::new();
        preentry(&slot, claim, false).await;
        tokio::task::yield_now().await;
        assert_eq!(slot.join_ready().await, Ok(false));
        assert!(entry.pending());
        assert!(slot.book.lock().await.handle.is_some());
        assert!(entry.status().unwrap().operation_id.is_none());
        slot.close_latch();
        assert_eq!(join(&slot).await, Ok(true));
        assert!(!entry.pending());
        assert_eq!(entry.status().unwrap().state, wire::State::Cancelled);
        assert!(entry.completed_operation().unwrap().is_none());
        let book = slot.book.lock().await;
        assert!(book.handle.is_none() && book.entry.is_none() && book.start.is_none());
    });
}
#[test]
fn original_handle_panic_is_joined_but_unknown_entry_is_not_refunded_or_replayed() {
    runtime().block_on(async {
        let r = Rig::new();
        let claim = r.claim();
        let entry = claim.entry().clone();
        let slot = ReserveRelay::new();
        preentry(&slot, claim, true).await;
        slot.close_latch();
        assert_eq!(join(&slot).await, Err(()));
        assert!(slot.book.lock().await.handle.is_none());
        assert!(entry.pending());
        assert_eq!(entry.status().unwrap().state, wire::State::Unknown);
        assert_eq!(
            r.inbox.submit(r.input.clone()).unwrap(),
            entry.status().unwrap()
        );
        assert!(entry.completed_operation().unwrap().is_none());
    });
}
#[test]
fn contended_slot_preserves_original_sender_then_closed_release_cannot_start() {
    runtime().block_on(async {
        let r = Rig::new();
        let claim = r.claim();
        let entry = claim.entry().clone();
        let slot = ReserveRelay::new();
        preentry(&slot, claim, false).await;
        let book = slot.book.lock().await;
        slot.close_latch();
        assert!(slot.closed.load(Ordering::SeqCst));
        assert!(book.start.is_some() && book.handle.is_some());
        drop(book);
        slot.close_latch();
        assert_eq!(join(&slot).await, Ok(true));
        assert!(entry.status().unwrap().operation_id.is_none());
    });
}
#[test]
fn actual_continuation_and_tick_futures_are_send_without_polling_native_work() {
    fn contract(
        doc: &DocumentBinding,
        claim: requests::Claim,
        slot: Arc<ReserveRelay>,
        path: &Path,
    ) {
        fn send<T: Send>(_: T) {}
        send(doc.run_agent_reserve(claim, path.to_path_buf()));
        send(slot.tick(doc, path));
        send(slot.join_finished(doc));
    }
    let _ = contract;
}
