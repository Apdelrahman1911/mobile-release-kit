//! The genuine memory-only Saved owner/clock with NO native/key/runtime
//! originals. These tests exercise refusal/minimum-F, not successful custody.
use super::*;
use serde_json::json;

fn session(mode: wire::Mode) -> (SavedCommandOwner, Arc<Session>) {
    let context = wire::prepare(&json!({"projectId":"fixture","draftRevision":1,"baselineGeneration":1,
        "savedConfig":{"bytes":20,"sha256":"a".repeat(64)},
        "savedVersion":{"source":"version.properties","bytes":20,"sha256":"b".repeat(64),"name":"1.2.3","build":1},
        "credentialContextRevision":1,"recordId":"c".repeat(32),"recordRevision":1,"executionMode":"local","platform":"ios",
        "mode":mode,"reference":if mode == wire::Mode::KeyPrepare {json!({"operationId":"d".repeat(32),"ownerGeneration":"e".repeat(32)})} else {serde_json::Value::Null},
        "newApplication":false,"displayName":"Explicit synthetic name"})).unwrap().context;
    let owner = SavedCommandOwner::apple_provisioning(RuntimeConfig::packaged(
        std::path::PathBuf::from("/unopened-local-key-test-runtime"),
    ));
    let (owner, original) =
        super::super::tests::active_with_context(owner, Context::AppleProvisioning(context));
    initialize(&original).unwrap();
    (owner, original)
}

#[test]
fn original_stop_preserves_minimum_f_and_every_later_excluded_loss_vetoes_key_tail() {
    for excluded in [
        Reason::ContextChanged,
        Reason::CredentialsUnavailable,
        Reason::DocumentLost,
        Reason::CleanupUnknown,
        Reason::ProtocolError,
    ] {
        let (owner, original) = session(wire::Mode::KeyPrepare);
        let key = original.apple_key.get().unwrap();
        let first = original.clocks.admitted + Duration::from_secs(5);
        let earlier = original.clocks.admitted + Duration::from_secs(2);
        let later = original.clocks.admitted + Duration::from_secs(8);
        let mut registry = owner.inner.lock();
        owner
            .inner
            .stop_locked(&mut registry, &original, Reason::Cancelled, first);
        assert!(key.clock.failure() == Some((AssetReason::UserCancelled, first)));
        assert_eq!(key.clock.key_preservation_end(), Some(first + SETTLEMENT));
        owner
            .inner
            .stop_locked(&mut registry, &original, Reason::Shutdown, later);
        assert_eq!(key.clock.key_preservation_end(), Some(first + SETTLEMENT));
        owner
            .inner
            .stop_locked(&mut registry, &original, Reason::TimedOut, earlier);
        assert_eq!(key.clock.key_preservation_end(), Some(earlier + SETTLEMENT));
        owner
            .inner
            .stop_locked(&mut registry, &original, excluded, later);
        assert!(key.clock.key_preservation_end().is_none());
        assert!(key.clock.failure() == Some((AssetReason::Deadline, earlier)));
        assert_eq!(
            *original.native_cleanup_cutoff.borrow(),
            earlier + SETTLEMENT
        );
        assert_eq!(registry.active.as_ref().unwrap().first_stop, Some(earlier));
        assert!(*original.stop.borrow());
        assert!(!key.worker_joined.load(Ordering::SeqCst));
        assert!(!key.generator_never_entered.load(Ordering::SeqCst));
        assert!(!key.clock.completed());
    }
}

#[test]
fn review_cannot_borrow_key_preservation_and_work_timeout_never_renews_h() {
    let (_, review) = session(wire::Mode::KeyReview);
    assert!(review
        .apple_key
        .get()
        .unwrap()
        .clock
        .key_preservation_end()
        .is_none());
    let (owner, original) = session(wire::Mode::KeyPrepare);
    let key = original.apple_key.get().unwrap();
    let work = original.clocks.work;
    let mut registry = owner.inner.lock();
    owner
        .inner
        .stop_locked(&mut registry, &original, Reason::TimedOut, work);
    assert_eq!(key.clock.cleanup_end(), work + SETTLEMENT);
    assert_eq!(key.clock.key_preservation_end(), Some(work + SETTLEMENT));
    owner.inner.stop_locked(
        &mut registry,
        &original,
        Reason::Cancelled,
        work + Duration::from_secs(1),
    );
    assert_eq!(key.clock.cleanup_end(), work + SETTLEMENT);
    assert_eq!(key.clock.hard_end(), original.clocks.cleanup);
    // Existing native audit still ends at W; only the closed key custody tail
    // uses this parent's cleanup endpoint. No new Pending/generator can pass.
    assert_eq!(*original.native_audit_cutoff.borrow(), work);
    assert!(begin_pending_write(&original).is_err());
}

#[test]
fn empty_reserved_receiver_and_cancelled_unattached_owner_do_not_mint_no_generation_or_saved() {
    let (owner, original) = session(wire::Mode::KeyPrepare);
    let key = original.apple_key.get().unwrap();
    assert!(key.receive.is_some());
    assert!(!key.receive.as_ref().unwrap().no_body_returned());
    key.decline_before_asset(AssetReason::UserCancelled, original.clocks.admitted)
        .unwrap();
    assert!(key.phase() == Some(SavePhase::NotCreated));
    assert!(key.original.get().is_none() && key.destination.get().is_none());
    assert!(!key.generator_never_entered.load(Ordering::SeqCst));
    assert!(
        !key.worker_joined.load(Ordering::SeqCst) && !key.all_jobs_joined.load(Ordering::SeqCst)
    );
    assert!(saved_reference(&original).is_none());
    assert!(!original.driver_joined.load(Ordering::SeqCst));
    assert!(!original.watchdog_joined.load(Ordering::SeqCst));
    assert!(
        original.material.lock().unwrap().is_none()
            && original.material_retired.load(Ordering::SeqCst)
    );
    // This existing owner really has missing joins; it must retain Unknown.
    assert!(!owner.can_exit());
    assert!(owner.disabled());
    assert!(saved_reference(&original).is_none());
    assert!(!key.private_drained.load(Ordering::SeqCst));
}

#[test]
fn actual_parent_quote_covers_reserved_receiver_without_creating_key_or_cert_authority() {
    let (_, original) = session(wire::Mode::KeyPrepare);
    let key = original.apple_key.get().unwrap();
    let quote = backing_bytes(wire::Mode::KeyPrepare).unwrap();
    assert!(
        quote
            >= private::ReceiveBook::retained_bytes().unwrap()
                + std::mem::size_of::<AppleKeySession>()
    );
    assert_eq!(key.own_retained_bytes(), Some(quote));
    assert!(backing_bytes(wire::Mode::KeyReview).unwrap() < quote);
    assert_eq!(backing_bytes(wire::Mode::Review), Some(0));
    assert!(key.binding.get().is_none() && key.saved_reference.get().is_none());
    assert!(key.output.get().is_none() && key.loan.get().is_none());
}
