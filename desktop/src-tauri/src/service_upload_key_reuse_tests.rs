//! Existing real bounded Inbox with inert callback DATA only. A callback here
//! is not an Asset Load, native return, assessment or qualification receipt.
use super::*;

#[test]
fn existing_prepare_is_a_closed_selection_with_its_own_consent_and_no_fields() {
    let value = serde_json::json!({"kind":"prepare-existing","recordId":id(5),"expectedRevision":1});
    let selected: p::Selection = serde_json::from_value(value.clone()).unwrap();
    assert!(selected.valid());
    assert_eq!(selected.kind(), p::Kind::PrepareExisting);
    assert_eq!(selected.kind().consent(), "agent-android-upload-key-prepare-once-v1");
    for other in [p::Kind::GenerateNew, p::Kind::BindReviewed, p::Kind::BackupEncrypted, p::Kind::RestoreEncrypted] {
        assert_ne!(selected.kind().consent(), other.consent());
    }
    for field in ["path", "password", "fields", "generate", "autoBind", "previewToken", "kindOverride"] {
        let mut extra = value.clone(); extra[field] = serde_json::json!(true);
        assert!(serde_json::from_value::<p::Selection>(extra).is_err());
    }
    for revision in [0, u32::MAX] {
        let mut wrong = value.clone(); wrong["expectedRevision"] = revision.into();
        assert!(!serde_json::from_value::<p::Selection>(wrong).unwrap().valid());
    }
}

#[test]
fn review_ready_needs_all_three_original_returns_and_never_becomes_assignment() {
    for order in [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        let r = Rig::new(p::Kind::PrepareExisting);
        let (claim, link) = r.claim(); arm(&link);
        let mut claim = Some(claim);
        for (position, part) in order.into_iter().enumerate() {
            match part {
                0 => claim.take().unwrap().returned(Ok(())),
                1 => link.entry().native_retired(7, p::State::ReviewReady, p::Reason::None, None),
                _ => link.entry().continuation_joined(true),
            }
            let status = r.status();
            assert_eq!(status.settlement, if position < 2 { Settlement::Pending } else { Settlement::Settled });
            assert!(status.key.is_none());
        }
        assert_eq!(r.status().state, p::State::ReviewReady);
        assert!(r.inbox.access(None).unwrap().prepared.is_none()); // Only actual MAIN native stamp may project this.
        assert!(r.inbox.claim().unwrap().is_none());
        assert_eq!(r.inbox.submit(r.input.clone()).unwrap(), r.status());
        for kind in [p::Kind::GenerateNew, p::Kind::BindReviewed, p::Kind::BackupEncrypted, p::Kind::RestoreEncrypted] {
            let mut wrong = r.status(); wrong.kind = kind; assert!(wrong.validate().is_err());
        }
        let mut wrong = r.status(); wrong.key = Some(key()); assert!(wrong.validate().is_err());
        assert_eq!(r.inbox.allow(r.scope.clone(), id(90)).unwrap_err(), Error::Conflict);
        r.inbox.revoke(&r.input.grant_id, Instant::now()).unwrap();
        assert_eq!(r.status().state, p::State::ReviewReady); // Withdrawal is neither Bind nor rewritten history.
    }
}

#[test]
fn prepare_loss_or_late_stop_cannot_publish_a_usable_review_or_replay() {
    for failure in 0..4 {
        let r = Rig::new(p::Kind::PrepareExisting);
        let (claim, link) = r.claim(); arm(&link);
        if failure == 0 { drop(claim); } else { claim.returned(Ok(())); }
        if failure == 1 { link.entry().unknown(); }
        link.entry().native_retired(7, p::State::ReviewReady, p::Reason::None, None);
        if failure == 3 { r.scope.read.revoke(Instant::now()); r.status(); }
        link.entry().continuation_joined(failure != 2);
        let status = r.status();
        assert_eq!(status.state, if failure == 3 { p::State::Cancelled } else { p::State::Unknown });
        assert!(status.key.is_none());
        assert!(r.inbox.access(None).unwrap().prepared.is_none());
        assert!(r.inbox.claim().unwrap().is_none());
        assert_eq!(r.inbox.submit(r.input.clone()).unwrap(), status);
    }
}

#[test]
fn prepare_and_old_actions_share_exactly_the_original_thirty_two_rows() {
    let r = Rig::new(p::Kind::PrepareExisting);
    r.inbox.publish_read(&r.scope.read, 0).unwrap();
    let kinds = [p::Kind::PrepareExisting, p::Kind::GenerateNew, p::Kind::BindReviewed, p::Kind::BackupEncrypted, p::Kind::RestoreEncrypted];
    for n in 0..p::REQUEST_LIMIT {
        let scope = Arc::new(NativeScope { kind: kinds[n % kinds.len()], project_id: r.scope.project_id.clone(),
            runtime_id: r.scope.runtime_id.clone(), end: r.scope.end, read: r.scope.read.clone(), identity: r.scope.identity.clone(),
            changes: r.scope.changes.clone() });
        let consent = id(100 + n as u32);
        r.inbox.allow(scope, consent.clone()).unwrap();
        let input = p::Submit { origin: p::Query { request_id: id(200 + n as u32), ..r.input.origin.clone() }, grant_id: consent.clone() };
        r.inbox.submit(input.clone()).unwrap();
        r.inbox.query(&input.origin, true).unwrap();
        r.inbox.revoke(&consent, Instant::now()).unwrap();
    }
    assert_eq!(r.inbox.retained_ids(&id(2)).unwrap().len(), 32);
    assert_eq!(r.inbox.allow(r.scope.clone(), id(999)).unwrap_err(), Error::Busy);
    assert!(r.inbox.book.lock().unwrap().entries.iter().all(|e| e.row.lock().unwrap().status.key.is_none()));
}
