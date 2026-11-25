//! Real memory methods only. Never supplies a native retirement/GO witness.
use super::*;
use crate::{edit_owner::EditOwner, runtime::RuntimeConfig, service_protocol::Id};
use std::{path::PathBuf, time::Duration};

fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn scope(doc: &Arc<()>, data: p::Review, identity: Arc<()>) -> Arc<r::NativeScope> {
    let now = Instant::now();
    r::NativeScope::new(
        id('1'),
        "project-1".into(),
        "/never-opened-github-delegation".into(),
        1,
        2,
        3,
        data,
        identity,
        now + Duration::from_secs(100),
        Arc::new(
            crate::service_version_reserve_requests::ReadPermission::new(
                now + Duration::from_secs(110),
            ),
        ),
        Arc::downgrade(doc),
        tokio::sync::watch::channel(1).0,
    )
}
fn data(kind: p::Kind) -> p::Review {
    p::Review::from_prepared(kind, p::PreparedReference {
        session_id: "github-connection-1".into(),
        consent_id: "a".repeat(32),
        expected_revision: 7,
        prepared_sha256: "b".repeat(64),
    }).unwrap()
}
fn input() -> p::Submit {
    p::Submit {
        origin: p::Query {
            project_id: id('1'),
            service_instance: id('2'),
            request_id: id('4'),
        },
        grant_id: id('3'),
    }
}

#[test]
fn streamed_review_binds_private_input_and_actual_original_edit_stamp() {
    let owner = EditOwner::new(RuntimeConfig::packaged(PathBuf::from(
        "/never-opened-github-review-test",
    )));
    let doc = Arc::new(());
    owner.bind_saved_registration(
        &doc,
        Arc::new(crate::saved_command_owner::AndroidRegistrationControl::default()),
    );
    owner.initial_document("main").unwrap();
    let foreign = EditOwner::new(RuntimeConfig::packaged(PathBuf::from(
        "/never-opened-other-github-review-test",
    )));
    foreign.bind_saved_registration(
        &doc,
        Arc::new(crate::saved_command_owner::AndroidRegistrationControl::default()),
    );
    foreign.initial_document("main").unwrap();
    let original = owner.saved_registration_guard(&doc).unwrap();
    let other = foreign.saved_registration_guard(&doc).unwrap();
    for kind in [
        p::Kind::RepositoryCreate,
        p::Kind::DraftPrCreate,
        p::Kind::FailedJobsRetry,
    ] {
        let identity = Arc::new(());
        let private = serde_json::json!({"accountId":17,"owner":"fixed-owner","privateDraft":"must-not-be-a-public-field","attempt":3});
        let at = Instant::now() + Duration::from_secs(100);
        let a = review(
            kind,
            "github-connection-1",
            &"a".repeat(32),
            7,
            &private,
            identity.clone(),
            original.stamp().unwrap(),
            at,
        )
        .unwrap();
        let b = review(
            kind,
            "github-connection-1",
            &"a".repeat(32),
            7,
            &private,
            identity.clone(),
            original.stamp().unwrap(),
            at,
        )
        .unwrap();
        assert_eq!(a.data, b.data);
        assert!(Arc::ptr_eq(&a.identity, &identity));
        assert!(original.matches(&a.stamp));
        assert!(!other.matches(&a.stamp));
        assert_eq!(
            a.data.prepared().unwrap().prepared_sha256,
            format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&private).unwrap())
            )
        );
        let mut changed = private;
        changed["attempt"] = serde_json::json!(4);
        let c = review(
            kind,
            "github-connection-1",
            &"a".repeat(32),
            7,
            &changed,
            identity,
            original.stamp().unwrap(),
            at,
        )
        .unwrap();
        assert_ne!(a.data.prepared().unwrap().prepared_sha256, c.data.prepared().unwrap().prepared_sha256);
        let public = serde_json::to_string(&a.data).unwrap();
        assert!(!public.contains("privateDraft") && !public.contains("must-not-be"));
    }
}

#[test]
fn optional_origin_requires_same_claimed_live_scope_not_equal_metadata() {
    let doc = Arc::new(());
    let original = scope(&doc, data(p::Kind::RepositoryCreate), Arc::new(()));
    let equal = scope(&doc, original.review.clone(), original.identity.clone());
    let inbox = r::Inbox::new(id('2'));
    inbox.allow(original.clone(), id('3')).unwrap();
    inbox.submit(input()).unwrap();
    let entry = inbox.entries().unwrap().pop().unwrap();
    let weak = Some(Arc::downgrade(&original));
    assert!(origin(&None, None));
    assert!(!origin(&weak, None));
    assert!(!origin(&None, Some(&entry)));
    assert!(!origin(&weak, Some(&entry))); // not claimed
    let call = inbox.claim().unwrap().unwrap();
    assert!(origin(&weak, Some(&entry)));
    assert!(!origin(&Some(Arc::downgrade(&equal)), Some(&entry)));
    revoke(&weak); // actual unused-original close, not an invented native return
    assert!(!origin(&weak, Some(&entry)));
    assert!(entry.pending());
    call.returned(Err(p::Reason::PermissionRevoked));
    assert!(entry.pending()); // history has not returned
}

#[test]
fn typed_native_refusal_mapping_cannot_clear_unknown_or_supply_other_returns() {
    let doc = Arc::new(());
    let original = scope(&doc, data(p::Kind::RepositoryCreate), Arc::new(()));
    let inbox = r::Inbox::new(id('2'));
    inbox.allow(original, id('3')).unwrap();
    inbox.submit(input()).unwrap();
    let call = inbox.claim().unwrap().unwrap();
    let entry = call.entry().clone();
    entry.entering().unwrap();
    entry.arm("repository-create-1").unwrap();
    accepted(
        &Some(entry.clone()),
        "repository-create-1",
        crate::github_repository_create_protocol::Reason::TargetChanged,
        crate::github_repository_create_protocol::Effect::NotSent,
    );
    let status = entry.status().unwrap();
    assert_eq!(status.state, p::State::Finishing);
    assert!(entry.pending());
    assert!(entry.claim_history().unwrap().is_none()); // original caller still held
    unknown(&Some(entry.clone()));
    call.returned(Ok(()));
    accepted(
        &Some(entry.clone()),
        "repository-create-1",
        crate::github_repository_create_protocol::Reason::None,
        crate::github_repository_create_protocol::Effect::CreatedObserved,
    );
    assert_eq!(entry.status().unwrap().state, p::State::Unknown);
    assert!(entry.pending());
}
