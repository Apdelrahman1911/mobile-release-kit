//! Real Book/Entry/codec methods with inert facts; no native receipts or IO.
use super::*;
use p::enrollment as data;
use std::time::Duration;

fn id(n: u64) -> Id {
    Id::parse(&format!("{n:032x}")).unwrap()
}
fn review(kind: p::Kind) -> p::Review {
    match kind {
        p::Kind::CounterEnrollmentReview => {
            p::Review::CounterEnrollmentReview(data::ReviewReference {
                session_id: "session-a".into(),
                expected_revision: 4,
                expected_connection_revision: 9,
                request_sha256: "b".repeat(64),
            })
        }
        p::Kind::CounterEnrollmentConnect => {
            p::Review::CounterEnrollmentConnect(data::ConnectReference {
                session_id: "session-a".into(),
                expected_revision: 4,
                expected_connection_revision: 9,
                review_id: "a".repeat(32),
                review_sha256: "b".repeat(64),
            })
        }
        _ => p::Review::from_prepared(
            kind,
            p::PreparedReference {
                session_id: "session-a".into(),
                expected_revision: 4,
                consent_id: "a".repeat(32),
                prepared_sha256: "b".repeat(64),
            },
        )
        .unwrap(),
    }
}
fn scope(doc: &Arc<()>, kind: p::Kind) -> Arc<NativeScope> {
    let now = Instant::now();
    NativeScope::new(
        id(1),
        "project-1".into(),
        "/never-opened-enrollment-row".into(),
        1,
        2,
        3,
        review(kind),
        Arc::new(()),
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
fn snapshot(kind: p::Kind, op: &str) -> data::Snapshot {
    if kind == p::Kind::CounterEnrollmentReview {
        data::Snapshot {
            operation: data::Operation::Review,
            phase: data::Phase::Reviewed,
            reason: data::OutcomeReason::None,
            review: Some(data::ReviewView {
                id: op.into(),
                repository: "fixture/app".into(),
                version: data::Version {
                    name: "1.2.3".into(),
                    build: 7,
                },
                reservations: 2,
            }),
        }
    } else {
        data::Snapshot {
            operation: data::Operation::Connect,
            phase: data::Phase::Connected,
            reason: data::OutcomeReason::Connected,
            review: None,
        }
    }
}
fn returned(entry: &Entry, op: &str) {
    let kind = entry.scope.review.kind();
    entry.enrollment_returned(
        op,
        p::Reason::None,
        if kind == p::Kind::CounterEnrollmentReview {
            p::Effect::None
        } else {
            p::Effect::LocalMappingObserved
        },
        Some(snapshot(kind, op)),
    );
}
struct F {
    inbox: Inbox,
    scope: Arc<NativeScope>,
    doc: Arc<()>,
    input: p::Submit,
}
impl F {
    fn new(kind: p::Kind) -> Self {
        let doc = Arc::new(());
        let scope = scope(&doc, kind);
        let inbox = Inbox::new(id(2));
        inbox.allow(scope.clone(), id(3)).unwrap();
        let input = p::Submit {
            origin: p::Query {
                project_id: id(1),
                service_instance: id(2),
                request_id: id(4),
            },
            grant_id: id(3),
        };
        inbox.submit(input.clone()).unwrap();
        Self {
            inbox,
            scope,
            doc,
            input,
        }
    }
    fn claim(&self) -> Claim {
        let review_id = match &self.scope.review {
            p::Review::CounterEnrollmentConnect(r) => Some(r.review_id.as_str()),
            _ => None,
        };
        self.inbox
            .claim_enrollment(
                &self.input.origin,
                &self.doc,
                "project-1",
                self.scope.review.kind(),
                review_id,
            )
            .unwrap()
    }
}

#[test]
fn closed_enrollment_data_keeps_old_ids_and_refuses_authority_fields() {
    for kind in [
        p::Kind::CounterEnrollmentReview,
        p::Kind::CounterEnrollmentConnect,
    ] {
        let mut value = serde_json::json!({"kind":kind,"sessionId":"session-a", "expectedRevision":4,"expectedConnectionRevision":9});
        if kind == p::Kind::CounterEnrollmentConnect {
            value["reviewId"] = serde_json::json!("a".repeat(32));
        }
        let input: data::Input = serde_json::from_value(value.clone()).unwrap();
        assert!(input.valid());
        assert_eq!(input.kind(), kind);
        assert!(kind.operation(&"a".repeat(32)));
        assert!(!kind.operation("version-enrollment-1"));
        let action = serde_json::to_value(kind.action()).unwrap();
        assert!(action.as_str().unwrap().len() <= 32); // unchanged Operation wire quote
        assert_eq!(action, serde_json::to_value(kind).unwrap());
        for field in ["authority", "ledger", "root", "token", "accountId", "url"] {
            let mut bad = value.clone();
            bad[field] = serde_json::json!("not-authority");
            assert!(
                serde_json::from_value::<data::Input>(bad).is_err(),
                "{field}"
            );
        }
        for field in [
            "sessionId",
            "expectedRevision",
            "expectedConnectionRevision",
        ] {
            let mut bad = value.clone();
            bad[field] = serde_json::Value::Null;
            assert!(serde_json::from_value::<data::Input>(bad).is_err());
        }
    }
    let old = review(p::Kind::RepositoryCreate);
    assert_eq!(
        serde_json::to_value(old).unwrap(),
        serde_json::json!({"kind":"repository-create",
        "sessionId":"session-a","expectedRevision":4,"consentId":"a".repeat(32),"preparedSha256":"b".repeat(64)})
    );
    assert!(!p::Kind::CounterCreate.operation(&"a".repeat(32)));
    assert!(p::Kind::CounterCreate.operation("github-publication-1"));
    assert!(p::Review::from_prepared(
        p::Kind::CounterEnrollmentConnect,
        p::PreparedReference {
            session_id: "session-a".into(),
            expected_revision: 4,
            consent_id: "a".repeat(32),
            prepared_sha256: "b".repeat(64),
        }
    )
    .is_none());
}

#[test]
fn exact_foreground_claim_precedes_no_other_kind_and_cannot_be_replayed() {
    let f = F::new(p::Kind::CounterEnrollmentConnect);
    assert!(f.inbox.claim().unwrap().is_none()); // old automatic relay does not run this live row
    for (document, runtime, kind, review_id) in [
        (
            Arc::new(()),
            "project-1",
            p::Kind::CounterEnrollmentConnect,
            Some("a".repeat(32)),
        ),
        (
            f.doc.clone(),
            "project-2",
            p::Kind::CounterEnrollmentConnect,
            Some("a".repeat(32)),
        ),
        (
            f.doc.clone(),
            "project-1",
            p::Kind::CounterEnrollmentReview,
            None,
        ),
        (
            f.doc.clone(),
            "project-1",
            p::Kind::CounterEnrollmentConnect,
            Some("c".repeat(32)),
        ),
    ] {
        assert!(f
            .inbox
            .claim_enrollment(
                &f.input.origin,
                &document,
                runtime,
                kind,
                review_id.as_deref()
            )
            .is_err());
    }
    let mut foreign = f.input.origin.clone();
    foreign.service_instance = id(9);
    assert!(f
        .inbox
        .claim_enrollment(
            &foreign,
            &f.doc,
            "project-1",
            p::Kind::CounterEnrollmentConnect,
            Some(&"a".repeat(32))
        )
        .is_err());
    assert_eq!(
        f.inbox.query(&f.input.origin, false).unwrap().state,
        p::State::Queued
    );
    let c = f.claim();
    let entry = c.entry().clone();
    assert!(f
        .inbox
        .claim_enrollment(
            &f.input.origin,
            &f.doc,
            "project-1",
            p::Kind::CounterEnrollmentConnect,
            Some(&"a".repeat(32))
        )
        .is_err());
    assert_eq!(
        f.inbox.submit(f.input.clone()).unwrap().state,
        p::State::Starting
    );
    c.returned(Err(p::Reason::NativeRefused));
    entry
        .claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    assert!(entry.status().unwrap().never_admitted);
    assert!(!entry.enrollment_retired(&"a".repeat(32)));
}

#[test]
fn real_native_caller_and_latest_history_are_all_needed_for_enrollment_result() {
    for kind in [
        p::Kind::CounterEnrollmentReview,
        p::Kind::CounterEnrollmentConnect,
    ] {
        for native_first in [false, true] {
            let f = F::new(kind);
            let c = f.claim();
            let e = c.entry().clone();
            let op = "a".repeat(32);
            e.enrollment_attached(&op).unwrap();
            e.go(&op).unwrap();
            let progress = e.claim_history().unwrap().unwrap();
            if native_first {
                returned(&e, &op);
            }
            c.returned(Ok(()));
            if !native_first {
                returned(&e, &op);
            }
            let pending = e.status().unwrap();
            assert_eq!(pending.state, p::State::Finishing);
            assert!(pending.result.is_none());
            assert_eq!(
                pending.effect,
                if kind.mutation() {
                    p::Effect::PotentiallyApplied
                } else {
                    p::Effect::None
                }
            );
            assert!(!e.enrollment_retired(&op));
            assert!(!e.positively_returned(&op));
            progress.returned(Ok(())).unwrap();
            assert!(!e.enrollment_retired(&op));
            e.claim_history()
                .unwrap()
                .unwrap()
                .returned(Ok(()))
                .unwrap();
            assert!(e.enrollment_retired(&op) && e.positively_returned(&op));
            let complete = e.status().unwrap();
            assert_eq!(complete.state, p::State::Complete);
            assert!(matches!(
                complete.result,
                Some(p::dispatch::Snapshot::Enrollment(_))
            ));
            f.inbox
                .revoke(p::Reason::PermissionRevoked, Instant::now())
                .unwrap();
            assert!(e.positively_returned(&op)); // withdrawing a completed producer is not a new permission
            assert!(!e.enrollment_retired(&"b".repeat(32)));
        }
    }
}

#[test]
fn possible_cas_unknown_or_missing_returns_never_say_not_sent_or_supply_review() {
    for cut in 0..4 {
        let f = F::new(p::Kind::CounterEnrollmentConnect);
        let c = f.claim();
        let e = c.entry().clone();
        let op = "a".repeat(32);
        e.enrollment_attached(&op).unwrap();
        if cut != 0 {
            e.go(&op).unwrap();
        }
        returned(&e, &op);
        if cut == 1 {
            drop(c);
        } else {
            c.returned(Ok(()));
        }
        if cut == 2 {
            drop(e.claim_history().unwrap().unwrap());
        }
        if cut == 3 {
            // Poison/uncertainty discovered by the actual native Control must
            // fence history even before a later public status samples it.
            f.scope.enrollment_unknown();
            assert!(e.claim_history().unwrap().is_none());
        }
        let s = e.status().unwrap();
        assert_eq!(s.state, p::State::Unknown);
        assert!(s.result.is_none());
        assert!(e.pending());
        assert!(!e.enrollment_retired(&op) && !e.positively_returned(&op));
        if cut != 0 {
            assert_eq!(s.effect, p::Effect::PotentiallyApplied);
        }
        returned(&e, &op);
        assert_eq!(e.status().unwrap().state, p::State::Unknown);
    }
}

#[test]
fn quiet_cancelled_queue_closes_only_as_real_unclaimed_nonentry_and_keeps_first_read() {
    let f = F::new(p::Kind::CounterEnrollmentReview);
    let at = Instant::now();
    f.scope.revoke(p::Reason::UserCancelled, at);
    let first = at - Duration::from_millis(500);
    f.scope.read.revoke(first);
    let c = f.inbox.claim().unwrap().unwrap();
    let e = c.entry().clone();
    assert_eq!(e.first_stop(), Some((false, first)));
    c.returned(Err(e.first_reason().unwrap()));
    assert!(e.status().unwrap().operation_id.is_none());
    assert!(e.pending());
    e.claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    let s = e.status().unwrap();
    assert_eq!(s.state, p::State::Cancelled);
    assert!(s.never_admitted && s.result.is_none());
    assert_eq!(s.effect, p::Effect::None);
    assert!(f.inbox.claim().unwrap().is_none());
}

#[test]
fn original_stop_poison_is_absorbing_before_a_later_native_or_caller_return() {
    let f = F::new(p::Kind::CounterEnrollmentReview);
    let c = f.claim();
    let e = c.entry().clone();
    let op = "a".repeat(32);
    e.enrollment_attached(&op).unwrap();
    e.go(&op).unwrap();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = f.scope.stop.lock().unwrap();
        panic!("inert original STOP poison");
    }));
    assert!(e.first_stop().unwrap().0);
    returned(&e, &op);
    c.returned(Ok(()));
    assert!(e.claim_history().unwrap().is_none());
    // Scope poison may itself prevent serialization; it can never return a
    // usable positive row or make the retained original reusable.
    assert!(e.status().is_err() || e.status().is_ok_and(|s| s.state == p::State::Unknown));
    assert!(!e.positively_returned(&op) && !e.enrollment_retired(&op));
}

#[test]
fn compact_results_require_nulls_exact_original_and_owned_physical_capacity() {
    let op = "a".repeat(32);
    let good = snapshot(p::Kind::CounterEnrollmentConnect, &op);
    let mut raw = serde_json::to_value(&good).unwrap();
    raw.as_object_mut().unwrap().remove("review");
    assert!(serde_json::from_value::<data::Snapshot>(raw).is_err());
    assert!(!good.valid_row(
        p::Kind::CounterEnrollmentConnect,
        p::State::Finishing,
        Some(&op),
        p::Effect::LocalMappingObserved
    ));
    assert!(!good.valid_for(p::Kind::CounterEnrollmentReview));
    let f = F::new(p::Kind::CounterEnrollmentReview);
    let c = f.claim();
    let e = c.entry().clone();
    e.enrollment_attached(&op).unwrap();
    e.go(&op).unwrap();
    returned(&e, &op);
    c.returned(Ok(()));
    e.claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    let mut copy = e.status().unwrap();
    let Some(p::dispatch::Snapshot::Enrollment(s)) = copy.result.as_mut() else {
        panic!("enrollment result");
    };
    s.review.as_mut().unwrap().repository = "foreign/project".into();
    s.review.as_mut().unwrap().id = "c".repeat(32);
    assert!(copy.validate().is_err());
    let Some(p::dispatch::Snapshot::Enrollment(original)) = e.status().unwrap().result else {
        panic!("original");
    };
    assert_eq!(original.review.unwrap().repository, "fixture/app");
    let mut excess = snapshot(p::Kind::CounterEnrollmentReview, &op);
    excess
        .review
        .as_mut()
        .unwrap()
        .repository
        .reserve_exact(data::SNAPSHOT_BACKING);
    assert!(!excess.valid_for(p::Kind::CounterEnrollmentReview));
    let doc = Arc::new(());
    let mut oversized = scope(&doc, p::Kind::CounterEnrollmentReview);
    let p::Review::CounterEnrollmentReview(v) = &mut Arc::get_mut(&mut oversized).unwrap().review
    else {
        unreachable!()
    };
    v.session_id.reserve_exact(129);
    assert!(Inbox::new(id(8)).allow(oversized, id(9)).is_err());
}

#[test]
fn all_mixed_thirty_two_rows_keep_original_snapshots_and_no_extra_capacity() {
    let doc = Arc::new(());
    let inbox = Inbox::new(id(2));
    for n in 0..p::REQUEST_LIMIT {
        let kind = [
            p::Kind::RepositoryCreate,
            p::Kind::CounterEnrollmentReview,
            p::Kind::CounterEnrollmentConnect,
        ][n % 3];
        let s = scope(&doc, kind);
        let grant = id(100 + n as u64);
        inbox.allow(s, grant.clone()).unwrap();
        let origin = p::Query {
            project_id: id(1),
            service_instance: id(2),
            request_id: id(1000 + n as u64),
        };
        inbox
            .submit(p::Submit {
                origin: origin.clone(),
                grant_id: grant,
            })
            .unwrap();
        let c = if kind.enrollment_family() {
            let review_id = (kind == p::Kind::CounterEnrollmentConnect).then(|| "a".repeat(32));
            inbox
                .claim_enrollment(&origin, &doc, "project-1", kind, review_id.as_deref())
                .unwrap()
        } else {
            inbox.claim().unwrap().unwrap()
        };
        let e = c.entry().clone();
        if kind.enrollment_family() {
            let op = format!("{:032x}", n + 1);
            e.enrollment_attached(&op).unwrap();
            e.go(&op).unwrap();
            returned(&e, &op);
        } else {
            e.entering().unwrap();
            e.arm("repository-create-1").unwrap();
            e.go("repository-create-1").unwrap();
            e.returned_native(
                "repository-create-1",
                p::Reason::None,
                p::Effect::CreatedObserved,
            );
        }
        c.returned(Ok(()));
        e.claim_history()
            .unwrap()
            .unwrap()
            .returned(Ok(()))
            .unwrap();
    }
    assert_eq!(inbox.entries().unwrap().len(), 32);
    assert_eq!(retained_document_backing(), Some(p::DOCUMENT_BACKING));
    assert_eq!(
        inbox
            .entries()
            .unwrap()
            .iter()
            .filter(|e| e.status().unwrap().result.is_some())
            .count(),
        21
    );
    assert_eq!(
        inbox
            .allow(scope(&doc, p::Kind::CounterEnrollmentReview), id(999))
            .err(),
        Some(Error::Busy)
    );
    assert_eq!(inbox.catalogue_requests(&id(2), &id(1)).unwrap().len(), 32);
    assert!(inbox.catalogue_requests(&id(2), &id(9)).unwrap().is_empty());
}
