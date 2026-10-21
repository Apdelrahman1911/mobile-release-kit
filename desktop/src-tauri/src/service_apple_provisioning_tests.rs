//! DATA/real synchronization tests only. No native/Apple/service/filesystem IO.
use super::*;
use std::time::Duration;
fn id(c: char) -> Id {
    Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn review() -> p::Review {
    p::Review {
        mode: p::Mode::Review,
        operation_id: id('a'),
        owner_generation: id('b'),
        status_revision: 3,
        saved_config: p::Content {
            bytes: 100,
            sha256: "c".repeat(64),
        },
        saved_version: p::Version {
            bytes: 40,
            sha256: "d".repeat(64),
            name: "1.2.3".into(),
            build: 42,
        },
    }
}
struct Fixture {
    inbox: Inbox,
    doc: Arc<()>,
    witness: Arc<()>,
    scope: Arc<NativeScope>,
}
impl Fixture {
    fn scope(doc: &Arc<()>, w: &Arc<()>) -> Arc<NativeScope> {
        let now = Instant::now();
        Arc::new(NativeScope {
            project_id: id('1'),
            runtime_id: "p1".into(),
            review_id: id('a'),
            review: review(),
            root: "/inert/never-opened".into(),
            device: 1,
            inode: 2,
            observation_revision: 1,
            expires: now + Duration::from_secs(290),
            read: Arc::new(
                crate::service_version_reserve_requests::ReadPermission::new(
                    now + Duration::from_secs(3600),
                ),
            ),
            document: Arc::downgrade(doc),
            witness: Arc::downgrade(w),
            control: Control::new(),
            retired: AtomicBool::new(false),
            changes: tokio::sync::watch::channel(0).0,
        })
    }
    fn new() -> Self {
        let doc = Arc::new(());
        let witness = Arc::new(());
        let scope = Self::scope(&doc, &witness);
        Self {
            inbox: Inbox::new(id('2')),
            doc,
            witness,
            scope,
        }
    }
    fn allow(&self) {
        self.inbox.allow(self.scope.clone(), id('3')).unwrap();
    }
    fn input(&self) -> p::Submit {
        p::Submit {
            origin: p::Query {
                project_id: id('1'),
                service_instance: id('2'),
                request_id: id('5'),
            },
            grant_id: id('3'),
            review_id: id('a'),
        }
    }
    fn submit(&self) -> Arc<Entry> {
        self.inbox.submit(self.input(), Instant::now()).unwrap();
        self.inbox.entries().unwrap()[0].clone()
    }
    fn finished(&self) -> NativeData {
        NativeData {
            operation: p::Operation {
                operation_id: id('a'),
                owner_generation: id('b'),
                status_revision: 5,
            },
            state: OperationState::Succeeded,
            reason: p::Reason::None,
            outcome: Some(p::Outcome::Complete),
            result: Some(p::Report {
                decision: "review-required".into(),
                comparison: None,
                attempt: None,
                certificate_id: None,
                certificate_sha256: None,
                do_not_replay: true,
                credential_ready: false,
            }),
            record_at_completion: None,
            retired: true,
        }
    }
}
#[test]
fn apple_cli_triple_cut_in_both_native_caller_orders() {
    for native_first in [false, true] {
        let f = Fixture::new();
        f.allow();
        let e = f.submit();
        let claim = f.inbox.claim().unwrap().unwrap();
        if native_first {
            e.native(f.finished());
            assert!(e.claim_history().unwrap().is_none());
            assert_eq!(e.status().unwrap().state, p::State::Finishing);
        } else {
            assert!(e.claim_history().unwrap().is_none());
        }
        claim.returned();
        if !native_first {
            assert!(e.pending());
            e.native(f.finished());
        }
        let h = e.claim_history().unwrap().unwrap();
        assert!(e.pending());
        assert!(e.status().unwrap().result.is_none());
        h.returned(Ok(())).unwrap();
        let status = e.status().unwrap();
        assert_eq!(status.state, p::State::Complete);
        assert_eq!(status.settlement, Settlement::Settled);
        assert!(!e.pending());
        assert!(status.result.is_some());
    }
}
#[test]
fn apple_cli_history_progress_ack_cannot_settle_later_native_terminal() {
    let f = Fixture::new();
    f.allow();
    let e = f.submit();
    let c = f.inbox.claim().unwrap().unwrap();
    let mut n = f.finished();
    n.operation.status_revision = 4;
    n.retired = false;
    n.state = OperationState::Running;
    n.reason = p::Reason::None;
    n.outcome = None;
    n.result = None;
    e.native(n);
    let progress = e.claim_history().unwrap().unwrap();
    e.native(f.finished());
    c.returned();
    progress.returned(Ok(())).unwrap();
    assert!(e.pending());
    e.claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    assert!(!e.pending());
}
#[test]
fn apple_cli_dropped_call_or_history_is_absorbing_unknown() {
    for caller in [true, false] {
        let f = Fixture::new();
        f.allow();
        let e = f.submit();
        let c = f.inbox.claim().unwrap().unwrap();
        e.native(f.finished());
        if caller {
            drop(c);
        } else {
            c.returned();
            drop(e.claim_history().unwrap().unwrap());
        }
        e.native(f.finished());
        assert_eq!(e.status().unwrap().state, p::State::Unknown);
        assert!(e.pending());
        assert!(f.inbox.can_allow().is_err());
    }
}
#[test]
fn apple_cli_history_error_not_native_result_is_unknown() {
    let f = Fixture::new();
    f.allow();
    let e = f.submit();
    f.inbox.claim().unwrap().unwrap().returned();
    e.native(f.finished());
    assert!(e
        .claim_history()
        .unwrap()
        .unwrap()
        .returned(Err(Error::Unavailable))
        .is_err());
    assert_eq!(e.status().unwrap().reason, p::Reason::HistoryUnavailable);
    assert!(e.status().unwrap().result.is_none());
}
#[test]
fn apple_cli_retired_unused_unknown_cannot_be_replaced() {
    let f = Fixture::new();
    f.allow();
    f.scope.retired.store(true, Ordering::Release);
    f.scope.control.unknown(Instant::now());
    assert!(f.inbox.can_allow().is_err());
    assert!(f
        .inbox
        .allow(Fixture::scope(&f.doc, &f.witness), id('6'))
        .is_err());
}
#[test]
fn apple_cli_same_request_reconnect_does_not_reexecute_and_grant_consumes_once() {
    let f = Fixture::new();
    f.allow();
    let e = f.submit();
    let mut changed = f.input();
    changed.review_id = id('7');
    assert!(f.inbox.submit(changed, Instant::now()).is_err());
    let again = f.inbox.submit(f.input(), Instant::now()).unwrap();
    assert_eq!(again.origin, e.origin().clone());
    assert_eq!(f.inbox.entries().unwrap().len(), 1);
    let mut other = f.input();
    other.origin.request_id = id('8');
    assert!(f.inbox.submit(other, Instant::now()).is_err());
    assert!(f.inbox.claim().unwrap().is_some());
    assert!(f.inbox.claim().unwrap().is_none());
}
#[test]
fn apple_cli_cancel_is_not_retirement_and_preserves_earliest_stop() {
    let f = Fixture::new();
    f.allow();
    let e = f.submit();
    let at = e.submitted_at();
    e.cancel(p::Reason::UserCancelled, at);
    e.cancel(p::Reason::PermissionRevoked, at + Duration::from_secs(1));
    assert_eq!(
        e.scope.control.first().unwrap(),
        Some((p::Reason::UserCancelled, at))
    );
    let s = f.inbox.query(e.origin(), true).unwrap();
    assert_eq!(s.settlement, Settlement::Pending);
    assert_eq!(s.state, p::State::Stopping);
    assert!(s.result.is_none());
}
#[test]
fn apple_cli_unknown_does_not_renew_original_cutoff() {
    let c = Control::new();
    let at = Instant::now();
    c.stop(p::Reason::UserCancelled, at);
    c.unknown(at + Duration::from_secs(8));
    assert!(c.first().is_err());
    assert_eq!(c.uncertain_at(at + Duration::from_secs(30)), at);
}
#[test]
fn apple_cli_read_revoke_and_wrong_doc_never_admit() {
    for revoke in [true, false] {
        let mut f = Fixture::new();
        f.allow();
        if revoke {
            f.scope.read.revoke(Instant::now());
        } else {
            f.doc = Arc::new(());
        }
        assert!(f.inbox.submit(f.input(), Instant::now()).is_err());
        assert!(f.inbox.entries().unwrap().is_empty());
    }
}
#[test]
fn apple_cli_native_identity_conflict_or_false_terminal_stays_unknown() {
    for mutate in [0, 1, 2] {
        let f = Fixture::new();
        f.allow();
        let e = f.submit();
        let mut n = f.finished();
        match mutate {
            0 => n.operation.operation_id = id('8'),
            1 => n.retired = false,
            _ => n.result = None,
        }
        e.native(n);
        assert_eq!(e.status().unwrap().state, p::State::Unknown);
    }
}
#[test]
fn apple_cli_complete_keeps_metadata_not_a_new_grant_or_replay() {
    let f = Fixture::new();
    f.allow();
    let e = f.submit();
    f.inbox.claim().unwrap().unwrap().returned();
    e.native(f.finished());
    e.claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    assert_eq!(
        f.inbox.query(e.origin(), true).unwrap().state,
        p::State::Complete
    );
    let a = f.inbox.access().unwrap();
    assert!(a.consumed);
    assert!(!a.enabled);
    assert!(!a.pending);
    assert!(f.inbox.can_allow().is_err()); // Consumed permission alone is not withdrawal.
    f.inbox.withdraw(&id('3'), Instant::now()).unwrap();
    assert!(f.inbox.can_allow().is_ok());
    // No GUI progress/final event was required: a late first access still
    // reads this same complete row. A later explicitly allowed request may
    // occupy the sole lease, but it cannot replace the old query's finality.
    assert_eq!(a.status.as_ref().unwrap().state, p::State::Complete);
    let mut next = Fixture::scope(&f.doc, &f.witness);
    let next_scope = Arc::get_mut(&mut next).unwrap();
    next_scope.review_id = id('8');
    next_scope.review.operation_id = id('8');
    f.inbox.allow(next, id('6')).unwrap();
    let mut input = f.input();
    input.origin.request_id = id('7');
    input.grant_id = id('6');
    input.review_id = id('8');
    assert_eq!(
        f.inbox.submit(input, Instant::now()).unwrap().state,
        p::State::Queued
    );
    assert_eq!(
        f.inbox.query(e.origin(), false).unwrap().state,
        p::State::Complete
    );
    assert_eq!(f.inbox.entries().unwrap().len(), 2);
}
#[test]
fn apple_cli_finite_roster_never_reclaims_terminal_or_unknown_rows() {
    let f = Fixture::new();
    let mut b = f.inbox.book.lock().unwrap();
    for _ in 0..p::REQUEST_LIMIT {
        b.entries.push(Stored::Start(Arc::new(Entry {
            input: f.input(),
            scope: f.scope.clone(),
            submitted: Instant::now(),
            row: Mutex::new(Row {
                revision: 1,
                claimed: true,
                caller_returned: true,
                observed_stop: None,
                native: Some(f.finished()),
                history_started: true,
                history_acked: 5,
                history_claim: None,
                unknown: None,
            }),
        })));
    }
    drop(b);
    assert!(f.inbox.can_allow().is_err());
    assert!(f
        .inbox
        .allow(Fixture::scope(&f.doc, &f.witness), id('6'))
        .is_err());
    assert_eq!(f.inbox.entries().unwrap().len(), 32);
}
#[test]
fn apple_cli_wire_required_nulls_closed_reports_and_private_fields() {
    let f = Fixture::new();
    f.allow();
    let a = f.inbox.access().unwrap();
    a.validate().unwrap();
    let mut v = serde_json::to_value(&a).unwrap();
    v.as_object_mut().unwrap().remove("status");
    assert!(serde_json::from_value::<p::Access>(v).is_err());
    let mut r = serde_json::to_value(review()).unwrap();
    r["credential"] = "forbidden".into();
    assert!(serde_json::from_value::<p::Review>(r).is_err());
    let mut n = f.finished();
    n.result.as_mut().unwrap().credential_ready = true;
    assert!(!n.valid(&review()));
}

#[test]
fn apple_cli_exact_modes_and_status_payloads_remain_small_and_closed() {
    let f = Fixture::new();
    f.allow();
    let e = f.submit();
    let status = e.status().unwrap();
    let mut value = serde_json::to_value(&status).unwrap();
    value["review"]["mode"] = "key-recover".into();
    assert!(serde_json::from_value::<p::Status>(value).is_err());
    for private in ["csr", "password", "p12", "certificateDer", "sourceKey"] {
        let mut v = serde_json::to_value(&status).unwrap();
        v[private] = "forbidden".into();
        assert!(serde_json::from_value::<p::Status>(v).is_err());
    }
    let response = crate::service_protocol::Response {
        version: 1,
        request_id: id('6'),
        service_instance: id('2'),
        client_id: id('7'),
        session_id: id('8'),
        response: crate::service_protocol::ResponseBody::AppleProvisioningRequest(status),
    };
    assert!(
        crate::service_protocol::encode_response(&response)
            .unwrap()
            .len()
            < p::STATUS_LIMIT
    );
    assert!(
        std::mem::size_of::<Entry>()
            + std::mem::size_of::<NativeScope>()
            + std::mem::size_of::<Row>()
            + std::mem::size_of::<Control>()
            < 4096
    );
    // 8KiB scope/native-link metadata plus TWO 8KiB native/history snapshots.
    // The accepted common eight-worker pool owns the IPC-only term, not each
    // retained family. Keep ALL32 row debits and the original128KiB ancillary.
    assert!(p::ROW_BACKING >= 3 * 8192);
    assert_eq!(p::DOCUMENT_BACKING, 32 * p::ROW_BACKING + 128 * 1024);
    assert_eq!(p::IPC_WORKER_BACKING, 3 * p::STATUS_LIMIT + p::RAW_LIMIT);
    assert_eq!(crate::installed_cli_ipc::CLIENTS, 8);
}
#[test]
fn apple_cli_record_requires_exact_mode_and_all_three_return_cuts() {
    let mut f = Fixture::new();
    Arc::get_mut(&mut f.scope).unwrap().review.mode = p::Mode::KeyPrepare;
    f.allow();
    let e = f.submit();
    let mut native = f.finished();
    native.result.as_mut().unwrap().decision = "produced".into();
    native.record_at_completion = Some(p::RecordAtCompletion {
        kind: p::RecordKind::AppleDistributionKey,
        reference: crate::service_protocol::CredentialReference {
            vault_id: id('1'),
            generation_id: id('2'),
            record_id: id('3'),
            revision_id: id('4'),
            revision_counter: 1,
        },
    });
    e.native(native);
    assert!(e.status().unwrap().record_at_completion.is_none());
    f.inbox.claim().unwrap().unwrap().returned();
    assert!(e.status().unwrap().record_at_completion.is_none());
    e.claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    let status = e.status().unwrap();
    assert!(status.record_at_completion.is_some());
    status.validate().unwrap();
    let mut wrong = status.clone();
    wrong.review.mode = p::Mode::P12Save;
    assert!(wrong.validate().is_err());
    let mut later = status;
    later
        .record_at_completion
        .as_mut()
        .unwrap()
        .reference
        .revision_counter = 2;
    assert!(later.validate().is_err());
}

#[test]
fn apple_cli_stop_before_native_frame_advances_only_data_revision() {
    let f = Fixture::new();
    f.allow();
    let entry = f.submit();
    let before = entry.status().unwrap();
    f.inbox.query(&f.input().origin, true).unwrap();
    let stopped = entry.status().unwrap();
    assert!(stopped.revision > before.revision);
    assert_eq!(stopped.state, p::State::Stopping);
    assert_eq!(stopped.settlement, Settlement::Pending);
    assert_eq!(stopped.operation, None);
    assert_eq!(stopped, entry.status().unwrap());
    f.scope.control.unknown(Instant::now());
    let unknown = entry.status().unwrap();
    assert!(unknown.revision > stopped.revision);
    assert_eq!(unknown.state, p::State::Unknown);
    assert!(f.inbox.can_allow().is_err());
}
