//! Extends the existing Store DATA fixture. Real Inbox/Entry/READ/history
//! methods only; no Saved admission, IO, native joins or provider is fabricated.
use super::*;
use crate::{
    service_store_inventory_protocol as inventory, service_store_prepare_protocol as flow,
    service_store_requests::preparation as queue,
};

fn selected(kind: flow::Kind) -> flow::Selection {
    let r = review();
    flow::Selection {
        kind,
        saved_config: r.saved_config,
        saved_version: r.saved_version,
        candidate: kind.candidate().then(|| p::Candidate {
            operation_id: "12345678-1234-4234-8234-123456789abc".into(),
            sha256: "e".repeat(64),
        }),
    }
}
fn scope(f: &Fixture, kind: flow::Kind) -> Arc<queue::Scope> {
    queue::Scope::new(
        id('1'),
        "p1".into(),
        id('4'),
        selected(kind),
        "/inert/never-opened".into(),
        1,
        2,
        1,
        f.scope.expires,
        f.scope.read.clone(),
        Arc::downgrade(&f.doc),
        Arc::downgrade(&f.witness),
        tokio::sync::watch::channel(0).0,
    )
}
fn r() -> flow::Review {
    flow::Review {
        review_id: id('a'),
        operation: p::Operation {
            operation_id: id('a'),
            owner_generation: id('b'),
            status_revision: 3,
        },
    }
}
fn enter(f: &Fixture, kind: flow::Kind) -> (Arc<queue::PrepareEntry>, queue::PrepareClaim) {
    f.inbox.allow_preparation(scope(f, kind), id('3')).unwrap();
    f.inbox
        .submit_preparation(f.input(), Instant::now())
        .unwrap();
    let e = f.inbox.preparation_entry(&f.input().origin).unwrap();
    let c = f.inbox.claim_preparation().unwrap().unwrap();
    assert!(matches!(c.call, queue::Call::Prepare));
    (e, c)
}
fn prepared(e: &Arc<queue::PrepareEntry>) {
    e.attach(r(), e.scope.expires).unwrap();
    e.installed().unwrap();
    e.native(queue::Native {
        operation: r().operation,
        state: OperationState::Prepared,
        reason: p::Reason::None,
        outcome: None,
        result: None,
        retired: false,
    });
}
fn start(f: &Fixture, e: &Arc<queue::PrepareEntry>) -> queue::PrepareClaim {
    e.allow_start(&r(), id('6')).unwrap();
    let mut input = f.input();
    input.grant_id = id('6');
    input.review_id = id('a');
    e.submit_start(input, Instant::now()).unwrap();
    let c = f.inbox.claim_preparation().unwrap().unwrap();
    assert!(matches!(c.call, queue::Call::Start));
    c
}
fn finished(f: &Fixture) -> queue::Native {
    let n = f.finished();
    queue::Native {
        operation: n.operation,
        state: n.state,
        reason: n.reason,
        outcome: n.outcome,
        result: n.result.map(|report| flow::Report::Ordinary { report }),
        retired: n.retired,
    }
}
fn android() -> inventory::Android {
    inventory::Android {
        observation: inventory::Observation::Observed,
        coverage: "play-android-current-inventory/1".into(),
        revision: Some("c".repeat(64)),
        counts: Some(inventory::AndroidCounts {
            tracks: 400,
            releases: 400,
            version_codes: 4000,
            bundles: 400,
            apks: 400,
        }),
        max_build: Some(2_100_000_000),
        marketing_version: None,
        temporary_edit: inventory::Edit::Deleted,
        historical_uniqueness: "not-established".into(),
    }
}
fn ios() -> inventory::Ios {
    inventory::Ios {
        observation: inventory::Observation::Observed,
        coverage: "asc-ios-current-inventory/1".into(),
        revision: Some("d".repeat(64)),
        counts: Some(inventory::IosCounts {
            builds: 400,
            build_uploads: 400,
            app_store_versions: 400,
        }),
        max_build: Some(2_100_000_000),
        marketing_version: Some("1.2.3".into()),
        historical_uniqueness: "not-established".into(),
    }
}
#[test]
fn prepare_attachment_fact_and_actual_return_are_both_required_before_start() {
    for cut in 0..3 {
        let f = Fixture::new();
        let (e, c) = enter(&f, flow::Kind::AndroidAccess);
        if cut > 0 {
            e.attach(r(), e.scope.expires).unwrap();
        }
        if cut == 2 {
            e.installed().unwrap();
        }
        assert!(e.allow_start(&r(), id('6')).is_err());
        // Err without construction is known refusal. Err after attach OR
        // installed publication is retained uncertainty, never non-admission.
        c.returned(false);
        let s = e.status().unwrap();
        assert_eq!(
            s.phase,
            if cut == 0 {
                flow::Phase::Final
            } else {
                flow::Phase::Unknown
            }
        );
        assert_eq!(e.constructed(), cut > 0);
        if cut > 0 {
            assert!(e.pending());
            assert!(f.inbox.can_allow().is_err());
        }
    }
    let f = Fixture::new();
    let (e, c) = enter(&f, flow::Kind::AndroidAccess);
    prepared(&e);
    assert!(e.installed_review().is_err());
    c.returned(true);
    assert_eq!(e.installed_review().unwrap(), r());
    assert_eq!(e.status().unwrap().phase, flow::Phase::Prepared);
    assert!(f.inbox.claim_preparation().unwrap().is_none());
    e.allow_start(&r(), id('6')).unwrap();
    assert!(f.inbox.claim_preparation().unwrap().is_none()); // Allow != submit.
    let a = f.inbox.preparation_access().unwrap();
    a.validate().unwrap();
    assert_eq!(a.permission, Some(flow::Permission::Start));
    assert!(a.enabled && !a.consumed);
}
#[test]
fn prepare_start_native_and_history_returns_keep_same_original_in_both_orders() {
    for native_first in [false, true] {
        let f = Fixture::new();
        let (e, c) = enter(&f, flow::Kind::AndroidAccess);
        prepared(&e);
        c.returned(true);
        let start = start(&f, &e);
        if native_first {
            e.native(finished(&f));
            assert!(e.claim_history().unwrap().is_none());
        }
        start.returned(true);
        if !native_first {
            assert!(e.pending());
            e.native(finished(&f));
        }
        let h = e.claim_history().unwrap().unwrap();
        assert_eq!(e.status().unwrap().phase, flow::Phase::Finishing);
        assert!(e.status().unwrap().result.is_none());
        h.returned(Ok(())).unwrap();
        let s = e.status().unwrap();
        assert_eq!(s.phase, flow::Phase::Final);
        assert_eq!(s.settlement, Settlement::Settled);
        assert_eq!(s.result, finished(&f).result);
        assert!(!e.pending());
        let a = f.inbox.preparation_access().unwrap();
        a.validate().unwrap();
        assert!(a.consumed && !a.enabled && !a.pending);
    }
}
#[test]
fn prepare_progress_history_is_not_terminal_ack_and_failed_claim_is_retained() {
    for fail in [false, true] {
        let f = Fixture::new();
        let (e, c) = enter(&f, flow::Kind::AndroidAccess);
        prepared(&e);
        c.returned(true);
        let progress = e.claim_history().unwrap().unwrap();
        let start = start(&f, &e);
        e.native(finished(&f));
        start.returned(true);
        progress.returned(Ok(())).unwrap();
        assert!(e.pending());
        let terminal = e.claim_history().unwrap().unwrap();
        if fail {
            assert!(terminal.returned(Err(Error::Unavailable)).is_err());
            e.native(finished(&f));
            assert_eq!(e.status().unwrap().phase, flow::Phase::Unknown);
            assert!(e.claim_history().unwrap().is_none());
            assert!(e.pending());
        } else {
            terminal.returned(Ok(())).unwrap();
            assert!(!e.pending());
        }
    }
}
#[test]
fn prepare_wrong_phase_ids_retries_and_dropped_original_call_never_reexecute() {
    let f = Fixture::new();
    let (e, c) = enter(&f, flow::Kind::AndroidAccess);
    assert!(f.inbox.submit(f.input(), Instant::now()).is_err());
    assert_eq!(
        f.inbox
            .submit_preparation(f.input(), Instant::now())
            .unwrap()
            .origin,
        *e.origin()
    );
    assert!(e.submit_start(f.input(), Instant::now()).is_err());
    prepared(&e);
    c.returned(true);
    let start = start(&f, &e);
    let mut input = f.input();
    input.grant_id = id('6');
    input.review_id = id('a');
    assert!(e.submit_start(input.clone(), Instant::now()).is_ok());
    assert!(f.inbox.claim_preparation().unwrap().is_none());
    input.grant_id = id('7');
    assert!(e.submit_start(input, Instant::now()).is_err());
    drop(start);
    e.native(finished(&f));
    assert_eq!(e.status().unwrap().phase, flow::Phase::Unknown);
    assert!(e.pending());
    assert!(e.claim_history().unwrap().is_none());
}
#[test]
fn prepare_stop_before_start_is_not_retirement_and_original_read_tightens_first_f() {
    let f = Fixture::new();
    let (e, c) = enter(&f, flow::Kind::AndroidAccess);
    prepared(&e);
    c.returned(true);
    let early = Instant::now();
    let later = early + Duration::from_secs(1);
    e.cancel(p::Reason::UserCancelled, later);
    assert_eq!(e.status().unwrap().phase, flow::Phase::Stopping);
    assert!(e.pending());
    assert!(e.allow_start(&r(), id('6')).is_err());
    e.scope.read.revoke(early);
    assert!(e.current(false).is_err());
    assert_eq!(
        e.scope.control.first().unwrap(),
        Some((p::Reason::PermissionRevoked, early))
    );
    let mut n = finished(&f);
    n.state = OperationState::Cancelled;
    n.reason = p::Reason::PermissionRevoked;
    n.outcome = Some(p::Outcome::Cancelled);
    n.result = None;
    e.native(n);
    assert!(e.pending());
    e.claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    assert_eq!(e.status().unwrap().outcome, Some(p::Outcome::Cancelled));
    assert!(!e.pending());
}
#[test]
fn prepare_and_original_rows_share_all_32_slots_and_keep_last_failed_history() {
    let f = Fixture::new();
    for n in 0..p::REQUEST_LIMIT {
        let mut input = f.input();
        input.origin.request_id = Id::parse(&format!("{:032x}", n + 1)).unwrap();
        if n % 2 == 0 {
            f.inbox
                .allow(Fixture::scope(&f.doc, &f.witness), id('3'))
                .unwrap();
            f.inbox.submit(input.clone(), Instant::now()).unwrap();
            let c = f.inbox.claim().unwrap().unwrap();
            let e = c.entry().clone();
            c.returned();
            e.native(f.finished());
            e.claim_history()
                .unwrap()
                .unwrap()
                .returned(Ok(()))
                .unwrap();
        } else {
            f.inbox
                .allow_preparation(scope(&f, flow::Kind::PairedVersions), id('3'))
                .unwrap();
            f.inbox
                .submit_preparation(input.clone(), Instant::now())
                .unwrap();
            let e = f.inbox.preparation_entry(&input.origin).unwrap();
            let c = f.inbox.claim_preparation().unwrap().unwrap();
            prepared(&e);
            c.returned(true);
            e.allow_start(&r(), id('6')).unwrap();
            let mut start_input = input.clone();
            start_input.grant_id = id('6');
            start_input.review_id = id('a');
            e.submit_start(start_input, Instant::now()).unwrap();
            let c = f.inbox.claim_preparation().unwrap().unwrap();
            c.returned(true);
            let mut ndata = finished(&f);
            ndata.result = Some(flow::Report::CurrentVersions {
                inventory: inventory::Inventory::Both {
                    android: android(),
                    ios: ios(),
                },
            });
            e.native(ndata);
            let h = e.claim_history().unwrap().unwrap();
            if n + 1 == p::REQUEST_LIMIT {
                assert!(h.returned(Err(Error::Unavailable)).is_err());
                assert!(e.pending());
            } else {
                h.returned(Ok(())).unwrap();
                assert!(!e.pending());
            }
        }
    }
    assert_eq!(f.inbox.entries().unwrap().len(), 16);
    assert_eq!(f.inbox.preparation_entries().unwrap().len(), 16);
    assert_eq!(
        f.inbox
            .catalogue_requests(&id('2'), &id('1'))
            .unwrap()
            .len(),
        32
    );
    assert!(f.inbox.can_allow().is_err());
    assert!(f
        .inbox
        .allow_preparation(scope(&f, flow::Kind::AndroidAccess), id('8'))
        .is_err());
    // Old completed rows remain original read-only values despite current Unknown.
    let old = p::Query {
        project_id: id('1'),
        service_instance: id('2'),
        request_id: Id::parse(&format!("{:032x}", 1)).unwrap(),
    };
    assert_eq!(
        f.inbox.query(&old, false).unwrap().state,
        p::State::Complete
    );
}
#[test]
fn prepare_inventory_is_closed_owned_data_and_excess_capacity_is_refused() {
    let f = Fixture::new();
    let (e, c) = enter(&f, flow::Kind::PairedVersions);
    prepared(&e);
    c.returned(true);
    start(&f, &e).returned(true);
    let mut n = finished(&f);
    n.result = Some(flow::Report::CurrentVersions {
        inventory: inventory::Inventory::Both {
            android: android(),
            ios: ios(),
        },
    });
    e.native(n);
    e.claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    let mut public = e.status().unwrap();
    let original = public.clone();
    if let Some(flow::Report::CurrentVersions {
        inventory: inventory::Inventory::Both { android, ios },
    }) = public.result.as_mut()
    {
        android.revision = None;
        ios.marketing_version = Some("99.0".into());
    }
    assert_eq!(e.status().unwrap(), original);
    assert!(public.validate().is_err());
    let mut wire = serde_json::to_value(&original).unwrap();
    wire["result"]["inventory"]["android"]
        .as_object_mut()
        .unwrap()
        .remove("maxBuild");
    assert!(serde_json::from_value::<flow::Status>(wire).is_err());
    let f = Fixture::new();
    let mut bad = scope(&f, flow::Kind::AndroidAccess);
    Arc::get_mut(&mut bad).unwrap().root.reserve(8192);
    assert!(f.inbox.allow_preparation(bad, id('3')).is_err());
    let (e, c) = enter(&f, flow::Kind::PairedVersions);
    prepared(&e);
    c.returned(true);
    start(&f, &e).returned(true);
    let mut a = android();
    a.coverage.reserve(8192);
    assert!(a.valid());
    let mut n = finished(&f);
    n.result = Some(flow::Report::CurrentVersions {
        inventory: inventory::Inventory::Both {
            android: a,
            ios: ios(),
        },
    });
    e.native(n);
    assert_eq!(e.status().unwrap().phase, flow::Phase::Unknown);
}
#[test]
fn prepare_complete_requires_actual_start_claim_and_original_status_is_correlated() {
    let f = Fixture::new();
    let (e, c) = enter(&f, flow::Kind::AndroidAccess);
    prepared(&e);
    c.returned(true);
    e.native(finished(&f));
    assert_eq!(e.status().unwrap().phase, flow::Phase::Unknown);
    let a = f.inbox.preparation_access().unwrap();
    a.validate().unwrap();
    assert!(a.unknown && a.pending && !a.enabled);
    let mut false_access = a.clone();
    false_access.status.as_mut().unwrap().origin.request_id = id('9');
    assert!(false_access.validate().is_err());
    let mut v = serde_json::to_value(&a).unwrap();
    v.as_object_mut().unwrap().remove("status");
    assert!(serde_json::from_value::<flow::Access>(v).is_err());
}
#[test]
fn prepare_complete_2mib_quote_includes_mixed_rows_native_history_and_all_copies() {
    use std::mem::size_of;
    // Complete potential capacity, not actual row count. Id is copied bounded
    // 32-byte DATA. Entry includes its inline row and both Native enum cells.
    let scope_cells =
        size_of::<queue::PrepareEntry>() + size_of::<queue::Scope>() + size_of::<Control>();
    let scope_heap = 4096 + 64 + 3 * 64 + 36 + 64 + 32 * 24 + 512; // paths, scalars, all IDs, Arc/watch bookkeeping.
    assert!(
        scope_cells + scope_heap <= 8192,
        "{scope_cells}+{scope_heap}"
    );
    let report_heap = 2 * (64 + 32 + 64 + 64)
        + 16 * size_of::<p::Finding>()
        + 8 * size_of::<p::Limitation>()
        + 36
        + 3 * 64;
    assert!(size_of::<queue::Native>() + report_heap <= 8192);
    assert!(
        size_of::<flow::Status>() + size_of::<flow::Access>() + scope_heap + report_heap
            <= 2 * p::STATUS_LIMIT
    );
    let rows = p::REQUEST_LIMIT.checked_mul(3 * 8192).unwrap();
    let ipc = 8usize
        .checked_mul(crate::service_protocol::REQUEST_BYTES + 2 * p::STATUS_LIMIT)
        .unwrap();
    let conversion = 2 * 65536 + 32768;
    let grant_and_fixed = 128 * 1024;
    // Two bounded native RAW decode/value copies plus the original value
    // during serde selection/validation; never borrow the eight IPC slots.
    let gui_decode = 3 * flow::RAW_NODES * 512 + flow::RAW_LIMIT;
    let complete = rows
        .checked_add(ipc)
        .unwrap()
        .checked_add(conversion)
        .unwrap()
        .checked_add(grant_and_fixed)
        .unwrap()
        .checked_add(gui_decode)
        .unwrap();
    assert!(complete <= p::DOCUMENT_BACKING);
    assert_eq!(p::DOCUMENT_BACKING, 2 * 1024 * 1024);
    assert!(usize::MAX.checked_add(complete).is_none());
    let original_limit = crate::service_request_catalogue::ADDITIONAL_LIMIT;
    assert!(original_limit >= p::REQUEST_LIMIT); // no added queue/catalogue allowance.
}
