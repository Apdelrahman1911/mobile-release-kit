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
        candidate: kind.prepares_intent().then(|| p::Candidate {
            operation_id: "12345678-1234-4234-8234-123456789abc".into(),
            sha256: "e".repeat(64),
        }),
        later: kind.stage().map(|(_, stage)| flow::StageSelection {
            stage,
            predecessor_operation_id: if stage == flow::Stage::ExternalTesting {
                "12345678-1234-4234-8234-123456789abc"
            } else {
                "32345678-1234-4234-8234-123456789abc"
            }.into(),
            predecessor_receipt_sha256: "f".repeat(64),
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
            let kind = if (n / 2) % 5 == 0 {
                flow::Kind::PairedVersions
            } else {
                STAGE_KINDS[(n / 2) % 5 - 1]
            };
            f.inbox
                .allow_preparation(scope(&f, kind), id('3'))
                .unwrap();
            f.inbox
                .submit_preparation(input.clone(), Instant::now())
                .unwrap();
            let e = f.inbox.preparation_entry(&input.origin).unwrap();
            let c = f.inbox.claim_preparation().unwrap().unwrap();
            let review = if kind.stage().is_some() { stage_review() } else { r() };
            e.attach(review.clone(), e.scope.expires).unwrap();
            e.installed().unwrap();
            e.native(queue::Native {
                operation: review.operation.clone(), state: OperationState::Prepared,
                reason: p::Reason::None, outcome: None, result: None, retired: false,
            });
            c.returned(true);
            e.allow_start(&review, id('6')).unwrap();
            let mut start_input = input.clone();
            start_input.grant_id = id('6');
            start_input.review_id = review.review_id.clone();
            e.submit_start(start_input, Instant::now()).unwrap();
            let c = f.inbox.claim_preparation().unwrap().unwrap();
            c.returned(true);
            let mut ndata = finished(&f);
            ndata.operation.operation_id = review.operation.operation_id;
            ndata.result = Some(if kind.stage().is_some() { stage_report(&e.scope.selection) } else { flow::Report::CurrentVersions {
                inventory: inventory::Inventory::Both {
                    android: android(),
                    ios: ios(),
                },
            }});
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
    let scope_heap = 4096 + 64 + 3 * 64 + 36 + 64 + 36 + 64 + 32 * 24 + 512; // includes the new bounded predecessor tuple, never a second row.
    assert!(
        scope_cells + scope_heap <= 8192,
        "{scope_cells}+{scope_heap}"
    );
    let original_report_heap = 2 * (64 + 32 + 64 + 64)
        + 16 * size_of::<p::Finding>()
        + 8 * size_of::<p::Limitation>()
        + 36
        + 3 * 64;
    // Three UUIDs, four hashes and the largest actual UTF-8 destination.
    // Six limitations are inline fixed DATA, no Vec capacity to discard.
    let stage_report_heap = 3 * 36 + 4 * 64 + 400 + 9;
    let report_heap = original_report_heap.max(stage_report_heap);
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

const STAGE_KINDS: [flow::Kind; 4] = [
    flow::Kind::AndroidExternalTesting, flow::Kind::IosExternalTesting,
    flow::Kind::AndroidProductionSubmit, flow::Kind::IosProductionSubmit,
];
fn stage_review() -> flow::Review {
    let operation = Id::parse("22345678123442348234123456789abc").unwrap();
    flow::Review { review_id: operation.clone(), operation: p::Operation {
        operation_id: operation, owner_generation: id('b'), status_revision: 3,
    }}
}
fn stage_report(s: &flow::Selection) -> flow::Report {
    let (platform, stage) = s.kind.stage().unwrap();
    let candidate = s.candidate.as_ref().unwrap();
    let later = s.later.as_ref().unwrap();
    flow::Report::StagePrepare { report: flow::StageReport {
        platform, stage, operation_id: "22345678-1234-4234-8234-123456789abc".into(),
        head_sequence: stage.prepared_head(), candidate_operation_id: candidate.operation_id.clone(),
        candidate_sha256: candidate.sha256.clone(), predecessor_operation_id: later.predecessor_operation_id.clone(),
        predecessor_receipt_sha256: later.predecessor_receipt_sha256.clone(),
        intent_sha256: "a".repeat(64), store_precondition_sha256: "b".repeat(64),
        destination: match (platform, stage) {
            (p::Platform::Android, flow::Stage::ExternalTesting) => flow::StageDestination::Android { channel: "🧪".repeat(100), release_status: "completed".into() },
            (p::Platform::Android, flow::Stage::ProductionSubmit) => flow::StageDestination::Android { channel: "production".into(), release_status: "draft".into() },
            (p::Platform::Ios, flow::Stage::ExternalTesting) => flow::StageDestination::IosExternal { channel: "testflight-external".into() },
            (p::Platform::Ios, flow::Stage::ProductionSubmit) => flow::StageDestination::IosProduction { channel: "app-store-review".into(), automatic_release: false },
        },
        limitations: flow::STAGE_LIMITATIONS,
    }}
}
#[test]
fn later_prepare_preserves_seven_wire_shapes_and_requires_exact_kind_and_present_tuple() {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct OriginalSelection<'a> {
        kind: flow::Kind, saved_config: &'a p::Content, saved_version: &'a p::Version, candidate: &'a Option<p::Candidate>,
    }
    let mut consents = std::collections::BTreeSet::new();
    for kind in [flow::Kind::AndroidAccess, flow::Kind::IosAccess, flow::Kind::AndroidCandidate, flow::Kind::IosCandidate,
        flow::Kind::AndroidVersions, flow::Kind::IosVersions, flow::Kind::PairedVersions] {
        let s = selected(kind);
        assert!(s.valid());
        assert_eq!(serde_json::to_vec(&s).unwrap(), serde_json::to_vec(&OriginalSelection {
            kind, saved_config: &s.saved_config, saved_version: &s.saved_version, candidate: &s.candidate,
        }).unwrap());
        let mut explicit_null = serde_json::to_value(&s).unwrap();
        explicit_null["later"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<flow::Selection>(explicit_null).is_err());
        let mut hybrid = s;
        hybrid.later = selected(STAGE_KINDS[0]).later;
        assert!(!hybrid.valid());
        consents.insert(kind.consent());
    }
    for kind in STAGE_KINDS {
        let s = selected(kind);
        assert!(s.valid() && s.bounded_capacity());
        assert!(!kind.candidate() && kind.prepares_intent());
        assert!(flow::ordinary_review(&s, &stage_review()).is_none());
        assert!(consents.insert(kind.consent())); // no candidate/access/other-stage consent reuse.
        let encoded = serde_json::to_value(&s).unwrap();
        assert_eq!(serde_json::from_value::<flow::Selection>(encoded.clone()).unwrap(), s);
        let mut absent = encoded.clone();
        absent.as_object_mut().unwrap().remove("later");
        assert!(!serde_json::from_value::<flow::Selection>(absent).unwrap().valid());
        let mut null = encoded;
        null["later"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<flow::Selection>(null).is_err());
        for wrong in [flow::Kind::AndroidCandidate, flow::Kind::IosVersions] {
            let mut other = s.clone(); other.kind = wrong; assert!(!other.valid());
        }
        let mut wrong_stage = s.clone();
        wrong_stage.later.as_mut().unwrap().stage = if s.later.as_ref().unwrap().stage == flow::Stage::ExternalTesting {
            flow::Stage::ProductionSubmit
        } else { flow::Stage::ExternalTesting };
        assert!(!wrong_stage.valid());
    }
}
#[test]
fn later_prepare_report_stays_owned_and_waits_for_original_start_and_history() {
    for kind in STAGE_KINDS {
        let f = Fixture::new();
        let (e, caller) = enter(&f, kind);
        let review = stage_review();
        e.attach(review.clone(), e.scope.expires).unwrap(); e.installed().unwrap();
        assert!(e.allow_start(&review, id('6')).is_err());
        caller.returned(true);
        e.allow_start(&review, id('6')).unwrap();
        let mut input = f.input(); input.grant_id = id('6'); input.review_id = review.review_id.clone();
        e.submit_start(input, Instant::now()).unwrap();
        let start = f.inbox.claim_preparation().unwrap().unwrap();
        let report = stage_report(&e.scope.selection);
        assert!(report.valid_for(&e.scope.selection, &review) && report.bounded_capacity());
        let mut bad_id = review.clone(); bad_id.operation.operation_id = id('a');
        assert!(!report.valid_for(&e.scope.selection, &bad_id));
        let native = queue::Native { operation: review.operation.clone(), state: OperationState::Succeeded,
            reason: p::Reason::None, outcome: Some(p::Outcome::Complete), result: Some(report), retired: true };
        // Same real Entry methods with inert return DATA, not a physical native receipt.
        e.native(native);
        assert!(e.claim_history().unwrap().is_none() && e.status().unwrap().result.is_none());
        start.returned(true);
        let history = e.claim_history().unwrap().unwrap();
        assert_eq!(e.status().unwrap().phase, flow::Phase::Finishing);
        history.returned(Ok(())).unwrap();
        let original = e.status().unwrap(); original.validate().unwrap();
        assert_eq!(original.phase, flow::Phase::Final);
        let bytes = serde_json::to_vec(&original).unwrap(); assert!(bytes.len() <= flow::STATUS_LIMIT);
        assert_eq!(serde_json::from_slice::<flow::Status>(&bytes).unwrap(), original);
        let mut changed = original.clone();
        if let Some(flow::Report::StagePrepare { report }) = &mut changed.result {
            report.predecessor_receipt_sha256 = "9".repeat(64);
        }
        assert!(changed.validate().is_err()); assert_eq!(e.status().unwrap(), original);
        let mut other = selected(flow::Kind::AndroidCandidate);
        other.candidate = e.scope.selection.candidate.clone();
        assert!(!original.result.as_ref().unwrap().valid_for(&other, &review));
    }
}
#[test]
fn later_prepare_excess_capacity_and_wrong_terminal_tuple_never_gain_success() {
    for excessive in [false, true] {
        let f = Fixture::new();
        let (e, caller) = enter(&f, flow::Kind::AndroidExternalTesting);
        let review = stage_review();
        e.attach(review.clone(), e.scope.expires).unwrap(); e.installed().unwrap(); caller.returned(true);
        e.allow_start(&review, id('6')).unwrap();
        let mut input = f.input(); input.grant_id = id('6'); input.review_id = review.review_id.clone();
        e.submit_start(input, Instant::now()).unwrap(); f.inbox.claim_preparation().unwrap().unwrap().returned(true);
        let mut report = stage_report(&e.scope.selection);
        let flow::Report::StagePrepare { report: stage } = &mut report else { unreachable!() };
        if excessive { stage.intent_sha256.reserve(8192); } else { stage.head_sequence = 8; }
        assert_eq!(report.valid_for(&e.scope.selection, &review), excessive);
        e.native(queue::Native { operation: review.operation, state: OperationState::Succeeded,
            reason: p::Reason::None, outcome: Some(p::Outcome::Complete), result: Some(report), retired: true });
        assert_eq!(e.status().unwrap().phase, flow::Phase::Unknown);
        assert!(e.pending() && e.status().unwrap().result.is_none() && e.claim_history().unwrap().is_none());
    }
    let f = Fixture::new();
    let mut over = scope(&f, flow::Kind::IosProductionSubmit);
    Arc::get_mut(&mut over).unwrap().selection.later.as_mut().unwrap().predecessor_operation_id.reserve(8192);
    assert!(f.inbox.allow_preparation(over, id('3')).is_err());
}
