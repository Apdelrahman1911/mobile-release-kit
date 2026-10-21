//! Original in-memory Build Entry/Claim/READ/history methods. These DATA tests
//! run no native recovery and do not manufacture a native observation/receipt.
use super::*;
use crate::agent_ios_archive::recovery;
use crate::service_version_reserve_requests::ReadPermission;

fn selected(f: &Fixture, read: Arc<ReadPermission>) -> Arc<NativeScope> {
    let (changes, _) = tokio::sync::watch::channel(0);
    Arc::new(NativeScope {
        project_id: f.point.project_id.clone(),
        runtime_id: f.point.runtime_id.clone(),
        root: f.point.root.clone(),
        device: f.point.device,
        inode: f.point.inode,
        registration: 1,
        input_revision: 2,
        document: Arc::downgrade(&f.document),
        observation_revision: f.point.revision,
        review: recovery::Review {
            mode: recovery::Mode::LocalIosRecovery,
            recovery: recovery::Intent::Inspect,
        }
        .into(),
        read: Some(read),
        input: NativeInput::Recovery,
        changes,
    })
}
fn read() -> Arc<ReadPermission> {
    Arc::new(ReadPermission::new(
        Instant::now() + Duration::from_secs(600),
    ))
}
fn queued(f: &Fixture, scope: Arc<NativeScope>, n: u8) -> (Prepare, Arc<NativeLink>, Claim) {
    f.inbox.allow(scope.clone()).unwrap();
    let input = f.request(n);
    f.inbox
        .prepare_ios_read(input.clone(), &f.point, scope.read.as_ref().unwrap())
        .unwrap();
    let claim = f.inbox.claim(Family::IosArchive).unwrap().unwrap();
    let link = claim
        .entry()
        .bind(
            Family::IosArchive,
            id(n + 40),
            id(n + 80),
            1,
            Instant::now() + Duration::from_secs(300),
        )
        .unwrap();
    (input, link, claim)
}
fn start(input: &Prepare, link: &NativeLink) -> Start {
    let original = link.entry().original.get().unwrap();
    Start {
        origin: input.query(),
        operation_id: original.operation.clone(),
        owner_generation: original.generation.clone(),
    }
}
fn completed(link: &NativeLink) -> recovery::Operation {
    let Operation::IosRecovery(mut op) = link
        .entry()
        .latest
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .as_ref()
        .clone()
    else {
        panic!("recovery fixture")
    };
    op.status_revision += 1;
    op.state = OperationState::Succeeded;
    op.settlement = Settlement::Settled;
    op.outcome = Some(android::Outcome::Complete);
    op.reason = recovery::Reason::None;
    op.stage = Some(recovery::Stage::DisposingWork);
    op.report = Some(recovery::Report {
        schema_version: 1,
        scope: recovery::Mode::LocalIosRecovery,
        limitations: recovery::LIMITATIONS,
        account: Some(recovery::Row {
            status: recovery::State::Pending,
            session: Some("c".repeat(32)),
            next: recovery::Next::Ordinary,
        }),
        project: Some(recovery::Row {
            status: recovery::State::CleanupOnly,
            session: Some("d".repeat(32)),
            next: recovery::Next::Ordinary,
        }),
    });
    op
}
#[test]
fn recovery_configless_scope_is_closed_and_same_read_is_required_before_prepare() {
    let mut f = Fixture::new();
    let saved = f.scope(Family::IosArchive);
    f.point.config = None;
    let read = read();
    let scope = selected(&f, read.clone());
    assert!(scope.valid() && scope.matches(&f.point) && scope.matches_read(&read));
    assert!(!saved.matches(&f.point));
    assert_eq!(scope.saved_inputs(), None);
    let mut wrong = selected(&f, read.clone());
    Arc::get_mut(&mut wrong).unwrap().input = NativeInput::Saved {
        draft_revision: 1,
        baseline_generation: 1,
    };
    assert!(!wrong.valid() && !wrong.matches(&f.point));
    let mut wrong = selected(&f, read.clone());
    Arc::get_mut(&mut wrong).unwrap().review = saved.review.clone();
    assert!(!wrong.valid() && !wrong.matches(&f.point));
    let mut missing = selected(&f, read.clone());
    Arc::get_mut(&mut missing).unwrap().read = None;
    assert!(!missing.valid());
    f.inbox.allow(scope.clone()).unwrap();
    assert!(f
        .inbox
        .prepare(Family::IosArchive, f.request(3), &f.point)
        .is_err());
    assert!(f
        .inbox
        .prepare_ios_read(
            f.request(3),
            &f.point,
            &Arc::new(ReadPermission::new(read.end()))
        )
        .is_err());
    assert!(f.inbox.entries(Family::IosArchive).unwrap().is_empty());
    f.inbox
        .prepare_ios_read(f.request(3), &f.point, &read)
        .unwrap();
    assert_eq!(f.inbox.entries(Family::IosArchive).unwrap().len(), 1);
}
#[test]
fn recovery_prepare_return_history_and_fresh_root_revision_gate_only_first_start() {
    let mut f = Fixture::new();
    f.point.config = None;
    let read = read();
    let (input, link, preparing) = queued(&f, selected(&f, read.clone()), 3);
    let start = start(&input, &link);
    assert!(link.entry().claim_history().unwrap().is_none());
    assert!(f.inbox.start_ios_read(&start, &f.point, &read).is_err());
    preparing.returned(true);
    assert!(f.inbox.start_ios_read(&start, &f.point, &read).is_err());
    acknowledge(&link);
    f.point.revision += 1;
    assert!(f.inbox.start_ios_read(&start, &f.point, &read).is_err());
    f.point.revision -= 1;
    f.point.root.push("foreign");
    assert!(f.inbox.start_ios_read(&start, &f.point, &read).is_err());
    f.point.root.pop();
    assert!(f
        .inbox
        .start_ios_read(&start, &f.point, &Arc::new(ReadPermission::new(read.end())))
        .is_err());
    assert!(f.inbox.start(Family::IosArchive, &start).is_err());
    f.inbox.start_ios_read(&start, &f.point, &read).unwrap();
    let starting = f.inbox.claim(Family::IosArchive).unwrap().unwrap();
    link.consume_start(Family::IosArchive).unwrap();
    starting.returned(true);
    // An actual Start consumes the shared observation. Repeating the same IDs
    // observes the original, never needs/creates a fresh point or second claim.
    f.point.fresh = false;
    assert_eq!(
        f.inbox
            .start_ios_read(&start, &f.point, &read)
            .unwrap()
            .start_state,
        StartState::Consumed
    );
    assert!(f.inbox.claim(Family::IosArchive).unwrap().is_none());
}
#[test]
fn recovery_native_data_and_original_callers_both_wait_for_exact_history_ack() {
    for native_first in [false, true] {
        let f = Fixture::new();
        let read = read();
        let scope = selected(&f, read.clone());
        let (input, link, preparing) = queued(&f, scope, 3);
        preparing.returned(true);
        acknowledge(&link);
        f.inbox
            .start_ios_read(&start(&input, &link), &f.point, &read)
            .unwrap();
        let starting = f.inbox.claim(Family::IosArchive).unwrap().unwrap();
        link.consume_start(Family::IosArchive).unwrap();
        if native_first {
            link.publish(completed(&link)).unwrap();
            assert!(link.entry().claim_history().unwrap().is_none());
            assert_eq!(
                link.entry().status().unwrap().operation.unwrap().state(),
                OperationState::Prepared
            );
            starting.returned(true);
        } else {
            starting.returned(true);
            link.publish(completed(&link)).unwrap();
        }
        let (_, original) = link.entry().claim_history().unwrap().unwrap();
        assert!(f.inbox.allow(selected(&f, read.clone())).is_err());
        assert_ne!(
            link.entry()
                .status()
                .unwrap()
                .operation
                .unwrap()
                .settlement(),
            Settlement::Settled
        );
        link.entry()
            .history_returned(original.status_revision(), Ok(()))
            .unwrap();
        let final_value = recovery::Status::try_from(link.entry().status().unwrap()).unwrap();
        assert!(final_value.history_available);
        assert_eq!(
            final_value
                .operation
                .unwrap()
                .report
                .unwrap()
                .account
                .unwrap()
                .status,
            recovery::State::Pending
        );
        f.inbox.allow(selected(&f, read)).unwrap(); // complete Inspect was NOT restored state
    }
}
#[test]
fn recovery_lost_caller_or_history_is_absorbing_and_earliest_read_stop_survives_consume() {
    for lost_prepare in [false, true] {
        let f = Fixture::new();
        let read = read();
        let (input, link, preparing) = queued(&f, selected(&f, read.clone()), 3);
        if lost_prepare {
            drop(preparing);
        } else {
            preparing.returned(true);
            acknowledge(&link);
            f.inbox
                .start_ios_read(&start(&input, &link), &f.point, &read)
                .unwrap();
            let starting = f.inbox.claim(Family::IosArchive).unwrap().unwrap();
            link.consume_start(Family::IosArchive).unwrap();
            drop(starting);
        }
        link.publish(completed(&link)).unwrap();
        let status = link.entry().status().unwrap();
        assert_eq!(status.request_state, RequestState::AdmissionUnknown);
        assert!(status.operation.is_none() && !status.history_available);
        assert!(f.inbox.allow(selected(&f, read)).is_err());
    }
    let f = Fixture::new();
    let read = read();
    let first = Instant::now();
    let (input, link, preparing) = queued(&f, selected(&f, read.clone()), 3);
    preparing.returned(true);
    acknowledge(&link);
    f.inbox
        .start_ios_read(&start(&input, &link), &f.point, &read)
        .unwrap();
    let starting = f.inbox.claim(Family::IosArchive).unwrap().unwrap();
    link.consume_start(Family::IosArchive).unwrap();
    starting.returned(true);
    link.entry().cancel();
    read.revoke(first);
    assert_eq!(link.entry().stop_at(Instant::now()), Some(first));
    assert_eq!(link.entry().control_poll(), Some(Duration::from_millis(5)));
    assert_eq!(link.entry().read_end(), Some(read.end()));
    assert!(!link
        .entry()
        .scope()
        .matches_read(&Arc::new(ReadPermission::new(read.end()))));
    let mut stopped = completed(&link);
    stopped.state = OperationState::Cancelled;
    stopped.outcome = Some(android::Outcome::Cancelled);
    stopped.reason = recovery::Reason::Cancelled;
    stopped.report = None;
    link.publish(stopped).unwrap();
    let (_, original) = link.entry().claim_history().unwrap().unwrap();
    assert!(link
        .entry()
        .history_returned(original.status_revision(), Err(Error::StateUnknown))
        .is_err());
    assert!(link.entry().status().unwrap().operation.is_none());
    assert!(link
        .entry()
        .history_returned(original.status_revision(), Ok(()))
        .is_err());
}
#[test]
fn recovery_and_saved_rows_share_original32_and_bounded_full_reports() {
    let f = Fixture::new();
    for n in 0..LIMIT {
        let link = if n % 2 == 0 {
            let read = read();
            let (input, link, preparing) = queued(&f, selected(&f, read.clone()), (n + 10) as u8);
            preparing.returned(true);
            acknowledge(&link);
            f.inbox
                .start_ios_read(&start(&input, &link), &f.point, &read)
                .unwrap();
            let starting = f.inbox.claim(Family::IosArchive).unwrap().unwrap();
            link.consume_start(Family::IosArchive).unwrap();
            starting.returned(true);
            link.publish(completed(&link)).unwrap();
            link
        } else {
            let (_, link) = memory_bound(&f, &f.scope(Family::AndroidInspect), n);
            link.publish(terminal(&link)).unwrap();
            link
        };
        acknowledge(&link);
        assert!(link.entry().status().unwrap().history_available);
    }
    assert_eq!(
        f.inbox.entries(Family::IosArchive).unwrap().len()
            + f.inbox.entries(Family::AndroidInspect).unwrap().len(),
        LIMIT
    );
    assert_eq!(
        f.inbox.allow(selected(&f, read())).unwrap_err(),
        Error::Busy
    );
    assert!(ROW_CEILING <= ROW_BACKING && ANCILLARY_CEILING <= ANCILLARY_BACKING);
    assert_eq!(DOCUMENT_BACKING, 688_128);
}
