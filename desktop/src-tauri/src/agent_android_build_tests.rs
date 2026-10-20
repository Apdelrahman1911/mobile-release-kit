//! Inert finite authorization/transport tests, not native build qualification.
use super::*;
fn id(n: u8) -> Id {
    Id::parse(&format!("{n:032x}")).unwrap()
}
pub(super) fn review() -> Review {
    Review {
        mode: Mode::SavedAndroidBuildStructureAndVersion,
        saved_config: Config {
            bytes: 100,
            sha256: "a".repeat(64),
        },
        saved_version: Version {
            bytes: 32,
            sha256: "b".repeat(64),
            name: "1.2.3".into(),
            build: 7,
        },
        tools: Tools {
            instance: id(4),
            catalog_generation: 2,
            record_sha256: "c".repeat(64),
        },
    }
}
struct Fixture {
    inbox: Arc<Inbox>,
    scope: Arc<NativeScope>,
    point: crate::agent_local_checks::SavedPoint,
    _document: Arc<()>,
}
impl Fixture {
    fn new() -> Self {
        let document = Arc::new(());
        let (changes, _) = tokio::sync::watch::channel(0);
        let scope = Arc::new(NativeScope {
            project_id: id(2),
            runtime_id: "project-1".into(),
            root: "/synthetic/project".into(),
            device: 3,
            inode: 4,
            registration: 1,
            input_revision: 2,
            document: Arc::downgrade(&document),
            observation_revision: 5,
            review: review().into(),
            draft_revision: 1,
            baseline_generation: 2,
            changes,
        });
        let point = crate::agent_local_checks::SavedPoint {
            project_id: scope.project_id.clone(),
            runtime_id: scope.runtime_id.clone(),
            root: scope.root.clone(),
            device: scope.device,
            inode: scope.inode,
            revision: 5,
            fresh: true,
            config: Some(scope.review.config().clone()),
        };
        Self {
            inbox: Arc::new(Inbox::new(id(1))),
            scope,
            point,
            _document: document,
        }
    }
    fn request(&self, n: u8) -> Prepare {
        Prepare {
            service_instance: id(1),
            project_id: id(2),
            request_id: id(n),
            expected_observation_revision: 5,
        }
    }
    fn bound(&self) -> (Prepare, Arc<NativeLink>) {
        self.inbox.allow(self.scope.clone()).unwrap();
        let input = self.request(3);
        self.inbox.prepare(FAMILY,input.clone(), &self.point).unwrap();
        let claim = self.inbox.claim(FAMILY).unwrap().unwrap();
        assert!(matches!(claim.kind(), ClaimKind::Prepare));
        let link = claim
            .entry()
            .bind(FAMILY,id(5), id(6), 1, Instant::now() + Duration::from_secs(300))
            .unwrap();
        claim.returned(true);
        (input, link)
    }
}
fn start(input: &Prepare) -> Start {
    Start {
        origin: input.query(),
        operation_id: id(5),
        owner_generation: id(6),
    }
}
fn final_cancel(link: &NativeLink, revision: u32) -> Operation {
    let mut op = link.entry().status().unwrap().operation.unwrap().android().clone();
    op.status_revision = revision;
    op.state = OperationState::Cancelled;
    op.settlement = Settlement::Settled;
    op.outcome = Some(Outcome::Cancelled);
    op.reason = Reason::Cancelled;
    op
}
#[test]
fn named_grant_and_exact_saved_point_required_before_any_prepare() {
    let mut f = Fixture::new();
    let input = f.request(3);
    assert_eq!(
        f.inbox.prepare(FAMILY,input.clone(), &f.point).unwrap_err(),
        Error::AccessDenied
    );
    f.inbox.allow(f.scope.clone()).unwrap();
    f.point.fresh = false;
    assert_eq!(
        f.inbox.prepare(FAMILY,input.clone(), &f.point).unwrap_err(),
        Error::Conflict
    );
    f.point.fresh = true;
    f.point.runtime_id = "project-2".into();
    assert_eq!(
        f.inbox.prepare(FAMILY,input.clone(), &f.point).unwrap_err(),
        Error::Conflict
    );
    f.point.runtime_id = "project-1".into();
    f.point.config.as_mut().unwrap().sha256 = "d".repeat(64);
    assert_eq!(
        f.inbox.prepare(FAMILY,input, &f.point).unwrap_err(),
        Error::Conflict
    );
    assert!(f.inbox.access(FAMILY).unwrap().enabled);
    assert!(f.inbox.claim(FAMILY).unwrap().is_none());
}
#[test]
fn prepare_returns_original_ids_without_start_or_a_go_claim() {
    let f = Fixture::new();
    let (input, link) = f.bound();
    let status = f.inbox.query(FAMILY,&input.query(), false).unwrap();
    assert_eq!(status.operation.as_ref().unwrap().operation_id(), &id(5));
    assert_eq!(status.operation.unwrap().state(), OperationState::Prepared);
    assert_eq!(status.start_state, StartState::NotRequested);
    assert!(f.inbox.claim(FAMILY).unwrap().is_none());
    assert!(!link.start_matches(FAMILY, Some(link.entry())));
    assert_eq!(
        f.inbox.prepare(FAMILY,input, &f.point).unwrap().start_state,
        StartState::NotRequested
    );
    assert_eq!(f.inbox.entries(FAMILY).unwrap().len(), 1);
}
#[test]
fn exact_start_is_one_use_and_duplicate_reconnect_only_queries() {
    let f = Fixture::new();
    let (input, link) = f.bound();
    let mut request = start(&input);
    request.owner_generation = id(8);
    assert_eq!(f.inbox.start(FAMILY,&request).unwrap_err(), Error::Conflict);
    request.owner_generation = id(6);
    assert_eq!(
        f.inbox.start(FAMILY,&request).unwrap().start_state,
        StartState::Queued
    );
    let t = link.entry().start_at().unwrap();
    let claim = f.inbox.claim(FAMILY).unwrap().unwrap();
    assert!(matches!(claim.kind(), ClaimKind::Start));
    assert!(link.start_matches(FAMILY, Some(claim.entry())));
    link.consume_start(FAMILY).unwrap();
    claim.returned(true);
    assert_eq!(
        f.inbox.start(FAMILY,&request).unwrap().start_state,
        StartState::Consumed
    );
    assert_eq!(link.entry().start_at(), Some(t));
    assert!(f.inbox.claim(FAMILY).unwrap().is_none());
    assert!(link.consume_start(FAMILY).is_err());
    assert!(f.inbox.prepare(FAMILY,f.request(9), &f.point).is_err());
}
#[test]
fn concurrent_start_has_one_original_claim_and_never_restarts_its_clock() {
    let f = Fixture::new();
    let (input, link) = f.bound();
    let request = start(&input);
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let inbox = f.inbox.clone();
            let request = request.clone();
            std::thread::spawn(move || inbox.start(FAMILY,&request).unwrap())
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let t = link.entry().start_at().unwrap();
    let claim = f.inbox.claim(FAMILY).unwrap().unwrap();
    assert!(f.inbox.claim(FAMILY).unwrap().is_none());
    link.consume_start(FAMILY).unwrap();
    claim.returned(true);
    assert_eq!(link.entry().start_at(), Some(t));
}
#[test]
fn lost_prepare_return_keeps_bound_request_and_cannot_authorize_a_retry() {
    let f = Fixture::new();
    f.inbox.allow(f.scope.clone()).unwrap();
    let input = f.request(3);
    f.inbox.prepare(FAMILY,input.clone(), &f.point).unwrap();
    let claim = f.inbox.claim(FAMILY).unwrap().unwrap();
    let link = claim
        .entry()
        .bind(FAMILY,id(5), id(6), 1, Instant::now() + Duration::from_secs(300))
        .unwrap();
    drop(claim);
    let status = f.inbox.prepare(FAMILY,input.clone(), &f.point).unwrap();
    assert_eq!(status.request_state, RequestState::AdmissionUnknown);
    assert!(status.operation.is_some());
    assert!(f.inbox.start(FAMILY,&start(&input)).is_err());
    assert!(f.inbox.allow(f.scope.clone()).is_err());
    assert!(link.entry().stop_at(Instant::now()).is_some());
    assert!(f.inbox.claim(FAMILY).unwrap().is_none());
}
#[test]
fn start_lost_ack_and_native_unknown_never_become_replay_or_settlement() {
    let f = Fixture::new();
    let (input, link) = f.bound();
    let request = start(&input);
    f.inbox.start(FAMILY,&request).unwrap();
    let claim = f.inbox.claim(FAMILY).unwrap().unwrap();
    link.consume_start(FAMILY).unwrap();
    drop(claim);
    assert_eq!(
        f.inbox.start(FAMILY,&request).unwrap().request_state,
        RequestState::AdmissionUnknown
    );
    let mut unknown = link.entry().status().unwrap().operation.unwrap().android().clone();
    unknown.status_revision += 1;
    unknown.state = OperationState::Unknown;
    unknown.settlement = Settlement::Unknown;
    unknown.outcome = Some(Outcome::Unknown);
    unknown.reason = Reason::CleanupUnknown;
    link.publish(unknown.clone()).unwrap();
    link.publish(final_cancel(&link, 3)).unwrap();
    assert_eq!(link.entry().status().unwrap().operation, Some(unknown.into()));
    assert!(f.inbox.claim(FAMILY).unwrap().is_none());
    assert!(f.inbox.allow(f.scope.clone()).is_err());
}
#[test]
fn start_expiry_is_not_a_new_running_work_deadline_but_revoke_is_real_stop() {
    let f = Fixture::new();
    let (input, link) = f.bound();
    let after = link.entry().start_deadline() + START_WINDOW;
    assert!(link.entry().stop_at(after).is_some()); // Unconsumed native review.
    f.inbox.start(FAMILY,&start(&input)).unwrap();
    let claim = f.inbox.claim(FAMILY).unwrap().unwrap();
    link.consume_start(FAMILY).unwrap();
    claim.returned(true);
    let (stop, _) = tokio::sync::watch::channel(false);
    link.attach_stop(&stop).unwrap();
    assert!(link.entry().stop_at(after).is_none()); // Same native3000/3010 clocks, not a renewed lease.
    f.inbox.revoke(FAMILY).unwrap();
    let first = link.entry().stop_at(Instant::now()).unwrap();
    assert!(*stop.borrow());
    f.inbox.revoke(FAMILY).unwrap();
    link.entry().cancel();
    assert_eq!(link.entry().stop_at(Instant::now()), Some(first));
    assert_eq!(
        f.inbox.query(FAMILY,&input.query(), false).unwrap().start_state,
        StartState::Consumed
    );
}
#[test]
fn cancellation_before_prepare_consumes_permission_but_does_not_invent_native_ids() {
    let f = Fixture::new();
    f.inbox.allow(f.scope.clone()).unwrap();
    let input = f.request(3);
    f.inbox.prepare(FAMILY,input.clone(), &f.point).unwrap();
    let status = f.inbox.query(FAMILY,&input.query(), true).unwrap();
    assert_eq!(
        status.request_state,
        RequestState::CancelledBeforePreparation
    );
    assert!(status.operation.is_none());
    assert!(f.inbox.claim(FAMILY).unwrap().is_none());
    assert!(f.inbox.prepare(FAMILY,f.request(7), &f.point).is_err());
    assert_eq!(
        f.inbox.prepare(FAMILY,input, &f.point).unwrap().request_state,
        RequestState::CancelledBeforePreparation
    );
}
#[test]
fn foreign_instance_and_body_do_not_spend_or_reassign_an_original() {
    let f = Fixture::new();
    f.inbox.allow(f.scope.clone()).unwrap();
    let input = f.request(3);
    let mut wrong = input.clone();
    wrong.service_instance = id(9);
    assert_eq!(
        f.inbox.prepare(FAMILY,wrong, &f.point).unwrap_err(),
        Error::Conflict
    );
    assert!(f.inbox.access(FAMILY).unwrap().enabled);
    f.inbox.prepare(FAMILY,input.clone(), &f.point).unwrap();
    let mut wrong = input;
    wrong.expected_observation_revision = 8;
    assert_eq!(
        f.inbox.prepare(FAMILY,wrong, &f.point).unwrap_err(),
        Error::Conflict
    );
    assert_eq!(f.inbox.entries(FAMILY).unwrap().len(), 1);
}
#[test]
fn disappearing_link_does_not_release_original_slot_or_create_new_consent() {
    let f = Fixture::new();
    let (input, link) = f.bound();
    drop(link);
    assert!(f.inbox.start(FAMILY,&start(&input)).is_err());
    assert!(f.inbox.allow(f.scope.clone()).is_err());
    assert_eq!(
        f.inbox
            .query(FAMILY,&input.query(), false)
            .unwrap()
            .operation
            .unwrap()
            .settlement(),
        Settlement::Pending
    );
}
#[test]
fn claimed_history_is_separate_from_latest_and_failure_never_settles_native_work() {
    let f = Fixture::new();
    let (_, link) = f.bound();
    let (first, operation) = link.entry().claim_history().unwrap().unwrap();
    let op = operation.android().clone();
    assert!(first);
    let mut running = op.clone();
    running.status_revision += 1;
    running.state = OperationState::Running;
    link.publish(running.clone()).unwrap();
    assert!(link.entry().claim_history().is_err());
    link.entry()
        .history_returned(op.status_revision, Ok(()))
        .unwrap();
    let (first, latest) = link.entry().claim_history().unwrap().unwrap();
    assert!(!first);
    assert_eq!(latest.android(), &running);
    assert!(link
        .entry()
        .history_returned(latest.status_revision(), Err(Error::StateUnknown))
        .is_err());
    let state = link.entry().status().unwrap();
    assert!(!state.history_available);
    assert_eq!(state.operation.unwrap().settlement(), Settlement::Pending);
    assert!(link.entry().claim_history().unwrap().is_none());
}
#[test]
fn finite_tombstones_never_evict_or_reissue_a_used_request() {
    let f = Fixture::new();
    for n in 0..LIMIT {
        f.inbox.allow(f.scope.clone()).unwrap();
        let input = f.request((n + 10) as u8);
        f.inbox.prepare(FAMILY,input.clone(), &f.point).unwrap();
        f.inbox.query(FAMILY,&input.query(), true).unwrap();
    }
    assert_eq!(f.inbox.entries(FAMILY).unwrap().len(), LIMIT);
    assert!(f.inbox.allow(f.scope.clone()).is_err());
    assert_eq!(
        f.inbox
            .prepare(FAMILY,f.request(10), &f.point)
            .unwrap()
            .request_state,
        RequestState::CancelledBeforePreparation
    );
}
#[test]
fn native_retirement_can_resolve_admission_unknown_but_cannot_rearm_start() {
    let f = Fixture::new();
    let (input, link) = f.bound();
    f.inbox.start(FAMILY,&start(&input)).unwrap();
    let claim = f.inbox.claim(FAMILY).unwrap().unwrap();
    drop(claim);
    link.publish(final_cancel(&link, 2)).unwrap();
    let status = f.inbox.start(FAMILY,&start(&input)).unwrap();
    assert_eq!(status.operation.unwrap().settlement(), Settlement::Settled);
    assert_eq!(status.start_state, StartState::Admitting);
    assert!(f.inbox.claim(FAMILY).unwrap().is_none());
}
#[test]
fn closed_client_shapes_cannot_carry_executables_paths_or_signing_options() {
    let f = Fixture::new();
    let input = f.request(3);
    let base = serde_json::to_value(&input).unwrap();
    for field in [
        "command",
        "root",
        "signing",
        "artifactValidation",
        "consentVersion",
        "window",
    ] {
        let mut changed = base.clone();
        changed[field] = serde_json::json!("synthetic");
        assert!(serde_json::from_value::<Prepare>(changed).is_err());
    }
    let version = serde_json::to_value(&review().saved_version).unwrap();
    let mut path = version;
    path["source"] = serde_json::json!("private/path");
    assert!(serde_json::from_value::<Version>(path).is_err());
}
