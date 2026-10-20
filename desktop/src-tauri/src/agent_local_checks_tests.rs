//! Inert DATA/lifecycle tests. No filesystem, native runtime, worker or process
//! is created; native settlement can only be asserted by the original adapter.
use super::*;
fn id(byte: char) -> Id {
    Id::parse(&byte.to_string().repeat(32)).unwrap()
}
struct Fixture {
    inbox: Inbox,
    scope: Arc<NativeScope>,
    _document: Arc<()>,
}
impl Fixture {
    fn new() -> Self {
        let document = Arc::new(());
        let (changes, _) = tokio::sync::watch::channel(0);
        let scope = Arc::new(NativeScope {
            project_id: id('a'),
            runtime_id: "project-1".into(),
            root: PathBuf::from("/inert-local-check"),
            device: 1,
            inode: 2,
            registration: 1,
            input_revision: 1,
            document: Arc::downgrade(&document),
            observation_revision: 2,
            config: Config {
                bytes: 123,
                sha256: "f".repeat(64),
            },
            draft_revision: 4,
            baseline_generation: 3,
            changes,
        });
        Self {
            inbox: Inbox::new(id('b')),
            scope,
            _document: document,
        }
    }
    fn allow(&self) {
        self.inbox.allow(self.scope.clone()).unwrap();
    }
    fn point(&self) -> SavedPoint {
        SavedPoint {
            project_id: self.scope.project_id.clone(),
            runtime_id: self.scope.runtime_id.clone(),
            root: self.scope.root.clone(),
            device: 1,
            inode: 2,
            revision: 2,
            fresh: true,
            config: Some(self.scope.config.clone()),
        }
    }
    fn submit(&self, key: char) -> Submit {
        Submit {
            service_instance: id('b'),
            project_id: id('a'),
            request_id: id(key),
            expected_observation_revision: 2,
        }
    }
    fn claimed(&self) -> (Submit, Claim) {
        self.allow();
        let input = self.submit('c');
        self.inbox.submit(input.clone(), &self.point()).unwrap();
        let claim = self.inbox.claim().unwrap().unwrap();
        (input, claim)
    }
}
fn pending(state: OperationState, revision: u32) -> Operation {
    Operation {
        operation_id: id('d'),
        owner_generation: id('e'),
        status_revision: revision,
        state,
        settlement: Settlement::Pending,
        outcome: None,
        reason: Reason::None,
        result: None,
    }
}
fn cancelled(revision: u32) -> Operation {
    Operation {
        state: OperationState::Cancelled,
        settlement: Settlement::Settled,
        outcome: Some(Outcome::Cancelled),
        reason: Reason::Cancelled,
        ..pending(OperationState::Prepared, revision)
    }
}
#[test]
fn no_execution_without_separate_exact_unused_permission() {
    let f = Fixture::new();
    let input = f.submit('c');
    assert_eq!(
        f.inbox.submit(input.clone(), &f.point()).unwrap_err(),
        Error::AccessDenied
    );
    f.allow();
    let mut wrong = input.clone();
    wrong.project_id = id('f');
    assert_eq!(
        f.inbox.submit(wrong, &f.point()).unwrap_err(),
        Error::Conflict
    );
    let mut point = f.point();
    point.fresh = false;
    assert_eq!(
        f.inbox.submit(input.clone(), &point).unwrap_err(),
        Error::Conflict
    );
    point = f.point();
    point.inode += 1;
    assert_eq!(
        f.inbox.submit(input.clone(), &point).unwrap_err(),
        Error::Conflict
    );
    point = f.point();
    point.config.as_mut().unwrap().sha256 = "0".repeat(64);
    assert_eq!(
        f.inbox.submit(input.clone(), &point).unwrap_err(),
        Error::Conflict
    );
    assert!(!f.inbox.access().unwrap().consumed);
    assert_eq!(
        f.inbox.submit(input, &f.point()).unwrap().request_state,
        RequestState::Queued
    );
    assert!(f.inbox.access().unwrap().consumed);
}
#[test]
fn identical_reconnect_is_observation_not_second_execution_even_after_revoke() {
    let f = Fixture::new();
    let (input, claim) = f.claimed();
    let entry = claim.entry().clone();
    f.inbox.revoke().unwrap();
    claim.returned(false);
    let mut stale = f.point();
    stale.fresh = false;
    let old = f.inbox.submit(input.clone(), &stale).unwrap();
    assert_eq!(old.origin, input.query());
    assert_eq!(old.request_state, RequestState::RefusedBeforeAdmission);
    assert!(f.inbox.claim().unwrap().is_none());
    let mut changed = input;
    changed.expected_observation_revision += 1;
    assert_eq!(
        f.inbox.submit(changed, &f.point()).unwrap_err(),
        Error::Conflict
    );
    assert!(entry.stop_at(Instant::now()).is_some());
}
#[test]
fn revoke_before_and_after_original_stop_binding_uses_same_sender() {
    let f = Fixture::new();
    let (_, claim) = f.claimed();
    let link = claim.entry().bind(id('d'), id('e'), 1).unwrap();
    f.inbox.revoke().unwrap();
    let (stop, receiver) = tokio::sync::watch::channel(false);
    link.attach_stop(&stop).unwrap();
    assert!(*receiver.borrow());
    assert!(!link.start_matches(Some(claim.entry())));
    claim.returned(true);
    let f = Fixture::new();
    let (_, claim) = f.claimed();
    let link = claim.entry().bind(id('d'), id('e'), 1).unwrap();
    let (stop, receiver) = tokio::sync::watch::channel(false);
    link.attach_stop(&stop).unwrap();
    f.inbox.revoke().unwrap();
    assert!(*receiver.borrow());
    claim.returned(true);
    assert!(f
        .inbox
        .query(&f.submit('c').query(), false)
        .unwrap()
        .operation
        .is_some());
}
#[test]
fn expiry_is_fixed_and_cancel_is_not_native_settlement() {
    let f = Fixture::new();
    let (input, claim) = f.claimed();
    let link = claim.entry().bind(id('d'), id('e'), 1).unwrap();
    let expiry = link.expires();
    let before = expiry - Duration::from_nanos(1);
    assert!(claim.entry().stop_at(before).is_none());
    assert_eq!(claim.entry().stop_at(expiry), Some(expiry));
    let (stop, receiver) = tokio::sync::watch::channel(false);
    link.attach_stop(&stop).unwrap();
    let cancelled = f.inbox.query(&input.query(), true).unwrap();
    assert!(*receiver.borrow());
    assert_eq!(cancelled.operation.unwrap().settlement, Settlement::Pending);
    assert_eq!(link.expires(), expiry);
    assert!(claim.entry().occupies());
    claim.returned(true);
}
#[test]
fn dropped_admission_and_dropped_native_link_do_not_release_request_or_replay() {
    let f = Fixture::new();
    let (input, claim) = f.claimed();
    drop(claim);
    assert_eq!(
        f.inbox.query(&input.query(), false).unwrap().request_state,
        RequestState::AdmissionUnknown
    );
    assert!(f.inbox.allow(f.scope.clone()).is_err());
    assert!(f.inbox.claim().unwrap().is_none());
    let f = Fixture::new();
    let (input, claim) = f.claimed();
    let link = claim.entry().bind(id('d'), id('e'), 1).unwrap();
    claim.returned(true);
    drop(link);
    assert_eq!(
        f.inbox
            .query(&input.query(), false)
            .unwrap()
            .operation
            .unwrap()
            .settlement,
        Settlement::Pending
    );
    assert!(f.inbox.allow(f.scope.clone()).is_err());
}
#[test]
fn native_unknown_absorbs_later_terminal_and_history_never_changes_it() {
    let f = Fixture::new();
    let (_, claim) = f.claimed();
    let link = claim.entry().bind(id('d'), id('e'), 1).unwrap();
    link.publish(Operation {
        state: OperationState::Unknown,
        settlement: Settlement::Unknown,
        outcome: Some(Outcome::Unknown),
        reason: Reason::CleanupUnknown,
        ..pending(OperationState::Running, 2)
    })
    .unwrap();
    link.publish(cancelled(3)).unwrap();
    let (_, data) = claim.entry().claim_history().unwrap().unwrap();
    claim
        .entry()
        .history_returned(data.status_revision, Ok(()))
        .unwrap();
    assert_eq!(
        claim
            .entry()
            .status()
            .unwrap()
            .operation
            .unwrap()
            .settlement,
        Settlement::Unknown
    );
    assert!(claim.entry().occupies());
    claim.returned(true);
}
#[test]
fn genuine_retirement_resolves_lost_admission_ack_not_a_native_unknown() {
    let f = Fixture::new();
    let (_, claim) = f.claimed();
    let link = claim.entry().bind(id('d'), id('e'), 1).unwrap();
    drop(claim);
    assert_eq!(
        link.entry().status().unwrap().request_state,
        RequestState::AdmissionUnknown
    );
    link.publish(cancelled(2)).unwrap();
    assert_eq!(
        link.entry().status().unwrap().request_state,
        RequestState::OriginalAvailable
    );
    assert!(!link.entry().occupies());
    let f = Fixture::new();
    let (_, claim) = f.claimed();
    let link = claim.entry().bind(id('d'), id('e'), 1).unwrap();
    link.publish(cancelled(2)).unwrap();
    claim.returned(false);
    assert!(!link.entry().occupies()); // Returned genuine no-start refusal, not unknown.
}
#[test]
fn exact_native_ids_and_progress_order_and_terminal_immutability() {
    let f = Fixture::new();
    let (_, claim) = f.claimed();
    let link = claim.entry().bind(id('d'), id('e'), 1).unwrap();
    let mut foreign = pending(OperationState::Running, 2);
    foreign.owner_generation = id('f');
    assert!(link.publish(foreign).is_err());
    link.publish(pending(OperationState::Running, 2)).unwrap();
    assert!(link.publish(pending(OperationState::Prepared, 1)).is_err());
    link.publish(cancelled(3)).unwrap();
    assert!(link.publish(pending(OperationState::Running, 4)).is_err());
    assert!(!link.start_matches(None));
    claim.returned(true);
}
#[test]
fn coalesced_latest_never_overwrites_retained_original_history_claim() {
    let f = Fixture::new();
    let (_, claim) = f.claimed();
    let link = claim.entry().bind(id('d'), id('e'), 1).unwrap();
    let (first, before) = link.entry().claim_history().unwrap().unwrap();
    assert!(first);
    link.publish(pending(OperationState::Running, 2)).unwrap();
    assert!(link.entry().claim_history().is_err());
    link.entry()
        .history_returned(before.status_revision, Ok(()))
        .unwrap();
    let (first, latest) = link.entry().claim_history().unwrap().unwrap();
    assert!(!first);
    assert_eq!(latest.status_revision, 2);
    assert!(link
        .entry()
        .history_returned(latest.status_revision, Err(Error::StateUnknown))
        .is_err());
    assert!(link.entry().claim_history().unwrap().is_none());
    assert!(!link.entry().status().unwrap().history_available);
    assert_eq!(
        link.entry().status().unwrap().operation.unwrap().settlement,
        Settlement::Pending
    );
    claim.returned(true);
}
#[test]
fn one_outstanding_and_full_launch_ledger_never_evict_or_auto_replay() {
    let f = Fixture::new();
    f.allow();
    let input = f.submit('c');
    f.inbox.submit(input.clone(), &f.point()).unwrap();
    assert_eq!(
        f.inbox.submit(f.submit('d'), &f.point()).unwrap_err(),
        Error::Busy
    );
    f.inbox.query(&input.query(), true).unwrap();
    for n in 1..LIMIT {
        f.allow();
        let mut input = f.submit('c');
        input.request_id = Id::parse(&format!("{n:032x}")).unwrap();
        f.inbox.submit(input.clone(), &f.point()).unwrap();
        f.inbox.query(&input.query(), true).unwrap();
    }
    assert_eq!(f.inbox.entries().unwrap().len(), LIMIT);
    f.allow();
    assert_eq!(
        f.inbox.submit(f.submit('d'), &f.point()).unwrap_err(),
        Error::Busy
    );
    assert!(f.inbox.query(&input.query(), false).is_ok());
}
#[test]
fn host_restart_and_changed_project_or_body_do_not_adopt_an_original() {
    let f = Fixture::new();
    let (input, claim) = f.claimed();
    claim.returned(false);
    let other = Inbox::new(id('f'));
    assert_eq!(
        other.query(&input.query(), false).unwrap_err(),
        Error::Conflict
    );
    let mut foreign = input.query();
    foreign.project_id = id('f');
    assert_eq!(f.inbox.query(&foreign, true).unwrap_err(), Error::Conflict);
    let mut query = input.query();
    query.service_instance = id('f');
    assert_eq!(f.inbox.query(&query, false).unwrap_err(), Error::Conflict);
}
#[test]
fn close_revokes_independently_and_poison_cannot_skip_stop() {
    let f = Fixture::new();
    let (_, claim) = f.claimed();
    let link = claim.entry().bind(id('d'), id('e'), 1).unwrap();
    let (stop, receiver) = tokio::sync::watch::channel(false);
    link.attach_stop(&stop).unwrap();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = f.inbox.book.lock().unwrap();
        panic!("inert poison");
    }));
    assert!(f.inbox.revoke().is_err());
    assert!(*receiver.borrow());
    assert!(!link.start_matches(Some(claim.entry())));
    claim.returned(true);
    f.inbox.close();
    assert!(f.inbox.claim().is_err());
}
#[test]
fn codes_only_report_and_config_must_match_without_turning_failures_into_passes() {
    let f = Fixture::new();
    let (_, claim) = f.claimed();
    let link = claim.entry().bind(id('d'), id('e'), 1).unwrap();
    let mut counts = STATUSES
        .into_iter()
        .map(|key| (key, 0))
        .collect::<BTreeMap<_, _>>();
    counts.insert(CoreStatus::Fail, 1);
    let report = Report {
        schema_version: 1,
        scope: "saved-local-android-project-checks".into(),
        used_config: f.scope.config.clone(),
        findings: vec![Finding {
            ordinal: 0,
            check: Check::ConfiguredProjectCheck,
            message: Check::ConfiguredProjectCheck,
            status: CoreStatus::Fail,
            project_check_index: Some(0),
        }],
        summary: Summary {
            total: 1,
            shown: 1,
            omitted: 0,
            counts,
        },
        limitations: LIMITATIONS.to_vec(),
    };
    assert!(report.valid());
    let mut raw = serde_json::to_value(&report).unwrap();
    raw["findings"][0]["message"] = serde_json::json!("private/path/output");
    assert!(serde_json::from_value::<Report>(raw).is_err());
    let mut result = Operation {
        state: OperationState::Succeeded,
        settlement: Settlement::Settled,
        outcome: Some(Outcome::Complete),
        result: Some(report),
        ..pending(OperationState::Prepared, 2)
    };
    result.result.as_mut().unwrap().used_config.bytes += 1;
    assert!(link.publish(result.clone()).is_err());
    result.result.as_mut().unwrap().used_config = f.scope.config.clone();
    link.publish(result).unwrap();
    assert_eq!(
        link.entry()
            .status()
            .unwrap()
            .operation
            .unwrap()
            .result
            .unwrap()
            .summary
            .counts[&CoreStatus::Fail],
        1
    );
    claim.returned(true);
}
#[test]
fn duplicate_projection_is_noop_and_quote_covers_bounded_typed_rows_not_rss() {
    let f = Fixture::new();
    let (_, claim) = f.claimed();
    let link = claim.entry().bind(id('d'), id('e'), 1).unwrap();
    let mut changes = f.scope.changes.subscribe();
    changes.borrow_and_update();
    link.publish(pending(OperationState::Prepared, 1)).unwrap();
    assert!(!changes.has_changed().unwrap());
    let row_quote = std::mem::size_of::<Entry>()
        + std::mem::size_of::<Lease>()
        + std::mem::size_of::<NativeScope>()
        + 4096
        + 1024
        + 2 * (std::mem::size_of::<Operation>() + 128 * std::mem::size_of::<Finding>() + 4096);
    assert!((LIMIT + 2) * row_quote + 2 * REPORT_LIMIT < DOCUMENT_BACKING);
    claim.returned(true);
}
