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
    assert!(PUBLIC_HEAP_CEILING <= STATUS_HEAP_BYTES);
    assert!(ROW_CEILING <= ROW_BACKING);
    assert!(ANCILLARY_CEILING <= ANCILLARY_BACKING);
    assert_eq!(DOCUMENT_BACKING, 851_968);
    assert!(LIMIT * ROW_CEILING + ANCILLARY_CEILING + 4 * REPORT_LIMIT <= DOCUMENT_BACKING);
    eprintln!("local report DATA: row={ROW_CEILING}/16384 public={PUBLIC_HEAP_CEILING}/8192 ancillary={ANCILLARY_CEILING}/65536 retained={DOCUMENT_BACKING}; shared eight IPC copies excluded");
    claim.returned(true);
}

fn full_terminal(revision: u32) -> Operation {
    let counts = STATUSES.into_iter().map(|status| {
        (status, if status == CoreStatus::Fail { 128 } else { 0 })
    }).collect();
    Operation {
        state: OperationState::Succeeded,
        settlement: Settlement::Settled,
        outcome: Some(Outcome::Complete),
        result: Some(Report {
            schema_version: 1,
            scope: "saved-local-android-project-checks".into(),
            used_config: Config { bytes: 123, sha256: "f".repeat(64) },
            findings: (0..128).map(|ordinal| Finding {
                ordinal, check: Check::ConfiguredProjectCheck,
                message: Check::ConfiguredProjectCheck, status: CoreStatus::Fail,
                project_check_index: Some(ordinal % 32),
            }).collect(),
            summary: Summary { total: 128, shown: 128, omitted: 0, counts },
            limitations: LIMITATIONS.to_vec(),
        }),
        ..pending(OperationState::Prepared, revision)
    }
}

#[test]
fn all32_failed_history_claims_share_exact_terminal_without_replay_or_public_mutation() {
    let mut f = Fixture::new();
    let scope = Arc::get_mut(&mut f.scope).unwrap();
    scope.root = PathBuf::from(format!("/{}", "r".repeat(ROOT_HEAP_BYTES - 1)));
    scope.runtime_id = "r".repeat(64);
    let mut original_queries = Vec::new();
    for n in 1..=LIMIT {
        f.allow();
        let mut input = f.submit('c');
        input.request_id = Id::parse(&format!("{n:032x}")).unwrap();
        f.inbox.submit(input.clone(), &f.point()).unwrap();
        let claim = f.inbox.claim().unwrap().unwrap();
        let operation = Id::parse(&format!("{:032x}", n + 100)).unwrap();
        let generation = Id::parse(&format!("{:032x}", n + 200)).unwrap();
        let link = claim.entry().bind(operation.clone(), generation.clone(), 1).unwrap();
        assert!(Arc::ptr_eq(&link.entry().lease.scope, &f.scope));
        claim.returned(true);
        let mut terminal = full_terminal(2);
        terminal.operation_id = operation;
        terminal.owner_generation = generation;
        // A valid native projection with spare capacity is bounded before it
        // is compacted. It does not leave that spare capacity in the32 rows.
        let report = terminal.result.as_mut().unwrap();
        report.findings.reserve(128);
        report.scope.reserve(128);
        report.limitations.reserve(32);
        assert!(terminal.valid());
        link.publish(terminal).unwrap();
        let retained = link.entry().latest.lock().unwrap().clone().unwrap();
        let report = retained.result.as_ref().unwrap();
        assert_eq!(report.findings.capacity(), report.findings.len());
        assert_eq!(report.scope.capacity(), report.scope.len());
        assert_eq!(report.limitations.capacity(), report.limitations.len());
        assert!(retained.heap_bytes().unwrap() + 3 * ID_HEAP_BYTES <= STATUS_HEAP_BYTES);
        let (_, mut history_dto) = link.entry().claim_history().unwrap().unwrap();
        assert!(Arc::ptr_eq(&retained,
            link.entry().publication.lock().unwrap().claim.as_ref().unwrap()));
        // Public copies have no shared mutable access to the retained value.
        history_dto.result.as_mut().unwrap().summary.counts.insert(CoreStatus::Fail, 0);
        let mut status_dto = link.entry().status().unwrap();
        status_dto.operation.as_mut().unwrap().result.as_mut().unwrap().findings.clear();
        assert!(link.entry().history_returned(2, Err(Error::StateUnknown)).is_err());
        assert_eq!(retained.result.as_ref().unwrap().findings.len(), 128);
        assert_eq!(retained.result.as_ref().unwrap().summary.counts[&CoreStatus::Fail], 128);
        assert!(link.entry().claim_history().unwrap().is_none());
        let status = f.inbox.submit(input.clone(), &f.point()).unwrap();
        assert!(status.do_not_replay && !status.history_available);
        assert_eq!(status.operation.unwrap().settlement, Settlement::Settled);
        assert!(f.inbox.claim().unwrap().is_none());
        original_queries.push(input.query());
    }
    let entries = f.inbox.entries().unwrap();
    assert_eq!(entries.len(), LIMIT);
    for entry in &entries {
        let latest = entry.latest.lock().unwrap().clone().unwrap();
        let publication = entry.publication.lock().unwrap();
        assert!(publication.failed);
        assert!(Arc::ptr_eq(&latest, publication.claim.as_ref().unwrap()));
    }
    f.allow(); // Existing Allow behavior remains; full launch ledger refuses submit.
    assert_eq!(f.inbox.submit(f.submit('d'), &f.point()).unwrap_err(), Error::Busy);
    for query in original_queries {
        assert!(f.inbox.query(&query, false).unwrap().do_not_replay);
    }
}

#[test]
fn older_failed_progress_claim_and_terminal_are_retained_without_two_full_reports() {
    let f = Fixture::new();
    let (_, claim) = f.claimed();
    let link = claim.entry().bind(id('d'), id('e'), 1).unwrap();
    claim.returned(true);
    let (_, progress) = link.entry().claim_history().unwrap().unwrap();
    let old_claim = link.entry().publication.lock().unwrap().claim.clone().unwrap();
    link.publish(full_terminal(2)).unwrap();
    let terminal = link.entry().latest.lock().unwrap().clone().unwrap();
    assert!(!Arc::ptr_eq(&old_claim, &terminal));
    assert!(old_claim.result.is_none());
    assert_eq!(old_claim.status_revision, progress.status_revision);
    assert!(terminal.result.is_some());
    assert!(link.entry().history_returned(1, Err(Error::StateUnknown)).is_err());
    assert!(Arc::ptr_eq(&old_claim,
        link.entry().publication.lock().unwrap().claim.as_ref().unwrap()));
    let mut changed = terminal.as_ref().clone();
    changed.status_revision += 1;
    assert_eq!(link.publish(changed), Err(Error::StateUnknown));
    assert!(Arc::ptr_eq(&terminal, link.entry().latest.lock().unwrap().as_ref().unwrap()));
    assert!(!link.entry().status().unwrap().history_available);
}

#[test]
fn oversized_native_scope_or_projection_capacity_cannot_replace_original_storage() {
    let live = Fixture::new();
    live.allow();
    let original_lease = live.inbox.book.lock().unwrap().lease.clone().unwrap();
    let mut f = Fixture::new();
    Arc::get_mut(&mut f.scope).unwrap().root.reserve(ROOT_HEAP_BYTES + 1);
    assert!(f.scope.root.as_os_str().len() < ROOT_HEAP_BYTES);
    assert!(matches!(live.inbox.allow(f.scope.clone()), Err(Error::InvalidRequest)));
    assert!(Arc::ptr_eq(&original_lease, live.inbox.book.lock().unwrap().lease.as_ref().unwrap()));
    assert!(original_lease.revoked.get().is_none());
    assert!(live.inbox.access().unwrap().enabled);
    assert!(live.inbox.entries().unwrap().is_empty());
    let f = Fixture::new();
    let (_, claim) = f.claimed();
    let link = claim.entry().bind(id('d'), id('e'), 1).unwrap();
    claim.returned(true);
    let original = link.entry().latest.lock().unwrap().clone().unwrap();
    let mut oversized = full_terminal(2);
    oversized.result.as_mut().unwrap().findings.reserve(
        REPORT_LIMIT / std::mem::size_of::<Finding>() + 1);
    assert!(oversized.valid());
    assert_eq!(link.publish(oversized), Err(Error::StateUnknown));
    assert!(Arc::ptr_eq(&original, link.entry().latest.lock().unwrap().as_ref().unwrap()));
    assert!(Arc::ptr_eq(&f.scope, &link.entry().lease.scope));
    // The valid terminal still uses the original IDs; an allocation refusal
    // does not reset its revision, owner identity or pending operation.
    link.publish(full_terminal(2)).unwrap();
    assert_eq!(link.entry().status().unwrap().operation.unwrap().settlement, Settlement::Settled);
}
