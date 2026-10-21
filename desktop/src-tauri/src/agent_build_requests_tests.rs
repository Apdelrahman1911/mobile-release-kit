//! Inert data/original memory lifecycle only. No filesystem, native owner,
//! qualification, executable or project build is performed.
use super::*;
fn id(n: u8) -> Id {
    Id::parse(&format!("{n:032x}")).unwrap()
}
struct Fixture {
    inbox: Inbox,
    document: Arc<()>,
    point: crate::agent_local_checks::SavedPoint,
}
impl Fixture {
    fn new() -> Self {
        Self {
            inbox: Inbox::new(id(1)),
            document: Arc::new(()),
            point: crate::agent_local_checks::SavedPoint {
                project_id: id(2),
                runtime_id: "project-1".into(),
                root: "/inert/never-opened".into(),
                device: 1,
                inode: 2,
                revision: 5,
                fresh: true,
                config: Some(Config {
                    bytes: 100,
                    sha256: "a".repeat(64),
                }),
            },
        }
    }
    fn scope(&self, family: Family) -> Arc<NativeScope> {
        let version = android::Version {
            bytes: 32,
            sha256: "b".repeat(64),
            name: "1.2.3".into(),
            build: 7,
        };
        let config = self.point.config.clone().unwrap();
        let review = match family {
            Family::AndroidInspect => Review::Android(android::Review {
                mode: android::Mode::SavedAndroidBuildStructureAndVersion,
                signing: None, upload_certificate_sha256: None,
                saved_config: config,
                saved_version: version,
                tools: android::Tools {
                    instance: id(6),
                    catalog_generation: 1,
                    record_sha256: "c".repeat(64),
                },
            }),
            Family::IosArchive => Review::Ios(ios::Review {
                mode: ios::Mode::SavedIosUnsignedArchive,
                signing: None,
                saved_config: config,
                saved_version: version,
            }),
        };
        let (changes, _) = tokio::sync::watch::channel(0);
        Arc::new(NativeScope {
            project_id: id(2),
            runtime_id: self.point.runtime_id.clone(),
            root: self.point.root.clone(),
            device: 1,
            inode: 2,
            registration: 1,
            input_revision: 2,
            document: Arc::downgrade(&self.document),
            observation_revision: 5,
            review,
            read: None,
            input: crate::agent_build_requests::NativeInput::Saved { draft_revision: 1, baseline_generation: 1 },
            changes,
        })
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
        self.inbox.allow(self.scope(Family::IosArchive)).unwrap();
        let input = self.request(3);
        self.inbox
            .prepare(Family::IosArchive, input.clone(), &self.point)
            .unwrap();
        let claim = self.inbox.claim(Family::IosArchive).unwrap().unwrap();
        let link = claim
            .entry()
            .bind(
                Family::IosArchive,
                id(4),
                id(5),
                1,
                Instant::now() + Duration::from_secs(300),
            )
            .unwrap();
        claim.returned(true);
        acknowledge(&link);
        (input, link)
    }
}
fn acknowledge(link: &NativeLink) {
    let (_, data) = link.entry().claim_history().unwrap().unwrap();
    link.entry().history_returned(data.status_revision(), Ok(())).unwrap();
}
#[test]
fn other_family_cannot_spend_query_cancel_claim_or_bind_the_grant() {
    let f = Fixture::new();
    f.inbox.allow(f.scope(Family::IosArchive)).unwrap();
    let p = f.request(3);
    assert!(f
        .inbox
        .prepare(Family::AndroidInspect, p.clone(), &f.point)
        .is_err());
    assert!(!f.inbox.access(Family::AndroidInspect).unwrap().enabled);
    assert!(f.inbox.access(Family::IosArchive).unwrap().enabled);
    f.inbox
        .prepare(Family::IosArchive, p.clone(), &f.point)
        .unwrap();
    assert!(f.inbox.claim(Family::AndroidInspect).unwrap().is_none());
    assert!(f
        .inbox
        .query(Family::AndroidInspect, &p.query(), true)
        .is_err());
    let claim = f.inbox.claim(Family::IosArchive).unwrap().unwrap();
    assert!(claim.entry().stop_at(Instant::now()).is_none());
    assert!(claim
        .entry()
        .bind(
            Family::AndroidInspect,
            id(4),
            id(5),
            1,
            Instant::now() + START_WINDOW
        )
        .is_err());
    assert!(claim.entry().original.get().is_none());
    claim.returned(false);
}
#[test]
fn explicit_other_allow_replaces_only_unconsumed_grant_and_query_does_not() {
    let f = Fixture::new();
    f.inbox.allow(f.scope(Family::AndroidInspect)).unwrap();
    assert!(!f.inbox.access(Family::IosArchive).unwrap().enabled);
    assert!(f.inbox.access(Family::AndroidInspect).unwrap().enabled);
    f.inbox.allow(f.scope(Family::IosArchive)).unwrap();
    assert!(!f.inbox.access(Family::AndroidInspect).unwrap().enabled);
    f.inbox.revoke(Family::AndroidInspect).unwrap();
    assert!(f.inbox.access(Family::IosArchive).unwrap().enabled);
    f.inbox
        .prepare(Family::IosArchive, f.request(3), &f.point)
        .unwrap();
    assert_eq!(
        f.inbox.allow(f.scope(Family::AndroidInspect)).unwrap_err(),
        Error::Busy
    );
}
#[test]
fn one_total_tombstone_bound_and_request_ids_cannot_change_family() {
    let f = Fixture::new();
    for n in 0..LIMIT {
        let family = if n % 2 == 0 {
            Family::AndroidInspect
        } else {
            Family::IosArchive
        };
        f.inbox.allow(f.scope(family)).unwrap();
        let p = f.request((n + 10) as u8);
        f.inbox.prepare(family, p.clone(), &f.point).unwrap();
        f.inbox.query(family, &p.query(), true).unwrap();
    }
    assert_eq!(f.inbox.book.lock().unwrap().entries.len(), LIMIT);
    assert!(f.inbox.allow(f.scope(Family::IosArchive)).is_err());
    assert!(f
        .inbox
        .prepare(Family::IosArchive, f.request(10), &f.point)
        .is_err());
    assert_eq!(
        f.inbox
            .prepare(Family::AndroidInspect, f.request(10), &f.point)
            .unwrap()
            .request_state,
        RequestState::CancelledBeforePreparation
    );
}
#[test]
fn same_ios_start_link_is_one_use_and_foreign_family_never_consumes_it() {
    let f = Fixture::new();
    let (p, link) = f.bound();
    let start = Start {
        origin: p.query(),
        operation_id: id(4),
        owner_generation: id(5),
    };
    assert!(android::Status::try_from(link.entry().status().unwrap()).is_err());
    assert!(ios::Status::try_from(link.entry().status().unwrap()).is_ok());
    assert!(f.inbox.start(Family::AndroidInspect, &start).is_err());
    f.inbox.start(Family::IosArchive, &start).unwrap();
    let at = link.entry().start_at().unwrap();
    let claim = f.inbox.claim(Family::IosArchive).unwrap().unwrap();
    assert!(!link.start_matches(Family::AndroidInspect, Some(claim.entry())));
    assert!(link.consume_start(Family::AndroidInspect).is_err());
    link.consume_start(Family::IosArchive).unwrap();
    claim.returned(true);
    assert_eq!(
        f.inbox
            .start(Family::IosArchive, &start)
            .unwrap()
            .start_state,
        StartState::Consumed
    );
    assert_eq!(link.entry().start_at(), Some(at));
    assert!(f.inbox.claim(Family::IosArchive).unwrap().is_none());
    assert!(link
        .entry()
        .stop_at(link.entry().start_deadline() + START_WINDOW)
        .is_none());
    f.inbox.revoke(Family::IosArchive).unwrap();
    let first = link.entry().stop_at(Instant::now());
    f.inbox.revoke(Family::IosArchive).unwrap();
    assert_eq!(first, link.entry().stop_at(Instant::now()));
    assert!(first.is_some());
}
#[test]
fn ios_unknown_absorbs_and_lost_ack_blocks_both_families_without_native_receipt() {
    let f = Fixture::new();
    let (p, link) = f.bound();
    f.inbox
        .start(
            Family::IosArchive,
            &Start {
                origin: p.query(),
                operation_id: id(4),
                owner_generation: id(5),
            },
        )
        .unwrap();
    let claim = f.inbox.claim(Family::IosArchive).unwrap().unwrap();
    link.consume_start(Family::IosArchive).unwrap();
    let mut op = ios::Status::try_from(link.entry().status().unwrap())
        .unwrap()
        .operation
        .unwrap();
    drop(claim);
    assert!(link.entry().status().unwrap().operation.is_none());
    op.status_revision = 2;
    op.state = OperationState::Unknown;
    op.settlement = Settlement::Unknown;
    op.outcome = Some(ios::Outcome::Unknown);
    op.reason = ios::Reason::CleanupUnknown;
    link.publish(op.clone()).unwrap();
    let unknown = op.clone();
    op.status_revision = 3;
    op.state = OperationState::Cancelled;
    op.settlement = Settlement::Settled;
    op.outcome = Some(ios::Outcome::Cancelled);
    op.reason = ios::Reason::Cancelled;
    link.publish(op).unwrap();
    assert_eq!(
        ios::Status::try_from(link.entry().status().unwrap())
            .unwrap()
            .operation,
        Some(unknown)
    );
    for family in [Family::AndroidInspect, Family::IosArchive] {
        assert!(f.inbox.allow(f.scope(family)).is_err());
    }
    assert!(f.inbox.claim(Family::IosArchive).unwrap().is_none());
}
#[test]
fn ios_historical_report_has_real_counts_and_rejects_paths_synthetic_digests_or_signing() {
    let f = Fixture::new();
    let (_, link) = f.bound();
    let s = ios::Status::try_from(link.entry().status().unwrap()).unwrap();
    let r = ios::Report {
        scope: ios::Scope::LocalUnsignedIosArchiveObservation,
        used_config: s.review.saved_config,
        used_version: s.review.saved_version,
        entries: 10,
        bytes: 100,
        export: None,
    };
    assert!(r.valid());
    let value = serde_json::to_value(&r).unwrap();
    for field in ["archive", "sha256", "bundleId", "signing", "ipa"] {
        let mut v = value.clone();
        v[field] = serde_json::json!("synthetic");
        assert!(serde_json::from_value::<ios::Report>(v).is_err());
    }
    let mut r = r;
    r.entries = 0;
    assert!(!r.valid());
    r.entries = 1;
    r.bytes = 8 * 1024u64.pow(3) + 1;
    assert!(!r.valid());
}

// Additional bounded-storage cases reuse the original inert Fixture above.
fn maximal_scope(f: &Fixture, family: Family) -> Arc<NativeScope> {
    let mut scope = f.scope(family);
    match &mut Arc::get_mut(&mut scope).unwrap().review {
        Review::Android(r) => r.saved_version.name = "v".repeat(64),
        Review::Ios(r) => r.saved_version.name = "v".repeat(64),
        Review::IosRecovery(_) => panic!("saved-build fixture only"),
    }
    scope
}
fn memory_bound(f: &Fixture, scope: &Arc<NativeScope>, n: usize) -> (Prepare, Arc<NativeLink>) {
    let family = scope.review.family();
    f.inbox.allow(scope.clone()).unwrap();
    let input = f.request((n + 10) as u8);
    f.inbox.prepare(family, input.clone(), &f.point).unwrap();
    let claim = f.inbox.claim(family).unwrap().unwrap();
    let link = claim.entry().bind(family, id((n + 100) as u8), id((n + 200) as u8), 1,
        Instant::now() + Duration::from_secs(300)).unwrap();
    claim.returned(true);
    assert!(Arc::ptr_eq(scope, &link.entry().lease.scope));
    (input, link)
}
fn terminal(link: &NativeLink) -> Operation {
    let mut op = link.entry().latest.lock().unwrap().as_ref().unwrap().as_ref().clone();
    match &mut op {
        Operation::Android(o) => {
            use android::FindingStatus::*;
            let counts = [Pass, Fail, Missing, Blocked, Invalid, Skip, Manual,
                Configured, NotApplicable].into_iter()
                .map(|status| (status, if status == Pass { 128 } else { 0 })).collect();
            o.status_revision = 2;
            o.state = OperationState::Succeeded;
            o.settlement = Settlement::Settled;
            o.outcome = Some(android::Outcome::Complete);
            o.stage = Some(android::Stage::DisposingWork);
            o.disposition = Some(android::Disposition {
                work: android::WorkDisposition::Removed,
                artifacts: android::ArtifactDisposition::RetainedLocalResult,
            });
            o.result = Some(android::Report {
                scope: android::Scope::LocalPostBuildArtifactObservation,
                used_config: link.entry().scope().review.android().unwrap().saved_config.clone(),
                used_version: link.entry().scope().review.android().unwrap().saved_version.clone(),
                findings: (0..128).map(|ordinal| android::Finding {
                    ordinal, check: android::Check::OtherCoreFinding, status: Pass,
                }).collect(),
                summary: android::Summary { total: 128, shown: 128, omitted: 0, counts },
                artifact: android::Artifact { size: 1024, sha256: "f".repeat(64) },
                signing: None,
            });
        }
        Operation::Ios(o) => {
            o.status_revision = 2;
            o.state = OperationState::Succeeded;
            o.settlement = Settlement::Settled;
            o.outcome = Some(ios::Outcome::Complete);
            o.stage = Some(ios::Stage::DisposingWork);
            o.disposition = Some(ios::Disposition {
                snapshot: ios::SnapshotDisposition::Removed,
                work: ios::WorkDisposition::Removed,
                output: ios::OutputDisposition::RetainedLocalResult,
            });
            o.result = Some(ios::Report {
                scope: ios::Scope::LocalUnsignedIosArchiveObservation,
                used_config: link.entry().scope().review.ios().unwrap().saved_config.clone(),
                used_version: link.entry().scope().review.ios().unwrap().saved_version.clone(),
                entries: 100_000, bytes: 8 * 1024u64.pow(3), export: None,
            });
        }
        Operation::IosRecovery(_) => panic!("saved-build fixture only"),
    }
    assert!(op.valid_for(&link.entry().scope().review));
    op
}
fn corrupt_copy(op: &mut Operation) {
    match op {
        Operation::Android(o) => o.result.as_mut().unwrap().findings.clear(),
        Operation::Ios(o) => o.result.as_mut().unwrap().entries = 0,
        Operation::IosRecovery(_) => panic!("saved-build fixture only"),
    }
}

#[test]
fn typed_row_public_and_ancillary_bounds_keep_all32_and_four_nonipc_reports() {
    assert!(PUBLIC_HEAP_CEILING <= STATUS_HEAP_BYTES);
    assert!(ROW_CEILING <= ROW_BACKING);
    assert!(ANCILLARY_CEILING <= ANCILLARY_BACKING);
    assert_eq!(DOCUMENT_BACKING, 688_128);
    assert!(LIMIT * ROW_CEILING + ANCILLARY_CEILING + 4 * android::REPORT_LIMIT
        <= DOCUMENT_BACKING);
    eprintln!("build report DATA: row={ROW_CEILING}/16384 public={PUBLIC_HEAP_CEILING}/8192 ancillary={ANCILLARY_CEILING}/65536 retained={DOCUMENT_BACKING}; shared eight IPC copies excluded");
}

#[test]
fn all32_mixed_rows_retain_acknowledged_reports_and_one_absorbing_failed_claim() {
    let mut f = Fixture::new();
    f.point.runtime_id = "r".repeat(64);
    f.point.root = format!("/{}", "r".repeat(ROOT_HEAP_BYTES - 1)).into();
    for n in 0..LIMIT {
        let family = if n % 2 == 0 { Family::AndroidInspect } else { Family::IosArchive };
        // Different maximal scope allocations exercise the closed32-row
        // bound, not32 entries all borrowing one artificially cheap scope.
        let scope = maximal_scope(&f, family);
        let (input, link) = memory_bound(&f, &scope, n);
        acknowledge(&link);
        let start = Start {
            origin: input.query(), operation_id: id((n + 100) as u8), owner_generation: id((n + 200) as u8),
        };
        f.inbox.start(family, &start).unwrap();
        let claim = f.inbox.claim(family).unwrap().unwrap();
        link.consume_start(family).unwrap();
        claim.returned(true);
        let mut op = terminal(&link);
        match &mut op {
            Operation::Android(o) => {
                let r = o.result.as_mut().unwrap();
                r.findings.reserve(128);
                r.used_version.name.reserve(128);
            }
            Operation::Ios(o) => o.result.as_mut().unwrap().used_version.name.reserve(128),
            Operation::IosRecovery(_) => panic!("saved-build fixture only"),
        }
        link.publish(op).unwrap();
        let retained = link.entry().latest.lock().unwrap().clone().unwrap();
        match retained.as_ref() {
            Operation::Android(o) => {
                let r = o.result.as_ref().unwrap();
                assert_eq!(r.findings.capacity(), 128);
                assert_eq!(r.used_version.name.capacity(), r.used_version.name.len());
            }
            Operation::Ios(o) => {
                let r = o.result.as_ref().unwrap();
                assert_eq!(r.used_version.name.capacity(), r.used_version.name.len());
            }
            Operation::IosRecovery(_) => panic!("saved-build fixture only"),
        }
        assert!(retained.heap_bytes().unwrap() + 8 * ID_HEAP_BYTES <= STATUS_HEAP_BYTES);
        let (_, mut history_dto) = link.entry().claim_history().unwrap().unwrap();
        assert!(Arc::ptr_eq(&retained,
            link.entry().publication.lock().unwrap().claim.as_ref().unwrap()));
        corrupt_copy(&mut history_dto);
        let failed = n + 1 == LIMIT;
        if failed {
            assert!(link.entry().history_returned(2, Err(Error::StateUnknown)).is_err());
            assert!(link.entry().status().unwrap().operation.is_none());
        } else {
            link.entry().history_returned(2, Ok(())).unwrap();
            let mut status_dto = link.entry().status().unwrap();
            corrupt_copy(status_dto.operation.as_mut().unwrap());
        }
        assert!(retained.valid_for(&scope.review));
        assert!(link.entry().claim_history().unwrap().is_none());
        let status = f.inbox.prepare(family, input.clone(), &f.point).unwrap();
        assert!(status.do_not_replay);
        assert_eq!(status.history_available, !failed);
        assert_eq!(status.start_state, StartState::Consumed);
        if failed { assert_eq!(status.request_state, RequestState::AdmissionUnknown); }
        else { assert_eq!(status.operation.as_ref().unwrap().settlement(), Settlement::Settled); }
        // Exercise the actual unchanged public family projection/validator,
        // not just a private compact record or a fabricated serialized value.
        let bytes = match family {
            Family::AndroidInspect => crate::service_metadata_text_protocol::encoded(
                &android::Status::try_from(status).unwrap(), android::REPORT_LIMIT).unwrap(),
            Family::IosArchive => crate::service_metadata_text_protocol::encoded(
                &ios::Status::try_from(status).unwrap(), ios::REPORT_LIMIT).unwrap(),
        };
        assert!(!bytes.is_empty());
        assert_eq!(f.inbox.start(family, &start).unwrap().start_state, StartState::Consumed);
        assert!(f.inbox.claim(family).unwrap().is_none());
    }
    assert_eq!(f.inbox.book.lock().unwrap().entries.len(), LIMIT);
    for family in [Family::AndroidInspect, Family::IosArchive] {
        let entries = f.inbox.entries(family).unwrap();
        assert_eq!(entries.len(), LIMIT / 2);
        for entry in entries {
            let latest = entry.latest.lock().unwrap().clone().unwrap();
            let publication = entry.publication.lock().unwrap();
            if publication.failed { assert!(Arc::ptr_eq(&latest, publication.claim.as_ref().unwrap())); }
            else { assert!(publication.claim.is_none()); assert!(Arc::ptr_eq(&latest, publication.visible.as_ref().unwrap())); }
        }
        assert!(matches!(f.inbox.allow(maximal_scope(&f, family)), Err(Error::Busy)));
    }
}

#[test]
fn earlier_failed_progress_is_preserved_beside_one_full_immutable_terminal() {
    for family in [Family::AndroidInspect, Family::IosArchive] {
        let f = Fixture::new();
        let scope = maximal_scope(&f, family);
        let (_, link) = memory_bound(&f, &scope, 0);
        let (_, progress) = link.entry().claim_history().unwrap().unwrap();
        let old = link.entry().publication.lock().unwrap().claim.clone().unwrap();
        link.publish(terminal(&link)).unwrap();
        let latest = link.entry().latest.lock().unwrap().clone().unwrap();
        assert!(!Arc::ptr_eq(&old, &latest));
        assert_eq!(old.status_revision(), progress.status_revision());
        assert!(match old.as_ref() {
            Operation::Android(o) => o.result.is_none(), Operation::Ios(o) => o.result.is_none(),
            Operation::IosRecovery(_) => panic!("saved-build fixture only"),
        });
        assert!(link.entry().history_returned(1, Err(Error::StateUnknown)).is_err());
        assert!(Arc::ptr_eq(&old,
            link.entry().publication.lock().unwrap().claim.as_ref().unwrap()));
        let mut changed = latest.as_ref().clone();
        match &mut changed {
            Operation::Android(o) => o.status_revision += 1,
            Operation::Ios(o) => o.status_revision += 1,
            Operation::IosRecovery(_) => panic!("saved-build fixture only"),
        }
        assert_eq!(link.publish(changed), Err(Error::StateUnknown));
        assert!(Arc::ptr_eq(&latest, link.entry().latest.lock().unwrap().as_ref().unwrap()));
        assert!(!link.entry().status().unwrap().history_available);
    }
}

#[test]
fn private_scope_and_incoming_report_capacity_refuse_without_rebinding_either_family() {
    for family in [Family::AndroidInspect, Family::IosArchive] {
        let f = Fixture::new();
        let original_scope = maximal_scope(&f, family);
        f.inbox.allow(original_scope).unwrap();
        let original_lease = f.inbox.book.lock().unwrap().lease.clone().unwrap();
        let mut oversized_scope = maximal_scope(&f, family);
        let review = &mut Arc::get_mut(&mut oversized_scope).unwrap().review;
        match &mut *review {
            Review::Android(r) => r.saved_version.name.reserve(256),
            Review::Ios(r) => r.saved_version.name.reserve(256),
            Review::IosRecovery(_) => panic!("saved-build fixture only"),
        }
        assert!(review.valid());
        assert!(matches!(f.inbox.allow(oversized_scope), Err(Error::InvalidRequest)));
        assert!(Arc::ptr_eq(&original_lease, f.inbox.book.lock().unwrap().lease.as_ref().unwrap()));
        assert!(original_lease.revoked.get().is_none());
        assert!(f.inbox.access(family).unwrap().enabled);
        assert!(f.inbox.book.lock().unwrap().entries.is_empty());
        let scope = maximal_scope(&f, family);
        let (_, link) = memory_bound(&f, &scope, 0);
        let original = link.entry().latest.lock().unwrap().clone().unwrap();
        let mut oversized = terminal(&link);
        match &mut oversized {
            Operation::Android(o) => o.result.as_mut().unwrap().findings.reserve(
                android::REPORT_LIMIT / std::mem::size_of::<android::Finding>() + 1),
            Operation::Ios(o) => o.result.as_mut().unwrap().used_version.name.reserve(ios::REPORT_LIMIT),
            Operation::IosRecovery(_) => panic!("saved-build fixture only"),
        }
        assert!(oversized.valid_for(&scope.review));
        assert_eq!(link.publish(oversized), Err(Error::StateUnknown));
        assert!(Arc::ptr_eq(&original, link.entry().latest.lock().unwrap().as_ref().unwrap()));
        assert!(Arc::ptr_eq(&scope, &link.entry().lease.scope));
        link.publish(terminal(&link)).unwrap();
        acknowledge(&link);
        assert_eq!(link.entry().status().unwrap().operation.unwrap().settlement(), Settlement::Settled);
    }
}

#[path = "agent_build_original_return_tests.rs"]
mod original_returns;

#[path = "agent_ios_recovery_requests_tests.rs"]
mod ios_recovery;
