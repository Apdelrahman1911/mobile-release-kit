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
            draft_revision: 1,
            baseline_generation: 1,
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
        (input, link)
    }
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
    drop(claim);
    let mut op = ios::Status::try_from(link.entry().status().unwrap())
        .unwrap()
        .operation
        .unwrap();
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
