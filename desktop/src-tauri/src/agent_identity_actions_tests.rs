//! Inert inbox/protocol tests. Native scopes/observations below are DATA only;
//! no native Session, filesystem owner, process or all-joins receipt is minted.
use super::*;
fn id(n: u32) -> Id {
    Id::parse(&format!("{n:032x}")).unwrap()
}
struct Fixture {
    inbox: Inbox,
    entry: Arc<Entry>,
    _doc: Arc<()>,
    _marker: Arc<()>,
    stopped: tokio::sync::watch::Receiver<bool>,
}
impl Fixture {
    fn new(allow: bool) -> Self {
        let inbox = Inbox::new(id(1));
        let doc = Arc::new(());
        let marker = Arc::new(());
        inbox
            .allow(NativeScope {
                project_id: id(2),
                runtime_id: "project-1".into(),
                root: PathBuf::from("/synthetic-project"),
                device: 1,
                inode: 2,
                registration: 1,
                input_revision: 1,
                document: Arc::downgrade(&doc),
            })
            .unwrap();
        let input = Submit {
            service_instance: id(1),
            project_id: id(2),
            intent_id: id(3),
            expected_observation_revision: 1,
            change: Change {
                selection: Selection {
                    platform: Platform::Android,
                    target: ":app".into(),
                    project: None,
                },
                desired_identity: "com.example.next".into(),
                identity_intent: IdentityIntent::NewApplication,
            },
        };
        inbox
            .submit(
                Origin {
                    instance: id(1),
                    client: id(20),
                    session: id(21),
                },
                input,
                &SavedPoint {
                    project_id: id(2),
                    runtime_id: "project-1".into(),
                    root: PathBuf::from("/synthetic-project"),
                    device: 1,
                    inode: 2,
                    revision: 1,
                    fresh: true,
                },
            )
            .unwrap();
        let entry = inbox.entry(&id(3)).unwrap();
        let claim = inbox.begin_review(&entry).unwrap();
        entry.original_claim_entered();
        entry
            .bind_original(id(4), id(5), Arc::downgrade(&marker))
            .unwrap();
        claim.returned(true).unwrap();
        let (stop, stopped) = tokio::sync::watch::channel(false);
        if allow {
            entry
                .allow_actions(original(), Instant::now() + Duration::from_secs(60), stop)
                .unwrap();
        }
        Self {
            inbox,
            entry,
            _doc: doc,
            _marker: marker,
            stopped,
        }
    }
    fn queue(&self) -> Claim {
        self.inbox
            .identity_action(&query(), Some(Kind::Prepare), None, false)
            .unwrap();
        self.inbox.claim_identity_action().unwrap().unwrap()
    }
    fn prepared(&self) {
        let claim = self.queue();
        self.entry.consume_action(Kind::Prepare).unwrap();
        claim.returned(true);
        self.entry
            .observe_action(observation(
                10,
                OperationState::Prepared,
                Settlement::Pending,
            ))
            .unwrap();
    }
}
fn query() -> Query {
    Query {
        service_instance: id(1),
        project_id: id(2),
        intent_id: id(3),
    }
}
fn original() -> Original {
    Original {
        operation_id: id(4),
        owner_generation: id(5),
        revision: id(6),
    }
}
fn review() -> Review {
    Review {
        plan_token: id(7),
        before_identity: "com.example.old".into(),
        after_identity: "com.example.next".into(),
        changes: vec![
            Location {
                path: "release/mobile-release.json".into(),
                line: 1,
                column: 1,
                role: Role::SavedIdentity,
            },
            Location {
                path: "app/build.gradle.kts".into(),
                line: 3,
                column: 4,
                role: Role::AndroidApplicationId,
            },
        ],
        unchanged: false,
        new_application_warning: true,
        build_verification_required: true,
        retain_version_reservations: true,
    }
}
fn observation(revision: u32, state: OperationState, settlement: Settlement) -> Observation {
    Observation {
        status_revision: revision,
        state,
        settlement,
        apply_submitted: false,
        review: Some(review()),
        effect: None,
        journal: None,
    }
}
fn start() -> Start {
    Start {
        origin: query(),
        original: original(),
        plan_token: id(7),
        reviewed: true,
    }
}

#[test]
fn proposal_permission_and_original_link_do_not_authorize_cli_prepare() {
    let f = Fixture::new(false);
    assert!(f
        .inbox
        .identity_action(&query(), Some(Kind::Prepare), None, false)
        .is_err());
    assert!(f.inbox.claim_identity_action().unwrap().is_none());
    assert!(f.entry.actions().is_none());
}
#[test]
fn same_two_claims_are_consumed_before_send_and_never_replayed() {
    let f = Fixture::new(true);
    f.prepared();
    for _ in 0..3 {
        f.inbox
            .identity_action(&query(), Some(Kind::Prepare), None, false)
            .unwrap();
    }
    assert!(f.inbox.claim_identity_action().unwrap().is_none());
    f.inbox
        .identity_action(&query(), Some(Kind::Start), Some(&start()), false)
        .unwrap();
    let claim = f.inbox.claim_identity_action().unwrap().unwrap();
    f.entry.consume_action(Kind::Start).unwrap();
    assert!(f.entry.consume_action(Kind::Start).is_err());
    claim.returned(true);
    let repeated = f
        .inbox
        .identity_action(&query(), Some(Kind::Start), Some(&start()), false)
        .unwrap();
    assert_eq!(repeated.start, Step::Submitted);
    assert!(!repeated.permission_live);
    assert!(f.inbox.claim_identity_action().unwrap().is_none());
    let (stop, _) = tokio::sync::watch::channel(false);
    assert!(f
        .entry
        .allow_actions(original(), Instant::now() + Duration::from_secs(60), stop)
        .is_err());
}
#[test]
fn start_requires_exact_original_revision_plan_and_explicit_review() {
    let f = Fixture::new(true);
    f.prepared();
    for field in 0..5 {
        let mut s = start();
        match field {
            0 => s.original.operation_id = id(9),
            1 => s.original.owner_generation = id(9),
            2 => s.original.revision = id(9),
            3 => s.plan_token = id(9),
            _ => s.reviewed = false,
        };
        assert!(f
            .inbox
            .identity_action(&query(), Some(Kind::Start), Some(&s), false)
            .is_err());
    }
    assert!(f.inbox.claim_identity_action().unwrap().is_none());
}
#[test]
fn lost_ack_retains_claim_and_cancel_does_not_claim_native_settlement() {
    let f = Fixture::new(true);
    f.prepared();
    f.inbox
        .identity_action(&query(), Some(Kind::Start), Some(&start()), false)
        .unwrap();
    let claim = f.inbox.claim_identity_action().unwrap().unwrap();
    f.entry.consume_action(Kind::Start).unwrap();
    drop(claim);
    let status = f.inbox.identity_action(&query(), None, None, true).unwrap();
    assert!(status.unconfirmed && status.cancel_requested && status.do_not_replay);
    assert_eq!(status.observation.unwrap().settlement, Settlement::Pending);
    assert!(*f.stopped.borrow());
    f.inbox
        .identity_action(&query(), Some(Kind::Start), Some(&start()), false)
        .unwrap();
    assert!(f.inbox.claim_identity_action().unwrap().is_none());
}
#[test]
fn returned_preclaim_refusal_is_not_unknown_or_an_edit_result() {
    let f = Fixture::new(true);
    let claim = f.queue();
    claim.returned(false);
    let status = f.entry.action_status().unwrap();
    assert_eq!(status.prepare, Step::Refused);
    assert!(!status.unconfirmed);
    assert!(status.observation.is_none());
    assert!(*f.stopped.borrow());
    assert!(f.inbox.claim_identity_action().unwrap().is_none());
}
#[test]
fn revocation_expiry_and_foreign_query_cannot_rearm_same_original() {
    let f = Fixture::new(true);
    let a = f.entry.actions().unwrap();
    assert_eq!(
        a.cancellation_at(a.expires + Duration::from_secs(5)),
        Some((a.expires, true))
    );
    f.inbox.revoke().unwrap();
    assert!(f
        .inbox
        .identity_action(&query(), Some(Kind::Prepare), None, false)
        .is_err());
    assert!(!f.entry.action_status().unwrap().permission_live);
    for field in 0..3 {
        let mut q = query();
        match field {
            0 => q.service_instance = id(8),
            1 => q.project_id = id(8),
            _ => q.intent_id = id(8),
        };
        assert!(f.inbox.identity_action(&q, None, None, true).is_err());
    }
    let g = Fixture::new(true);
    let mut foreign = query();
    foreign.intent_id = id(8);
    assert!(g.inbox.identity_action(&foreign, None, None, true).is_err());
    assert!(!*g.stopped.borrow());
}
#[test]
fn exact_cancel_fences_pending_allow_without_revoking_shared_proposal_lease() {
    let f = Fixture::new(false);
    f.entry.cancel_action(Instant::now());
    let (stop, _) = tokio::sync::watch::channel(false);
    assert!(f
        .entry
        .allow_actions(original(), Instant::now() + Duration::from_secs(60), stop)
        .is_err());
    assert!(f.entry.actions().is_none());
    assert!(!f.entry.lease.revoked.load(Ordering::Acquire));
    let g = Fixture::new(true);
    let first = Instant::now();
    g.entry.cancel_action(first);
    g.entry.cancel_action(first + Duration::from_secs(2));
    assert_eq!(g.entry.actions().unwrap().cancelled.get(), Some(&first));
    assert!(!g.entry.lease.revoked.load(Ordering::Acquire));
    assert!(*g.stopped.borrow());
}
#[test]
fn permission_cannot_outlive_original_review_or_turn_settlement_into_a_new_allow() {
    let f = Fixture::new(false);
    let (stop, _) = tokio::sync::watch::channel(false);
    let original_end = f.entry.approval.get().unwrap().expires;
    f.entry
        .allow_actions(original(), original_end + Duration::from_secs(60), stop)
        .unwrap();
    assert!(f.entry.actions().unwrap().expires <= original_end);
    f.prepared();
    f.entry
        .observe_action(observation(11, OperationState::Failed, Settlement::Settled))
        .unwrap();
    assert!(!f.entry.action_status().unwrap().permission_live);
}
#[test]
fn original_unknown_and_recovery_are_not_success_and_lost_weak_is_not_finality() {
    let f = Fixture::new(true);
    f.prepared();
    drop(f._marker);
    assert_eq!(f.entry.original.get().unwrap().retained.strong_count(), 0);
    assert_eq!(
        f.entry
            .action_status()
            .unwrap()
            .observation
            .unwrap()
            .settlement,
        Settlement::Pending
    );
    let mut unknown = observation(11, OperationState::Unknown, Settlement::Unknown);
    unknown.effect = Some(Effect::Unknown);
    unknown.journal = Some(Journal::Unknown);
    f.entry.observe_action(unknown).unwrap();
    assert!(f
        .entry
        .observe_action(observation(12, OperationState::Failed, Settlement::Settled))
        .is_err());
    assert_eq!(
        f.entry
            .action_status()
            .unwrap()
            .observation
            .unwrap()
            .settlement,
        Settlement::Unknown
    );
    assert!(f.entry.action_occupies());
    let g = Fixture::new(true);
    g.prepared();
    g.inbox
        .identity_action(&query(), Some(Kind::Start), Some(&start()), false)
        .unwrap();
    let claim = g.inbox.claim_identity_action().unwrap().unwrap();
    g.entry.consume_action(Kind::Start).unwrap();
    claim.returned(true);
    let mut recovering = observation(11, OperationState::RecoveryRequired, Settlement::Settled);
    recovering.apply_submitted = true;
    recovering.effect = Some(Effect::Committed);
    recovering.journal = Some(Journal::RecoveryRequired);
    g.entry.observe_action(recovering).unwrap();
    let status = g.entry.action_status().unwrap();
    assert_eq!(
        status.observation.unwrap().state,
        OperationState::RecoveryRequired
    );
    assert!(!g.entry.action_occupies());
}
#[test]
fn bounded_public_review_refuses_extra_authority_and_false_success() {
    let f = Fixture::new(true);
    f.prepared();
    let status = f.entry.action_status().unwrap();
    status.validate().unwrap();
    let mut bad = status.clone();
    bad.observation.as_mut().unwrap().state = OperationState::Succeeded;
    assert!(bad.validate().is_err());
    let mut bad = status.clone();
    bad.observation
        .as_mut()
        .unwrap()
        .review
        .as_mut()
        .unwrap()
        .changes[0]
        .path = "/private/key".into();
    assert!(bad.validate().is_err());
    let mut bad = status.clone();
    bad.observation
        .as_mut()
        .unwrap()
        .review
        .as_mut()
        .unwrap()
        .retain_version_reservations = false;
    assert!(bad.validate().is_err());
    let mut bad = status.clone();
    let changes = &mut bad
        .observation
        .as_mut()
        .unwrap()
        .review
        .as_mut()
        .unwrap()
        .changes;
    changes.push(changes[1].clone());
    assert!(bad.validate().is_err());
    let mut v = serde_json::to_value(status).unwrap();
    v["root"] = serde_json::json!("/forged");
    assert!(serde_json::from_value::<Status>(v).is_err());
}
#[test]
fn required_nullable_fields_are_typed_and_never_default_missing() {
    let f = Fixture::new(true);
    let mut empty = serde_json::to_value(f.entry.action_status().unwrap()).unwrap();
    assert!(empty["observation"].is_null());
    assert!(serde_json::from_value::<Status>(empty.clone())
        .unwrap()
        .observation
        .is_none());
    empty.as_object_mut().unwrap().remove("observation");
    assert!(serde_json::from_value::<Status>(empty).is_err());

    f.prepared();
    let mut typed = serde_json::to_value(f.entry.action_status().unwrap()).unwrap();
    typed["observation"]["effect"] = serde_json::json!("not_started");
    typed["observation"]["journal"] = serde_json::json!("not_created");
    let decoded = serde_json::from_value::<Status>(typed.clone()).unwrap();
    decoded.validate().unwrap();
    let observation = decoded.observation.unwrap();
    assert_eq!(observation.review, Some(review()));
    assert_eq!(observation.effect, Some(Effect::NotStarted));
    assert_eq!(observation.journal, Some(Journal::NotCreated));

    let mut nulls = typed.clone();
    for key in ["review", "effect", "journal"] {
        nulls["observation"][key] = serde_json::Value::Null;
    }
    let observation = serde_json::from_value::<Status>(nulls)
        .unwrap()
        .observation
        .unwrap();
    assert!(observation.review.is_none());
    assert!(observation.effect.is_none());
    assert!(observation.journal.is_none());

    for key in ["review", "effect", "journal"] {
        let mut v = typed.clone();
        v["observation"].as_object_mut().unwrap().remove(key);
        assert!(serde_json::from_value::<Status>(v).is_err());
        let mut v = typed.clone();
        v["observation"][key] = serde_json::json!(17);
        assert!(serde_json::from_value::<Status>(v).is_err());
    }
    typed["observation"] = serde_json::json!(17);
    assert!(serde_json::from_value::<Status>(typed).is_err());
}
#[test]
fn original_noop_has_no_journal_and_remains_a_valid_settled_result() {
    let f = Fixture::new(true);
    let mut s = f.entry.action_status().unwrap();
    s.change.desired_identity = "com.example.old".into();
    s.prepare = Step::Submitted;
    s.start = Step::Submitted;
    s.permission_live = false;
    s.remaining_ms = 0;
    let mut r = review();
    r.after_identity = r.before_identity.clone();
    r.changes.clear();
    r.unchanged = true;
    r.new_application_warning = false;
    s.observation = Some(Observation {
        status_revision: 1,
        state: OperationState::Succeeded,
        settlement: Settlement::Settled,
        apply_submitted: true,
        review: Some(r),
        effect: Some(Effect::Unchanged),
        journal: Some(Journal::NotCreated),
    });
    s.validate().unwrap();
}
