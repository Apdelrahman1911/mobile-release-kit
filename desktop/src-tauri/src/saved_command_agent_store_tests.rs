//! The actual Saved facet's closed guards/projection with inert DATA only.
use super::*;
fn id(c: char) -> s::Id {
    s::Id::parse(&c.to_string().repeat(32)).unwrap()
}
fn context() -> Context {
    Context::LocalStorePreflight(store_wire::tests::context())
}
fn projected(c: Context) -> RunProjection {
    RunProjection {
        agent_build: None,
        agent_local_check: None,
        operation_id: "a".repeat(32),
        owner_generation: "b".repeat(32),
        context: c,
        phase: Phase::AwaitingConsent,
        intent_usable: true,
        outcome: None,
        reason: Reason::None,
        result: None,
        stage: None,
    }
}
fn root() -> RegisteredRoot {
    RegisteredRoot {
        path: "/inert/never-opened".into(),
        identity: crate::asset_source::ProjectIdentity::Posix(
            crate::asset_source::DirectoryIdentity::synthetic_evidence_identity(),
        ),
    }
}
#[test]
fn store_facet_never_delegates_both_query_or_later_context() {
    let mut c = store_wire::tests::context();
    assert!(witness(&Context::LocalStorePreflight(c.clone())).is_some());
    c.platform = store_wire::AccessPlatform::Both;
    assert!(witness(&Context::LocalStorePreflight(c.clone())).is_none());
    let mut value = serde_json::to_value(store_wire::tests::context()).unwrap();
    value["platform"] = "ios".into();
    value["query"] = "ios-current-versions".into();
    let query: store_wire::Context = serde_json::from_value(value).unwrap();
    assert!(witness(&Context::LocalStorePreflight(query.clone())).is_none());
    assert!(review(
        &Context::LocalStorePreflight(query),
        id('a').as_str(),
        id('b').as_str(),
        1
    )
    .is_err());
    assert!(witness(&Context::LocalStorePrepare(prepare_wire::tests::context())).is_some());
    let ordinary=Context::OfflinePreflight(crate::offline_preflight_protocol::prepare(&serde_json::json!({"projectId":"p1","draftRevision":1,"baselineGeneration":1,"savedConfig":{"bytes":1,"sha256":"a".repeat(64)}})).unwrap().context());
    assert!(witness(&ordinary).is_none());
}
#[test]
fn store_terminal_shaped_data_before_original_retirement_stays_pending() {
    let c = context();
    let r = review(&c, id('a').as_str(), id('b').as_str(), 1).unwrap();
    let control = requests::Control::new();
    let mut p = projected(c);
    p.phase = Phase::Terminal;
    p.intent_usable = false;
    p.outcome = Some(Outcome::Cancelled);
    p.reason = Reason::Cancelled;
    let pending = projection(&p, 2, false, &r, &control).unwrap();
    assert!(!pending.retired);
    assert!(pending.outcome.is_none());
    assert!(pending.result.is_none());
    let retired = projection(&p, 2, true, &r, &control).unwrap();
    assert!(retired.retired);
    assert_eq!(retired.outcome, Some(p::Outcome::Cancelled));
    p.phase = Phase::Unknown;
    assert!(projection(&p, 3, true, &r, &control).is_err());
}
#[test]
fn store_actual_validated_result_projects_fail_findings_without_release_authority() {
    let c = context();
    let r = review(&c, id('a').as_str(), id('b').as_str(), 1).unwrap();
    let t: store_wire::Terminal = serde_json::from_value(store_wire::tests::complete()).unwrap();
    let mut p = projected(c);
    p.phase = Phase::Terminal;
    p.intent_usable = false;
    p.outcome = Some(Outcome::Complete);
    p.result = Some(Terminal::LocalStorePreflight(t));
    let n = projection(&p, 2, true, &r, &requests::Control::new()).unwrap();
    let v = serde_json::to_value(n.result.unwrap()).unwrap();
    assert_eq!(v["findings"][0]["status"], "FAIL");
    assert_eq!(v.as_object().unwrap().len(), 3);
    assert!(v.get("account").is_none());
    let mut other = r;
    other.saved_version.build += 1;
    assert!(projection(&p, 2, true, &other, &requests::Control::new()).is_err());
}
#[test]
fn store_candidate_report_only_exposes_same_local_intent_digests() {
    let c = prepare_wire::tests::context();
    let r = review(
        &Context::LocalStorePrepare(c.clone()),
        id('a').as_str(),
        id('b').as_str(),
        1,
    )
    .unwrap();
    let raw = serde_json::json!({"schemaVersion":1,"context":c,"outcome":"complete","reason":"none","result":{"schemaVersion":1,"scope":"local-android-store-prepare","headSequence":5,"preparedIntent":{"operationId":c.candidate_operation_id,"candidateSha256":c.candidate_sha256,"intentSha256":"e".repeat(64),"storePreconditionSha256":"f".repeat(64),"sourceCommit":"a".repeat(40),"sourceTree":"b".repeat(40),"applicationId":"dev.example.app","version":{"name":"1.2.3","build":42},"destination":{"channel":"internal","releaseStatus":"completed"},"observedAt":"2026-10-16T20:00:00Z","limitations":p::prepare_limitations(p::Platform::Android)}},"lifetime":{"complete":true,"fatal":false,"contained":true,"commandDispatched":true,"commands":14,"profileCalls":0,"inputClosed":true,"handlersRestored":true,"invocationClosed":true,"stopObserved":"none"}});
    let t: prepare_wire::Terminal = serde_json::from_value(raw).unwrap();
    let out = report(&Terminal::LocalStorePrepare(t), &r).unwrap();
    assert!(out.valid_for(&r));
    let value = serde_json::to_value(out).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 7);
    assert!(value.get("sourceCommit").is_none());
    assert!(value.get("destination").is_none());
}
pub(super) fn binding() -> (
    SavedCommandOwner,
    Prepared,
    Arc<Binding>,
    requests::Inbox,
    Arc<()>,
) {
    binding_with_read_end(None)
}
fn binding_with_read_end(
    read_end: Option<Instant>,
) -> (
    SavedCommandOwner,
    Prepared,
    Arc<Binding>,
    requests::Inbox,
    Arc<()>,
) {
    let owner = SavedCommandOwner::new(
        RuntimeConfig::packaged("/unopened-store-runtime".into()),
        SavedCommandDomain::LocalStorePreflight,
    );
    let c = context();
    let r = review(&c, id('a').as_str(), id('b').as_str(), 1).unwrap();
    let witness = Arc::new(());
    let doc = Arc::new(());
    let expires = Instant::now() + Duration::from_secs(290);
    let root = root();
    let scope = Arc::new(requests::NativeScope {
        project_id: id('1'),
        runtime_id: c.project_id().into(),
        review_id: id('4'),
        review: r.clone(),
        root: root.path.clone(),
        device: 1,
        inode: 2,
        observation_revision: 1,
        expires,
        read: Arc::new(
            crate::service_version_reserve_requests::ReadPermission::new(
                read_end.unwrap_or(expires + Duration::from_secs(1200)),
            ),
        ),
        document: Arc::downgrade(&doc),
        witness: Arc::downgrade(&witness),
        control: requests::Control::new(),
        retired: AtomicBool::new(false),
        changes: watch::channel(0).0,
    });
    let approval = Arc::new(Approval {
        owner: Arc::downgrade(&owner.inner),
        witness: Arc::downgrade(&witness),
        material: Weak::new(),
        context: c.clone(),
        registration: 1,
        root: root.clone(),
        expires,
        review: r,
    });
    let link = Arc::new(Binding {
        approval,
        scope: scope.clone(),
        _witness: witness.clone(),
        entry: OnceLock::new(),
        latest: Mutex::new(None),
        consumed: AtomicBool::new(false),
    });
    let prepared = Prepared {
        agent_store_preparation: None,
        agent_store: Some(link.clone()),
        store_witness: Some(witness),
        agent_build: None,
        agent_local_check: None,
        upload_key_preparation: None,
        upload_key: None,
        apple: None,
        tools: None,
        local_history: None,
        projection: projected(c),
        expires,
        registration: 1,
        project: root,
        recovery_stamp: None,
        material: None,
        recovery: None,
        android_selection: None,
        artifact_selection: None,
        artifact_tools: None,
    };
    let inbox = requests::Inbox::new(id('2'));
    inbox.allow(scope, id('3')).unwrap();
    inbox
        .submit(
            p::Submit {
                origin: p::Query {
                    project_id: id('1'),
                    service_instance: id('2'),
                    request_id: id('5'),
                },
                grant_id: id('3'),
                review_id: id('4'),
            },
            Instant::now(),
        )
        .unwrap();
    (owner, prepared, link, inbox, doc)
}
// The existing DATA fixture constructs an unentered Session/Registry. No
// task, timer, material, native admission or retirement receipt is produced.
fn running_read(
    read_end: Instant,
) -> (
    SavedCommandOwner,
    Arc<Session>,
    Arc<Binding>,
    requests::Inbox,
    Arc<()>,
) {
    let (owner, _prepared, link, inbox, doc) = binding_with_read_end(Some(read_end));
    let (owner, session) = super::super::tests::active_with_context(owner, context());
    assert_eq!(control_poll(&session), None);
    assert_eq!(owner.inner.endpoint(&session), Some(session.clocks.work));
    let mut active = owner.inner.lock().active.take().unwrap();
    drop(session);
    Arc::get_mut(&mut active.owner).unwrap().agent_store = Some(link.clone());
    link.consumed.store(true, Ordering::Release);
    link.scope.control.attach(&active.owner.stop).unwrap();
    link.attach(&inbox.entries().unwrap().remove(0)).unwrap();
    let session = active.owner.clone();
    owner.inner.lock().active = Some(active);
    (owner, session, link, inbox, doc)
}
#[test]
fn store_watchdog_uses_original_read_end_without_relay_or_worker_output() {
    let read_end = Instant::now() + Duration::from_secs(60);
    let (owner, session, link, _inbox, _doc) = running_read(read_end);
    assert_eq!(link.read_end(), read_end);
    assert_eq!(control_poll(&session), Some(Duration::from_millis(5)));
    assert!(read_end < session.clocks.work);
    assert_eq!(owner.inner.endpoint(&session), Some(read_end));
    // Call the real clock transition without a relay, frame or Tokio runtime.
    {
        let mut r = owner.inner.lock();
        owner.inner.advance_locked(&mut r, &session, read_end);
        let a = r.active.as_ref().unwrap();
        assert_eq!(a.first_stop, Some(read_end));
        assert_eq!(a.projection.phase, Phase::Stopping);
        assert!(!a.terminal && !a.final_join_seen);
    }
    assert!(*session.stop.borrow());
    assert_eq!(
        link.scope.control.first().unwrap(),
        Some((p::Reason::PermissionRevoked, read_end))
    );
    assert_eq!(
        owner.inner.endpoint(&session),
        Some(session.finality_end(Some(read_end)))
    );
    assert_eq!(
        *session.native_cleanup_cutoff.borrow(),
        session.cleanup_end(Some(read_end))
    );
}
#[test]
fn store_watchdog_samples_renewed_old_read_after_stop_and_keeps_earliest_f() {
    let read_end = Instant::now() + Duration::from_secs(600);
    let (owner, session, link, _inbox, _doc) = running_read(read_end);
    let first = session.clocks.admitted + Duration::from_secs(3);
    let later = session.clocks.admitted + Duration::from_secs(8);
    let sampled = session.clocks.admitted + Duration::from_secs(9);
    {
        let mut r = owner.inner.lock();
        owner
            .inner
            .stop_locked(&mut r, &session, Reason::Cancelled, later);
        assert_eq!(r.active.as_ref().unwrap().first_stop, Some(later));
    }
    // This is the actual immutable old ReadPermission retained by the link.
    // A renewed permission cannot replace it or clear its earlier revoke.
    let renewed = crate::service_version_reserve_requests::ReadPermission::new(
        read_end + Duration::from_secs(900),
    );
    link.scope.read.revoke(first);
    assert_eq!(renewed.stop(sampled).unwrap(), None);
    assert_eq!(link.scope.control.first().unwrap(), None);
    assert_eq!(control_poll(&session), Some(Duration::from_millis(5)));
    {
        let mut r = owner.inner.lock();
        owner.inner.advance_locked(&mut r, &session, sampled);
        let a = r.active.as_ref().unwrap();
        assert_eq!(a.first_stop, Some(first));
        assert!(!a.unknown && !a.terminal && !a.final_join_seen);
    }
    let original_end = session.finality_end(Some(first));
    assert_eq!(owner.inner.endpoint(&session), Some(original_end));
    assert_eq!(
        *session.native_cleanup_cutoff.borrow(),
        session.cleanup_end(Some(first))
    );
    assert_eq!(link.read_end(), read_end);
    {
        let mut r = owner.inner.lock();
        owner.inner.advance_locked(&mut r, &session, original_end);
        assert_eq!(r.active.as_ref().unwrap().first_stop, Some(first));
        assert!(r.active.as_ref().unwrap().unknown);
    }
    assert_eq!(owner.inner.endpoint(&session), None);
    assert!(owner.inner.lock().active.is_some());
}
#[test]
fn store_same_original_entry_and_witness_required_before_one_consumption() {
    let (_o, mut prepared, link, inbox, _doc) = binding();
    let entry = inbox.entries().unwrap().remove(0);
    link.attach(&entry).unwrap();
    assert!(!start_matches(&prepared, None));
    assert!(start_matches(&prepared, Some(&entry)));
    let old = prepared.store_witness.replace(Arc::new(()));
    assert!(!start_matches(&prepared, Some(&entry)));
    prepared.store_witness = old;
    consume(&prepared).unwrap();
    assert!(!start_matches(&prepared, Some(&entry)));
    assert!(consume(&prepared).is_err());
    assert!(link.attach(&entry).is_err());
}
#[test]
fn store_early_native_retirement_is_retained_data_not_lost_to_late_relay() {
    let (_o, p, link, inbox, _doc) = binding();
    let terminal = retire(p.projection.clone(), Reason::Cancelled);
    link.publish(&terminal, 2, true);
    assert!(link.scope.retired.load(Ordering::Acquire));
    let claim = inbox.claim().unwrap().unwrap();
    link.attach(claim.entry()).unwrap();
    let entry = claim.entry().clone();
    assert!(entry.pending());
    claim.returned();
    entry
        .claim_history()
        .unwrap()
        .unwrap()
        .returned(Ok(()))
        .unwrap();
    assert_eq!(entry.status().unwrap().state, p::State::Cancelled);
}
#[test]
fn store_missing_material_or_consumed_missing_native_owner_never_becomes_clean() {
    let (owner, mut p, link, _inbox, _doc) = binding();
    p.agent_store = None;
    {
        let mut registry = owner.inner.lock();
        registry.revision = 1;
        registry.prepared = Some(p);
    }
    assert!(owner
        .store_approval(p::Kind::AccessCheck, &id('a'), &id('b'), 1)
        .is_err());
    owner.inner.lock().prepared.take();
    owner.stop_agent_store(&link, p::Reason::NativeRefused, Instant::now());
    assert!(link.scope.control.first().is_err());
}
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn store_raw_main_request_is_bounded_before_closed_decode() {
    use crate::asset_session::agent_store::{decode, Allow};
    let value = serde_json::json!({"kind":"access-check","operationId":id('a'),"ownerGeneration":id('b'),"expectedStatusRevision":3,"consentVersion":"agent-android-store-access-once-v1"});
    let mut bytes = serde_json::to_vec(&value).unwrap();
    assert!(decode::<Allow>(&bytes).is_ok());
    bytes.resize(p::RAW_LIMIT, b' ');
    assert!(decode::<Allow>(&bytes).is_ok());
    bytes.push(b' ');
    assert!(decode::<Allow>(&bytes).is_err());
    assert!(decode::<Allow>(br#"{"kind":"access-check","kind":"candidate-prepare"}"#).is_err());
}

#[path = "saved_command_agent_store_release_tests.rs"]
mod release_tests;
